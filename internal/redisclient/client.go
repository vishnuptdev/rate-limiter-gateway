// Package redisclient is a minimal, dependency-free Redis client
// implementing just enough of the RESP2 protocol (see
// https://redis.io/docs/reference/protocol-spec/) to run commands and
// Lua scripts (EVAL) over a real TCP connection. It exists because this
// environment's Go module proxy is unreachable (see NOTES.md) so no
// third-party Redis client could be fetched; hand-rolling RESP is also a
// reasonable way to demonstrate protocol-level understanding, which is
// the point of this batch of projects.
//
// It is intentionally small: a connection pool of plain TCP connections,
// a request encoder, and a reply parser. No pipelining, no pub/sub.
package redisclient

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Client is a simple connection-pooled RESP client safe for concurrent use.
type Client struct {
	addr string
	pool chan *conn
	mu   sync.Mutex
	size int
}

type conn struct {
	nc net.Conn
	r  *bufio.Reader
	w  *bufio.Writer
}

// New creates a client that lazily dials addr (e.g. "127.0.0.1:6379"),
// keeping up to maxConns connections in a pool.
func New(addr string, maxConns int) *Client {
	return &Client{addr: addr, pool: make(chan *conn, maxConns), size: maxConns}
}

func (c *Client) getConn() (*conn, error) {
	select {
	case cn := <-c.pool:
		return cn, nil
	default:
	}
	nc, err := net.DialTimeout("tcp", c.addr, 3*time.Second)
	if err != nil {
		return nil, fmt.Errorf("redis dial %s: %w", c.addr, err)
	}
	return &conn{nc: nc, r: bufio.NewReader(nc), w: bufio.NewWriter(nc)}, nil
}

func (c *Client) putConn(cn *conn, broken bool) {
	if broken {
		cn.nc.Close()
		return
	}
	select {
	case c.pool <- cn:
	default:
		cn.nc.Close()
	}
}

// Reply is a parsed RESP reply. Exactly one of the fields is meaningful,
// determined by Type.
type Reply struct {
	Type  byte // '+' simple string, '-' error, ':' integer, '$' bulk string, '*' array
	Str   string
	Int   int64
	Array []*Reply
	IsNil bool
}

func encodeCommand(args []string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
	}
	return []byte(b.String())
}

func readReply(r *bufio.Reader) (*Reply, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) == 0 {
		return nil, errors.New("redis: empty reply line")
	}
	switch line[0] {
	case '+':
		return &Reply{Type: '+', Str: line[1:]}, nil
	case '-':
		return &Reply{Type: '-', Str: line[1:]}, nil
	case ':':
		n, err := strconv.ParseInt(line[1:], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("redis: bad integer reply: %w", err)
		}
		return &Reply{Type: ':', Int: n}, nil
	case '$':
		n, err := strconv.Atoi(line[1:])
		if err != nil {
			return nil, fmt.Errorf("redis: bad bulk length: %w", err)
		}
		if n == -1 {
			return &Reply{Type: '$', IsNil: true}, nil
		}
		buf := make([]byte, n+2) // + trailing CRLF
		if _, err := readFull(r, buf); err != nil {
			return nil, err
		}
		return &Reply{Type: '$', Str: string(buf[:n])}, nil
	case '*':
		n, err := strconv.Atoi(line[1:])
		if err != nil {
			return nil, fmt.Errorf("redis: bad array length: %w", err)
		}
		if n == -1 {
			return &Reply{Type: '*', IsNil: true}, nil
		}
		items := make([]*Reply, n)
		for i := 0; i < n; i++ {
			item, err := readReply(r)
			if err != nil {
				return nil, err
			}
			items[i] = item
		}
		return &Reply{Type: '*', Array: items}, nil
	default:
		return nil, fmt.Errorf("redis: unknown reply type byte %q", line[0])
	}
}

func readFull(r *bufio.Reader, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// Do sends a command (e.g. Do("SET", "k", "v")) and returns the parsed reply.
func (c *Client) Do(args ...string) (*Reply, error) {
	cn, err := c.getConn()
	if err != nil {
		return nil, err
	}
	if _, err := cn.w.Write(encodeCommand(args)); err != nil {
		c.putConn(cn, true)
		return nil, err
	}
	if err := cn.w.Flush(); err != nil {
		c.putConn(cn, true)
		return nil, err
	}
	reply, err := readReply(cn.r)
	if err != nil {
		c.putConn(cn, true)
		return nil, err
	}
	if reply.Type == '-' {
		c.putConn(cn, false)
		return reply, errors.New("redis error: " + reply.Str)
	}
	c.putConn(cn, false)
	return reply, nil
}

// Ping checks connectivity.
func (c *Client) Ping() error {
	r, err := c.Do("PING")
	if err != nil {
		return err
	}
	if r.Str != "PONG" {
		return fmt.Errorf("unexpected PING reply: %+v", r)
	}
	return nil
}

// Eval runs a Lua script via EVAL with the given keys and args, returning
// the raw reply so callers can interpret it (scripts here return integers
// or arrays of integers).
func (c *Client) Eval(script string, keys []string, args []string) (*Reply, error) {
	cmd := make([]string, 0, 3+len(keys)+len(args))
	cmd = append(cmd, "EVAL", script, strconv.Itoa(len(keys)))
	cmd = append(cmd, keys...)
	cmd = append(cmd, args...)
	return c.Do(cmd...)
}

// FlushAll wipes the whole Redis instance -- used only by tests to get a
// clean slate.
func (c *Client) FlushAll() error {
	_, err := c.Do("FLUSHALL")
	return err
}

// Close drains the pool, closing every idle connection.
func (c *Client) Close() {
	for {
		select {
		case cn := <-c.pool:
			cn.nc.Close()
		default:
			return
		}
	}
}
