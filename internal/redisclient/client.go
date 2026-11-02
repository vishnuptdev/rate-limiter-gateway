// Package redisclient is a minimal, dependency-free Redis client
// implementing just enough of the RESP2 protocol (see
// https://redis.io/docs/reference/protocol-spec/) to run commands and
// Lua scripts (EVAL / EVALSHA) over a real TCP (optionally TLS)
// connection. The project is stdlib-only by design (supply-chain
// minimalism), so no third-party Redis client is used.
//
// It is intentionally small: a pool of idle connections, a request
// encoder, and a reply parser. Every command runs under a read/write
// deadline. No pipelining, no pub/sub.
package redisclient

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Options configures a Client.
type Options struct {
	Addr        string        // host:port (required)
	Password    string        // sent with AUTH on every new connection when non-empty
	DB          int           // SELECTed on every new connection when non-zero
	PoolSize    int           // max idle connections kept (default 16)
	DialTimeout time.Duration // default 3s
	RWTimeout   time.Duration // per-command read+write deadline, default 3s
	TLS         bool          // wrap connections in TLS (min TLS 1.2)
}

// Error is a Redis error reply ("-ERR ...").
type Error struct{ Msg string }

func (e *Error) Error() string { return "redis error: " + e.Msg }

// IsNoScript reports whether err is a NOSCRIPT error (EVALSHA of a
// script the server has not cached).
func IsNoScript(err error) bool {
	var re *Error
	return errors.As(err, &re) && strings.HasPrefix(re.Msg, "NOSCRIPT")
}

// Client is a simple connection-pooled RESP client safe for concurrent use.
type Client struct {
	opts Options
	pool chan *conn
}

type conn struct {
	nc net.Conn
	r  *bufio.Reader
	w  *bufio.Writer
}

// New creates a client that lazily dials addr (e.g. "127.0.0.1:6379"),
// keeping up to maxConns idle connections in a pool. Backward-compatible
// shorthand for NewClient(Options{Addr: addr, PoolSize: maxConns}).
func New(addr string, maxConns int) *Client {
	return NewClient(Options{Addr: addr, PoolSize: maxConns})
}

// NewClient creates a client from opts, applying defaults.
func NewClient(o Options) *Client {
	if o.PoolSize <= 0 {
		o.PoolSize = 16
	}
	if o.DialTimeout <= 0 {
		o.DialTimeout = 3 * time.Second
	}
	if o.RWTimeout <= 0 {
		o.RWTimeout = 3 * time.Second
	}
	return &Client{opts: o, pool: make(chan *conn, o.PoolSize)}
}

func (c *Client) dial() (*conn, error) {
	d := net.Dialer{Timeout: c.opts.DialTimeout}
	nc, err := d.Dial("tcp", c.opts.Addr)
	if err != nil {
		return nil, fmt.Errorf("redis dial %s: %w", c.opts.Addr, err)
	}
	if c.opts.TLS {
		host, _, err := net.SplitHostPort(c.opts.Addr)
		if err != nil {
			host = c.opts.Addr
		}
		tc := tls.Client(nc, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
		nc.SetDeadline(time.Now().Add(c.opts.DialTimeout))
		if err := tc.Handshake(); err != nil {
			nc.Close()
			return nil, fmt.Errorf("redis tls %s: %w", c.opts.Addr, err)
		}
		nc = tc
	}
	cn := &conn{nc: nc, r: bufio.NewReader(nc), w: bufio.NewWriter(nc)}
	if c.opts.Password != "" {
		if _, err := c.roundTrip(cn, time.Time{}, []string{"AUTH", c.opts.Password}); err != nil {
			nc.Close()
			return nil, fmt.Errorf("redis auth: %w", err)
		}
	}
	if c.opts.DB != 0 {
		if _, err := c.roundTrip(cn, time.Time{}, []string{"SELECT", strconv.Itoa(c.opts.DB)}); err != nil {
			nc.Close()
			return nil, fmt.Errorf("redis select: %w", err)
		}
	}
	return cn, nil
}

func (c *Client) getConn() (*conn, error) {
	select {
	case cn := <-c.pool:
		return cn, nil
	default:
	}
	return c.dial()
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

// roundTrip writes one command and reads one reply under a deadline
// (RWTimeout from now, tightened to dl when dl is non-zero). A returned
// *Error (server error reply) leaves the connection healthy.
func (c *Client) roundTrip(cn *conn, dl time.Time, args []string) (*Reply, error) {
	d := time.Now().Add(c.opts.RWTimeout)
	if !dl.IsZero() && dl.Before(d) {
		d = dl
	}
	cn.nc.SetDeadline(d)
	if _, err := cn.w.Write(encodeCommand(args)); err != nil {
		return nil, err
	}
	if err := cn.w.Flush(); err != nil {
		return nil, err
	}
	reply, err := readReply(cn.r)
	if err != nil {
		return nil, err
	}
	if reply.Type == '-' {
		return reply, &Error{Msg: reply.Str}
	}
	return reply, nil
}

// Do sends a command (e.g. Do("SET", "k", "v")) and returns the parsed reply.
func (c *Client) Do(args ...string) (*Reply, error) {
	return c.DoContext(context.Background(), args...)
}

// DoContext is Do honouring ctx's deadline (and cancellation before send).
func (c *Client) DoContext(ctx context.Context, args ...string) (*Reply, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cn, err := c.getConn()
	if err != nil {
		return nil, err
	}
	dl, _ := ctx.Deadline()
	reply, err := c.roundTrip(cn, dl, args)
	var re *Error
	c.putConn(cn, err != nil && !errors.As(err, &re))
	return reply, err
}

// Ping checks connectivity.
func (c *Client) Ping() error {
	return c.PingContext(context.Background())
}

// PingContext is Ping honouring ctx.
func (c *Client) PingContext(ctx context.Context) error {
	r, err := c.DoContext(ctx, "PING")
	if err != nil {
		return err
	}
	if r.Str != "PONG" {
		return fmt.Errorf("unexpected PING reply: %+v", r)
	}
	return nil
}

// Eval runs a Lua script via EVAL with the given keys and args, returning
// the raw reply so callers can interpret it.
func (c *Client) Eval(script string, keys []string, args []string) (*Reply, error) {
	return c.EvalContext(context.Background(), script, keys, args)
}

// EvalContext is Eval honouring ctx.
func (c *Client) EvalContext(ctx context.Context, script string, keys, args []string) (*Reply, error) {
	return c.DoContext(ctx, scriptCmd("EVAL", script, keys, args)...)
}

// EvalSha runs a cached script by its SHA1. A NOSCRIPT failure can be
// detected with IsNoScript.
func (c *Client) EvalSha(ctx context.Context, sha string, keys, args []string) (*Reply, error) {
	return c.DoContext(ctx, scriptCmd("EVALSHA", sha, keys, args)...)
}

// ScriptLoad caches script on the server and returns its SHA1.
func (c *Client) ScriptLoad(ctx context.Context, script string) (string, error) {
	r, err := c.DoContext(ctx, "SCRIPT", "LOAD", script)
	if err != nil {
		return "", err
	}
	return r.Str, nil
}

func scriptCmd(verb, body string, keys, args []string) []string {
	cmd := make([]string, 0, 3+len(keys)+len(args))
	cmd = append(cmd, verb, body, strconv.Itoa(len(keys)))
	cmd = append(cmd, keys...)
	return append(cmd, args...)
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
