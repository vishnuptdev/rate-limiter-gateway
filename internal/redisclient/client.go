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
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Upper bounds on server-announced lengths, so a corrupt or hostile reply
// cannot make the client allocate unbounded memory up front (Redis' own
// proto-max-bulk-len default is 512MB).
const (
	maxBulkLen  = 512 << 20
	maxArrayLen = 1 << 24
	// arrayPrealloc caps the capacity reserved from an announced array
	// length; longer arrays grow by append as their elements arrive.
	arrayPrealloc = 1024
	// maxReplyDepth caps array nesting. RateGuard's replies nest at most two
	// levels; without a cap a hostile server streaming "*1\r\n" forever
	// drives the recursion until the goroutine stack limit kills the
	// process (a fatal error, not a recoverable panic).
	maxReplyDepth = 32
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

// encodeCommand returns the RESP encoding of args (used by tests; the
// client writes straight into its buffered writer with writeCommand).
func encodeCommand(args []string) []byte {
	var b bytes.Buffer
	w := bufio.NewWriter(&b)
	writeCommand(w, args)
	w.Flush()
	return b.Bytes()
}

// writeCommand encodes args as a RESP array of bulk strings directly into
// w (no intermediate string, no fmt). bufio errors are sticky, so the
// caller's Flush reports any write failure.
func writeCommand(w *bufio.Writer, args []string) {
	var num [20]byte
	w.WriteByte('*')
	w.Write(strconv.AppendInt(num[:0], int64(len(args)), 10))
	w.WriteString("\r\n")
	for _, a := range args {
		w.WriteByte('$')
		w.Write(strconv.AppendInt(num[:0], int64(len(a)), 10))
		w.WriteString("\r\n")
		w.WriteString(a)
		w.WriteString("\r\n")
	}
}

// readLine returns the next reply line without its CRLF. The slice is only
// valid until the next read from r (it usually aliases r's buffer).
func readLine(r *bufio.Reader) ([]byte, error) {
	line, err := r.ReadSlice('\n')
	if err == bufio.ErrBufferFull {
		// Longer than the reader's buffer (e.g. a long error message).
		// Copy first: line aliases the buffer the next read overwrites.
		head := append([]byte(nil), line...)
		var rest []byte
		rest, err = r.ReadBytes('\n')
		line = append(head, rest...)
	}
	if err != nil {
		return nil, err
	}
	for len(line) > 0 && (line[len(line)-1] == '\n' || line[len(line)-1] == '\r') {
		line = line[:len(line)-1]
	}
	return line, nil
}

// parseInt parses a RESP integer without allocating; malformed input falls
// back to strconv for its error.
func parseInt(b []byte) (int64, error) {
	neg := false
	d := b
	if len(d) > 0 && (d[0] == '-' || d[0] == '+') {
		neg = d[0] == '-'
		d = d[1:]
	}
	if len(d) == 0 || len(d) > 18 {
		return strconv.ParseInt(string(b), 10, 64)
	}
	var n int64
	for _, c := range d {
		if c < '0' || c > '9' {
			return strconv.ParseInt(string(b), 10, 64)
		}
		n = n*10 + int64(c-'0')
	}
	if neg {
		n = -n
	}
	return n, nil
}

func readReply(r *bufio.Reader) (*Reply, error) {
	rep := new(Reply)
	if err := readReplyInto(r, rep, 0); err != nil {
		return nil, err
	}
	return rep, nil
}

// readReplyInto parses one reply into rep; depth is its array nesting level.
func readReplyInto(r *bufio.Reader, rep *Reply, depth int) error {
	line, err := readLine(r)
	if err != nil {
		return err
	}
	if len(line) == 0 {
		return errors.New("redis: empty reply line")
	}
	switch line[0] {
	case '+':
		*rep = Reply{Type: '+', Str: string(line[1:])}
	case '-':
		*rep = Reply{Type: '-', Str: string(line[1:])}
	case ':':
		n, err := parseInt(line[1:])
		if err != nil {
			return fmt.Errorf("redis: bad integer reply: %w", err)
		}
		*rep = Reply{Type: ':', Int: n}
	case '$':
		n, err := parseInt(line[1:])
		if err != nil || n < -1 || n > maxBulkLen {
			if err == nil {
				err = strconv.ErrRange
			}
			return fmt.Errorf("redis: bad bulk length: %w", err)
		}
		if n == -1 {
			*rep = Reply{Type: '$', IsNil: true}
			return nil
		}
		buf := make([]byte, n+2) // + trailing CRLF
		if _, err := readFull(r, buf); err != nil {
			return err
		}
		*rep = Reply{Type: '$', Str: string(buf[:n])}
	case '*':
		n, err := parseInt(line[1:])
		if err != nil || n < -1 || n > maxArrayLen {
			if err == nil {
				err = strconv.ErrRange
			}
			return fmt.Errorf("redis: bad array length: %w", err)
		}
		if n == -1 {
			*rep = Reply{Type: '*', IsNil: true}
			return nil
		}
		if n > 0 && depth >= maxReplyDepth {
			return errors.New("redis: reply nested too deeply")
		}
		// Never trust the announced length for up-front allocation: a
		// hostile "*16777215" header must not cost ~1GB before a single
		// element arrives. Start small and grow only as elements are
		// actually read (maxArrayLen still caps the total).
		items := make([]*Reply, 0, min(n, arrayPrealloc))
		for i := int64(0); i < n; i++ {
			item := new(Reply)
			if err := readReplyInto(r, item, depth+1); err != nil {
				return err
			}
			items = append(items, item)
		}
		*rep = Reply{Type: '*', Array: items}
	default:
		return fmt.Errorf("redis: unknown reply type byte %q", line[0])
	}
	return nil
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
	writeCommand(cn.w, args)
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
