package redisclient

import (
	"bufio"
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeServer is a tiny RESP server recording the commands it receives and
// answering from a handler.
type fakeServer struct {
	ln   net.Listener
	mu   sync.Mutex
	cmds [][]string
}

func startFake(t *testing.T, handle func(cmd []string) string) *fakeServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fs := &fakeServer{ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer nc.Close()
				r := bufio.NewReader(nc)
				for {
					rep, err := readReply(r)
					if err != nil {
						return
					}
					cmd := make([]string, len(rep.Array))
					for i, a := range rep.Array {
						cmd[i] = a.Str
					}
					fs.mu.Lock()
					fs.cmds = append(fs.cmds, cmd)
					fs.mu.Unlock()
					resp := handle(cmd)
					if resp == "" {
						continue // never answer (timeout test)
					}
					nc.Write([]byte(resp))
				}
			}()
		}
	}()
	return fs
}

func (f *fakeServer) commands() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.cmds {
		out = append(out, strings.Join(c, " "))
	}
	return out
}

func TestAuthSelectOnDial(t *testing.T) {
	fs := startFake(t, func(cmd []string) string {
		switch cmd[0] {
		case "AUTH", "SELECT":
			return "+OK\r\n"
		}
		return "+PONG\r\n"
	})
	c := NewClient(Options{Addr: fs.ln.Addr().String(), Password: "s3cret", DB: 3})
	defer c.Close()
	if err := c.Ping(); err != nil {
		t.Fatal(err)
	}
	if err := c.Ping(); err != nil { // pooled connection: no second AUTH
		t.Fatal(err)
	}
	got := strings.Join(fs.commands(), "|")
	if got != "AUTH s3cret|SELECT 3|PING|PING" {
		t.Fatalf("commands = %q", got)
	}
}

func TestAuthFailureClosesConn(t *testing.T) {
	fs := startFake(t, func(cmd []string) string { return "-WRONGPASS invalid\r\n" })
	c := NewClient(Options{Addr: fs.ln.Addr().String(), Password: "bad"})
	if err := c.Ping(); err == nil || !strings.Contains(err.Error(), "WRONGPASS") {
		t.Fatalf("err = %v", err)
	}
}

func TestPerCommandDeadline(t *testing.T) {
	fs := startFake(t, func(cmd []string) string { return "" })
	c := NewClient(Options{Addr: fs.ln.Addr().String(), RWTimeout: 100 * time.Millisecond})
	defer c.Close()
	start := time.Now()
	if err := c.Ping(); err == nil {
		t.Fatal("expected timeout")
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("took %v", el)
	}
	// Context deadline tightens the per-command deadline.
	c2 := NewClient(Options{Addr: fs.ln.Addr().String(), RWTimeout: 10 * time.Second})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start = time.Now()
	if err := c2.PingContext(ctx); err == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("ctx deadline ignored: %v after %v", err, time.Since(start))
	}
}

func TestEvalShaAndScriptLoad(t *testing.T) {
	c := newTestClient(t)
	defer c.Close()
	ctx := context.Background()
	sha, err := c.ScriptLoad(ctx, "return ARGV[1]")
	if err != nil || len(sha) != 40 {
		t.Fatalf("sha=%q err=%v", sha, err)
	}
	r, err := c.EvalSha(ctx, sha, nil, []string{"hi"})
	if err != nil || r.Str != "hi" {
		t.Fatalf("%+v %v", r, err)
	}
	_, err = c.EvalSha(ctx, strings.Repeat("0", 40), nil, nil)
	if !IsNoScript(err) {
		t.Fatalf("expected NOSCRIPT, got %v", err)
	}
	// A server error reply must not poison the pooled connection.
	if err := c.Ping(); err != nil {
		t.Fatal(err)
	}
}

func TestBackwardCompatNew(t *testing.T) {
	c := New("127.0.0.1:1", 2)
	if cap(c.pool) != 2 || c.opts.RWTimeout == 0 || c.opts.DialTimeout == 0 {
		t.Fatalf("%+v", c.opts)
	}
}
