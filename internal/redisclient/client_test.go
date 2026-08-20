package redisclient

import (
	"os"
	"testing"
)

func testAddr() string {
	if a := os.Getenv("REDIS_TEST_ADDR"); a != "" {
		return a
	}
	return "127.0.0.1:6379"
}

func newTestClient(t *testing.T) *Client {
	t.Helper()
	c := New(testAddr(), 4)
	if err := c.Ping(); err != nil {
		t.Skipf("SKIP: redis not reachable at %s: %v", testAddr(), err)
	}
	return c
}

func TestPing(t *testing.T) {
	c := newTestClient(t)
	defer c.Close()
	if err := c.Ping(); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func TestSetGet(t *testing.T) {
	c := newTestClient(t)
	defer c.Close()
	if _, err := c.Do("SET", "rlg:test:key", "hello"); err != nil {
		t.Fatalf("SET: %v", err)
	}
	r, err := c.Do("GET", "rlg:test:key")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	if r.Str != "hello" {
		t.Fatalf("expected 'hello', got %q", r.Str)
	}
}

func TestGetMissingKeyIsNil(t *testing.T) {
	c := newTestClient(t)
	defer c.Close()
	c.Do("DEL", "rlg:test:missing")
	r, err := c.Do("GET", "rlg:test:missing")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	if !r.IsNil {
		t.Fatalf("expected nil reply for missing key, got %+v", r)
	}
}

func TestEval(t *testing.T) {
	c := newTestClient(t)
	defer c.Close()
	r, err := c.Eval("return ARGV[1] + ARGV[2]", nil, []string{"2", "3"})
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if r.Int != 5 {
		t.Fatalf("expected 5, got %+v", r)
	}
}

func TestIncr(t *testing.T) {
	c := newTestClient(t)
	defer c.Close()
	c.Do("DEL", "rlg:test:counter")
	for i := 0; i < 5; i++ {
		if _, err := c.Do("INCR", "rlg:test:counter"); err != nil {
			t.Fatalf("INCR: %v", err)
		}
	}
	r, err := c.Do("GET", "rlg:test:counter")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	if r.Str != "5" {
		t.Fatalf("expected counter=5, got %q", r.Str)
	}
}
