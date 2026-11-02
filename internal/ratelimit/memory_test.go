package ratelimit

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ratelimitergateway/internal/model"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	// Aligned to a whole second so window math is easy to reason about.
	return &fakeClock{t: time.Unix(1_700_000_000, 0)}
}
func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newTestMemory(t *testing.T, max int) (*Memory, *fakeClock) {
	t.Helper()
	clk := newFakeClock()
	m := NewMemory(MemoryOptions{MaxKeys: max, Now: clk.Now, GCInterval: time.Hour,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	t.Cleanup(func() { m.Close() })
	return m, clk
}

var ctx = context.Background()

func TestMemoryTokenBucket(t *testing.T) {
	p := Params{Algorithm: model.AlgoTokenBucket, Limit: 10, Window: time.Second, Burst: 5}
	m, clk := newTestMemory(t, 0)
	for i := 0; i < 5; i++ {
		d, err := m.Allow(ctx, "k", p)
		if err != nil || !d.Allowed || d.Remaining != 4-i || d.Limit != 5 {
			t.Fatalf("call %d: %+v %v", i, d, err)
		}
	}
	d, _ := m.Allow(ctx, "k", p)
	if d.Allowed || d.Remaining != 0 || d.RetryAfter != 100*time.Millisecond {
		t.Fatalf("expected denied retry 100ms, got %+v", d)
	}
	if d.ResetAfter != 500*time.Millisecond {
		t.Fatalf("ResetAfter (time until full) = %v want 500ms", d.ResetAfter)
	}
	clk.Advance(100 * time.Millisecond)
	if d, _ = m.Allow(ctx, "k", p); !d.Allowed || d.Remaining != 0 {
		t.Fatalf("after refill: %+v", d)
	}
	clk.Advance(10 * time.Second) // refill is capped at Burst
	d, _ = m.Allow(ctx, "k", p)
	if !d.Allowed || d.Remaining != 4 {
		t.Fatalf("cap: %+v", d)
	}
}

func TestMemoryTokenBucketCostAndOversize(t *testing.T) {
	p := Params{Algorithm: model.AlgoTokenBucket, Limit: 10, Window: time.Second, Cost: 3}
	m, _ := newTestMemory(t, 0)
	for i := 0; i < 3; i++ {
		if d, _ := m.Allow(ctx, "k", p); !d.Allowed {
			t.Fatalf("call %d denied", i)
		}
	}
	d, _ := m.Allow(ctx, "k", p) // 1 token left, need 3 => 2 more tokens = 200ms
	if d.Allowed || d.Remaining != 1 || d.RetryAfter != 200*time.Millisecond {
		t.Fatalf("%+v", d)
	}
	big := p
	big.Cost = 11
	d, _ = m.Allow(ctx, "fresh", big)
	if d.Allowed || d.RetryAfter != 0 || d.Remaining != 10 {
		// fresh bucket is already full: time to full is 0
		t.Fatalf("oversize on fresh: %+v", d)
	}
	m.Allow(ctx, "fresh", Params{Algorithm: p.Algorithm, Limit: 10, Window: time.Second, Cost: 4})
	d, _ = m.Allow(ctx, "fresh", big)
	if d.Allowed || d.RetryAfter != 400*time.Millisecond {
		t.Fatalf("oversize RetryAfter should be time to full (400ms): %+v", d)
	}
}

func TestMemorySlidingWindowLog(t *testing.T) {
	p := Params{Algorithm: model.AlgoSlidingWindow, Limit: 3, Window: time.Second}
	m, clk := newTestMemory(t, 0)
	for i := 0; i < 3; i++ {
		d, _ := m.Allow(ctx, "k", p)
		if !d.Allowed || d.Remaining != 2-i {
			t.Fatalf("call %d: %+v", i, d)
		}
		clk.Advance(100 * time.Millisecond)
	}
	// t=300ms: entries at 0,100,200.
	d, _ := m.Allow(ctx, "k", p)
	if d.Allowed || d.RetryAfter != 700*time.Millisecond || d.Remaining != 0 {
		t.Fatalf("denied: %+v", d)
	}
	if d.ResetAfter != 900*time.Millisecond {
		t.Fatalf("ResetAfter = %v", d.ResetAfter)
	}
	clk.Advance(700 * time.Millisecond) // t=1000ms: first entry (t=0) expired exactly
	d, _ = m.Allow(ctx, "k", p)
	if !d.Allowed || d.Remaining != 0 {
		t.Fatalf("after first expires: %+v", d)
	}
	clk.Advance(5 * time.Second)
	d, _ = m.Allow(ctx, "k", p)
	if !d.Allowed || d.Remaining != 2 {
		t.Fatalf("after full expiry: %+v", d)
	}
}

func TestMemorySlidingWindowCounter(t *testing.T) {
	p := Params{Algorithm: model.AlgoSlidingWindowCounter, Limit: 10, Window: time.Second}
	m, clk := newTestMemory(t, 0)
	for i := 0; i < 10; i++ {
		if d, _ := m.Allow(ctx, "k", p); !d.Allowed {
			t.Fatalf("call %d denied", i)
		}
	}
	d, _ := m.Allow(ctx, "k", p)
	if d.Allowed || d.RetryAfter != 1100*time.Millisecond || d.ResetAfter != 2*time.Second {
		t.Fatalf("same window full: %+v", d)
	}
	// 500ms into next window: weighted = 10*0.5 = 5 => 5 more allowed.
	clk.Advance(1500 * time.Millisecond)
	for i := 0; i < 5; i++ {
		if d, _ := m.Allow(ctx, "k", p); !d.Allowed {
			t.Fatalf("weighted call %d denied: %+v", i, d)
		}
	}
	d, _ = m.Allow(ctx, "k", p)
	if d.Allowed {
		t.Fatalf("6th should be denied: %+v", d)
	}
	// curr=5, prev=10; need weighted+1<=10 => 10*(1-f)+5<=9 => f>=0.6 => 100ms.
	if d.RetryAfter != 100*time.Millisecond {
		t.Fatalf("RetryAfter = %v want 100ms", d.RetryAfter)
	}
	clk.Advance(d.RetryAfter)
	if d, _ = m.Allow(ctx, "k", p); !d.Allowed {
		t.Fatalf("should be allowed at RetryAfter: %+v", d)
	}
	// Skipping a whole window forgets everything.
	clk.Advance(3 * time.Second)
	if d, _ = m.Allow(ctx, "k", p); !d.Allowed || d.Remaining != 9 {
		t.Fatalf("after idle: %+v", d)
	}
}

func TestMemoryFixedWindow(t *testing.T) {
	p := Params{Algorithm: model.AlgoFixedWindow, Limit: 3, Window: time.Second}
	m, clk := newTestMemory(t, 0)
	clk.Advance(400 * time.Millisecond) // 400ms into the window
	for i := 0; i < 3; i++ {
		d, _ := m.Allow(ctx, "k", p)
		if !d.Allowed || d.Remaining != 2-i || d.ResetAfter != 600*time.Millisecond {
			t.Fatalf("call %d: %+v", i, d)
		}
	}
	d, _ := m.Allow(ctx, "k", p)
	if d.Allowed || d.RetryAfter != 600*time.Millisecond || d.ResetAfter != 600*time.Millisecond {
		t.Fatalf("denied: %+v", d)
	}
	clk.Advance(600 * time.Millisecond)
	if d, _ = m.Allow(ctx, "k", p); !d.Allowed || d.Remaining != 2 {
		t.Fatalf("new window: %+v", d)
	}
}

func TestMemoryConcurrencyReleaseAndPeek(t *testing.T) {
	p := Params{Algorithm: model.AlgoConcurrency, Limit: 2}
	m, _ := newTestMemory(t, 0)
	m.Allow(ctx, "k", p)
	m.Allow(ctx, "k", p)
	if d, _ := m.Allow(ctx, "k", p); d.Allowed || d.Remaining != 0 || d.RetryAfter <= 0 {
		t.Fatalf("third: %+v", d)
	}
	if err := m.Release(ctx, "k", p); err != nil {
		t.Fatal(err)
	}
	if d, _ := m.Allow(ctx, "k", p); !d.Allowed {
		t.Fatalf("after release: %+v", d)
	}
	m.Release(ctx, "k", p)
	m.Release(ctx, "k", p)
	m.Release(ctx, "k", p) // extra release must not go negative
	if d, _, _ := m.Peek(ctx, "k", p); d.Remaining != 2 {
		t.Fatalf("peek after drain: %+v", d)
	}
}

func TestMemoryNormalizeErrors(t *testing.T) {
	m, _ := newTestMemory(t, 0)
	cases := map[string]Params{
		"zero limit":     {Algorithm: model.AlgoFixedWindow, Window: time.Second},
		"zero window":    {Algorithm: model.AlgoFixedWindow, Limit: 1},
		"neg cost":       {Algorithm: model.AlgoFixedWindow, Limit: 1, Window: time.Second, Cost: -1},
		"unknown algo":   {Algorithm: "nope", Limit: 1, Window: time.Second},
		"negative burst": {Algorithm: model.AlgoTokenBucket, Limit: 1, Window: time.Second, Burst: -1},
	}
	for name, p := range cases {
		if _, err := m.Allow(ctx, "k", p); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestMemoryGC(t *testing.T) {
	m, clk := newTestMemory(t, 0)
	p := Params{Algorithm: model.AlgoFixedWindow, Limit: 1, Window: time.Second}
	m.Allow(ctx, "a", p)
	m.Allow(ctx, "b", p)
	clk.Advance(1500 * time.Millisecond)
	if n := m.gc(); n != 0 {
		t.Fatalf("not idle long enough, removed %d", n)
	}
	m.Allow(ctx, "b", p) // touch b
	clk.Advance(1500 * time.Millisecond)
	if n := m.gc(); n != 1 || m.KeyCount() != 1 {
		t.Fatalf("removed=%d keys=%d, want 1/1", n, m.KeyCount())
	}
	// An in-flight concurrency key is never collected.
	cp := Params{Algorithm: model.AlgoConcurrency, Limit: 5}
	m.Allow(ctx, "c", cp)
	clk.Advance(time.Hour)
	m.gc()
	if d, ok, _ := m.Peek(ctx, "c", cp); !ok || d.Remaining != 4 {
		t.Fatalf("in-flight key GCed: %+v ok=%v", d, ok)
	}
}

func TestMemoryMaxKeys(t *testing.T) {
	m, _ := newTestMemory(t, 2)
	p := Params{Algorithm: model.AlgoFixedWindow, Limit: 1, Window: time.Hour}
	for _, k := range []string{"a", "b"} {
		if d, _ := m.Allow(ctx, k, p); !d.Allowed {
			t.Fatal("tracked key denied")
		}
	}
	// Over cap: always allowed (fresh, untracked), never stored.
	for i := 0; i < 3; i++ {
		if d, _ := m.Allow(ctx, "overflow", p); !d.Allowed {
			t.Fatalf("untracked key should be allowed, got %+v", d)
		}
	}
	if m.KeyCount() != 2 {
		t.Fatalf("KeyCount = %d", m.KeyCount())
	}
	if d, _ := m.Allow(ctx, "a", p); d.Allowed {
		t.Fatal("tracked key must still be limited")
	}
	m.Reset(ctx, "a", p)
	if m.KeyCount() != 1 {
		t.Fatalf("after reset KeyCount = %d", m.KeyCount())
	}
}

// TestMemoryConcurrentExactLimit hammers every algorithm with 100
// goroutines; exactly Limit requests must be admitted (the clock is frozen,
// so no refill / window roll can happen).
func TestMemoryConcurrentExactLimit(t *testing.T) {
	for _, a := range model.Algorithms {
		t.Run(string(a), func(t *testing.T) {
			m, _ := newTestMemory(t, 0)
			exactLimitTest(t, m, a)
		})
	}
}

func exactLimitTest(t *testing.T, e Engine, a model.Algorithm) {
	t.Helper()
	const limit, workers, perWorker = 37, 100, 5
	p := Params{Algorithm: a, Limit: limit, Window: time.Hour}
	key := fmt.Sprintf("exact-%s-%d", a, time.Now().UnixNano())
	var allowed atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				d, err := e.Allow(ctx, key, p)
				if err != nil {
					t.Error(err)
					return
				}
				if d.Remaining < 0 {
					t.Errorf("negative remaining %+v", d)
				}
				if d.Allowed {
					allowed.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	if allowed.Load() != limit {
		t.Fatalf("allowed %d, want exactly %d", allowed.Load(), limit)
	}
	e.Reset(ctx, key, p)
}

func TestMemoryPeekDoesNotConsume(t *testing.T) {
	for _, a := range model.Algorithms {
		t.Run(string(a), func(t *testing.T) {
			m, _ := newTestMemory(t, 0)
			peekTest(t, m, a)
		})
	}
}

func peekTest(t *testing.T, e Engine, a model.Algorithm) {
	t.Helper()
	p := Params{Algorithm: a, Limit: 3, Window: time.Hour}
	key := fmt.Sprintf("peek-%s-%d", a, time.Now().UnixNano())
	defer e.Reset(ctx, key, p)
	d, ok, err := e.Peek(ctx, key, p)
	if err != nil || ok || !d.Allowed || d.Remaining != 3 {
		t.Fatalf("fresh peek: %+v ok=%v err=%v", d, ok, err)
	}
	if _, err := e.Allow(ctx, key, p); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		d, ok, err = e.Peek(ctx, key, p)
		if err != nil || !ok || !d.Allowed || d.Remaining != 2 {
			t.Fatalf("peek %d: %+v ok=%v err=%v", i, d, ok, err)
		}
	}
	// Two more Allows still succeed => the peeks consumed nothing.
	for i := 0; i < 2; i++ {
		if d, _ := e.Allow(ctx, key, p); !d.Allowed {
			t.Fatalf("allow after peeks denied: %+v", d)
		}
	}
	d, ok, _ = e.Peek(ctx, key, p)
	if !ok || d.Allowed || d.Remaining != 0 {
		t.Fatalf("exhausted peek: %+v", d)
	}
}

func TestMemoryResetAllAlgorithms(t *testing.T) {
	for _, a := range model.Algorithms {
		t.Run(string(a), func(t *testing.T) {
			m, _ := newTestMemory(t, 0)
			resetTest(t, m, a)
		})
	}
}

func resetTest(t *testing.T, e Engine, a model.Algorithm) {
	t.Helper()
	p := Params{Algorithm: a, Limit: 2, Window: time.Hour}
	key := fmt.Sprintf("reset-%s-%d", a, time.Now().UnixNano())
	e.Allow(ctx, key, p)
	e.Allow(ctx, key, p)
	if d, _ := e.Allow(ctx, key, p); d.Allowed {
		t.Fatalf("should be exhausted: %+v", d)
	}
	if err := e.Reset(ctx, key, p); err != nil {
		t.Fatal(err)
	}
	if d, ok, _ := e.Peek(ctx, key, p); ok || d.Remaining != 2 {
		t.Fatalf("after reset: %+v ok=%v", d, ok)
	}
	if d, _ := e.Allow(ctx, key, p); !d.Allowed {
		t.Fatalf("allow after reset: %+v", d)
	}
	e.Reset(ctx, key, p)
}

func TestMemoryReleaseConcurrentSlots(t *testing.T) {
	m, _ := newTestMemory(t, 0)
	releaseSlotTest(t, m)
}

func releaseSlotTest(t *testing.T, e Engine) {
	t.Helper()
	p := Params{Algorithm: model.AlgoConcurrency, Limit: 3}
	key := fmt.Sprintf("rel-%d", time.Now().UnixNano())
	defer e.Reset(ctx, key, p)
	for i := 0; i < 3; i++ {
		if d, _ := e.Allow(ctx, key, p); !d.Allowed {
			t.Fatalf("slot %d denied", i)
		}
	}
	if d, _ := e.Allow(ctx, key, p); d.Allowed {
		t.Fatal("4th slot should be denied")
	}
	if err := e.Release(ctx, key, p); err != nil {
		t.Fatal(err)
	}
	if d, _ := e.Allow(ctx, key, p); !d.Allowed {
		t.Fatal("released slot not reusable")
	}
	if d, _ := e.Allow(ctx, key, p); d.Allowed {
		t.Fatal("over limit after reuse")
	}
	// Release on a non-concurrency algorithm is a no-op.
	if err := e.Release(ctx, key, Params{Algorithm: model.AlgoFixedWindow, Limit: 1, Window: time.Second}); err != nil {
		t.Fatal(err)
	}
}

func TestMemoryMisc(t *testing.T) {
	m, _ := newTestMemory(t, 0)
	if m.Name() != "memory" || m.Healthy(ctx) != nil {
		t.Fatal("name/health")
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil { // idempotent
		t.Fatal(err)
	}
}
