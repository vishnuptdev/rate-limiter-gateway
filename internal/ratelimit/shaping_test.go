package ratelimit

import (
	"fmt"
	"testing"
	"time"

	"ratelimitergateway/internal/model"
)

func TestMemoryGCRA(t *testing.T) {
	// T = 100ms, tolerance = 4*T => burst of 5.
	p := Params{Algorithm: model.AlgoGCRA, Limit: 10, Window: time.Second, Burst: 5}
	m, clk := newTestMemory(t, 0)
	for i := 0; i < 5; i++ {
		d, err := m.Allow(ctx, "k", p)
		if err != nil || !d.Allowed || d.Remaining != 4-i || d.Limit != 5 || d.Delay != 0 {
			t.Fatalf("call %d: %+v %v", i, d, err)
		}
	}
	d, _ := m.Allow(ctx, "k", p)
	if d.Allowed || d.Remaining != 0 || d.RetryAfter != 100*time.Millisecond || d.ResetAfter != 500*time.Millisecond {
		t.Fatalf("expected denied retry 100ms reset 500ms, got %+v", d)
	}
	clk.Advance(99 * time.Millisecond)
	if d, _ = m.Allow(ctx, "k", p); d.Allowed || d.RetryAfter != time.Millisecond {
		t.Fatalf("1ms early: %+v", d)
	}
	clk.Advance(time.Millisecond)
	if d, _ = m.Allow(ctx, "k", p); !d.Allowed || d.Remaining != 0 {
		t.Fatalf("after one interval: %+v", d)
	}
	clk.Advance(time.Hour) // credit is capped at Burst
	if d, _ = m.Allow(ctx, "k", p); !d.Allowed || d.Remaining != 4 {
		t.Fatalf("cap: %+v", d)
	}
	// Cost > Burst can never fit.
	if d, _ = m.Allow(ctx, "k", Params{Algorithm: model.AlgoGCRA, Limit: 10, Window: time.Second, Burst: 5, Cost: 6}); d.Allowed {
		t.Fatalf("oversize cost allowed: %+v", d)
	}
	// Burst 0 defaults to Limit; Peek does not consume.
	q := Params{Algorithm: model.AlgoGCRA, Limit: 3, Window: time.Second}
	for i := 0; i < 2; i++ {
		if d, ok, _ := m.Peek(ctx, "fresh", q); ok || !d.Allowed || d.Remaining != 3 || d.Limit != 3 {
			t.Fatalf("peek %d: %+v ok=%v", i, d, ok)
		}
	}
}

func TestMemoryLeakyBucketQueue(t *testing.T) {
	// Drain 1 request per 100ms, queue of 3.
	p := Params{Algorithm: model.AlgoLeakyBucket, Limit: 10, Window: time.Second, Burst: 3}
	m, clk := newTestMemory(t, 0)
	wantDelay := []time.Duration{0, 100 * time.Millisecond, 200 * time.Millisecond}
	for i, w := range wantDelay {
		d, _ := m.Allow(ctx, "k", p)
		if !d.Allowed || d.Delay != w || d.Remaining != 2-i || d.Limit != 3 {
			t.Fatalf("call %d: %+v want delay %v", i, d, w)
		}
	}
	d, _ := m.Allow(ctx, "k", p)
	if d.Allowed || d.Delay != 0 || d.RetryAfter != 100*time.Millisecond {
		t.Fatalf("queue full: %+v", d)
	}
	clk.Advance(100 * time.Millisecond) // one slot drained
	if d, _ = m.Allow(ctx, "k", p); !d.Allowed || d.Delay != 200*time.Millisecond {
		t.Fatalf("after drain: %+v", d)
	}
	clk.Advance(time.Second) // fully drained: no delay again
	if d, _ = m.Allow(ctx, "k", p); !d.Allowed || d.Delay != 0 {
		t.Fatalf("idle: %+v", d)
	}
	if d, ok, _ := m.Peek(ctx, "k", p); !ok || !d.Allowed || d.Delay != 100*time.Millisecond {
		t.Fatalf("peek: %+v ok=%v", d, ok)
	}
}

func TestMemoryShapingIdleGCAndEviction(t *testing.T) {
	for _, a := range []model.Algorithm{model.AlgoGCRA, model.AlgoLeakyBucket} {
		t.Run(string(a), func(t *testing.T) {
			m, clk := newTestMemory(t, 0)
			p := Params{Algorithm: a, Limit: 10, Window: time.Hour, Burst: 5}
			m.Allow(ctx, "a", p)
			m.gc()
			if m.KeyCount() != 1 {
				t.Fatal("entry with backlog must not be collected")
			}
			clk.Advance(time.Hour/10 + time.Millisecond) // backlog (one interval) drained
			if n := m.gc(); n != 1 {
				t.Fatalf("fully replenished entry should be collected, removed %d", n)
			}

			// Key cap: replenished entries are evicted losslessly, busy ones
			// push new keys into shared (still limited) overflow buckets.
			m2, clk2 := newTestMemory(t, 1)
			m2.Allow(ctx, "x", p)
			clk2.Advance(time.Hour)
			// Eviction is per shard: pick a new key in x's shard.
			y := "y"
			for i := 0; m2.shardFor(storeKey(a, y)) != m2.shardFor(storeKey(a, "x")); i++ {
				y = fmt.Sprintf("y%d", i)
			}
			m2.Allow(ctx, y, p)
			if m2.KeyCount() != 1 || m2.OverflowCount() != 0 {
				t.Fatalf("lossless eviction expected: keys=%d overflow=%d", m2.KeyCount(), m2.OverflowCount())
			}
			one := Params{Algorithm: a, Limit: 1, Window: time.Hour}
			m2.Allow(ctx, y, one)
			allowed := 0
			for i := 0; i < 20000; i++ {
				if d, _ := m2.Allow(ctx, fmt.Sprintf("flood-%d", i), one); d.Allowed {
					allowed++
				}
			}
			if allowed > overflowBuckets || m2.OverflowCount() == 0 {
				t.Fatalf("flood allowed=%d overflow=%d", allowed, m2.OverflowCount())
			}
		})
	}
}

func TestRedisShapingSharedAndDelay(t *testing.T) {
	r, _ := newTestRedis(t)
	// Slow drain so wall-clock progress during the test is negligible.
	p := Params{Algorithm: model.AlgoLeakyBucket, Limit: 1, Window: 10 * time.Second, Burst: 3}
	for i := 0; i < 3; i++ {
		d, err := r.Allow(ctx, "lb", p)
		want := time.Duration(i) * 10 * time.Second
		if err != nil || !d.Allowed || d.Delay < want-100*time.Millisecond || d.Delay > want || d.Remaining != 2-i {
			t.Fatalf("call %d: %+v %v want delay ~%v", i, d, err, want)
		}
	}
	d, _ := r.Allow(ctx, "lb", p)
	if d.Allowed || d.RetryAfter <= 0 || d.RetryAfter > 10*time.Second {
		t.Fatalf("queue full: %+v", d)
	}
	g := Params{Algorithm: model.AlgoGCRA, Limit: 1, Window: 10 * time.Second, Burst: 2}
	for i := 0; i < 2; i++ {
		if d, _ := r.Allow(ctx, "g", g); !d.Allowed || d.Delay != 0 {
			t.Fatalf("gcra %d: %+v", i, d)
		}
	}
	if d, _ := r.Allow(ctx, "g", g); d.Allowed {
		t.Fatalf("gcra third: %+v", d)
	}
}
