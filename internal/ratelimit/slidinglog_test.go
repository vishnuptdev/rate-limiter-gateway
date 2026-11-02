package ratelimit

import (
	"math/rand/v2"
	"testing"
	"time"

	"ratelimitergateway/internal/model"
)

// refLog is a naive sliding-window log: it recounts every record on each
// call. The memory engine keeps a running sum instead; both must agree.
type refLog struct {
	recs []logRec
}

func (r *refLog) allow(p Params, now int64) (allowed bool, remaining int) {
	win := int64(p.Window)
	kept := r.recs[:0:0]
	for _, x := range r.recs {
		if x.ns > now-win {
			kept = append(kept, x)
		}
	}
	r.recs = kept
	count := 0
	for _, x := range r.recs {
		count += x.n
	}
	allowed = p.Cost <= p.Limit && count+p.Cost <= p.Limit
	if allowed {
		r.recs = append(r.recs, logRec{ns: now, n: p.Cost})
		count += p.Cost
	}
	return allowed, max(0, p.Limit-count)
}

func TestSlidingLogMatchesNaiveReference(t *testing.T) {
	m, clk := newTestMemory(t, 0)
	rng := rand.New(rand.NewPCG(1, 2))
	ref := &refLog{}
	limits := []int{3, 5, 10, 4}
	windows := []time.Duration{time.Second, 500 * time.Millisecond, 2 * time.Second}
	limit, window := 5, time.Second
	for i := 0; i < 5000; i++ {
		// Every so often change the limit and/or window between calls
		// (plan/consumer overrides can do this for the same key).
		if i%97 == 0 {
			limit = limits[rng.IntN(len(limits))]
		}
		if i%131 == 0 {
			window = windows[rng.IntN(len(windows))]
		}
		clk.Advance(time.Duration(rng.IntN(150)) * time.Millisecond)
		p := Params{Algorithm: model.AlgoSlidingWindow, Limit: limit, Window: window, Cost: 1 + rng.IntN(4)}
		if rng.IntN(20) == 0 {
			p.Cost = limit + 1 // can never fit
		}
		d, err := m.Allow(ctx, "k", p)
		if err != nil {
			t.Fatal(err)
		}
		wantOK, wantRem := ref.allow(p, clk.Now().UnixNano())
		if d.Allowed != wantOK || d.Remaining != wantRem {
			t.Fatalf("step %d %+v: got allowed=%v remaining=%d, reference allowed=%v remaining=%d",
				i, p, d.Allowed, d.Remaining, wantOK, wantRem)
		}
	}
}

func TestSlidingLogCostAndLimitChange(t *testing.T) {
	m, clk := newTestMemory(t, 0)
	p := Params{Algorithm: model.AlgoSlidingWindow, Limit: 10, Window: time.Second, Cost: 4}
	for i, want := range []struct {
		ok  bool
		rem int
	}{{true, 6}, {true, 2}, {false, 2}} {
		d, _ := m.Allow(ctx, "c", p)
		if d.Allowed != want.ok || d.Remaining != want.rem {
			t.Fatalf("call %d: %+v", i, d)
		}
	}
	// Lowering the limit below what is already used denies everything and
	// reports 0 remaining; raising it again uses the same 8 recorded units.
	p.Limit, p.Cost = 5, 1
	if d, _ := m.Allow(ctx, "c", p); d.Allowed || d.Remaining != 0 {
		t.Fatalf("lowered limit: %+v", d)
	}
	p.Limit = 9
	if d, _ := m.Allow(ctx, "c", p); !d.Allowed || d.Remaining != 0 {
		t.Fatalf("raised limit: %+v", d)
	}
	// After the window the units expire and the full limit is back.
	clk.Advance(time.Second + time.Millisecond)
	p.Cost = 9
	if d, _ := m.Allow(ctx, "c", p); !d.Allowed || d.Remaining != 0 {
		t.Fatalf("after window: %+v", d)
	}
}
