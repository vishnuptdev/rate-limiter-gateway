package limiter

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestTokenBucket_ConcurrentRespectsLimit fires many goroutines at a single
// key simultaneously and checks that no more than `burst` of them are
// allowed -- the thing that actually matters for a rate limiter under
// concurrency, and the thing -race is here to catch data races in.
func TestTokenBucket_ConcurrentRespectsLimit(t *testing.T) {
	tb := NewTokenBucket(1, 10) // slow refill, so within this test only the initial burst matters
	var allowed int64
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := tb.Allow("k1")
			if err != nil {
				t.Errorf("Allow: %v", err)
				return
			}
			if res.Allowed {
				atomic.AddInt64(&allowed, 1)
			}
		}()
	}
	wg.Wait()
	if allowed > 10 {
		t.Fatalf("expected at most 10 allowed requests (burst), got %d", allowed)
	}
	if allowed == 0 {
		t.Fatal("expected at least some requests to be allowed")
	}
}

func TestTokenBucket_RefillsOverTime(t *testing.T) {
	tb := NewTokenBucket(100, 1) // 100 tokens/sec, burst of 1
	res, err := tb.Allow("k")
	if err != nil || !res.Allowed {
		t.Fatalf("expected first request allowed, got %+v err=%v", res, err)
	}
	res, err = tb.Allow("k")
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if res.Allowed {
		t.Fatal("expected second immediate request to be denied (burst exhausted)")
	}
	if res.RetryAfter <= 0 {
		t.Fatal("expected a positive RetryAfter when denied")
	}

	time.Sleep(20 * time.Millisecond) // >= 2 tokens worth at 100/sec
	res, err = tb.Allow("k")
	if err != nil || !res.Allowed {
		t.Fatalf("expected request allowed after refill window, got %+v err=%v", res, err)
	}
}

func TestTokenBucket_IndependentKeys(t *testing.T) {
	tb := NewTokenBucket(1, 1)
	r1, _ := tb.Allow("a")
	r2, _ := tb.Allow("b")
	if !r1.Allowed || !r2.Allowed {
		t.Fatal("expected independent keys to each get their own bucket")
	}
}

func TestSlidingWindow_ConcurrentRespectsLimit(t *testing.T) {
	sw := NewSlidingWindow(10, time.Minute)
	var allowed int64
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := sw.Allow("k1")
			if err != nil {
				t.Errorf("Allow: %v", err)
				return
			}
			if res.Allowed {
				atomic.AddInt64(&allowed, 1)
			}
		}()
	}
	wg.Wait()
	if allowed != 10 {
		t.Fatalf("expected exactly 10 allowed requests within the window, got %d", allowed)
	}
}

func TestSlidingWindow_ExpiresOldEntries(t *testing.T) {
	sw := NewSlidingWindow(1, 20*time.Millisecond)
	r1, _ := sw.Allow("k")
	if !r1.Allowed {
		t.Fatal("expected first request allowed")
	}
	r2, _ := sw.Allow("k")
	if r2.Allowed {
		t.Fatal("expected second immediate request denied (limit=1)")
	}
	time.Sleep(30 * time.Millisecond)
	r3, _ := sw.Allow("k")
	if !r3.Allowed {
		t.Fatal("expected request allowed after the window elapsed")
	}
}

func TestSlidingWindow_Usage(t *testing.T) {
	sw := NewSlidingWindow(5, time.Minute)
	sw.Allow("k")
	sw.Allow("k")
	remaining, limit, ok := sw.Usage("k")
	if !ok {
		t.Fatal("expected Usage to report data for a used key")
	}
	if limit != 5 || remaining != 3 {
		t.Fatalf("expected remaining=3 limit=5, got remaining=%d limit=%d", remaining, limit)
	}
}
