package limiter

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ratelimitergateway/internal/redisclient"
)

func newTestRedisClient(t *testing.T) *redisclient.Client {
	t.Helper()
	addr := os.Getenv("REDIS_TEST_ADDR")
	if addr == "" {
		addr = "127.0.0.1:6379"
	}
	rc := redisclient.New(addr, 8)
	if err := rc.Ping(); err != nil {
		t.Skipf("SKIP: redis not reachable at %s: %v", addr, err)
	}
	return rc
}

// TestRedisTokenBucket_SharedAcrossTwoInstances is the key "genuinely
// distributed" test: it builds TWO separate RedisTokenBucket instances
// (standing in for two separate gateway processes) pointed at the same
// Redis, hammers the SAME key from both concurrently, and checks the
// total number of allowed requests never exceeds the shared burst -- i.e.
// the limit is enforced globally, not per-instance.
func TestRedisTokenBucket_SharedAcrossTwoInstances(t *testing.T) {
	rc := newTestRedisClient(t)
	defer rc.Close()
	prefix := fmt.Sprintf("rlgtest:%d:", time.Now().UnixNano())

	instanceA := NewRedisTokenBucket(rc, 1, 10, prefix) // 10-token burst, slow refill
	instanceB := NewRedisTokenBucket(rc, 1, 10, prefix) // same key prefix = same shared bucket

	var allowed int64
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(useA bool) {
			defer wg.Done()
			var res Result
			var err error
			if useA {
				res, err = instanceA.Allow("shared-key")
			} else {
				res, err = instanceB.Allow("shared-key")
			}
			if err != nil {
				t.Errorf("Allow: %v", err)
				return
			}
			if res.Allowed {
				atomic.AddInt64(&allowed, 1)
			}
		}(i%2 == 0)
	}
	wg.Wait()

	if allowed > 10 {
		t.Fatalf("expected at most 10 allowed requests shared across both instances, got %d -- limit is NOT being shared", allowed)
	}
	if allowed == 0 {
		t.Fatal("expected at least some requests allowed")
	}
}

func TestRedisTokenBucket_Basic(t *testing.T) {
	rc := newTestRedisClient(t)
	defer rc.Close()
	prefix := fmt.Sprintf("rlgtest:%d:", time.Now().UnixNano())
	tb := NewRedisTokenBucket(rc, 100, 2, prefix)

	r1, err := tb.Allow("k")
	if err != nil || !r1.Allowed {
		t.Fatalf("expected first request allowed, got %+v err=%v", r1, err)
	}
	r2, err := tb.Allow("k")
	if err != nil || !r2.Allowed {
		t.Fatalf("expected second request allowed (burst=2), got %+v err=%v", r2, err)
	}
	r3, err := tb.Allow("k")
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if r3.Allowed {
		t.Fatal("expected third immediate request denied (burst exhausted)")
	}
}

func TestRedisSlidingWindow_SharedAcrossTwoInstances(t *testing.T) {
	rc := newTestRedisClient(t)
	defer rc.Close()
	prefix := fmt.Sprintf("rlgtest:%d:", time.Now().UnixNano())

	instanceA := NewRedisSlidingWindow(rc, 10, time.Minute, prefix)
	instanceB := NewRedisSlidingWindow(rc, 10, time.Minute, prefix)

	var allowed int64
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(useA bool) {
			defer wg.Done()
			var res Result
			var err error
			if useA {
				res, err = instanceA.Allow("shared-key")
			} else {
				res, err = instanceB.Allow("shared-key")
			}
			if err != nil {
				t.Errorf("Allow: %v", err)
				return
			}
			if res.Allowed {
				atomic.AddInt64(&allowed, 1)
			}
		}(i%2 == 0)
	}
	wg.Wait()

	if allowed != 10 {
		t.Fatalf("expected exactly 10 allowed requests shared across both instances, got %d", allowed)
	}
}

func TestRedisSlidingWindow_ExpiresOldEntries(t *testing.T) {
	rc := newTestRedisClient(t)
	defer rc.Close()
	prefix := fmt.Sprintf("rlgtest:%d:", time.Now().UnixNano())
	sw := NewRedisSlidingWindow(rc, 1, 50*time.Millisecond, prefix)

	r1, err := sw.Allow("k")
	if err != nil || !r1.Allowed {
		t.Fatalf("expected first request allowed, got %+v err=%v", r1, err)
	}
	r2, _ := sw.Allow("k")
	if r2.Allowed {
		t.Fatal("expected second immediate request denied")
	}
	time.Sleep(70 * time.Millisecond)
	r3, err := sw.Allow("k")
	if err != nil || !r3.Allowed {
		t.Fatalf("expected request allowed after window elapsed, got %+v err=%v", r3, err)
	}
}
