package ratelimit

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ratelimitergateway/internal/model"
	"ratelimitergateway/internal/redisclient"
)

func testRedisAddr() string {
	if a := os.Getenv("REDIS_TEST_ADDR"); a != "" {
		return a
	}
	return "127.0.0.1:6379"
}

// newTestRedis returns an engine using a unique key prefix so tests never
// collide; it skips when Redis is unreachable.
func newTestRedis(t testing.TB) (*Redis, *redisclient.Client) {
	t.Helper()
	c := redisclient.New(testRedisAddr(), 16)
	if err := c.Ping(); err != nil {
		t.Skipf("SKIP: redis not reachable at %s: %v", testRedisAddr(), err)
	}
	t.Cleanup(c.Close)
	return NewRedis(c, fmt.Sprintf("rgtest:%d:", time.Now().UnixNano())), c
}

func TestRedisConformance(t *testing.T) {
	r, _ := newTestRedis(t)
	for _, a := range model.Algorithms {
		t.Run("exact/"+string(a), func(t *testing.T) { exactLimitTest(t, r, a) })
		t.Run("peek/"+string(a), func(t *testing.T) { peekTest(t, r, a) })
		t.Run("reset/"+string(a), func(t *testing.T) { resetTest(t, r, a) })
	}
	t.Run("release", func(t *testing.T) { releaseSlotTest(t, r) })
}

func TestRedisTwoInstancesShareState(t *testing.T) {
	r1, c := newTestRedis(t)
	c2 := redisclient.New(testRedisAddr(), 4)
	defer c2.Close()
	r2 := NewRedis(c2, r1.prefix)
	_ = c
	for _, a := range model.Algorithms {
		t.Run(string(a), func(t *testing.T) {
			p := Params{Algorithm: a, Limit: 20, Window: time.Hour}
			key := "shared-" + string(a)
			var allowed atomic.Int64
			var wg sync.WaitGroup
			for i := 0; i < 100; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					e := Engine(r1)
					if i%2 == 1 {
						e = r2
					}
					for j := 0; j < 3; j++ {
						d, err := e.Allow(ctx, key, p)
						if err != nil {
							t.Error(err)
							return
						}
						if d.Allowed {
							allowed.Add(1)
						}
					}
				}(i)
			}
			wg.Wait()
			if allowed.Load() != 20 {
				t.Fatalf("allowed %d across two engines, want exactly 20", allowed.Load())
			}
			// Each instance sees the other's consumption.
			if d, ok, _ := r2.Peek(ctx, key, p); !ok || d.Remaining != 0 {
				t.Fatalf("r2 peek: %+v ok=%v", d, ok)
			}
		})
	}
}

func TestRedisTokenBucketRefill(t *testing.T) {
	r, _ := newTestRedis(t)
	p := Params{Algorithm: model.AlgoTokenBucket, Limit: 10, Window: time.Second, Burst: 2}
	d, _ := r.Allow(ctx, "k", p)
	if !d.Allowed || d.Remaining != 1 || d.Limit != 2 {
		t.Fatalf("%+v", d)
	}
	r.Allow(ctx, "k", p)
	d, _ = r.Allow(ctx, "k", p)
	if d.Allowed || d.RetryAfter < 50*time.Millisecond || d.RetryAfter > 100*time.Millisecond {
		t.Fatalf("denied: %+v", d)
	}
	if d.ResetAfter < 150*time.Millisecond || d.ResetAfter > 200*time.Millisecond {
		t.Fatalf("ResetAfter (to full): %+v", d)
	}
	time.Sleep(d.RetryAfter + 20*time.Millisecond)
	if d, _ = r.Allow(ctx, "k", p); !d.Allowed {
		t.Fatalf("after wait: %+v", d)
	}
	// Oversize cost: denied, RetryAfter = time to full.
	big := p
	big.Cost = 3
	d, _ = r.Allow(ctx, "other", big)
	if d.Allowed || d.Remaining != 2 {
		t.Fatalf("oversize: %+v", d)
	}
}

func TestRedisFixedWindowAndLog(t *testing.T) {
	r, _ := newTestRedis(t)
	for _, a := range []model.Algorithm{model.AlgoFixedWindow, model.AlgoSlidingWindow, model.AlgoSlidingWindowCounter} {
		t.Run(string(a), func(t *testing.T) {
			p := Params{Algorithm: a, Limit: 2, Window: 600 * time.Millisecond}
			// Retry across a possible boundary: the fixed window may roll
			// early; assert only on the first denial that follows two allows.
			var denied Decision
			for attempt := 0; attempt < 5; attempt++ {
				key := fmt.Sprintf("k%d", attempt)
				a1, _ := r.Allow(ctx, key, p)
				a2, _ := r.Allow(ctx, key, p)
				d, _ := r.Allow(ctx, key, p)
				if a1.Allowed && a2.Allowed && !d.Allowed {
					denied = d
					time.Sleep(d.RetryAfter + 30*time.Millisecond)
					if d2, _ := r.Allow(ctx, key, p); !d2.Allowed {
						t.Fatalf("RetryAfter %v was not honoured: %+v", d.RetryAfter, d2)
					}
					break
				}
				time.Sleep(650 * time.Millisecond)
			}
			if denied.Limit != 2 || denied.RetryAfter <= 0 || denied.Remaining != 0 {
				t.Fatalf("never observed a clean denial: %+v", denied)
			}
		})
	}
}

func TestRedisConcurrencyLeaseExpiry(t *testing.T) {
	r, c := newTestRedis(t)
	p := Params{Algorithm: model.AlgoConcurrency, Limit: 1}
	if d, _ := r.Allow(ctx, "k", p); !d.Allowed {
		t.Fatal("first denied")
	}
	if d, _ := r.Allow(ctx, "k", p); d.Allowed {
		t.Fatal("second allowed")
	}
	// Key must carry a TTL no longer than the lease (crash safety).
	rep, err := c.Do("PTTL", r.redisKey(model.AlgoConcurrency, "k"))
	if err != nil || rep.Int <= 0 || rep.Int > concurrencyLeaseTTL.Milliseconds() {
		t.Fatalf("PTTL = %+v err=%v", rep, err)
	}
	// Simulate the lease expiring (crashed gateway): rewrite its score.
	key := r.redisKey(model.AlgoConcurrency, "k")
	if _, err := c.Eval(`local m = redis.call('ZRANGE', KEYS[1], 0, 0)[1]; redis.call('ZADD', KEYS[1], 1, m); return 1`, []string{key}, nil); err != nil {
		t.Fatal(err)
	}
	if d, _ := r.Allow(ctx, "k", p); !d.Allowed {
		t.Fatal("expired lease should free the slot")
	}
}

func TestRedisAllKeysHaveTTL(t *testing.T) {
	r, c := newTestRedis(t)
	for _, a := range model.Algorithms {
		p := Params{Algorithm: a, Limit: 5, Window: time.Minute}
		r.Allow(ctx, "ttl", p)
		rep, err := c.Do("PTTL", r.redisKey(a, "ttl"))
		if err != nil || rep.Int <= 0 {
			t.Errorf("%s: PTTL = %+v err=%v", a, rep, err)
		}
		r.Reset(ctx, "ttl", p)
	}
}

func TestRedisNoScriptFallback(t *testing.T) {
	r, c := newTestRedis(t)
	p := Params{Algorithm: model.AlgoFixedWindow, Limit: 5, Window: time.Minute}
	if _, err := r.Allow(ctx, "k", p); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do("SCRIPT", "FLUSH"); err != nil {
		t.Skipf("SCRIPT FLUSH not permitted: %v", err)
	}
	d, err := r.Allow(ctx, "k", p)
	if err != nil || !d.Allowed || d.Remaining != 3 {
		t.Fatalf("after SCRIPT FLUSH: %+v err=%v", d, err)
	}
}

func TestRedisMiscAndErrors(t *testing.T) {
	r, _ := newTestRedis(t)
	if r.Name() != "redis" || r.Healthy(ctx) != nil || r.Close() != nil {
		t.Fatal("name/health/close")
	}
	if _, err := r.Allow(ctx, "k", Params{Algorithm: model.AlgoFixedWindow}); err == nil {
		t.Fatal("expected invalid params error")
	}
	bad := NewRedis(redisclient.NewClient(redisclient.Options{Addr: "127.0.0.1:1", DialTimeout: 200 * time.Millisecond}), "x:")
	if err := bad.Healthy(ctx); err == nil {
		t.Fatal("expected unhealthy")
	}
	if _, err := bad.Allow(ctx, "k", Params{Algorithm: model.AlgoFixedWindow, Limit: 1, Window: time.Second}); err == nil {
		t.Fatal("expected backend error")
	}
}
