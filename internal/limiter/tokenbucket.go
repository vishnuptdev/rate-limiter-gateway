package limiter

import (
	"math"
	"sync"
	"time"
)

// TokenBucket is an in-process (single-instance) token bucket limiter,
// safe for concurrent use. Each key gets its own bucket that refills at
// `rate` tokens/second up to `burst` tokens.
type TokenBucket struct {
	rate  float64
	burst int
	mu    sync.Mutex
	state map[string]*bucketState
	now   func() time.Time // overridable for tests
}

type bucketState struct {
	tokens     float64
	lastRefill time.Time
}

func NewTokenBucket(rate float64, burst int) *TokenBucket {
	return &TokenBucket{rate: rate, burst: burst, state: make(map[string]*bucketState), now: time.Now}
}

func (b *TokenBucket) Allow(key string) (Result, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	st, ok := b.state[key]
	if !ok {
		st = &bucketState{tokens: float64(b.burst), lastRefill: now}
		b.state[key] = st
	} else {
		elapsed := now.Sub(st.lastRefill).Seconds()
		st.tokens = math.Min(float64(b.burst), st.tokens+elapsed*b.rate)
		st.lastRefill = now
	}

	if st.tokens >= 1 {
		st.tokens -= 1
		return Result{Allowed: true, Remaining: int(st.tokens)}, nil
	}

	deficit := 1 - st.tokens
	retryAfter := time.Duration(deficit / b.rate * float64(time.Second))
	return Result{Allowed: false, Remaining: 0, RetryAfter: retryAfter}, nil
}

func (b *TokenBucket) Usage(key string) (remaining int, limit int, ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	st, exists := b.state[key]
	if !exists {
		return b.burst, b.burst, false
	}
	// Report tokens as of last check without mutating state (no refill here;
	// this is a read for /metrics, not a consumption).
	return int(st.tokens), b.burst, true
}
