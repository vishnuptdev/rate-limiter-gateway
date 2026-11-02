package ratelimit

import (
	"errors"
	"fmt"
	"time"

	"ratelimitergateway/internal/model"
)

// ErrInvalidParams is wrapped by every error caused by bad Params.
var ErrInvalidParams = errors.New("ratelimit: invalid params")

// concurrencyLeaseTTL is how long a concurrency slot lives without being
// released. It makes the Redis engine crash-safe: a gateway that dies with
// requests in flight stops holding slots after this long. Requests that run
// longer than this lose their slot (their later Release is then a no-op or
// frees another lease; see the Redis engine docs).
const concurrencyLeaseTTL = 60 * time.Second

// concurrencyRetryHint is the RetryAfter / ResetAfter reported for the
// concurrency algorithm: slots free up when in-flight requests finish,
// which the engine cannot predict, so callers get a short fixed hint.
const concurrencyRetryHint = time.Second

// normalize validates p and applies defaults (Cost 0 => 1, Burst 0 => Limit).
func normalize(p Params) (Params, error) {
	if p.Limit <= 0 {
		return p, fmt.Errorf("%w: limit must be > 0", ErrInvalidParams)
	}
	if p.Cost < 0 {
		return p, fmt.Errorf("%w: cost must be >= 0", ErrInvalidParams)
	}
	if p.Cost == 0 {
		p.Cost = 1
	}
	switch p.Algorithm {
	case model.AlgoConcurrency:
		// Window and Burst are ignored.
	case model.AlgoTokenBucket, model.AlgoGCRA, model.AlgoLeakyBucket:
		if p.Burst < 0 {
			return p, fmt.Errorf("%w: burst must be >= 0", ErrInvalidParams)
		}
		if p.Burst == 0 {
			p.Burst = p.Limit
		}
		fallthrough
	case model.AlgoSlidingWindow, model.AlgoSlidingWindowCounter, model.AlgoFixedWindow:
		if p.Window < time.Millisecond {
			return p, fmt.Errorf("%w: window must be >= 1ms", ErrInvalidParams)
		}
	default:
		return p, fmt.Errorf("%w: unknown algorithm %q", ErrInvalidParams, p.Algorithm)
	}
	return p, nil
}

// decisionLimit is the Limit reported in a Decision: the burst capacity for
// the token bucket, GCRA and leaky bucket, Limit otherwise.
func decisionLimit(p Params) int {
	switch p.Algorithm {
	case model.AlgoTokenBucket, model.AlgoGCRA, model.AlgoLeakyBucket:
		return p.Burst
	}
	return p.Limit
}

// ceilMs rounds d up to a whole number of milliseconds (never negative).
func ceilMs(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	ms := (d + time.Millisecond - 1) / time.Millisecond
	return ms * time.Millisecond
}
