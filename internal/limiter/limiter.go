// Package limiter implements two rate-limiting strategies (token bucket and
// sliding window), each available in an in-process (single-instance)
// flavor and a Redis-backed flavor for sharing limits across multiple
// gateway instances.
package limiter

import "time"

// Result is the outcome of a single Allow check.
type Result struct {
	Allowed    bool
	Remaining  int           // tokens/requests remaining in the current window/bucket
	RetryAfter time.Duration // only meaningful when Allowed == false
}

// Limiter decides whether a request identified by key may proceed.
type Limiter interface {
	Allow(key string) (Result, error)
	// Usage reports current state for a key, for the metrics endpoint.
	// ok is false if the key has no recorded usage yet.
	Usage(key string) (remaining int, limit int, ok bool)
}
