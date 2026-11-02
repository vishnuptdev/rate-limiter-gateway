// Package ratelimit provides rate-limiting engines. An Engine is stateless
// with respect to configuration: every call carries its own Params, so one
// engine instance serves every policy, plan and consumer override and
// config changes take effect instantly without rebuilding limiters.
package ratelimit

import (
	"context"
	"time"

	"ratelimitergateway/internal/model"
)

// Params describes the limit to apply for a single call.
type Params struct {
	Algorithm model.Algorithm
	Limit     int           // requests per Window (concurrency: max in-flight)
	Window    time.Duration // ignored by concurrency
	Burst     int           // token bucket capacity; 0 => Limit
	Cost      int           // units to consume; 0 => 1
}

// Decision is the outcome of a check.
type Decision struct {
	Allowed    bool
	Limit      int           // effective limit (token bucket: Burst)
	Remaining  int           // units left after this call (never negative)
	ResetAfter time.Duration // time until the bucket/window is fully replenished
	RetryAfter time.Duration // when !Allowed: earliest time a retry could succeed
}

// Engine checks and consumes rate limits. Implementations must be safe for
// concurrent use and, for distributed engines, atomic across processes.
//
// key is fully namespaced by the caller (e.g. "<policyID>:<compositeKey>");
// engines add only their own storage prefix.
type Engine interface {
	// Allow consumes p.Cost units if available.
	Allow(ctx context.Context, key string, p Params) (Decision, error)
	// Peek reports the current state without consuming. ok=false if the key
	// has no state yet (Decision then describes a fresh bucket).
	Peek(ctx context.Context, key string, p Params) (d Decision, ok bool, err error)
	// Release returns one in-flight slot for AlgoConcurrency (no-op for
	// other algorithms). Callers must call it exactly once per allowed
	// concurrency Allow, typically in a defer after the upstream responds.
	Release(ctx context.Context, key string, p Params) error
	// Reset deletes all state for key under the given algorithm.
	Reset(ctx context.Context, key string, p Params) error
	// Name is "memory" or "redis".
	Name() string
	// Healthy reports backend reachability (always nil for memory).
	Healthy(ctx context.Context) error
	// Close releases resources (background GC goroutines, connections).
	Close() error
}
