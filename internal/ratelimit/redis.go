package ratelimit

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"ratelimitergateway/internal/model"
	"ratelimitergateway/internal/redisclient"
)

type script struct {
	body string
	sha  string
}

func newScript(body string) script {
	sum := sha1.Sum([]byte(body))
	return script{body: body, sha: hex.EncodeToString(sum[:])}
}

var (
	scTokenBucket     = newScript(luaTokenBucket)
	scSlidingLog      = newScript(luaSlidingLog)
	scSlidingCounter  = newScript(luaSlidingCounter)
	scFixedWindow     = newScript(luaFixedWindow)
	scConcurrency     = newScript(luaConcurrency)
	scConcurrencyRel  = newScript(luaConcurrencyRelease)
	errBadScriptReply = fmt.Errorf("ratelimit: unexpected script reply")
)

// Redis is a distributed Engine: every decision is one atomic Lua script
// that reads the Redis server clock (TIME), so all gateway instances sharing
// a Redis agree regardless of local clock skew. Requires Redis >= 5.
//
// Key layout: "<prefix><algorithm>:<key>"; every key carries a PEXPIRE.
//
// Concurrency: slots are ZSET members "<nonce>:<i>" scored by lease expiry
// (now + 60s). The Engine API has no lease handle, so Release removes the
// member closest to expiry (the oldest lease) after discarding expired ones.
// Because members are interchangeable this is equivalent for counting; the
// only effect is that a request running longer than the 60s lease can have
// its slot reclaimed (crash safety) and its late Release then frees a
// different live lease. Size the lease with that in mind: it bounds how long
// a crashed gateway can pin slots.
type Redis struct {
	c      *redisclient.Client
	prefix string
}

// NewRedis creates a Redis engine. prefix is prepended to every key (for
// example "rateguard:"). The client is not closed by Close (the caller owns it).
func NewRedis(c *redisclient.Client, prefix string) *Redis {
	return &Redis{c: c, prefix: prefix}
}

func (r *Redis) Name() string { return "redis" }

func (r *Redis) Healthy(ctx context.Context) error { return r.c.PingContext(ctx) }

// Close is a no-op: the redisclient.Client is owned by the caller.
func (r *Redis) Close() error { return nil }

func (r *Redis) redisKey(a model.Algorithm, key string) string {
	return r.prefix + string(a) + ":" + key
}

// run executes sc with EVALSHA, falling back to EVAL (which also caches the
// script) on NOSCRIPT, e.g. after SCRIPT FLUSH or a Redis restart.
func (r *Redis) run(ctx context.Context, sc script, key string, args []string) (*redisclient.Reply, error) {
	rep, err := r.c.EvalSha(ctx, sc.sha, []string{key}, args)
	if err != nil && redisclient.IsNoScript(err) {
		rep, err = r.c.EvalContext(ctx, sc.body, []string{key}, args)
	}
	return rep, err
}

func nonce() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func b01(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func (r *Redis) decide(ctx context.Context, key string, p Params, peek bool) (Decision, bool, error) {
	p, err := normalize(p)
	if err != nil {
		return Decision{}, false, err
	}
	var sc script
	var args []string
	ms := strconv.FormatInt(p.Window.Milliseconds(), 10)
	lim, cost := strconv.Itoa(p.Limit), strconv.Itoa(p.Cost)
	switch p.Algorithm {
	case model.AlgoTokenBucket:
		sc, args = scTokenBucket, []string{lim, ms, strconv.Itoa(p.Burst), cost, b01(peek)}
	case model.AlgoSlidingWindow:
		n, err := nonce()
		if err != nil {
			return Decision{}, false, err
		}
		sc, args = scSlidingLog, []string{lim, ms, cost, b01(peek), n}
	case model.AlgoSlidingWindowCounter:
		sc, args = scSlidingCounter, []string{lim, ms, cost, b01(peek)}
	case model.AlgoFixedWindow:
		sc, args = scFixedWindow, []string{lim, ms, cost, b01(peek)}
	case model.AlgoConcurrency:
		n, err := nonce()
		if err != nil {
			return Decision{}, false, err
		}
		sc, args = scConcurrency, []string{lim, cost, b01(peek), n,
			strconv.FormatInt(concurrencyLeaseTTL.Milliseconds(), 10),
			strconv.FormatInt(concurrencyRetryHint.Milliseconds(), 10)}
	}
	rep, err := r.run(ctx, sc, r.redisKey(p.Algorithm, key), args)
	if err != nil {
		return Decision{}, false, err
	}
	if len(rep.Array) != 6 {
		return Decision{}, false, errBadScriptReply
	}
	v := func(i int) int64 { return rep.Array[i].Int }
	d := Decision{
		Allowed:    v(0) == 1,
		Limit:      int(v(1)),
		Remaining:  int(max(v(2), 0)),
		ResetAfter: time.Duration(max(v(3), 0)) * time.Millisecond,
		RetryAfter: time.Duration(max(v(4), 0)) * time.Millisecond,
	}
	return d, v(5) == 1, nil
}

func (r *Redis) Allow(ctx context.Context, key string, p Params) (Decision, error) {
	d, _, err := r.decide(ctx, key, p, false)
	return d, err
}

func (r *Redis) Peek(ctx context.Context, key string, p Params) (Decision, bool, error) {
	return r.decide(ctx, key, p, true)
}

func (r *Redis) Release(ctx context.Context, key string, p Params) error {
	if p.Algorithm != model.AlgoConcurrency {
		return nil
	}
	n := p.Cost
	if n <= 0 {
		n = 1
	}
	_, err := r.run(ctx, scConcurrencyRel, r.redisKey(p.Algorithm, key), []string{strconv.Itoa(n)})
	return err
}

func (r *Redis) Reset(ctx context.Context, key string, p Params) error {
	_, err := r.c.DoContext(ctx, "DEL", r.redisKey(p.Algorithm, key))
	return err
}
