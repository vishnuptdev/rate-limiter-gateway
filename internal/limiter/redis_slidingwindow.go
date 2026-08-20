package limiter

import (
	"fmt"
	"strconv"
	"time"

	"ratelimitergateway/internal/redisclient"
)

// slidingWindowScript keeps a Redis sorted set of request timestamps per
// key: prunes anything outside the window, checks the count, and (if
// under the limit) adds this request -- all atomically in one EVAL, so
// concurrent callers across multiple gateway processes can't both slip in
// over the limit via a check-then-act race.
const slidingWindowScript = `
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])

local cutoff = now - window_ms
redis.call('ZREMRANGEBYSCORE', key, '-inf', cutoff)

local count = redis.call('ZCARD', key)
local allowed = 0
if count < limit then
  local seq = redis.call('INCR', key .. ':seq')
  local member = tostring(now) .. '-' .. tostring(seq)
  redis.call('ZADD', key, now, member)
  local ttl = math.ceil(window_ms / 1000) + 1
  redis.call('EXPIRE', key, ttl)
  redis.call('EXPIRE', key .. ':seq', ttl)
  allowed = 1
  count = count + 1
end

local retry_after_ms = 0
if allowed == 0 then
  local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
  if #oldest > 0 then
    retry_after_ms = (tonumber(oldest[2]) + window_ms) - now
    if retry_after_ms < 0 then retry_after_ms = 0 end
  end
end

local remaining = limit - count
if remaining < 0 then remaining = 0 end

return {allowed, remaining, retry_after_ms}
`

// RedisSlidingWindow is a Redis-backed sliding-window limiter shared
// across every gateway process pointed at the same Redis instance.
type RedisSlidingWindow struct {
	rc        *redisclient.Client
	limit     int
	window    time.Duration
	keyPrefix string
}

func NewRedisSlidingWindow(rc *redisclient.Client, limit int, window time.Duration, keyPrefix string) *RedisSlidingWindow {
	if keyPrefix == "" {
		keyPrefix = "rlg:sw:"
	}
	return &RedisSlidingWindow{rc: rc, limit: limit, window: window, keyPrefix: keyPrefix}
}

func (r *RedisSlidingWindow) Allow(key string) (Result, error) {
	now := time.Now().UnixMilli()
	windowMs := r.window.Milliseconds()
	reply, err := r.rc.Eval(slidingWindowScript,
		[]string{r.keyPrefix + key},
		[]string{strconv.FormatInt(now, 10), strconv.FormatInt(windowMs, 10), strconv.Itoa(r.limit)},
	)
	if err != nil {
		return Result{}, fmt.Errorf("redis sliding window eval: %w", err)
	}
	if len(reply.Array) != 3 {
		return Result{}, fmt.Errorf("redis sliding window: unexpected reply shape")
	}
	allowed := reply.Array[0].Int == 1
	remaining := int(reply.Array[1].Int)
	retryAfterMs := reply.Array[2].Int
	return Result{Allowed: allowed, Remaining: remaining, RetryAfter: time.Duration(retryAfterMs) * time.Millisecond}, nil
}

func (r *RedisSlidingWindow) Usage(key string) (remaining int, limit int, ok bool) {
	now := time.Now().UnixMilli()
	cutoff := strconv.FormatInt(now-r.window.Milliseconds(), 10)
	reply, err := r.rc.Do("ZCOUNT", r.keyPrefix+key, "("+cutoff, "+inf")
	if err != nil {
		return r.limit, r.limit, false
	}
	count := int(reply.Int)
	rem := r.limit - count
	if rem < 0 {
		rem = 0
	}
	return rem, r.limit, count > 0
}
