package limiter

import (
	"fmt"
	"strconv"
	"time"

	"ratelimitergateway/internal/redisclient"
)

// tokenBucketScript performs an atomic refill-then-consume against a Redis
// hash {tokens, ts}. Running it as a single EVAL is what makes this safe
// across concurrent requests from *multiple gateway processes* -- Redis
// executes the whole script atomically, so there's no read-modify-write
// race even though many gateway instances call this concurrently.
const tokenBucketScript = `
local key = KEYS[1]
local rate = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local requested = tonumber(ARGV[4])

local data = redis.call('HMGET', key, 'tokens', 'ts')
local tokens
local ts
if data[1] == false then
  tokens = burst
  ts = now
else
  tokens = tonumber(data[1])
  ts = tonumber(data[2])
end

local elapsed = (now - ts) / 1000.0
if elapsed < 0 then elapsed = 0 end
tokens = tokens + elapsed * rate
if tokens > burst then tokens = burst end
ts = now

local allowed = 0
if tokens >= requested then
  tokens = tokens - requested
  allowed = 1
end

redis.call('HMSET', key, 'tokens', tostring(tokens), 'ts', tostring(ts))
redis.call('EXPIRE', key, 3600)

return {allowed, tostring(tokens)}
`

// RedisTokenBucket is a Redis-backed token bucket: every gateway process
// that points at the same Redis instance shares the same bucket per key,
// which is what makes the rate limit genuinely distributed rather than
// per-process.
type RedisTokenBucket struct {
	rc        *redisclient.Client
	rate      float64
	burst     int
	keyPrefix string
}

func NewRedisTokenBucket(rc *redisclient.Client, rate float64, burst int, keyPrefix string) *RedisTokenBucket {
	if keyPrefix == "" {
		keyPrefix = "rlg:tb:"
	}
	return &RedisTokenBucket{rc: rc, rate: rate, burst: burst, keyPrefix: keyPrefix}
}

func (r *RedisTokenBucket) Allow(key string) (Result, error) {
	now := time.Now().UnixMilli()
	reply, err := r.rc.Eval(tokenBucketScript,
		[]string{r.keyPrefix + key},
		[]string{fmt.Sprintf("%g", r.rate), strconv.Itoa(r.burst), strconv.FormatInt(now, 10), "1"},
	)
	if err != nil {
		return Result{}, fmt.Errorf("redis token bucket eval: %w", err)
	}
	if len(reply.Array) != 2 {
		return Result{}, fmt.Errorf("redis token bucket: unexpected reply shape")
	}
	allowed := reply.Array[0].Int == 1
	tokens, err := strconv.ParseFloat(reply.Array[1].Str, 64)
	if err != nil {
		return Result{}, fmt.Errorf("redis token bucket: bad tokens value: %w", err)
	}
	if allowed {
		return Result{Allowed: true, Remaining: int(tokens)}, nil
	}
	deficit := 1 - tokens
	retryAfter := time.Duration(deficit / r.rate * float64(time.Second))
	return Result{Allowed: false, Remaining: 0, RetryAfter: retryAfter}, nil
}

func (r *RedisTokenBucket) Usage(key string) (remaining int, limit int, ok bool) {
	reply, err := r.rc.Do("HGET", r.keyPrefix+key, "tokens")
	if err != nil || reply.IsNil {
		return r.burst, r.burst, false
	}
	tokens, err := strconv.ParseFloat(reply.Str, 64)
	if err != nil {
		return r.burst, r.burst, false
	}
	return int(tokens), r.burst, true
}
