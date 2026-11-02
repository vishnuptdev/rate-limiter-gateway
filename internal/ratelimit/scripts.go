package ratelimit

// Lua scripts, one per algorithm. All of them:
//   - take the state key as KEYS[1] and every parameter as ARGV,
//   - read the clock with the Redis TIME command (never the client's), so
//     gateways with skewed clocks agree,
//   - run atomically (a script is a single server-side operation),
//   - set PEXPIRE on every key they write,
//   - return {allowed, limit, remaining, reset_ms, retry_ms, existed}.
//
// A "peek" flag makes them read-only and report whether the cost would fit.
// They rely on effects replication (default since Redis 5) because they
// write after calling TIME, and on ZPOPMIN (Redis >= 5).

const luaPrelude = `
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local EPS = 1e-9
`

// ARGV: limit, window_ms, burst, cost, peek
const luaTokenBucket = luaPrelude + `
local limit = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local cap = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])
local peek = ARGV[5] == '1'
local rate = limit / window
local h = redis.call('HMGET', KEYS[1], 'tk', 'ts')
local existed = 0
local tokens = cap
if h[1] then
  existed = 1
  tokens = tonumber(h[1])
  local el = now - tonumber(h[2])
  if el > 0 then tokens = tokens + el * rate end
  if tokens > cap then tokens = cap end
end
local allowed = 0
local retry = 0
if cost <= tokens + EPS then
  allowed = 1
  if not peek then
    tokens = tokens - cost
    if tokens < 0 then tokens = 0 end
  end
elseif cost > cap then
  retry = math.ceil((cap - tokens) / rate)
else
  retry = math.ceil((cost - tokens) / rate)
end
local reset = math.ceil((cap - tokens) / rate)
if reset < 0 then reset = 0 end
if not peek then
  redis.call('HSET', KEYS[1], 'tk', string.format('%.9f', tokens), 'ts', now)
  redis.call('PEXPIRE', KEYS[1], reset + 1000)
end
return {allowed, cap, math.floor(tokens + EPS), reset, retry, existed}
`

// ARGV: limit, window_ms, cost, peek, nonce
// ZSET of accepted units; member "<us>:<nonce>:<i>", score = time in us.
const luaSlidingLog = luaPrelude + `
local limit = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local cost = tonumber(ARGV[3])
local peek = ARGV[4] == '1'
local nonce = ARGV[5]
local nowus = tonumber(t[1]) * 1000000 + tonumber(t[2])
local wus = window * 1000
local cutoff = nowus - wus
if peek then
  -- read-only: count only the live entries
else
  redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', cutoff)
end
local count = redis.call('ZCOUNT', KEYS[1], '(' .. cutoff, '+inf')
local existed = 0
if count > 0 then existed = 1 end
local allowed = 0
if cost <= limit and count + cost <= limit then
  allowed = 1
  if not peek then
    for i = 1, cost do
      redis.call('ZADD', KEYS[1], nowus, nowus .. ':' .. nonce .. ':' .. i)
    end
    count = count + cost
    redis.call('PEXPIRE', KEYS[1], window + 1000)
  end
end
local reset = 0
local newest = redis.call('ZREVRANGEBYSCORE', KEYS[1], '+inf', '(' .. cutoff, 'WITHSCORES', 'LIMIT', 0, 1)
if newest[2] then reset = math.ceil((tonumber(newest[2]) + wus - nowus) / 1000) end
local retry = 0
if allowed == 0 then
  if cost > limit then
    retry = reset
  else
    local need = count + cost - limit
    local o = redis.call('ZRANGEBYSCORE', KEYS[1], '(' .. cutoff, '+inf', 'WITHSCORES', 'LIMIT', need - 1, 1)
    if o[2] then retry = math.ceil((tonumber(o[2]) + wus - nowus) / 1000) end
  end
end
if reset < 0 then reset = 0 end
if retry < 0 then retry = 0 end
local rem = limit - count
if rem < 0 then rem = 0 end
return {allowed, limit, rem, reset, retry, existed}
`

// ARGV: limit, window_ms, cost, peek
// Hash {w = window index, c = current count, p = previous count}.
const luaSlidingCounter = luaPrelude + `
local limit = tonumber(ARGV[1])
local win = tonumber(ARGV[2])
local cost = tonumber(ARGV[3])
local peek = ARGV[4] == '1'
local idx = math.floor(now / win)
local into = now - idx * win
local frac = into / win
local h = redis.call('HMGET', KEYS[1], 'w', 'c', 'p')
local existed = 0
local curr, prev = 0, 0
if h[1] then
  existed = 1
  local w = tonumber(h[1])
  if w == idx then
    curr = tonumber(h[2]); prev = tonumber(h[3])
  elseif w == idx - 1 then
    prev = tonumber(h[2]); curr = 0
  end
end
local weighted = prev * (1 - frac) + curr
local allowed = 0
if cost <= limit and weighted + cost <= limit + EPS then
  allowed = 1
  if not peek then
    curr = curr + cost
    weighted = weighted + cost
  end
end
if not peek then
  redis.call('HSET', KEYS[1], 'w', idx, 'c', curr, 'p', prev)
  redis.call('PEXPIRE', KEYS[1], win * 2 + 1000)
end
local rem = math.floor(limit - weighted + EPS)
if rem < 0 then rem = 0 end
local left = win - into
local reset = 0
if curr > 0 then reset = left + win elseif prev > 0 then reset = left end
local retry = 0
if allowed == 0 then
  if cost > limit then
    retry = reset
  elseif prev > 0 and limit - curr - cost >= 0 then
    local f = 1 - (limit - curr - cost) / prev
    retry = math.ceil((f - frac) * win)
    if retry <= 0 then retry = 1 end
  else
    local f = 1 - (limit - cost) / curr
    if f < 0 then f = 0 end
    retry = math.ceil(left + f * win)
  end
end
return {allowed, limit, rem, reset, retry, existed}
`

// ARGV: limit, window_ms, cost, peek
// Plain counter whose TTL is aligned to the epoch window boundary.
const luaFixedWindow = luaPrelude + `
local limit = tonumber(ARGV[1])
local win = tonumber(ARGV[2])
local cost = tonumber(ARGV[3])
local peek = ARGV[4] == '1'
local cur = redis.call('GET', KEYS[1])
local existed = 0
local count = 0
local ttl = win - (now % win)
if cur then
  existed = 1
  count = tonumber(cur)
  local pttl = redis.call('PTTL', KEYS[1])
  if pttl > 0 then ttl = pttl end
end
local allowed = 0
if cost <= limit and count + cost <= limit then
  allowed = 1
  if not peek then
    if existed == 1 then
      redis.call('INCRBY', KEYS[1], cost)
    else
      redis.call('SET', KEYS[1], cost, 'PX', ttl)
    end
    count = count + cost
  end
end
local rem = limit - count
if rem < 0 then rem = 0 end
local retry = 0
if allowed == 0 then retry = ttl end
return {allowed, limit, rem, ttl, retry, existed}
`

// ARGV: limit, cost, peek, nonce, lease_ms, retry_hint_ms
// ZSET of leases; member "<nonce>:<i>", score = lease expiry in ms.
const luaConcurrency = luaPrelude + `
local limit = tonumber(ARGV[1])
local cost = tonumber(ARGV[2])
local peek = ARGV[3] == '1'
local nonce = ARGV[4]
local lease = tonumber(ARGV[5])
local hint = tonumber(ARGV[6])
if not peek then
  redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now)
end
local count = redis.call('ZCOUNT', KEYS[1], '(' .. now, '+inf')
local existed = 0
if count > 0 then existed = 1 end
local allowed = 0
if cost <= limit and count + cost <= limit then
  allowed = 1
  if not peek then
    for i = 1, cost do
      redis.call('ZADD', KEYS[1], now + lease, nonce .. ':' .. i)
    end
    count = count + cost
    redis.call('PEXPIRE', KEYS[1], lease)
  end
end
local rem = limit - count
if rem < 0 then rem = 0 end
local reset = 0
if count > 0 then reset = hint end
local retry = 0
if allowed == 0 then retry = hint end
return {allowed, limit, rem, reset, retry, existed}
`

// ARGV: units. Frees that many leases, closest to expiry (oldest) first.
const luaConcurrencyRelease = luaPrelude + `
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now)
redis.call('ZPOPMIN', KEYS[1], tonumber(ARGV[1]))
return 1
`

// ARGV: limit, window_ms, burst, cost, peek, shape
// Shared by GCRA (shape=0) and the leaky bucket (shape=1); see
// Memory.gcra for the semantics. State: string key holding the theoretical
// arrival time (TAT) in microseconds of server time. Working in microseconds
// keeps the emission interval accurate for high limits. Returns the usual six
// values plus delay_ms (leaky bucket queue wait).
const luaGCRA = luaPrelude + `
local limit = tonumber(ARGV[1])
local window = tonumber(ARGV[2]) * 1000
local burst = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])
local peek = ARGV[5] == '1'
local shape = ARGV[6] == '1'
local nowus = tonumber(t[1]) * 1000000 + tonumber(t[2])
local unit = math.max(math.floor(window / limit + 0.5), 1)
local inc = math.max(math.floor(window * cost / limit + 0.5), 1)
local cap = math.max(math.floor(window * burst / limit + 0.5), unit)
local cur = redis.call('GET', KEYS[1])
local existed = 0
local tat = 0
if cur then existed = 1; tat = tonumber(cur) end
local backlog = math.max(tat - nowus, 0)
local wait = backlog
local allowed = 0
local retry = 0
if backlog + inc <= cap then
  allowed = 1
  if not peek then backlog = backlog + inc end
elseif inc > cap then
  retry = backlog
else
  retry = backlog + inc - cap
end
if not peek then
  if allowed == 1 then
    redis.call('SET', KEYS[1], string.format('%.0f', nowus + backlog), 'PX', math.ceil(backlog / 1000) + 1000)
  elseif existed == 1 then
    redis.call('PEXPIRE', KEYS[1], math.ceil(backlog / 1000) + 1000)
  end
end
local rem = math.floor((cap - backlog) / unit)
if rem < 0 then rem = 0 end
local delay = 0
if shape and allowed == 1 then delay = math.ceil(wait / 1000) end
return {allowed, burst, rem, math.ceil(backlog / 1000), math.ceil(retry / 1000), existed, delay}
`
