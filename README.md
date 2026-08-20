# rate-limiter-gateway

A reverse-proxy API gateway with pluggable rate-limiting strategies
(token bucket, sliding window) and pluggable backends (in-memory,
Redis-backed distributed). No AI/LLM involved — this is a rate limiter and
a proxy.

See `NOTES.md` for environment restrictions and the reasoning behind
non-obvious decisions (in particular, why there's a hand-rolled Redis
client instead of a third-party one, and why Lua/EVAL is used).

## Architecture

```
cmd/gateway/main.go         entrypoint: config, dummy backend, gateway listener
internal/config/            env-var configuration
internal/limiter/           TokenBucket, SlidingWindow (in-memory)
                             RedisTokenBucket, RedisSlidingWindow (distributed)
internal/redisclient/       hand-rolled RESP2 client (no dependencies)
internal/proxy/             rate-limit middleware + reverse proxy + /metrics/usage
```

Request flow: client → `Gateway.Handler` (extract `X-API-Key` →
`Limiter.Allow(key)` → 429 + `Retry-After` if denied, else forward via
`httputil.ReverseProxy`) → dummy upstream backend (a second real HTTP
listener on `127.0.0.1:9090`, started by the same binary for a
self-contained demo).

## Strategy comparison

| | Token bucket | Sliding window |
|---|---|---|
| Burst tolerance | Yes — up to `burst` requests instantly, then refills at `rate`/sec | No — hard cap of `limit` requests in any trailing `window` |
| Memory (in-process) | O(1) per key | O(requests in window) per key |
| Good for | "steady average rate with occasional bursts" APIs | "exactly N requests per minute" contracts |
| Redis storage | 1 hash per key (`tokens`, `ts`) | 1 sorted set per key (timestamp → request id) |

Both are implemented as **atomic Redis Lua scripts** in the distributed
mode — see `NOTES.md` for why that matters under concurrency.

## Setup

Requires Go 1.22+. Redis is optional (only needed for
`RLG_LIMITER_BACKEND=redis`); this environment already has it running via
`redis-server --daemonize yes`.

```bash
cd rate-limiter-gateway
go run ./cmd/gateway
# gateway on :8080 (configurable), dummy backend on 127.0.0.1:9090
```

Try it:

```bash
curl -H "X-API-Key: demo" http://localhost:8080/hello        # 200, proxied
curl -H "X-API-Key: demo" http://localhost:8080/hello        # ... repeat past burst ...
# eventually:
# HTTP/1.1 429 Too Many Requests
# Retry-After: 1
# {"error":"rate limit exceeded","retry_after_seconds":1}

curl http://localhost:8080/metrics/usage                      # usage for every key seen
curl http://localhost:8080/metrics/usage?key=demo              # usage for one key
```

## Configuration reference

| Variable | Default | Meaning |
|---|---|---|
| `RLG_PORT` | `8080` | gateway listen port |
| `RLG_BACKEND_URL` | `http://127.0.0.1:9090` | upstream the proxy forwards to |
| `RLG_STRATEGY` | `token_bucket` | `token_bucket` or `sliding_window` |
| `RLG_LIMITER_BACKEND` | `memory` | `memory` or `redis` |
| `RLG_REDIS_ADDR` | `127.0.0.1:6379` | used when `RLG_LIMITER_BACKEND=redis` |
| `RLG_RATE` | `5` | token bucket: tokens/sec refill rate |
| `RLG_BURST` | `10` | token bucket: max tokens |
| `RLG_LIMIT` | `10` | sliding window: max requests per window |
| `RLG_WINDOW` | `10s` | sliding window: window size (Go duration syntax) |

Example running two gateway instances sharing a limit via Redis:

```bash
RLG_LIMITER_BACKEND=redis RLG_PORT=8080 go run ./cmd/gateway &
RLG_LIMITER_BACKEND=redis RLG_PORT=8081 RLG_BACKEND_URL=http://127.0.0.1:9090 go run ./cmd/gateway &
# both instances now share the same per-key limit via Redis
```

(Note: both processes also each start their own dummy backend on
`:9090`; in a real deployment the backend would be a separate service, not
embedded in the gateway binary — it's embedded here purely so the demo is
one command. In this two-instance-on-one-machine example only the first
`:9090` bind succeeds, which is fine since both gateways forward to it.)

## Verification

```bash
go build ./...
go vet ./...
go test ./... -race -v
```

At time of writing: **19 tests, 19 passed, 0 failed** (`go test ./...
-race`). See `NOTES.md` for the full breakdown and what the multi-instance
Redis tests specifically prove.

## What's real vs. simplified

- Real Redis, real atomic Lua scripts, real separate `Limiter` instances
  proven to share state in tests (not simulated with goroutines in one
  instance).
- Real reverse proxy hop to a real second HTTP listener.
- The in-memory backend is exactly what it says: per-process only, not
  distributed. It's the explicit non-distributed comparison point, not a
  disguised version of the Redis mode.
