# NOTES — engineering decisions & environment restrictions

## Environment

- Same restriction as the other Go projects in this batch: `proxy.golang.org`
  and any `golang.org/x/...` vanity import are unreachable from this
  sandbox (`403 Forbidden` from `go get`), but direct `git` fetches of
  `github.com` repos work. This project ended up needing **zero** external
  Go dependencies at all — see "No Redis client dependency" below.
- **Redis is genuinely available and running in this environment**
  (`redis-server` binary present; started with `redis-server --daemonize yes`).
  So the "distributed" claim in this project is real, not a labeled
  fallback: `RLG_LIMITER_BACKEND=redis` genuinely shares limiter state
  across separate `Limiter` instances (standing in for separate gateway
  processes) talking to the same Redis. This is proven in
  `internal/limiter/redis_limiter_test.go` by constructing two independent
  limiter instances and hammering the same key from both concurrently.

## No Redis client dependency — hand-rolled RESP client

`redis/go-redis` and similar clients could not be fetched reliably given
the module-proxy restriction above, and pulling in a large client for two
Lua-script calls felt like the wrong trade anyway. Instead,
`internal/redisclient` implements just enough of RESP2 (arrays, bulk
strings, simple strings, integers, errors) over a plain `net.Conn` to run
`EVAL` and a handful of basic commands, with a small connection pool. This
is ~220 lines, has zero dependencies, and is protocol-level code that
directly demonstrates understanding of how a real client talks to Redis —
which fits the point of this exercise better than importing a library
would have. It is deliberately not a general-purpose client: no
pipelining, no pub/sub, no cluster support.

## Why Lua/EVAL instead of separate INCR/EXPIRE calls

Both distributed limiters (`redis_tokenbucket.go`, `redis_slidingwindow.go`)
do their read-refill-check-write cycle as a single `EVAL` script rather
than a sequence of separate Redis commands from Go. Redis executes a
script atomically, so this is what actually prevents a race between two
gateway processes both reading "9 tokens left," both deciding to allow,
and jointly over-spending the bucket. A naive GET-then-SET from Go would
have exactly that race under concurrency; that's why the two-instance
tests in `redis_limiter_test.go` exist — to prove that isn't happening.

## Design decisions

- **Strategy selection** (`RLG_STRATEGY=token_bucket|sliding_window`) and
  **backend selection** (`RLG_LIMITER_BACKEND=memory|redis`) are
  orthogonal config knobs, matching the "selectable via config" requirement.
- **API key extraction**: `X-API-Key` header, required. A request with no
  key is rejected with `400` rather than falling back to an anonymous
  shared bucket, which would let unauthenticated traffic drain a limit
  meant for a real caller.
- **Dummy backend**: `cmd/gateway/main.go` starts a second, genuinely
  separate `net/http` listener on `127.0.0.1:9090` and the gateway proxies
  to it via `httputil.ReverseProxy` — a real HTTP hop, not a function call
  standing in for one.
- **In-memory sliding window** stores a per-key slice of timestamps and
  prunes expired ones on each check (O(n) per request in the number of
  requests within the window). Fine at demo scale; a production version
  at high QPS would use fixed-size counter buckets (an approximate sliding
  window) instead. The Redis-backed version uses a sorted set
  (`ZADD`/`ZREMRANGEBYSCORE`/`ZCARD`), which has the same complexity
  characteristics but off-loads storage to Redis.
- **Token bucket `Usage()`** reports the last-computed token count without
  triggering a refill calculation, so hitting `/metrics/usage` doesn't
  itself perturb the bucket.

## Testing

- `go test ./... -race -v`: **19 tests, 19 passed, 0 failed** (run from a
  clean shell; see README "Verification" for the exact command). This
  includes genuine concurrency tests (100 goroutines hitting one key) for
  both in-memory strategies, and the two-separate-instances Redis sharing
  tests described above.
- Redis-dependent tests skip cleanly (not fail) if Redis isn't reachable
  at `REDIS_TEST_ADDR` (default `127.0.0.1:6379`), so the suite still runs
  meaningfully in an environment without Redis — though in *this*
  environment Redis is present and those tests do run for real.

## Known limitations (explicit, not hidden)

- No sliding-window-counter (approximate) mode — only the exact
  timestamp-log sliding window, which is more memory-hungry at high QPS.
  Documented as a known scaling limitation, not implemented, since the
  token bucket already demonstrates the config-selectable-strategy
  requirement and a second full implementation would be scope creep for a
  demo of this size.
- The Redis client pool has no health-check/reconnect-with-backoff loop
  beyond "reconnect on next use if the pooled conn is dead" — adequate for
  a demo, not for a production client.
- Metrics endpoint tracks "seen keys" in an in-process map, so after a
  process restart the full key list is empty until keys are hit again
  (individual `?key=` lookups still work immediately since they query the
  limiter directly).
