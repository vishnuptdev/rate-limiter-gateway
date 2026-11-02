# RateGuard

**Rate limiting for your APIs, in a single Go binary.**

RateGuard is a rate-limiting reverse proxy and decision service with an embedded
admin dashboard. Put it in front of your APIs so it enforces limits on every
request, or call its check API from your own services when you do not want an
extra proxy hop. Manage routes, policies, plans, consumers and API keys from a
web UI, with an audit trail and live traffic visibility.

It is one binary with no database, no build step for the UI, and no third-party
Go dependencies (standard library only).

> Screenshots: _placeholder — dashboard screenshots (Overview, Live Logs,
> Simulator, Limits inspector) will be added here._

## Features

- **Reverse proxy mode.** Route by host, path prefix and method. Allowed requests
  are forwarded to your upstream; denied requests get `429` with `Retry-After`.
- **Check API mode.** `POST /_rlg/v1/check` returns an allow/deny decision and
  rate-limit headers, for services that enforce limits themselves.
- **Seven algorithms.** Token bucket, sliding window, sliding-window counter,
  fixed window, concurrency (in-flight requests), GCRA, and leaky bucket
  (traffic shaping that delays instead of rejecting).
- **Policies, plans and consumers.** Limits are attached to routes through
  policies. Plans and per-consumer overrides adjust them per customer. Keys are
  hashed at rest and shown once.
- **Shadow mode.** Run a policy in observe-only mode and see what it would block
  before you enforce it.
- **Distributed limits.** The Redis engine runs each algorithm as an atomic Lua
  script, so several RateGuard instances share one set of counters.
- **Fail-open or fail-closed.** Choose per policy what happens when the limiter
  backend is unavailable.
- **Standard headers.** IETF `RateLimit-*` headers, with optional legacy
  `X-RateLimit-*` headers.
- **Admin dashboard.** Overview with live charts, streaming logs with filters,
  a request simulator, a limits inspector (peek and reset), an integration page
  with copy-paste snippets, audit log, and settings.
- **Access control.** Roles (admin, editor, viewer), scoped API tokens, session
  cookies with CSRF protection, login lockout, and an audit log of every change.
- **Observability.** Prometheus metrics at `/metrics`.

## 60-second quickstart

### With Docker

```bash
docker build -t rateguard .
docker run --rm -p 8080:8080 -p 9000:9000 \
  -e RLG_DEMO=true \
  -e RLG_ADMIN_PASSWORD='choose-a-long-password' \
  -v rateguard-data:/data \
  rateguard
```

### With the binary

```bash
go build -o rateguard ./cmd/rateguard
RLG_DEMO=true RLG_ADMIN_PASSWORD='choose-a-long-password' ./rateguard
```

Then:

1. Open the dashboard at `http://localhost:9000` and log in as `admin`.
2. Demo mode seeds a route, policies, a plan, a consumer and a dummy upstream.
   The Routes page shows the demo route. Send requests to the data plane on
   `:8080` and watch them appear in Live Logs.
3. Use the Simulator to test a request against the policies without sending it.

`RLG_ADMIN_PASSWORD` must be at least 12 characters. If you leave it unset on
first start, RateGuard generates a password and prints it once to stderr.

## Architecture

```
                 clients (API keys)                       your services
                        │                                       │
                        ▼                                       ▼
        ┌───────────────────────────────┐        POST /_rlg/v1/check
        │  :8080  data plane            │◀───────(Bearer token, scope check)
        │  routing · auth · policies    │
        │  proxy · headers · check API  │──────▶ upstream APIs
        └───────────────┬───────────────┘
                        │ counters (atomic)
                        ▼
        ┌───────────────────────────────┐
        │  limiter engine               │   RLG_ENGINE=memory | redis
        │  memory  or  Redis (Lua)      │◀──── shared across instances
        └───────────────────────────────┘

        ┌───────────────────────────────┐
        │  :9000  admin + dashboard     │   REST API · auth · audit log
        │  /metrics (Prometheus)        │──────▶ config store
        └───────────────────────────────┘        RLG_STORE=file | redis
```

Config changes made in the dashboard are validated, applied to the running data
plane, and then saved to the config store. With `RLG_STORE=redis`, every
instance watches the config version and picks up changes.

## Choosing an algorithm

| Algorithm | Behaviour | Memory per key | Pick it when |
|---|---|---|---|
| `token_bucket` | Refills at a steady rate up to a burst capacity | O(1) | You want a steady average rate and can tolerate short bursts |
| `sliding_window` | Exact count of requests in any trailing window (log) | O(requests in window) | You need an exact "N requests per window" contract |
| `sliding_window_counter` | Weighted blend of the current and previous fixed windows (approximate) | O(1) | You want close-to-exact limits at high volume |
| `fixed_window` | One counter per calendar-aligned window | O(1) | You want the simplest option and accept up to 2x burst across a window boundary |
| `concurrency` | Caps in-flight requests; the slot is released when the proxied response completes | O(in-flight) | You want to protect an upstream from simultaneous load (proxy mode only; the check API skips it) |
| `gcra` | Generic Cell Rate Algorithm: one timestamp per key (the theoretical arrival time); admits at a smooth rate `limit/window` with `burst` tolerance | O(1), one int64 | You want token-bucket behaviour with the smallest possible state, or exact per-request `Retry-After` hints |
| `leaky_bucket` | Traffic shaping: requests queue and drain at `limit/window`; `burst` is the queue size. Admitted requests are delayed (the gateway waits, up to the window) instead of rejected; a full queue gives 429 | O(1), one int64 | You must smooth bursts into an even rate for a fragile upstream and prefer latency over errors. The check API returns `delay_ms` rather than sleeping |

Token bucket and sliding window are the two you will reach for most often.
Token bucket gives burst tolerance: up to `burst` requests go through at once,
then the bucket refills. Sliding window gives a hard cap on every trailing window,
with no burst allowance.

In Redis mode each algorithm runs as a single Lua script. Redis executes a script
atomically, so two RateGuard instances cannot both read "9 tokens left" and both
spend the last one. Scripts use the Redis server clock (`TIME`), so instances with
skewed clocks still agree on the counters.

## Response headers

Every rate-limited response carries headers from the most restrictive policy
(the one with the lowest remaining count).

| Header | When | Meaning |
|---|---|---|
| `RateLimit-Limit` | Every rate-limited response | Limit of the most restrictive policy |
| `RateLimit-Remaining` | Every rate-limited response | Requests left in the current window |
| `RateLimit-Reset` | Every rate-limited response | Seconds until the window resets (rounded up) |
| `RateLimit-Policy` | Every rate-limited response | `<limit>;w=<window seconds>` |
| `Retry-After` | `429` responses | Seconds to wait, at least 1 |
| `X-RateLimit-Limit`, `-Remaining`, `-Reset` | When `LegacyHeaders` is on | Legacy form; `-Reset` is a Unix timestamp |
| `X-RateGuard-Route`, `X-RateGuard-Policy` | When `ExposeDecision` is on | Matched route and deciding policy |
| `X-RateGuard-Consumer` | Upstream requests only | Consumer ID. Inbound `X-RateGuard-*` headers are stripped, so clients cannot spoof them |

A `429` body looks like this:

```json
{"error":"rate_limited","message":"Rate limit exceeded","policy":"api-per-minute","limit":100,"remaining":0,"retry_after_s":12,"reset_s":12}
```

## Configuration reference

| Variable | Default | Meaning |
|---|---|---|
| `RLG_LISTEN` | `:8080` | Data plane listen address |
| `RLG_ADMIN_LISTEN` | `:9000` | Admin API and dashboard listen address |
| `RLG_DATA_DIR` | `./data` | Local state: `auth.json`, `audit.jsonl`, and `config.json` in file-store mode |
| `RLG_ENGINE` | — | Limiter engine: `memory` (per process) or `redis` (shared) |
| `RLG_STORE` | — | Config store: `file` (local JSON) or `redis` (shared, versioned) |
| `RLG_REDIS_ADDR` | `127.0.0.1:6379` | Redis address, used when `redis` is the engine or store |
| `RLG_REDIS_PASSWORD` | unset | Redis AUTH password |
| `RLG_REDIS_DB` | unset | Redis database number |
| `RLG_REDIS_TLS` | unset | Connect to Redis over TLS when `true` |
| `RLG_ADMIN_PASSWORD` | unset | Password for the bootstrap `admin` user, used only when no users exist yet |
| `RLG_COOKIE_SECURE` | unset | Force the `Secure` attribute on session cookies (always set under TLS) |
| `RLG_METRICS_PUBLIC` | unset | Serve `/metrics` without authentication when `true` |
| `RLG_TLS_CERT`, `RLG_TLS_KEY` | unset | TLS certificate and key for the admin listener |
| `RLG_DEMO` | unset | Seed a demo configuration and a dummy upstream when `true` |
| `RLG_LOG_LEVEL` | — | Log verbosity |

Set `RLG_ENGINE=redis` and `RLG_STORE=redis` on every instance that should
share limits and configuration. Give each instance its own `RLG_DATA_DIR`. See
[docs/SECURITY.md](docs/SECURITY.md) for the caveats on per-instance user data.

## Build, test, run

```bash
make build     # go build -o rateguard ./cmd/rateguard
make test      # go test -race ./...
make lint      # go vet ./... and gofmt check
make run       # run with ./data as the data directory
make demo      # run with RLG_DEMO=true
make docker    # build the container image
```

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): product spec and contracts
  (behaviour, endpoints, headers, storage)
- [docs/INTEGRATION.md](docs/INTEGRATION.md): reverse proxy, check API, and
  combined integration, step by step
- [docs/SECURITY.md](docs/SECURITY.md): threat model, auth model, hardening
  checklist
- [examples/](examples/): Node/Express, Python/FastAPI, Go `net/http`, NGINX
  and Kubernetes examples
- [docker-compose.yml](docker-compose.yml): two RateGuard instances sharing Redis,
  with a demo upstream
