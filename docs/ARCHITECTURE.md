# RateGuard Gateway — Architecture & Contract (SPEC)

Product name: **RateGuard** (binary `rateguard`, Go module `ratelimitergateway`).
A single, zero-dependency Go binary that is (a) a rate-limiting reverse
proxy, (b) a rate-limit decision API for services that don't want a proxy
hop, and (c) an embedded admin dashboard.

## Global constraints (binding on every package)

1. **Go stdlib only.** No third-party Go modules (supply-chain minimalism is a
   selling point). Go 1.24 (`crypto/pbkdf2`, `crypto/rand`, `log/slog`, `embed`).
2. **No build step for the dashboard.** Vanilla ES modules + CSS, embedded with
   `go:embed`. No CDN, no external fonts/scripts (strict CSP: `default-src 'self'`).
3. `internal/model` is the shared contract — do not change existing exported
   names/fields there; additions are allowed only if strictly necessary and
   must be reported.
4. Every package has table-driven tests; `go test -race ./...` must pass.
   Redis tests skip cleanly if `REDIS_TEST_ADDR` (default `127.0.0.1:6379`) is
   unreachable.
5. `go vet ./...` clean, `gofmt` clean.
6. Security: never log or store plaintext API keys / passwords / tokens;
   constant-time comparisons for secrets; bounded memory everywhere
   (ring buffers, capped maps, request body limits); all HTTP servers have
   timeouts.
7. Package boundaries: each package owns only its directory. Cross-package
   needs are expressed as small interfaces in the *consuming* package.

## Packages

| Package | Responsibility |
|---|---|
| `internal/model` | Config + telemetry + simulator types (done) |
| `internal/ratelimit` | `Engine` interface (done) + `Memory` and `Redis` engines, all 7 algorithms (token bucket, sliding window log, sliding window counter, fixed window, concurrency, GCRA, leaky bucket) |
| `internal/redisclient` | Hand-rolled RESP2 client (exists) — add AUTH/SELECT, timeouts, EVALSHA cache |
| `internal/store` | `ConfigStore` (done) + `File` and `Redis` implementations, `Validate` |
| `internal/gateway` | Data plane: routing, auth, key extraction, policy evaluation, proxy, headers, check API, simulator |
| `internal/telemetry` | Request log ring buffer, live subscribers, timeseries, overview, Prometheus |
| `internal/admin` | Admin REST API, auth (users/sessions/CSRF/API tokens/RBAC), audit log, serves dashboard |
| `internal/dashboard` | Embedded SPA static files (`embed.go` exposes `FS fs.FS`) |
| `cmd/rateguard` | Wiring, env config, graceful shutdown, demo mode |

## Data plane behaviour (`internal/gateway`)

- Listener default `:8080`.
- Route selection: enabled routes only; match host (exact or `*.suffix`;
  case-insensitive, port and trailing dot ignored on both sides),
  path prefix (segment-aware: `/api` matches `/api` and `/api/x`, not `/apix`;
  case-sensitive), method. Highest `Priority` wins; ties → longest `PathPrefix`; ties → ID.
  No match → `404 {"error":"no_route"}`.
- Client IP: `RemoteAddr`; if the immediate peer is in `Settings.TrustedProxies`,
  walk `X-Forwarded-For` right-to-left skipping trusted hops.
- `ip` key part: IPv6 addresses are masked to `Settings.IPv6PrefixLen` bits
  (32..128, 0 → 64), keyed as `2001:db8:1:2::/64`; IPv4 and IPv4-mapped
  addresses are used in full.
- Upgrades: `Upgrade: h2c` (with or without `Connection: Upgrade`) → `400
  {"error":"upgrade_not_allowed"}` on every route. Any other upgrade
  (`Connection: upgrade` + `Upgrade`) → same 400 unless `Route.AllowUpgrade`.
  An allowed upgrade is evaluated as one request; concurrency slots are held
  until the tunnel closes; the tunnel is bounded by the route timeout and the
  server read/write timeouts.
- API key: header `Settings.APIKeyHeader` (default `X-API-Key`) or
  `Authorization: Bearer <key>`. Look up by sha256 hex → consumer. Revoked,
  expired, or disabled consumer = invalid. If route `RequireAPIKey` and key
  missing/invalid → `401 {"error":"unauthorized","message":"..."}`. If key is
  present but invalid on an optional route → also 401 (never silently anon).
- Policies evaluated: `Settings.GlobalPolicyIDs` then `Route.PolicyIDs`
  (dedupe, skip disabled/missing). Effective numbers: consumer override >
  plan override > policy. Engine key = `<policyID>:<composite>` where composite
  joins `KeyBy` parts with `|`; `api_key` part uses the first 16 hex of sha256.
- Each enforce policy that denies → `429`. All policies are checked even after a
  deny? **No** — stop at the first enforce deny (don't burn other buckets).
  Shadow denies are recorded and continue.
- Concurrency policies: release slot when the proxied response completes.
- Leaky-bucket policies: an allowed decision carries `Decision.Delay`; the proxy
  waits that long (timer + `select` on the client context, bounded by validation (30s max);
  a global waiter cap (default 10000) returns 429 `shaping_queue_full`) before forwarding. A client abort while queued logs decision `error` /
  `client_closed` (HTTP 499) and does not proxy; held concurrency slots are still
  released. GCRA and leaky bucket share one state value (TAT) and one Lua script.
- Backend error: policy `FailMode` open → skip policy; closed → `503 {"error":"limiter_unavailable"}`.
- Response headers on every rate-limited route (from the *most restrictive*
  policy = lowest remaining): IETF `RateLimit-Limit`, `RateLimit-Remaining`,
  `RateLimit-Reset` (seconds, int ceil), `RateLimit-Policy: <limit>;w=<window s>`;
  if `Settings.LegacyHeaders` also `X-RateLimit-Limit/-Remaining/-Reset`
  (Reset = unix seconds). 429 adds `Retry-After` (int seconds ≥1).
- 429 body: `{"error":"rate_limited","message":"Rate limit exceeded","policy":"<name>","limit":N,"remaining":0,"retry_after_s":N,"reset_s":N}`.
- `Settings.ExposeDecision` → `X-RateGuard-Route`, `X-RateGuard-Policy`.
- Proxy: `httputil.ReverseProxy` per upstream (cached), `StripPrefix`,
  sets `X-Forwarded-For/Proto/Host`, adds `X-RateGuard-Consumer` (ID) upstream,
  strips the inbound API key header? **No** (upstreams may need it) — but strips
  any inbound `X-RateGuard-*` headers to prevent spoofing. Sets `X-Real-IP` to
  the computed client IP (inbound `Forwarded` is dropped); strips request
  trailers named `X-RateGuard-*`, hop-by-hop or client-IP headers, the
  `HTTP2-Settings` header and the dashboard's `rg_session` cookie. Per-route timeout.
  Upstream errors → `502 {"error":"bad_gateway"}`.
- `Settings.MaxBodyBytes > 0` → `http.MaxBytesReader`.
- Reserved paths (never proxied): `GET /_rlg/healthz` → 200; `GET /_rlg/readyz`
  → 200 if config loaded & engine healthy else 503; `POST /_rlg/v1/check`
  (if `CheckAPIEnabled`); `/_rlg/v1/auth`, any method (unless `ForwardAuthDisabled`; see below).
- Every request produces one `model.LogEntry` passed to a `Recorder`
  (`Record(model.LogEntry)`); allowed requests sampled by `LogSampleAllowed`.
  `RateKey` must never contain a raw API key.

### Decision (check) API — `POST /_rlg/v1/check`

For services that call RateGuard instead of proxying through it.
Auth: `Authorization: Bearer <token>` where token is verified by a
`TokenVerifier` interface (`Verify(token string, scope string) bool`, scope
`"check"`) supplied by the admin package. Request:

```json
{"route_id":"r_x?","method":"GET","path":"/v1/orders","host":"api.acme.com",
 "api_key":"rlg_live_...?","ip":"1.2.3.4?","headers":{"X-Tenant":"t1"},"cost":1}
```

If `route_id` omitted the route is matched from method/host/path. Response 200
always (even when limited):

```json
{"allowed":false,"decision":"limited","route_id":"...","consumer_id":"...",
 "policy_id":"...","limit":100,"remaining":0,"reset_s":12,"retry_after_s":12,"delay_ms":0,
 "headers":{"RateLimit-Limit":"100","RateLimit-Remaining":"0","RateLimit-Reset":"12","Retry-After":"12"},
 "results":[{"policy_id":"...","allowed":false,"limit":100,"remaining":0,"shadow":false}]}
```

Concurrency policies are skipped by the check API (no completion signal).
`delay_ms` is the largest leaky-bucket queue delay among enforcing policies; the
check API reports it and never sleeps (the caller holds the request).

### Forward-auth endpoint — `/_rlg/v1/auth`

For reverse proxies that delegate the decision (NGINX `auth_request`, Traefik
`ForwardAuth`, Caddy `forward_auth`, Envoy `ext_authz` HTTP, ingress-nginx
`auth-url`). Never proxies. Shares route matching, key extraction, `evaluate`,
`writeLimited`/`rateHeaders`, leaky-bucket waiting (`reserveShaper`/`waitShaping`)
and logging with the proxy path; log `Source` is `"forward_auth"`.

- Caller auth: none by default (restrict by network). If
  `Settings.ForwardAuthRequireToken`, header `X-RateGuard-Auth-Token` must verify
  with `TokenVerifier` scope `"check"`, else 401.
- Original request: method from `X-Forwarded-Method`/`X-Original-Method` (default
  GET); URI from `X-Forwarded-Uri`/`X-Original-URI` (default `/`), normalised
  with `cleanPath` (invalid → 400); host from `X-Forwarded-Host` else `Host`;
  client IP via the trusted-proxy rules (`X-Forwarded-For`, else `X-Real-IP`, only
  honoured when `RemoteAddr` is trusted; otherwise `RemoteAddr`).
- Envoy form: `/_rlg/v1/auth/<orig path>?<query>` with the original method is
  accepted when no forwarded-URI header is present; `route_id` is ignored there.
- Route: `?route_id=` if given (unknown → 404), else matched normally.
- `?deny_status=401|403|429` (default 429, other → 400) sets the limited status
  (NGINX auth_request only relays 401/403); headers/body unchanged. Like
  `route_id`, ignored in the Envoy form. The appended path goes through `cleanPath`
  (also applied by ServeHTTP before routing, so `..` cannot escape the prefix).
- Responses: allowed → `200`, empty body, `RateLimit-*` headers,
  `X-RateGuard-Consumer` (present with an empty value when anonymous); limited → `429` with the standard JSON body and headers;
  bad/missing key → 401; no route → 404; bad path → 400; limiter failure
  (fail-closed) → 503.
- Leaky bucket: waits server-side like the proxy (global waiter cap applies).
  Concurrency policies are skipped.

### Gateway Go API (consumed by admin + main)

```go
type Recorder interface { Record(model.LogEntry) }
type TokenVerifier interface { Verify(token, scope string) bool }
type Options struct { Engine ratelimit.Engine; Recorder Recorder; Tokens TokenVerifier; Logger *slog.Logger }
func New(o Options) *Gateway
func (g *Gateway) Apply(s *model.Snapshot) error           // validate (store.Validate) + compile + atomic swap
func (g *Gateway) Current() *model.Snapshot
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request)
func (g *Gateway) Simulate(ctx context.Context, req model.SimRequest) model.SimResult
func (g *Gateway) EngineKey(policyID string, composite string) string // "<policyID>:<composite>"
```

## Store (`internal/store`)

- `func Validate(s *model.Snapshot) error` → returns `*ValidationError{Problems []Problem{Field, Message}}`
  (Field like `policies[2].limit`). Rules: unique non-empty IDs per kind
  (`^[a-z0-9][a-z0-9_-]{0,63}$`), names non-empty ≤100 chars, known algorithm,
  limit 1..1e9, window ≥1ms and ≤ 365d (not required for concurrency), burst ≥0,
  cost 0..limit, valid KeyBy entries, mode/fail_mode valid, route upstream an
  absolute http/https URL with host, path_prefix starts with `/` if non-empty,
  methods are uppercase known HTTP methods, all referenced policy/plan IDs exist,
  key hashes are 64 hex, trusted proxies parse as CIDR or IP,
  `LogSampleAllowed` in [0,1].
- `File`: JSON at `<dir>/config.json`, written via temp file + fsync + rename, perm 0600.
- `Redis`: key `rateguard:config` (JSON) + `rateguard:config:version`; Save uses
  a Lua script that only writes if version is newer; Watch polls version every 2s.
- `Memory` store for tests.

## Telemetry (`internal/telemetry`)

```go
type Hub struct{...}
func NewHub(o Options) *Hub        // Options{LogCapacity int (default 10000); Now func() time.Time}
func (h *Hub) Record(e model.LogEntry)              // assigns ID (monotonic, sortable) if empty; non-blocking
func (h *Hub) QueryLogs(q model.LogQuery) []model.LogEntry   // newest first
func (h *Hub) Subscribe(buf int) (<-chan model.LogEntry, func())  // slow subscribers drop, never block Record
func (h *Hub) Timeseries(rng time.Duration, routeID string) model.Timeseries // rng ∈ {15m,1h,6h,24h}; step 5s/15s/1m/5m
func (h *Hub) Overview() model.Overview   // last 24h, top lists of 10
func (h *Hub) WritePrometheus(w io.Writer) // text exposition format
```

Prometheus metrics: `rateguard_requests_total{route,decision,status_class}`,
`rateguard_rate_limited_total{policy}`, `rateguard_request_duration_seconds` histogram
`{route}` (buckets .001,.005,.01,.025,.05,.1,.25,.5,1,2.5,5,10),
`rateguard_upstream_duration_seconds` histogram, `rateguard_log_buffer_entries` gauge.
Label cardinality capped (max 500 distinct routes/policies; overflow label `"_other"`).
Percentiles from fixed log-scale histogram buckets per time bucket (not
storing all samples). Top-N counts via bounded maps (cap 10k keys, evict lowest).

## Admin (`internal/admin`)

Listener default `:9000` (separate from the data plane). Serves dashboard at
`/` (SPA fallback to `index.html` for non-`/api` paths), API at `/api/*`,
Prometheus at `/metrics` (requires auth token with `read` scope or session,
unless `RLG_METRICS_PUBLIC=true`).

### Auth & security

- Users in `<dataDir>/auth.json` (0600): `{username, role: "admin"|"editor"|"viewer", password_hash (pbkdf2-sha256, 600k iters, 16B salt, format "pbkdf2_sha256$600000$<b64salt>$<b64hash>"), must_change_password, created_at, last_login_at}`.
- Bootstrap: if no users, create `admin` with `RLG_ADMIN_PASSWORD` if set,
  else a random 20-char password printed once to stderr, `must_change_password=true`.
- Sessions: 32-byte random ID, stored server-side hashed, cookie `rg_session`
  `HttpOnly; SameSite=Strict; Path=/; Secure` (Secure when TLS or `RLG_COOKIE_SECURE=true`),
  idle timeout 12h, absolute 7d. Session store in memory (lost on restart = re-login; acceptable).
- CSRF: per-session token returned by `/api/auth/me` and `/api/auth/login`;
  required as `X-CSRF-Token` on all non-GET requests authenticated by cookie.
  Bearer-token requests don't need CSRF.
- API tokens (for CI / IaC / check API): `rgt_<40 random base62>`; stored as sha256;
  scopes subset of `admin`, `read`, `check`. Plaintext returned once.
- Roles: viewer = read-only; editor = config CRUD + reset limits; admin = everything
  incl. users, tokens, settings, import. `must_change_password` users can only
  call `/api/auth/*` until changed.
- Login brute-force protection: per-username and per-IP, 5 failures → exponential
  lockout (30s doubling, max 15m). Generic error message. Equal-time path for
  unknown users (hash a dummy).
- Password policy: ≥12 chars.
- Security headers on every admin response: CSP `default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
  `X-Frame-Options: DENY`, `Cross-Origin-Opener-Policy: same-origin`,
  `Strict-Transport-Security` when TLS. `Cache-Control: no-store` on `/api/*`.
- JSON bodies limited to 1 MiB (import: 10 MiB), `DisallowUnknownFields`.
- Audit log: every mutation appended to `<dataDir>/audit.jsonl`
  `{id,time,actor,actor_type:"user"|"token",ip,action,target_type,target_id,summary}`;
  in-memory last 5000 for the API.

### Config mutation flow

`Manager` holds a mutex; each write: `next := current.Clone()` → mutate →
set timestamps/IDs → `next.Version++` → `store.Validate` → `runtime.Apply(next)` →
`store.Save(next)` → audit. On store failure, re-apply previous. IDs: when
client omits `id`, generate from name slug + 4 random chars (`free-tier-a1b2`).
On `store.Watch` callback with newer version → `runtime.Apply`.

### REST API (all JSON; errors `{"error":"code","message":"...","problems":[{field,message}]?}`)

| Method & path | Role | Notes |
|---|---|---|
| `POST /api/auth/login` `{username,password}` | – | → `{user, csrf_token}` + cookie |
| `POST /api/auth/logout` | any | |
| `GET /api/auth/me` | any | → `{user:{username,role,must_change_password}, csrf_token}` |
| `POST /api/auth/password` `{current_password,new_password}` | any | |
| `GET /api/system` | viewer | `{version, go_version, instance_id, started_at, uptime_s, engine:{name,healthy,error?}, store:{name}, config_version, data_plane_addr, admin_addr}` |
| `GET /api/overview` | viewer | `model.Overview` + `{counts:{routes,policies,plans,consumers}}` merged at top level |
| `GET /api/timeseries?range=1h&route_id=` | viewer | `model.Timeseries` |
| `GET /api/logs?decision=&route_id=&consumer_id=&policy_id=&status_min=&status_max=&q=&before=&limit=` | viewer | `{entries:[LogEntry]}` |
| `GET /api/logs/stream` | viewer | SSE: `event: log` `data: <LogEntry json>`; heartbeat comment every 15s; supports same filters |
| `GET/POST /api/policies`, `GET/PUT/DELETE /api/policies/{id}` | viewer/editor | DELETE fails 409 if referenced (lists referrers) |
| `GET/POST /api/routes`, `GET/PUT/DELETE /api/routes/{id}` | viewer/editor | |
| `GET/POST /api/plans`, `GET/PUT/DELETE /api/plans/{id}` | viewer/editor | 409 if consumers on plan |
| `GET/POST /api/consumers`, `GET/PUT/DELETE /api/consumers/{id}` | viewer/editor | PUT ignores `keys` (managed via key endpoints) |
| `POST /api/consumers/{id}/keys` `{name?, expires_at?}` | editor | → `{key:"rlg_live_<32 base62>", api_key: APIKey}` plaintext once |
| `DELETE /api/consumers/{id}/keys/{keyId}` | editor | revokes (sets Revoked) |
| `GET /api/settings`, `PUT /api/settings` | viewer/admin | |
| `POST /api/simulate` `model.SimRequest` | viewer (consume=true needs editor) | → `model.SimResult` |
| `GET /api/limits?policy_id=&key=` | viewer | peek: `{policy_id,key,engine_key,exists,limit,remaining,reset_s}` (`key` is the composite) |
| `POST /api/limits/reset` `{policy_id,key}` | editor | |
| `GET /api/config/export` | admin | full snapshot JSON (download) |
| `POST /api/config/import` `{snapshot, dry_run}` | admin | validate (+apply unless dry_run) → `{ok, problems?, diff:{added,removed,changed counts per kind}}` |
| `GET /api/audit?limit=&before=` | admin | `{entries:[...]}` |
| `GET/POST /api/users`, `PUT/DELETE /api/users/{username}` | admin | can't delete self / last admin |
| `GET/POST /api/tokens`, `DELETE /api/tokens/{id}` | admin | POST `{name,scopes,expires_at?}` → `{token:"rgt_...", info}` |

Admin Go API (consumed by main):

```go
type Runtime interface { Apply(*model.Snapshot) error; Current() *model.Snapshot; Simulate(context.Context, model.SimRequest) model.SimResult; EngineKey(policyID, composite string) string }
type Telemetry interface { QueryLogs(model.LogQuery) []model.LogEntry; Subscribe(int) (<-chan model.LogEntry, func()); Timeseries(time.Duration, string) model.Timeseries; Overview() model.Overview; WritePrometheus(io.Writer) }
type Options struct { DataDir string; Store store.ConfigStore; Runtime Runtime; Telemetry Telemetry; Engine ratelimit.Engine; StaticFS fs.FS; Logger *slog.Logger; Version, InstanceID, DataPlaneAddr, AdminAddr string; CookieSecure bool; MetricsPublic bool; BootstrapPassword string }
func New(o Options) (*Server, error)   // loads auth.json, bootstraps admin
func (s *Server) Handler() http.Handler
func (s *Server) Tokens() gateway-compatible TokenVerifier (method Verify(token, scope string) bool)
func (s *Server) Start(ctx context.Context) // launches store.Watch loop
```

## Dashboard (`internal/dashboard/static`)

Pages: Login, Overview (KPIs, live RPS/limited chart, status breakdown, top
limited keys/routes/policies/consumers), Live Logs (streaming table w/ pause,
filters, detail drawer, export CSV), Routes, Policies, Plans, Consumers (+ key
issuance with copy-once modal), Simulator ("test a request"), Limits inspector
(peek/reset), Integration (copy-paste snippets for curl/Node/Python/Go/NGINX
auth_request/Kubernetes, pre-filled with this instance's addresses), Audit log,
Settings (+ users, API tokens, import/export). Dark/light theme, keyboard
shortcuts (`g o` overview, `g l` logs, `/` search), responsive.
