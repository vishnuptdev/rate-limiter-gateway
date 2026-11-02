# Plan: RateGuard v2 (commercial-grade gateway + dashboard)

Spec: `docs/ARCHITECTURE.md` (binding). Contract files already written:
`internal/model/model.go`, `internal/ratelimit/engine.go`, `internal/store/store.go`.

## Global Constraints

See "Global constraints" in `docs/ARCHITECTURE.md` — all 7 apply verbatim.
Each task owns ONLY the directories listed; never edit another task's directory.

### Task 1: Rate-limit engines
Dirs: `internal/ratelimit/`, `internal/redisclient/`.
- `NewMemory(opts MemoryOptions) *Memory` — sharded (64 shards) maps, all 5 algorithms
  (`token_bucket`, `sliding_window` exact log, `sliding_window_counter` weighted two-window,
  `fixed_window`, `concurrency`), idle-key GC goroutine (keys idle > 2×window removed every 30s),
  max keys cap (default 1,000,000; when full, new keys are allowed but not tracked — log once).
  Injectable clock for tests.
- `NewRedis(c *redisclient.Client, prefix string) *Redis` — one atomic Lua script per algorithm,
  params as ARGV, Redis server time (`TIME`) inside scripts to avoid clock skew, EVALSHA with
  NOSCRIPT fallback, PEXPIRE on all keys. Concurrency uses a sorted set of lease IDs with
  lease TTL 60s (crash-safe), Release removes the lease (Allow returns lease id internally via
  key-scoped tracking: the Engine API has no lease handle, so store leases as ZSET members
  `<nonce>` and Release removes the oldest member — document this).
- redisclient: options struct (`Addr, Password, DB, PoolSize, DialTimeout, RWTimeout, TLS bool`),
  AUTH + SELECT on dial, per-command deadlines, `EvalSha`, `ScriptLoad`, keep backward-compatible `New(addr, n)`.
- Decision semantics exactly per `engine.go` docs; Remaining never negative; Cost>Limit → denied with RetryAfter = time to full.
- Tests: per algorithm correctness with fake clock, `-race` 100-goroutine concurrency (exactly Limit allowed),
  Redis two-instance sharing tests, Peek doesn't consume, Reset works, Release frees slot.
- Delete old `internal/limiter/` package when done ONLY IF nothing else imports it (main still does — leave it; Task 7 removes it).

### Task 2: Store + gateway data plane
Dirs: `internal/store/`, `internal/gateway/`.
Implement everything in spec sections "Data plane behaviour", "Decision (check) API",
"Gateway Go API", "Store". Tests use an in-test fake `ratelimit.Engine` (Task 1 is parallel).
httptest upstreams; test routing priority, prefix segment matching, trusted proxy XFF,
API key auth paths, overrides precedence, shadow mode, fail open/closed, headers, 429 body,
check API auth + response, concurrency release, header spoof stripping, simulator, Validate rules,
file store atomic write + perms, redis store version guard (skip w/o redis).

### Task 3: Telemetry
Dir: `internal/telemetry/`. Implement spec section "Telemetry" fully. Bounded memory.
Tests: ring buffer wrap, query filters + cursor, subscriber drop policy, timeseries gap fill +
step sizes, percentile accuracy within bucket tolerance, overview tops, Prometheus output
parses (line format), cardinality cap, concurrency `-race`.

### Task 4: Admin API + auth
Dir: `internal/admin/`. Implement spec section "Admin" fully (auth, security headers, Manager,
every REST endpoint, SSE, audit, tokens, RBAC, bootstrap, Prometheus endpoint auth).
Uses local interfaces `Runtime`, `Telemetry`; tests with fakes + `store` memory/file store
(Task 2 parallel: if `store.Validate`/`store.NewMemory` not yet present, define a tiny local
fake ConfigStore in tests and call validation through an injectable `Options.Validate func(*model.Snapshot) error`
defaulting to `store.Validate` — coordinate via the exact name `store.Validate`).
Tests: login/lockout, CSRF required, role matrix, must-change-password gating, token scopes,
key issuance plaintext-once + hash stored, delete-referenced 409, import dry-run, audit entries,
security headers, body limits, SPA fallback.

### Task 5: Dashboard SPA
Dir: `internal/dashboard/`. `embed.go` (`//go:embed static` → `var FS fs.FS` rooted at static).
Vanilla ES modules, hash router, no deps, CSP-compliant (no inline script/style attributes
set via HTML strings — use CSSOM/classes; `element.style.x=` is fine under CSP), hand-rolled SVG charts.
Every page in spec section "Dashboard". Consumes the REST API exactly as specified.
Professional SaaS-grade visual design. Include a `dev` mock mode: `?mock=1` serves fixture
data so it can be screenshot without a backend.

### Task 6: Docs, deploy, SDK examples
Dirs: `README.md`, `docs/INTEGRATION.md`, `docs/SECURITY.md`, `Dockerfile`, `docker-compose.yml`,
`.dockerignore`, `Makefile`, `examples/` (node express middleware using check API, python
fastapi dependency, go net/http middleware, nginx auth_request config, k8s manifests).
Only from spec; no Go code outside examples/go.

### Task 7: Integration (controller)
`cmd/rateguard/main.go`: env config, wire everything, demo mode (`RLG_DEMO=true` seeds
routes/policies/plans/consumer + dummy upstream), graceful shutdown, server timeouts. Remove
`cmd/gateway`, `internal/limiter`, `internal/proxy`, `internal/config`. End-to-end test.

### Task 8: More algorithms — GCRA and leaky bucket (shaping)
Dirs: `internal/model/` (add constants only), `internal/ratelimit/`, `internal/store/validate.go`, `internal/gateway/`, docs table in README.
- `AlgoGCRA = "gcra"`: Generic Cell Rate Algorithm (Stripe/Redis-cell style). State = one int64 TAT per key.
  Emission interval T = Window/Limit; tolerance τ = T*(Burst-1) (Burst 0 => Limit). Allow iff TAT - now <= τ; then
  TAT = max(TAT, now) + T*Cost. RetryAfter = TAT - τ - now when denied. Remaining = floor((τ - (TAT-now))/T)+... clamp >= 0.
  Memory: lock-free CAS on an atomic int64 per key. Redis: single Lua script with server TIME, 1 key (string), PEXPIRE.
- `AlgoLeakyBucket = "leaky_bucket"`: queue-based traffic shaping. Requests drain at Limit/Window; Burst = queue size (0 => Limit).
  A request that fits in the queue is ALLOWED with a `Delay` (new field `Decision.Delay time.Duration`): the gateway waits that
  long (context-aware, aborted on client disconnect) before proxying; if the queue is full -> denied (429) with RetryAfter.
  Check API returns `delay_ms` instead of sleeping. Memory + Redis (Lua) implementations.
- `model.Algorithms` gains both; Validate accepts them; Simulator shows them; README algorithm table lists 7 algorithms with when-to-use.
- Tests: exact semantics with fake clock, -race concurrency (exactly the allowed count), Redis shared-state tests, gateway delay test.

### Task 9: Performance — near-zero added latency
Dirs: `internal/gateway/`, `internal/ratelimit/`, `internal/telemetry/`, `internal/redisclient/`, `docs/PERFORMANCE.md`.
- Add benchmarks: engine Allow per algorithm (memory, parallel), gateway ServeHTTP overhead with a no-op upstream (allowed + 429 paths),
  check API, telemetry Record. Profile (`-cpuprofile`, `-memprofile`), then optimise the hot path: zero/near-zero allocations
  for key building and header writing, avoid fmt in hot path, precompute per-policy header strings at compile time, sync.Pool where useful,
  reverse proxy transport tuning (MaxIdleConnsPerHost, HTTP/2, keep-alives, buffer pool), Redis: pipeline/EVALSHA only, connection pool sizing,
  memory engine: avoid time.Now per call where safe (coarse clock with ≤1ms resolution, option), shard by maphash.
- Target and report: memory engine Allow < 100ns/op parallel; gateway overhead (excluding upstream) p50 < 50µs; 0-2 allocs on engine path.
- Write docs/PERFORMANCE.md with real numbers from this machine (before/after table) and tuning guide.

### Task 10: Open-source launch polish (stars + resume)
Runs last, after Tasks 4/5/7/8/9 merged. Files: LICENSE (MIT, "Copyright (c) 2026 vishnuptdev"), README.md, CONTRIBUTING.md,
CODE_OF_CONDUCT.md (Contributor Covenant 2.1), CHANGELOG.md (v1.0.0), .github/workflows/ci.yml (go 1.24: gofmt check, vet, test -race with redis service,
build; docker build), .github/workflows/release.yml (on tag v*: cross-compile linux/darwin/windows amd64+arm64 tarballs with checksums,
push multi-arch image to ghcr.io/vishnuptdev/rateguard), .github/ISSUE_TEMPLATE/{bug_report,feature_request}.yml, .github/pull_request_template.md,
.github/dependabot.yml (github-actions + docker), docs/screenshots/*.png (real Playwright screenshots of the dashboard in demo mode, light+dark).
README: hero line + badges (CI, Go Report Card, license, Go version, release), screenshot, "Why RateGuard" bullets, 60-second quickstart
(docker run + binary + `RLG_DEMO=true`), feature list, 7-algorithm table, integration modes, real benchmark numbers from docs/PERFORMANCE.md,
architecture diagram, config reference (all env vars with defaults), FAQ, roadmap, contributing, license. Honest claims only (no fake numbers, no
false comparisons with other products).
