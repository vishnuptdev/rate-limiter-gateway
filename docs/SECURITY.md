# Security

This document covers RateGuard's threat model, its authentication and
authorization design, a hardening checklist for production, and known limitations.
For the detailed behavioural contract, see [ARCHITECTURE.md](ARCHITECTURE.md).

## Reporting a vulnerability

Please report suspected vulnerabilities privately. Do not open a public issue.

- Contact: use GitHub private vulnerability reporting: [Report a vulnerability](https://github.com/vishnuptdev/rate-limiter-gateway/security/advisories/new). Please do not open public issues for security problems.
- Include: affected version or commit, steps to reproduce, and the impact you
  expect.
- We aim to acknowledge reports within **7 days** and to
  keep you informed until a fix ships. We are happy to credit reporters who want
  it.

## Threat model

### Assets

| Asset | Why it matters |
|---|---|
| Consumer API keys (`rlg_live_...`) | Identify a customer to the data plane. Leaked keys let someone spend another customer's budget |
| Admin credentials and sessions | Control routes, policies, keys and users. Full control of the gateway |
| API tokens (`rgt_...`) | Give CI systems and services access to the admin or check API |
| Configuration (routes, policies, plans) | Decides what is allowed, and where traffic goes |
| Audit log | Evidence of who changed what |
| Rate-limit state (memory or Redis) | Determines whether limits hold |
| Upstream services | Protected by RateGuard, and reachable through it |

### Actors

| Actor | Goal |
|---|---|
| External client | Exceed limits, bypass them, or exhaust RateGuard resources |
| Consumer with a valid key | Stay within its own budget, or steal another consumer's budget |
| Compromised or curious dashboard viewer | Read data they should not see (for example, keys or other users) |
| Phishing or XSS victim with an admin session | Act as an admin through the browser |
| Network attacker | Read or modify traffic in transit, including credentials |
| Attacker with Redis access | Reset counters, read or alter configuration |
| Misconfigured proxy or spoofed headers | Pretend to be another client IP or consumer |

### Trust boundaries

1. **Client to data plane (`:8080`).** Untrusted. Inbound `X-RateGuard-*` headers
   are stripped. `X-Forwarded-For` is honoured only when the immediate peer is in
   Trusted proxies.
2. **Service to check API (`POST /_rlg/v1/check`).** Authenticated with a `check`-scope
   token. Treat the token as a secret.
3. **Browser to admin (`:9000`).** Authenticated by session cookie or API token,
   with CSRF protection and role checks on every endpoint.
4. **RateGuard to Redis.** Protected by AUTH and optionally TLS. Redis holds
   configuration (with key hashes, never plaintext keys) and counters.
5. **RateGuard to upstream.** Upstreams should trust RateGuard only on a private
   network path.

### Main threats and controls

| Threat | Controls |
|---|---|
| Spoofing client IP with `X-Forwarded-For` | Only trusted hops are walked; the rightmost untrusted address is used. Untrusted peers' headers are ignored |
| Forging `X-RateGuard-*` headers to upstreams | Stripped on ingress |
| Guessing or brute-forcing consumer keys | Keys carry 32 random base62 characters after `rlg_live_`. Only the SHA-256 hash is stored. Lookup uses the hash |
| Timing attacks on secrets | Constant-time comparison for secrets; equal-time path for unknown usernames (a dummy hash is computed) |
| Password guessing | Per-username and per-IP lockout: 5 failures, then exponential lockout starting at 30 s, doubling, capped at 15 min. Generic error messages |
| Weak passwords | Minimum 12 characters. Passwords are hashed with PBKDF2-SHA256 (600,000 iterations, 16-byte random salt) |
| Session theft | Session IDs are 32 random bytes, stored server-side hashed. Cookie is `HttpOnly; SameSite=Strict; Path=/; Secure` (Secure under TLS or `RLG_COOKIE_SECURE=true`). Idle timeout 12 h, absolute 7 d |
| CSRF on admin actions | Per-session CSRF token required as `X-CSRF-Token` on every non-GET request authenticated by cookie. Bearer-token requests do not carry cookies and are not subject to it |
| XSS in the dashboard | Strict CSP: `default-src 'self'`, `script-src 'self'`, no inline scripts, no CDN, no external fonts |
| Clickjacking | `frame-ancestors 'none'` and `X-Frame-Options: DENY` |
| Cached admin responses | `Cache-Control: no-store` on `/api/*` |
| Oversized or malformed input | JSON bodies capped at 1 MiB (import: 10 MiB); unknown JSON fields rejected. Proxied bodies capped by `MaxBodyBytes` when set |
| Slowloris and hung connections | All HTTP servers have timeouts. Per-route upstream timeouts |
| Memory exhaustion from telemetry | Log buffer is a fixed-size ring (default 10,000 entries). Top-N maps capped at 10k keys with eviction. Metric label cardinality capped at 500 routes or policies, overflow to `_other`. Percentiles from fixed histogram buckets |
| Secrets in logs or storage | API keys, passwords and tokens are never logged or stored in plaintext. `RateKey` never contains a raw API key |
| Unauthorized config changes | RBAC on every endpoint (viewer, editor, admin). Every mutation is written to the audit log |
| Tampering with a deployed config | Config writes are validated before they are applied or saved. Redis writes use a version guard so an older snapshot cannot overwrite a newer one |
| Scraping metrics | `/metrics` requires a session or a token with `read` scope, unless `RLG_METRICS_PUBLIC=true` |

## Authentication and authorization model

### Roles

| Capability | viewer | editor | admin |
|---|---|---|---|
| View overview, logs, routes, policies, plans, consumers | yes | yes | yes |
| Create and edit routes, policies, plans, consumers | no | yes | yes |
| Issue and revoke consumer keys | no | yes | yes |
| Reset rate-limit counters | no | yes | yes |
| Run the simulator with `consume=true` | no | yes | yes |
| Change settings | no | no | yes |
| Manage users, API tokens, audit log | no | no | yes |
| Export and import configuration | no | no | yes |

Users with `must_change_password` can only call `/api/auth/*` until they change
their password. Admins cannot delete themselves, and the last admin cannot be
removed.

### Users and bootstrap

Users are stored in `<RLG_DATA_DIR>/auth.json` with file mode `0600`. Each entry
holds the username, role, password hash (`pbkdf2_sha256$600000$<salt>$<hash>`),
`must_change_password`, and timestamps.

On first start, if there are no users, RateGuard creates `admin`:

- With `RLG_ADMIN_PASSWORD` set, that password is used and `must_change_password`
  is `false`. Treat this variable as a bootstrap secret: remove it from the
  environment once the admin account exists.
- Without it, a random 20-character password is printed once to stderr, and
  `must_change_password` is `true`.

### Sessions and CSRF

Logging in returns a CSRF token alongside the session cookie. The dashboard sends
it as `X-CSRF-Token` on every write. Sessions live in memory, so a restart signs
everyone out (see limitations).

### API tokens

API tokens are for CI, infrastructure-as-code and services, and carry one or more
scopes:

| Scope | Allows |
|---|---|
| `admin` | Everything an admin can do through the API |
| `read` | Read-only admin API, and `/metrics` |
| `check` | `POST /_rlg/v1/check` only |

Tokens look like `rgt_` followed by 40 random base62 characters. RateGuard stores
the SHA-256 hash and shows the plaintext once, at creation. Set an expiry on every
token that does not need to live forever. Revoke tokens with
`DELETE /api/tokens/{id}`.

Bearer-token requests are not subject to CSRF checks, because the browser does
not attach them automatically.

## Hardening checklist

**Secrets and accounts**

- [ ] Set `RLG_ADMIN_PASSWORD` to a long random value (12+ characters, ideally
      20+) and remove it from the environment after the first start.
- [ ] Have every user change `must_change_password` on first login.
- [ ] Create named users rather than sharing `admin`. Use `viewer` and `editor` where
      admin is not needed.
- [ ] Give each integration its own API token with the narrowest scope and an
      expiry. Rotate tokens on a schedule and when staff change.
- [ ] Store `RLG_ADMIN_PASSWORD`, `RLG_REDIS_PASSWORD` and API tokens in a secret
      manager. Do not put them in images, compose files or shell history.
- [ ] Review the audit log regularly.

**Transport**

- [ ] Serve the admin listener over TLS (`RLG_TLS_CERT`, `RLG_TLS_KEY`), or terminate
      TLS in front of it and keep port 9000 on a private network.
- [ ] Put the data plane behind TLS (load balancer or NGINX). Keys travel in headers.
- [ ] Set `RLG_COOKIE_SECURE=true` whenever the dashboard is served over HTTPS.
- [ ] Use `RLG_REDIS_TLS=true` and a Redis password when Redis is not on a
      loopback or private-only network.

**Network**

- [ ] Restrict the admin port (9000) to operators' networks: firewall rules,
      security groups, or a Kubernetes NetworkPolicy.
- [ ] Keep upstreams on a private network that only RateGuard can reach.
- [ ] Set **Trusted proxies** to exactly the addresses of your load balancers, and
      nothing wider. Do not trust `0.0.0.0/0`.
- [ ] Keep `RLG_METRICS_PUBLIC` unset (or `false`). Scrape `/metrics` with a `read`
      token.

**Runtime**

- [ ] Run the container image as its non-root user with a read-only root filesystem
      (the provided Dockerfile and Kubernetes manifest do this).
- [ ] Persist `RLG_DATA_DIR` on a volume with backups: it holds `auth.json` and
      `audit.jsonl`.
- [ ] Do not run `RLG_DEMO=true` in production. Demo mode seeds sample
      configuration and a dummy upstream.
- [ ] Set `MaxBodyBytes` on routes that receive uploads or other large bodies.
- [ ] Run new policies in `shadow` mode first, then enforce. Choose `fail_mode`
      deliberately for each policy.
- [ ] Use Redis for shared state across instances, and monitor the engine's health
      on the Overview page or at `/api/system`.

## Hardening

Protections built into the data plane and its dependencies. Each has a
regression test (`internal/gateway/hardening_test.go`,
`internal/telemetry/hardening_test.go`, `internal/redisclient/parse_test.go`).

| Area | Protection |
|---|---|
| Forward-auth trust | RateGuard evaluates the route described by `X-Forwarded-Uri` (preferred over `X-Original-URI` / `X-Original-URL`), `X-Forwarded-Method` and `X-Forwarded-Host`. **The calling proxy must set these headers on every auth request**; a proxy that passes client-supplied values through lets the client choose the route that is checked. All shipped examples and dashboard snippets set them; with ingress-nginx the `auth-snippet` is required, with Traefik keep `trustForwardHeader` off, with Envoy do not allow those headers through `allowed_headers`. See [INTEGRATION.md](INTEGRATION.md#trust-requirement-the-proxy-must-set-the-forwarded-headers) |
| Forward-auth consumer header | An allowed answer always carries `X-RateGuard-Consumer` (empty when anonymous), so proxies that copy it onto the upstream request overwrite a client-sent value |
| IPv6 address rotation | The `ip` key part keys IPv6 clients by prefix: `Settings.IPv6PrefixLen` (default 64, valid 32..128, 128 = per address). IPv4 and IPv4-mapped addresses are always keyed in full |
| Protocol upgrades | `Upgrade: h2c` is refused with `400` on every route (an h2c connection would multiplex unmetered requests) and `HTTP2-Settings` is never forwarded. WebSocket and other upgrades are refused (`400 upgrade_not_allowed`) unless the route sets `allow_upgrade`; an allowed upgrade counts as one request, concurrency policies hold their slot for the connection's lifetime, and the route timeout and the data-plane server's read/write timeouts (60 s / 120 s) bound it |
| Header spoofing | Inbound `X-RateGuard-*` headers (including `_` variants such as `X-Rateguard_Consumer`) are stripped. Request trailers named `X-RateGuard-*`, hop-by-hop headers (`Connection`, `Keep-Alive`, `TE`, `Upgrade`, ...) or client-IP headers are dropped together with their `Trailer` declaration |
| Client-IP headers | Upstreams get `X-Forwarded-For` replaced by the peer address for untrusted peers (appended to only for trusted proxies), `X-Real-IP` set to the client IP RateGuard limited on, and no inbound `Forwarded` |
| Dashboard session cookie | The `rg_session` cookie is removed from proxied requests. Browsers send cookies to every port of a host, so a dashboard sharing a host name with the data plane would otherwise leak admin sessions to upstreams. Other cookies pass through. API keys are never read from cookies |
| Route matching | Hosts compare case-insensitively with any port and trailing dot ignored (`API.example.com.:443` = `api.example.com`). Paths are **case-sensitive** and `;params` are part of the path; give catch-all routes limits you can live with for such variants. Configure hosts in their ASCII (punycode) form: RateGuard does not convert IDNs |
| Telemetry lock | Log searches copy the ring in chunks of 128 entries under the hub lock and filter outside it, so a dashboard search never stalls `Record` on the request path |
| Redis replies | Bulk and array lengths are range-checked, arrays are not preallocated from the announced length, and nesting is capped at 32 levels, so a hostile or corrupted Redis cannot exhaust memory or overflow the stack |
| Slow clients | Both listeners set `ReadHeaderTimeout` (10 s) and `ReadTimeout`; the data plane also `WriteTimeout`. The admin listener's `WriteTimeout` is 0 for the live-log stream, which requires an authenticated session or `read` token before it streams, caps streams globally and per user, and sets a 30 s deadline on every write |

## Known limitations

These are things we want operators to know about. Several have planned fixes.

- **Sessions are in memory.** A restart or a move to another instance logs users
  out. Users log in again. This is deliberate for now.
- **Users and API tokens are per instance.** `auth.json` lives in each instance's
  `RLG_DATA_DIR` and instances do not sync it. A user or token created on one
  instance does not exist on another, which matters for check-API tokens if you
  run several instances. Until this is addressed, create users and tokens on each
  instance that needs them, and keep the file on durable storage.
- **Key-table cap lets new keys through.** Each engine tracks up to about 1,000,000
  keys by default. Once the cap is full, new keys are allowed but not tracked. An
  attacker who floods with unique keys can therefore get unlimited traffic on the
  overflow keys. Watch the engine's key count and alert on it.
- **Fail-open policies favour availability.** A policy with `fail_mode: open` lets
  traffic through when Redis is down. Choose it knowingly.
- **Shadow mode does not enforce.** Shadow denies are recorded and logged, and the
  request continues.
- **The check API is only as trustworthy as its caller.** RateGuard trusts the
  token's holder to report the true method, path and key. Services must not let
  clients choose those fields.

## Security-related configuration

| Setting | Purpose |
|---|---|
| `RLG_ADMIN_PASSWORD` | Bootstrap admin password (first start only) |
| `RLG_TLS_CERT`, `RLG_TLS_KEY` | TLS for the admin listener |
| `RLG_COOKIE_SECURE` | Force the `Secure` cookie attribute |
| `RLG_METRICS_PUBLIC` | Allow unauthenticated `/metrics` (keep unset) |
| `RLG_REDIS_PASSWORD`, `RLG_REDIS_TLS` | Redis AUTH and TLS |
| `RLG_DEMO` | Seed demo data (keep unset in production) |
| Trusted proxies (Settings) | Which peers may set `X-Forwarded-For` |
| `APIKeyHeader` (Settings) | Header name used for consumer keys |
| `MaxBodyBytes` (Settings) | Request body cap on proxied routes |
