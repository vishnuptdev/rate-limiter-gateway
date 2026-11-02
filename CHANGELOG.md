# Changelog

All notable changes to RateGuard are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
to follow [Semantic Versioning](https://semver.org/).

## [1.0.0] - Unreleased

First public release.

### Added

- **Single binary, zero dependencies.** Go standard library only. The admin
  dashboard is embedded with `go:embed` and has no build step.
- **Three integration modes.** Reverse proxy, check API (`POST /_rlg/v1/check`)
  and forward auth (`/_rlg/v1/auth`) for NGINX `auth_request`, Traefik, Caddy,
  Envoy `ext_authz` and ingress-nginx.
- **Seven algorithms.** Token bucket, sliding window (exact log), sliding-window
  counter, fixed window, concurrency, GCRA and leaky bucket (traffic shaping).
- **Memory and Redis engines.** The Redis engine runs each algorithm as one
  atomic Lua script so several instances share counters. The Redis config store
  keeps a versioned configuration that all instances watch.
- **Policies, plans and consumers.** Per-plan and per-consumer limit overrides,
  API keys hashed with SHA-256 and shown once, shadow mode for dry-running a
  limit, and fail-open or fail-closed behaviour per policy.
- **Standard headers.** IETF `RateLimit-*` and `RateLimit-Policy` headers,
  `Retry-After` on `429`, and optional legacy `X-RateLimit-*` headers.
- **Admin dashboard.** Overview with live charts, streaming logs with filters
  and CSV export, a request simulator, a limits inspector (peek and reset),
  an integration page with copy-paste snippets, audit log, settings, and
  light and dark themes.
- **Access control.** Admin, editor and viewer roles, scoped API tokens
  (`admin`, `read`, `check`), PBKDF2-SHA256 password hashes, CSRF protection,
  login lockout with exponential back-off, and an audit log of every change.
- **Observability.** Prometheus metrics at `/metrics`, health and readiness
  endpoints at `/_rlg/healthz` and `/_rlg/readyz`.
- **Demo mode.** `RLG_DEMO=true` seeds routes, policies for every algorithm,
  plans, two consumers with API keys, and a local echo upstream.
- **Integration examples** for NGINX, Traefik, Caddy, Envoy, Kubernetes,
  Node/Express, Python/FastAPI, Go, Java/Spring, C#/ASP.NET Core, Ruby/Rack and
  PHP/PSR-15.
- **Deployment.** Distroless non-root Docker image, a Docker Compose file with
  two instances sharing Redis, and a Kubernetes manifest.
- **Release tooling.** GitHub Actions for CI (gofmt, vet, race tests against
  Redis 7, build, Docker build) and for tagged releases (binaries for linux,
  darwin and windows on amd64 and arm64, SHA-256 checksums, multi-arch image on
  ghcr.io).
- `rateguard version` prints the build version; Docker and `make` builds embed
  it.

### Performance

- Request-path and engine optimisations: allocation-free memory engine
  `Allow`, pooled proxy copy buffers, header writing without maps, an O(1)
  sliding-window log, and an allocation-light Redis client. The results and the
  machine they were measured on are in [docs/PERFORMANCE.md](docs/PERFORMANCE.md).

### Security

- Strict CSP on the dashboard, `HttpOnly` `SameSite=Strict` session cookies,
  constant-time secret comparison, bounded memory on every in-process
  structure, request path normalisation, and stripping of inbound
  `X-RateGuard-*` headers. See [docs/SECURITY.md](docs/SECURITY.md) for the
  threat model and known limitations.

[1.0.0]: https://github.com/vishnuptdev/rate-limiter-gateway/releases/tag/v1.0.0
