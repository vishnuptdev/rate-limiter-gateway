# Contributing to RateGuard

Thanks for your interest. Bug reports, docs fixes and focused features are all
welcome. By taking part you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Before you start

- Search existing issues first. For anything larger than a small fix, open an
  issue to agree on the approach before you write code.
- Security problems: do **not** open a public issue. See [docs/SECURITY.md](docs/SECURITY.md).

## Development setup

You need Go 1.24.7 or newer (the `go.mod` floor). Redis 7 is optional (only the Redis tests need it).

```bash
git clone https://github.com/vishnuptdev/rate-limiter-gateway.git
cd rate-limiter-gateway
make build        # builds ./rateguard
make demo         # runs with RLG_DEMO=true and ./data-demo
```

The dashboard is plain HTML, CSS and JS embedded with `go:embed`
(`internal/dashboard/static`). There is no frontend build step.

| Path | What lives there |
|---|---|
| `cmd/rateguard` | Entry point and env-var configuration |
| `cmd/rateguard-bench` | Loopback load-test tool |
| `internal/gateway` | Data plane: routing, auth, proxy, check API, forward auth |
| `internal/ratelimit` | The seven algorithms, memory and Redis engines |
| `internal/admin` | Admin REST API, auth, sessions, audit log |
| `internal/store` | Config stores (file, Redis) and validation |
| `internal/telemetry` | Live logs, stats, Prometheus metrics |
| `internal/redisclient` | Minimal RESP client |
| `docs/` | Architecture contract, integration guide, performance, security |

## Running tests

```bash
make test         # go test -race ./...
make lint         # go vet + gofmt check
```

The Redis engine, client and store tests skip when Redis is unreachable. To run
them:

```bash
docker run --rm -d -p 6379:6379 redis:7
REDIS_TEST_ADDR=127.0.0.1:6379 make test
```

Benchmarks and the load test are described in
[docs/PERFORMANCE.md](docs/PERFORMANCE.md#reproducing).

## Code style

- **Standard library only.** RateGuard has zero third-party Go dependencies and
  that is a feature. A PR that adds a module needs a very strong reason.
- Run `gofmt` (CI enforces it) and keep `go vet` clean.
- Cover behaviour changes with tests, using `-race` for anything concurrent.
  For bug fixes, write the failing test first where practical.
- Security-sensitive code (auth, key handling, path normalisation, header
  handling) should state the threat it addresses in a comment or test.
- Update the docs when behaviour, config, headers or endpoints change.

## Commit style

A short imperative subject (about 72 characters) and an optional body that
explains why. A conventional prefix is welcome but not required:

```
fix(gateway): strip inbound X-RateGuard-* headers on forward auth
feat(ratelimit): add GCRA to the Redis engine
docs: clarify trusted proxies
```

## Pull request flow

1. Fork the repo and branch from `main` (`git switch -c fix/short-name`).
2. Make the change with tests, then run `make lint test`.
3. Open a PR and fill in the template. Keep it focused: one concern per PR.
4. CI must pass: gofmt, vet, race tests with Redis, build, Docker build.
5. A maintainer reviews. Expect some back and forth.

## Releasing (maintainers)

Update `CHANGELOG.md`, then push a tag such as `v1.0.0`. The release workflow
builds binaries and SHA-256 checksums for linux, darwin and windows (amd64 and
arm64), creates the GitHub release, and pushes a multi-arch image to
`ghcr.io/vishnuptdev/rateguard`.
