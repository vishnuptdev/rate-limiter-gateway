# Integrating RateGuard

RateGuard can enforce limits in three ways. Pick the one that fits where your
traffic enters and where your services make their calls.

| Mode | Where RateGuard sits | Who enforces | Best for |
|---|---|---|---|
| **1. Reverse proxy** | In the request path, in front of your upstream | RateGuard returns `429` itself | Public APIs, or any HTTP service you can route through a proxy |
| **2. Check API** | Beside your service; your code calls it | Your service acts on the decision | Services that already own their request path, or that need a custom cost per operation |
| **3. Both** | Proxy for external traffic, check API for internal calls | Both | Mixed estates: public API plus internal or background work |

Examples for each language are under [`examples/`](../examples/). The dashboard's
**Integration** page also shows copy-paste snippets pre-filled with your
instance's addresses.

Throughout this guide:

- `RateGuard data plane` means `:8080`.
- `RateGuard admin` means `:9000` (dashboard and REST API).
- Replace hostnames and keys with your own values.

---

## Mode 1: Reverse proxy

RateGuard receives each request, selects a route, evaluates its policies, and
either returns `429` or forwards the request to the route's upstream.

### Step 1. Start RateGuard

Run it with the binary or the container image (see the [README quickstart](../README.md#60-second-quickstart)).
For more than one instance, set `RLG_ENGINE=redis` and `RLG_STORE=redis` on each
instance and point them at the same Redis.

Open the admin dashboard on port 9000 and log in as `admin`. If this is a fresh
install, you will be asked to change the password (`must_change_password`).

### Step 2. Create a policy

A policy is one rate limit: an algorithm, a limit, a window, and the key the
limit is counted against.

In **Policies**, create a policy and set:

- **Algorithm**: one of `token_bucket`, `sliding_window`, `sliding_window_counter`,
  `fixed_window`, `concurrency`. See the [algorithm table](../README.md#choosing-an-algorithm).
- **Limit** and, for window algorithms, **window** (for example 100 per 1 minute) and
  optional **burst** for token bucket.
- **KeyBy**: what the limit is counted per. Typical choices are the API key
  (`api_key`), the client IP, or a header value. Combine parts when needed.
- **Mode**: `enforce` denies requests. `shadow` records would-be denials and lets
  the request through, which is the safe way to roll out a new limit.
- **Fail mode**: `open` lets requests through if the limiter backend is down;
  `closed` returns `503 limiter_unavailable`.

Start new policies in `shadow` mode, watch **Live Logs** and the Overview for a
day, then switch to `enforce`.

### Step 3. Create a route

A route tells RateGuard which requests belong to which upstream.

In **Routes**, create a route and set:

- **Host**: exact (`api.acme.com`) or suffix (`*.acme.com`).
- **Path prefix**: matched on segment boundaries. `/api` matches `/api` and
  `/api/orders`, but not `/apix`.
- **Methods**: uppercase HTTP methods (for example `GET`, `POST`).
- **Upstream**: an absolute `http://` or `https://` URL, for example
  `http://orders.internal:8000`.
- **Strip prefix**: remove the path prefix before forwarding, if the upstream does
  not expect it.
- **Require API key**: when on, a missing or invalid key returns `401`. An invalid
  key on an optional route also returns `401`.
- **Policies**: the policies to evaluate on this route. Global policies listed in
  Settings apply to every route.
- **Priority**: when several routes match, the highest priority wins. Ties go to the
  longest path prefix.

Requests that match no route get `404 {"error":"no_route"}`.

### Step 4. Issue consumer keys

Each customer or application that calls the API is a **consumer**. Consumers can
belong to a **plan**, which can override the policy numbers for everyone on that
plan. A consumer can also have its own override.

In **Consumers**, create a consumer, then **Issue key**. The key looks like
`rlg_live_...` and is shown **once**. RateGuard stores only its SHA-256 hash.

Give the key to the client. The client can send it in either of two ways:

```bash
curl -H "X-API-Key: rlg_live_..."           http://localhost:8080/api/orders
curl -H "Authorization: Bearer rlg_live_..." http://localhost:8080/api/orders
```

The header name is configurable in Settings (`APIKeyHeader`, default `X-API-Key`).

### Step 5. Point clients at RateGuard

Change your clients' base URL from the upstream to RateGuard (`:8080`). Keep the
same paths, so the route matches. RateGuard forwards the request with
`X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host` and
`X-RateGuard-Consumer` (the consumer ID) set. Any inbound `X-RateGuard-*` headers
are stripped.

If RateGuard runs behind a load balancer or NGINX, add that proxy's address to
Settings → **Trusted proxies** (CIDR or IP). Only then does RateGuard read the
client IP from `X-Forwarded-For`.

### Step 6. Check it works

```bash
# Allowed: 200 from the upstream, with RateLimit-* headers
curl -i -H "X-API-Key: rlg_live_..." http://localhost:8080/api/orders

# Repeat until the limit is hit. Denied: 429 with Retry-After
curl -i -H "X-API-Key: rlg_live_..." http://localhost:8080/api/orders
```

A denied response looks like this:

```
HTTP/1.1 429 Too Many Requests
RateLimit-Limit: 100
RateLimit-Remaining: 0
RateLimit-Reset: 12
RateLimit-Policy: 100;w=60
Retry-After: 12
Content-Type: application/json

{"error":"rate_limited","message":"Rate limit exceeded","policy":"orders-per-minute","limit":100,"remaining":0,"retry_after_s":12,"reset_s":12}
```

Watch **Live Logs** to see each decision, and use the **Simulator** to test a
request against the current configuration without sending it.

### Concurrency policies

A `concurrency` policy caps in-flight requests. Its slot is released when the
proxied response finishes, so it only works in proxy mode.

---

## Mode 2: Check API

Your service asks RateGuard for a decision and then acts on it. RateGuard does
not forward the request. This suits services that already handle their own
routing, or that want to charge a different cost per operation.

### Step 1. Enable the check API

In Settings, turn on **Check API** (`CheckAPIEnabled`). It is served on the data
plane at `POST /_rlg/v1/check`.

### Step 2. Create a token with the `check` scope

In **Settings → API tokens**, create a token with scope `check`, and set an expiry
if you can. The token looks like `rgt_...` and is shown **once**. Store it in your
service's secret manager. Use the narrowest scope; a `check` token cannot read
configuration or change anything.

### Step 3. Call the check API

Send the consumer's API key in the body and the RateGuard token in the
`Authorization` header:

```bash
curl -s -X POST http://rateguard:8080/_rlg/v1/check \
  -H "Authorization: Bearer $RATEGUARD_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
        "method": "GET",
        "path": "/v1/orders",
        "host": "api.acme.com",
        "api_key": "rlg_live_...",
        "ip": "203.0.113.7",
        "headers": {"X-Tenant": "t1"},
        "cost": 1
      }'
```

Fields:

| Field | Required | Notes |
|---|---|---|
| `method`, `path`, `host` | Yes, unless `route_id` is given | Used to match the route |
| `route_id` | No | Skips route matching |
| `api_key` | No | The consumer's key. Omit it for IP-keyed policies |
| `ip` | No | Client IP, for `ip`-keyed policies |
| `headers` | No | Headers the policies key on |
| `cost` | No | Units this operation consumes (default 1) |

The response is always `200`, even when the request is limited. Read `allowed`:

```json
{"allowed":false,"decision":"limited","route_id":"r_orders","consumer_id":"c_acme",
 "policy_id":"orders-per-minute","limit":100,"remaining":0,"reset_s":12,"retry_after_s":12,
 "headers":{"RateLimit-Limit":"100","RateLimit-Remaining":"0","RateLimit-Reset":"12","Retry-After":"12"},
 "results":[{"policy_id":"orders-per-minute","allowed":false,"limit":100,"remaining":0,"shadow":false}]}
```

When `allowed` is `false`, your service should return `429` to its own client and
copy `headers` onto the response. The response also includes `results`, one entry
per policy evaluated.

Concurrency policies are skipped by the check API, because there is no completion
signal.

### Failing open in your service

If the check call fails or times out, decide what your service does. The examples
use a 50 ms timeout and let the request through (fail-open). Pick fail-closed only
for operations where unlimited traffic is worse than an outage.

### Examples

- Node / Express: [`examples/node/express-middleware.js`](../examples/node/express-middleware.js)
- Python / FastAPI: [`examples/python/fastapi_dependency.py`](../examples/python/fastapi_dependency.py)
- Go `net/http`: [`examples/go/middleware.go`](../examples/go/middleware.go)

---

## Mode 3: Both

Use the proxy for external traffic and the check API for calls your own services
make. The two modes share the same policies, limits and consumers, so one
consumer's budget is shared across both.

**Avoid counting the same request twice.** If a service receives a request through
the proxy and then calls the check API for the same route, policy and key, each
request consumes two units of the same limit. Give internal callers their own
route or policy, or skip the check call for requests that already came through
the proxy.

---

## Deployment patterns

### Docker Compose

[`docker-compose.yml`](../docker-compose.yml) runs two RateGuard instances sharing
Redis, plus a demo upstream (`traefik/whoami`). Create `.env` with `REDIS_PASSWORD`
and `RLG_ADMIN_PASSWORD`, then `docker compose up --build`. Point a route at
`http://whoami:80` to try it.

### NGINX in front

[`examples/nginx/auth_request.conf`](../examples/nginx/auth_request.conf) shows
NGINX proxying to two RateGuard instances. Use this pattern when NGINX already
terminates TLS. Note that `auth_request` does not fit the check API; put RateGuard
in the proxy path instead, as the file explains.

### Kubernetes

[`examples/k8s/rateguard.yaml`](../examples/k8s/rateguard.yaml) has a Secret, a
two-replica Deployment with readiness (`/_rlg/readyz`) and liveness
(`/_rlg/healthz`) probes, and a Service. It needs an existing Redis, and it uses
`emptyDir` for `/data`; read the comments there before using it for real traffic.

---

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `404 {"error":"no_route"}` | No enabled route matches the host, path prefix or method. Check **Routes** and the path-prefix segment rule |
| `401 unauthorized` | Route requires a key and none was sent, or the key is revoked, expired, or belongs to a disabled consumer |
| Every request has the same client IP | RateGuard is behind a proxy that is not in Trusted proxies, so the proxy's IP is used |
| Limit never triggers | The policy is in `shadow` mode, or its `KeyBy` does not match the traffic (for example, `api_key` with no key sent) |
| `502 bad_gateway` | The upstream is unreachable or timed out |
| `503 limiter_unavailable` | The policy is fail-closed and the limiter backend (Redis) failed |
| Check API returns `401` | The token is wrong, expired, or lacks scope `check`. Check **Settings → API tokens** |
| Check call never reaches RateGuard | The check API is disabled in Settings (`CheckAPIEnabled`), or the service is calling the wrong base URL |
