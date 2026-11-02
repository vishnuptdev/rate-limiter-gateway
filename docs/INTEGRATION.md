# Integrating RateGuard

RateGuard can enforce limits in four ways. Pick the one that fits where your
traffic enters and where your services make their calls.

| Mode | Where RateGuard sits | Who enforces | Best for |
|---|---|---|---|
| **1. Reverse proxy** | In the request path, in front of your upstream | RateGuard returns `429` itself | Public APIs, or any HTTP service you can route through a proxy |
| **2. Check API** | Beside your service; your code calls it | Your service acts on the decision | Services that already own their request path, or that need a custom cost per operation |
| **3. Forward auth** | Beside an existing proxy or ingress that calls it per request | The proxy relays RateGuard's `200` / `429` | NGINX, Traefik, Caddy, Envoy, ingress-nginx: no code changes, no traffic through RateGuard |
| **4. Both** | Proxy for external traffic, check API for internal calls | Both | Mixed estates: public API plus internal or background work |

### Which mode should I use?

| Your situation | Use |
|---|---|
| You can point clients (or a DNS name) at RateGuard | Reverse proxy |
| You already run NGINX / Traefik / Caddy / Envoy / ingress-nginx and want limits without moving traffic | Forward auth |
| Limits depend on something only your code knows (a cost per operation, a tenant resolved from the body) | Check API |
| Background jobs or service-to-service calls | Check API |
| You need leaky-bucket shaping with the request held by the platform | Reverse proxy or forward auth (both wait server-side); the check API only reports `delay_ms` |
| You need concurrency limits | Reverse proxy only (the check API and forward auth have no completion signal) |
| Language SDKs (Java, .NET, Ruby, PHP, Node, Python, Go) | Check API |

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
  `fixed_window`, `concurrency`, `gcra`, `leaky_bucket`. See the [algorithm table](../README.md#choosing-an-algorithm).
- **Limit** and, for window algorithms, **window** (for example 100 per 1 minute) and
  optional **burst** (token bucket, GCRA; queue size for leaky bucket).
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

## Mode 3: Forward auth

The proxy or ingress in front of your service asks RateGuard about every request
before forwarding it. RateGuard never proxies: it answers `200` (let it through) or
`429` / `401` / `404`, and the proxy relays that answer.

```
client -> NGINX / Traefik / Caddy / Envoy -> your service
              |   ^
              v   | 200 + headers, or 429
           RateGuard  /_rlg/v1/auth
```

### Endpoint contract

`/_rlg/v1/auth`, any method, on the data plane (`:8080`). Enabled by default
(turn off with `Settings.ForwardAuthDisabled`).

| Input | Source |
|---|---|
| Original method | `X-Forwarded-Method`, else `X-Original-Method`, else `GET` |
| Original path and query | `X-Forwarded-Uri`, else `X-Original-URI`, else `/`. Normalised exactly like proxy-mode paths, so encoded slashes, backslashes and NUL give `400` and `..` is resolved |
| Host | `X-Forwarded-Host`, else `Host` |
| Client IP | `X-Forwarded-For` / `X-Real-IP` **only if the calling proxy is in Trusted proxies**; otherwise the TCP peer |
| API key | The usual headers (`X-API-Key` or `Authorization: Bearer`) of the forwarded request |
| Route | `?route_id=<id>` on the auth URL if given, else matched from method/host/path as in proxy mode |
| Limited status | `?deny_status=401`, `403` or `429` on the auth URL (default 429) |
| Envoy form | `/_rlg/v1/auth/<original path>?<query>` with the original method; used when no forwarded-URI header is present. `route_id` is ignored in this form |

| Result | Response |
|---|---|
| Allowed | `200`, empty body, `RateLimit-*` headers and `X-RateGuard-Consumer` |
| Limited | `429`, the standard JSON body, `Retry-After` and `RateLimit-*` |
| Missing or invalid API key | `401` |
| No route | `404` |
| Invalid path | `400` |
| Limiter backend down | `503` |

Leaky-bucket policies make the endpoint wait server-side, exactly as the proxy does,
so keep the proxy's auth timeout above your longest shaping delay. Concurrency
policies are skipped. Requests are logged with source `forward_auth`.

### Securing the endpoint

By default the endpoint trusts whoever can reach it, so **expose it only to the
proxy's network** (do not publish port 8080 for it publicly, or firewall it). To
require a credential, turn on `Settings.ForwardAuthRequireToken` and make the proxy
send `X-RateGuard-Auth-Token: <token>` with an API token of scope `check`; anything
else gets `401`. Not every proxy can add a static header to its auth request
(Traefik cannot), so choose network isolation there.

### NGINX `auth_request`

[`examples/nginx/auth_request.conf`](../examples/nginx/auth_request.conf). Copy the
`location = /_rateguard_auth` block and add `auth_request /_rateguard_auth;` to the
protected location. Stock NGINX passes only `401` and `403` from the auth
subrequest to the client, so the example calls
`/_rlg/v1/auth?deny_status=403` and maps it with `error_page 403 = @ratelimited;`
to a real `429` (the named location returns 429 and copies `Retry-After`).

`deny_status` (`401`, `403` or `429`; default `429`) sets the status of limited
responses only; the headers and body are unchanged. Like `route_id`, it is an
operator setting on the auth URL and is ignored in the Envoy appended-path form.

### Traefik `ForwardAuth`

[`examples/traefik/docker-compose.yml`](../examples/traefik/docker-compose.yml):

```yaml
- traefik.http.middlewares.rateguard.forwardauth.address=http://rateguard:8080/_rlg/v1/auth
- traefik.http.middlewares.rateguard.forwardauth.authResponseHeaders=X-RateGuard-Consumer,RateLimit-Limit,RateLimit-Remaining,RateLimit-Reset
```

### Caddy `forward_auth`

[`examples/caddy/Caddyfile`](../examples/caddy/Caddyfile):

```
forward_auth rateguard:8080 {
	uri /_rlg/v1/auth
	copy_headers X-RateGuard-Consumer RateLimit-Limit RateLimit-Remaining RateLimit-Reset
}
```

### Envoy `ext_authz` (HTTP)

[`examples/envoy/ext_authz.yaml`](../examples/envoy/ext_authz.yaml). Set
`http_service.path_prefix: /_rlg/v1/auth` and forward `x-api-key` and
`x-forwarded-for` in `allowed_headers`.

### Kubernetes ingress-nginx

[`examples/k8s/ingress-nginx-auth.yaml`](../examples/k8s/ingress-nginx-auth.yaml):

```yaml
nginx.ingress.kubernetes.io/auth-url: "http://rateguard.default.svc.cluster.local:8080/_rlg/v1/auth"
nginx.ingress.kubernetes.io/auth-response-headers: "X-RateGuard-Consumer, RateLimit-Limit, RateLimit-Remaining, RateLimit-Reset"
```

Same mechanism as NGINX (`?deny_status=403` plus snippets mapping 403 to 429).

### Language SDK examples (check API)

Fail-open, 50 ms timeout, `Authorization: Bearer <token>`, headers copied from the
response. Each is one file with a usage comment at the top:

- Java / Spring: [`examples/java/RateGuardFilter.java`](../examples/java/RateGuardFilter.java)
- C# / ASP.NET Core: [`examples/dotnet/RateGuardMiddleware.cs`](../examples/dotnet/RateGuardMiddleware.cs)
- Ruby / Rack: [`examples/ruby/rate_guard.rb`](../examples/ruby/rate_guard.rb)
- PHP / PSR-15: [`examples/php/RateGuardMiddleware.php`](../examples/php/RateGuardMiddleware.php)

---

## Mode 4: Both

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

[`examples/nginx/reverse_proxy.conf`](../examples/nginx/reverse_proxy.conf) shows
NGINX proxying to two RateGuard instances. Use this pattern when NGINX already
terminates TLS. To keep traffic off RateGuard, use forward auth instead
([`auth_request.conf`](../examples/nginx/auth_request.conf), Mode 3).

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
