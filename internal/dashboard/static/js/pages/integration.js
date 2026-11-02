// Integration: copy-paste snippets pre-filled with this instance's addresses and the selected route/consumer.
import { h, mount } from '../dom.js';
import { icon } from '../icons.js';
import * as api from '../api.js';
import { entities, system } from '../state.js';
import { pageHead, card, codeBlock, tabs, errorState } from '../ui.js';
import { select } from '../forms.js';
import { replaceQuery } from '../router.js';
import { addrToURL } from './consumer.js';
import { keyState } from './consumers.js';

const LANGS = [
  { id: 'curl', label: 'curl', icon: 'terminal' },
  { id: 'node', label: 'Node / Express', icon: 'code' },
  { id: 'python', label: 'Python / FastAPI', icon: 'code' },
  { id: 'go', label: 'Go', icon: 'code' },
  { id: 'java', label: 'Java / Spring', icon: 'code' },
  { id: 'dotnet', label: '.NET', icon: 'code' },
  { id: 'ruby', label: 'Ruby / Rack', icon: 'code' },
  { id: 'php', label: 'PHP / PSR-15', icon: 'code' },
  { id: 'forwardauth', label: 'Forward auth', icon: 'shield' },
  { id: 'nginx', label: 'NGINX proxy', icon: 'server' },
  { id: 'k8s', label: 'Kubernetes', icon: 'layers' },
];

function snippets(ctx) {
  const { gw, admin, route, header, keyNote, path, method, host, checkEnabled } = ctx;
  const rid = route ? route.id : '';
  const hostHdr = host ? ` -H "Host: ${host}"` : '';
  const checkBody = JSON.stringify({ route_id: rid || undefined, method, path, api_key: '$RATEGUARD_API_KEY', ip: '203.0.113.10' });
  const out = {};
  out.curl = [
    { title: 'Call your API through the gateway (proxy mode)', lang: 'bash', code:
`${keyNote}export RATEGUARD_API_KEY="rlg_live_..."

curl -i ${method !== 'GET' ? `-X ${method} ` : ''}${gw}${path}${hostHdr} \\
  -H "${header}: $RATEGUARD_API_KEY"

# Every limited route answers with IETF RateLimit headers:
#   RateLimit-Limit, RateLimit-Remaining, RateLimit-Reset, RateLimit-Policy
# and 429 + Retry-After when the limit is exceeded.` },
    { title: 'Ask for a decision without proxying (check API)', lang: 'bash', code:
`# Requires an API token with the "check" scope (Settings → API tokens).
curl -s -X POST ${gw}/_rlg/v1/check \\
  -H "Authorization: Bearer $RATEGUARD_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '${checkBody.replace('"$RATEGUARD_API_KEY"', `"'"$RATEGUARD_API_KEY"'"`)}'

# → {"allowed":true,"decision":"allowed","limit":600,"remaining":599,"reset_s":1,...}` },
  ];
  out.node = [{ title: 'middleware/rateguard.js — Express middleware using the check API', lang: 'js', code:
`// Node 18+ (global fetch). npm i express
const RATEGUARD_URL = process.env.RATEGUARD_URL || "${gw}";
const RATEGUARD_TOKEN = process.env.RATEGUARD_TOKEN; // API token with the "check" scope

export function rateguard({ routeId = ${rid ? `"${rid}"` : 'undefined'}, failOpen = true } = {}) {
  return async (req, res, next) => {
    try {
      const r = await fetch(\`\${RATEGUARD_URL}/_rlg/v1/check\`, {
        method: "POST",
        headers: { "Authorization": \`Bearer \${RATEGUARD_TOKEN}\`, "Content-Type": "application/json" },
        body: JSON.stringify({
          route_id: routeId,
          method: req.method,
          path: req.originalUrl,
          host: req.hostname,
          ip: req.ip,
          api_key: req.get("${header}") || undefined,
        }),
        signal: AbortSignal.timeout(250),
      });
      const d = await r.json();
      for (const [k, v] of Object.entries(d.headers || {})) res.set(k, v);
      if (d.allowed) return next();
      if (d.decision === "unauthorized") return res.status(401).json({ error: "unauthorized" });
      return res.status(429).json({ error: "rate_limited", retry_after_s: d.retry_after_s });
    } catch (err) {
      return failOpen ? next() : res.status(503).json({ error: "limiter_unavailable" });
    }
  };
}

// app.use("${path}", rateguard());` }];
  out.python = [{ title: 'rateguard.py — FastAPI dependency using the check API', lang: 'python', code:
`# pip install fastapi httpx
import os
import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, Response

RATEGUARD_URL = os.getenv("RATEGUARD_URL", "${gw}")
RATEGUARD_TOKEN = os.environ["RATEGUARD_TOKEN"]  # API token with the "check" scope
client = httpx.AsyncClient(timeout=0.25)


async def rate_limit(request: Request, response: Response):
    try:
        r = await client.post(
            f"{RATEGUARD_URL}/_rlg/v1/check",
            headers={"Authorization": f"Bearer {RATEGUARD_TOKEN}"},
            json={
                "route_id": ${rid ? `"${rid}"` : 'None'},
                "method": request.method,
                "path": request.url.path,
                "host": request.url.hostname,
                "ip": request.client.host if request.client else None,
                "api_key": request.headers.get("${header}"),
            },
        )
        d = r.json()
    except httpx.HTTPError:
        return  # fail open
    for k, v in (d.get("headers") or {}).items():
        response.headers[k] = v
    if not d["allowed"]:
        status = 401 if d["decision"] == "unauthorized" else 429
        raise HTTPException(status, detail=d["decision"], headers=d.get("headers"))


app = FastAPI()


@app.get("${path}", dependencies=[Depends(rate_limit)])
async def handler():
    return {"ok": True}` }];
  out.go = [{ title: 'rateguard.go — net/http middleware using the check API', lang: 'go', code:
`package rateguard

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"time"
)

var (
	baseURL = envOr("RATEGUARD_URL", "${gw}")
	token   = os.Getenv("RATEGUARD_TOKEN") // API token with the "check" scope
	client  = &http.Client{Timeout: 250 * time.Millisecond}
)

type decision struct {
	Allowed  bool              \`json:"allowed"\`
	Decision string            \`json:"decision"\`
	Headers  map[string]string \`json:"headers"\`
}

// Middleware asks RateGuard before calling next. It fails open on errors.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		body, _ := json.Marshal(map[string]any{
			"route_id": "${rid}", "method": r.Method, "path": r.URL.Path,
			"host": r.Host, "ip": ip, "api_key": r.Header.Get("${header}"),
		})
		req, _ := http.NewRequestWithContext(r.Context(), http.MethodPost, baseURL+"/_rlg/v1/check", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			next.ServeHTTP(w, r) // fail open
			return
		}
		defer resp.Body.Close()
		var d decision
		if json.NewDecoder(resp.Body).Decode(&d) != nil {
			next.ServeHTTP(w, r)
			return
		}
		for k, v := range d.Headers {
			w.Header().Set(k, v)
		}
		switch {
		case d.Allowed:
			next.ServeHTTP(w, r)
		case d.Decision == "unauthorized":
			http.Error(w, \`{"error":"unauthorized"}\`, http.StatusUnauthorized)
		default:
			http.Error(w, \`{"error":"rate_limited"}\`, http.StatusTooManyRequests)
		}
	})
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}` }];
  const gwHostPort = gw.replace(/^https?:\/\//, '');
  out.nginx = [
    { title: 'Put RateGuard in the request path (recommended)', lang: 'nginx', code:
`upstream rateguard {
    server ${gwHostPort};
    keepalive 64;
}

server {
    listen 443 ssl;
    server_name ${host || 'api.example.com'};

    location ${path === '/' ? '/' : path} {
        proxy_pass http://rateguard;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
# Add NGINX's address to Settings → Trusted proxies so RateGuard
# keys by the real client IP from X-Forwarded-For.
# Want to keep your own upstream and only ask RateGuard for a verdict?
# See the Forward auth tab (auth_request).` },
  ];
  out.k8s = [{ title: 'rateguard.yaml — Deployment, Service and Ingress', lang: 'yaml', code:
`apiVersion: v1
kind: Secret
metadata:
  name: rateguard
stringData:
  admin-password: "change-me-to-a-long-random-value"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rateguard
spec:
  replicas: 2   # use the Redis engine + store so replicas share limits & config
  selector:
    matchLabels: { app: rateguard }
  template:
    metadata:
      labels: { app: rateguard }
    spec:
      containers:
        - name: rateguard
          image: rateguard:latest   # build from the repo Dockerfile
          ports:
            - { name: gateway, containerPort: ${portOf(gw, 8080)} }
            - { name: admin, containerPort: ${portOf(admin, 9000)} }
          env:
            - name: RLG_ADMIN_PASSWORD
              valueFrom: { secretKeyRef: { name: rateguard, key: admin-password } }
            - { name: RLG_COOKIE_SECURE, value: "true" }
          readinessProbe:
            httpGet: { path: /_rlg/readyz, port: gateway }
          livenessProbe:
            httpGet: { path: /_rlg/healthz, port: gateway }
          resources:
            requests: { cpu: 100m, memory: 64Mi }
---
apiVersion: v1
kind: Service
metadata:
  name: rateguard
spec:
  selector: { app: rateguard }
  ports:
    - { name: gateway, port: 80, targetPort: gateway }
    - { name: admin, port: 9000, targetPort: admin }
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: api
spec:
  rules:
    - host: ${host || 'api.example.com'}
      http:
        paths:
          - path: ${path}
            pathType: Prefix
            backend:
              service: { name: rateguard, port: { name: gateway } }
# Keep the admin port (9000) private: expose it via kubectl port-forward or an internal ingress.` }];
  const hk = header.toLowerCase();
  const tokNote = ctx.requireToken ? 'Settings requires a token for forward-auth: keep the X-RateGuard-Auth-Token line (a "check"-scoped API token).' : 'Optional: enable Settings → Require token for forward-auth and send X-RateGuard-Auth-Token.';
  const common = 'Check API: POST /_rlg/v1/check with a "check"-scoped token. Fails open on errors and on answers slower than 50 ms.';
  const rq = ctx.requireToken ? '' : '# ';
  out.java = [{ title: 'RateGuardFilter.java — Spring Boot 3 filter using the check API', lang: 'java', code:
`// ${common}
// Env: RATEGUARD_URL (default ${gw}), RATEGUARD_TOKEN. Needs Jackson only.
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class RateGuardFilter extends OncePerRequestFilter {
    private static final Duration TIMEOUT = Duration.ofMillis(50);
    private static final ObjectMapper JSON = new ObjectMapper();
    private final HttpClient client = HttpClient.newBuilder().connectTimeout(TIMEOUT).build();
    private final String checkUrl =
            System.getenv().getOrDefault("RATEGUARD_URL", "${gw}") + "/_rlg/v1/check";
    private final String token = System.getenv("RATEGUARD_TOKEN");

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        JsonNode decision = null;
        try {
            Map<String, Object> body = new LinkedHashMap<>();
${rid ? `            body.put("route_id", "${rid}");\n` : ''}            body.put("method", req.getMethod());
            body.put("path", req.getRequestURI());
            body.put("host", req.getServerName());
            body.put("api_key", req.getHeader("${header}"));
            body.put("ip", req.getRemoteAddr());
            HttpRequest r = HttpRequest.newBuilder(URI.create(checkUrl)).timeout(TIMEOUT)
                    .header("Content-Type", "application/json")
                    .header("Authorization", "Bearer " + token)
                    .POST(HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(body))).build();
            HttpResponse<String> resp = client.send(r, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() == 200) decision = JSON.readTree(resp.body());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            // fail open
        }
        if (decision == null || "error".equals(decision.path("decision").asText())) {
            chain.doFilter(req, res);
            return;
        }
        decision.path("headers").fields().forEachRemaining(h -> res.setHeader(h.getKey(), h.getValue().asText()));
        if (!decision.path("allowed").asBoolean(true)) {
            String d = decision.path("decision").asText("");
            int status = d.equals("unauthorized") ? 401 : d.equals("no_route") ? 404 : 429;
            res.setStatus(status);
            res.setContentType("application/json");
            res.getWriter().write("{\\"error\\":\\"" + (status == 429 ? "rate_limited" : d) + "\\"}");
            return;
        }
        chain.doFilter(req, res);
    }
}` }];
  out.dotnet = [{ title: 'RateGuardMiddleware.cs — ASP.NET Core middleware using the check API', lang: 'csharp', code:
`// ${common}
// Program.cs:
//   builder.Services.AddHttpClient("rateguard", c => {
//       c.BaseAddress = new Uri(Environment.GetEnvironmentVariable("RATEGUARD_URL") ?? "${gw}");
//       c.Timeout = TimeSpan.FromMilliseconds(50);
//   });
//   app.UseMiddleware<RateGuardMiddleware>();
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

public class RateGuardMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IHttpClientFactory _factory;
    private readonly string? _token = Environment.GetEnvironmentVariable("RATEGUARD_TOKEN");

    public RateGuardMiddleware(RequestDelegate next, IHttpClientFactory factory)
    {
        _next = next;
        _factory = factory;
    }

    public async Task InvokeAsync(HttpContext ctx)
    {
        JsonElement? decision = null;
        try
        {
            var body = new
            {
${rid ? `                route_id = "${rid}",\n` : ''}                method = ctx.Request.Method,
                path = ctx.Request.Path.Value,
                host = ctx.Request.Host.Host,
                api_key = ctx.Request.Headers["${header}"].FirstOrDefault(),
                ip = ctx.Connection.RemoteIpAddress?.ToString(),
            };
            using var req = new HttpRequestMessage(HttpMethod.Post, "/_rlg/v1/check") { Content = JsonContent.Create(body) };
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _token);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ctx.RequestAborted);
            cts.CancelAfter(TimeSpan.FromMilliseconds(50));
            using var resp = await _factory.CreateClient("rateguard").SendAsync(req, cts.Token);
            resp.EnsureSuccessStatusCode();
            decision = await resp.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: cts.Token);
        }
        catch (Exception) { /* fail open */ }

        if (decision is JsonElement e0 && e0.TryGetProperty("decision", out var dk) && dk.GetString() == "error")
            decision = null;

        if (decision is JsonElement d)
        {
            if (d.TryGetProperty("headers", out var headers))
                foreach (var h in headers.EnumerateObject())
                    ctx.Response.Headers[h.Name] = h.Value.GetString();
            if (d.TryGetProperty("allowed", out var a) && !a.GetBoolean())
            {
                var kind = d.TryGetProperty("decision", out var k) ? k.GetString() : "limited";
                ctx.Response.StatusCode = kind == "unauthorized" ? 401 : kind == "no_route" ? 404 : 429;
                await ctx.Response.WriteAsJsonAsync(new { error = kind == "limited" ? "rate_limited" : kind });
                return;
            }
        }
        await _next(ctx);
    }
}` }];
  out.ruby = [{ title: 'rate_guard.rb — Rack middleware using the check API (Rails, Sinatra, Hanami)', lang: 'ruby', code:
`# ${common}
# config.ru:  use RateGuard, url: ENV.fetch("RATEGUARD_URL", "${gw}"), token: ENV.fetch("RATEGUARD_TOKEN")
require "json"
require "net/http"
require "rack"
require "uri"

class RateGuard
  TIMEOUT = 0.05 # seconds

  def initialize(app, url: "${gw}", token: nil, timeout: TIMEOUT)
    @app = app
    @uri = URI.join(url.end_with?("/") ? url : "#{url}/", "_rlg/v1/check")
    @token = token
    @timeout = timeout
  end

  def call(env)
    decision = check(Rack::Request.new(env))
    return @app.call(env) if decision.nil? || decision["decision"] == "error"

    headers = decision["headers"] || {}
    unless decision["allowed"] == false
      status, resp_headers, body = @app.call(env)
      return [status, resp_headers.merge(headers), body]
    end
    code = { "unauthorized" => 401, "no_route" => 404 }.fetch(decision["decision"], 429)
    error = code == 429 ? "rate_limited" : decision["decision"]
    [code, headers.merge("Content-Type" => "application/json"), [JSON.generate(error: error)]]
  end

  private

  def check(req)
    http = Net::HTTP.new(@uri.host, @uri.port)
    http.use_ssl = @uri.scheme == "https"
    http.open_timeout = http.read_timeout = http.write_timeout = @timeout
    post = Net::HTTP::Post.new(@uri.request_uri, "Content-Type" => "application/json", "Authorization" => "Bearer #{@token}")
    post.body = JSON.generate(
${rid ? `      route_id: "${rid}",\n` : ''}      method: req.request_method, path: req.path, host: req.host,
      api_key: req.get_header("HTTP_${header.toUpperCase().replace(/-/g, '_')}"), ip: req.ip
    )
    resp = http.request(post)
    resp.code == "200" ? JSON.parse(resp.body) : nil
  rescue StandardError
    nil # fail open
  end
end` }];
  out.php = [{ title: 'RateGuardMiddleware.php — PSR-15 middleware using the check API (Slim, Mezzio)', lang: 'php', code:
`<?php
// ${common}
// Needs psr/http-server-middleware and ext-curl.
// $app->add(new RateGuardMiddleware(getenv('RATEGUARD_URL') ?: '${gw}', getenv('RATEGUARD_TOKEN'), $app->getResponseFactory()));
declare(strict_types=1);

use Psr\\Http\\Message\\ResponseFactoryInterface;
use Psr\\Http\\Message\\ResponseInterface;
use Psr\\Http\\Message\\ServerRequestInterface;
use Psr\\Http\\Server\\MiddlewareInterface;
use Psr\\Http\\Server\\RequestHandlerInterface;

final class RateGuardMiddleware implements MiddlewareInterface
{
    private const TIMEOUT_MS = 50;

    public function __construct(private string $baseUrl, private ?string $token, private ResponseFactoryInterface $responses)
    {
        $this->baseUrl = rtrim($baseUrl, '/');
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $d = $this->check($request);
        if ($d === null || ($d['decision'] ?? '') === 'error') {
            return $handler->handle($request); // fail open
        }
        if (($d['allowed'] ?? true) === false) {
            $kind = $d['decision'] ?? 'limited';
            $status = match ($kind) { 'unauthorized' => 401, 'no_route' => 404, default => 429 };
            $response = $this->responses->createResponse($status)->withHeader('Content-Type', 'application/json');
            $response->getBody()->write(json_encode(['error' => $kind === 'limited' ? 'rate_limited' : $kind]));
        } else {
            $response = $handler->handle($request);
        }
        foreach (($d['headers'] ?? []) as $name => $value) {
            $response = $response->withHeader((string) $name, (string) $value);
        }
        return $response;
    }

    private function check(ServerRequestInterface $request): ?array
    {
        try {
            $uri = $request->getUri();
            $ch = curl_init($this->baseUrl . '/_rlg/v1/check');
            curl_setopt_array($ch, [
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => json_encode([
${rid ? `                    'route_id' => '${rid}',\n` : ''}                    'method' => $request->getMethod(),
                    'path' => $uri->getPath() ?: '/',
                    'host' => $uri->getHost(),
                    'api_key' => $request->getHeaderLine('${header}') ?: null,
                    'ip' => $request->getServerParams()['REMOTE_ADDR'] ?? null,
                ]),
                CURLOPT_HTTPHEADER => ['Content-Type: application/json', 'Authorization: Bearer ' . $this->token],
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT_MS => self::TIMEOUT_MS,
                CURLOPT_CONNECTTIMEOUT_MS => self::TIMEOUT_MS,
                CURLOPT_NOSIGNAL => 1,
            ]);
            $out = curl_exec($ch);
            if ($out === false || curl_getinfo($ch, CURLINFO_RESPONSE_CODE) !== 200) {
                return null;
            }
            $d = json_decode($out, true, 16, JSON_THROW_ON_ERROR);
            return is_array($d) ? $d : null;
        } catch (Throwable $e) {
            return null; // fail open
        }
    }
}` }];

  out.forwardauth = [
    { title: 'NGINX — auth_request', lang: 'nginx', code:
`# RateGuard only answers allow/deny; NGINX keeps proxying to your upstream.
# ${tokNote}
# Add NGINX's address to Settings → Trusted proxies.
# Stock auth_request only passes 401/403 from the subrequest, so ask RateGuard
# for 403 on limited requests (?deny_status=403) and map it to 429 below.
location = /_rateguard_auth {
    internal;
    proxy_pass ${gw}/_rlg/v1/auth?deny_status=403${rid ? `&route_id=${rid}` : ''};
    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_connect_timeout 1s;
    proxy_read_timeout 5s;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Forwarded-Method $request_method;
    proxy_set_header X-Forwarded-Uri    $request_uri;
    proxy_set_header X-Forwarded-Host   $host;
    proxy_set_header X-Forwarded-For    $remote_addr;
    ${rq}proxy_set_header X-RateGuard-Auth-Token "rgt_...";
    # The ${header} header is passed through from the original request.
}

location ${path} {
    auth_request /_rateguard_auth;
    error_page 403 = @ratelimited;
    auth_request_set $rg_limit     $upstream_http_ratelimit_limit;
    auth_request_set $rg_remaining $upstream_http_ratelimit_remaining;
    auth_request_set $rg_reset     $upstream_http_ratelimit_reset;
    auth_request_set $rg_retry     $upstream_http_retry_after;
    auth_request_set $rg_consumer  $upstream_http_x_rateguard_consumer;
    add_header RateLimit-Limit     $rg_limit     always;
    add_header RateLimit-Remaining $rg_remaining always;
    add_header RateLimit-Reset     $rg_reset     always;
    proxy_set_header X-RateGuard-Consumer $rg_consumer;
    proxy_pass http://your-upstream:3000;
    proxy_set_header Host $host;
}

location @ratelimited {
    add_header Retry-After $rg_retry always;
    add_header RateLimit-Limit     $rg_limit     always;
    add_header RateLimit-Remaining $rg_remaining always;
    add_header RateLimit-Reset     $rg_reset     always;
    default_type application/json;
    return 429 '{"error":"rate_limited","message":"Rate limit exceeded"}';
}` },
    { title: 'Traefik — ForwardAuth middleware (docker labels)', lang: 'yaml', code:
`# Traefik relays RateGuard's 429 (with Retry-After and RateLimit-*) to the client.
# Add Traefik's network to Settings → Trusted proxies. Do not publish RateGuard's port.
# Traefik cannot add a static header to the auth call, so leave
# "Require token for forward-auth" off and rely on the private network.
labels:
  - traefik.enable=true
  - traefik.http.routers.api.rule=Host(\`${host || 'api.example.com'}\`)
  - traefik.http.routers.api.middlewares=rateguard
  - traefik.http.middlewares.rateguard.forwardauth.address=${gw}/_rlg/v1/auth${rid ? `?route_id=${rid}` : ''}
  - traefik.http.middlewares.rateguard.forwardauth.authResponseHeaders=X-RateGuard-Consumer,RateLimit-Limit,RateLimit-Remaining,RateLimit-Reset,RateLimit-Policy` },
    { title: 'Caddy — forward_auth', lang: 'caddy', code:
`# Caddy relays RateGuard's 429 to the client. Add Caddy's address to Settings → Trusted proxies.
${host || 'api.example.com'} {
	forward_auth ${gwHostPort} {
		uri /_rlg/v1/auth${rid ? `?route_id=${rid}` : ''}
		copy_headers X-RateGuard-Consumer RateLimit-Limit RateLimit-Remaining RateLimit-Reset RateLimit-Policy
	}
	reverse_proxy your-upstream:3000
}` },
    { title: 'Envoy — HTTP ext_authz filter', lang: 'yaml', code:
`# Envoy sends the original method and path after path_prefix, so no X-Forwarded-Uri is needed.
# Routes are matched by host/path/method here (?route_id= is ignored).
# Set use_remote_address: true on the HttpConnectionManager and add Envoy to Trusted proxies.
http_filters:
  - name: envoy.filters.http.ext_authz
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
      transport_api_version: V3
      failure_mode_allow: true       # fail open if RateGuard is unreachable
      http_service:
        server_uri:
          uri: ${gw}
          cluster: rateguard
          timeout: 0.25s
        path_prefix: /_rlg/v1/auth
        authorization_request:
          allowed_headers:
            patterns:
              - exact: ${hk}
              - exact: authorization
              - exact: x-forwarded-for
        authorization_response:
          allowed_upstream_headers:
            patterns:
              - exact: x-rateguard-consumer
          allowed_client_headers:
            patterns:
              - exact: retry-after
              - exact: ratelimit-limit
              - exact: ratelimit-remaining
              - exact: ratelimit-reset
              - exact: ratelimit-policy
  - name: envoy.filters.http.router
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
# cluster "rateguard": type STRICT_DNS, endpoint ${gwHostPort}` },
    { title: 'ingress-nginx — auth-url annotations', lang: 'yaml', code:
`# Needs allow-snippet-annotations on the controller. Without snippets, limited clients see 403 instead of 429.
# Add the ingress controller's pod/node CIDR to Settings → Trusted proxies.
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: api
  annotations:
    nginx.ingress.kubernetes.io/auth-url: "http://rateguard.default.svc.cluster.local:${portOf(gw, 8080)}/_rlg/v1/auth?deny_status=403${rid ? `&route_id=${rid}` : ''}"
    nginx.ingress.kubernetes.io/auth-snippet: |
      proxy_set_header X-Forwarded-Method $request_method;
      proxy_set_header X-Forwarded-Uri $request_uri;
      proxy_set_header X-Forwarded-Host $host;
    nginx.ingress.kubernetes.io/configuration-snippet: |
      error_page 403 = @ratelimited;
    nginx.ingress.kubernetes.io/server-snippet: |
      location @ratelimited {
        default_type application/json;
        return 429 '{"error":"rate_limited","message":"Rate limit exceeded"}';
      }
    nginx.ingress.kubernetes.io/auth-response-headers: "X-RateGuard-Consumer, RateLimit-Limit, RateLimit-Remaining, RateLimit-Reset"
spec:
  ingressClassName: nginx
  rules:
    - host: ${host || 'api.example.com'}
      http:
        paths:
          - path: ${path}
            pathType: Prefix
            backend:
              service: { name: your-service, port: { number: 80 } }` },
  ];
  if (ctx.forwardDisabled) out.forwardauth.unshift({ warnFwd: true });
  if (!checkEnabled) ['node', 'python', 'go', 'java', 'dotnet', 'ruby', 'php'].forEach(k => out[k].unshift({ warn: true }));
  return out;
}

const MODES = [
  { id: 'nginx', title: 'Reverse proxy', pick: 'You want the fewest moving parts.',
    body: 'Point traffic at RateGuard and it forwards allowed requests to your upstream. Nothing to install in your app.', cta: 'Proxy config' },
  { id: 'forwardauth', title: 'Forward auth', pick: 'You already run NGINX, Traefik, Caddy, Envoy or ingress-nginx.',
    body: 'Your proxy keeps routing and asks RateGuard “allow or deny?” for each request. Adds one fast subrequest, no extra hop for the body.', cta: 'Proxy snippets' },
  { id: 'node', title: 'Check API', pick: 'You want the limit decided inside your application code.',
    body: 'Call POST /_rlg/v1/check from middleware, per user or per action. Fail open with a 50 ms timeout.', cta: 'Language snippets' },
];

function decisionCard(pickMode) {
  return h('section', { class: 'card', style: { marginBottom: '16px' }, 'aria-label': 'Which mode should I use' },
    h('div', { class: 'card-head' }, h('div', {}, h('h2', {}, 'Which mode should I use?'), h('div', { class: 'desc' }, 'All three enforce the same policies. They differ in where the request goes.'))),
    h('div', { class: 'card-body' }, h('div', { class: 'grid three' }, MODES.map(m =>
      h('div', { class: 'stack tight' },
        h('strong', {}, m.title),
        h('div', {}, m.pick),
        h('div', { class: 'small muted' }, m.body),
        h('button', { class: 'btn sm', type: 'button', onClick: () => pickMode(m.id) }, m.cta))))));
}

function portOf(url, def) {
  const m = String(url).match(/:(\d+)(?:\/|$)/);
  return m ? m[1] : def;
}

export default {
  async render({ root, query }) {
    let lang = LANGS.some(l => l.id === query.lang) ? query.lang : 'curl';
    const body = h('div', {}, h('div', { class: 'skel block', style: { height: '300px' } }));
    const routeSel = select({ cls: 'sm', 'aria-label': 'Route', options: [{ value: '', label: 'Any route' }] });
    const consSel = select({ cls: 'sm', 'aria-label': 'Consumer', options: [{ value: '', label: 'Any consumer' }] });
    const tabHost = h('div');
    mount(root,
      pageHead({ title: 'Integration', lede: 'Copy-paste snippets for the three ways to enforce limits: as a reverse proxy, as forward auth behind your own proxy, or via the check API. Pre-filled with this instance’s addresses.' }),
      decisionCard(id => { lang = id; replaceQuery({ lang }); mount(tabHost, tabs(LANGS, lang, t => { lang = t; draw(); })); draw(); }),
      h('section', { class: 'card' },
        h('div', { class: 'toolbar' }, h('span', { class: 'small muted' }, 'Pre-fill for'), routeSel, consSel, h('span', { class: 'grow' }), h('span', { class: 'xs muted', id: 'int-addr' })),
        h('div', { class: 'card-body' }, tabHost, body)));

    let sys, routes = [], consumers = [], settings = {};
    try {
      [sys, routes, consumers, settings] = await Promise.all([
        system(), entities('routes').catch(() => []), entities('consumers').catch(() => []), api.get('/settings').catch(() => ({})),
      ]);
    } catch (e) { mount(body, errorState(e)); return; }
    mount(routeSel, h('option', { value: '' }, 'Any route'), routes.map(r => h('option', { value: r.id }, r.name)));
    mount(consSel, h('option', { value: '' }, 'Any consumer'), consumers.map(c => h('option', { value: c.id }, c.name)));
    routeSel.value = query.route || (routes[0] ? routes[0].id : '');
    consSel.value = query.consumer || '';
    const gw = addrToURL(sys.data_plane_addr) || location.origin;
    const admin = addrToURL(sys.admin_addr) || location.origin;
    root.querySelector('#int-addr').textContent = `Gateway ${gw} · Admin ${admin}`;

    function draw() {
      replaceQuery({ route: routeSel.value, consumer: consSel.value, lang });
      const route = routes.find(r => r.id === routeSel.value);
      const cons = consumers.find(c => c.id === consSel.value);
      const key = cons && (cons.keys || []).find(k => keyState(k) === 'active');
      const ctx = {
        gw, admin, route, header: settings.api_key_header || 'X-API-Key',
        path: route && route.match.path_prefix ? route.match.path_prefix : '/',
        method: route && route.match.methods && route.match.methods.length ? route.match.methods[0] : 'GET',
        host: route && route.match.host && !route.match.host.startsWith('*') ? route.match.host : '',
        keyNote: cons ? `# ${cons.name}${key ? `: use the key starting ${key.prefix}… (shown once when issued)` : ' has no active key — issue one on the consumer page'}\n` : '',
        checkEnabled: settings.check_api_enabled !== false,
        forwardDisabled: !!settings.forward_auth_disabled,
        requireToken: !!settings.forward_auth_require_token,
      };
      const sn = snippets(ctx)[lang];
      mount(body, h('div', { class: 'stack' },
        route && route.require_api_key && !cons ? h('div', { class: 'callout info' }, icon('key'), h('div', {}, h('strong', {}, route.name), ' requires an API key. Pick a consumer above to see which key to use.')) : null,
        sn.map(s => s.warnFwd
          ? h('div', { class: 'callout warn' }, icon('alert'), h('div', {}, 'The forward-auth endpoint is disabled in ', h('a', { href: '#/settings' }, 'Settings'), '. Enable it before using these snippets.'))
          : s.warn
          ? h('div', { class: 'callout warn' }, icon('alert'), h('div', {}, 'The check API is disabled in ', h('a', { href: '#/settings' }, 'Settings'), '. Enable it before using these snippets.'))
          : h('div', { class: 'stack tight' }, null,
            codeBlock(s.code, { title: s.title, lang: s.lang })))));
    }
    mount(tabHost, tabs(LANGS, lang, id => { lang = id; draw(); }));
    routeSel.addEventListener('change', draw);
    consSel.addEventListener('change', draw);
    draw();
  },
};
