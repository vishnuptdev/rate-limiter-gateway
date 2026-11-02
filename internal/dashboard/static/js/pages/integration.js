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
  { id: 'nginx', label: 'NGINX', icon: 'server' },
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
# keys by the real client IP from X-Forwarded-For.` },
    { title: 'auth_request (decision only)', lang: 'nginx', note: true, code:
`# auth_request only understands the subrequest's status code (2xx = allow).
# RateGuard's check API always answers 200 with a JSON verdict, so it can't
# drive auth_request directly. Use one of:
#   • the proxy setup above (RateGuard answers 429 itself), or
#   • the check API from your application (see the Node/Python/Go tabs).
location = /_rateguard_check {
    internal;
    proxy_pass ${gw}/_rlg/v1/check;
    proxy_method POST;
    proxy_set_header Authorization "Bearer <check-scope token>";
    proxy_set_header Content-Type "application/json";
    proxy_set_body '{"route_id":"${rid}","method":"$request_method","path":"$request_uri","ip":"$remote_addr","api_key":"$http_${header.toLowerCase().replace(/-/g, '_')}"}';
}` },
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
  if (!checkEnabled) ['node', 'python', 'go'].forEach(k => out[k].unshift({ warn: true }));
  return out;
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
      pageHead({ title: 'Integration', lede: 'Copy-paste snippets to put RateGuard in front of your API or to call its decision API from your code. Pre-filled with this instance’s addresses.' }),
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
      };
      const sn = snippets(ctx)[lang];
      mount(body, h('div', { class: 'stack' },
        route && route.require_api_key && !cons ? h('div', { class: 'callout info' }, icon('key'), h('div', {}, h('strong', {}, route.name), ' requires an API key. Pick a consumer above to see which key to use.')) : null,
        sn.map(s => s.warn
          ? h('div', { class: 'callout warn' }, icon('alert'), h('div', {}, 'The check API is disabled in ', h('a', { href: '#/settings' }, 'Settings'), '. Enable it before using these snippets.'))
          : h('div', { class: 'stack tight' }, s.note ? h('div', { class: 'callout warn' }, icon('alert'), h('div', {}, h('strong', {}, 'Heads up: '), 'NGINX ', h('code', {}, 'auth_request'), ' can’t read a JSON verdict, and the check API always returns 200. Proxy through RateGuard instead, or call the check API from your app.')) : null,
            codeBlock(s.code, { title: s.title, lang: s.lang })))));
    }
    mount(tabHost, tabs(LANGS, lang, id => { lang = id; draw(); }));
    routeSel.addEventListener('change', draw);
    consSel.addEventListener('change', draw);
    draw();
  },
};
