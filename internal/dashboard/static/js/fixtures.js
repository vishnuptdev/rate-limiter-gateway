// Realistic fixture data for mock mode (?mock=1). Deterministic where it
// matters (timeseries are a pure function of time) so screenshots are stable.

export function rng(seed = 42) {
  let a = seed >>> 0;
  return () => {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const hash01 = n => { const r = rng(Math.floor(n) ^ 0x9e3779b9); r(); return r(); };
export const pick = (r, arr) => arr[Math.floor(r() * arr.length)];
function weighted(r, items) {
  const total = items.reduce((a, x) => a + x[1], 0);
  let v = r() * total;
  for (const [it, w] of items) { v -= w; if (v <= 0) return it; }
  return items[items.length - 1][0];
}
export const hex = (r, n) => Array.from({ length: n }, () => Math.floor(r() * 16).toString(16)).join('');
const b62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
export const base62 = (r, n) => Array.from({ length: n }, () => b62[Math.floor(r() * 62)]).join('');

const iso = t => new Date(t).toISOString();
const DAY = 86400000;

export function buildSnapshot(now = Date.now()) {
  const r = rng(7);
  const c = (d) => iso(now - d * DAY);
  const policies = [
    { id: 'api-default', name: 'API default', description: 'Baseline per-consumer limit applied to every public API route.', algorithm: 'gcra', limit: 600, window: '1m0s', burst: 1200, key_by: ['consumer'], mode: 'enforce', fail_mode: 'open', enabled: true, created_at: c(84), updated_at: c(3) },
    { id: 'login-guard', name: 'Login brute-force guard', description: 'Stops credential stuffing on the auth endpoints.', algorithm: 'sliding_window', limit: 10, window: '1m0s', key_by: ['ip', 'path'], mode: 'enforce', fail_mode: 'closed', enabled: true, created_at: c(80), updated_at: c(12) },
    { id: 'search-burst', name: 'Search burst', description: 'Smooths bursty autocomplete traffic.', algorithm: 'sliding_window_counter', limit: 25, window: '1s', key_by: ['api_key'], mode: 'enforce', fail_mode: 'open', enabled: true, created_at: c(61), updated_at: c(9) },
    { id: 'export-daily', name: 'Daily export quota', description: 'Bulk exports are expensive — metered per day.', algorithm: 'fixed_window', limit: 200, window: '24h0m0s', cost: 1, key_by: ['consumer'], mode: 'enforce', fail_mode: 'open', enabled: true, created_at: c(40), updated_at: c(2) },
    { id: 'upload-concurrency', name: 'Upload concurrency', description: 'Caps simultaneous uploads per tenant.', algorithm: 'concurrency', limit: 4, window: '0s', key_by: ['consumer'], mode: 'enforce', fail_mode: 'open', enabled: true, created_at: c(33), updated_at: c(33) },
    { id: 'tenant-header', name: 'Per-tenant fairness', description: 'Dry-running a stricter per-tenant ceiling before enforcing.', algorithm: 'sliding_window_counter', limit: 3000, window: '1m0s', key_by: ['header:X-Tenant-ID', 'route'], mode: 'shadow', fail_mode: 'open', enabled: true, created_at: c(5), updated_at: c(1) },
    { id: 'global-ceiling', name: 'Global ceiling', description: 'Protects upstreams from total overload.', algorithm: 'fixed_window', limit: 60000, window: '1m0s', key_by: ['global'], mode: 'enforce', fail_mode: 'open', enabled: true, created_at: c(90), updated_at: c(30) },
    { id: 'upload-shaper', name: 'Upload shaper', description: 'Smooths upload bursts so the blob store sees a steady rate — excess waits in a queue.', algorithm: 'leaky_bucket', limit: 20, window: '1s', burst: 40, key_by: ['consumer'], mode: 'enforce', fail_mode: 'open', enabled: true, created_at: c(18), updated_at: c(4) },
    { id: 'mobile-bursty', name: 'Mobile app bursts', description: 'App launch fan-out: allow a burst, then a steady refill.', algorithm: 'token_bucket', limit: 120, window: '1m0s', burst: 300, key_by: ['api_key'], mode: 'enforce', fail_mode: 'open', enabled: true, created_at: c(26), updated_at: c(8) },
    { id: 'legacy-v0', name: 'Legacy v0 throttle', algorithm: 'token_bucket', limit: 30, window: '1m0s', key_by: ['ip'], mode: 'enforce', fail_mode: 'open', enabled: false, created_at: c(120), updated_at: c(45) },
  ];
  const routes = [
    { id: 'orders-api', name: 'Orders API', match: { host: 'api.acme.dev', path_prefix: '/v1/orders', methods: [] }, upstream: 'http://orders.internal:8000', strip_prefix: false, policy_ids: ['api-default'], require_api_key: true, timeout: '15s', priority: 10, enabled: true, created_at: c(84), updated_at: c(3) },
    { id: 'search-api', name: 'Search', match: { host: 'api.acme.dev', path_prefix: '/v1/search', methods: ['GET'] }, upstream: 'http://search.internal:9200', policy_ids: ['search-burst', 'api-default'], require_api_key: true, timeout: '5s', priority: 20, enabled: true, created_at: c(61), updated_at: c(9) },
    { id: 'auth-login', name: 'Auth: login', match: { host: '', path_prefix: '/auth/login', methods: ['POST'] }, upstream: 'http://identity.internal:7000', policy_ids: ['login-guard'], require_api_key: false, timeout: '10s', priority: 50, enabled: true, created_at: c(80), updated_at: c(12) },
    { id: 'exports', name: 'Bulk exports', match: { host: 'api.acme.dev', path_prefix: '/v1/exports', methods: ['POST', 'GET'] }, upstream: 'http://exporter.internal:8100', policy_ids: ['export-daily', 'api-default'], require_api_key: true, timeout: '1m0s', priority: 10, enabled: true, created_at: c(40), updated_at: c(2) },
    { id: 'uploads', name: 'Uploads', match: { host: 'upload.acme.dev', path_prefix: '/', methods: ['PUT', 'POST'] }, upstream: 'http://blobs.internal:9000', strip_prefix: false, policy_ids: ['upload-concurrency', 'upload-shaper'], require_api_key: true, timeout: '2m0s', priority: 0, enabled: true, created_at: c(33), updated_at: c(33) },
    { id: 'catalog-public', name: 'Public catalog', match: { host: '*.acme.dev', path_prefix: '/v1/catalog', methods: ['GET'] }, upstream: 'http://catalog.internal:8080', policy_ids: ['api-default'], require_api_key: false, timeout: '10s', priority: 5, enabled: true, created_at: c(70), updated_at: c(20) },
    { id: 'legacy-v0', name: 'Legacy v0', match: { host: 'legacy.acme.dev', path_prefix: '/v0', methods: [] }, upstream: 'http://monolith.internal:3000', strip_prefix: true, policy_ids: ['legacy-v0'], require_api_key: false, timeout: '30s', priority: 0, enabled: false, created_at: c(120), updated_at: c(45) },
  ];
  const plans = [
    { id: 'free', name: 'Free', description: 'Self-serve sign-ups. Tight limits, no bulk exports.', overrides: { 'api-default': { limit: 60, burst: 120 }, 'export-daily': { limit: 5 }, 'search-burst': { limit: 5 } }, created_at: c(90), updated_at: c(14) },
    { id: 'pro', name: 'Pro', description: 'Paid teams.', overrides: { 'api-default': { limit: 1200, burst: 2400 }, 'export-daily': { limit: 500 } }, created_at: c(90), updated_at: c(14) },
    { id: 'enterprise', name: 'Enterprise', description: 'Contracted customers with negotiated limits.', overrides: { 'api-default': { limit: 6000, burst: 12000 }, 'export-daily': { limit: 5000 }, 'upload-concurrency': { limit: 32 }, 'search-burst': { limit: 200 } }, created_at: c(90), updated_at: c(6) },
  ];
  const names = [
    ['northwind', 'Northwind Traders', 'enterprise'], ['globex', 'Globex Corporation', 'enterprise'], ['initech', 'Initech', 'pro'],
    ['umbrella-health', 'Umbrella Health', 'pro'], ['stark-mobile', 'Stark Mobile', 'enterprise'], ['wayne-analytics', 'Wayne Analytics', 'pro'],
    ['acme-ios', 'Acme iOS app', 'pro'], ['hooli', 'Hooli', 'free'], ['pied-piper', 'Pied Piper', 'free'], ['soylent', 'Soylent Labs', 'free'],
    ['vandelay', 'Vandelay Imports', 'pro'], ['tyrell', 'Tyrell Systems', 'enterprise'], ['cyberdyne', 'Cyberdyne', 'free'], ['massive-dynamic', 'Massive Dynamic', 'pro'],
  ];
  const consumers = names.map(([id, name, plan], i) => {
    const created = now - (90 - i * 5) * DAY;
    const nkeys = 1 + (i % 3);
    const keys = Array.from({ length: nkeys }, (_, k) => {
      const pre = 'rlg_live_' + base62(r, 3);
      return {
        id: `key_${base62(r, 8).toLowerCase()}`, prefix: pre,
        name: ['production', 'staging', 'ci'][k], created_at: iso(created + k * 7 * DAY),
        expires_at: k === 2 ? iso(now + 21 * DAY) : undefined, revoked: i % 5 === 1 && k === 1,
      };
    });
    const c2 = { id, name, plan_id: plan, keys, disabled: id === 'cyberdyne', created_at: iso(created), updated_at: iso(created + 3 * DAY),
      metadata: { owner: ['jane@acme.dev', 'sam@acme.dev', 'li@acme.dev'][i % 3], region: ['us-east-1', 'eu-west-1', 'ap-south-1'][i % 3], ...(i % 4 === 0 ? { crm_id: 'CRM-' + (10400 + i) } : {}) } };
    if (id === 'northwind') c2.overrides = { 'api-default': { limit: 10000, burst: 20000 } };
    if (id === 'hooli') c2.overrides = { 'search-burst': { limit: 2, window: '1s' } };
    return c2;
  });
  return {
    version: 148, updated_at: iso(now - 3600e3), policies, routes, plans, consumers,
    settings: { api_key_header: 'X-API-Key', trusted_proxies: ['10.0.0.0/8', '172.16.0.0/12'], global_policy_ids: ['global-ceiling', 'tenant-header'], legacy_headers: true, expose_decision: false, max_body_bytes: 10485760, log_sample_allowed: 1, check_api_enabled: true, cors_allow_origins: [], ipv6_prefix_len: 64 },
  };
}

export function buildUsers(now = Date.now()) {
  return [
    { username: 'admin', role: 'admin', must_change_password: false, created_at: iso(now - 92 * DAY), last_login_at: iso(now - 600e3) },
    { username: 'maria.k', role: 'editor', must_change_password: false, created_at: iso(now - 60 * DAY), last_login_at: iso(now - 2 * DAY) },
    { username: 'devon', role: 'editor', must_change_password: false, created_at: iso(now - 31 * DAY), last_login_at: iso(now - 5 * 3600e3) },
    { username: 'oncall-viewer', role: 'viewer', must_change_password: true, created_at: iso(now - 2 * DAY), last_login_at: null },
  ];
}

export function buildTokens(now = Date.now()) {
  return [
    { id: 'tok_terraform', name: 'terraform-ci', prefix: 'rgt_8fK2', scopes: ['admin'], created_at: iso(now - 50 * DAY), expires_at: iso(now + 130 * DAY), last_used_at: iso(now - 2 * 3600e3) },
    { id: 'tok_grafana', name: 'grafana-scrape', prefix: 'rgt_Qm1x', scopes: ['read'], created_at: iso(now - 44 * DAY), expires_at: null, last_used_at: iso(now - 15e3) },
    { id: 'tok_orders', name: 'orders-service', prefix: 'rgt_Zp93', scopes: ['check'], created_at: iso(now - 12 * DAY), expires_at: null, last_used_at: iso(now - 2e3) },
  ];
}

export function buildAudit(now = Date.now()) {
  const r = rng(99);
  const acts = [
    ['policy.update', 'policy', 'api-default', 'Changed limit 500 → 600 per 1m'],
    ['policy.create', 'policy', 'tenant-header', 'Created shadow policy “Per-tenant fairness”'],
    ['route.update', 'route', 'search-api', 'Added policy search-burst'],
    ['consumer.key.create', 'consumer', 'northwind', 'Issued key rlg_live_8Hd (production)'],
    ['consumer.key.revoke', 'consumer', 'globex', 'Revoked key rlg_live_Wq1'],
    ['plan.update', 'plan', 'enterprise', 'Raised api-default override to 6000'],
    ['limits.reset', 'limit', 'search-burst:hooli', 'Reset bucket'],
    ['settings.update', 'settings', 'settings', 'Enabled legacy headers'],
    ['user.create', 'user', 'oncall-viewer', 'Created viewer'],
    ['token.create', 'token', 'tok_orders', 'Created token orders-service (check)'],
    ['auth.login', 'session', 'admin', 'Signed in'],
    ['consumer.update', 'consumer', 'initech', 'Moved to plan pro'],
    ['route.create', 'route', 'catalog-public', 'Created route Public catalog'],
    ['config.import', 'config', 'snapshot', 'Imported 3 policies, 1 route'],
  ];
  const actors = [['admin', 'user'], ['maria.k', 'user'], ['devon', 'user'], ['terraform-ci', 'token']];
  let t = now - 4 * 60e3;
  return Array.from({ length: 140 }, (_, i) => {
    const [action, tt, tid, summary] = acts[i % acts.length];
    const [actor, at] = action === 'config.import' ? actors[3] : pick(r, actors.slice(0, 3));
    t -= (20 + r() * 300) * 60e3 * (i < 6 ? 0.1 : 1);
    return { id: `aud_${String(100000 - i).padStart(6, '0')}`, time: iso(t), actor, actor_type: at, ip: at === 'token' ? '10.12.4.19' : pick(r, ['203.0.113.24', '198.51.100.7', '10.20.1.5']), action, target_type: tt, target_id: tid, summary };
  });
}

/* ------------------------------------------------------------- traffic */
// Requests/sec at time t: diurnal curve + deterministic jitter + an incident.
export function rpsAt(t) {
  const hour = (t / 3600e3) % 24;
  const diurnal = 0.62 + 0.38 * Math.sin(((hour - 9) / 24) * Math.PI * 2);
  const jitter = 0.9 + hash01(t / 15000) * 0.2;
  return 420 * diurnal * jitter;
}
function incident(t, now) {
  // A burst of abuse 35-25 minutes ago and a smaller one ~4h ago.
  const ago = (now - t) / 60e3;
  if (ago > 25 && ago < 35) return 1 + 3.2 * Math.sin(((ago - 25) / 10) * Math.PI);
  if (ago > 235 && ago < 255) return 1 + 1.4 * Math.sin(((ago - 235) / 20) * Math.PI);
  return 1;
}

export const RANGES = { '15m': [15 * 60e3, 5], '1h': [3600e3, 15], '6h': [6 * 3600e3, 60], '24h': [DAY, 300] };

export function timeseries(range = '1h', now = Date.now(), routeFactor = 1) {
  const [span, step] = RANGES[range] || RANGES['1h'];
  const stepMs = step * 1000;
  const end = Math.floor(now / stepMs) * stepMs;
  const n = Math.round(span / stepMs);
  const points = [];
  for (let i = n - 1; i >= 0; i--) {
    const t = end - i * stepMs;
    const inc = incident(t, now);
    const reqs = rpsAt(t) * step * routeFactor;
    const limRate = 0.035 + (inc - 1) * 0.11 + hash01(t / 7000) * 0.012;
    const limited = Math.round(reqs * limRate);
    const shadow = Math.round(reqs * (0.012 + hash01(t / 3000) * 0.008));
    const errors = Math.round(reqs * (0.006 + hash01(t / 11000) * 0.006 + (inc > 1.5 ? 0.01 : 0)));
    const allowed = Math.round(reqs * inc) - limited - errors;
    const lat = 1 + (inc - 1) * 0.6;
    points.push({
      t: iso(t), allowed: Math.max(0, allowed), limited, shadow_limited: shadow, errors,
      p50_ms: +(7.5 * lat + hash01(t / 5000) * 2.5).toFixed(2),
      p95_ms: +(38 * lat + hash01(t / 6000) * 14).toFixed(2),
      p99_ms: +(96 * lat + hash01(t / 9000) * 70).toFixed(2),
    });
  }
  return { step_s: step, points };
}

export function overview(snap, now = Date.now()) {
  const ts = timeseries('24h', now);
  const sum = k => ts.points.reduce((a, p) => a + p[k], 0);
  const allowed = sum('allowed'), limited = sum('limited'), shadow = sum('shadow_limited'), errors = sum('errors');
  const requests = allowed + limited + errors;
  const cname = id => (snap.consumers.find(c => c.id === id) || {}).name || id;
  const top = (ids, total, decay = 0.62) => ids.map((id, i) => ({ id, label: cname(id), count: Math.round(total * Math.pow(decay, i) * (1 - decay)) }));
  const keys = ['hooli', 'pied-piper', 'cyberdyne', 'initech', 'acme-ios', 'soylent', 'vandelay', 'massive-dynamic'];
  return {
    requests, allowed, limited, shadow_limited: shadow, errors,
    rps_1m: +(rpsAt(now) * incident(now - 30e3, now)).toFixed(1),
    p50_ms: 8.4, p95_ms: 44.7, p99_ms: 131.2,
    top_limited_keys: [
      { id: '3f9a1c0be2d84e71', label: 'Hooli', count: Math.round(limited * 0.31) },
      { id: '185.220.101.4|/auth/login', label: '185.220.101.4', count: Math.round(limited * 0.19) },
      { id: 'pied-piper', label: 'Pied Piper', count: Math.round(limited * 0.14) },
      { id: 'initech', label: 'Initech', count: Math.round(limited * 0.08) },
      { id: '45.155.205.233|/auth/login', label: '45.155.205.233', count: Math.round(limited * 0.06) },
      { id: 'cyberdyne', label: 'Cyberdyne', count: Math.round(limited * 0.04) },
      { id: '9b02ee71a4cc5d10', label: 'Acme iOS app', count: Math.round(limited * 0.03) },
    ],
    top_routes: [['orders-api', 'Orders API', 0.38], ['search-api', 'Search', 0.27], ['catalog-public', 'Public catalog', 0.16], ['exports', 'Bulk exports', 0.08], ['auth-login', 'Auth: login', 0.07], ['uploads', 'Uploads', 0.04]]
      .map(([id, label, f]) => ({ id, label, count: Math.round(requests * f) })),
    top_policies: [['search-burst', 'Search burst', 0.44], ['login-guard', 'Login brute-force guard', 0.27], ['api-default', 'API default', 0.21], ['export-daily', 'Daily export quota', 0.08]]
      .map(([id, label, f]) => ({ id, label, count: Math.round(limited * f) })),
    top_consumers: top(['northwind', 'globex', 'stark-mobile', 'tyrell', 'initech', 'acme-ios', 'wayne-analytics', 'hooli'], requests * 0.9, 0.7),
    status_breakdown: [
      { id: '2xx', label: '2xx', count: Math.round(allowed * 0.962) },
      { id: '3xx', label: '3xx', count: Math.round(allowed * 0.011) },
      { id: '4xx', label: '4xx', count: Math.round(allowed * 0.024 + errors * 0.6) },
      { id: '429', label: '429', count: limited },
      { id: '5xx', label: '5xx', count: Math.round(allowed * 0.003 + errors * 0.4) },
    ],
    since: iso(now - DAY),
    counts: { routes: snap.routes.length, policies: snap.policies.length, plans: snap.plans.length, consumers: snap.consumers.length },
    _keys: keys,
  };
}

/* ------------------------------------------------------------- logs */
const UAS = ['okhttp/4.12.0', 'python-requests/2.32.3', 'Go-http-client/2.0', 'axios/1.7.2', 'curl/8.7.1', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15', 'AcmeSDK-iOS/5.2.1'];
const IPS = ['34.201.18.77', '52.14.233.9', '18.196.40.21', '185.220.101.4', '45.155.205.233', '91.198.174.192', '203.0.113.24', '198.51.100.7', '35.177.2.140', '104.28.12.66'];
let seq = 0;
export function logEntry(snap, r, t) {
  const route = weighted(r, [[snap.routes[0], 38], [snap.routes[1], 27], [snap.routes[5], 16], [snap.routes[3], 8], [snap.routes[2], 7], [snap.routes[4], 4], [null, 0.6]]);
  const consumer = route && route.require_api_key ? weighted(r, snap.consumers.map((c, i) => [c, Math.max(1, 14 - i)])) : (route && r() < 0.3 ? pick(r, snap.consumers) : null);
  const ip = route && route.id === 'auth-login' && r() < 0.4 ? pick(r, IPS.slice(3, 5)) : pick(r, IPS);
  const paths = {
    'orders-api': () => pick(r, ['/v1/orders', `/v1/orders/ord_${base62(r, 8)}`, `/v1/orders/ord_${base62(r, 8)}/items`]),
    'search-api': () => `/v1/search?q=${pick(r, ['shoes', 'lamp', 'usb-c+cable', 'desk', 'monitor+arm', 'coffee'])}`,
    'catalog-public': () => `/v1/catalog/${pick(r, ['products', 'categories', 'brands'])}/${Math.floor(r() * 9000 + 1000)}`,
    'exports': () => pick(r, ['/v1/exports', `/v1/exports/exp_${base62(r, 6)}`]),
    'auth-login': () => '/auth/login',
    'uploads': () => `/assets/${base62(r, 10)}.png`,
  };
  const method = route ? (route.match.methods && route.match.methods.length ? pick(r, route.match.methods) : weighted(r, [['GET', 7], ['POST', 2], ['PATCH', 0.6], ['DELETE', 0.3]])) : 'GET';
  let decision = weighted(r, [['allowed', 91], ['limited', 5.4], ['shadow_limited', 1.4], ['unauthorized', 0.9], ['error', 0.5]]);
  if (!route) decision = 'no_route';
  if (consumer && consumer.id === 'hooli' && r() < 0.5) decision = 'limited';
  const policyId = route ? (decision === 'shadow_limited' ? 'tenant-header' : route.policy_ids[0]) : '';
  const policy = snap.policies.find(p => p.id === policyId);
  const status = { allowed: weighted(r, [[200, 90], [201, 5], [204, 2], [304, 1], [404, 1.5], [500, 0.3]]), limited: 429, shadow_limited: 200, unauthorized: 401, no_route: 404, error: weighted(r, [[502, 3], [503, 1]]) }[decision];
  const keyOf = () => {
    if (!policy) return '';
    return policy.key_by.map(k => k === 'consumer' ? (consumer ? consumer.id : ip) : k === 'ip' ? ip : k === 'api_key' ? hex(r, 16) : k === 'path' ? '/auth/login' : k === 'route' ? route.id : k === 'global' ? 'global' : k.startsWith('header:') ? 't_' + base62(r, 4) : '-').join('|');
  };
  const lat = decision === 'limited' || decision === 'unauthorized' ? 0.3 + r() * 0.9 : 4 + Math.pow(r(), 3) * 180;
  const limit = policy ? policy.limit : 0;
  seq++;
  return {
    id: `${t.toString(36)}-${String(seq).padStart(6, '0')}`,
    time: iso(t), method, host: route && route.match.host && !route.match.host.startsWith('*') ? route.match.host : 'api.acme.dev',
    path: route ? paths[route.id]() : pick(r, ['/wp-login.php', '/.env', '/v2/unknown']),
    route_id: route ? route.id : undefined, route_name: route ? route.name : undefined,
    client_ip: ip, consumer_id: consumer ? consumer.id : undefined, consumer_name: consumer ? consumer.name : undefined,
    rate_key: keyOf() || undefined, policy_id: policyId || undefined, decision, status,
    limit: limit || undefined, remaining: decision === 'limited' ? 0 : Math.floor(r() * (limit || 1)),
    latency_ms: +lat.toFixed(2), upstream_ms: decision === 'allowed' || decision === 'shadow_limited' ? +(lat * 0.92).toFixed(2) : 0,
    bytes_out: decision === 'allowed' ? Math.floor(200 + r() * 24000) : 112,
    user_agent: consumer && consumer.id === 'acme-ios' ? UAS[6] : pick(r, UAS.slice(0, 6)),
    error: decision === 'error' ? pick(r, ['upstream timeout after 15s', 'dial tcp 10.0.3.14:8000: connect: connection refused']) : undefined,
    source: r() < 0.08 ? 'check_api' : 'proxy',
  };
}
