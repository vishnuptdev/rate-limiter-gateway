// In-browser fixture API for ?mock=1. Implements the admin REST contract
// (docs/ARCHITECTURE.md) against an in-memory snapshot so every page can be
// demoed — including CRUD, 422 validation, 409 conflicts and the live log
// stream (simulated with timers). Never loaded unless mock mode is on.
import * as F from './fixtures.js';

const q0 = new URLSearchParams(location.search);
const NOW = Date.now();
const r = F.rng(1234);
const snap = F.buildSnapshot(NOW);
const users = F.buildUsers(NOW);
const tokens = F.buildTokens(NOW);
const audit = F.buildAudit(NOW);
const limitsState = new Map();
const role = ['admin', 'editor', 'viewer'].includes(q0.get('role')) ? q0.get('role') : 'admin';
let me = q0.get('mockauth') === 'out' ? null : { username: role === 'admin' ? 'admin' : role === 'editor' ? 'maria.k' : 'oncall-viewer', role, must_change_password: q0.get('mockauth') === 'change' };

// Pre-fill the log ring with the last ~20 minutes.
const logs = [];
{
  let t = NOW - 20 * 60e3;
  while (t < NOW) { logs.push(F.logEntry(snap, r, t)); t += 400 + r() * 1800; }
  logs.reverse(); // newest first
}
const subscribers = new Set();
function record(e) {
  logs.unshift(e);
  if (logs.length > 5000) logs.pop();
  subscribers.forEach(f => f(e));
}

const sleep = ms => new Promise(res => setTimeout(res, ms));
const iso = t => new Date(t).toISOString();
const ok = body => ({ status: 200, body });
const created = body => ({ status: 201, body });
const fail = (status, error, message, problems) => ({ status, body: { error, message, ...(problems ? { problems } : {}) } });
const ID_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const ALGOS = ['gcra', 'token_bucket', 'sliding_window', 'sliding_window_counter', 'fixed_window', 'leaky_bucket', 'concurrency'];
const KINDS = { policies: 'policy', routes: 'route', plans: 'plan', consumers: 'consumer' };
const slug = s => String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40) || 'item';

function parseDur(v) {
  if (typeof v === 'number') return v * 1000;
  const m = String(v || '').match(/^(?:(\d+)h)?(?:(\d+)m(?!s))?(?:(\d+(?:\.\d+)?)s)?(?:(\d+)ms)?$/);
  if (!m || !String(v)) return NaN;
  return (+(m[1] || 0)) * 3600e3 + (+(m[2] || 0)) * 60e3 + (+(m[3] || 0)) * 1000 + (+(m[4] || 0));
}

function audited(action, targetType, targetId, summary) {
  audit.unshift({ id: `aud_${Date.now().toString(36)}`, time: iso(Date.now()), actor: me ? me.username : 'admin', actor_type: 'user', ip: '127.0.0.1', action, target_type: targetType, target_id: targetId, summary });
}

function validate(kind, obj, idx) {
  const p = [];
  const f = (field, message) => p.push({ field: `${kind}[${idx}].${field}`, message });
  if (!obj.name || !String(obj.name).trim()) f('name', 'Name is required');
  else if (obj.name.length > 100) f('name', 'Name must be at most 100 characters');
  if (obj.id && !ID_RE.test(obj.id)) f('id', 'IDs use lowercase letters, digits, - and _ (max 64)');
  if (kind === 'policies') {
    if (!ALGOS.includes(obj.algorithm)) f('algorithm', 'Unknown algorithm');
    if (!(obj.limit >= 1 && obj.limit <= 1e9)) f('limit', 'Limit must be between 1 and 1,000,000,000');
    if (obj.algorithm !== 'concurrency') {
      const w = parseDur(obj.window);
      if (!(w >= 1)) f('window', 'Window must be a duration like 1s, 1m or 24h');
      else if (w > 365 * 86400e3) f('window', 'Window must be at most 365 days');
    }
    if (obj.burst < 0) f('burst', 'Burst cannot be negative');
    if (obj.cost && obj.cost > obj.limit) f('cost', 'Cost cannot exceed the limit');
    if (!Array.isArray(obj.key_by) || !obj.key_by.length) f('key_by', 'Choose at least one key');
    (obj.key_by || []).forEach((k, i) => { if (/^(header|query):$/.test(k)) p.push({ field: `${kind}[${idx}].key_by[${i}]`, message: `“${k}” needs a name` }); });
  }
  if (kind === 'routes') {
    if (!/^https?:\/\/[^/]+/.test(obj.upstream || '')) f('upstream', 'Upstream must be an absolute http(s) URL with a host');
    const pp = obj.match && obj.match.path_prefix;
    if (pp && !pp.startsWith('/')) f('match.path_prefix', 'Path prefix must start with “/”');
    (obj.policy_ids || []).forEach(id => { if (!snap.policies.some(x => x.id === id)) f('policy_ids', `Unknown policy “${id}”`); });
  }
  if (kind === 'consumers' && obj.plan_id && !snap.plans.some(x => x.id === obj.plan_id)) f('plan_id', 'Unknown plan');
  return p;
}

function referrers(kind, id) {
  if (kind === 'policies') {
    const refs = snap.routes.filter(rt => rt.policy_ids.includes(id)).map(rt => ({ type: 'route', id: rt.id, name: rt.name }));
    if (snap.settings.global_policy_ids.includes(id)) refs.push({ type: 'settings', id: 'global_policy_ids' });
    snap.plans.forEach(pl => { if (pl.overrides && pl.overrides[id]) refs.push({ type: 'plan', id: pl.id, name: pl.name }); });
    return refs;
  }
  if (kind === 'plans') return snap.consumers.filter(c => c.plan_id === id).map(c => ({ type: 'consumer', id: c.id, name: c.name }));
  return [];
}

function crud(kind, method, id, body) {
  const arr = snap[kind];
  const i = id ? arr.findIndex(x => x.id === id) : -1;
  if (method === 'GET' && !id) return ok(arr);
  if (method === 'GET') return i < 0 ? fail(404, 'not_found', `${KINDS[kind]} not found`) : ok(arr[i]);
  if (method === 'POST') {
    const obj = { ...body };
    if (!obj.id) obj.id = `${slug(obj.name)}-${F.base62(r, 4).toLowerCase()}`;
    if (arr.some(x => x.id === obj.id)) return fail(422, 'validation_failed', 'Validation failed', [{ field: `${kind}[${arr.length}].id`, message: 'ID already exists' }]);
    const probs = validate(kind, obj, arr.length);
    if (probs.length) return fail(422, 'validation_failed', 'Validation failed', probs);
    obj.created_at = obj.updated_at = iso(Date.now());
    if (kind === 'consumers') obj.keys = [];
    arr.push(obj);
    snap.version++;
    audited(`${KINDS[kind]}.create`, KINDS[kind], obj.id, `Created ${KINDS[kind]} “${obj.name}”`);
    return created(obj);
  }
  if (i < 0) return fail(404, 'not_found', `${KINDS[kind]} not found`);
  if (method === 'PUT') {
    const obj = { ...arr[i], ...body, id, created_at: arr[i].created_at, updated_at: iso(Date.now()) };
    if (kind === 'consumers') obj.keys = arr[i].keys;
    const probs = validate(kind, obj, i);
    if (probs.length) return fail(422, 'validation_failed', 'Validation failed', probs);
    arr[i] = obj;
    snap.version++;
    audited(`${KINDS[kind]}.update`, KINDS[kind], id, `Updated ${KINDS[kind]} “${obj.name}”`);
    return ok(obj);
  }
  if (method === 'DELETE') {
    const refs = referrers(kind, id);
    if (refs.length) return { status: 409, body: { error: 'referenced', message: `${KINDS[kind]} is still referenced`, referrers: refs } };
    arr.splice(i, 1);
    snap.version++;
    audited(`${KINDS[kind]}.delete`, KINDS[kind], id, `Deleted ${KINDS[kind]} ${id}`);
    return { status: 204, body: null };
  }
  return fail(405, 'method_not_allowed', 'Method not allowed');
}

function matchLogs(e, q) {
  if (q.decision && e.decision !== q.decision) return false;
  if (q.route_id && e.route_id !== q.route_id) return false;
  if (q.consumer_id && e.consumer_id !== q.consumer_id) return false;
  if (q.policy_id && e.policy_id !== q.policy_id) return false;
  if (q.status_min && e.status < +q.status_min) return false;
  if (q.status_max && e.status > +q.status_max) return false;
  if (q.q) {
    const s = q.q.toLowerCase();
    if (![e.path, e.client_ip, e.rate_key, e.consumer_name].some(x => x && x.toLowerCase().includes(s))) return false;
  }
  return true;
}

function effective(policy, consumer) {
  let limit = policy.limit, window = policy.window, burst = policy.burst || 0, from = 'policy';
  const plan = consumer && snap.plans.find(p => p.id === consumer.plan_id);
  const apply = (o, src) => { if (!o) return; if (o.limit) { limit = o.limit; from = src; } if (o.window) window = o.window; if (o.burst) burst = o.burst; };
  if (plan) apply(plan.overrides && plan.overrides[policy.id], `plan:${plan.id}`);
  if (consumer) apply(consumer.overrides && consumer.overrides[policy.id], 'consumer');
  return { limit, window, burst, from };
}

function simulate(req) {
  const host = (req.host || '').split(':')[0];
  const path = req.path || '/';
  const method = (req.method || 'GET').toUpperCase();
  const cands = snap.routes.filter(rt => rt.enabled).filter(rt => {
    const m = rt.match;
    if (m.host && !(m.host === host || (m.host.startsWith('*.') && host.endsWith(m.host.slice(1))))) return false;
    if (m.path_prefix && m.path_prefix !== '/' && !(path === m.path_prefix || path.startsWith(m.path_prefix + '/') || path.startsWith(m.path_prefix + '?'))) return false;
    if (m.methods && m.methods.length && !m.methods.includes(method)) return false;
    return true;
  }).sort((a, b) => b.priority - a.priority || (b.match.path_prefix || '').length - (a.match.path_prefix || '').length);
  const route = cands[0];
  if (!route) return { matched: false, policies: [], decision: 'no_route', notes: ['No enabled route matches this host, path and method.'] };
  const hdrs = Object.fromEntries(Object.entries(req.headers || {}).map(([k, v]) => [k.toLowerCase(), v]));
  const key = hdrs[snap.settings.api_key_header.toLowerCase()] || (hdrs.authorization || '').replace(/^Bearer\s+/i, '');
  let consumer = null, authError = '';
  const notes = [];
  if (key) {
    consumer = snap.consumers.find(c => c.keys.some(k => key.startsWith(k.prefix) && !k.revoked));
    if (!consumer && key.startsWith('rlg_live_')) consumer = snap.consumers[Math.abs([...key].reduce((a, ch) => a * 31 + ch.charCodeAt(0), 7)) % 6];
    if (!consumer) authError = 'API key not recognised';
    else if (consumer.disabled) { authError = 'Consumer is disabled'; consumer = null; }
  } else if (route.require_api_key) authError = 'API key required on this route';
  if (authError) return { matched: true, route_id: route.id, route_name: route.name, upstream: route.upstream, auth_error: authError, policies: [], decision: 'unauthorized', notes: ['The gateway would answer 401 before any limit is checked.'] };
  const ids = [...new Set([...snap.settings.global_policy_ids, ...route.policy_ids])];
  let decision = 'allowed';
  const ip = req.ip || '203.0.113.10';
  const policies = ids.map(id => snap.policies.find(p => p.id === id)).filter(p => p && p.enabled).map(p => {
    const eff = effective(p, consumer);
    const rk = p.key_by.map(k => k === 'consumer' ? (consumer ? consumer.id : ip) : k === 'ip' ? ip : k === 'api_key' ? (key ? 'a1b2c3d4e5f60718' : '-') : k === 'path' ? path : k === 'method' ? method : k === 'route' ? route.id : k === 'global' ? 'global' : k.startsWith('header:') ? (hdrs[k.slice(7).toLowerCase()] || '-') : k.startsWith('query:') ? ((req.query || {})[k.slice(6)] || '-') : '-').join('|');
    const res = { policy_id: p.id, policy_name: p.name, algorithm: p.algorithm, mode: p.mode, limit: eff.limit, window: eff.window, burst: eff.burst || undefined, limit_from: eff.from, rate_key: rk };
    if (req.consume) {
      if (p.algorithm === 'concurrency') { notes.push(`${p.name}: concurrency slots are not consumed by the simulator.`); return res; }
      const st = limitsState.get(`${p.id}:${rk}`) || { remaining: Math.max(0, eff.limit - Math.floor(eff.limit * 0.3)) };
      const allowed = st.remaining > 0;
      if (allowed) st.remaining--;
      limitsState.set(`${p.id}:${rk}`, st);
      Object.assign(res, { allowed, remaining: st.remaining, retry_after_ms: allowed ? 0 : 12000 });
      if (p.algorithm === 'leaky_bucket' && allowed) { res.delay_ms = 40 + Math.floor(r() * 160); notes.push(`${p.name}: request queued and released after ${res.delay_ms} ms (traffic shaping).`); }
      if (!allowed && decision === 'allowed') decision = p.mode === 'shadow' ? 'shadow_limited' : 'limited';
    }
    return res;
  });
  if (!req.consume) notes.push('Dry run: buckets were not touched. Enable “consume” to run a real check.');
  if (!consumer) notes.push('No API key: “consumer” keys fall back to the client IP.');
  return { matched: true, route_id: route.id, route_name: route.name, upstream: route.upstream, consumer_id: consumer ? consumer.id : undefined, consumer_name: consumer ? consumer.name : undefined, policies, decision, notes };
}

function diff(next) {
  const out = {};
  for (const k of Object.keys(KINDS)) {
    const a = new Map(snap[k].map(x => [x.id, JSON.stringify({ ...x, created_at: 0, updated_at: 0 })]));
    const b = new Map((next[k] || []).map(x => [x.id, JSON.stringify({ ...x, created_at: 0, updated_at: 0 })]));
    out[k] = {
      added: [...b.keys()].filter(id => !a.has(id)).length,
      removed: [...a.keys()].filter(id => !b.has(id)).length,
      changed: [...b.keys()].filter(id => a.has(id) && a.get(id) !== b.get(id)).length,
    };
  }
  out.settings = { added: 0, removed: 0, changed: JSON.stringify(next.settings || {}) !== JSON.stringify(snap.settings) ? 1 : 0 };
  return out;
}

/* ---------------------------------------------------------------- router */
export async function handle(method, url, body) {
  await sleep(url.startsWith('/auth') ? 120 : 80 + Math.random() * 180);
  const [path, qs = ''] = url.split('?');
  const q = Object.fromEntries(new URLSearchParams(qs));
  const seg = path.split('/').filter(Boolean).map(decodeURIComponent);

  if (path === '/auth/login' && method === 'POST') {
    if (!body.username || !body.password) return fail(400, 'bad_request', 'Username and password are required');
    if (body.password === 'wrong') return fail(401, 'invalid_credentials', 'invalid username or password');
    if (body.password === 'locked') return { status: 429, body: { error: 'locked_out', message: 'too many failed login attempts; try again later', retry_after_s: 60 } };
    me = { username: body.username, role: users.find(u => u.username === body.username)?.role || role, must_change_password: false };
    return ok({ user: me, csrf_token: 'mock-csrf' });
  }
  if (path === '/auth/me') return me ? ok({ user: me, csrf_token: 'mock-csrf' }) : fail(401, 'unauthorized', 'Not signed in');
  if (path === '/auth/logout') { me = null; return { status: 204, body: null }; }
  if (!me) return fail(401, 'unauthorized', 'Not signed in');
  if (path === '/auth/password') {
    if ((body.new_password || '').length < 12) return fail(422, 'weak_password', 'password must be at least 12 characters');
    if (body.current_password === 'wrong') return fail(401, 'invalid_credentials', 'current password is incorrect');
    me.must_change_password = false;
    return ok({ csrf_token: 'mock-csrf-2' });
  }
  if (me.must_change_password) return fail(403, 'password_change_required', 'You must change your password first');
  const editor = me.role !== 'viewer', admin = me.role === 'admin';
  if (method !== 'GET' && !editor && path !== '/simulate') return fail(403, 'forbidden', 'Your role cannot make changes');

  if (path === '/system') {
    return ok({ version: 'v2.0.0-demo', go_version: 'go1.24.7', instance_id: 'rg-7f3c9a', started_at: iso(NOW - 3 * 86400e3 - 4 * 3600e3), uptime_s: Math.floor((Date.now() - NOW) / 1000) + 3 * 86400 + 4 * 3600, engine: { name: 'redis', healthy: true }, store: { name: 'redis' }, config_version: snap.version, data_plane_addr: ':8080', admin_addr: ':9000' });
  }
  if (path === '/overview') return ok(F.overview(snap, Date.now()));
  if (path === '/timeseries') {
    const factor = q.route_id ? ({ 'orders-api': 0.38, 'search-api': 0.27, 'catalog-public': 0.16, exports: 0.08, 'auth-login': 0.07, uploads: 0.04 }[q.route_id] || 0.02) : 1;
    return ok(F.timeseries(q.range || '1h', Date.now(), factor));
  }
  if (path === '/logs') {
    let list = logs;
    if (q.before) { const i = list.findIndex(e => e.id === q.before); list = i >= 0 ? list.slice(i + 1) : []; }
    const lim = Math.min(1000, +q.limit || 100);
    return ok({ entries: list.filter(e => matchLogs(e, q)).slice(0, lim) });
  }
  if (seg[0] in KINDS) {
    if (seg[0] === 'consumers' && seg[2] === 'keys') {
      const c = snap.consumers.find(x => x.id === seg[1]);
      if (!c) return fail(404, 'not_found', 'consumer not found');
      if (method === 'POST') {
        const plain = 'rlg_live_' + F.base62(r, 32);
        const k = { id: 'key_' + F.base62(r, 8).toLowerCase(), prefix: plain.slice(0, 12), name: body.name || '', created_at: iso(Date.now()), expires_at: body.expires_at || undefined, revoked: false };
        c.keys.push(k);
        audited('consumer.key.create', 'consumer', c.id, `Issued key ${k.prefix}`);
        return created({ key: plain, api_key: k });
      }
      if (method === 'DELETE') {
        const k = c.keys.find(x => x.id === seg[3]);
        if (!k) return fail(404, 'not_found', 'key not found');
        k.revoked = true;
        audited('consumer.key.revoke', 'consumer', c.id, `Revoked key ${k.prefix}`);
        return ok({ api_key: k });
      }
    }
    return crud(seg[0], method, seg[1], body);
  }
  if (path === '/settings') {
    if (method === 'GET') return ok(snap.settings);
    if (!admin) return fail(403, 'forbidden', 'Only admins can change settings');
    const probs = [];
    if (!body.api_key_header) probs.push({ field: 'settings.api_key_header', message: 'Header name is required' });
    if (body.ipv6_prefix_len && (body.ipv6_prefix_len < 32 || body.ipv6_prefix_len > 128)) probs.push({ field: 'settings.ipv6_prefix_len', message: 'Must be between 32 and 128' });
    if (body.log_sample_allowed < 0 || body.log_sample_allowed > 1) probs.push({ field: 'settings.log_sample_allowed', message: 'Must be between 0 and 1' });
    (body.trusted_proxies || []).forEach((p, i) => { if (!/^[0-9a-f:.]+(\/\d+)?$/i.test(p)) probs.push({ field: `settings.trusted_proxies[${i}]`, message: `“${p}” is not an IP or CIDR` }); });
    if (probs.length) return fail(422, 'validation_failed', 'Validation failed', probs);
    snap.settings = { ...snap.settings, ...body };
    snap.version++;
    audited('settings.update', 'settings', 'settings', 'Updated gateway settings');
    return ok(snap.settings);
  }
  if (path === '/simulate') {
    if (body.consume && !editor) return fail(403, 'forbidden', 'Consuming requires the editor role');
    return ok(simulate(body));
  }
  if (path === '/limits') {
    const p = snap.policies.find(x => x.id === q.policy_id);
    if (!p) return fail(404, 'not_found', 'policy not found');
    const ek = `${p.id}:${q.key || ''}`;
    const exists = limitsState.has(ek) || (q.key || '').length % 3 !== 0;
    const st = limitsState.get(ek) || { remaining: exists ? Math.floor(p.limit * (0.15 + ((q.key || '').length % 7) / 10)) : p.limit };
    if (/hooli|185\.220|3f9a/.test(q.key || '')) st.remaining = 0;
    return ok({ policy_id: p.id, key: q.key, engine_key: ek, exists, limit: p.limit, remaining: st.remaining, reset_s: exists ? 7 + ((q.key || '').length * 13) % 50 : 0 });
  }
  if (path === '/limits/reset') {
    limitsState.set(`${body.policy_id}:${body.key}`, { remaining: (snap.policies.find(x => x.id === body.policy_id) || { limit: 0 }).limit });
    audited('limits.reset', 'limit', `${body.policy_id}:${body.key}`, 'Reset bucket');
    return ok({ ok: true });
  }
  if (!admin && /^\/(config|audit|users|tokens)/.test(path)) return fail(403, 'forbidden', 'Admin role required');
  if (path === '/config/export') return ok(JSON.parse(JSON.stringify(snap)));
  if (path === '/config/import') {
    const next = body.snapshot;
    if (!next || typeof next !== 'object' || !Array.isArray(next.policies)) return fail(422, 'validation_failed', 'Validation failed', [{ field: 'snapshot', message: 'Not a RateGuard snapshot (missing policies)' }]);
    const problems = [];
    next.policies.forEach((p, i) => validate('policies', p, i).forEach(x => problems.push(x)));
    if (problems.length) return body.dry_run ? ok({ ok: false, dry_run: true, message: 'Validation failed', problems, diff: diff(next) }) : fail(422, 'validation_failed', 'Validation failed', problems);
    const d = diff(next);
    if (!body.dry_run) { ['policies', 'routes', 'plans', 'consumers'].forEach(k => { snap[k] = next[k] || []; }); if (next.settings) snap.settings = next.settings; snap.version++; audited('config.import', 'config', 'snapshot', 'Imported configuration'); }
    return ok({ ok: true, dry_run: !!body.dry_run, diff: d, version: snap.version });
  }
  if (path === '/audit') {
    let list = audit;
    if (q.before) { const i = list.findIndex(e => e.id === q.before); list = i >= 0 ? list.slice(i + 1) : []; }
    return ok({ entries: list.slice(0, Math.min(500, +q.limit || 50)) });
  }
  if (seg[0] === 'users') {
    if (method === 'GET') return ok(users);
    if (method === 'POST') {
      const probs = [];
      if (!/^[a-z0-9._-]{2,64}$/i.test(body.username || '')) probs.push({ field: 'username', message: 'Use 2–64 letters, digits, dot, dash or underscore' });
      if (users.some(u => u.username === body.username)) probs.push({ field: 'username', message: 'That username is taken' });
      if ((body.password || '').length < 12) probs.push({ field: 'password', message: 'Use at least 12 characters' });
      if (probs.length) return fail(422, 'validation_failed', 'Validation failed', probs);
      const u = { username: body.username, role: body.role || 'viewer', must_change_password: body.must_change_password !== false, created_at: iso(Date.now()), last_login_at: null };
      users.push(u);
      audited('user.create', 'user', u.username, `Created ${u.role}`);
      return created(u);
    }
    const u = users.find(x => x.username === seg[1]);
    if (!u) return fail(404, 'not_found', 'user not found');
    if (method === 'PUT') {
      if (body.password && body.password.length < 12) return fail(422, 'validation_failed', 'Validation failed', [{ field: 'password', message: 'Use at least 12 characters' }]);
      if (u.role === 'admin' && body.role && body.role !== 'admin' && users.filter(x => x.role === 'admin').length === 1) return fail(409, 'conflict', 'Cannot demote the last admin');
      Object.assign(u, body.role ? { role: body.role } : {}, body.password ? { must_change_password: true } : {});
      audited('user.update', 'user', u.username, 'Updated user');
      return ok(u);
    }
    if (method === 'DELETE') {
      if (u.username === me.username) return fail(409, 'conflict', 'You cannot delete yourself');
      users.splice(users.indexOf(u), 1);
      audited('user.delete', 'user', u.username, 'Deleted user');
      return { status: 204, body: null };
    }
  }
  if (seg[0] === 'tokens') {
    if (method === 'GET') return ok(tokens);
    if (method === 'POST') {
      if (!body.name) return fail(422, 'validation_failed', 'Validation failed', [{ field: 'name', message: 'Name is required' }]);
      if (!body.scopes || !body.scopes.length) return fail(422, 'validation_failed', 'Validation failed', [{ field: 'scopes', message: 'Pick at least one scope' }]);
      const plain = 'rgt_' + F.base62(r, 40);
      const info = { id: 'tok_' + F.base62(r, 8).toLowerCase(), name: body.name, prefix: plain.slice(0, 8), scopes: body.scopes, created_at: iso(Date.now()), expires_at: body.expires_at || null, last_used_at: null };
      tokens.push(info);
      audited('token.create', 'token', info.id, `Created token ${info.name}`);
      return created({ token: plain, info });
    }
    if (method === 'DELETE') {
      const i = tokens.findIndex(t => t.id === seg[1]);
      if (i < 0) return fail(404, 'not_found', 'token not found');
      tokens.splice(i, 1);
      audited('token.delete', 'token', seg[1], 'Revoked token');
      return { status: 204, body: null };
    }
  }
  return fail(404, 'not_found', `No mock for ${method} ${path}`);
}

/* ------------------------------------------------------------ live stream */
let generator = 0;
function ensureGenerator() {
  if (generator) return;
  const tick = () => {
    const n = Math.floor(1 + r() * 4);
    const now = Date.now();
    for (let i = 0; i < n; i++) record(F.logEntry(snap, r, now - Math.floor(r() * 300)));
    generator = setTimeout(tick, 250 + r() * 650);
  };
  generator = setTimeout(tick, 400);
}

/** EventSource look-alike fed by the fixture generator. */
export class MockEventSource {
  constructor(url) {
    this.url = url;
    this.readyState = 0;
    this.listeners = {};
    const q = Object.fromEntries(new URLSearchParams(url.split('?')[1] || ''));
    this.fn = e => { if (this.readyState === 1 && matchLogs(e, q)) this.emit('log', { data: JSON.stringify(e) }); };
    setTimeout(() => {
      if (this.readyState === 2) return;
      this.readyState = 1;
      this.emit('open', {});
      subscribers.add(this.fn);
      ensureGenerator();
    }, 300);
  }
  addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); }
  removeEventListener(t, f) { this.listeners[t] = (this.listeners[t] || []).filter(x => x !== f); }
  emit(t, ev) { (this.listeners[t] || []).forEach(f => f(ev)); }
  close() {
    this.readyState = 2;
    subscribers.delete(this.fn);
    if (!subscribers.size) { clearTimeout(generator); generator = 0; }
  }
}
