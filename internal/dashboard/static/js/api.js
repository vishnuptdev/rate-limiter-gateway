// Same-origin JSON client for the admin API (/api/*).
// - cookie session; X-CSRF-Token on every non-GET
// - 401 -> app shows login; must_change_password -> forced password change
// - errors normalised into ApiError {status, code, message, problems}
// In mock mode (?mock=1 or localStorage rg-mock=1) requests are answered by
// an in-browser fixture layer instead of the network.

const listeners = new Map();
export function on(evt, fn) {
  if (!listeners.has(evt)) listeners.set(evt, new Set());
  listeners.get(evt).add(fn);
  return () => listeners.get(evt).delete(fn);
}
function emit(evt, data) { (listeners.get(evt) || []).forEach(f => { try { f(data); } catch (e) { console.error(e); } }); }

export class ApiError extends Error {
  constructor(status, body) {
    super((body && (body.message || body.error)) || `Request failed (${status})`);
    this.status = status;
    this.code = (body && body.error) || '';
    this.problems = (body && Array.isArray(body.problems)) ? body.problems : [];
    this.body = body;
  }
  get friendly() {
    if (this.status === 0) return 'Cannot reach the RateGuard admin API. Check your connection and try again.';
    if (this.status === 403) return 'You don’t have permission to do that. Ask an admin for access.';
    if (this.status === 404) return 'Not found — it may have been deleted.';
    if (this.status === 409) {
      const refs = (this.body && Array.isArray(this.body.referrers)) ? this.body.referrers : [];
      const msg = this.message ? this.message.charAt(0).toUpperCase() + this.message.slice(1) : 'That conflicts with the current configuration';
      return refs.length ? `${msg} by ${refs.map(r => `${r.type} ${r.name || r.id}`).join(', ')}. Remove those references first.` : msg + '.';
    }
    if (this.status === 401 && this.code === 'invalid_credentials') return 'Current password is incorrect.';
    if (this.code === 'weak_password') return this.message.charAt(0).toUpperCase() + this.message.slice(1) + '.';
    if (this.status === 422) return this.problems.length ? 'Please fix the highlighted fields.' : this.message;
    if (this.status === 429) return this.message || 'Too many attempts. Please wait and try again.';
    if (this.status >= 500) return 'The server hit an error. ' + (this.message || '');
    return this.message;
  }
}

let csrfToken = '';
export const setCSRF = t => { csrfToken = t || ''; };

function readFlag() {
  try {
    const q = new URLSearchParams(location.search);
    if (q.get('mock') === '0') { localStorage.removeItem('rg-mock'); return false; }
    if (q.get('mock') === '1') return true;
    return localStorage.getItem('rg-mock') === '1';
  } catch { return new URLSearchParams(location.search).get('mock') === '1'; }
}
export const MOCK = readFlag();

let mockMod = null;
async function mock() {
  if (!mockMod) mockMod = await import('./mock.js');
  return mockMod;
}

function qs(params) {
  if (!params) return '';
  const u = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== '') u.set(k, v);
  const s = u.toString();
  return s ? '?' + s : '';
}

const isAuthPath = p => p.startsWith('/auth/');

export async function request(method, path, body, opts = {}) {
  const url = path + qs(opts.query);
  let status, data;
  if (MOCK) {
    const m = await mock();
    ({ status, body: data } = await m.handle(method, url, body));
  } else {
    let res;
    const headers = { Accept: 'application/json' };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (method !== 'GET' && method !== 'HEAD' && csrfToken) headers['X-CSRF-Token'] = csrfToken;
    try {
      res = await fetch('/api' + url, {
        method, headers, credentials: 'same-origin', cache: 'no-store', signal: opts.signal,
        body: body !== undefined ? JSON.stringify(body) : undefined,
      });
    } catch (e) {
      if (e.name === 'AbortError') throw e;
      throw new ApiError(0, { message: 'Network error' });
    }
    status = res.status;
    const text = await res.text();
    try { data = text ? JSON.parse(text) : null; } catch { data = { message: text.slice(0, 200) }; }
  }
  if (status >= 200 && status < 300) return data;
  const err = new ApiError(status, data);
  if (status === 401 && !(isAuthPath(path) && path !== '/auth/me')) emit('unauthorized', err);
  if (status === 403 && /password/.test(err.code + ' ' + err.message) && !isAuthPath(path)) emit('mustchange', err);
  throw err;
}

export const get = (p, query, opts) => request('GET', p, undefined, { ...opts, query });
export const post = (p, body, opts) => request('POST', p, body === undefined ? {} : body, opts);
export const put = (p, body, opts) => request('PUT', p, body, opts);
export const del = (p, opts) => request('DELETE', p, undefined, opts);

/** Accepts either a bare array or an {key:[...]} / {items:[...]} envelope. */
export function list(resp, key) {
  if (Array.isArray(resp)) return resp;
  if (!resp || typeof resp !== 'object') return [];
  if (key && Array.isArray(resp[key])) return resp[key];
  if (Array.isArray(resp.items)) return resp.items;
  const firstArr = Object.values(resp).find(Array.isArray);
  return firstArr || [];
}

/** Fetch a downloadable payload (export). Returns a Blob. */
export async function download(path) {
  if (MOCK) {
    const data = await get(path);
    return new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  }
  const res = await fetch('/api' + path, { credentials: 'same-origin', cache: 'no-store' });
  if (!res.ok) {
    let body = null;
    try { body = await res.json(); } catch { /* not json */ }
    const err = new ApiError(res.status, body);
    if (res.status === 401) emit('unauthorized', err);
    throw err;
  }
  return res.blob();
}

/**
 * Open the live log stream. Returns a close() function.
 * onEntry(LogEntry), onState('connecting'|'open'|'reconnecting'|'closed').
 */
export function stream(params, onEntry, onState) {
  let closed = false;
  let es = null;
  let errors = 0;
  const handle = ev => {
    try { onEntry(JSON.parse(ev.data)); } catch (e) { console.warn('bad log event', e); }
  };
  onState('connecting');
  const open = Source => {
    if (closed) return;
    es = new Source('/api/logs/stream' + qs(params), { withCredentials: true });
    es.addEventListener('open', () => { errors = 0; onState('open'); });
    es.addEventListener('log', handle);
    es.addEventListener('error', () => {
      if (closed) return;
      errors++;
      onState('reconnecting');
      // EventSource can't expose the status code; probe the session after repeated failures.
      if (errors === 3) get('/auth/me').catch(() => {});
    });
  };
  if (MOCK) mock().then(m => open(m.MockEventSource));
  else open(window.EventSource);
  return () => { closed = true; if (es) es.close(); onState('closed'); };
}
