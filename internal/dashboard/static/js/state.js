// Session + small shared caches.
import * as api from './api.js';

export const session = { user: null, csrf: '' };

const RANK = { viewer: 1, editor: 2, admin: 3 };
/** can('edit') -> editor or admin; can('admin') -> admin only. */
export function can(what) {
  const r = RANK[session.user && session.user.role] || 0;
  if (what === 'admin') return r >= 3;
  if (what === 'edit') return r >= 2;
  return r >= 1;
}

export function setSession(resp) {
  session.user = resp && resp.user ? resp.user : null;
  session.csrf = (resp && resp.csrf_token) || '';
  api.setCSRF(session.csrf);
}

// Entity cache: used by forms (policy pickers etc.) and the command palette.
const cache = new Map();
const TTL = 15000;
export async function entities(kind, { fresh = false } = {}) {
  const hit = cache.get(kind);
  if (!fresh && hit && Date.now() - hit.t < TTL) return hit.v;
  const v = api.list(await api.get('/' + kind), kind);
  cache.set(kind, { t: Date.now(), v });
  return v;
}
export function invalidate(kind) { if (kind) cache.delete(kind); else cache.clear(); }

let systemInfo = null;
export async function system({ fresh = false } = {}) {
  if (!fresh && systemInfo) return systemInfo;
  systemInfo = await api.get('/system');
  return systemInfo;
}
