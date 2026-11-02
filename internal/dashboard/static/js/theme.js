// Theme: 'system' (follows prefers-color-scheme), 'light' or 'dark'.
// Persisted in localStorage when available.
const KEY = 'rg-theme';

function read() {
  try {
    const q = new URLSearchParams(location.search).get('theme');
    if (q === 'light' || q === 'dark') return q;
    return localStorage.getItem(KEY) || 'system';
  } catch { return 'system'; }
}

let pref = read();
const subs = new Set();

function apply() {
  const el = document.documentElement;
  if (pref === 'light' || pref === 'dark') el.dataset.theme = pref;
  else delete el.dataset.theme;
}

export const preference = () => pref;
export function effective() {
  if (pref !== 'system') return pref;
  return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

export function setTheme(t) {
  pref = t;
  try { if (t === 'system') localStorage.removeItem(KEY); else localStorage.setItem(KEY, t); } catch { /* storage unavailable */ }
  apply();
  subs.forEach(f => f(effective()));
}

export function toggle() { setTheme(effective() === 'dark' ? 'light' : 'dark'); }
export function onChange(f) { subs.add(f); return () => subs.delete(f); }

apply();
if (window.matchMedia) {
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => { if (pref === 'system') subs.forEach(f => f(effective())); });
}
