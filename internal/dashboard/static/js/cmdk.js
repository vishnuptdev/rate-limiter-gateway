// Command palette (Ctrl/Cmd+K) and global keyboard shortcuts.
import { h, mount, nextId } from './dom.js';
import { icon } from './icons.js';
import { go } from './router.js';
import { entities } from './state.js';
import { modal, overlayOpen } from './ui.js';
import * as theme from './theme.js';

let ctx = { pages: [], actions: () => [] };
export function init(c) { ctx = c; bindKeys(); }

/* -------------------------------------------------------------- fuzzy */
function score(q, text) {
  if (!q) return { s: 1, hits: [] };
  const t = text.toLowerCase();
  const idx = t.indexOf(q);
  if (idx >= 0) return { s: 100 - idx + (idx === 0 ? 50 : 0), hits: Array.from({ length: q.length }, (_, i) => idx + i) };
  let ti = 0, s = 0, last = -2;
  const hits = [];
  for (const ch of q) {
    const f = t.indexOf(ch, ti);
    if (f < 0) return null;
    s += f === last + 1 ? 5 : 1;
    hits.push(f); last = f; ti = f + 1;
  }
  return { s, hits };
}
function marked(text, hits) {
  if (!hits.length) return text;
  const set = new Set(hits);
  const out = [];
  let buf = '', inMark = false;
  for (let i = 0; i < text.length; i++) {
    const m = set.has(i);
    if (m !== inMark) { if (buf) out.push(inMark ? h('mark', {}, buf) : buf); buf = ''; inMark = m; }
    buf += text[i];
  }
  if (buf) out.push(inMark ? h('mark', {}, buf) : buf);
  return out;
}

/* -------------------------------------------------------------- palette */
let openState = null;
export async function openPalette() {
  if (openState) return;
  const listId = nextId('pl');
  const inp = h('input', { type: 'text', placeholder: 'Search pages, routes, policies, consumers…', 'aria-label': 'Command palette', role: 'combobox', 'aria-expanded': 'true', 'aria-controls': listId, 'aria-autocomplete': 'list', autocomplete: 'off', spellcheck: 'false' });
  const list = h('div', { class: 'palette-list', role: 'listbox', id: listId });
  const prevFocus = document.activeElement;
  const root = h('div', { class: 'palette-root', onMousedown: e => { if (e.target === root) close(); } },
    h('div', { class: 'palette', role: 'dialog', 'aria-modal': 'true', 'aria-label': 'Command palette' },
      h('div', { class: 'palette-input' }, icon('search'), inp, h('kbd', {}, 'Esc')),
      list,
      h('div', { class: 'palette-foot' },
        h('span', {}, h('kbd', {}, '↑'), h('kbd', {}, '↓'), 'navigate'),
        h('span', {}, h('kbd', {}, '↵'), 'open'),
        h('span', {}, h('kbd', {}, 'Esc'), 'close'))));
  document.getElementById('overlays').appendChild(root);
  inp.focus();

  let items = [
    ...(typeof ctx.pages === 'function' ? ctx.pages() : ctx.pages).map(p => ({ group: 'Pages', label: p.label, icon: p.icon, meta: p.keys || '', run: () => go(p.path) })),
    ...ctx.actions(),
    { group: 'Actions', label: 'Toggle light / dark theme', icon: 'moon', run: () => theme.toggle() },
  ];
  let sel = 0, shown = [];
  const draw = () => {
    const q = inp.value.trim().toLowerCase();
    shown = items.map(it => ({ it, m: score(q, it.label + (it.sub ? ' ' + it.sub : '')) })).filter(x => x.m)
      .sort((a, b) => (q ? b.m.s - a.m.s : 0)).slice(0, 60);
    sel = Math.min(sel, Math.max(0, shown.length - 1));
    const groups = [];
    shown.forEach((x, i) => {
      if (!groups.length || groups[groups.length - 1].name !== x.it.group) groups.push({ name: x.it.group, rows: [] });
      groups[groups.length - 1].rows.push([x, i]);
    });
    mount(list, shown.length ? groups.map(g => [
      h('div', { class: 'palette-group', role: 'presentation' }, g.name),
      g.rows.map(([x, i]) => {
        const lbl = x.it.label;
        const el = h('div', { class: 'palette-item', role: 'option', id: `${listId}-${i}`, 'aria-selected': String(i === sel),
          onMousemove: () => { if (sel !== i) { sel = i; mark(); } }, onClick: () => run(i) },
        icon(x.it.icon || 'arrowRight'), h('span', { class: 'trunc' }, marked(lbl, x.m.hits.filter(k => k < lbl.length))),
        x.it.meta ? h('span', { class: 'meta' }, x.it.meta) : null);
        return el;
      }),
    ]) : h('div', { class: 'empty compact' }, h('p', {}, 'No matches')));
    mark();
  };
  const mark = () => {
    list.querySelectorAll('.palette-item').forEach(el => el.setAttribute('aria-selected', String(el.id === `${listId}-${sel}`)));
    const cur = document.getElementById(`${listId}-${sel}`);
    if (cur) { inp.setAttribute('aria-activedescendant', cur.id); cur.scrollIntoView({ block: 'nearest' }); }
  };
  const run = i => { const x = shown[i]; if (!x) return; close(true); x.it.run(); };
  function close(ran) {
    root.remove(); openState = null;
    document.removeEventListener('keydown', keys, true);
    if (!ran && prevFocus && prevFocus.focus) prevFocus.focus();
  }
  const keys = e => {
    if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); close(); }
    else if (e.key === 'ArrowDown') { e.preventDefault(); sel = Math.min(shown.length - 1, sel + 1); mark(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); sel = Math.max(0, sel - 1); mark(); }
    else if (e.key === 'Enter') { e.preventDefault(); run(sel); }
    else if (e.key === 'Tab') e.preventDefault();
  };
  document.addEventListener('keydown', keys, true);
  inp.addEventListener('input', () => { sel = 0; draw(); });
  openState = { close };
  draw();

  // Entities load in the background; failures (e.g. permissions) are ignored.
  const kinds = [['routes', 'Routes', 'route', r => `/routes?edit=${encodeURIComponent(r.id)}`],
    ['policies', 'Policies', 'gauge', p => `/policies?edit=${encodeURIComponent(p.id)}`],
    ['plans', 'Plans', 'layers', p => `/plans?edit=${encodeURIComponent(p.id)}`],
    ['consumers', 'Consumers', 'users', c => `/consumers/${encodeURIComponent(c.id)}`]];
  const results = await Promise.allSettled(kinds.map(k => entities(k[0])));
  if (!openState) return;
  results.forEach((r, i) => {
    if (r.status !== 'fulfilled') return;
    const [, group, ic, path] = kinds[i];
    r.value.forEach(e => items.push({ group, label: e.name || e.id, sub: e.id, meta: e.id, icon: ic, run: () => { const [p, q] = path(e).split('?'); go(p, q ? Object.fromEntries(new URLSearchParams(q)) : undefined); } }));
  });
  draw();
}

/* -------------------------------------------------------------- help */
export const SHORTCUTS = [
  [['Ctrl', 'K'], 'Open command palette'],
  [['/'], 'Focus search'],
  [['?'], 'Show keyboard shortcuts'],
  [['g', 'o'], 'Go to Overview'],
  [['g', 'l'], 'Go to Live logs'],
  [['g', 'r'], 'Go to Routes'],
  [['g', 'p'], 'Go to Policies'],
  [['g', 'n'], 'Go to Plans'],
  [['g', 'c'], 'Go to Consumers'],
  [['g', 's'], 'Go to Simulator'],
  [['g', 'i'], 'Go to Integration'],
  [['g', ','], 'Go to Settings'],
  [['t'], 'Toggle theme'],
  [['Esc'], 'Close dialog / panel'],
];
export function showHelp() {
  const mac = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);
  modal({
    title: 'Keyboard shortcuts', icon: 'keyboard', size: 'lg',
    body: h('div', { class: 'shortcut-grid' }, SHORTCUTS.map(([keys, label]) => h('div', { class: 'shortcut-row' },
      h('span', {}, label),
      h('span', { class: 'keys' }, keys.map((k, i) => [i && keys[0] === 'g' ? 'then' : i ? '+' : null, h('kbd', {}, k === 'Ctrl' && mac ? '⌘' : k)]))))),
  });
}

/* -------------------------------------------------------------- keys */
const GO = { o: '/', l: '/logs', r: '/routes', p: '/policies', n: '/plans', c: '/consumers', s: '/simulator', i: '/integration', ',': '/settings', a: '/audit', m: '/limits', y: '/system' };
let bound = false;
function typing(t) {
  return t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName));
}
function bindKeys() {
  if (bound) return;
  bound = true;
  let gAt = 0;
  document.addEventListener('keydown', e => {
    if ((e.ctrlKey || e.metaKey) && !e.altKey && e.key.toLowerCase() === 'k') {
      if (!document.querySelector('.shell')) return;
      e.preventDefault(); openPalette(); return;
    }
    if (e.ctrlKey || e.metaKey || e.altKey || typing(e.target) || overlayOpen() || openState) return;
    if (!document.querySelector('.shell')) return;
    if (gAt && Date.now() - gAt < 1200 && GO[e.key]) { e.preventDefault(); gAt = 0; go(GO[e.key]); return; }
    gAt = 0;
    if (e.key === 'g') { gAt = Date.now(); return; }
    if (e.key === '/') {
      const s = document.querySelector('[data-search]');
      if (s) { e.preventDefault(); s.focus(); s.select && s.select(); }
      return;
    }
    if (e.key === '?') { e.preventDefault(); showHelp(); return; }
    if (e.key === 't') { theme.toggle(); }
  });
}
