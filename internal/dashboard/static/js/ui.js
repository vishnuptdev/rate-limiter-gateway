// Shared UI components: toasts, modals, confirm, drawers, tables, states, badges.
import { h, s, clear, mount, nextId } from './dom.js';
import { icon } from './icons.js';
import { DECISION_LABEL } from './format.js';

/* ------------------------------------------------------------- toasts */
export function toast(kind, title, desc, { timeout = 4200 } = {}) {
  const root = document.getElementById('toasts');
  const ic = { good: 'checkCircle', crit: 'alertCircle', warn: 'alert', info: 'info' }[kind] || 'info';
  const close = () => { el.classList.add('out'); setTimeout(() => el.remove(), 180); };
  const el = h('div', { class: `toast ${kind}`, role: kind === 'crit' ? 'alert' : 'status' },
    icon(ic, 'lead'),
    h('div', { class: 'grow' }, h('div', { class: 't' }, title), desc ? h('div', { class: 'd' }, desc) : null),
    h('button', { class: 'btn ghost xs icon-only close', 'aria-label': 'Dismiss notification', onClick: close }, icon('x', 'sm')));
  root.appendChild(el);
  while (root.children.length > 4) root.firstChild.remove();
  if (timeout) setTimeout(close, kind === 'crit' ? timeout * 1.6 : timeout);
  return close;
}
export const toastError = (err, title = 'Something went wrong') =>
  toast('crit', title, (err && (err.friendly || err.message)) || String(err));

/* ------------------------------------------------------------- overlays */
const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
const stack = [];

function trap(rootEl, onEscape) {
  const prev = document.activeElement;
  const key = e => {
    if (stack[stack.length - 1] !== rootEl) return;
    if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); onEscape(); return; }
    if (e.key !== 'Tab') return;
    const f = Array.from(rootEl.querySelectorAll(FOCUSABLE)).filter(x => x.offsetParent !== null);
    if (!f.length) return;
    const first = f[0], last = f[f.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  };
  document.addEventListener('keydown', key, true);
  stack.push(rootEl);
  return () => {
    document.removeEventListener('keydown', key, true);
    const i = stack.indexOf(rootEl);
    if (i >= 0) stack.splice(i, 1);
    if (prev && prev.focus && document.contains(prev)) prev.focus();
  };
}
export const overlayOpen = () => stack.length > 0;

function focusFirst(el) {
  requestAnimationFrame(() => {
    const auto = el.querySelector('[autofocus]') || el.querySelector('input:not([type=hidden]):not([disabled]), select, textarea') || el.querySelector(FOCUSABLE);
    if (auto) auto.focus();
  });
}

/** modal({title, desc, icon, iconKind, body, foot, size}) -> {close, root, body} */
export function modal({ title, desc, icon: ic, iconKind = '', body, foot, size = '', onClose, dismissable = true }) {
  const titleId = nextId('m');
  const descId = desc ? nextId('md') : null;
  let release;
  const close = (result) => {
    if (!root.isConnected) return;
    release();
    root.remove();
    if (onClose) onClose(result);
  };
  const bodyEl = h('div', { class: 'modal-body' }, body);
  const dialog = h('div', { class: `modal ${size}`, role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': titleId, 'aria-describedby': descId },
    h('div', { class: 'modal-head' },
      ic ? h('div', { class: `modal-icon ${iconKind}` }, icon(ic)) : null,
      h('div', { class: 'grow' }, h('h2', { id: titleId }, title), desc ? h('p', { class: 'desc', id: descId }, desc) : null),
      dismissable ? h('button', { class: 'btn ghost sm icon-only', 'aria-label': 'Close dialog', onClick: () => close() }, icon('x')) : null),
    bodyEl,
    foot ? h('div', { class: 'modal-foot' }, foot) : null);
  const root = h('div', { class: 'modal-root', onMousedown: e => { if (e.target === root && dismissable) close(); } }, dialog);
  document.getElementById('overlays').appendChild(root);
  release = trap(root, () => { if (dismissable) close(); });
  focusFirst(dialog);
  return { close, root, body: bodyEl, dialog };
}

/** confirm({title, message, confirmLabel, danger, typeToConfirm}) -> Promise<boolean> */
export function confirm({ title, message, confirmLabel = 'Confirm', danger = false, typeToConfirm = '' }) {
  return new Promise(resolve => {
    let ok = false;
    const typed = typeToConfirm ? h('input', { class: 'input mono', 'aria-label': `Type ${typeToConfirm} to confirm`, autocomplete: 'off', spellcheck: 'false' }) : null;
    const btn = h('button', { class: `btn ${danger ? 'danger' : 'primary'}`, disabled: !!typeToConfirm, onClick: () => { ok = true; m.close(); } }, confirmLabel);
    if (typed) typed.addEventListener('input', () => { btn.disabled = typed.value !== typeToConfirm; });
    const m = modal({
      title, icon: danger ? 'alert' : 'info', iconKind: danger ? 'crit' : '', size: 'sm',
      body: h('div', { class: 'stack tight' },
        typeof message === 'string' ? h('p', { class: 'subtle' }, message) : message,
        typed ? h('div', { class: 'field mt-8' }, h('label', {}, 'Type ', h('code', {}, typeToConfirm), ' to confirm'), typed) : null),
      foot: [h('button', { class: 'btn', onClick: () => m.close() }, 'Cancel'), btn],
      onClose: () => resolve(ok),
    });
    if (!typed) requestAnimationFrame(() => (danger ? m.dialog.querySelector('.modal-foot .btn') : btn).focus());
  });
}

/** Right-hand drawer. */
export function drawer({ title, sub, body, foot, wide = false, onClose }) {
  const titleId = nextId('d');
  let release;
  const close = () => {
    if (!root.isConnected) return;
    release(); root.remove(); if (onClose) onClose();
  };
  const bodyEl = h('div', { class: 'drawer-body' }, body);
  const panel = h('aside', { class: `drawer ${wide ? 'wide' : ''}`, role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': titleId },
    h('div', { class: 'drawer-head' },
      h('div', { class: 'grow' }, h('h2', { id: titleId, class: 'trunc' }, title), sub ? h('div', { class: 'xs muted trunc' }, sub) : null),
      h('button', { class: 'btn ghost sm icon-only', 'aria-label': 'Close panel', onClick: close }, icon('x'))),
    bodyEl,
    foot ? h('div', { class: 'drawer-foot' }, foot) : null);
  const root = h('div', { class: 'drawer-root', onMousedown: e => { if (e.target === root) close(); } }, panel);
  document.getElementById('overlays').appendChild(root);
  release = trap(root, close);
  focusFirst(panel);
  return { close, body: bodyEl, panel };
}

/* ------------------------------------------------------------- clipboard */
export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const ta = h('textarea', { class: 'sr-only', readOnly: true }, text);
    document.body.appendChild(ta);
    ta.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch { ok = false; }
    ta.remove();
    return ok;
  }
}

export function copyButton(getText, { label = 'Copy', size = 'sm', iconOnly = false, cls = '' } = {}) {
  const lbl = h('span', {}, label);
  const ic = h('span', { class: 'row' }, icon('copy', 'sm'));
  const b = h('button', { type: 'button', class: `btn ${size} ${iconOnly ? 'icon-only' : ''} ${cls}`, 'aria-label': iconOnly ? label : null, title: iconOnly ? label : null },
    ic, iconOnly ? null : lbl);
  b.addEventListener('click', async () => {
    const ok = await copyText(typeof getText === 'function' ? getText() : getText);
    mount(ic, icon(ok ? 'check' : 'x', 'sm'));
    if (!iconOnly) lbl.textContent = ok ? 'Copied' : 'Copy failed';
    setTimeout(() => { mount(ic, icon('copy', 'sm')); lbl.textContent = label; }, 1600);
  });
  return b;
}

/** Copy-once secret modal (API keys / tokens). */
export function secretModal({ title, secret, note, extra }) {
  return new Promise(resolve => {
    const ack = h('input', { type: 'checkbox' });
    const done = h('button', { class: 'btn primary', disabled: true, onClick: () => m.close() }, 'Done');
    ack.addEventListener('change', () => { done.disabled = !ack.checked; });
    const m = modal({
      title, icon: 'key', iconKind: 'good', dismissable: false,
      desc: 'This is the only time the full secret is shown. RateGuard stores only a hash.',
      body: h('div', { class: 'stack' },
        h('div', { class: 'secret-box' }, h('span', { class: 'grow' }, secret), copyButton(secret, { cls: 'primary' })),
        note ? h('div', { class: 'callout warn' }, icon('alert'), h('div', {}, note)) : null,
        extra || null,
        h('label', { class: 'check' }, ack, h('span', {}, 'I’ve copied this secret and stored it somewhere safe.'))),
      foot: done,
      onClose: () => resolve(),
    });
  });
}

/* ------------------------------------------------------------- states */
export function emptyState({ icon: ic = 'inbox', title, text, action, compact = false }) {
  return h('div', { class: `empty ${compact ? 'compact' : ''}` },
    h('div', { class: 'empty-icon' }, icon(ic)),
    h('h3', {}, title),
    text ? h('p', {}, text) : null,
    action ? h('div', { class: 'row' }, action) : null);
}

export function errorState(err, retry) {
  const forbidden = err && err.status === 403;
  return h('div', { class: 'empty error-state' },
    h('div', { class: 'empty-icon' }, icon(forbidden ? 'lock' : 'alertCircle')),
    h('h3', {}, forbidden ? 'You don’t have access to this' : 'Couldn’t load this data'),
    h('p', {}, forbidden ? 'Your role doesn’t include this area. Ask an admin if you need access.' : ((err && (err.friendly || err.message)) || 'Unknown error')),
    retry && !forbidden ? h('div', { class: 'row' }, h('button', { class: 'btn', onClick: retry }, icon('refresh', 'sm'), 'Try again')) : null);
}

export function skeletonRows(n = 5, cols = 4) {
  return h('div', { class: 'stack tight card-body', 'aria-busy': 'true', 'aria-label': 'Loading' },
    Array.from({ length: n }, (_, i) => h('div', { class: 'row gap-16' },
      Array.from({ length: cols }, (_, j) => h('div', { class: 'skel line', style: { width: `${[34, 18, 14, 22, 12][(i + j) % 5] + (j === 0 ? 10 : 0)}%` } })))));
}

export function skeletonCard(height = 220) {
  return h('div', { class: 'card card-body', 'aria-busy': 'true' },
    h('div', { class: 'skel title' }),
    h('div', { class: 'skel block mt-16', style: { height: height + 'px' } }));
}

/** Render async data into `el` with loading / error / content states. */
export async function load(el, fetcher, render, { skeleton } = {}) {
  mount(el, skeleton || skeletonRows());
  try {
    const data = await fetcher();
    mount(el, render(data));
    return data;
  } catch (e) {
    if (e.name === 'AbortError') return;
    mount(el, errorState(e, () => load(el, fetcher, render, { skeleton })));
    return undefined;
  }
}

/* ------------------------------------------------------------- bits */
export const badge = (text, kind = '', ic = null, extra = '') => h('span', { class: `badge ${kind} ${extra}`.trim() }, ic ? icon(ic) : null, text);

const DECISION_KIND = { allowed: ['good', 'check'], limited: ['serious', 'ban'], shadow_limited: ['warn', 'eye'], unauthorized: ['crit', 'lock'], no_route: ['', 'x'], error: ['crit', 'alert'] };
export function decisionBadge(d) {
  const [k, ic] = DECISION_KIND[d] || ['', 'info'];
  return badge(DECISION_LABEL[d] || d || '—', k, ic);
}

export function statusCode(st) {
  const cls = st === 429 ? 's429' : st >= 500 ? 's5' : st >= 400 ? 's4' : st >= 300 ? 's3' : 's2';
  return h('span', { class: `status-code ${cls}` }, String(st || '—'));
}

export function modeBadge(mode) {
  return mode === 'shadow' ? badge('Shadow', 'warn', 'eye') : badge('Enforce', 'accent', 'shield');
}

export function enabledBadge(on, onText = 'Enabled', offText = 'Disabled') {
  return on ? badge(onText, 'good', 'check') : badge(offText, '', 'minus');
}

export function roleBadge(role) {
  return badge(role, role === 'admin' ? 'accent' : role === 'editor' ? 'info' : '', null, 'square');
}

export function seg(options, value, onChange, { label = '', size = '' } = {}) {
  const el = h('div', { class: `seg ${size}`, role: 'group', 'aria-label': label });
  const btns = options.map(o => {
    const b = h('button', { type: 'button', 'aria-pressed': String(o.value === value), onClick: () => set(o.value, true) }, o.label);
    b.dataset.v = o.value;
    return b;
  });
  function set(v, fire) {
    value = v;
    btns.forEach(b => b.setAttribute('aria-pressed', String(b.dataset.v === String(v))));
    if (fire) onChange(v);
  }
  mount(el, btns);
  el.setValue = v => set(v, false);
  return el;
}

/** tabs([{id,label,count}], active, onChange) — ARIA tablist with arrow-key nav. */
export function tabs(items, active, onChange) {
  const el = h('div', { class: 'tabs', role: 'tablist' });
  const btns = items.map(it => h('button', {
    class: 'tab', role: 'tab', type: 'button', id: 'tab-' + it.id,
    'aria-selected': String(it.id === active), tabindex: it.id === active ? '0' : '-1',
    onClick: () => select(it.id),
  }, it.icon ? icon(it.icon, 'sm') : null, it.label, it.count != null ? h('span', { class: 'count' }, String(it.count)) : null));
  btns.forEach((b, i) => { b.dataset.id = items[i].id; });
  function select(id) {
    btns.forEach(b => { const on = b.dataset.id === id; b.setAttribute('aria-selected', String(on)); b.tabIndex = on ? 0 : -1; });
    onChange(id);
  }
  el.addEventListener('keydown', e => {
    if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
    const i = btns.indexOf(document.activeElement);
    if (i < 0) return;
    const n = btns[(i + (e.key === 'ArrowRight' ? 1 : btns.length - 1)) % btns.length];
    n.focus(); select(n.dataset.id);
  });
  mount(el, btns);
  return el;
}

export function pageHead({ title, lede, actions }) {
  return h('div', { class: 'page-head' },
    h('div', { class: 'grow' }, h('h1', {}, title), lede ? h('p', { class: 'lede' }, lede) : null),
    actions ? h('div', { class: 'page-actions' }, actions) : null);
}

export function card({ title, desc, actions, body, flush = false, cls = '', headCls = '' }) {
  return h('section', { class: `card ${cls}` },
    title ? h('div', { class: `card-head ${headCls}` },
      h('div', { class: 'grow' }, h('h2', {}, title), desc ? h('div', { class: 'desc' }, desc) : null),
      actions ? h('div', { class: 'row wrap' }, actions) : null) : null,
    h('div', { class: flush ? 'card-body flush' : 'card-body' }, body));
}

export function readonlyBanner(text = 'You have read-only access. Ask an editor or admin to make changes.') {
  return h('div', { class: 'readonly-banner' }, icon('lock', 'sm'), text);
}

/** Run an async action with the button in a busy state. */
export async function busy(btn, fn) {
  const prev = Array.from(btn.childNodes);
  btn.disabled = true;
  btn.setAttribute('aria-busy', 'true');
  mount(btn, h('span', { class: 'spinner' }), ...prev.filter(n => n.nodeType === 3 || n.tagName === 'SPAN'));
  try { return await fn(); } finally {
    btn.disabled = false;
    btn.removeAttribute('aria-busy');
    mount(btn, prev);
  }
}

/* ------------------------------------------------------------- tables */
/**
 * table({columns:[{key,label,render,sort,align,cls,hide}], rows, onRow, empty, sortKey, sortDir, rowClass})
 * Client-side sortable; rows are keyboard-activatable when onRow is set.
 */
export function table({ columns, rows, onRow, empty, sortKey = null, sortDir = 'asc', dense = false, rowClass, caption }) {
  const wrap = h('div', { class: 'table-wrap' });
  let key = sortKey, dir = sortDir;
  const draw = () => {
    if (!rows.length) { mount(wrap, empty || emptyState({ title: 'Nothing here yet', compact: true })); return; }
    let data = rows.slice();
    const col = columns.find(c => c.key === key);
    if (col) {
      const val = col.sort === true || !col.sort ? (r => r[col.key]) : col.sort;
      data.sort((a, b) => {
        const x = val(a), y = val(b);
        const c = typeof x === 'number' && typeof y === 'number' ? x - y : String(x ?? '').localeCompare(String(y ?? ''), undefined, { numeric: true });
        return dir === 'asc' ? c : -c;
      });
    }
    const thead = h('thead', {}, h('tr', {}, columns.map(c => {
      const cls = [c.align === 'right' ? 'num' : '', c.cls || '', c.hide ? `hide-${c.hide}` : ''].join(' ');
      if (!c.sort) return h('th', { class: cls, scope: 'col' }, c.label || h('span', { class: 'sr-only' }, c.srLabel || 'Actions'));
      const active = c.key === key;
      return h('th', { class: cls, scope: 'col', 'aria-sort': active ? (dir === 'asc' ? 'ascending' : 'descending') : 'none' },
        h('button', { class: 'sort', type: 'button', onClick: () => { if (key === c.key) dir = dir === 'asc' ? 'desc' : 'asc'; else { key = c.key; dir = c.defaultDir || 'asc'; } draw(); } },
          c.label, icon(active ? (dir === 'asc' ? 'arrowUp' : 'arrowDown') : 'sort')));
    })));
    const tbody = h('tbody', {}, data.map(r => {
      const tr = h('tr', { class: [onRow ? 'clickable' : '', rowClass ? rowClass(r) : ''].join(' ') },
        columns.map(c => h('td', { class: [c.align === 'right' ? 'num' : '', c.cls || '', c.hide ? `hide-${c.hide}` : ''].join(' ') },
          c.render ? c.render(r) : (r[c.key] ?? '—'))));
      if (onRow) {
        tr.tabIndex = 0;
        tr.addEventListener('click', e => { if (!e.target.closest('button, a, input, select, label')) onRow(r, e); });
        tr.addEventListener('keydown', e => { if (e.key === 'Enter' && e.target === tr) onRow(r, e); });
      }
      return tr;
    }));
    mount(wrap, h('table', { class: `table ${dense ? 'dense' : ''}` }, caption ? h('caption', { class: 'sr-only' }, caption) : null, thead, tbody));
  };
  draw();
  wrap.update = newRows => { rows = newRows; draw(); };
  return wrap;
}

/* ------------------------------------------------------------- menus */
export function menuButton(trigger, items) {
  let open = null;
  const closeMenu = () => {
    if (!open) return;
    open.remove(); open = null;
    trigger.setAttribute('aria-expanded', 'false');
    document.removeEventListener('mousedown', outside, true);
    document.removeEventListener('keydown', keys, true);
  };
  const outside = e => { if (open && !open.contains(e.target) && !trigger.contains(e.target)) closeMenu(); };
  const keys = e => {
    if (!open) return;
    const its = Array.from(open.querySelectorAll('.menu-item'));
    const i = its.indexOf(document.activeElement);
    if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); closeMenu(); trigger.focus(); }
    else if (e.key === 'ArrowDown') { e.preventDefault(); its[(i + 1) % its.length].focus(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); its[(i - 1 + its.length) % its.length].focus(); }
    else if (e.key === 'Tab') closeMenu();
  };
  trigger.setAttribute('aria-haspopup', 'menu');
  trigger.setAttribute('aria-expanded', 'false');
  trigger.addEventListener('click', () => {
    if (open) { closeMenu(); return; }
    const list = typeof items === 'function' ? items() : items;
    open = h('div', { class: 'menu', role: 'menu' }, list.map(it => {
      if (it === '-') return h('div', { class: 'menu-sep', role: 'separator' });
      if (it.header) return h('div', { class: 'menu-head' }, it.header);
      return h('button', { class: `menu-item ${it.danger ? 'danger' : ''}`, role: 'menuitem', type: 'button', onClick: () => { closeMenu(); it.onClick(); } },
        it.icon ? icon(it.icon) : null, it.label);
    }));
    document.body.appendChild(open);
    const r = trigger.getBoundingClientRect();
    const mw = Math.max(200, open.offsetWidth);
    open.style.top = `${r.bottom + window.scrollY + 6}px`;
    open.style.left = `${Math.max(8, Math.min(r.right - mw, window.innerWidth - mw - 8)) + window.scrollX}px`;
    trigger.setAttribute('aria-expanded', 'true');
    document.addEventListener('mousedown', outside, true);
    document.addEventListener('keydown', keys, true);
    const first = open.querySelector('.menu-item');
    if (first) first.focus();
  });
  return trigger;
}

/* ------------------------------------------------------------- code */
/** Very small highlighter: comments + strings. Builds DOM, never HTML. */
export function codeBlock(code, { title, lang } = {}) {
  const pre = h('pre', {}, h('code', { class: lang ? 'lang-' + lang : '' }, highlight(code, lang)));
  return h('div', { class: 'code-block' },
    title ? h('div', { class: 'code-head' }, h('span', {}, title), copyButton(code, { size: 'xs' })) : copyButton(code, { size: 'xs', cls: 'copy' }),
    pre);
}

function highlight(code, lang) {
  const out = [];
  const commentRe = lang === 'python' || lang === 'yaml' || lang === 'bash' || lang === 'nginx' ? /#[^\n]*/y : /\/\/[^\n]*/y;
  let i = 0, buf = '';
  const flush = () => { if (buf) { out.push(buf); buf = ''; } };
  while (i < code.length) {
    const ch = code[i];
    commentRe.lastIndex = i;
    const cm = (ch === '#' || ch === '/') ? commentRe.exec(code) : null;
    if (cm && (i === 0 || /[\s;({,]/.test(code[i - 1]))) { flush(); out.push(h('span', { class: 'tok-c' }, cm[0])); i += cm[0].length; continue; }
    if (ch === '"' || ch === "'" || ch === '`') {
      const j = code.indexOf(ch, i + 1);
      const nl = code.indexOf('\n', i + 1);
      if (j > 0 && (ch === '`' || nl === -1 || j < nl)) { flush(); out.push(h('span', { class: 'tok-s' }, code.slice(i, j + 1))); i = j + 1; continue; }
    }
    buf += ch; i++;
  }
  flush();
  return out;
}

export { s, clear };
