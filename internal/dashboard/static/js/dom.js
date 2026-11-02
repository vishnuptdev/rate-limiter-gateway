// Tiny DOM builder. Everything is created through the DOM API (never
// innerHTML), so user data can't inject markup and the strict CSP holds.

const SVG_NS = 'http://www.w3.org/2000/svg';
const ATTR_ONLY = new Set(['list', 'form', 'spellcheck', 'autocomplete', 'inputmode', 'enterkeyhint', 'autocapitalize', 'role']);

function apply(el, props) {
  if (!props) return;
  for (const [k, v] of Object.entries(props)) {
    if (v == null || v === false) continue;
    if (k === 'class' || k === 'className') {
      const cls = Array.isArray(v) ? v.filter(Boolean).join(' ') : v;
      if (cls) el.setAttribute('class', cls);
    } else if (k === 'style') {
      // CSSOM writes are allowed under style-src 'self'.
      for (const [p, sv] of Object.entries(v)) {
        if (sv == null) continue;
        if (p.startsWith('--')) el.style.setProperty(p, sv);
        else el.style[p] = sv;
      }
    } else if (k === 'dataset') {
      for (const [d, dv] of Object.entries(v)) if (dv != null) el.dataset[d] = dv;
    } else if (k.startsWith('on') && typeof v === 'function') {
      el.addEventListener(k.slice(2).toLowerCase(), v);
    } else if (k === 'ref' && typeof v === 'function') {
      v(el);
    } else if (k in el && !ATTR_ONLY.has(k) && !k.includes('-')) {
      el[k] = v === true && typeof el[k] === 'string' ? '' : v;
    } else {
      el.setAttribute(k, v === true ? '' : String(v));
    }
  }
}

function append(el, children) {
  for (const c of children) {
    if (c == null || c === false || c === true) continue;
    if (Array.isArray(c)) append(el, c);
    else if (c instanceof Node) el.appendChild(c);
    else el.appendChild(document.createTextNode(String(c)));
  }
}

function isProps(x) {
  return x && typeof x === 'object' && !(x instanceof Node) && !Array.isArray(x);
}

/** h('div', {class:'x', onClick}, ...children) */
export function h(tag, props, ...children) {
  if (!isProps(props)) { if (props !== undefined) children.unshift(props); props = null; }
  const el = document.createElement(tag);
  apply(el, props);
  append(el, children);
  return el;
}

/** s('path', {d:'...'}) — SVG elements; attributes are always set as attributes. */
export function s(tag, props, ...children) {
  if (!isProps(props)) { if (props !== undefined) children.unshift(props); props = null; }
  const el = document.createElementNS(SVG_NS, tag);
  if (props) {
    for (const [k, v] of Object.entries(props)) {
      if (v == null || v === false) continue;
      if (k === 'style') { for (const [p, sv] of Object.entries(v)) if (sv != null) el.style.setProperty(p.replace(/[A-Z]/g, m => '-' + m.toLowerCase()), sv); }
      else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v);
      else if (k === 'class') el.setAttribute('class', Array.isArray(v) ? v.filter(Boolean).join(' ') : v);
      else el.setAttribute(k, String(v));
    }
  }
  append(el, children);
  return el;
}

export function clear(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
  return el;
}

export function mount(el, ...children) {
  clear(el);
  append(el, children);
  return el;
}

export function frag(...children) {
  const f = document.createDocumentFragment();
  append(f, children);
  return f;
}

export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

let uid = 0;
export const nextId = (p = 'id') => `${p}-${++uid}`;

export function debounce(fn, ms = 200) {
  let t;
  return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}

/** A minimal reactive cell for simple page state. */
export function signal(value) {
  const subs = new Set();
  return {
    get: () => value,
    set(v) { value = v; subs.forEach(f => f(v)); },
    sub(f) { subs.add(f); return () => subs.delete(f); },
  };
}
