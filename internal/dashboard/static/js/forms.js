// Form building blocks + server validation (422) mapping.
import { h, $$, nextId, mount } from './dom.js';
import { icon } from './icons.js';

/** field({label, name, hint, optional, control, full}) — wrapper carrying data-field for problem mapping. */
export function field({ label, name, hint, optional = false, control, full = false, cls = '' }) {
  const id = control.id || nextId('f');
  if (!control.id && control.tagName && /^(INPUT|SELECT|TEXTAREA)$/.test(control.tagName)) control.id = id;
  const hintId = hint ? nextId('h') : null;
  if (hintId && control.setAttribute) control.setAttribute('aria-describedby', hintId);
  const isNative = control.tagName && /^(INPUT|SELECT|TEXTAREA)$/.test(control.tagName);
  return h('div', { class: `field ${full ? 'full' : ''} ${cls}`.trim(), dataset: { field: name || '' } },
    label ? (isNative ? h('label', { for: control.id }, label, optional ? h('span', { class: 'opt' }, 'optional') : null)
      : h('div', { class: 'field-label', id: id + '-l' }, label, optional ? h('span', { class: 'opt' }, 'optional') : null)) : null,
    control,
    hint ? h('div', { class: 'hint', id: hintId }, hint) : null);
}

export function input(props = {}) {
  return h('input', { class: `input ${props.mono ? 'mono' : ''} ${props.cls || ''}`.trim(), type: 'text', autocomplete: 'off', ...strip(props, ['mono', 'cls']) });
}

export function textarea(props = {}) {
  const { value = '', ...rest } = props;
  const t = h('textarea', { class: `textarea ${props.code ? 'code' : ''}`, spellcheck: 'false', ...strip(rest, ['code']) });
  t.value = value;
  return t;
}

/** select({options:[{value,label}|string], value}) */
export function select(props = {}) {
  const { options = [], value, ...rest } = props;
  const el = h('select', { class: `select ${props.cls || ''}`.trim(), ...strip(rest, ['cls']) },
    options.map(o => {
      const v = typeof o === 'string' ? o : o.value;
      const l = typeof o === 'string' ? o : o.label;
      return h('option', { value: v, disabled: o.disabled || false }, l);
    }));
  if (value !== undefined) el.value = value;
  return el;
}

export function toggle({ label, desc, checked = false, name, disabled = false, onChange }) {
  const inp = h('input', { type: 'checkbox', role: 'switch', checked, name, disabled });
  if (onChange) inp.addEventListener('change', () => onChange(inp.checked));
  const el = h('label', { class: 'switch', dataset: { field: name || '' } }, inp, h('span', { class: 'track', 'aria-hidden': 'true' }),
    h('span', {}, h('span', { class: 't' }, label), desc ? h('span', { class: 'd muted small' }, ' — ', desc) : null));
  el.input = inp;
  return el;
}

export function checkbox({ label, desc, checked = false, name, disabled = false }) {
  const inp = h('input', { type: 'checkbox', checked, name, disabled });
  const el = h('label', { class: 'check', dataset: { field: name || '' } }, inp,
    h('span', {}, h('span', { class: 't' }, label), desc ? h('span', { class: 'd' }, h('br'), desc) : null));
  el.input = inp;
  return el;
}

function strip(o, keys) { const r = { ...o }; keys.forEach(k => delete r[k]); return r; }

/* ----------------------------------------------------- problem mapping */
export function clearProblems(root) {
  $$('.field-error', root).forEach(e => e.remove());
  $$('.invalid', root).forEach(e => e.classList.remove('invalid'));
  $$('[aria-invalid]', root).forEach(e => e.removeAttribute('aria-invalid'));
  const top = root.querySelector(':scope > .form-error, .form-error[data-top]');
  if (top) top.remove();
}

/** "policies[0].match.path_prefix" -> candidates ["match.path_prefix", "path_prefix"] */
export function fieldCandidates(f) {
  let rest = String(f || '').replace(/^(policies|routes|plans|consumers|users|tokens)\[\d+\]\.?/, '').replace(/^settings\./, '');
  const out = [];
  if (rest) out.push(rest);
  const noIdx = rest.replace(/\[\d+\]/g, '');
  if (noIdx !== rest) out.push(noIdx);
  const last = noIdx.split('.').pop();
  if (last && !out.includes(last)) out.push(last);
  return out;
}

/** Show 422 problems inline. Returns problems that couldn't be placed. */
export function applyProblems(root, problems) {
  clearProblems(root);
  const leftovers = [];
  let firstEl = null;
  for (const p of problems || []) {
    let target = null;
    for (const c of fieldCandidates(p.field)) {
      target = root.querySelector(`[data-field="${CSS.escape(c)}"]`);
      if (target) break;
    }
    if (!target) { leftovers.push(p); continue; }
    target.classList.add('invalid');
    const ctl = target.matches('input,select,textarea') ? target : target.querySelector('input,select,textarea');
    if (ctl) ctl.setAttribute('aria-invalid', 'true');
    const errId = nextId('err');
    if (ctl) ctl.setAttribute('aria-errormessage', errId);
    target.appendChild(h('div', { class: 'field-error', id: errId, role: 'alert' }, icon('alertCircle'), h('span', {}, p.message)));
    if (!firstEl) firstEl = ctl || target;
  }
  if (firstEl && firstEl.focus) firstEl.focus({ preventScroll: false });
  return leftovers;
}

/** Display an ApiError on a form: inline problems + a summary box for the rest. */
export function showFormError(root, err) {
  const left = err && err.status === 422 ? applyProblems(root, err.problems) : (clearProblems(root), []);
  const msg = err && err.status === 422
    ? (left.length ? 'Some settings need attention:' : (err.problems.length ? null : err.message))
    : (err && (err.friendly || err.message)) || 'Request failed';
  if (!msg && !left.length) return;
  const box = h('div', { class: 'form-error', role: 'alert', dataset: { top: '1' } }, icon('alertCircle'),
    h('div', {}, msg || '', left.length ? h('ul', {}, left.map(p => h('li', {}, p.field ? h('code', {}, p.field) : null, ' ', p.message))) : null));
  root.prepend(box);
  if (!(err && err.status === 422 && err.problems.length > left.length)) box.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
}

/* ----------------------------------------------------- composite editors */
/** Key/value list editor (headers, query, metadata). */
export function kvEditor(pairs = {}, { keyPh = 'Key', valPh = 'Value', name = '', disabled = false, addLabel = 'Add' } = {}) {
  const list = h('div', { class: 'kv-list' });
  const rows = [];
  const add = (k = '', v = '') => {
    const ki = input({ value: k, placeholder: keyPh, 'aria-label': keyPh, mono: true, disabled });
    const vi = input({ value: v, placeholder: valPh, 'aria-label': valPh, disabled });
    const row = h('div', { class: 'kv-row' }, ki, vi,
      h('button', { type: 'button', class: 'btn ghost sm icon-only', 'aria-label': 'Remove row', disabled, onClick: () => { row.remove(); rows.splice(rows.indexOf(r), 1); } }, icon('x', 'sm')));
    const r = { ki, vi, row };
    rows.push(r);
    list.appendChild(row);
    return r;
  };
  Object.entries(pairs || {}).forEach(([k, v]) => add(k, v));
  const addBtn = h('button', { type: 'button', class: 'btn sm ghost', disabled, onClick: () => add().ki.focus() }, icon('plus', 'sm'), addLabel);
  const el = h('div', { class: 'stack tight', dataset: { field: name } }, list, h('div', {}, addBtn));
  el.value = () => {
    const out = {};
    rows.forEach(r => { const k = r.ki.value.trim(); if (k) out[k] = r.vi.value; });
    return out;
  };
  return el;
}

/** Ordered multi-select of IDs (route policies, global policies). */
export function orderedPicker(all, selected = [], { name = '', disabled = false, emptyText = 'None selected', labelOf = x => x.name, metaOf = () => '' } = {}) {
  let sel = selected.filter(id => all.some(a => a.id === id)).concat(selected.filter(id => !all.some(a => a.id === id)));
  const listEl = h('div', { class: 'policy-order' });
  const addSel = select({ cls: 'sm', 'aria-label': 'Add item', disabled });
  const el = h('div', { class: 'stack tight', dataset: { field: name } }, listEl, h('div', { class: 'row' }, addSel));
  const draw = () => {
    mount(listEl, sel.length ? sel.map((id, i) => {
      const it = all.find(a => a.id === id);
      return h('div', { class: 'po-item' },
        h('span', { class: 'po-idx' }, String(i + 1)),
        h('div', { class: 'grow trunc' }, it ? labelOf(it) : h('span', { class: 'muted' }, id + ' (missing)'), ' ', h('span', { class: 'xs muted mono' }, it ? metaOf(it) : '')),
        h('button', { type: 'button', class: 'btn ghost xs icon-only', 'aria-label': 'Move up', disabled: disabled || i === 0, onClick: () => { [sel[i - 1], sel[i]] = [sel[i], sel[i - 1]]; draw(); } }, icon('chevronUp', 'sm')),
        h('button', { type: 'button', class: 'btn ghost xs icon-only', 'aria-label': 'Move down', disabled: disabled || i === sel.length - 1, onClick: () => { [sel[i + 1], sel[i]] = [sel[i], sel[i + 1]]; draw(); } }, icon('chevronDown', 'sm')),
        h('button', { type: 'button', class: 'btn ghost xs icon-only', 'aria-label': 'Remove', disabled, onClick: () => { sel.splice(i, 1); draw(); } }, icon('x', 'sm')));
    }) : h('div', { class: 'hint' }, emptyText));
    const avail = all.filter(a => !sel.includes(a.id));
    mount(addSel, h('option', { value: '' }, avail.length ? '+ Add…' : 'All added'), avail.map(a => h('option', { value: a.id }, labelOf(a))));
    addSel.disabled = disabled || !avail.length;
  };
  addSel.addEventListener('change', () => { if (addSel.value) { sel.push(addSel.value); draw(); } });
  draw();
  el.value = () => sel.slice();
  return el;
}

/** Comma/newline list textarea -> []string */
export function listValue(v) {
  return String(v || '').split(/[\n,]/).map(x => x.trim()).filter(Boolean);
}
