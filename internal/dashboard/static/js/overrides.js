// Per-policy limit override editor (used by Plans and Consumers).
import { h } from './dom.js';
import { icon } from './icons.js';
import * as fmt from './format.js';
import { input } from './forms.js';

/**
 * overridesEditor(policies, overrides, {inherited}) -> element with .value()
 * inherited: optional map policyId -> {limit, window, burst, from} shown as placeholder.
 */
export function overridesEditor(policies, overrides = {}, { inherited = {}, disabled = false } = {}) {
  const rows = [];
  const showAllBtn = h('button', { type: 'button', class: 'btn xs ghost' });
  let showAll = false;
  const tbody = h('tbody');
  const el = h('div', { class: 'stack tight', dataset: { field: 'overrides' } },
    h('div', { class: 'table-wrap card' }, h('table', { class: 'table dense' },
      h('thead', {}, h('tr', {},
        h('th', { scope: 'col' }, 'Policy'), h('th', { scope: 'col' }, 'Base'),
        h('th', { scope: 'col' }, 'Limit'), h('th', { scope: 'col' }, 'Window'), h('th', { scope: 'col' }, 'Burst'))),
      tbody)),
    h('div', { class: 'row between' }, h('span', { class: 'hint' }, 'Empty fields inherit. Overrides apply to every route the policy runs on.'), showAllBtn));

  policies.forEach(p => {
    const o = overrides[p.id] || {};
    const inh = inherited[p.id];
    const ph = (k, f) => (inh && inh[k] ? f(inh[k]) : '');
    const limit = input({ value: o.limit ? String(o.limit) : '', type: 'number', min: '1', placeholder: ph('limit', String) || String(p.limit), 'aria-label': `${p.name} limit override`, cls: 'sm', disabled });
    const win = input({ value: o.window ? fmt.goDur(o.window) : '', placeholder: ph('window', fmt.goDur) || fmt.goDur(p.window), mono: true, 'aria-label': `${p.name} window override`, cls: 'sm', disabled: disabled || p.algorithm === 'concurrency' });
    const burst = input({ value: o.burst ? String(o.burst) : '', type: 'number', min: '0', placeholder: fmt.BURSTY.includes(p.algorithm) ? (ph('burst', String) || String(p.burst || p.limit)) : '—', 'aria-label': `${p.name} burst override`, cls: 'sm', disabled: disabled || !fmt.BURSTY.includes(p.algorithm) });
    [limit, win, burst].forEach(i => { i.style.minWidth = '84px'; });
    const tr = h('tr', {},
      h('td', {}, h('div', { class: 'cell-title' }, p.name), h('div', { class: 'cell-sub mono' }, p.id)),
      h('td', { class: 'small nowrap' }, fmt.policySummary(p), inh && inh.from ? h('div', { class: 'cell-sub' }, 'via ', inh.from) : null),
      h('td', { dataset: { field: `overrides.${p.id}.limit` } }, limit),
      h('td', { dataset: { field: `overrides.${p.id}.window` } }, win),
      h('td', { dataset: { field: `overrides.${p.id}.burst` } }, burst));
    const active = () => !!(limit.value || win.value || burst.value);
    rows.push({ p, limit, win, burst, tr, active });
    tbody.appendChild(tr);
  });
  const paint = () => {
    const anyActive = rows.some(r => r.active());
    rows.forEach(r => { r.tr.classList.toggle('hidden', !showAll && anyActive && !r.active()); r.tr.classList.toggle('active', r.active()); });
    showAllBtn.classList.toggle('hidden', !anyActive || rows.every(r => r.active()));
    showAllBtn.replaceChildren(icon(showAll ? 'chevronUp' : 'chevronDown', 'sm'), showAll ? 'Show overridden only' : `Show all ${rows.length} policies`);
  };
  showAllBtn.addEventListener('click', () => { showAll = !showAll; paint(); });
  paint();
  if (!policies.length) el.replaceChildren(h('div', { class: 'hint' }, 'Create a policy first — overrides change its numbers for this tier.'));
  el.value = () => {
    const out = {};
    rows.forEach(r => {
      const o = {};
      const l = parseInt(r.limit.value, 10), b = parseInt(r.burst.value, 10), w = r.win.value.trim();
      if (l) o.limit = l;
      if (w) o.window = w;
      if (b) o.burst = b;
      if (Object.keys(o).length) out[r.p.id] = o;
    });
    return out;
  };
  return el;
}

/** Compact read-only summary of overrides: "API default 600/min → 1,200/min". */
export function overrideList(policies, overrides = {}) {
  const ids = Object.keys(overrides || {});
  if (!ids.length) return h('div', { class: 'small muted' }, 'No overrides — policy defaults apply.');
  return h('ul', { class: 'list-reset ov-list' }, ids.map(id => {
    const p = policies.find(x => x.id === id);
    const o = overrides[id];
    const eff = p ? { ...p, limit: o.limit || p.limit, window: o.window || p.window } : null;
    return h('li', { class: 'ov-item' },
      h('div', { class: 'small trunc' }, p ? p.name : id),
      h('div', { class: 'row small gap-4' },
        p ? h('span', { class: 'muted tnum nowrap' }, fmt.policySummary(p)) : null,
        icon('arrowRight', 'sm'),
        h('strong', { class: 'tnum nowrap' }, eff ? fmt.policySummary(eff) : JSON.stringify(o)),
        o.burst ? h('span', { class: 'xs muted nowrap' }, `· ${fmt.burstLabel(p ? p.algorithm : '')} ${fmt.int(o.burst)}`) : null));
  }));
}
