// Policies: list + rich editor (algorithm explainer visuals, mode, key_by builder).
import { h, s, mount, nextId } from '../dom.js';
import { icon } from '../icons.js';
import * as api from '../api.js';
import * as fmt from '../format.js';
import { can, entities, invalidate } from '../state.js';
import { pageHead, table, badge, enabledBadge, modeBadge, emptyState, load, menuButton, toast, readonlyBanner, seg } from '../ui.js';
import { field, input, textarea, toggle } from '../forms.js';
import { editorDrawer, confirmDelete, filterRows, searchBox, noMatches, sectionTitle } from '../crud.js';
import { go, replaceQuery } from '../router.js';

export const ALGOS = [
  { id: 'gcra', title: 'GCRA', desc: 'Evenly spaced requests — one every window ÷ limit — with a burst tolerance. O(1) state. Best default for APIs.' },
  { id: 'token_bucket', title: 'Token bucket', desc: 'Refills at limit per window; bursts up to the bucket size after idle periods. Classic and well understood.' },
  { id: 'sliding_window', title: 'Sliding window', desc: 'Exact: never more than limit in any trailing window. Memory grows with the limit.' },
  { id: 'sliding_window_counter', title: 'Sliding window counter', desc: 'Approximate sliding window in constant memory (Cloudflare-style). Ideal at high volume.' },
  { id: 'fixed_window', title: 'Fixed window', desc: 'At most limit per aligned window, e.g. per calendar minute or day. Simple quotas.' },
  { id: 'leaky_bucket', title: 'Leaky bucket', desc: 'Traffic shaping: requests over the steady rate wait in a queue (delayed, not rejected) until it is full. Protects fragile upstreams.' },
  { id: 'concurrency', title: 'Concurrency', desc: 'At most limit requests in flight at once. Slots free up when responses complete.' },
];

/** Tiny explanatory visual for each algorithm (pure SVG, theme-aware via CSS classes). */
export function algoViz(id) {
  const svg = s('svg', { class: 'viz', viewBox: '0 0 200 44', 'aria-hidden': 'true', preserveAspectRatio: 'xMidYMid meet' });
  const bar = (x, hgt, deny = false) => s('rect', { class: `v-bar ${deny ? 'deny' : ''}`, x, y: 38 - hgt, width: 8, height: hgt, rx: 2 });
  if (id === 'gcra') {
    // Evenly spaced emission slots; arrivals early within tolerance pass, too-early ones are denied.
    for (let i = 0; i < 7; i++) svg.appendChild(s('line', { class: 'v-line', x1: 16 + i * 28, x2: 16 + i * 28, y1: 4, y2: 40 }));
    [[16, false], [36, false], [44, false], [52, true], [72, false], [100, false], [128, false], [156, false], [178, false]].forEach(([x, deny]) => svg.appendChild(bar(x - 4, 20, deny)));
    return svg;
  }
  if (id === 'leaky_bucket') {
    // Bursty arrivals -> queue -> steady drip out.
    [[8, 26], [18, 14], [28, 30]].forEach(([x, hh]) => svg.appendChild(bar(x, hh)));
    svg.appendChild(s('path', { class: 'v-line', d: 'M44 22 L58 22' }));
    [0, 1, 2, 3].forEach(i => svg.appendChild(s('rect', { class: `v-slot ${i < 3 ? 'on' : ''}`, x: 62 + i * 20, y: 12, width: 16, height: 20, rx: 4 })));
    svg.appendChild(s('path', { class: 'v-line', d: 'M146 22 L156 22' }));
    [160, 172, 184].forEach(x => svg.appendChild(bar(x, 14)));
    return svg;
  }
  if (id === 'token_bucket') {
    const lvl = [30, 22, 14, 6, 0, 0, 6, 12, 18, 24, 30, 22, 14];
    svg.appendChild(s('path', { class: 'v-fill', d: 'M10,38 ' + lvl.map((v, i) => `L${10 + i * 14},${38 - v}`).join(' ') + ` L${10 + 12 * 14},38Z` }));
    svg.appendChild(s('path', { class: 'v-stroke', d: lvl.map((v, i) => `${i ? 'L' : 'M'}${10 + i * 14},${38 - v}`).join(' ') }));
    [0, 1, 2, 3].forEach(i => svg.appendChild(s('circle', { cx: 17 + i * 14, cy: 6, r: 2.5, class: 'v-bar' })));
    [4, 5].forEach(i => svg.appendChild(s('circle', { cx: 17 + i * 14, cy: 6, r: 2.5, class: 'v-bar deny' })));
  } else if (id === 'sliding_window') {
    svg.appendChild(s('rect', { class: 'v-win', x: 92, y: 4, width: 76, height: 36, rx: 5 }));
    [12, 26, 40, 58, 70, 98, 108, 120, 134, 146, 158].forEach((x, i) => svg.appendChild(bar(x, 12 + ((i * 7) % 14), i === 10)));
    svg.appendChild(s('path', { class: 'v-line', d: 'M60 22 L86 22' }));
  } else if (id === 'sliding_window_counter') {
    svg.appendChild(s('line', { class: 'v-line', x1: 100, x2: 100, y1: 2, y2: 42 }));
    svg.appendChild(s('rect', { class: 'v-win', x: 62, y: 4, width: 76, height: 36, rx: 5 }));
    svg.appendChild(s('rect', { class: 'v-bar', x: 30, y: 12, width: 50, height: 26, rx: 3 }));
    svg.appendChild(s('rect', { class: 'v-bar', x: 112, y: 22, width: 50, height: 16, rx: 3 }));
    const sh = s('rect', { x: 62, y: 12, width: 18, height: 26 });
    sh.style.fill = 'var(--surface)'; sh.style.fillOpacity = '0.45';
    svg.appendChild(sh);
  } else if (id === 'fixed_window') {
    [66, 132].forEach(x => svg.appendChild(s('line', { class: 'v-line', x1: x, x2: x, y1: 2, y2: 42 })));
    [[8, 4], [72, 6], [138, 3]].forEach(([x0, n], w) => {
      for (let i = 0; i < n; i++) svg.appendChild(bar(x0 + i * 10, 22, w === 1 && i >= 4));
    });
  } else {
    [0, 1, 2, 3].forEach(i => {
      const r = s('rect', { class: `v-slot ${i < 3 ? 'on' : ''}`, x: 10 + i * 30, y: 10, width: 24, height: 24, rx: 5 });
      svg.appendChild(r);
    });
    svg.appendChild(s('path', { class: 'v-line', d: 'M136 22 L156 22' }));
    svg.appendChild(s('rect', { class: 'v-bar deny', x: 162, y: 14, width: 16, height: 16, rx: 4 }));
  }
  return svg;
}

const KEY_PARTS = [
  { v: 'consumer', label: 'Consumer', ex: 'acme-corp', desc: 'Authenticated consumer (falls back to IP)' },
  { v: 'api_key', label: 'API key', ex: '3f9a1c0be2d84e71', desc: 'Hashed API key' },
  { v: 'ip', label: 'Client IP', ex: '203.0.113.7', desc: 'Honours trusted proxies' },
  { v: 'header:', label: 'Header…', ex: 'tenant-42', desc: 'Value of a request header' },
  { v: 'query:', label: 'Query param…', ex: 'abc', desc: 'Value of a query parameter' },
  { v: 'path', label: 'Path', ex: '/v1/orders', desc: 'Request path' },
  { v: 'method', label: 'Method', ex: 'POST', desc: 'HTTP method' },
  { v: 'route', label: 'Route', ex: 'orders-api', desc: 'Matched route ID' },
  { v: 'global', label: 'Global', ex: 'global', desc: 'One bucket shared by everyone' },
];
export function keyLabel(k) {
  if (k.startsWith('header:')) return `header ${k.slice(7)}`;
  if (k.startsWith('query:')) return `query ${k.slice(6)}`;
  const p = KEY_PARTS.find(x => x.v === k);
  return p ? p.label.toLowerCase() : k;
}
const keyPhrase = ks => ks.length ? 'per ' + ks.map(k => k === 'global' ? 'gateway (one shared bucket)' : keyLabel(k)).join(' + ') : '';

function keyByBuilder(initial, disabled) {
  let keys = (initial || []).slice();
  const chips = h('div', { class: 'chips' });
  const preview = h('div', { class: 'keyby-preview' });
  const custom = h('div', { class: 'row hidden' });
  const add = h('div', { class: 'chips' });
  const el = h('div', { class: 'stack tight', dataset: { field: 'key_by' } }, chips, add, custom, preview);
  const fire = () => el.dispatchEvent(new Event('change', { bubbles: true }));
  const draw = () => {
    mount(chips, keys.length ? keys.map((k, i) => h('span', { class: 'chip' }, k,
      h('button', { type: 'button', 'aria-label': `Remove ${k}`, disabled, onClick: () => { keys.splice(i, 1); draw(); fire(); } }, icon('x')))) : h('span', { class: 'hint' }, 'No key selected — pick at least one below.'));
    mount(add, KEY_PARTS.filter(p => p.v.endsWith(':') || !keys.includes(p.v)).map(p => h('button', { type: 'button', class: 'btn xs', title: p.desc, disabled, onClick: () => addPart(p) }, icon('plus', 'sm'), p.label)));
    const ex = keys.map(k => { const p = KEY_PARTS.find(x => x.v === k || (x.v.endsWith(':') && k.startsWith(x.v))); return p ? p.ex : '-'; });
    mount(preview, keys.length ? ['Bucket key: ', h('strong', {}, '<policy>:' + ex.join('|'))] : 'Bucket key: —');
  };
  const addPart = p => {
    if (!p.v.endsWith(':')) { keys.push(p.v); draw(); fire(); return; }
    const inp = input({ placeholder: p.v === 'header:' ? 'X-Tenant-ID' : 'tenant', mono: true, cls: 'sm', 'aria-label': p.v === 'header:' ? 'Header name' : 'Query parameter name' });
    const ok = h('button', { type: 'button', class: 'btn sm primary' }, 'Add');
    const done = () => { const n = inp.value.trim(); if (n) { keys.push(p.v + n); draw(); fire(); } custom.classList.add('hidden'); };
    ok.addEventListener('click', done);
    inp.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); done(); } if (e.key === 'Escape') { e.stopPropagation(); custom.classList.add('hidden'); } });
    mount(custom, h('span', { class: 'mono small muted' }, p.v), inp, ok);
    custom.classList.remove('hidden');
    inp.focus();
  };
  draw();
  el.value = () => keys.slice();
  return el;
}

function optCards(options, value, onChange, { label, cls = '' }) {
  const wrap = h('div', { class: `opt-cards ${cls}`, role: 'radiogroup', 'aria-label': label });
  const cards = options.map(o => h('button', { type: 'button', class: 'opt-card', role: 'radio', 'aria-checked': String(o.id === value), tabindex: o.id === value ? '0' : '-1', onClick: () => set(o.id, true) },
    h('span', { class: 'check-mark', 'aria-hidden': 'true' }), o.viz || null, h('span', { class: 't' }, o.title), h('span', { class: 'd' }, o.desc)));
  cards.forEach((c, i) => { c.dataset.id = options[i].id; });
  function set(v, fire) {
    value = v;
    cards.forEach(c => { const on = c.dataset.id === v; c.setAttribute('aria-checked', String(on)); c.tabIndex = on ? 0 : -1; });
    if (fire) { onChange(v); wrap.dispatchEvent(new Event('change', { bubbles: true })); }
  }
  wrap.addEventListener('keydown', e => {
    const dir = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 }[e.key];
    if (!dir) return;
    e.preventDefault();
    const i = cards.findIndex(c => c.dataset.id === value);
    const n = cards[(i + dir + cards.length) % cards.length];
    set(n.dataset.id, true); n.focus();
  });
  mount(wrap, cards);
  wrap.value = () => value;
  return wrap;
}

function openEditor(existing, done, refs) {
  const isNew = !existing;
  const p = existing ? structuredClone(existing) : { name: '', algorithm: 'gcra', limit: 100, window: '1m0s', burst: 0, cost: 0, key_by: ['consumer'], mode: 'enforce', fail_mode: 'open', enabled: true, description: '' };
  const ro = !can('edit');
  const name = input({ value: p.name, placeholder: 'API default', autofocus: true });
  const id = input({ value: p.id || '', placeholder: 'auto-generated from name', mono: true, disabled: !isNew });
  const desc = textarea({ value: p.description || '', placeholder: 'What this policy protects and why', rows: 2 });
  desc.style.minHeight = '60px';
  let algo = p.algorithm;
  const algoCards = optCards(ALGOS.map(a => ({ ...a, viz: algoViz(a.id) })), algo, v => { algo = v; sync(); }, { label: 'Algorithm' });
  const limit = input({ value: String(p.limit || ''), type: 'number', min: '1', step: '1', inputmode: 'numeric' });
  const windowIn = input({ value: fmt.goDur(p.window) || '', placeholder: '1m', mono: true });
  const presets = h('div', { class: 'chips' }, ['1s', '10s', '1m', '1h', '24h'].map(v => h('button', { type: 'button', class: 'btn xs', disabled: ro, onClick: () => { windowIn.value = v; windowIn.dispatchEvent(new Event('input', { bubbles: true })); } }, v)));
  const burst = input({ value: p.burst ? String(p.burst) : '', type: 'number', min: '0', step: '1', placeholder: 'same as limit' });
  const cost = input({ value: p.cost ? String(p.cost) : '', type: 'number', min: '0', step: '1', placeholder: '1' });
  const keyBy = keyByBuilder(p.key_by, ro);
  let mode = p.mode || 'enforce';
  const modeCards = optCards([
    { id: 'enforce', title: 'Enforce', desc: 'Requests over the limit get 429 Too Many Requests with Retry-After.' },
    { id: 'shadow', title: 'Shadow (dry run)', desc: 'Never blocks. Over-limit requests are logged as “shadow limited” so you can tune safely.' },
  ], mode, v => { mode = v; sync(); }, { label: 'Mode', cls: 'mode-cards' });
  let failMode = p.fail_mode || 'open';
  const failSeg = seg([{ value: 'open', label: 'Fail open' }, { value: 'closed', label: 'Fail closed' }], failMode, v => { failMode = v; sync(); }, { label: 'Backend failure behaviour' });
  const failHint = h('div', { class: 'hint' });
  const enabled = toggle({ label: 'Enabled', checked: p.enabled, name: 'enabled' });
  const summary = h('div', { class: 'summary-callout', 'aria-live': 'polite' });
  const windowField = field({ label: 'Window', name: 'window', control: h('div', { class: 'stack tight' }, windowIn, presets), hint: 'Go duration: 500ms, 1s, 1m, 1h, 24h.' });
  const burstField = field({ label: 'Burst (bucket size)', name: 'burst', control: burst, optional: true, hint: 'Max requests allowed at once after idle. Empty = limit.' });
  const burstLabel = burstField.querySelector('label').firstChild;
  const burstHint = burstField.querySelector('.hint');
  const costField = field({ label: 'Cost per request', name: 'cost', control: cost, optional: true, hint: 'Units consumed per request. Default 1.' });
  const refsNote = refs && refs.length ? h('div', { class: 'callout info' }, icon('info'), h('div', {}, 'Used by ', refs.map((r, i) => [i ? ', ' : '', h('strong', {}, r)]), '. Changes apply immediately to live traffic.')) : null;

  const value = () => ({
    ...(existing || {}),
    ...(isNew && id.value.trim() ? { id: id.value.trim() } : {}),
    name: name.value.trim(), description: desc.value.trim() || undefined,
    algorithm: algo, limit: parseInt(limit.value, 10) || 0,
    window: algo === 'concurrency' ? '0s' : (windowIn.value.trim() || ''),
    burst: fmt.BURSTY.includes(algo) ? (parseInt(burst.value, 10) || 0) : 0,
    cost: parseInt(cost.value, 10) || 0,
    key_by: keyBy.value(), mode, fail_mode: failMode, enabled: enabled.input.checked,
  });

  function sync() {
    const v = value();
    burstField.classList.toggle('hidden', !fmt.BURSTY.includes(algo));
    burstLabel.textContent = algo === 'leaky_bucket' ? 'Queue size' : algo === 'gcra' ? 'Burst tolerance' : 'Burst (bucket size)';
    burstHint.textContent = algo === 'leaky_bucket' ? 'Requests that may wait for a slot before new ones get 429. Empty = limit.' : algo === 'gcra' ? 'Extra requests allowed back-to-back before spacing is enforced. Empty = limit.' : 'Max requests allowed at once after idle. Empty = limit.';
    windowField.classList.toggle('hidden', algo === 'concurrency');
    const w = fmt.parseDuration(v.window);
    windowIn.classList.toggle('invalid', algo !== 'concurrency' && !!windowIn.value && isNaN(w));
    failHint.textContent = failMode === 'open'
      ? 'If the limiter backend (e.g. Redis) is unreachable, skip this policy and allow traffic.'
      : 'If the limiter backend is unreachable, reject with 503 limiter_unavailable.';
    const per = keyPhrase(v.key_by);
    const lim = fmt.int(v.limit || 0);
    let text;
    if (algo === 'concurrency') text = [`Allow at most `, h('strong', {}, lim), ` concurrent requests ${per}.`];
    else {
      const wp = isNaN(w) || !w ? '…' : fmt.windowPhrase(w);
      text = [`Allow `, h('strong', {}, `${lim} requests per ${wp}`), ` ${per}`];
      if (algo === 'token_bucket') text.push(`, refilling smoothly with bursts up to `, h('strong', {}, fmt.int(v.burst || v.limit || 0)));
      if (algo === 'gcra' && !isNaN(w) && v.limit) text.push(`, evenly spaced (one every `, h('strong', {}, fmt.ms(w / v.limit)), `) with a burst tolerance of `, h('strong', {}, fmt.int(v.burst || v.limit)));
      if (algo === 'leaky_bucket') text.push(` at a steady rate; up to `, h('strong', {}, fmt.int(v.burst || v.limit || 0)), ` excess requests are queued (delayed) instead of rejected`);
      if (algo === 'fixed_window') text.push(', resetting at each window boundary');
      if (algo === 'sliding_window_counter') text.push(' (approximate)');
      text.push('.');
    }
    if (v.cost > 1) text.push(` Each request costs ${v.cost}.`);
    text.push(mode === 'shadow' ? ' Over-limit requests are allowed but logged as shadow limited.' : algo === 'leaky_bucket' ? ' When the queue is full, requests get 429.' : ' Over-limit requests get 429.');
    mount(summary, icon('sparkles'), h('div', {}, text));
  }

  const form = h('form', { class: 'form', id: nextId('policy-form'), novalidate: true },
    ro ? readonlyBanner() : null,
    refsNote,
    summary,
    h('div', { class: 'form-section' },
      sectionTitle('Basics'),
      h('div', { class: 'form-grid' },
        field({ label: 'Name', name: 'name', control: name }),
        field({ label: 'ID', name: 'id', control: id, optional: isNew, hint: isNew ? 'Lowercase letters, digits, - and _. Permanent.' : 'IDs are permanent.' }),
        field({ label: 'Description', name: 'description', control: desc, optional: true, full: true })),
      enabled),
    h('div', { class: 'form-section' },
      sectionTitle('Algorithm', 'How requests are counted against the limit.'),
      field({ name: 'algorithm', control: algoCards })),
    h('div', { class: 'form-section' },
      sectionTitle('Limit'),
      h('div', { class: 'form-grid' },
        field({ label: 'Limit', name: 'limit', control: limit, hint: 'Requests per window (concurrency: max in flight).' }),
        windowField, burstField, costField)),
    h('div', { class: 'form-section' },
      sectionTitle('Key', 'Who gets their own bucket. Combine parts for composite keys, e.g. consumer + route.'),
      keyBy),
    h('div', { class: 'form-section' },
      sectionTitle('Mode'),
      field({ name: 'mode', control: modeCards }),
      field({ label: 'When the limiter backend fails', name: 'fail_mode', control: h('div', { class: 'stack tight' }, failSeg, failHint) })));
  form.addEventListener('input', sync);
  form.addEventListener('change', sync);
  sync();

  editorDrawer({
    title: isNew ? 'New policy' : p.name, sub: isNew ? 'A reusable, named rate limit' : p.id, form, readOnly: ro,
    saveLabel: isNew ? 'Create policy' : 'Save changes',
    extraFoot: !isNew ? h('a', { class: 'btn ghost', href: `#/limits?policy_id=${encodeURIComponent(p.id)}`, dataset: { keep: '1' } }, icon('search', 'sm'), 'Inspect buckets') : null,
    onSave: async () => {
      const v = value();
      if (isNew) await api.post('/policies', v); else await api.put('/policies/' + encodeURIComponent(p.id), v);
      invalidate('policies');
      toast('good', isNew ? 'Policy created' : 'Policy saved', v.name);
      done();
    },
  });
}

export default {
  async render({ root, query }) {
    let q = query.q || '';
    const listEl = h('div');
    const editable = can('edit');
    let data = { policies: [], routes: [], settings: null };
    const usedBy = p => {
      const r = data.routes.filter(rt => (rt.policy_ids || []).includes(p.id)).map(rt => `route ${rt.name}`);
      if (data.settings && (data.settings.global_policy_ids || []).includes(p.id)) r.unshift('all routes (global)');
      return r;
    };
    const open = p => openEditor(p, refresh, p ? usedBy(p) : []);

    const draw = () => {
      if (!data.policies.length) {
        mount(listEl, emptyState({ icon: 'gauge', title: 'No policies yet', text: 'Policies are reusable limits — e.g. 600 requests per minute per consumer. Attach them to routes or apply them globally.',
          action: editable ? h('button', { class: 'btn primary', onClick: () => open(null) }, icon('plus', 'sm'), 'Create policy') : null }));
        return;
      }
      const rows = filterRows(data.policies, q, ['name', 'id', 'algorithm', 'description', r => (r.key_by || []).join(' ')]);
      mount(listEl, rows.length ? table({
        rows, onRow: open, caption: 'Policies', sortKey: 'name',
        columns: [
          { key: 'name', label: 'Policy', sort: true, render: p => h('div', {}, h('div', { class: 'cell-title' }, p.name), h('div', { class: 'cell-sub mono' }, p.id)) },
          { key: 'algorithm', label: 'Algorithm', sort: true, hide: 'sm', render: p => h('span', { class: 'small' }, fmt.ALGO_LABEL[p.algorithm] || p.algorithm) },
          { key: 'limit', label: 'Limit', sort: p => p.limit, render: p => h('div', {}, h('div', { class: 'tnum', style: { fontWeight: '550' } }, fmt.policySummary(p)), fmt.BURSTY.includes(p.algorithm) && p.burst ? h('div', { class: 'cell-sub' }, `${fmt.burstLabel(p.algorithm)} ${fmt.int(p.burst)}`) : null) },
          { key: 'key_by', label: 'Keyed by', hide: 'md', render: p => h('div', { class: 'chips' }, (p.key_by || []).map(k => h('span', { class: 'chip plain' }, k))) },
          { key: 'mode', label: 'Mode', sort: true, render: p => modeBadge(p.mode) },
          { key: 'used', label: 'Used by', hide: 'md', sort: p => usedBy(p).length, render: p => { const u = usedBy(p); return u.length ? h('span', { class: 'small', title: u.join(', ') }, u[0].startsWith('all') ? 'Global' : fmt.plural(u.length, 'route')) : h('span', { class: 'small muted' }, 'Unused'); } },
          { key: 'enabled', label: 'Status', sort: p => (p.enabled ? 1 : 0), render: p => enabledBadge(p.enabled) },
          { key: 'x', label: '', cls: 'actions', render: p => menuButton(h('button', { class: 'btn ghost sm icon-only', 'aria-label': `Actions for ${p.name}` }, icon('more')), () => [
            { label: editable ? 'Edit' : 'View', icon: 'edit', onClick: () => open(p) },
            { label: 'Inspect buckets', icon: 'search', onClick: () => go('/limits', { policy_id: p.id }) },
            { label: 'View limited requests', icon: 'logs', onClick: () => go('/logs', { policy_id: p.id }) },
            ...(editable ? [
              { label: p.mode === 'shadow' ? 'Switch to enforce' : 'Switch to shadow', icon: p.mode === 'shadow' ? 'shield' : 'eye', onClick: async () => {
                try { await api.put('/policies/' + encodeURIComponent(p.id), { ...p, mode: p.mode === 'shadow' ? 'enforce' : 'shadow' }); invalidate('policies'); toast('good', `${p.name} is now ${p.mode === 'shadow' ? 'enforcing' : 'in shadow mode'}`); refresh(); } catch (e) { toast('crit', 'Couldn’t update policy', e.friendly); }
              } },
              '-',
              { label: 'Delete', icon: 'trash', danger: true, onClick: async () => { if (await confirmDelete({ what: 'policy', name: p.name, run: () => api.del('/policies/' + encodeURIComponent(p.id)) })) { invalidate('policies'); refresh(); } } },
            ] : []),
          ]) },
        ],
      }) : noMatches(() => { q = ''; root.querySelector('[data-search]').value = ''; draw(); }));
    };

    async function refresh() {
      await load(listEl, async () => {
        const [policies, routes, settings] = await Promise.all([api.get('/policies'), entities('routes', { fresh: true }).catch(() => []), api.get('/settings').catch(() => null)]);
        data = { policies: api.list(policies, 'policies'), routes, settings };
      }, () => { draw(); return listEl.firstChild || h('div'); });
    }

    mount(root,
      pageHead({ title: 'Policies', lede: 'Reusable rate limits. Attach them to routes, apply them globally, and tune them per plan or consumer.',
        actions: editable ? h('button', { class: 'btn primary', onClick: () => open(null) }, icon('plus', 'sm'), 'New policy') : null }),
      h('section', { class: 'card' },
        h('div', { class: 'toolbar' }, searchBox('Filter policies…', q, v => { q = v; replaceQuery({ q: v }); draw(); }),
          h('span', { class: 'grow' }), h('span', { class: 'xs muted hide-sm' }, 'Shadow policies never block — use them to dry-run new limits.')),
        listEl));
    await refresh();
    if (query.new && editable) open(null);
    else if (query.edit) {
      const p = data.policies.find(x => x.id === query.edit);
      if (p) open(p); else toast('warn', 'Policy not found', query.edit);
    }
  },
};

export { badge };
