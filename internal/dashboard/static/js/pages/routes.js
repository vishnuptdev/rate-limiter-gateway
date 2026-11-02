// Routes: list + editor (match, upstream, ordered policies, auth).
import { h, mount, nextId } from '../dom.js';
import { icon } from '../icons.js';
import * as api from '../api.js';
import * as fmt from '../format.js';
import { can, entities, invalidate } from '../state.js';
import { pageHead, table, badge, enabledBadge, emptyState, load, menuButton, toast, readonlyBanner } from '../ui.js';
import { field, input, toggle, orderedPicker } from '../forms.js';
import { editorDrawer, confirmDelete, filterRows, searchBox, noMatches, sectionTitle } from '../crud.js';
import { go, replaceQuery } from '../router.js';

const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];

export function matchText(m = {}) {
  return `${m.host || '*'}${m.path_prefix && m.path_prefix !== '/' ? m.path_prefix : '/'}`;
}

function methodPicker(selected, disabled) {
  const sel = new Set(selected || []);
  const wrap = h('div', { class: 'chips', role: 'group', 'aria-label': 'HTTP methods', dataset: { field: 'match.methods' } });
  const btns = METHODS.map(m => {
    const b = h('button', { type: 'button', class: 'btn xs', 'aria-pressed': String(sel.has(m)), disabled }, m);
    b.addEventListener('click', () => { if (sel.has(m)) sel.delete(m); else sel.add(m); paint(); wrap.dispatchEvent(new Event('change', { bubbles: true })); });
    return b;
  });
  const anyNote = h('span', { class: 'xs muted' });
  const paint = () => {
    btns.forEach((b, i) => { const on = sel.has(METHODS[i]); b.setAttribute('aria-pressed', String(on)); b.className = `btn xs ${on ? 'primary' : ''}`; });
    anyNote.textContent = sel.size ? '' : 'Any method';
  };
  mount(wrap, btns, anyNote);
  paint();
  wrap.value = () => METHODS.filter(m => sel.has(m));
  return wrap;
}

function openEditor(existing, policies, done, seed) {
  const isNew = !existing;
  const r = existing ? structuredClone(existing) : seed || { name: '', match: { host: '', path_prefix: '/', methods: [] }, upstream: 'http://', policy_ids: [], require_api_key: true, timeout: '30s', priority: 0, enabled: true, strip_prefix: false };
  const ro = !can('edit');
  const formId = nextId('route-form');
  const name = input({ value: r.name, placeholder: 'Orders API', required: true, autofocus: true });
  const id = input({ value: r.id || '', placeholder: 'auto-generated from name', mono: true, disabled: !isNew });
  const host = input({ value: r.match.host || '', placeholder: 'api.example.com or *.example.com', mono: true });
  const prefix = input({ value: r.match.path_prefix || '', placeholder: '/v1/orders', mono: true });
  const methods = methodPicker(r.match.methods, ro);
  const upstream = input({ value: r.upstream, placeholder: 'http://orders.internal:8000', mono: true, type: 'url' });
  const strip = toggle({ label: 'Strip path prefix', desc: 'forward /v1/orders/42 as /42', checked: !!r.strip_prefix, name: 'strip_prefix' });
  const timeout = input({ value: r.timeout ? fmt.goDur(r.timeout) : '', placeholder: '30s', mono: true });
  const priority = input({ value: String(r.priority || 0), type: 'number', step: '1' });
  const pol = orderedPicker(policies, r.policy_ids || [], { name: 'policy_ids', disabled: ro, emptyText: 'No route policies — only global policies apply.', metaOf: p => `${fmt.policySummary(p)}${p.mode === 'shadow' ? ' · shadow' : ''}` });
  const upgradeMax = input({ value: r.upgrade_max_duration ? fmt.goDur(r.upgrade_max_duration) : '', placeholder: '1h', mono: true });
  const upgradeMaxField = h('div', { class: 'form-grid' },
    field({ label: 'Upgrade max duration', name: 'upgrade_max_duration', control: upgradeMax, optional: true, hint: 'Upgraded connections are closed after this long. Go duration, at most 24h. Default 1h.' }));
  const paintUpgrade = on => { upgradeMaxField.style.display = on ? '' : 'none'; };
  const upgrade = toggle({ label: 'Allow WebSocket upgrades', desc: 'each connection open counts as one request against the route’s policies (concurrency policies can’t be used here). The Timeout above bounds only the handshake; the connection is closed at the upgrade max duration. h2c is always refused.', checked: !!r.allow_upgrade, name: 'allow_upgrade', onChange: paintUpgrade });
  paintUpgrade(!!r.allow_upgrade);
  const requireKey = toggle({ label: 'Require API key', desc: 'reject anonymous requests with 401', checked: r.require_api_key, name: 'require_api_key' });
  const enabled = toggle({ label: 'Enabled', checked: r.enabled, name: 'enabled' });
  const summary = h('div', { class: 'summary-callout' });

  const value = () => ({
    ...(existing || {}),
    ...(isNew && id.value.trim() ? { id: id.value.trim() } : {}),
    name: name.value.trim(),
    match: { host: host.value.trim(), path_prefix: prefix.value.trim(), methods: methods.value() },
    upstream: upstream.value.trim(), strip_prefix: strip.input.checked, allow_upgrade: upgrade.input.checked,
    upgrade_max_duration: (upgrade.input.checked && upgradeMax.value.trim()) || undefined,
    timeout: timeout.value.trim() || undefined, priority: parseInt(priority.value, 10) || 0,
    policy_ids: pol.value(), require_api_key: requireKey.input.checked, enabled: enabled.input.checked,
  });
  const paintSummary = () => {
    const v = value();
    const ps = v.policy_ids.map(pid => policies.find(p => p.id === pid)).filter(Boolean);
    mount(summary, icon('route'), h('div', {},
      h('strong', {}, v.match.methods.length ? v.match.methods.join(', ') : 'Any method'), ' to ', h('code', {}, matchText(v.match) + (v.match.path_prefix && v.match.path_prefix !== '/' ? '/*' : '*')),
      ' → ', h('code', {}, v.upstream || '—'), '. ',
      ps.length ? ['Limited by ', ps.map((p, i) => [i ? ', then ' : '', h('strong', {}, p.name), ` (${fmt.policySummary(p)})`]), '.'] : 'No route-specific limits.',
      v.require_api_key ? ' API key required.' : ' Anonymous requests allowed.'));
  };

  const form = h('form', { class: 'form', id: formId, novalidate: true },
    ro ? readonlyBanner() : null,
    summary,
    h('div', { class: 'form-section' },
      sectionTitle('Basics'),
      h('div', { class: 'form-grid' },
        field({ label: 'Name', name: 'name', control: name }),
        field({ label: 'ID', name: 'id', control: id, optional: isNew, hint: isNew ? 'Lowercase letters, digits, - and _. Can’t be changed later.' : 'IDs are permanent.' })),
      enabled),
    h('div', { class: 'form-section' },
      sectionTitle('Match', 'All non-empty conditions must match. Highest priority wins; ties go to the longest path prefix.'),
      h('div', { class: 'form-grid' },
        field({ label: 'Host', name: 'match.host', control: host, optional: true, hint: 'Exact host or wildcard. Empty matches any host.' }),
        field({ label: 'Path prefix', name: 'match.path_prefix', control: prefix, hint: 'Segment-aware: /api matches /api/x but not /apix.' }),
        field({ label: 'Methods', name: 'match.methods', control: methods, full: true }),
        field({ label: 'Priority', name: 'priority', control: priority, hint: 'Higher wins when several routes match.' }))),
    h('div', { class: 'form-section' },
      sectionTitle('Upstream'),
      h('div', { class: 'form-grid' },
        field({ label: 'Upstream URL', name: 'upstream', control: upstream, full: true, hint: 'Absolute http(s) URL the gateway proxies to.' }),
        field({ label: 'Timeout', name: 'timeout', control: timeout, optional: true, hint: 'Go duration, e.g. 15s or 1m. Default 30s. Responses are also cut at the server’s 120s write timeout, so values above 2m have no effect.' })),
      strip, upgrade, upgradeMaxField),
    h('div', { class: 'form-section' },
      sectionTitle('Rate limiting & auth', 'Global policies from Settings run first, then these — in order. The first enforcing deny wins.'),
      field({ label: 'Policies', name: 'policy_ids', control: pol }),
      requireKey));
  form.addEventListener('input', paintSummary);
  form.addEventListener('change', paintSummary);
  form.addEventListener('click', () => setTimeout(paintSummary));
  paintSummary();

  editorDrawer({
    title: isNew ? 'New route' : r.name, sub: isNew ? 'Map requests to an upstream and its limits' : r.id, form, readOnly: ro,
    saveLabel: isNew ? 'Create route' : 'Save changes',
    extraFoot: !isNew ? h('a', { class: 'btn ghost', href: `#/simulator?route_id=${encodeURIComponent(r.id)}&host=${encodeURIComponent(r.match.host && !r.match.host.startsWith('*') ? r.match.host : '')}&path=${encodeURIComponent(r.match.path_prefix || '/')}`, dataset: { keep: '1' } }, icon('flask', 'sm'), 'Test') : null,
    onSave: async () => {
      const v = value();
      if (isNew) await api.post('/routes', v); else await api.put('/routes/' + encodeURIComponent(r.id), v);
      invalidate('routes');
      toast('good', isNew ? 'Route created' : 'Route saved', v.name);
      done();
    },
  });
}

export default {
  async render({ root, query }) {
    let q = query.q || '';
    const listEl = h('div');
    const editable = can('edit');
    let data = { routes: [], policies: [] };

    const draw = () => {
      const rows = filterRows(data.routes, q, ['name', 'id', 'upstream', r => matchText(r.match)]);
      if (!data.routes.length) {
        mount(listEl, emptyState({ icon: 'route', title: 'No routes yet', text: 'A route maps incoming requests (host, path, method) to an upstream and the policies that limit it.',
          action: editable ? h('button', { class: 'btn primary', onClick: () => openEditor(null, data.policies, refresh) }, icon('plus', 'sm'), 'Create route') : null }));
        return;
      }
      mount(listEl, rows.length ? table({
        rows, onRow: r => openEditor(r, data.policies, refresh), caption: 'Routes', sortKey: 'priority', sortDir: 'desc',
        columns: [
          { key: 'name', label: 'Route', sort: true, render: r => h('div', {}, h('div', { class: 'cell-title' }, r.name), h('div', { class: 'cell-sub mono' }, r.id)) },
          { key: 'match', label: 'Match', sort: r => matchText(r.match), render: r => h('div', {}, h('div', { class: 'mono small' }, matchText(r.match)), h('div', { class: 'cell-sub' }, r.match.methods && r.match.methods.length ? r.match.methods.join(' · ') : 'any method')) },
          { key: 'upstream', label: 'Upstream', hide: 'md', sort: true, render: r => h('span', { class: 'mono small muted trunc', style: { maxWidth: '220px', display: 'inline-block' } }, r.upstream) },
          { key: 'policies', label: 'Policies', hide: 'sm', render: r => r.policy_ids.length ? h('div', { class: 'chips' }, r.policy_ids.map(pid => { const p = data.policies.find(x => x.id === pid); return h('span', { class: 'chip plain sans', title: p ? fmt.policySummary(p) : 'missing policy' }, p ? p.name : pid); })) : h('span', { class: 'muted' }, 'Global only') },
          { key: 'require_api_key', label: 'Auth', hide: 'md', sort: r => (r.require_api_key ? 1 : 0), render: r => r.require_api_key ? badge('API key', 'info', 'key') : badge('Public', '', 'globe') },
          { key: 'priority', label: 'Priority', align: 'right', hide: 'md', sort: true },
          { key: 'enabled', label: 'Status', sort: r => (r.enabled ? 1 : 0), render: r => enabledBadge(r.enabled) },
          { key: 'x', label: '', cls: 'actions', render: r => menuButton(h('button', { class: 'btn ghost sm icon-only', 'aria-label': `Actions for ${r.name}` }, icon('more')), () => [
            { label: editable ? 'Edit' : 'View', icon: 'edit', onClick: () => openEditor(r, data.policies, refresh) },
            { label: 'Test in simulator', icon: 'flask', onClick: () => go('/simulator', { route_id: r.id, host: r.match.host && !r.match.host.startsWith('*') ? r.match.host : '', path: r.match.path_prefix || '/' }) },
            { label: 'Integration snippets', icon: 'plug', onClick: () => go('/integration', { route: r.id }) },
            { label: 'View logs', icon: 'logs', onClick: () => go('/logs', { route_id: r.id }) },
            ...(editable ? [
              { label: r.enabled ? 'Disable' : 'Enable', icon: r.enabled ? 'pause' : 'play', onClick: async () => {
                try { await api.put('/routes/' + encodeURIComponent(r.id), { ...r, enabled: !r.enabled }); invalidate('routes'); toast('good', r.enabled ? 'Route disabled' : 'Route enabled', r.name); refresh(); } catch (e) { toast('crit', 'Couldn’t update route', e.friendly); }
              } },
              { label: 'Duplicate', icon: 'copy', onClick: () => { const c = structuredClone(r); delete c.id; delete c.created_at; delete c.updated_at; c.name += ' (copy)'; c.enabled = false; openEditorPrefilled(c); } },
              '-',
              { label: 'Delete', icon: 'trash', danger: true, onClick: async () => { if (await confirmDelete({ what: 'route', name: r.name, run: () => api.del('/routes/' + encodeURIComponent(r.id)) })) { invalidate('routes'); refresh(); } } },
            ] : []),
          ]) },
        ],
      }) : noMatches(() => { q = ''; root.querySelector('[data-search]').value = ''; draw(); }));
    };
    const openEditorPrefilled = c => openEditor(null, data.policies, refresh, c);

    async function refresh() {
      await load(listEl, async () => {
        const [routes, policies] = await Promise.all([api.get('/routes'), entities('policies', { fresh: true })]);
        data = { routes: api.list(routes, 'routes'), policies };
        return data;
      }, () => { draw(); return listEl.firstChild || h('div'); });
    }

    mount(root,
      pageHead({ title: 'Routes', lede: 'Match incoming requests to upstreams and attach the policies that limit them.',
        actions: editable ? h('button', { class: 'btn primary', onClick: () => openEditor(null, data.policies, refresh) }, icon('plus', 'sm'), 'New route') : null }),
      h('section', { class: 'card' },
        h('div', { class: 'toolbar' }, searchBox('Filter routes…', q, v => { q = v; replaceQuery({ q: v }); draw(); })),
        listEl));
    await refresh();
    if (query.new && editable) openEditor(null, data.policies, refresh);
    else if (query.edit) {
      const r = data.routes.find(x => x.id === query.edit);
      if (r) openEditor(r, data.policies, refresh); else toast('warn', 'Route not found', query.edit);
    }
  },
};
