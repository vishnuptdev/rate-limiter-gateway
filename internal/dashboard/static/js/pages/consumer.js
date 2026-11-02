// Consumer detail: profile, plan assignment, API keys (copy-once), overrides, metadata, recent traffic.
import { h, mount, nextId } from '../dom.js';
import { icon } from '../icons.js';
import * as api from '../api.js';
import * as fmt from '../format.js';
import { can, entities, invalidate, system } from '../state.js';
import { table, badge, emptyState, errorState, modal, toast, busy, tabs, secretModal, decisionBadge, statusCode, confirm, readonlyBanner, codeBlock, menuButton } from '../ui.js';
import { field, input, select, toggle, kvEditor, showFormError, clearProblems } from '../forms.js';
import { overridesEditor } from '../overrides.js';
import { confirmDelete } from '../crud.js';
import { keyState } from './consumers.js';
import { logDetail } from './logs.js';
import { go, replaceQuery } from '../router.js';

const EXPIRY = [{ value: '', label: 'Never' }, { value: '30', label: '30 days' }, { value: '90', label: '90 days' }, { value: '365', label: '1 year' }, { value: 'custom', label: 'Custom date…' }];

function issueKey(c, onDone) {
  const name = input({ placeholder: 'production', autofocus: true });
  const exp = select({ options: EXPIRY, value: '90' });
  const date = input({ type: 'date', cls: 'hidden', min: new Date(Date.now() + 86400e3).toISOString().slice(0, 10), 'aria-label': 'Expiry date' });
  exp.addEventListener('change', () => date.classList.toggle('hidden', exp.value !== 'custom'));
  const formId = nextId('kf');
  const form = h('form', { class: 'form', id: formId, novalidate: true },
    field({ label: 'Key name', name: 'name', control: name, optional: true, hint: 'Helps you tell keys apart, e.g. production, staging, ci.' }),
    field({ label: 'Expires', name: 'expires_at', control: h('div', { class: 'stack tight' }, exp, date) }));
  const submit = h('button', { class: 'btn primary', type: 'submit', form: formId }, icon('key', 'sm'), 'Issue key');
  const m = modal({ title: `New API key for ${c.name}`, icon: 'key', body: form, foot: [h('button', { class: 'btn', type: 'button', onClick: () => m.close() }, 'Cancel'), submit] });
  form.addEventListener('submit', async e => {
    e.preventDefault();
    clearProblems(form);
    let expires;
    if (exp.value === 'custom') {
      if (!date.value) { showFormError(form, { status: 422, problems: [{ field: 'expires_at', message: 'Pick a date' }] }); return; }
      expires = new Date(date.value + 'T23:59:59Z').toISOString();
    } else if (exp.value) expires = new Date(Date.now() + (+exp.value) * 86400e3).toISOString();
    await busy(submit, async () => {
      try {
        const res = await api.post(`/consumers/${encodeURIComponent(c.id)}/keys`, { name: name.value.trim() || undefined, expires_at: expires });
        m.close();
        let sys = null;
        try { sys = await system(); } catch { /* optional */ }
        const header = 'X-API-Key';
        const base = sys && sys.data_plane_addr ? addrToURL(sys.data_plane_addr) : 'https://api.example.com';
        await secretModal({
          title: 'API key created', secret: res.key,
          note: 'Copy it now and send it to the consumer over a secure channel. If it’s lost, revoke it and issue a new one.',
          extra: codeBlock(`curl -H "${header}: ${res.key}" ${base}/`, { lang: 'bash', title: 'Try it' }),
        });
        onDone();
      } catch (err) { showFormError(form, err); }
    });
  });
}

export function addrToURL(addr) {
  if (!addr) return '';
  if (/^https?:\/\//.test(addr)) return addr.replace(/\/$/, '');
  const host = addr.startsWith(':') ? location.hostname + addr : addr.replace(/^0\.0\.0\.0|^\[::\]/, location.hostname);
  return 'http://' + host;
}

export default {
  async render({ root, params, query, crumbs }) {
    const id = params.id;
    const editable = can('edit');
    let tab = ['overview', 'keys', 'limits', 'metadata'].includes(query.tab) ? query.tab : 'overview';
    let c, plans = [], policies = [];

    async function fetchAll() {
      [c, plans, policies] = await Promise.all([
        api.get('/consumers/' + encodeURIComponent(id)),
        entities('plans', { fresh: true }).catch(() => []),
        entities('policies', { fresh: true }).catch(() => []),
      ]);
    }
    mount(root, h('div', { class: 'stack' }, h('div', { class: 'skel title' }), h('div', { class: 'skel block', style: { height: '320px' } })));
    try { await fetchAll(); } catch (e) {
      mount(root, e.status === 404 ? emptyState({ icon: 'users', title: 'Consumer not found', text: `There is no consumer with ID “${id}”.`, action: h('a', { class: 'btn', href: '#/consumers' }, 'All consumers') }) : errorState(e, () => location.reload()));
      return;
    }
    crumbs([{ label: c.name }]);
    const body = h('div');
    const save = async (patch, msg) => {
      const next = { ...c, ...patch };
      const saved = await api.put('/consumers/' + encodeURIComponent(c.id), next);
      c = saved && saved.id ? saved : next;
      invalidate('consumers');
      toast('good', msg || 'Consumer saved');
      paintHead();
    };

    const head = h('div');
    function paintHead() {
      const plan = plans.find(p => p.id === c.plan_id);
      const active = (c.keys || []).filter(k => keyState(k) === 'active').length;
      mount(head, h('div', { class: 'page-head' },
        h('div', { class: 'entity-head grow' },
          h('div', { class: 'entity-icon', 'aria-hidden': 'true' }, fmt.initials(c.name)),
          h('div', { class: 'grow' },
            h('h1', {}, c.name),
            h('div', { class: 'row wrap mt-4' }, h('span', { class: 'mono small muted' }, c.id),
              c.disabled ? badge('Disabled', 'crit', 'ban') : badge('Active', 'good', 'check'),
              plan ? badge(plan.name, 'accent', 'layers', 'square') : badge('No plan', '', null, 'square'),
              h('span', { class: 'small muted' }, `${fmt.plural(active, 'active key')} · created ${fmt.date(c.created_at)}`)))),
        h('div', { class: 'page-actions' },
          h('a', { class: 'btn', href: `#/integration?consumer=${encodeURIComponent(c.id)}` }, icon('plug', 'sm'), 'Integrate'),
          h('a', { class: 'btn', href: `#/logs?consumer_id=${encodeURIComponent(c.id)}` }, icon('logs', 'sm'), 'Logs'),
          editable ? menuButton(h('button', { class: 'btn icon-only', 'aria-label': 'More actions' }, icon('more')), () => [
            { label: c.disabled ? 'Enable consumer' : 'Disable consumer', icon: c.disabled ? 'play' : 'ban', onClick: async () => {
              if (!c.disabled && !(await confirm({ title: `Disable ${c.name}?`, message: 'All of this consumer’s keys will be rejected with 401 until re-enabled.', confirmLabel: 'Disable', danger: true }))) return;
              try { await save({ disabled: !c.disabled }, c.disabled ? 'Consumer enabled' : 'Consumer disabled'); draw(); } catch (e) { toast('crit', 'Couldn’t update consumer', e.friendly); }
            } },
            '-',
            { label: 'Delete consumer', icon: 'trash', danger: true, onClick: async () => {
              if (await confirmDelete({ what: 'consumer', name: c.name, typeToConfirm: c.id, run: () => api.del('/consumers/' + encodeURIComponent(c.id)) })) { invalidate('consumers'); go('/consumers'); }
            } },
          ]) : null)));
    }

    function overviewTab() {
      const name = input({ value: c.name, disabled: !editable });
      const plan = select({ value: c.plan_id || '', disabled: !editable, options: [{ value: '', label: 'No plan (policy defaults)' }, ...plans.map(p => ({ value: p.id, label: p.name }))] });
      const enabled = toggle({ label: 'Enabled', desc: 'disabled consumers’ keys get 401', checked: !c.disabled, name: 'disabled', disabled: !editable });
      const formId = nextId('cdf');
      const submit = h('button', { class: 'btn primary', type: 'submit', form: formId }, 'Save');
      const form = h('form', { class: 'form', id: formId, novalidate: true },
        field({ label: 'Name', name: 'name', control: name }),
        field({ label: 'Plan', name: 'plan_id', control: plan, hint: h('span', {}, 'Plans set tiered limits. ', h('a', { href: '#/plans' }, 'Manage plans')) }),
        enabled);
      form.addEventListener('submit', async e => {
        e.preventDefault();
        clearProblems(form);
        await busy(submit, async () => {
          try { await save({ name: name.value.trim(), plan_id: plan.value || undefined, disabled: !enabled.input.checked }); crumbs([{ label: c.name }]); }
          catch (err) { showFormError(form, err); }
        });
      });
      const recent = h('div');
      api.get('/logs', { consumer_id: c.id, limit: 12 }).then(res => {
        const entries = api.list(res, 'entries');
        mount(recent, entries.length ? table({
          rows: entries, dense: true, onRow: e => logDetail(e), caption: 'Recent requests',
          columns: [
            { key: 'time', label: 'Time', render: e => h('span', { class: 'mono small muted' }, fmt.time(e.time)) },
            { key: 'decision', label: 'Decision', render: e => decisionBadge(e.decision) },
            { key: 'status', label: 'Status', hide: 'sm', render: e => statusCode(e.status) },
            { key: 'path', label: 'Request', render: e => h('span', { class: 'mono small trunc', style: { maxWidth: '260px', display: 'inline-block' } }, `${e.method} ${e.path}`) },
          ],
        }) : emptyState({ icon: 'logs', title: 'No recent requests', text: 'Requests from this consumer will show up here.', compact: true }));
      }).catch(err => mount(recent, errorState(err)));
      return h('div', { class: 'grid side-main' },
        h('section', { class: 'card' }, h('div', { class: 'card-head' }, h('h2', {}, 'Details')),
          h('div', { class: 'card-body' }, form,
            h('dl', { class: 'dl mt-24' }, h('dt', {}, 'Created'), h('dd', {}, fmt.dateTime(c.created_at)), h('dt', {}, 'Updated'), h('dd', {}, fmt.dateTime(c.updated_at)))),
          editable ? h('div', { class: 'card-foot' }, submit) : null),
        h('section', { class: 'card' }, h('div', { class: 'card-head' }, h('div', {}, h('h2', {}, 'Recent requests'), h('div', { class: 'desc' }, 'From the in-memory log buffer')),
          h('a', { class: 'btn sm ghost', href: `#/logs?consumer_id=${encodeURIComponent(c.id)}` }, 'Open in live logs', icon('arrowRight', 'sm'))),
        h('div', { class: 'card-body flush' }, recent)));
    }

    function keysTab() {
      const keys = (c.keys || []).slice().sort((a, b) => (keyState(a) === 'active' ? 0 : 1) - (keyState(b) === 'active' ? 0 : 1) || String(b.created_at).localeCompare(String(a.created_at)));
      const issue = editable ? h('button', { class: 'btn primary sm', onClick: () => issueKey(c, reloadKeys) }, icon('plus', 'sm'), 'Issue key') : null;
      return h('section', { class: 'card' },
        h('div', { class: 'card-head' }, h('div', {}, h('h2', {}, 'API keys'), h('div', { class: 'desc' }, 'Keys are shown once at creation; RateGuard stores only a SHA-256 hash.')), issue),
        h('div', { class: 'card-body flush' }, keys.length ? table({
          rows: keys, caption: 'API keys',
          columns: [
            { key: 'name', label: 'Name', render: k => h('span', { class: 'cell-title' }, k.name || h('span', { class: 'muted' }, 'Unnamed')) },
            { key: 'prefix', label: 'Key', render: k => h('code', {}, k.prefix + '…') },
            { key: 'created_at', label: 'Created', hide: 'sm', render: k => h('span', { class: 'small muted', title: fmt.dateTime(k.created_at) }, fmt.date(k.created_at)) },
            { key: 'expires_at', label: 'Expires', hide: 'sm', render: k => k.expires_at ? h('span', { class: 'small', title: fmt.dateTime(k.expires_at) }, fmt.ago(k.expires_at)) : h('span', { class: 'small muted' }, 'Never') },
            { key: 'state', label: 'Status', render: k => ({ active: badge('Active', 'good', 'check'), revoked: badge('Revoked', 'crit', 'ban'), expired: badge('Expired', 'warn', 'clock') })[keyState(k)] },
            { key: 'x', label: '', cls: 'actions', render: k => editable && keyState(k) === 'active' ? h('button', { class: 'btn sm danger-ghost', onClick: async () => {
              if (!(await confirm({ title: 'Revoke this key?', message: h('p', { class: 'subtle' }, 'Requests using ', h('code', {}, k.prefix + '…'), ' will be rejected with 401 immediately. This can’t be undone.'), confirmLabel: 'Revoke key', danger: true }))) return;
              try { await api.del(`/consumers/${encodeURIComponent(c.id)}/keys/${encodeURIComponent(k.id)}`); toast('good', 'Key revoked', k.prefix + '…'); reloadKeys(); }
              catch (e) { toast('crit', 'Couldn’t revoke key', e.friendly); }
            } }, 'Revoke') : null },
          ],
        }) : emptyState({ icon: 'key', title: 'No API keys', text: 'Issue a key so this consumer can authenticate with the gateway.', compact: true, action: editable ? h('button', { class: 'btn primary sm', onClick: () => issueKey(c, reloadKeys) }, icon('plus', 'sm'), 'Issue key') : null })));
    }

    function limitsTab() {
      const plan = plans.find(p => p.id === c.plan_id);
      const inherited = {};
      policies.forEach(p => {
        const o = plan && plan.overrides && plan.overrides[p.id];
        if (o) inherited[p.id] = { ...o, from: `plan ${plan.name}` };
      });
      const ov = overridesEditor(policies, c.overrides || {}, { inherited, disabled: !editable });
      const formId = nextId('of');
      const submit = h('button', { class: 'btn primary', type: 'submit', form: formId }, 'Save overrides');
      const form = h('form', { class: 'form', id: formId, novalidate: true }, editable ? null : readonlyBanner(), ov);
      form.addEventListener('submit', async e => {
        e.preventDefault();
        clearProblems(form);
        await busy(submit, async () => { try { await save({ overrides: ov.value() }, 'Overrides saved'); } catch (err) { showFormError(form, err); } });
      });
      return h('section', { class: 'card' },
        h('div', { class: 'card-head' }, h('div', {}, h('h2', {}, 'Limit overrides'), h('div', { class: 'desc' },
          'Consumer overrides beat ', plan ? ['the ', h('strong', {}, plan.name), ' plan'] : 'plan overrides', ' and policy defaults. Placeholders show what currently applies.'))),
        h('div', { class: 'card-body' }, form),
        editable ? h('div', { class: 'card-foot' }, h('a', { class: 'btn ghost', href: `#/simulator?consumer=${encodeURIComponent(c.id)}` }, icon('flask', 'sm'), 'Check effective limits'), h('span', { class: 'grow' }), submit) : null);
    }

    function metadataTab() {
      const kv = kvEditor(c.metadata || {}, { keyPh: 'key', valPh: 'value', name: 'metadata', disabled: !editable, addLabel: 'Add field' });
      const formId = nextId('mf');
      const submit = h('button', { class: 'btn primary', type: 'submit', form: formId }, 'Save metadata');
      const form = h('form', { class: 'form', id: formId, novalidate: true }, kv);
      form.addEventListener('submit', async e => {
        e.preventDefault();
        clearProblems(form);
        await busy(submit, async () => { try { await save({ metadata: kv.value() }, 'Metadata saved'); } catch (err) { showFormError(form, err); } });
      });
      return h('section', { class: 'card' },
        h('div', { class: 'card-head' }, h('div', {}, h('h2', {}, 'Metadata'), h('div', { class: 'desc' }, 'Free-form labels for your own bookkeeping — owner, CRM ID, region. Not used for limiting.'))),
        h('div', { class: 'card-body' }, form),
        editable ? h('div', { class: 'card-foot' }, submit) : null);
    }

    async function reloadKeys() {
      try { c = await api.get('/consumers/' + encodeURIComponent(id)); invalidate('consumers'); } catch { /* keep current */ }
      paintHead(); draw();
    }
    const tabEl = () => tabs([
      { id: 'overview', label: 'Overview', icon: 'overview' },
      { id: 'keys', label: 'API keys', icon: 'key', count: (c.keys || []).filter(k => keyState(k) === 'active').length },
      { id: 'limits', label: 'Limits', icon: 'gauge', count: Object.keys(c.overrides || {}).length || null },
      { id: 'metadata', label: 'Metadata', icon: 'tag' },
    ], tab, t => { tab = t; replaceQuery({ tab: t }); drawBody(); });
    const tabsHost = h('div');
    function drawBody() { mount(body, { overview: overviewTab, keys: keysTab, limits: limitsTab, metadata: metadataTab }[tab]()); }
    function draw() { mount(tabsHost, tabEl()); drawBody(); }
    paintHead();
    mount(root, head, tabsHost, body);
    draw();
  },
};
