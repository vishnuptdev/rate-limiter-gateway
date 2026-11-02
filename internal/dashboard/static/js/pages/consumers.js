// Consumers list + create.
import { h, mount, nextId } from '../dom.js';
import { icon } from '../icons.js';
import * as api from '../api.js';
import * as fmt from '../format.js';
import { can, entities, invalidate } from '../state.js';
import { pageHead, table, badge, emptyState, load, modal, toast, busy } from '../ui.js';
import { field, input, select, showFormError, clearProblems } from '../forms.js';
import { filterRows, searchBox, noMatches } from '../crud.js';
import { go, replaceQuery } from '../router.js';

export function keyState(k) {
  if (k.revoked) return 'revoked';
  if (k.expires_at && new Date(k.expires_at).getTime() < Date.now()) return 'expired';
  return 'active';
}

export function createConsumer(plans, onCreated) {
  const name = input({ placeholder: 'Acme Corp', autofocus: true });
  const id = input({ placeholder: 'auto-generated from name', mono: true });
  const plan = select({ options: [{ value: '', label: 'No plan (policy defaults)' }, ...plans.map(p => ({ value: p.id, label: p.name }))] });
  const formId = nextId('cf');
  const form = h('form', { class: 'form', id: formId, novalidate: true },
    field({ label: 'Name', name: 'name', control: name }),
    field({ label: 'ID', name: 'id', control: id, optional: true, hint: 'Used in rate keys and logs. Lowercase, digits, - and _.' }),
    field({ label: 'Plan', name: 'plan_id', control: plan }));
  const submit = h('button', { class: 'btn primary', type: 'submit', form: formId }, 'Create consumer');
  const m = modal({ title: 'New consumer', desc: 'A customer, app or tenant that calls your API with its own keys.', icon: 'user', body: form,
    foot: [h('button', { class: 'btn', type: 'button', onClick: () => m.close() }, 'Cancel'), submit] });
  form.addEventListener('submit', async e => {
    e.preventDefault();
    clearProblems(form);
    await busy(submit, async () => {
      try {
        const c = await api.post('/consumers', { ...(id.value.trim() ? { id: id.value.trim() } : {}), name: name.value.trim(), plan_id: plan.value || undefined, keys: [], disabled: false });
        invalidate('consumers');
        m.close();
        toast('good', 'Consumer created', 'Next: issue an API key.');
        onCreated(c);
      } catch (err) { showFormError(form, err); }
    });
  });
}

export default {
  async render({ root, query }) {
    let q = query.q || '';
    let planF = query.plan || '';
    const editable = can('edit');
    const listEl = h('div');
    let data = { consumers: [], plans: [] };
    const planSel = select({ cls: 'sm', 'aria-label': 'Filter by plan', options: [{ value: '', label: 'All plans' }] });
    planSel.addEventListener('change', () => { planF = planSel.value; replaceQuery({ plan: planF }); draw(); });

    const draw = () => {
      if (!data.consumers.length) {
        mount(listEl, emptyState({ icon: 'users', title: 'No consumers yet', text: 'Consumers are the customers and apps that call your API. Each gets API keys, a plan, and optional per-policy overrides.',
          action: editable ? h('button', { class: 'btn primary', onClick: create }, icon('plus', 'sm'), 'Create consumer') : null }));
        return;
      }
      const planName = id => (data.plans.find(p => p.id === id) || {}).name || id;
      let rows = filterRows(data.consumers, q, ['name', 'id', c => Object.values(c.metadata || {}).join(' '), c => (c.keys || []).map(k => k.prefix).join(' ')]);
      if (planF) rows = rows.filter(c => (c.plan_id || '') === planF);
      mount(listEl, rows.length ? table({
        rows, onRow: c => go('/consumers/' + encodeURIComponent(c.id)), caption: 'Consumers', sortKey: 'name',
        columns: [
          { key: 'name', label: 'Consumer', sort: true, render: c => h('div', { class: 'row' }, h('span', { class: 'avatar', 'aria-hidden': 'true' }, fmt.initials(c.name)),
            h('div', { class: 'grow' }, h('a', { class: 'cell-title', href: '#/consumers/' + encodeURIComponent(c.id) }, c.name), h('div', { class: 'cell-sub mono' }, c.id))) },
          { key: 'plan_id', label: 'Plan', sort: c => planName(c.plan_id || ''), render: c => c.plan_id ? badge(planName(c.plan_id), 'accent', 'layers', 'square') : h('span', { class: 'muted small' }, 'None') },
          { key: 'keys', label: 'Active keys', align: 'right', sort: c => (c.keys || []).filter(k => keyState(k) === 'active').length, render: c => { const n = (c.keys || []).filter(k => keyState(k) === 'active').length; return h('span', { class: n ? 'tnum' : 'tnum muted' }, String(n)); } },
          { key: 'overrides', label: 'Overrides', hide: 'md', sort: c => Object.keys(c.overrides || {}).length, render: c => { const n = Object.keys(c.overrides || {}).length; return n ? badge(fmt.plural(n, 'override'), 'info') : h('span', { class: 'muted small' }, '—'); } },
          { key: 'meta', label: 'Owner', hide: 'md', render: c => h('span', { class: 'small muted' }, (c.metadata && (c.metadata.owner || c.metadata.email)) || '—') },
          { key: 'created_at', label: 'Created', hide: 'sm', sort: true, defaultDir: 'desc', render: c => h('span', { class: 'small muted', title: fmt.dateTime(c.created_at) }, fmt.date(c.created_at)) },
          { key: 'disabled', label: 'Status', sort: c => (c.disabled ? 1 : 0), render: c => c.disabled ? badge('Disabled', 'crit', 'ban') : badge('Active', 'good', 'check') },
        ],
      }) : noMatches(() => { q = ''; planF = ''; planSel.value = ''; root.querySelector('[data-search]').value = ''; draw(); }));
    };
    const create = () => createConsumer(data.plans, c => go('/consumers/' + encodeURIComponent(c.id), { tab: 'keys' }));

    mount(root,
      pageHead({ title: 'Consumers', lede: 'Customers and apps calling your API — with their keys, plan and custom limits.',
        actions: editable ? h('button', { class: 'btn primary', onClick: create }, icon('plus', 'sm'), 'New consumer') : null }),
      h('section', { class: 'card' },
        h('div', { class: 'toolbar' }, searchBox('Search name, ID, key prefix, metadata…', q, v => { q = v; replaceQuery({ q: v }); draw(); }), planSel),
        listEl));
    await load(listEl, async () => {
      const [consumers, plans] = await Promise.all([api.get('/consumers'), entities('plans', { fresh: true }).catch(() => [])]);
      data = { consumers: api.list(consumers, 'consumers'), plans };
      mount(planSel, h('option', { value: '' }, 'All plans'), plans.map(p => h('option', { value: p.id }, p.name)));
      planSel.value = planF;
    }, () => { draw(); return listEl.firstChild || h('div'); });
    if (query.new && editable) create();
  },
};
