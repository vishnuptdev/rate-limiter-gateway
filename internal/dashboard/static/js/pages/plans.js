// Plans (pricing tiers) with per-policy override editor.
import { h, mount, nextId } from '../dom.js';
import { icon } from '../icons.js';
import * as api from '../api.js';
import * as fmt from '../format.js';
import { can, entities, invalidate } from '../state.js';
import { pageHead, emptyState, load, menuButton, toast, readonlyBanner } from '../ui.js';
import { field, input, textarea } from '../forms.js';
import { overridesEditor, overrideList } from '../overrides.js';
import { editorDrawer, confirmDelete, sectionTitle } from '../crud.js';
import { go } from '../router.js';

function openEditor(existing, policies, done) {
  const isNew = !existing;
  const p = existing ? structuredClone(existing) : { name: '', description: '', overrides: {} };
  const ro = !can('edit');
  const name = input({ value: p.name, placeholder: 'Pro', autofocus: true });
  const id = input({ value: p.id || '', placeholder: 'auto-generated from name', mono: true, disabled: !isNew });
  const desc = textarea({ value: p.description || '', placeholder: 'Who this tier is for', rows: 2 });
  desc.style.minHeight = '60px';
  const ov = overridesEditor(policies, p.overrides || {}, { disabled: ro });
  const form = h('form', { class: 'form', id: nextId('plan-form'), novalidate: true },
    ro ? readonlyBanner() : null,
    h('div', { class: 'form-section' },
      h('div', { class: 'form-grid' },
        field({ label: 'Name', name: 'name', control: name }),
        field({ label: 'ID', name: 'id', control: id, optional: isNew, hint: isNew ? 'Permanent; used when assigning consumers.' : 'IDs are permanent.' }),
        field({ label: 'Description', name: 'description', control: desc, optional: true, full: true }))),
    h('div', { class: 'form-section' },
      sectionTitle('Limit overrides', 'Every consumer on this plan gets these numbers instead of the policy defaults. Consumer-level overrides still win.'),
      ov));
  editorDrawer({
    title: isNew ? 'New plan' : p.name, sub: isNew ? 'A pricing tier that adjusts policy limits' : p.id, form, readOnly: ro,
    saveLabel: isNew ? 'Create plan' : 'Save changes',
    onSave: async () => {
      const v = { ...(existing || {}), ...(isNew && id.value.trim() ? { id: id.value.trim() } : {}), name: name.value.trim(), description: desc.value.trim() || undefined, overrides: ov.value() };
      if (isNew) await api.post('/plans', v); else await api.put('/plans/' + encodeURIComponent(p.id), v);
      invalidate('plans');
      toast('good', isNew ? 'Plan created' : 'Plan saved', v.name);
      done();
    },
  });
}

export default {
  async render({ root, query }) {
    const editable = can('edit');
    const listEl = h('div');
    let data = { plans: [], policies: [], consumers: [] };
    const open = p => openEditor(p, data.policies, refresh);

    const draw = () => {
      if (!data.plans.length) {
        mount(listEl, h('div', { class: 'card' }, emptyState({ icon: 'layers', title: 'No plans yet', text: 'Plans are tiers like Free, Pro and Enterprise. Each one overrides policy limits for every consumer assigned to it.',
          action: editable ? h('button', { class: 'btn primary', onClick: () => open(null) }, icon('plus', 'sm'), 'Create plan') : null })));
        return;
      }
      mount(listEl, h('div', { class: 'grid three' }, data.plans.map(pl => {
        const members = data.consumers.filter(c => c.plan_id === pl.id);
        return h('section', { class: 'card flexcol' },
          h('div', { class: 'card-head flush' },
            h('div', { class: 'row grow' }, h('div', { class: 'entity-icon', 'aria-hidden': 'true' }, pl.name.slice(0, 1).toUpperCase()),
              h('div', { class: 'grow' }, h('h2', {}, pl.name), h('div', { class: 'xs muted mono' }, pl.id))),
            menuButton(h('button', { class: 'btn ghost sm icon-only', 'aria-label': `Actions for ${pl.name}` }, icon('more')), () => [
              { label: editable ? 'Edit plan' : 'View plan', icon: 'edit', onClick: () => open(pl) },
              { label: 'View consumers', icon: 'users', onClick: () => go('/consumers', { plan: pl.id }) },
              ...(editable ? ['-', { label: 'Delete', icon: 'trash', danger: true, onClick: async () => { if (await confirmDelete({ what: 'plan', name: pl.name, run: () => api.del('/plans/' + encodeURIComponent(pl.id)) })) { invalidate('plans'); refresh(); } } }] : []),
            ])),
          h('div', { class: 'card-body stack' },
            pl.description ? h('p', { class: 'small subtle' }, pl.description) : null,
            h('div', { class: 'stat-inline' },
              h('div', { class: 's' }, h('div', { class: 'k' }, 'Consumers'), h('div', { class: 'v' }, fmt.int(members.length))),
              h('div', { class: 's' }, h('div', { class: 'k' }, 'Overrides'), h('div', { class: 'v' }, fmt.int(Object.keys(pl.overrides || {}).length)))),
            overrideList(data.policies, pl.overrides)),
          h('div', { class: 'card-foot' },
            h('a', { class: 'btn sm ghost', href: `#/consumers?plan=${encodeURIComponent(pl.id)}` }, 'Consumers'),
            h('button', { class: 'btn sm', onClick: () => open(pl) }, editable ? 'Edit overrides' : 'View')));
      })));
    };

    async function refresh() {
      await load(listEl, async () => {
        const [plans, policies, consumers] = await Promise.all([api.get('/plans'), entities('policies', { fresh: true }), entities('consumers', { fresh: true }).catch(() => [])]);
        data = { plans: api.list(plans, 'plans'), policies, consumers };
      }, () => { draw(); return listEl.firstChild || h('div'); });
    }

    mount(root,
      pageHead({ title: 'Plans', lede: 'Pricing tiers that raise or lower policy limits for every consumer on them.',
        actions: editable ? h('button', { class: 'btn primary', onClick: () => open(null) }, icon('plus', 'sm'), 'New plan') : null }),
      h('div', { class: 'callout mt-8' }, icon('info'), h('div', {}, 'Effective limit = ', h('strong', {}, 'consumer override'), ' › ', h('strong', {}, 'plan override'), ' › ', h('strong', {}, 'policy default'), '. Zero/empty fields inherit.')),
      h('div', { class: 'mt-16' }, listEl));
    await refresh();
    if (query.new && editable) open(null);
    else if (query.edit) {
      const p = data.plans.find(x => x.id === query.edit);
      if (p) open(p); else toast('warn', 'Plan not found', query.edit);
    }
  },
};
