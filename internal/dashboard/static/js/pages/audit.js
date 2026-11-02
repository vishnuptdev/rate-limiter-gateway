// Audit log (admin): every configuration and security-relevant change.
import { h, mount } from '../dom.js';
import { icon } from '../icons.js';
import * as api from '../api.js';
import * as fmt from '../format.js';
import { pageHead, table, badge, emptyState, errorState, skeletonRows, toast } from '../ui.js';
import { select } from '../forms.js';
import { filterRows, searchBox, noMatches } from '../crud.js';
import { replaceQuery } from '../router.js';
import { saveBlob } from './logs.js';

const PAGE = 100;
const kindOf = a => {
  if (/delete|revoke/.test(a)) return 'crit';
  if (/create|issue/.test(a)) return 'good';
  if (/reset|import/.test(a)) return 'warn';
  if (/login|logout|password/.test(a)) return 'info';
  return '';
};

export default {
  async render({ root, query }) {
    let q = query.q || '';
    let type = query.type || '';
    let entries = [];
    let more = true;
    const listEl = h('div', {}, skeletonRows(8, 5));
    const typeSel = select({ cls: 'sm', 'aria-label': 'Target type', options: [{ value: '', label: 'All targets' }] });
    const moreBtn = h('button', { class: 'btn sm', type: 'button' }, 'Load older');
    const footer = h('div', { class: 'logs-status' }, h('span', { class: 'tnum' }), h('span', { class: 'grow' }), moreBtn);
    const exportBtn = h('button', { class: 'btn', type: 'button', onClick: () => {
      saveBlob(new Blob([entries.map(e => JSON.stringify(e)).join('\n') + '\n'], { type: 'application/x-ndjson' }), `rateguard-audit-${new Date().toISOString().slice(0, 10)}.jsonl`);
    } }, icon('download', 'sm'), 'Export JSONL');

    const draw = () => {
      let rows = filterRows(entries, q, ['actor', 'action', 'target_id', 'summary', 'ip']);
      if (type) rows = rows.filter(e => e.target_type === type);
      footer.firstChild.textContent = `${fmt.int(entries.length)} entries loaded`;
      moreBtn.classList.toggle('hidden', !more);
      if (!entries.length) { mount(listEl, emptyState({ icon: 'scroll', title: 'No audit entries yet', text: 'Changes to routes, policies, plans, consumers, settings, users and tokens are recorded here.' })); return; }
      mount(listEl, rows.length ? table({
        rows, caption: 'Audit log', sortKey: 'time', sortDir: 'desc',
        columns: [
          { key: 'time', label: 'When', sort: true, defaultDir: 'desc', render: e => h('div', { title: fmt.dateTime(e.time) }, h('div', { class: 'small nowrap' }, fmt.ago(e.time)), h('div', { class: 'cell-sub nowrap' }, fmt.dateTime(e.time))) },
          { key: 'actor', label: 'Actor', sort: true, render: e => h('div', { class: 'row' }, h('span', { class: 'avatar', 'aria-hidden': 'true' }, e.actor_type === 'token' ? icon('token', 'sm') : (e.actor || '?').slice(0, 2)),
            h('div', {}, h('div', { class: 'cell-title' }, e.actor), h('div', { class: 'cell-sub' }, e.actor_type === 'token' ? 'API token' : e.actor_type === 'system' ? 'System' : 'User'))) },
          { key: 'action', label: 'Action', sort: true, render: e => badge(e.action, kindOf(e.action), null, 'mono square') },
          { key: 'target_id', label: 'Target', hide: 'sm', sort: true, render: e => h('div', {}, h('div', { class: 'mono small' }, e.target_id || '—'), h('div', { class: 'cell-sub' }, e.target_type)) },
          { key: 'summary', label: 'Summary', render: e => h('span', { class: 'small' }, e.summary) },
          { key: 'ip', label: 'IP', hide: 'md', render: e => h('span', { class: 'mono small muted' }, e.ip || '—') },
        ],
      }) : noMatches(() => { q = ''; type = ''; typeSel.value = ''; root.querySelector('[data-search]').value = ''; draw(); }));
    };

    async function fetchPage(before) {
      const res = await api.get('/audit', { limit: PAGE, before });
      const got = api.list(res, 'entries');
      more = got.length >= PAGE;
      entries = entries.concat(got);
      const types = [...new Set(entries.map(e => e.target_type).filter(Boolean))].sort();
      mount(typeSel, h('option', { value: '' }, 'All targets'), types.map(t => h('option', { value: t }, t)));
      typeSel.value = type;
      draw();
    }
    moreBtn.addEventListener('click', async () => {
      const last = entries[entries.length - 1];
      try { await fetchPage(last && last.id); } catch (e) { toast('crit', 'Couldn’t load more', e.friendly); }
    });
    typeSel.addEventListener('change', () => { type = typeSel.value; replaceQuery({ type }); draw(); });

    mount(root,
      pageHead({ title: 'Audit log', lede: 'Who changed what, when, and from where. Entries are append-only.', actions: exportBtn }),
      h('section', { class: 'card' },
        h('div', { class: 'toolbar' }, searchBox('Search actor, action, target…', q, v => { q = v; replaceQuery({ q: v }); draw(); }), typeSel),
        listEl, footer));
    try { await fetchPage(); } catch (e) { mount(listEl, errorState(e, () => location.reload())); }
  },
};
