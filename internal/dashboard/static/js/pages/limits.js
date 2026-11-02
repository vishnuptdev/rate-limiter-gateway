// Limits inspector: peek at a live bucket and reset it.
import { h, mount, nextId } from '../dom.js';
import { icon } from '../icons.js';
import * as api from '../api.js';
import * as fmt from '../format.js';
import { can, entities } from '../state.js';
import { pageHead, card, badge, emptyState, errorState, busy, toast, confirm, table, copyButton } from '../ui.js';
import { field, input, select, showFormError, clearProblems } from '../forms.js';
import { replaceQuery } from '../router.js';
import { keyLabel } from './policies.js';

export default {
  async render({ root, query }) {
    const editable = can('edit');
    let policies = [];
    let countdown = 0;
    const policySel = select({ options: [{ value: '', label: 'Loading policies…' }], 'aria-label': 'Policy' });
    const key = input({ value: query.key || '', placeholder: 'acme-corp', mono: true, dataset: { search: '1' } });
    const keyHint = h('div', { class: 'hint' }, 'The composite key: key_by parts joined with “|”.');
    const formId = nextId('lim');
    const peekBtn = h('button', { class: 'btn primary', type: 'submit', form: formId }, icon('search', 'sm'), 'Peek');
    const form = h('form', { class: 'form', id: formId, novalidate: true },
      field({ label: 'Policy', name: 'policy_id', control: policySel }),
      h('div', { class: 'field', dataset: { field: 'key' } }, h('label', { for: key.id = nextId('k') }, 'Bucket key'), key, keyHint));
    const result = h('div', {}, emptyState({ icon: 'gauge', title: 'Inspect a bucket', text: 'Pick a policy and a key to see how much capacity is left — and reset it if a customer got stuck.' }));
    const recent = h('div', {}, h('div', { class: 'card-body' }, h('div', { class: 'skel line' }), h('div', { class: 'skel line mt-8' })));

    const paintHint = () => {
      const p = policies.find(x => x.id === policySel.value);
      if (!p) return;
      mount(keyHint, 'Format: ', h('code', {}, (p.key_by || []).map(keyLabel).join(' | ') || '—'),
        (p.key_by || []).includes('api_key') ? ' (api_key = first 16 hex of the key’s SHA-256)' : '', '.');
      key.placeholder = (p.key_by || []).map(k => k === 'consumer' ? 'acme-corp' : k === 'ip' ? '203.0.113.7' : k === 'global' ? 'global' : k === 'path' ? '/v1/orders' : k === 'route' ? 'orders-api' : k === 'method' ? 'GET' : k === 'api_key' ? '3f9a1c0be2d84e71' : 'value').join('|');
    };
    policySel.addEventListener('change', paintHint);

    async function peek() {
      clearProblems(form);
      clearInterval(countdown);
      if (!policySel.value) { showFormError(form, { status: 422, problems: [{ field: 'policy_id', message: 'Choose a policy' }] }); return; }
      replaceQuery({ policy_id: policySel.value, key: key.value });
      try {
        const r = await api.get('/limits', { policy_id: policySel.value, key: key.value });
        showResult(r);
      } catch (e) {
        if (e.status === 422) showFormError(form, e);
        else mount(result, errorState(e, peek));
      }
    }

    function showResult(r) {
      const p = policies.find(x => x.id === r.policy_id) || {};
      const used = Math.max(0, (r.limit || 0) - (r.remaining || 0));
      const ratio = r.limit ? r.remaining / r.limit : 1;
      const resetEl = h('span', { class: 'tnum' }, `${r.reset_s || 0}s`);
      let left = r.reset_s || 0;
      if (left > 0) countdown = setInterval(() => { left = Math.max(0, left - 1); resetEl.textContent = `${left}s`; if (!left) clearInterval(countdown); }, 1000);
      const resetBtn = editable ? h('button', { class: 'btn danger-ghost', type: 'button' }, icon('reset', 'sm'), 'Reset bucket') : null;
      if (resetBtn) resetBtn.addEventListener('click', async () => {
        if (!(await confirm({ title: 'Reset this bucket?', message: h('p', { class: 'subtle' }, 'The key ', h('code', {}, r.engine_key), ' gets its full limit back immediately. The reset is recorded in the audit log.'), confirmLabel: 'Reset bucket', danger: true }))) return;
        await busy(resetBtn, async () => {
          try { await api.post('/limits/reset', { policy_id: r.policy_id, key: r.key }); toast('good', 'Bucket reset', r.engine_key); await peek(); }
          catch (e) { toast('crit', 'Couldn’t reset bucket', e.friendly); }
        });
      });
      mount(result, h('div', { class: 'stack' },
        h('div', { class: 'row wrap' },
          r.exists ? badge('Active bucket', 'good', 'check') : badge('No state yet', '', 'info'),
          ratio === 0 ? badge('Exhausted', 'serious', 'ban') : ratio < 0.2 ? badge('Nearly exhausted', 'warn', 'alert') : null,
          h('span', { class: 'grow' }),
          h('span', { class: 'copy-inline small muted' }, h('code', {}, r.engine_key), copyButton(r.engine_key, { size: 'xs', iconOnly: true, label: 'Copy engine key' }))),
        r.exists ? null : h('p', { class: 'small muted' }, 'The engine has no state for this key — it hasn’t been used within the current window, so it has the full limit.'),
        h('div', { class: 'stat-inline' },
          h('div', { class: 's' }, h('div', { class: 'k' }, 'Remaining'), h('div', { class: 'big-number' }, fmt.int(r.remaining), h('span', { class: 'muted', style: { fontSize: '18px', fontWeight: '500' } }, ` / ${fmt.int(r.limit)}`))),
          h('div', { class: 's' }, h('div', { class: 'k' }, 'Used'), h('div', { class: 'v' }, fmt.int(used))),
          h('div', { class: 's' }, h('div', { class: 'k' }, p.algorithm === 'concurrency' ? 'In flight' : 'Resets in'), h('div', { class: 'v' }, p.algorithm === 'concurrency' ? fmt.int(used) : resetEl))),
        h('div', { class: `meter single tall ${ratio === 0 ? 'crit' : ratio < 0.2 ? 'warn' : 'good'}`, role: 'meter', 'aria-valuemin': '0', 'aria-valuemax': String(r.limit || 0), 'aria-valuenow': String(r.remaining || 0), 'aria-label': 'Remaining capacity' },
          h('span', { style: { width: `${Math.max(0, Math.min(100, ratio * 100))}%` } })),
        h('dl', { class: 'dl' },
          h('dt', {}, 'Policy'), h('dd', {}, h('a', { href: `#/policies?edit=${encodeURIComponent(r.policy_id)}` }, p.name || r.policy_id), p.algorithm ? h('span', { class: 'muted' }, ` · ${fmt.ALGO_LABEL[p.algorithm]} · ${fmt.policySummary(p)}`) : null),
          h('dt', {}, 'Key'), h('dd', {}, h('code', {}, r.key || '(empty)'))),
        h('div', { class: 'row wrap' }, h('button', { class: 'btn', type: 'button', onClick: peek }, icon('refresh', 'sm'), 'Refresh'), resetBtn,
          h('span', { class: 'grow' }), h('a', { class: 'btn ghost', href: `#/logs?policy_id=${encodeURIComponent(r.policy_id)}&q=${encodeURIComponent(r.key || '')}` }, 'Related logs', icon('arrowRight', 'sm')))));
    }

    form.addEventListener('submit', async e => { e.preventDefault(); await busy(peekBtn, peek); });

    mount(root,
      pageHead({ title: 'Limits inspector', lede: 'Look inside a live rate-limit bucket and reset it — e.g. when a customer is stuck after a bug.' }),
      h('div', { class: 'grid side-main' },
        h('div', { class: 'stack' },
          h('section', { class: 'card' }, h('div', { class: 'card-head' }, h('h2', {}, 'Lookup')), h('div', { class: 'card-body' }, form), h('div', { class: 'card-foot' }, peekBtn)),
          card({ title: 'Recently limited', desc: 'Click to inspect', flush: true, body: recent })),
        card({ title: 'Bucket', body: result })));

    try {
      policies = await entities('policies', { fresh: true });
      mount(policySel, h('option', { value: '' }, 'Choose a policy…'), policies.map(p => h('option', { value: p.id }, `${p.name} — ${fmt.policySummary(p)}`)));
      policySel.value = query.policy_id || '';
      paintHint();
      if (query.policy_id && query.key !== undefined) peek();
    } catch (e) { mount(result, errorState(e)); }

    try {
      const res = await api.get('/logs', { decision: 'limited', limit: 200 });
      const seen = new Map();
      api.list(res, 'entries').forEach(e => {
        if (!e.policy_id || !e.rate_key) return;
        const k = e.policy_id + '\u0000' + e.rate_key;
        const cur = seen.get(k) || { policy_id: e.policy_id, key: e.rate_key, label: e.consumer_name || e.client_ip, count: 0, last: e.time };
        cur.count++;
        seen.set(k, cur);
      });
      const rows = [...seen.values()].sort((a, b) => b.count - a.count).slice(0, 8);
      mount(recent, rows.length ? table({
        rows, dense: true, caption: 'Recently limited keys',
        onRow: r => { policySel.value = r.policy_id; key.value = r.key; paintHint(); peek(); },
        columns: [
          { key: 'key', label: 'Key', render: r => h('div', {}, h('div', { class: 'mono small trunc', style: { maxWidth: '200px' } }, r.key), h('div', { class: 'cell-sub' }, r.policy_id)) },
          { key: 'count', label: '429s', align: 'right', render: r => h('span', { class: 'tnum' }, fmt.int(r.count)) },
        ],
      }) : emptyState({ icon: 'checkCircle', title: 'Nothing limited recently', compact: true }));
    } catch (e) { mount(recent, errorState(e)); }

    return () => clearInterval(countdown);
  },
};
