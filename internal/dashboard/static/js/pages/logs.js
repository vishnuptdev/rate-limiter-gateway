// Live logs: SSE stream with pause/resume, filters, capped DOM (1000 rows), detail drawer, CSV export.
import { h, mount, debounce } from '../dom.js';
import { icon } from '../icons.js';
import * as api from '../api.js';
import * as fmt from '../format.js';
import { entities } from '../state.js';
import { decisionBadge, statusCode, drawer, copyButton, emptyState, errorState, toast } from '../ui.js';
import { select } from '../forms.js';
import { replaceQuery, go } from '../router.js';

const MAX = 1000;
const STATUS = { '': [null, null], '2xx': [200, 299], '3xx': [300, 399], '4xx': [400, 499], '429': [429, 429], '5xx': [500, 599] };
const DECISIONS = ['allowed', 'limited', 'shadow_limited', 'unauthorized', 'no_route', 'error'];
const CSV_COLS = ['time', 'id', 'decision', 'status', 'method', 'host', 'path', 'route_id', 'consumer_id', 'consumer_name', 'client_ip', 'policy_id', 'rate_key', 'limit', 'remaining', 'latency_ms', 'upstream_ms', 'bytes_out', 'source', 'user_agent', 'error'];

function csv(rows) {
  const esc = v => {
    if (v == null) return '';
    let s = String(v);
    // Neutralise spreadsheet formulas, but leave plain numbers (e.g. -1, +5, -0.25, 1e3) alone.
    if (/^[=+\-@\t\r]/.test(s) && !/^[+-]?(\d+\.?\d*|\.\d+)(e[+-]?\d+)?$/i.test(s)) s = "'" + s;
    return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  return [CSV_COLS.join(','), ...rows.map(r => CSV_COLS.map(c => esc(r[c])).join(','))].join('\r\n');
}

export function saveBlob(blob, name) {
  const url = URL.createObjectURL(blob);
  const a = h('a', { href: url, download: name, class: 'hidden' });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

export function logDetail(e) {
  const dl = (pairs) => h('dl', { class: 'dl' }, pairs.filter(([, v]) => v !== undefined && v !== null && v !== '').map(([k, v]) => [h('dt', {}, k), h('dd', {}, v)]));
  const actions = h('div', { class: 'row wrap' },
    e.policy_id && e.rate_key ? h('a', { class: 'btn sm', href: `#/limits?policy_id=${encodeURIComponent(e.policy_id)}&key=${encodeURIComponent(e.rate_key)}` }, icon('search', 'sm'), 'Inspect bucket') : null,
    h('a', { class: 'btn sm', href: `#/simulator?method=${encodeURIComponent(e.method)}&host=${encodeURIComponent(e.host)}&path=${encodeURIComponent(e.path)}&ip=${encodeURIComponent(e.client_ip || '')}` }, icon('flask', 'sm'), 'Simulate'),
    e.consumer_id ? h('a', { class: 'btn sm', href: `#/consumers/${encodeURIComponent(e.consumer_id)}` }, icon('user', 'sm'), 'Consumer') : null,
    copyButton(() => JSON.stringify(e, null, 2), { label: 'Copy JSON' }));
  return drawer({
    title: `${e.method} ${e.path}`, sub: `${fmt.dateTime(e.time)} · ${e.id}`,
    body: h('div', { class: 'stack loose' },
      h('div', { class: 'row wrap' }, decisionBadge(e.decision), statusCode(e.status), h('span', { class: 'badge mono' }, e.source || 'proxy')),
      e.error ? h('div', { class: 'callout crit' }, icon('alertCircle'), h('div', {}, e.error)) : null,
      actions,
      h('section', { class: 'stack tight' }, h('h3', {}, 'Request'), dl([
        ['Time', fmt.dateTime(e.time) + ' (' + fmt.timeMs(e.time) + ')'], ['Method', e.method], ['Host', e.host], ['Path', h('code', {}, e.path)],
        ['Client IP', e.client_ip], ['User agent', e.user_agent]])),
      h('section', { class: 'stack tight' }, h('h3', {}, 'Decision'), dl([
        ['Route', e.route_id ? h('a', { href: `#/routes?edit=${encodeURIComponent(e.route_id)}` }, e.route_name || e.route_id) : 'No route matched'],
        ['Consumer', e.consumer_id ? h('a', { href: `#/consumers/${encodeURIComponent(e.consumer_id)}` }, e.consumer_name || e.consumer_id) : 'Anonymous'],
        ['Deciding policy', e.policy_id ? h('a', { href: `#/policies?edit=${encodeURIComponent(e.policy_id)}` }, e.policy_id) : undefined],
        ['Rate key', e.rate_key ? h('code', {}, e.rate_key) : undefined],
        ['Limit', e.limit ? `${fmt.int(e.remaining)} of ${fmt.int(e.limit)} remaining` : undefined]])),
      h('section', { class: 'stack tight' }, h('h3', {}, 'Timing'), dl([
        ['Gateway latency', fmt.ms(e.latency_ms)], ['Upstream', e.upstream_ms ? fmt.ms(e.upstream_ms) : 'Not proxied'],
        ['Overhead', e.upstream_ms ? fmt.ms(Math.max(0, e.latency_ms - e.upstream_ms)) : undefined], ['Bytes out', fmt.bytes(e.bytes_out)]]))),
  });
}

export default {
  async render({ root, query, wide }) {
    wide();
    const f = { q: query.q || '', decision: query.decision || '', route_id: query.route_id || '', consumer_id: query.consumer_id || '', policy_id: query.policy_id || '', status: query.status || '' };
    let rows = [];          // newest first, mirrors DOM order
    let pending = [];       // received while paused
    let paused = false;
    let closeStream = null;
    let queue = [];
    let raf = 0;
    let state = 'connecting';
    const trData = new WeakMap();

    const search = h('input', { class: 'input', type: 'search', placeholder: 'Search path, IP, key, consumer…', 'aria-label': 'Search logs', value: f.q, dataset: { search: '1' } });
    const decision = select({ cls: 'sm', 'aria-label': 'Decision', value: f.decision, options: [{ value: '', label: 'All decisions' }, ...DECISIONS.map(d => ({ value: d, label: fmt.DECISION_LABEL[d] }))] });
    const status = select({ cls: 'sm', 'aria-label': 'Status', value: f.status, options: [{ value: '', label: 'Any status' }, '2xx', '3xx', '4xx', '429', '5xx'] });
    const routeSel = select({ cls: 'sm', 'aria-label': 'Route', options: [{ value: '', label: 'All routes' }] });
    const consSel = select({ cls: 'sm hide-sm', 'aria-label': 'Consumer', options: [{ value: '', label: 'All consumers' }] });
    const policyChip = h('span');
    const fillSel = (sel, items, cur, all) => { mount(sel, h('option', { value: '' }, all), items.map(x => h('option', { value: x.id }, x.name || x.id))); sel.value = cur; };
    entities('routes').then(rs => fillSel(routeSel, rs, f.route_id, 'All routes')).catch(() => {});
    entities('consumers').then(cs => fillSel(consSel, cs, f.consumer_id, 'All consumers')).catch(() => {});
    if (f.route_id) mount(routeSel, h('option', { value: f.route_id }, f.route_id));
    if (f.consumer_id) mount(consSel, h('option', { value: f.consumer_id }, f.consumer_id));

    const pauseBtn = h('button', { class: 'btn sm', type: 'button' });
    const exportBtn = h('button', { class: 'btn sm', type: 'button', 'aria-label': 'Export CSV' }, icon('download', 'sm'), h('span', { class: 'hide-sm' }, 'Export CSV'));
    const clearBtn = h('button', { class: 'btn sm ghost', type: 'button' }, 'Clear');
    const tbody = h('tbody');
    const tableEl = h('table', { class: 'table logs' },
      h('caption', { class: 'sr-only' }, 'Request log, newest first'),
      h('thead', {}, h('tr', {},
        h('th', { scope: 'col' }, 'Time'), h('th', { scope: 'col' }, 'Decision'), h('th', { scope: 'col', class: 'hide-sm' }, 'Status'),
        h('th', { scope: 'col' }, 'Request'), h('th', { scope: 'col', class: 'hide-md' }, 'Route'), h('th', { scope: 'col', class: 'hide-sm' }, 'Consumer / IP'),
        h('th', { scope: 'col', class: 'hide-md' }, 'Rate key'), h('th', { scope: 'col', class: 'num' }, 'Latency'))),
      tbody);
    const emptyEl = h('div');
    const newPill = h('div', { class: 'new-pill hidden' }, h('button', { class: 'btn primary sm', type: 'button', onClick: () => setPaused(false) }, icon('arrowUp', 'sm'), h('span', {}, '')));
    const wrap = h('div', { class: 'table-wrap' }, newPill, tableEl, emptyEl);
    const statusDot = h('span', { class: 'dot' });
    const statusText = h('span');
    const countText = h('span', { class: 'tnum' });
    const olderBtn = h('button', { class: 'btn xs ghost', type: 'button' }, 'Load older');

    mount(root,
      h('div', { class: 'page-head' },
        h('div', { class: 'grow' }, h('h1', {}, 'Live logs'), h('p', { class: 'lede' }, 'Every request the gateway decides on, streamed as it happens. Allowed requests may be sampled; limited and errors are always logged.')),
        h('div', { class: 'page-actions' }, pauseBtn, exportBtn, clearBtn)),
      h('section', { class: 'card logs-shell' },
        h('div', { class: 'toolbar' },
          h('div', { class: 'input-wrap' }, icon('search'), search, h('kbd', { class: 'hide-sm' }, '/')),
          decision, status, routeSel, consSel, policyChip),
        wrap,
        h('div', { class: 'logs-status' }, statusDot, statusText, h('span', { class: 'grow' }), countText, olderBtn)));

    function drawPolicyChip() {
      mount(policyChip, f.policy_id ? h('span', { class: 'chip' }, 'policy: ' + f.policy_id, h('button', { type: 'button', 'aria-label': 'Clear policy filter', onClick: () => { f.policy_id = ''; drawPolicyChip(); restart(); } }, icon('x'))) : null);
    }
    drawPolicyChip();

    function setPaused(p) {
      paused = p;
      mount(pauseBtn, icon(p ? 'play' : 'pause', 'sm'), p ? 'Resume' : 'Pause');
      pauseBtn.setAttribute('aria-pressed', String(p));
      if (!p && pending.length) { const pend = pending; pending = []; insert(pend.reverse(), false); wrap.scrollTop = 0; }
      drawStatus();
    }

    function drawStatus() {
      const live = state === 'open' && !paused;
      statusDot.className = `dot ${live ? 'live' : state === 'reconnecting' ? 'warn' : ''}`;
      statusText.textContent = paused ? 'Paused' : { connecting: 'Connecting…', open: 'Streaming live', reconnecting: 'Reconnecting…', closed: 'Disconnected' }[state] || state;
      countText.textContent = `${fmt.int(rows.length)} rows${rows.length >= MAX ? ' (max)' : ''}`;
      newPill.classList.toggle('hidden', !pending.length);
      newPill.querySelector('span').textContent = `${fmt.int(pending.length)}${pending.length >= MAX ? '+' : ''} new — resume`;
      mount(emptyEl, rows.length ? null : emptyState({ icon: 'logs', title: hasFilters() ? 'No matching requests' : 'Waiting for traffic', text: hasFilters() ? 'Nothing matches these filters yet. New matching requests will appear here live.' : 'Requests through the gateway will appear here as they happen.', compact: true, action: hasFilters() ? h('button', { class: 'btn sm', onClick: resetFilters }, 'Clear filters') : null }));
      olderBtn.classList.toggle('hidden', !rows.length || rows.length >= MAX);
    }

    const hasFilters = () => !!(f.q || f.decision || f.route_id || f.consumer_id || f.policy_id || f.status);
    function resetFilters() {
      Object.assign(f, { q: '', decision: '', route_id: '', consumer_id: '', policy_id: '', status: '' });
      search.value = ''; decision.value = ''; status.value = ''; routeSel.value = ''; consSel.value = '';
      drawPolicyChip(); restart();
    }

    // Auto-layout tables ignore max-width on cells, so truncate an inner block instead.
    const cell = (w, content, title) => h('span', { class: 'trunc', title: title || null, style: { display: 'block', maxWidth: w } }, content);
    function row(e, fresh) {
      const tr = h('tr', { class: `clickable ${fresh ? 'row-new' : ''}`, tabindex: '0' },
        h('td', { class: 'mono nowrap muted', title: fmt.dateTime(e.time) }, fmt.timeMs(e.time)),
        h('td', {}, decisionBadge(e.decision)),
        h('td', { class: 'hide-sm' }, statusCode(e.status)),
        h('td', {}, cell('min(420px, 52vw)', [h('span', { class: 'method' }, e.method), ' ', h('span', { class: 'mono' }, e.path)], `${e.method} ${e.path}`)),
        h('td', { class: 'hide-md' }, cell('160px', e.route_name || e.route_id || h('span', { class: 'muted' }, '—'))),
        h('td', { class: 'hide-sm' }, cell('180px', e.consumer_name || h('span', { class: 'mono muted' }, e.client_ip))),
        h('td', { class: 'hide-md mono muted' }, cell('200px', e.rate_key || '—', e.rate_key)),
        h('td', { class: 'num mono nowrap' }, fmt.ms(e.latency_ms)));
      trData.set(tr, e);
      return tr;
    }
    const open = tr => { const e = trData.get(tr); if (e) logDetail(e); };
    tbody.addEventListener('click', ev => { const tr = ev.target.closest('tr'); if (tr) open(tr); });
    tbody.addEventListener('keydown', ev => {
      const tr = ev.target.closest('tr');
      if (!tr) return;
      if (ev.key === 'Enter') open(tr);
      else if (ev.key === 'ArrowDown' && tr.nextElementSibling) { ev.preventDefault(); tr.nextElementSibling.focus(); }
      else if (ev.key === 'ArrowUp' && tr.previousElementSibling) { ev.preventDefault(); tr.previousElementSibling.focus(); }
    });

    /** entries newest-first; prepend (live) or append (history). */
    function insert(entries, append, fresh = true) {
      if (!entries.length) return;
      const frag = document.createDocumentFragment();
      entries.forEach(e => frag.appendChild(row(e, fresh && !append)));
      if (append) { tbody.appendChild(frag); rows = rows.concat(entries); }
      else { tbody.insertBefore(frag, tbody.firstChild); rows = entries.concat(rows); }
      while (rows.length > MAX) { rows.pop(); tbody.lastChild.remove(); }
      drawStatus();
    }

    function onEntry(e) {
      if (paused) {
        pending.push(e);
        if (pending.length > MAX) pending.shift();
        drawStatusSoon();
        return;
      }
      queue.push(e);
      if (!raf) raf = requestAnimationFrame(() => { raf = 0; const q = queue; queue = []; insert(q.reverse(), false); });
    }
    let st = 0;
    const drawStatusSoon = () => { if (!st) st = setTimeout(() => { st = 0; drawStatus(); }, 250); };

    function params() {
      const [mn, mx] = STATUS[f.status] || [null, null];
      return { decision: f.decision, route_id: f.route_id, consumer_id: f.consumer_id, policy_id: f.policy_id, q: f.q, status_min: mn, status_max: mx };
    }

    let gen = 0;
    async function restart() {
      replaceQuery({ ...f });
      if (closeStream) closeStream();
      const my = ++gen;
      rows = []; pending = []; queue = [];
      mount(tbody);
      mount(emptyEl, h('div', { class: 'card-body' }, h('div', { class: 'skel line' }), h('div', { class: 'skel line mt-8' }), h('div', { class: 'skel line mt-8' })));
      try {
        const res = await api.get('/logs', { ...params(), limit: 200 });
        if (my !== gen) return;
        insert(api.list(res, 'entries'), true, false);
      } catch (e) {
        if (my !== gen) return;
        mount(emptyEl, errorState(e, restart));
      }
      if (my !== gen) return;
      drawStatus();
      closeStream = api.stream(params(), onEntry, s => { state = s; drawStatus(); });
    }

    olderBtn.addEventListener('click', async () => {
      const last = rows[rows.length - 1];
      if (!last) return;
      try {
        const res = await api.get('/logs', { ...params(), before: last.id, limit: Math.min(200, MAX - rows.length) });
        const more = api.list(res, 'entries');
        if (!more.length) toast('info', 'No older entries in the buffer');
        insert(more, true, false);
      } catch (e) { toast('crit', 'Couldn’t load older entries', e.friendly); }
    });
    pauseBtn.addEventListener('click', () => setPaused(!paused));
    clearBtn.addEventListener('click', () => { rows = []; pending = []; mount(tbody); drawStatus(); });
    exportBtn.addEventListener('click', () => {
      if (!rows.length) { toast('info', 'Nothing to export yet'); return; }
      saveBlob(new Blob([csv(rows)], { type: 'text/csv' }), `rateguard-logs-${new Date().toISOString().replace(/[:.]/g, '-')}.csv`);
      toast('good', `Exported ${fmt.int(rows.length)} rows`);
    });
    search.addEventListener('input', debounce(() => { f.q = search.value.trim(); restart(); }, 300));
    decision.addEventListener('change', () => { f.decision = decision.value; restart(); });
    status.addEventListener('change', () => { f.status = status.value; restart(); });
    routeSel.addEventListener('change', () => { f.route_id = routeSel.value; restart(); });
    consSel.addEventListener('change', () => { f.consumer_id = consSel.value; restart(); });
    const onVis = () => { /* keep streaming in background; DOM work is batched by rAF */ };
    document.addEventListener('visibilitychange', onVis);

    setPaused(false);
    await restart();
    return () => { gen++; if (closeStream) closeStream(); cancelAnimationFrame(raf); clearTimeout(st); document.removeEventListener('visibilitychange', onVis); };
  },
};

export { go };
