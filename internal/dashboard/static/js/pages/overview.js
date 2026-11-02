// Overview: KPIs with sparklines, traffic + latency charts, status breakdown, top-N lists.
import { h, mount } from '../dom.js';
import { icon } from '../icons.js';
import * as api from '../api.js';
import * as fmt from '../format.js';
import { timeChart, sparkline, segmentBar, SERIES } from '../charts.js';
import { seg, card, errorState, emptyState, skeletonCard, table } from '../ui.js';
import { replaceQuery } from '../router.js';

const RANGES = [{ value: '15m', label: '15m' }, { value: '1h', label: '1h' }, { value: '6h', label: '6h' }, { value: '24h', label: '24h' }];
const TRAFFIC = [
  { key: 'allowed', label: 'Allowed', color: SERIES(1) },
  { key: 'limited', label: 'Limited', color: SERIES(2) },
  { key: 'shadow_limited', label: 'Shadow limited', color: SERIES(3) },
  { key: 'errors', label: 'Errors', color: SERIES(4) },
];
const LATENCY = [
  { key: 'p50_ms', label: 'p50', color: SERIES(1) },
  { key: 'p95_ms', label: 'p95', color: SERIES(2) },
  { key: 'p99_ms', label: 'p99', color: SERIES(3) },
];
const STATUS = {
  '2xx': ['var(--good)', '2xx success'], '3xx': [SERIES(1), '3xx redirect'], '4xx': ['var(--warn)', '4xx client error'],
  '429': ['var(--serious)', '429 rate limited'], '5xx': ['var(--crit)', '5xx server error'],
};

function kpi({ label, ic, value, unit, sub, spark, color }) {
  return h('div', { class: 'card kpi' },
    h('div', { class: 'kpi-label' }, icon(ic, 'sm'), label),
    h('div', { class: 'kpi-value' }, value, unit ? h('span', { class: 'unit' }, unit) : null),
    h('div', { class: 'kpi-sub' }, sub),
    h('div', { class: 'kpi-spark' }, spark ? sparkline(spark, { color }) : null));
}

function topList(items, { empty, href, labelSub, bar = '', valueFmt = fmt.compact }) {
  if (!items || !items.length) return emptyState({ icon: 'inbox', title: empty, compact: true });
  const max = Math.max(...items.map(i => i.count), 1);
  return h('ol', { class: 'toplist' }, items.slice(0, 7).map(it => h('li', {},
    h('span', { class: `bar ${bar}`, style: { width: `calc(${(it.count / max) * 100}% - 20px)` } }),
    h('span', { class: 'lbl' }, h('a', { href: href(it) }, it.label || it.id), labelSub && labelSub(it) ? h('small', {}, labelSub(it)) : null),
    h('span', { class: 'val' }, valueFmt(it.count)))));
}

export default {
  async render({ root, query }) {
    let range = RANGES.some(r => r.value === query.range) ? query.range : '1h';
    let auto = query.live !== '0';
    let kind = 'area';
    let timer = 0;
    let charts = [];
    const ac = new AbortController();

    const kpis = h('div', { class: 'grid kpis' }, Array.from({ length: 5 }, () => h('div', { class: 'card kpi' }, h('div', { class: 'skel line', style: { width: '50%' } }), h('div', { class: 'skel title mt-8' }), h('div', { class: 'skel line mt-8', style: { width: '70%' } }))));
    const trafficEl = h('div', {}, h('div', { class: 'skel block', style: { height: '260px' } }));
    const latencyEl = h('div', {}, h('div', { class: 'skel block', style: { height: '200px' } }));
    const statusEl = h('div', {}, h('div', { class: 'skel block', style: { height: '200px' } }));
    const tops = h('div', { class: 'grid four' }, Array.from({ length: 4 }, () => skeletonCard(180)));
    const lede = h('p', { class: 'lede' }, 'Gateway traffic and rate-limit decisions.');
    const liveDot = h('span', { class: `dot ${auto ? 'live' : ''}` });
    const liveBtn = h('button', { class: 'btn sm', type: 'button', 'aria-pressed': String(auto), title: 'Auto-refresh every few seconds' }, liveDot, 'Live');
    liveBtn.addEventListener('click', () => {
      auto = !auto;
      liveBtn.setAttribute('aria-pressed', String(auto));
      liveDot.className = `dot ${auto ? 'live' : ''}`;
      replaceQuery({ live: auto ? '' : '0' });
      schedule();
    });
    const refreshBtn = h('button', { class: 'btn sm icon-only', type: 'button', 'aria-label': 'Refresh now', title: 'Refresh now', onClick: () => refresh() }, icon('refresh', 'sm'));
    const rangeSeg = seg(RANGES, range, v => { range = v; replaceQuery({ range: v }); refresh(true); }, { label: 'Time range' });
    const kindSeg = seg([{ value: 'area', label: 'Area' }, { value: 'bar', label: 'Bars' }, { value: 'table', label: 'Table' }], kind, v => { kind = v; drawTraffic(); }, { label: 'Chart type' });
    const updated = h('span', { class: 'xs muted tnum hide-sm' });

    mount(root,
      h('div', { class: 'page-head' },
        h('div', { class: 'grow' }, h('h1', {}, 'Overview'), lede),
        h('div', { class: 'page-actions' }, updated, rangeSeg, liveBtn, refreshBtn)),
      h('div', { class: 'stack' },
        kpis,
        card({ title: 'Traffic', desc: 'Requests per interval by decision', actions: kindSeg, body: trafficEl }),
        h('div', { class: 'grid main-side' },
          card({ title: 'Gateway latency', desc: 'Percentiles per interval (time in gateway incl. upstream)', body: latencyEl }),
          card({ title: 'Status codes', desc: 'Last 24 hours', body: statusEl })),
        tops));

    let ts = null, ov = null;
    let trafficChart = null, latencyChart = null;

    function drawTraffic() {
      if (!ts) return;
      if (kind === 'table') {
        if (trafficChart) { trafficChart.destroy(); trafficChart = null; }
        const rows = ts.points.slice().reverse().map(p => ({ ...p, total: p.allowed + p.limited + p.errors }));
        mount(trafficEl, h('div', { class: 'table-wrap', style: { maxHeight: '320px', overflowY: 'auto' } }, table({
          dense: true, rows, caption: 'Traffic per interval',
          columns: [
            { key: 't', label: 'Interval start', render: r => fmt.dateTime(r.t), sort: r => r.t },
            ...TRAFFIC.map(se => ({ key: se.key, label: se.label, align: 'right', render: r => fmt.int(r[se.key]), sort: true })),
            { key: 'total', label: 'Total', align: 'right', render: r => fmt.int(r.total), sort: true },
          ],
        })));
        return;
      }
      if (!trafficChart) {
        trafficChart = timeChart(trafficEl, {
          series: TRAFFIC, points: ts.points, kind, stacked: true, height: 260,
          ariaLabel: `Requests per ${ts.step_s}s interval by decision`, empty: 'No traffic in this range',
          tipFmt: v => fmt.int(v), legendValues: (_, total) => fmt.compact(total),
        });
        charts.push(trafficChart);
      } else if (trafficChart) {
        trafficChart.setKind(kind);
        trafficChart.update(ts.points);
      }
    }

    function drawLatency() {
      if (!latencyChart) {
        latencyChart = timeChart(latencyEl, {
          series: LATENCY, points: ts.points, kind: 'line', stacked: false, height: 200,
          yFmt: v => (v >= 1000 ? (v / 1000).toFixed(1) + 's' : Math.round(v) + 'ms'), tipFmt: v => fmt.ms(v),
          ariaLabel: 'Latency percentiles', empty: 'No latency samples',
        });
        charts.push(latencyChart);
      } else latencyChart.update(ts.points);
    }

    function drawKpis() {
      const p = ts.points;
      const tot = p.map(x => x.allowed + x.limited + x.errors);
      const limRate = ov.requests ? ov.limited / ov.requests : 0;
      mount(kpis,
        kpi({ label: 'Requests · 24h', ic: 'pulse', value: fmt.compact(ov.requests), sub: [h('span', {}, `${fmt.int(ov.allowed)} allowed`)], spark: tot, color: SERIES(1) }),
        kpi({ label: 'Throughput', ic: 'zap', value: fmt.dec(ov.rps_1m), unit: 'req/s', sub: 'avg over last minute', spark: tot, color: SERIES(1) }),
        kpi({ label: 'Rate limited', ic: 'ban', value: fmt.compact(ov.limited), sub: [h('span', { class: `delta ${limRate > 0.08 ? 'up-bad' : ''}` }, fmt.pct(ov.limited, ov.requests)), ' of requests', ov.shadow_limited ? ` · ${fmt.compact(ov.shadow_limited)} shadow` : ''], spark: p.map(x => x.limited), color: SERIES(2) }),
        kpi({ label: 'Errors', ic: 'alertCircle', value: fmt.compact(ov.errors), sub: [h('span', {}, fmt.pct(ov.errors, ov.requests)), ' auth, routing & upstream'], spark: p.map(x => x.errors), color: SERIES(4) }),
        kpi({ label: 'Latency p95', ic: 'clock', value: fmt.ms(ov.p95_ms).replace(/ ms$/, ''), unit: / ms$/.test(fmt.ms(ov.p95_ms)) ? 'ms' : '', sub: `p50 ${fmt.ms(ov.p50_ms)} · p99 ${fmt.ms(ov.p99_ms)}`, spark: p.map(x => x.p95_ms), color: SERIES(2) }));
    }

    function drawStatus() {
      const sb = (ov.status_breakdown || []).filter(x => x.count > 0);
      const total = sb.reduce((a, x) => a + x.count, 0);
      if (!total) { mount(statusEl, emptyState({ icon: 'pulse', title: 'No responses yet', text: 'Send traffic through the gateway to see status codes.', compact: true })); return; }
      const parts = sb.map(x => ({ label: (STATUS[x.id] || [])[1] || x.label, value: x.count, color: (STATUS[x.id] || [SERIES(7)])[0] }));
      mount(statusEl, h('div', { class: 'stack' },
        h('div', {}, h('div', { class: 'big-number' }, fmt.pct(sb.filter(x => x.id === '2xx' || x.id === '3xx').reduce((a, x) => a + x.count, 0), total)), h('div', { class: 'small muted' }, 'success rate (2xx + 3xx)')),
        segmentBar(parts, { label: 'Status code distribution' }),
        h('div', { class: 'stack tight' }, sb.map((x, i) => h('div', { class: 'row small' },
          h('span', { class: 'swatch', style: { background: parts[i].color } }),
          h('span', { class: 'grow subtle' }, parts[i].label),
          h('span', { class: 'tnum muted' }, fmt.pct(x.count, total)),
          h('span', { class: 'tnum', style: { minWidth: '56px', textAlign: 'right', fontWeight: '600' } }, fmt.compact(x.count)))))));
    }

    function drawTops() {
      mount(tops,
        card({ title: 'Top limited keys', flush: true, body: topList(ov.top_limited_keys, { empty: 'Nothing limited — nice.', href: it => `#/logs?decision=limited&q=${encodeURIComponent(it.id)}`, labelSub: it => (it.label && it.label !== it.id ? it.id : ''), bar: '' }) }),
        card({ title: 'Top routes', flush: true, body: topList(ov.top_routes, { empty: 'No routed traffic', href: it => `#/logs?route_id=${encodeURIComponent(it.id)}`, bar: 's1' }) }),
        card({ title: 'Most limiting policies', flush: true, body: topList(ov.top_policies, { empty: 'No policy has limited anything', href: it => `#/policies?edit=${encodeURIComponent(it.id)}` }) }),
        card({ title: 'Top consumers', flush: true, body: topList(ov.top_consumers, { empty: 'No identified consumers', href: it => `#/consumers/${encodeURIComponent(it.id)}`, bar: 's1' }) }));
    }

    async function refresh(rangeChanged = false) {
      try {
        const [t, o] = await Promise.all([
          api.get('/timeseries', { range }, { signal: ac.signal }),
          api.get('/overview', undefined, { signal: ac.signal }),
        ]);
        ts = t; ov = o;
        ts.points = ts.points || [];
        drawKpis(); drawTraffic(); drawLatency(); drawStatus(); drawTops();
        if (ov.counts) {
          const c = ov.counts;
          mount(lede, 'Last 24 hours across ',
            h('a', { href: '#/routes' }, fmt.plural(c.routes, 'route')), ' · ',
            h('a', { href: '#/policies' }, fmt.plural(c.policies, 'policy', 'policies')), ' · ',
            h('a', { href: '#/plans' }, fmt.plural(c.plans, 'plan')), ' · ',
            h('a', { href: '#/consumers' }, fmt.plural(c.consumers, 'consumer')));
        }
        updated.textContent = 'Updated ' + fmt.time(Date.now());
      } catch (e) {
        if (e.name === 'AbortError') return;
        if (!ts) {
          mount(root.querySelector('.stack'), errorState(e, () => refresh()));
          return;
        }
        updated.textContent = 'Refresh failed · retrying';
      }
      if (rangeChanged) schedule();
    }

    function schedule() {
      clearTimeout(timer);
      if (!auto) return;
      const every = range === '15m' ? 5000 : range === '1h' ? 15000 : 30000;
      timer = setTimeout(async () => { if (!document.hidden) await refresh(); schedule(); }, every);
    }

    await refresh();
    schedule();
    return () => { clearTimeout(timer); ac.abort(); charts.forEach(c => c.destroy()); };
  },
};
