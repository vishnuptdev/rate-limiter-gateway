// Hand-rolled SVG charts: time series (stacked area / line / stacked bar) and
// sparklines. Colours come from CSS custom properties so both themes work;
// series use the validated categorical palette in fixed order.
import { h, s, mount, clear } from './dom.js';
import { compact, timeShort, dateTime } from './format.js';

export const SERIES = i => `var(--series-${i})`;

function niceMax(v) {
  if (v <= 0) return 1;
  const exp = Math.pow(10, Math.floor(Math.log10(v)));
  const f = v / exp;
  const nf = f <= 1 ? 1 : f <= 1.2 ? 1.2 : f <= 1.5 ? 1.5 : f <= 2 ? 2 : f <= 2.5 ? 2.5 : f <= 3 ? 3 : f <= 4 ? 4 : f <= 5 ? 5 : f <= 6 ? 6 : f <= 8 ? 8 : 10;
  return nf * exp;
}

const TICK_STEPS = [60e3, 2 * 60e3, 5 * 60e3, 10 * 60e3, 15 * 60e3, 30 * 60e3, 3600e3, 2 * 3600e3, 3 * 3600e3, 6 * 3600e3];

/**
 * timeChart(el, {series:[{key,label,color}], points:[{t,...}], kind:'area'|'line'|'bar',
 *   stacked, height, yFmt, tipFmt, empty, ariaLabel, totalLabel})
 * Returns {update(points), destroy()}.
 */
export function timeChart(el, opts) {
  const o = { kind: 'area', stacked: true, height: 240, yFmt: compact, tipFmt: v => compact(v), empty: 'No data for this range', ...opts };
  const hidden = new Set(o.hidden || []);
  let points = o.points || [];
  let width = 0;
  let hoverIdx = -1;

  const tip = h('div', { class: 'chart-tip', role: 'presentation' });
  const svgWrap = h('div', { class: 'chart-svg' });
  const legend = o.legend === false ? null : h('div', { class: 'legend mt-8' });
  const root = h('div', { class: 'chart' }, svgWrap, tip);
  mount(el, root, legend);

  function visible() { return o.series.filter(x => !hidden.has(x.key)); }

  function drawLegend() {
    if (!legend) return;
    const totals = {};
    o.series.forEach(se => { totals[se.key] = points.reduce((a, p) => a + (+p[se.key] || 0), 0); });
    mount(legend, o.series.map(se => {
      const b = h('button', { type: 'button', class: 'item', 'aria-pressed': String(!hidden.has(se.key)), title: 'Toggle ' + se.label },
        h('span', { class: `swatch ${o.kind === 'line' ? 'line' : ''}`, style: { background: se.color } }), se.label,
        o.legendValues ? h('span', { class: 'v' }, o.legendValues(se, totals[se.key])) : null);
      b.addEventListener('click', () => {
        if (hidden.has(se.key)) hidden.delete(se.key);
        else if (visible().length > 1) hidden.add(se.key);
        draw(); drawLegend();
      });
      return b;
    }));
  }

  function geometry() {
    const H = o.height;
    const vis = visible();
    let max = 0;
    for (const p of points) {
      if (o.stacked) max = Math.max(max, vis.reduce((a, se) => a + (+p[se.key] || 0), 0));
      else for (const se of vis) max = Math.max(max, +p[se.key] || 0);
    }
    const top = niceMax(max * 1.05);
    const ticks = [0, top / 4, top / 2, (3 * top) / 4, top];
    const labelW = Math.max(...ticks.map(t => o.yFmt(t).length)) * 6.6 + 10;
    const m = { l: Math.max(28, labelW), r: 8, t: 10, b: 24 };
    const W = Math.max(120, width);
    return { H, W, m, top, ticks, vis, iw: W - m.l - m.r, ih: H - m.t - m.b };
  }

  let G = null;
  function draw() {
    width = svgWrap.clientWidth || el.clientWidth || 600;
    G = geometry();
    const { H, W, m, top, ticks, vis, iw, ih } = G;
    const n = points.length;
    const svg = s('svg', { viewBox: `0 0 ${W} ${H}`, height: H, role: 'img', 'aria-label': o.ariaLabel || 'Time series chart', tabindex: '0', focusable: 'true' });
    const y = v => m.t + ih - (v / top) * ih;
    // grid + y ticks
    ticks.forEach((t, i) => {
      const yy = Math.round(y(t)) + 0.5;
      svg.appendChild(s('line', { class: i === 0 ? 'baseline' : 'grid-line', x1: m.l, x2: W - m.r, y1: yy, y2: yy }));
      svg.appendChild(s('text', { class: 'tick', x: m.l - 8, y: yy + 3.5, 'text-anchor': 'end' }, o.yFmt(t)));
    });
    if (!n) {
      mount(svgWrap, svg, h('div', { class: 'chart-empty' }, o.empty));
      return;
    }
    const isBar = o.kind === 'bar';
    const bw = iw / n;
    const x = i => (isBar ? m.l + i * bw + bw / 2 : m.l + (n === 1 ? iw / 2 : (i / (n - 1)) * iw));
    G.x = x; G.y = y; G.bw = bw;

    // x ticks
    const t0 = new Date(points[0].t).getTime(), t1 = new Date(points[n - 1].t).getTime();
    const span = Math.max(1, t1 - t0);
    const want = Math.max(2, Math.floor(iw / 90));
    const step = TICK_STEPS.find(st => span / st <= want) || TICK_STEPS[TICK_STEPS.length - 1];
    const xt = tt => m.l + ((tt - t0) / span) * (isBar ? iw - bw : iw) + (isBar ? bw / 2 : 0);
    for (let tt = Math.ceil(t0 / step) * step; tt <= t1; tt += step) {
      const xx = xt(tt);
      if (xx < m.l + 14 || xx > W - m.r - 14) continue;
      svg.appendChild(s('text', { class: 'tick', x: xx, y: H - 6, 'text-anchor': 'middle' }, timeShort(tt)));
    }

    const all = points.map(p => vis.map(se => +p[se.key] || 0));
    const totalZero = all.every(r => r.every(v => v === 0));
    const g = s('g');
    if (isBar) {
      const gap = bw >= 8 ? 2 : bw >= 3 ? 1 : 0;
      const w = Math.max(0.6, bw - gap);
      points.forEach((p, i) => {
        let acc = 0;
        vis.forEach((se, si) => {
          const v = all[i][si];
          if (!v) return;
          const y0 = y(acc), y1 = y(acc + v);
          acc += v;
          const hh = Math.max(0.75, y0 - y1);
          const r = s('rect', { class: 'bar', x: x(i) - w / 2, y: y0 - hh, width: w, height: hh, rx: w >= 6 && si === vis.length - 1 ? 2 : 0 });
          r.style.fill = se.color;
          g.appendChild(r);
        });
      });
    } else {
      const base = new Array(n).fill(0);
      vis.forEach((se, si) => {
        const tops = points.map((_, i) => (o.stacked ? base[i] + all[i][si] : all[i][si]));
        const linePath = tops.map((v, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join('');
        if (o.kind === 'area') {
          const bottom = o.stacked ? base.slice() : new Array(n).fill(0);
          let d = linePath;
          for (let i = n - 1; i >= 0; i--) d += `L${x(i).toFixed(1)},${y(bottom[i]).toFixed(1)}`;
          const a = s('path', { class: 'area', d: d + 'Z' });
          a.style.fill = se.color;
          a.style.fillOpacity = o.stacked ? '0.26' : '0.12';
          g.appendChild(a);
        }
        const l = s('path', { class: 'line', d: linePath });
        l.style.stroke = se.color;
        if (o.kind === 'area') l.style.strokeWidth = '1.5';
        g.appendChild(l);
        if (o.stacked) tops.forEach((v, i) => { base[i] = v; });
      });
    }
    svg.appendChild(g);
    const hover = s('g', { class: 'hover-layer' });
    svg.appendChild(hover);
    const hit = s('rect', { class: 'hit', x: m.l, y: m.t, width: iw, height: ih });
    svg.appendChild(hit);
    const pick = clientX => {
      const r = svg.getBoundingClientRect();
      const px = (clientX - r.left) * (W / r.width);
      const i = isBar ? Math.floor((px - m.l) / bw) : Math.round(((px - m.l) / iw) * (n - 1));
      return Math.max(0, Math.min(n - 1, i));
    };
    hit.addEventListener('pointermove', e => showHover(pick(e.clientX), hover));
    hit.addEventListener('pointerdown', e => showHover(pick(e.clientX), hover));
    hit.addEventListener('pointerleave', () => hideHover(hover));
    svg.addEventListener('keydown', e => {
      if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
        e.preventDefault();
        const ni = hoverIdx < 0 ? n - 1 : Math.max(0, Math.min(n - 1, hoverIdx + (e.key === 'ArrowRight' ? 1 : -1)));
        showHover(ni, hover);
      } else if (e.key === 'Escape') hideHover(hover);
    });
    svg.addEventListener('blur', () => hideHover(hover));
    mount(svgWrap, svg, totalZero ? h('div', { class: 'chart-empty' }, o.empty) : null);
  }

  function showHover(i, layer) {
    if (!G || !points[i]) return;
    hoverIdx = i;
    clear(layer);
    const { m, ih, vis, W, H } = G;
    const p = points[i];
    const xx = G.x(i);
    if (o.kind === 'bar') {
      const r = s('rect', { x: xx - G.bw / 2, y: m.t, width: G.bw, height: ih });
      r.style.fill = 'var(--text)'; r.style.fillOpacity = '0.06';
      layer.appendChild(r);
    } else {
      layer.appendChild(s('line', { class: 'crosshair', x1: Math.round(xx) + 0.5, x2: Math.round(xx) + 0.5, y1: m.t, y2: m.t + ih }));
      let acc = 0;
      vis.forEach(se => {
        const v = +p[se.key] || 0;
        acc = o.stacked ? acc + v : v;
        const c = s('circle', { class: 'hover-dot', cx: xx, cy: G.y(acc), r: 4 });
        c.style.fill = se.color;
        layer.appendChild(c);
      });
    }
    const rows = vis.slice().reverse().map(se => h('div', { class: 'tip-row' },
      h('span', { class: `swatch ${o.kind === 'line' ? 'line' : ''}`, style: { background: se.color } }),
      h('span', { class: 'k' }, se.label), h('span', { class: 'v' }, o.tipFmt(+p[se.key] || 0, se))));
    const total = o.stacked && vis.length > 1 ? vis.reduce((a, se) => a + (+p[se.key] || 0), 0) : null;
    mount(tip, h('div', { class: 'tip-title' }, dateTime(p.t)), rows,
      total != null ? h('div', { class: 'tip-row tip-total' }, h('span', { class: 'k' }, o.totalLabel || 'Total'), h('span', { class: 'v' }, o.tipFmt(total))) : null);
    tip.classList.add('show');
    const rect = svgWrap.getBoundingClientRect();
    const scale = rect.width / W;
    const px = xx * scale;
    const tw = tip.offsetWidth, th = tip.offsetHeight;
    let left = px + 14;
    if (left + tw > rect.width) left = px - tw - 14;
    tip.style.left = Math.max(0, left) + 'px';
    tip.style.top = Math.max(0, (H * scale - th) / 2 - 10) + 'px';
  }
  function hideHover(layer) { hoverIdx = -1; clear(layer); tip.classList.remove('show'); }

  let raf = 0;
  const ro = new ResizeObserver(() => {
    cancelAnimationFrame(raf);
    raf = requestAnimationFrame(() => { if (Math.abs((svgWrap.clientWidth || 0) - width) > 1) draw(); });
  });
  ro.observe(svgWrap);
  draw();
  drawLegend();
  return {
    update(p) { points = p || []; draw(); drawLegend(); },
    setKind(k) { o.kind = k; o.stacked = k !== 'line' ? o.stacked : false; draw(); drawLegend(); },
    destroy() { ro.disconnect(); },
  };
}

/** Sparkline: small area + line, no axes. */
export function sparkline(values, { color = SERIES(1), height = 36, fill = true, ariaLabel = '' } = {}) {
  const W = 120, H = height;
  const n = values.length;
  const svg = s('svg', { class: 'spark', viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: 'none', role: ariaLabel ? 'img' : 'presentation', 'aria-label': ariaLabel || null, 'aria-hidden': ariaLabel ? null : 'true' });
  if (n < 2) return svg;
  const max = Math.max(...values, 1e-9), min = Math.min(...values, 0);
  const x = i => (i / (n - 1)) * W;
  const y = v => H - 2 - ((v - min) / (max - min || 1)) * (H - 4);
  const line = values.map((v, i) => `${i ? 'L' : 'M'}${x(i).toFixed(2)},${y(v).toFixed(2)}`).join('');
  if (fill) {
    const a = s('path', { d: `${line}L${W},${H}L0,${H}Z` });
    a.style.fill = color; a.style.fillOpacity = '0.12';
    svg.appendChild(a);
  }
  const l = s('path', { class: 'line', d: line, 'vector-effect': 'non-scaling-stroke' });
  l.style.stroke = color;
  svg.appendChild(l);
  return svg;
}

/** Downsample an array to at most n buckets by summing (or averaging). */
export function bucket(values, n = 48, avg = false) {
  if (values.length <= n) return values.slice();
  const out = [];
  const size = values.length / n;
  for (let i = 0; i < n; i++) {
    const a = Math.floor(i * size), b = Math.floor((i + 1) * size);
    let sum = 0;
    for (let j = a; j < b; j++) sum += values[j];
    out.push(avg ? sum / Math.max(1, b - a) : sum);
  }
  return out;
}

/** Segmented horizontal meter with 2px gaps, e.g. status breakdown. */
export function segmentBar(parts, { tall = true, label = '' } = {}) {
  const total = parts.reduce((a, p) => a + p.value, 0) || 1;
  return h('div', { class: `meter ${tall ? 'tall' : ''}`, role: 'img', 'aria-label': label },
    parts.filter(p => p.value > 0).map(p => h('span', { title: `${p.label}: ${p.value}`, style: { width: `${(p.value / total) * 100}%`, background: p.color } })));
}
