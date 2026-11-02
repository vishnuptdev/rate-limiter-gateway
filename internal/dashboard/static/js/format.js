// Number, time and duration formatting shared by every page.

const nf = new Intl.NumberFormat(undefined);
const nf1 = new Intl.NumberFormat(undefined, { maximumFractionDigits: 1 });
const nf2 = new Intl.NumberFormat(undefined, { maximumFractionDigits: 2 });

export const int = n => (n == null || isNaN(n) ? '—' : nf.format(Math.round(n)));
export const dec = (n, d = 1) => (n == null || isNaN(n) ? '—' : (d === 2 ? nf2 : nf1).format(n));

/** 1234 -> "1.2k", 4_500_000 -> "4.5M" */
export function compact(n) {
  if (n == null || isNaN(n)) return '—';
  const a = Math.abs(n);
  if (a < 1000) return nf1.format(n);
  if (a < 1e6) return nf1.format(n / 1e3) + 'k';
  if (a < 1e9) return nf1.format(n / 1e6) + 'M';
  return nf1.format(n / 1e9) + 'B';
}

export function pct(part, total, digits = 1) {
  if (!total) return '0%';
  const v = (part / total) * 100;
  if (v > 0 && v < 0.1) return '<0.1%';
  return v.toFixed(v >= 10 || digits === 0 ? 0 : digits) + '%';
}

export function ms(v) {
  if (v == null || isNaN(v)) return '—';
  if (v < 1) return v.toFixed(2) + ' ms';
  if (v < 10) return v.toFixed(1) + ' ms';
  if (v < 1000) return Math.round(v) + ' ms';
  return (v / 1000).toFixed(v < 10000 ? 2 : 1) + ' s';
}

export function bytes(n) {
  if (!n) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i ? n.toFixed(1) : n) + ' ' + u[i];
}

const units = { ns: 1e-6, us: 1e-3, 'µs': 1e-3, 'μs': 1e-3, ms: 1, s: 1000, m: 60000, h: 3600000 };

/** Parse a Go duration ("1h0m0s", "500ms", "1m30s") or a number of seconds -> milliseconds. NaN if invalid. */
export function parseDuration(v) {
  if (v == null || v === '') return NaN;
  if (typeof v === 'number') return v * 1000;
  const str = String(v).trim();
  if (/^-?\d+(\.\d+)?$/.test(str)) return parseFloat(str) * 1000;
  if (str === '0') return 0;
  const re = /(\d+(?:\.\d+)?)(ns|us|µs|μs|ms|s|m|h)/g;
  let total = 0, m, consumed = 0;
  while ((m = re.exec(str))) { total += parseFloat(m[1]) * units[m[2]]; consumed += m[0].length; }
  return consumed === str.length && consumed > 0 ? total : NaN;
}

/** milliseconds -> compact Go-compatible duration ("1m", "1h30m", "500ms") */
export function fmtDuration(msv) {
  if (msv == null || isNaN(msv)) return '';
  if (msv === 0) return '0s';
  if (msv < 1000) return Math.round(msv) + 'ms';
  let s = Math.round(msv / 1000);
  const h = Math.floor(s / 3600); s -= h * 3600;
  const m = Math.floor(s / 60); s -= m * 60;
  return (h ? h + 'h' : '') + (m ? m + 'm' : '') + (s ? s + 's' : '');
}

/** Human phrase for a window: "minute", "5 minutes", "hour", "day". */
export function windowPhrase(msv) {
  if (!msv) return '';
  const tbl = [[86400000, 'day'], [3600000, 'hour'], [60000, 'minute'], [1000, 'second']];
  for (const [u, name] of tbl) {
    if (msv >= u && msv % u === 0) {
      const n = msv / u;
      return n === 1 ? name : `${n} ${name}s`;
    }
  }
  return fmtDuration(msv);
}

export function goDur(v) { return fmtDuration(parseDuration(v)); }

const rtf = typeof Intl.RelativeTimeFormat === 'function' ? new Intl.RelativeTimeFormat(undefined, { numeric: 'auto', style: 'short' }) : null;

export function ago(t, now = Date.now()) {
  if (!t) return '—';
  const d = new Date(t).getTime();
  if (isNaN(d) || d <= 0) return '—';
  const diff = (d - now) / 1000;
  const a = Math.abs(diff);
  if (a < 10) return diff <= 0 ? 'just now' : 'in a few seconds';
  if (!rtf) return new Date(d).toLocaleString();
  if (a < 60) return rtf.format(Math.round(diff), 'second');
  if (a < 3600) return rtf.format(Math.round(diff / 60), 'minute');
  if (a < 86400) return rtf.format(Math.round(diff / 3600), 'hour');
  if (a < 86400 * 30) return rtf.format(Math.round(diff / 86400), 'day');
  return new Date(d).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

const dtf = new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' });
const tf = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
const tfm = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', hour12: false });
const df = new Intl.DateTimeFormat(undefined, { year: 'numeric', month: 'short', day: 'numeric' });

export const dateTime = t => (t ? dtf.format(new Date(t)) : '—');
export const time = t => (t ? tf.format(new Date(t)) : '—');
export const timeShort = t => (t ? tfm.format(new Date(t)) : '—');
export const date = t => (t && new Date(t).getTime() > 0 ? df.format(new Date(t)) : '—');
export function timeMs(t) {
  const d = new Date(t);
  return tf.format(d) + '.' + String(d.getMilliseconds()).padStart(3, '0');
}

export function uptime(sec) {
  if (sec == null) return '—';
  const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m`;
  return `${Math.floor(sec)}s`;
}

export function slug(s) {
  return String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 48);
}

export function plural(n, one, many = one + 's') { return `${int(n)} ${n === 1 ? one : many}`; }

export const ALGO_LABEL = {
  gcra: 'GCRA',
  token_bucket: 'Token bucket',
  leaky_bucket: 'Leaky bucket',
  sliding_window: 'Sliding window',
  sliding_window_counter: 'Sliding window counter',
  fixed_window: 'Fixed window',
  concurrency: 'Concurrency',
};

export const DECISION_LABEL = {
  allowed: 'Allowed',
  limited: 'Limited',
  shadow_limited: 'Shadow limited',
  unauthorized: 'Unauthorized',
  no_route: 'No route',
  error: 'Error',
};

/** One-line human summary of a policy's effective limit. */
/** Algorithms whose `burst` field is meaningful (bucket size / tolerance / queue size). */
export const BURSTY = ['token_bucket', 'gcra', 'leaky_bucket'];
export const burstLabel = a => (a === 'leaky_bucket' ? 'queue' : a === 'gcra' ? 'burst tolerance' : 'burst');

export function policySummary(p) {
  if (!p) return '';
  if (p.algorithm === 'concurrency') return `${int(p.limit)} in flight`;
  const w = parseDuration(p.window);
  return `${int(p.limit)} / ${windowPhrase(w) || '—'}`;
}

export function initials(name) {
  const w = String(name || '?').split(/[^A-Za-z0-9]+/).filter(Boolean);
  return (w.length > 1 ? w[0][0] + w[1][0] : (w[0] || '?').slice(0, 2)).toUpperCase();
}
