// Simulator: "what would the gateway do with this request?"
import { h, mount, nextId } from '../dom.js';
import { icon } from '../icons.js';
import * as api from '../api.js';
import * as fmt from '../format.js';
import { can, entities } from '../state.js';
import { pageHead, card, badge, modeBadge, emptyState, busy, toast, decisionBadge } from '../ui.js';
import { field, input, select, toggle, kvEditor, showFormError, clearProblems } from '../forms.js';
import { replaceQuery } from '../router.js';

const VERDICT = {
  allowed: ['good', 'check', 'Request would be allowed', 'Every policy has capacity. The request is proxied upstream.'],
  shadow_limited: ['warn', 'eye', 'Allowed — shadow limit exceeded', 'A shadow policy is over its limit. The request still goes through and is logged.'],
  limited: ['crit', 'ban', 'Request would be rate limited', 'The gateway answers 429 Too Many Requests with Retry-After.'],
  unauthorized: ['crit', 'lock', 'Request would be rejected (401)', 'The route requires a valid API key.'],
  no_route: ['warn', 'x', 'No route matches', 'The gateway answers 404 no_route.'],
  error: ['crit', 'alert', 'Limiter error', 'The backend errored on a fail-closed policy (503).'],
};

function step(kind, ic, title, body) {
  return h('div', { class: 'pipe-step' }, h('div', { class: `pipe-dot ${kind}` }, icon(ic)), h('div', { class: 'pipe-body' }, h('div', { class: 't' }, title), body));
}

function renderResult(res, req) {
  const [kind, ic, title, desc] = VERDICT[res.decision] || ['', 'info', res.decision, ''];
  const steps = [];
  steps.push(res.matched
    ? step('good', 'route', h('span', {}, 'Matched route ', h('a', { href: `#/routes?edit=${encodeURIComponent(res.route_id)}` }, res.route_name || res.route_id)),
      h('div', { class: 'small muted' }, 'Upstream ', h('code', {}, res.upstream || '—')))
    : step('warn', 'x', 'No route matched', h('div', { class: 'small muted' }, `${req.method} ${req.host || '*'}${req.path}`)));
  if (res.matched) {
    steps.push(res.auth_error
      ? step('crit', 'lock', 'Authentication failed', h('div', { class: 'small muted' }, res.auth_error))
      : step('good', res.consumer_id ? 'user' : 'globe', res.consumer_id ? h('span', {}, 'Identified consumer ', h('a', { href: `#/consumers/${encodeURIComponent(res.consumer_id)}` }, res.consumer_name || res.consumer_id)) : 'Anonymous request',
        h('div', { class: 'small muted' }, res.consumer_id ? 'Plan and consumer overrides apply.' : 'Keys by “consumer” fall back to the client IP.')));
  }
  (res.policies || []).forEach((p, i) => {
    const consumed = p.allowed !== undefined && p.allowed !== null;
    const k = !consumed ? '' : p.allowed ? 'good' : p.mode === 'shadow' ? 'warn' : 'crit';
    steps.push(step(k, consumed ? (p.allowed ? 'check' : 'ban') : 'gauge',
      h('span', { class: 'row wrap' }, h('span', {}, `${i + 1}. `, h('a', { href: `#/policies?edit=${encodeURIComponent(p.policy_id)}` }, p.policy_name || p.policy_id)), modeBadge(p.mode),
        h('span', { class: 'badge square' }, fmt.ALGO_LABEL[p.algorithm] || p.algorithm)),
      h('div', { class: 'stack tight mt-4' },
        h('div', { class: 'small' }, h('strong', { class: 'tnum' }, fmt.policySummary(p)), p.burst ? ` · burst ${fmt.int(p.burst)}` : '', ' · limit from ', h('code', {}, p.limit_from || 'policy')),
        h('div', { class: 'small muted' }, 'Bucket ', h('code', {}, `${p.policy_id}:${p.rate_key}`)),
        consumed ? h('div', { class: 'small' }, p.allowed ? `Allowed · ${fmt.int(p.remaining)} remaining${p.delay_ms ? ` · queued ${fmt.ms(p.delay_ms)} (shaped)` : ''}` : `Denied · retry after ${Math.ceil((p.retry_after_ms || 0) / 1000)}s`,
          ' ', h('a', { href: `#/limits?policy_id=${encodeURIComponent(p.policy_id)}&key=${encodeURIComponent(p.rate_key)}` }, 'Inspect')) : null)));
  });
  if (res.matched && !res.auth_error && !(res.policies || []).length) steps.push(step('', 'info', 'No policies apply', h('div', { class: 'small muted' }, 'This route has no route or global policies — it is unlimited.')));

  // Headers the client would receive (most restrictive consumed policy).
  let headers = null;
  const consumed = (res.policies || []).filter(p => p.allowed !== undefined && p.allowed !== null && p.algorithm !== 'concurrency');
  if (consumed.length) {
    const tight = consumed.reduce((a, b) => (b.remaining < a.remaining ? b : a));
    const w = Math.round(fmt.parseDuration(tight.window) / 1000);
    const rows = [['RateLimit-Limit', tight.limit], ['RateLimit-Remaining', tight.remaining], ['RateLimit-Policy', `${tight.limit};w=${w}`]];
    if (res.decision === 'limited') rows.push(['Retry-After', Math.max(1, Math.ceil((tight.retry_after_ms || 0) / 1000))]);
    headers = h('div', { class: 'code-block' }, h('div', { class: 'code-head' }, h('span', {}, 'Response headers')),
      h('pre', {}, rows.map(([k, v]) => [h('span', { class: 'tok-k' }, k), `: ${v}\n`])));
  }

  return h('div', { class: 'stack' },
    h('div', { class: `verdict ${kind}`, role: 'status' }, h('div', { class: 'v-icon' }, icon(ic, 'lg')),
      h('div', { class: 'grow' }, h('div', { class: 'v-title' }, title), h('div', { class: 'small subtle' }, desc)), decisionBadge(res.decision)),
    h('div', { class: 'pipeline' }, steps),
    headers,
    res.notes && res.notes.length ? h('div', { class: 'callout info' }, icon('info'), h('ul', { class: 'list-reset stack tight' }, res.notes.map(n => h('li', {}, n)))) : null);
}

export default {
  async render({ root, query }) {
    const editable = can('edit');
    const method = select({ options: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'], value: query.method || 'GET', 'aria-label': 'Method' });
    method.style.width = '110px';
    const host = input({ value: query.host || '', placeholder: 'api.example.com', mono: true });
    const path = input({ value: query.path || '/', placeholder: '/v1/orders', mono: true });
    const ip = input({ value: query.ip || '', placeholder: '203.0.113.10', mono: true });
    const apiKey = input({ value: '', placeholder: 'rlg_live_…', mono: true, autocomplete: 'off', spellcheck: 'false' });
    const headers = kvEditor({}, { keyPh: 'Header', valPh: 'Value', name: 'headers', addLabel: 'Add header' });
    const queryKv = kvEditor({}, { keyPh: 'Param', valPh: 'Value', name: 'query', addLabel: 'Add query param' });
    const consume = toggle({ label: 'Consume from buckets', desc: editable ? 'run a real check (counts against limits)' : 'requires editor role', checked: false, name: 'consume', disabled: !editable });
    const routeSel = select({ cls: 'sm', 'aria-label': 'Prefill from route', options: [{ value: '', label: 'Prefill from route…' }] });
    entities('routes').then(rs => {
      mount(routeSel, h('option', { value: '' }, 'Prefill from route…'), rs.map(r => h('option', { value: r.id }, r.name)));
      const pre = rs.find(r => r.id === query.route_id);
      if (pre) { fill(pre); if (query.path) path.value = query.path; form.requestSubmit(); }
      routeSel.addEventListener('change', () => { const r = rs.find(x => x.id === routeSel.value); if (r) fill(r); });
    }).catch(() => routeSel.classList.add('hidden'));
    function fill(r) {
      if (r.match.host && !r.match.host.startsWith('*')) host.value = r.match.host;
      else if (r.match.host) host.value = 'app' + r.match.host.slice(1);
      path.value = r.match.path_prefix || '/';
      if (r.match.methods && r.match.methods.length) method.value = r.match.methods[0];
    }

    const formId = nextId('sim');
    const run = h('button', { class: 'btn primary', type: 'submit', form: formId }, icon('play', 'sm'), 'Run simulation');
    const form = h('form', { class: 'form', id: formId, novalidate: true },
      h('div', { class: 'field', dataset: { field: 'path' } }, h('label', { for: path.id || (path.id = nextId('p')) }, 'Request'),
        h('div', { class: 'row' }, method, path)),
      field({ label: 'Host', name: 'host', control: host, optional: true }),
      h('div', { class: 'form-grid' },
        field({ label: 'Client IP', name: 'ip', control: ip, optional: true }),
        field({ label: 'API key', name: 'api_key', control: apiKey, optional: true, hint: 'Sent as X-API-Key (or your configured header).' })),
      query.consumer ? h('div', { class: 'callout' }, icon('key'), h('div', {}, 'Paste one of ', h('strong', {}, query.consumer), '’s API keys to see the limits they get.')) : null,
      field({ label: 'Headers', name: 'headers', control: headers, optional: true }),
      field({ label: 'Query parameters', name: 'query', control: queryKv, optional: true }),
      consume);
    const result = h('div', {}, emptyState({ icon: 'flask', title: 'Test a request', text: 'Describe a request on the left. RateGuard will show which route matches, who the consumer is, and how each policy decides — without sending traffic upstream.' }));

    let settingsHeader = 'X-API-Key';
    api.get('/settings').then(s => { if (s && s.api_key_header) settingsHeader = s.api_key_header; }).catch(() => {});

    form.addEventListener('submit', async e => {
      e.preventDefault();
      clearProblems(form);
      const hdrs = headers.value();
      if (apiKey.value.trim()) hdrs[settingsHeader] = apiKey.value.trim();
      const req = { method: method.value, host: host.value.trim(), path: path.value.trim() || '/', headers: hdrs, query: queryKv.value(), ip: ip.value.trim(), consume: consume.input.checked };
      replaceQuery({ method: req.method, host: req.host, path: req.path, ip: req.ip });
      await busy(run, async () => {
        try {
          const res = await api.post('/simulate', req);
          mount(result, renderResult(res, req));
        } catch (err) {
          showFormError(form, err);
          if (err.status !== 422) toast('crit', 'Simulation failed', err.friendly);
        }
      });
    });

    mount(root,
      pageHead({ title: 'Simulator', lede: 'Dry-run any request through routing, authentication and every policy — see exactly why it would be allowed or limited.' }),
      h('div', { class: 'grid side-main' },
        card({ title: 'Request', actions: routeSel, body: form, cls: '' }),
        h('div', { class: 'stack' }, card({ title: 'Result', body: result }))));
    root.querySelector('.grid > section').appendChild(h('div', { class: 'card-foot' }, run));
    if (query.path && !query.route_id) requestAnimationFrame(() => form.requestSubmit());
  },
};

export { badge };
