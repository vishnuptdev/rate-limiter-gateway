// Settings: gateway settings, users, API tokens, import/export.
import { h, mount, nextId } from '../dom.js';
import { icon } from '../icons.js';
import * as api from '../api.js';
import * as fmt from '../format.js';
import { can, entities, session, invalidate } from '../state.js';
import { pageHead, table, badge, roleBadge, emptyState, errorState, load, modal, toast, busy, tabs, secretModal, confirm, readonlyBanner, menuButton, skeletonRows } from '../ui.js';
import { field, input, select, textarea, toggle, checkbox, orderedPicker, listValue, showFormError, clearProblems } from '../forms.js';
import { replaceQuery } from '../router.js';
import { saveBlob } from './logs.js';

/* ------------------------------------------------------------ gateway */
async function gatewayTab(el) {
  const admin = can('admin');
  await load(el, async () => Promise.all([api.get('/settings'), entities('policies', { fresh: true }).catch(() => [])]), ([s, policies]) => {
    const header = input({ value: s.api_key_header || 'X-API-Key', mono: true });
    const proxies = textarea({ value: (s.trusted_proxies || []).join('\n'), placeholder: '10.0.0.0/8\n192.168.1.10', code: true, rows: 3 });
    const globals = orderedPicker(policies, s.global_policy_ids || [], { name: 'global_policy_ids', disabled: !admin, emptyText: 'No global policies.', metaOf: p => fmt.policySummary(p) });
    const legacy = toggle({ label: 'Legacy X-RateLimit-* headers', desc: 'also emit X-RateLimit-Limit/-Remaining/-Reset', checked: !!s.legacy_headers, name: 'legacy_headers' });
    const expose = toggle({ label: 'Expose decision headers', desc: 'add X-RateGuard-Route / -Policy to responses', checked: !!s.expose_decision, name: 'expose_decision' });
    const check = toggle({ label: 'Decision (check) API', desc: 'enable POST /_rlg/v1/check on the data plane', checked: s.check_api_enabled !== false, name: 'check_api_enabled' });
    const fwdOn = toggle({ label: 'Forward-auth endpoint', desc: 'serve GET/POST /_rlg/v1/auth for NGINX auth_request, Traefik ForwardAuth, Caddy forward_auth, Envoy ext_authz and ingress-nginx. Turn off if you only use the reverse proxy or the check API.', checked: !s.forward_auth_disabled, name: 'forward_auth_disabled' });
    const fwdTok = toggle({ label: 'Require token for forward-auth', desc: 'callers must send X-RateGuard-Auth-Token with a “check”-scoped API token. Leave off when the proxy cannot add a header (Traefik) and the endpoint is only reachable on a private network.', checked: !!s.forward_auth_require_token, name: 'forward_auth_require_token' });
    const maxBody = input({ value: s.max_body_bytes ? String(s.max_body_bytes) : '', type: 'number', min: '0', placeholder: 'unlimited' });
    const maxHint = h('span');
    const paintMax = () => { maxHint.textContent = +maxBody.value ? `= ${fmt.bytes(+maxBody.value)}` : 'Empty or 0 = unlimited.'; };
    maxBody.addEventListener('input', paintMax); paintMax();
    const sample = h('input', { type: 'range', class: 'range', min: '0', max: '1', step: '0.01', value: String(s.log_sample_allowed ?? 1), 'aria-label': 'Allowed request log sample rate' });
    const sampleVal = h('strong', { class: 'tnum' });
    const paintSample = () => { sampleVal.textContent = Math.round(+sample.value * 100) + '%'; };
    sample.addEventListener('input', paintSample); paintSample();
    const v6 = input({ value: String(s.ipv6_prefix_len || 64), type: 'number', min: '32', max: '128', step: '1' });
    const cors = textarea({ value: (s.cors_allow_origins || []).join('\n'), placeholder: 'https://app.example.com', code: true, rows: 2 });
    const formId = nextId('gs');
    const submit = h('button', { class: 'btn primary', type: 'submit', form: formId }, 'Save settings');
    const form = h('form', { class: 'form', id: formId, novalidate: true },
      admin ? null : readonlyBanner('Only admins can change gateway settings.'),
      h('div', { class: 'form-section' },
        h('div', { class: 'form-section-title' }, 'Authentication'),
        h('div', { class: 'form-grid' },
          field({ label: 'API key header', name: 'api_key_header', control: header, hint: 'Authorization: Bearer <key> is always accepted too.' }),
          field({ label: 'Trusted proxies', name: 'trusted_proxies', control: proxies, optional: true, hint: 'IPs or CIDRs, one per line. Their X-Forwarded-For is trusted for client IPs.' }))),
      h('div', { class: 'form-section' },
        h('div', { class: 'form-section-title' }, 'Global policies'),
        h('div', { class: 'muted' }, 'Applied to every route, before route policies, in this order.'),
        globals),
      h('div', { class: 'form-section' },
        h('div', { class: 'form-section-title' }, 'Responses'),
        legacy, expose, check),
      h('div', { class: 'form-section' },
        h('div', { class: 'form-section-title' }, 'Forward auth'),
        h('div', { class: 'muted' }, 'Lets your own proxy ask RateGuard “allow or deny?” per request without sending traffic through it. See Integration → Forward auth.'),
        fwdOn, fwdTok),
      h('div', { class: 'form-section' },
        h('div', { class: 'form-section-title' }, 'Limits & logging'),
        h('div', { class: 'form-grid' },
          field({ label: 'Max request body', name: 'max_body_bytes', control: h('div', { class: 'input-group' }, maxBody, h('span', { class: 'addon' }, 'bytes')), optional: true, hint: maxHint }),
          field({ label: 'IPv6 prefix for “ip” keys', name: 'ipv6_prefix_len', control: h('div', { class: 'input-group' }, v6, h('span', { class: 'addon' }, 'bits')), hint: 'IPv6 clients are limited per /64 by default so they can’t rotate addresses. 32–128; 128 = per address. IPv4 is always per address.' }),
          field({ label: 'Log sample (allowed requests)', name: 'log_sample_allowed', control: h('div', { class: 'stack tight' }, sample, h('div', { class: 'row small' }, sampleVal, h('span', { class: 'muted' }, 'of allowed requests are logged. Limited & errors are always logged.'))) }),
          field({ label: 'CORS allowed origins', name: 'cors_allow_origins', control: cors, optional: true, hint: 'For the data plane. One per line.', full: true }))));
    if (!admin) form.querySelectorAll('input, textarea, select, button').forEach(x => { x.disabled = true; });
    form.addEventListener('submit', async e => {
      e.preventDefault();
      clearProblems(form);
      await busy(submit, async () => {
        try {
          await api.put('/settings', {
            ...s, api_key_header: header.value.trim(), trusted_proxies: listValue(proxies.value), global_policy_ids: globals.value(),
            legacy_headers: legacy.input.checked, expose_decision: expose.input.checked, check_api_enabled: check.input.checked,
            forward_auth_disabled: !fwdOn.input.checked, forward_auth_require_token: fwdTok.input.checked,
            max_body_bytes: parseInt(maxBody.value, 10) || 0, ipv6_prefix_len: parseInt(v6.value, 10) || 0, log_sample_allowed: +sample.value, cors_allow_origins: listValue(cors.value),
          });
          toast('good', 'Settings saved', 'Applied to the gateway immediately.');
        } catch (err) { showFormError(form, err); if (err.status !== 422) toast('crit', 'Couldn’t save settings', err.friendly); }
      });
    });
    return h('section', { class: 'card' }, h('div', { class: 'card-body' }, form), admin ? h('div', { class: 'card-foot' }, submit) : null);
  });
}

/* ------------------------------------------------------------ users */
function genPassword() {
  const a = new Uint32Array(20);
  crypto.getRandomValues(a);
  const cs = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_';
  return Array.from(a, n => cs[n % cs.length]).join('');
}

function passwordInput(value = '') {
  const pw = input({ value, mono: true, autocomplete: 'new-password' });
  const gen = h('button', { type: 'button', class: 'btn sm', onClick: () => { pw.value = genPassword(); pw.dispatchEvent(new Event('input', { bubbles: true })); } }, icon('sparkles', 'sm'), 'Generate');
  const wrap = h('div', { class: 'row' }, pw, gen);
  wrap.input = pw;
  return wrap;
}

function userModal(existing, onDone) {
  const isNew = !existing;
  const username = input({ value: existing ? existing.username : '', disabled: !isNew, autocomplete: 'off', autofocus: isNew });
  const role = select({ value: existing ? existing.role : 'viewer', options: [
    { value: 'viewer', label: 'Viewer — read-only dashboards & logs' },
    { value: 'editor', label: 'Editor — manage config & reset limits' },
    { value: 'admin', label: 'Admin — everything incl. users & settings' }] });
  const pw = passwordInput(isNew ? genPassword() : '');
  const must = checkbox({ label: 'Require password change at next sign-in', checked: true, name: 'must_change_password' });
  const formId = nextId('uf');
  const form = h('form', { class: 'form', id: formId, novalidate: true },
    field({ label: 'Username', name: 'username', control: username }),
    field({ label: 'Role', name: 'role', control: role }),
    field({ label: isNew ? 'Temporary password' : 'New password', name: 'password', control: pw, optional: !isNew, hint: isNew ? 'At least 12 characters. Share it securely.' : 'Leave empty to keep the current password.' }),
    must);
  const submit = h('button', { class: 'btn primary', type: 'submit', form: formId }, isNew ? 'Create user' : 'Save user');
  const m = modal({ title: isNew ? 'Add user' : `Edit ${existing.username}`, icon: 'user', body: form, foot: [h('button', { class: 'btn', type: 'button', onClick: () => m.close() }, 'Cancel'), submit] });
  form.addEventListener('submit', async e => {
    e.preventDefault();
    clearProblems(form);
    await busy(submit, async () => {
      try {
        const pwv = pw.input.value;
        if (isNew) await api.post('/users', { username: username.value.trim(), role: role.value, password: pwv, must_change_password: must.input.checked });
        else await api.put('/users/' + encodeURIComponent(existing.username), { role: role.value, ...(pwv ? { password: pwv, must_change_password: must.input.checked } : {}) });
        m.close();
        toast('good', isNew ? 'User created' : 'User updated', isNew ? `Share the temporary password with ${username.value.trim()} securely.` : existing.username);
        onDone();
      } catch (err) { showFormError(form, err); }
    });
  });
}

async function usersTab(el) {
  const reload = () => usersTab(el);
  const add = h('button', { class: 'btn primary sm', onClick: () => userModal(null, reload) }, icon('plus', 'sm'), 'Add user');
  const body = h('div');
  mount(el, h('section', { class: 'card' },
    h('div', { class: 'card-head' }, h('div', {}, h('h2', {}, 'Users'), h('div', { class: 'desc' }, 'People who can sign in to this console.')), add),
    body));
  await load(body, () => api.get('/users'), res => {
    const users = api.list(res, 'users');
    return table({
      rows: users, caption: 'Users', sortKey: 'username',
      columns: [
        { key: 'username', label: 'User', sort: true, render: u => h('div', { class: 'row' }, h('span', { class: 'avatar', 'aria-hidden': 'true' }, u.username.slice(0, 2)),
          h('div', {}, h('div', { class: 'cell-title' }, u.username, u.username === session.user.username ? h('span', { class: 'xs muted' }, ' (you)') : null),
            u.must_change_password ? h('div', { class: 'cell-sub' }, 'Must change password') : null)) },
        { key: 'role', label: 'Role', sort: true, render: u => roleBadge(u.role) },
        { key: 'last_login_at', label: 'Last sign-in', hide: 'sm', sort: u => u.last_login_at || '', render: u => h('span', { class: 'small muted', title: u.last_login_at ? fmt.dateTime(u.last_login_at) : '' }, u.last_login_at ? fmt.ago(u.last_login_at) : 'Never') },
        { key: 'created_at', label: 'Created', hide: 'md', sort: true, render: u => h('span', { class: 'small muted' }, fmt.date(u.created_at)) },
        { key: 'x', label: '', cls: 'actions', render: u => menuButton(h('button', { class: 'btn ghost sm icon-only', 'aria-label': `Actions for ${u.username}` }, icon('more')), () => [
          { label: 'Edit role / reset password', icon: 'edit', onClick: () => userModal(u, reload) },
          ...(u.username !== session.user.username ? ['-', { label: 'Delete user', icon: 'trash', danger: true, onClick: async () => {
            if (!(await confirm({ title: `Delete ${u.username}?`, message: 'Their sessions end immediately and they can no longer sign in.', confirmLabel: 'Delete user', danger: true }))) return;
            try { await api.del('/users/' + encodeURIComponent(u.username)); toast('good', 'User deleted', u.username); reload(); } catch (e) { toast('crit', 'Couldn’t delete user', e.friendly); }
          } }] : []),
        ]) },
      ],
    });
  }, { skeleton: skeletonRows(4, 4) });
}

/* ------------------------------------------------------------ tokens */
const SCOPES = [
  { v: 'read', t: 'read', d: 'Read config, logs and metrics (Prometheus /metrics, dashboards).' },
  { v: 'check', t: 'check', d: 'Call the decision API POST /_rlg/v1/check from your services.' },
  { v: 'admin', t: 'admin', d: 'Full admin API access — for Terraform / CI. Treat like a root password.' },
];

function tokenModal(onDone) {
  const name = input({ placeholder: 'terraform-ci', autofocus: true });
  const boxes = SCOPES.map(s => checkbox({ label: s.t, desc: s.d, checked: s.v === 'read', name: 'scope-' + s.v }));
  const exp = select({ value: '90', options: [{ value: '30', label: '30 days' }, { value: '90', label: '90 days' }, { value: '365', label: '1 year' }, { value: '', label: 'Never' }] });
  const formId = nextId('tf');
  const form = h('form', { class: 'form', id: formId, novalidate: true },
    field({ label: 'Name', name: 'name', control: name, hint: 'Where it’s used, e.g. grafana-scrape, orders-service.' }),
    h('div', { class: 'field', dataset: { field: 'scopes' } }, h('div', { class: 'field-label' }, 'Scopes'), h('div', { class: 'stack tight' }, boxes)),
    field({ label: 'Expires', name: 'expires_at', control: exp }));
  const submit = h('button', { class: 'btn primary', type: 'submit', form: formId }, 'Create token');
  const m = modal({ title: 'New API token', desc: 'For automation and services — not for people.', icon: 'token', body: form, foot: [h('button', { class: 'btn', type: 'button', onClick: () => m.close() }, 'Cancel'), submit] });
  form.addEventListener('submit', async e => {
    e.preventDefault();
    clearProblems(form);
    const scopes = SCOPES.filter((_, i) => boxes[i].input.checked).map(s => s.v);
    if (!scopes.length) { showFormError(form, { status: 422, problems: [{ field: 'scopes', message: 'Pick at least one scope' }] }); return; }
    await busy(submit, async () => {
      try {
        const res = await api.post('/tokens', { name: name.value.trim(), scopes, expires_at: exp.value ? new Date(Date.now() + (+exp.value) * 86400e3).toISOString() : undefined });
        m.close();
        await secretModal({ title: 'API token created', secret: res.token, note: 'Store it in your secret manager now. It won’t be shown again.' });
        onDone();
      } catch (err) { showFormError(form, err); }
    });
  });
}

async function tokensTab(el) {
  const reload = () => tokensTab(el);
  const add = h('button', { class: 'btn primary sm', onClick: () => tokenModal(reload) }, icon('plus', 'sm'), 'New token');
  const body = h('div');
  mount(el, h('section', { class: 'card' },
    h('div', { class: 'card-head' }, h('div', {}, h('h2', {}, 'API tokens'), h('div', { class: 'desc' }, 'Bearer tokens for CI, infrastructure-as-code, metrics scraping and the check API.')), add),
    body));
  await load(body, () => api.get('/tokens'), res => {
    const toks = api.list(res, 'tokens');
    if (!toks.length) return emptyState({ icon: 'token', title: 'No API tokens', text: 'Create a token to automate RateGuard or let services call the decision API.', compact: true });
    return table({
      rows: toks, caption: 'API tokens', sortKey: 'created_at', sortDir: 'desc',
      columns: [
        { key: 'name', label: 'Token', sort: true, render: t => h('div', {}, h('div', { class: 'cell-title' }, t.name), h('code', { class: 'xs' }, (t.prefix || 'rgt_') + '…')) },
        { key: 'scopes', label: 'Scopes', render: t => h('div', { class: 'chips' }, (t.scopes || []).map(s => badge(s, s === 'admin' ? 'crit' : s === 'check' ? 'info' : '', null, 'square mono'))) },
        { key: 'last_used_at', label: 'Last used', hide: 'sm', sort: t => t.last_used_at || '', render: t => h('span', { class: 'small muted' }, t.last_used_at ? fmt.ago(t.last_used_at) : 'Never') },
        { key: 'expires_at', label: 'Expires', hide: 'md', sort: t => t.expires_at || 'z', render: t => t.expires_at ? (new Date(t.expires_at) < Date.now() ? badge('Expired', 'warn', 'clock') : h('span', { class: 'small', title: fmt.dateTime(t.expires_at) }, fmt.ago(t.expires_at))) : h('span', { class: 'small muted' }, 'Never') },
        { key: 'created_at', label: 'Created', hide: 'md', sort: true, render: t => h('span', { class: 'small muted' }, fmt.date(t.created_at), t.created_by ? ` by ${t.created_by}` : '') },
        { key: 'x', label: '', cls: 'actions', render: t => h('button', { class: 'btn sm danger-ghost', onClick: async () => {
          if (!(await confirm({ title: `Revoke ${t.name}?`, message: 'Anything using this token will start getting 401 immediately.', confirmLabel: 'Revoke token', danger: true }))) return;
          try { await api.del('/tokens/' + encodeURIComponent(t.id)); toast('good', 'Token revoked', t.name); reload(); } catch (e) { toast('crit', 'Couldn’t revoke token', e.friendly); }
        } }, 'Revoke') },
      ],
    });
  }, { skeleton: skeletonRows(3, 4) });
}

/* ------------------------------------------------------------ import/export */
function diffTable(diff) {
  if (!diff) return null;
  // Accept {policies:{added,removed,changed}} (server) or {added:{policies:n}} shapes.
  const kinds = ['policies', 'routes', 'plans', 'consumers', 'settings'];
  const get = (k, f) => (diff[k] && typeof diff[k] === 'object' && f in diff[k] ? diff[k][f] : diff[f] && diff[f][k]) || 0;
  const rows = kinds.map(k => ({ k, a: get(k, 'added'), r: get(k, 'removed'), c: get(k, 'changed') })).filter(x => x.k !== 'settings' || x.c);
  const total = rows.reduce((s, x) => s + x.a + x.r + x.c, 0);
  return h('div', { class: 'stack tight' },
    h('div', { class: 'small' }, total ? h('strong', {}, `${fmt.plural(total, 'change')} `) : 'No changes — the import matches the current configuration.', total ? 'compared with the live configuration:' : ''),
    h('div', { class: 'table-wrap card' }, h('table', { class: 'table dense diff-table' },
      h('thead', {}, h('tr', {}, h('th', { scope: 'col' }, 'Kind'), h('th', { scope: 'col', class: 'num' }, 'Added'), h('th', { scope: 'col', class: 'num' }, 'Removed'), h('th', { scope: 'col', class: 'num' }, 'Changed'))),
      h('tbody', {}, rows.map(x => h('tr', {}, h('td', {}, x.k),
        h('td', { class: `num ${x.a ? 'add' : 'muted'}` }, x.a ? `+${x.a}` : '0'),
        h('td', { class: `num ${x.r ? 'rem' : 'muted'}` }, x.r ? `−${x.r}` : '0'),
        h('td', { class: `num ${x.c ? 'chg' : 'muted'}` }, String(x.c))))))));
}

async function transferTab(el) {
  const exportBtn = h('button', { class: 'btn primary', type: 'button' }, icon('download', 'sm'), 'Download configuration');
  exportBtn.addEventListener('click', () => busy(exportBtn, async () => {
    try {
      const blob = await api.download('/config/export');
      let v = '';
      try { v = JSON.parse(await blob.text()).version; } catch { /* keep blank */ }
      saveBlob(blob, `rateguard-config${v ? '-v' + v : ''}.json`);
      toast('good', 'Configuration exported', 'Plaintext API keys are never included.');
    } catch (e) { toast('crit', 'Export failed', e.friendly); }
  }));

  const file = h('input', { type: 'file', accept: 'application/json,.json', class: 'sr-only', id: nextId('file') });
  const ta = textarea({ placeholder: 'Paste a configuration snapshot (JSON)…', code: true, rows: 8, 'aria-label': 'Snapshot JSON' });
  const drop = h('label', { class: 'dropzone', for: file.id }, icon('upload', 'lg'), h('div', { class: 'mt-8' }, h('strong', {}, 'Choose a file'), ' or drop it here'), h('div', { class: 'xs' }, 'JSON exported from RateGuard'));
  const result = h('div', { 'aria-live': 'polite' });
  const dryBtn = h('button', { class: 'btn', type: 'button' }, icon('check', 'sm'), 'Validate (dry run)');
  const applyBtn = h('button', { class: 'btn danger', type: 'button', disabled: true }, 'Apply import');
  let validated = null;
  const loadText = t => { ta.value = t; validated = null; applyBtn.disabled = true; mount(result); };
  file.addEventListener('change', async () => { if (file.files[0]) loadText(await file.files[0].text()); });
  ['dragenter', 'dragover'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add('over'); }));
  ['dragleave', 'drop'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove('over'); }));
  drop.addEventListener('drop', async e => { const f = e.dataTransfer.files[0]; if (f) loadText(await f.text()); });
  ta.addEventListener('input', () => { validated = null; applyBtn.disabled = true; });

  const parse = () => {
    let obj;
    try { obj = JSON.parse(ta.value); } catch (e) { mount(result, h('div', { class: 'form-error' }, icon('alertCircle'), h('div', {}, 'That isn’t valid JSON: ', e.message))); return null; }
    return obj && obj.snapshot ? obj.snapshot : obj;
  };
  const problemsList = ps => h('ul', {}, ps.map(p => h('li', {}, p.field ? h('code', {}, p.field) : null, ' ', p.message)));
  dryBtn.addEventListener('click', () => busy(dryBtn, async () => {
    const snap = parse();
    if (!snap) return;
    try {
      const res = await api.post('/config/import', { snapshot: snap, dry_run: true });
      const ok = res.ok !== false && !(res.problems && res.problems.length);
      validated = ok ? ta.value : null;
      applyBtn.disabled = !ok;
      mount(result, h('div', { class: 'stack' },
        ok ? h('div', { class: 'callout info' }, icon('checkCircle'), h('div', {}, h('strong', {}, 'Valid. '), 'Review the changes below, then apply.'))
          : h('div', { class: 'form-error' }, icon('alertCircle'), h('div', {}, res.message || 'The snapshot has problems:', res.problems ? problemsList(res.problems) : null)),
        diffTable(res.diff)));
    } catch (e) {
      mount(result, h('div', { class: 'form-error' }, icon('alertCircle'), h('div', {}, e.friendly, e.problems.length ? problemsList(e.problems) : null)));
    }
  }));
  applyBtn.addEventListener('click', async () => {
    if (validated !== ta.value) return;
    if (!(await confirm({ title: 'Replace the live configuration?', message: 'Routes, policies, plans, consumers and settings are replaced with the imported snapshot. Live traffic is affected immediately.', confirmLabel: 'Apply import', danger: true, typeToConfirm: 'import' }))) return;
    await busy(applyBtn, async () => {
      try {
        const res = await api.post('/config/import', { snapshot: parse(), dry_run: false });
        invalidate();
        toast('good', 'Configuration imported', res && res.version ? `Now at version ${res.version}.` : '');
        validated = null; applyBtn.disabled = true;
        mount(result, h('div', { class: 'callout info' }, icon('checkCircle'), h('div', {}, 'Import applied.')));
      } catch (e) {
        mount(result, h('div', { class: 'form-error' }, icon('alertCircle'), h('div', {}, e.friendly, e.problems.length ? problemsList(e.problems) : null)));
      }
    });
  });

  mount(el, h('div', { class: 'grid two' },
    h('section', { class: 'card' },
      h('div', { class: 'card-head' }, h('div', {}, h('h2', {}, 'Export'), h('div', { class: 'desc' }, 'Download the full configuration snapshot — for backups, review, or GitOps.'))),
      h('div', { class: 'card-body stack' },
        h('ul', { class: 'list-reset stack tight small subtle' },
          h('li', { class: 'row' }, icon('check', 'sm'), 'Routes, policies, plans, consumers and settings'),
          h('li', { class: 'row' }, icon('check', 'sm'), 'Never includes plaintext API keys'),
          h('li', { class: 'row' }, icon('x', 'sm'), 'Users and API tokens are not included')),
        h('div', {}, exportBtn))),
    h('section', { class: 'card' },
      h('div', { class: 'card-head' }, h('div', {}, h('h2', {}, 'Import'), h('div', { class: 'desc' }, 'Validate first: a dry run shows exactly what would change.'))),
      h('div', { class: 'card-body stack' }, file, drop, ta, result),
      h('div', { class: 'card-foot' }, dryBtn, applyBtn))));
}

export default {
  async render({ root, query }) {
    const admin = can('admin');
    const items = [{ id: 'gateway', label: 'Gateway', icon: 'settings' }];
    if (admin) items.push({ id: 'users', label: 'Users', icon: 'users' }, { id: 'tokens', label: 'API tokens', icon: 'token' }, { id: 'transfer', label: 'Import / Export', icon: 'upload' });
    let tab = items.some(i => i.id === query.tab) ? query.tab : 'gateway';
    const body = h('div');
    const show = () => {
      replaceQuery({ tab });
      ({ gateway: gatewayTab, users: usersTab, tokens: tokensTab, transfer: transferTab })[tab](body).catch(e => mount(body, errorState(e)));
    };
    mount(root,
      pageHead({ title: 'Settings', lede: admin ? 'Gateway-wide behaviour, console users, automation tokens and configuration backups.' : 'Gateway-wide behaviour. Other settings are visible to admins only.' }),
      tabs(items, tab, id => { tab = id; show(); }),
      body);
    show();
  },
};
