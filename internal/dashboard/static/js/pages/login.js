// Login screen (rendered outside the app shell).
import { h, s, mount } from '../dom.js';
import { icon } from '../icons.js';
import * as api from '../api.js';
import { field, input } from '../forms.js';

function art() {
  // Decorative traffic waveform with a ceiling line: allowed under, limited above.
  const W = 640, H = 260;
  const pts = Array.from({ length: 64 }, (_, i) => {
    const v = 120 + Math.sin(i / 4) * 40 + Math.sin(i / 1.7) * 18 + (i > 38 && i < 52 ? 150 * Math.sin(((i - 38) / 14) * Math.PI) : 0);
    return [i * (W / 63), H - v];
  });
  const ceil = 72;
  const svg = s('svg', { class: 'auth-art', viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: 'none', 'aria-hidden': 'true' });
  pts.forEach(([x, y], i) => {
    const bw = W / 64 - 3;
    const top = Math.max(y, ceil);
    const ok = s('rect', { x: x - bw / 2, y: top, width: bw, height: H - top, rx: 2 });
    ok.style.fill = '#3987e5'; ok.style.fillOpacity = String(0.28 + (i / 64) * 0.4);
    svg.appendChild(ok);
    if (y < ceil) {
      const lim = s('rect', { x: x - bw / 2, y, width: bw, height: ceil - y - 2, rx: 2 });
      lim.style.fill = '#d95926'; lim.style.fillOpacity = '0.85';
      svg.appendChild(lim);
    }
  });
  const line = s('line', { x1: 0, x2: W, y1: ceil, y2: ceil });
  line.style.stroke = '#a5a4ff'; line.style.strokeWidth = '1.5'; line.style.strokeDasharray = '6 6';
  svg.appendChild(line);
  return svg;
}

export default {
  render({ root, message, onSuccess }) {
    const user = input({ name: 'username', autocomplete: 'username', autocapitalize: 'none', spellcheck: 'false', required: true, autofocus: true });
    const pass = input({ name: 'password', type: 'password', autocomplete: 'current-password', required: true });
    const reveal = h('button', { type: 'button', class: 'btn ghost sm icon-only', 'aria-label': 'Show password', 'aria-pressed': 'false' }, icon('eye'));
    reveal.addEventListener('click', () => {
      const show = pass.type === 'password';
      pass.type = show ? 'text' : 'password';
      reveal.setAttribute('aria-pressed', String(show));
      reveal.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
      mount(reveal, icon(show ? 'eyeOff' : 'eye'));
    });
    const err = h('div', { role: 'alert' });
    const submit = h('button', { class: 'btn primary block', type: 'submit' }, 'Sign in');
    if (message) mount(err, h('div', { class: 'callout warn' }, icon('clock'), h('div', {}, message)));
    const form = h('form', { class: 'form', novalidate: true },
      err,
      field({ label: 'Username', name: 'username', control: user }),
      field({ label: 'Password', name: 'password', control: h('div', { class: 'input-group' }, pass, h('span', { class: 'addon' }, reveal)) }),
      submit);
    const passLabel = form.querySelectorAll('.field')[1].querySelector('.field-label');
    if (passLabel) { const l = h('label', { for: pass.id || (pass.id = 'login-pass') }, 'Password'); passLabel.replaceWith(l); }
    form.addEventListener('submit', async e => {
      e.preventDefault();
      if (!user.value.trim() || !pass.value) {
        mount(err, h('div', { class: 'form-error' }, icon('alertCircle'), h('div', {}, 'Enter your username and password.')));
        (user.value.trim() ? pass : user).focus();
        return;
      }
      submit.disabled = true;
      mount(submit, h('span', { class: 'spinner' }), 'Signing in…');
      try {
        const resp = await api.post('/auth/login', { username: user.value.trim(), password: pass.value });
        onSuccess(resp);
      } catch (ex) {
        const msg = ex.status === 401 || ex.status === 400 ? 'Invalid username or password.'
          : ex.status === 429 ? `Too many failed attempts. Try again ${ex.body && ex.body.retry_after_s ? `in ${ex.body.retry_after_s}s` : 'in a moment'}.` : ex.friendly;
        mount(err, h('div', { class: 'form-error' }, icon('alertCircle'), h('div', {}, msg)));
        pass.value = '';
        pass.focus();
      } finally {
        submit.disabled = false;
        mount(submit, 'Sign in');
      }
    });
    mount(root, h('div', { class: 'auth-page' },
      h('div', { class: 'auth-side' },
        h('div', { class: 'brand' }, h('span', { class: 'brand-logo' }, icon('shield')), 'RateGuard'),
        art(),
        h('div', {},
          h('h2', {}, 'Every request, exactly as fast as you allow.'),
          h('p', {}, 'Policies, plans and per-consumer limits for your APIs — enforced at the edge, observable in real time.')),
        h('div', { class: 'auth-feats' },
          h('span', {}, icon('zap', 'sm'), '7 algorithms'), h('span', {}, icon('eye', 'sm'), 'Shadow mode'), h('span', {}, icon('database', 'sm'), 'Redis-backed'))),
      h('main', { class: 'auth-main' },
        h('div', { class: 'auth-card' },
          h('div', { class: 'brand-logo mt-8', 'aria-hidden': 'true' }, icon('shield')),
          h('h1', { class: 'mt-16' }, 'Sign in to RateGuard'),
          h('p', { class: 'lede' }, 'Use your admin console credentials.'),
          form,
          api.MOCK ? h('div', { class: 'callout info mt-16' }, icon('info'), h('div', {}, 'Demo mode: any username and password works.')) : null,
          h('div', { class: 'auth-foot' }, h('span', {}, 'Protected by session cookies + CSRF'), h('span', {}, location.host))))));
  },
};
