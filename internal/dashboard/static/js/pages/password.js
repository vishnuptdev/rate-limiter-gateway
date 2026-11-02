// Password change: forced (full screen, after bootstrap / admin reset) or voluntary (modal).
import { h, mount } from '../dom.js';
import { icon } from '../icons.js';
import * as api from '../api.js';
import { field, input, showFormError, clearProblems } from '../forms.js';
import { modal, busy } from '../ui.js';
import { session, setSession } from '../state.js';

function strength(pw) {
  let sc = 0;
  if (pw.length >= 12) sc++;
  if (pw.length >= 16) sc++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) sc++;
  if (/\d/.test(pw)) sc++;
  if (/[^A-Za-z0-9]/.test(pw)) sc++;
  return pw.length < 12 ? Math.min(sc, 1) : sc;
}

function buildForm(onDone, forced) {
  const cur = input({ name: 'current_password', type: 'password', autocomplete: 'current-password', autofocus: true });
  const next = input({ name: 'new_password', type: 'password', autocomplete: 'new-password' });
  const conf = input({ name: 'confirm', type: 'password', autocomplete: 'new-password' });
  const bar = h('span', { style: { width: '0%' } });
  const meter = h('div', { class: 'meter single', 'aria-hidden': 'true' }, bar);
  const label = h('span', { class: 'xs muted' }, 'At least 12 characters');
  next.addEventListener('input', () => {
    const sc = strength(next.value);
    bar.style.width = `${(sc / 5) * 100}%`;
    meter.className = `meter single ${sc <= 1 ? 'crit' : sc <= 3 ? 'warn' : 'good'}`;
    label.textContent = next.value.length < 12 ? `${12 - next.value.length} more characters needed` : ['Weak', 'Weak', 'Fair', 'Good', 'Strong', 'Excellent'][sc];
  });
  const submit = h('button', { class: `btn primary ${forced ? 'block' : ''}`, type: 'submit' }, 'Update password');
  const form = h('form', { class: 'form', novalidate: true },
    field({ label: 'Current password', name: 'current_password', control: cur }),
    field({ label: 'New password', name: 'new_password', control: next }),
    h('div', { class: 'stack tight' }, meter, label),
    field({ label: 'Confirm new password', name: 'confirm', control: conf }),
    forced ? submit : null);
  form.addEventListener('submit', async e => {
    e.preventDefault();
    clearProblems(form);
    if (next.value !== conf.value) {
      showFormError(form, { status: 422, problems: [{ field: 'confirm', message: 'Passwords don’t match' }] });
      return;
    }
    await busy(submit, async () => {
      try {
        const res = await api.post('/auth/password', { current_password: cur.value, new_password: next.value });
        if (res && res.csrf_token) { session.csrf = res.csrf_token; api.setCSRF(res.csrf_token); }
        await onDone();
      } catch (ex) { showFormError(form, ex); }
    });
  });
  return { form, submit };
}

export default {
  render({ root, forced, onDone }) {
    if (!forced) {
      let m;
      const { form, submit } = buildForm(async () => { m.close(); await onDone(); }, false);
      submit.addEventListener('click', () => form.requestSubmit());
      submit.type = 'button';
      m = modal({ title: 'Change password', icon: 'lock', body: form, foot: [h('button', { class: 'btn', type: 'button', onClick: () => m.close() }, 'Cancel'), submit] });
      return;
    }
    document.title = 'Change password · RateGuard';
    const { form } = buildForm(onDone, true);
    root.classList.remove('boot');
    mount(root, h('main', { class: 'auth-main' }, h('div', { class: 'auth-card' },
      h('div', { class: 'brand-logo', 'aria-hidden': 'true' }, icon('shield')),
      h('h1', { class: 'mt-16' }, 'Choose a new password'),
      h('p', { class: 'lede' }, `Welcome, ${session.user ? session.user.username : ''}. Your account requires a new password before you can continue.`),
      form,
      h('div', { class: 'auth-foot' }, h('button', { class: 'inline-link', type: 'button', onClick: async () => {
        try { await api.post('/auth/logout'); } catch { /* ignore */ }
        setSession(null); location.hash = '#/login'; location.reload();
      } }, 'Sign out instead'), h('span', {}, '')))));
  },
};
