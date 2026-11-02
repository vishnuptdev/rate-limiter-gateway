// Helpers shared by the config CRUD pages (routes, policies, plans, consumers).
import { h, mount } from './dom.js';
import { icon } from './icons.js';
import { drawer, toast, confirm, busy, emptyState } from './ui.js';
import { showFormError, clearProblems } from './forms.js';
import { replaceQuery } from './router.js';

/**
 * Open a drawer containing `form`. onSave() resolves on success; errors are
 * mapped inline (422) or shown in the form. Returns the drawer handle.
 */
export function editorDrawer({ title, sub, form, saveLabel = 'Save changes', onSave, readOnly = false, extraFoot, wide = true, onClose }) {
  const save = h('button', { class: 'btn primary', type: 'submit', form: form.id }, saveLabel);
  const cancel = h('button', { class: 'btn', type: 'button' }, readOnly ? 'Close' : 'Cancel');
  let dirty = false;
  form.addEventListener('input', () => { dirty = true; });
  form.addEventListener('change', () => { dirty = true; });
  const d = drawer({
    title, sub, wide, body: form,
    foot: [extraFoot || null, h('span', { class: 'grow' }), cancel, readOnly ? null : save],
    onClose: () => { replaceQuery({ edit: '', new: '' }); if (onClose) onClose(); },
  });
  cancel.addEventListener('click', async () => {
    if (dirty && !readOnly && !(await confirm({ title: 'Discard changes?', message: 'Your edits haven’t been saved.', confirmLabel: 'Discard', danger: true }))) return;
    d.close();
  });
  form.addEventListener('submit', async e => {
    e.preventDefault();
    if (readOnly) return;
    clearProblems(form);
    await busy(save, async () => {
      try {
        await onSave();
        dirty = false;
        d.close();
      } catch (err) {
        showFormError(form, err);
        if (err.status !== 422) toast('crit', 'Couldn’t save', err.friendly);
      }
    });
  });
  if (readOnly) form.querySelectorAll('input, select, textarea, button:not([data-keep])').forEach(el => { el.disabled = true; });
  return d;
}

/** Confirm + delete with friendly 409 handling. */
export async function confirmDelete({ what, name, run, typeToConfirm = '' }) {
  const ok = await confirm({
    title: `Delete ${what}?`,
    message: h('p', { class: 'subtle' }, h('strong', {}, name), ` will be removed from the gateway configuration immediately. This can’t be undone.`),
    confirmLabel: `Delete ${what}`, danger: true, typeToConfirm,
  });
  if (!ok) return false;
  try {
    await run();
    toast('good', `${what.charAt(0).toUpperCase() + what.slice(1)} deleted`, name);
    return true;
  } catch (e) {
    toast('crit', `Couldn’t delete ${what}`, e.friendly);
    return false;
  }
}

/** Client-side search filter for list pages. */
export function filterRows(rows, q, fields) {
  q = (q || '').trim().toLowerCase();
  if (!q) return rows;
  return rows.filter(r => fields.some(f => String(typeof f === 'function' ? f(r) : r[f] ?? '').toLowerCase().includes(q)));
}

export function searchBox(placeholder, value, onInput) {
  const inp = h('input', { class: 'input', type: 'search', placeholder, 'aria-label': placeholder, value: value || '', dataset: { search: '1' } });
  inp.addEventListener('input', () => onInput(inp.value));
  return h('div', { class: 'input-wrap' }, icon('search'), inp, h('kbd', { class: 'hide-sm' }, '/'));
}

export function noMatches(clear) {
  return emptyState({ icon: 'search', title: 'No matches', text: 'Try a different search.', compact: true, action: h('button', { class: 'btn sm', onClick: clear }, 'Clear search') });
}

export function sectionTitle(title, desc) {
  return [h('div', { class: 'form-section-title' }, title), desc ? h('div', { class: 'muted' }, desc) : null];
}

export { mount };
