// RateGuard dashboard entry point: session bootstrap, app shell, routing.
import './theme.js';
import { h, mount } from './dom.js';
import { icon } from './icons.js';
import * as api from './api.js';
import * as router from './router.js';
import * as theme from './theme.js';
import { session, setSession, can, system, invalidate } from './state.js';
import { toast, menuButton, errorState, confirm } from './ui.js';
import * as cmdk from './cmdk.js';

import login from './pages/login.js';
import password from './pages/password.js';
import overview from './pages/overview.js';
import logs from './pages/logs.js';
import routes from './pages/routes.js';
import policies from './pages/policies.js';
import plans from './pages/plans.js';
import consumers from './pages/consumers.js';
import consumer from './pages/consumer.js';
import simulator from './pages/simulator.js';
import limits from './pages/limits.js';
import integration from './pages/integration.js';
import audit from './pages/audit.js';
import settings from './pages/settings.js';
import systemPage from './pages/system.js';

const NAV = [
  { group: 'Monitor', items: [
    { path: '/', label: 'Overview', icon: 'overview', page: overview, keys: 'g o' },
    { path: '/logs', label: 'Live logs', icon: 'logs', page: logs, keys: 'g l' },
  ] },
  { group: 'Configure', items: [
    { path: '/routes', label: 'Routes', icon: 'route', page: routes, keys: 'g r' },
    { path: '/policies', label: 'Policies', icon: 'gauge', page: policies, keys: 'g p' },
    { path: '/plans', label: 'Plans', icon: 'layers', page: plans, keys: 'g n' },
    { path: '/consumers', label: 'Consumers', icon: 'users', page: consumers, keys: 'g c' },
  ] },
  { group: 'Tools', items: [
    { path: '/simulator', label: 'Simulator', icon: 'flask', page: simulator, keys: 'g s' },
    { path: '/limits', label: 'Limits inspector', icon: 'search', page: limits, keys: 'g m' },
    { path: '/integration', label: 'Integration', icon: 'plug', page: integration, keys: 'g i' },
  ] },
  { group: 'Admin', items: [
    { path: '/audit', label: 'Audit log', icon: 'scroll', page: audit, role: 'admin', keys: 'g a' },
    { path: '/settings', label: 'Settings', icon: 'settings', page: settings, keys: 'g ,' },
    { path: '/system', label: 'System', icon: 'server', page: systemPage, keys: 'g y' },
  ] },
];
const ALL = NAV.flatMap(g => g.items);
ALL.forEach(it => router.route(it.path, it));
router.route('/consumers/:id', { path: '/consumers', page: consumer, parent: ALL.find(x => x.path === '/consumers') });
router.route('/login', { page: login, bare: true });

const app = document.getElementById('app');
let shell = null;
let cleanup = null;
let pageAbort = null;
let returnTo = '';

/* ------------------------------------------------------------ shell */
function navItem(it) {
  const a = h('a', { class: 'nav-item', href: '#' + it.path, dataset: { path: it.path } }, icon(it.icon), h('span', {}, it.label),
    it.keys ? h('span', { class: 'nav-kbd', 'aria-hidden': 'true' }, it.keys.split(' ').map(k => h('kbd', {}, k))) : null);
  a.addEventListener('click', () => shell && shell.root.classList.remove('nav-open'));
  return a;
}

function buildShell() {
  const nav = h('nav', { class: 'nav', 'aria-label': 'Main' }, NAV.map(g => {
    const items = g.items.filter(it => !it.role || can(it.role));
    return items.length ? h('div', { class: 'nav-group' }, h('div', { class: 'nav-label' }, g.group), items.map(navItem)) : null;
  }));
  const statusPill = h('a', { class: 'status-pill', href: '#/system' }, h('span', { class: 'dot' }), h('span', { class: 'trunc' }, 'Checking engine…'));
  const sidebar = h('aside', { class: 'sidebar', id: 'sidebar' },
    h('a', { class: 'brand', href: '#/' }, h('span', { class: 'brand-logo' }, icon('shield')), 'RateGuard',
      api.MOCK ? h('span', { class: 'brand-env', title: 'Fixture data — no backend' }, 'Demo') : null),
    nav,
    h('div', { class: 'sidebar-foot' }, statusPill));

  const crumbs = h('div', { class: 'crumbs' });
  const menuBtn = h('button', { class: 'btn ghost icon-only menu-btn', 'aria-label': 'Open navigation', 'aria-controls': 'sidebar', onClick: () => root.classList.toggle('nav-open') }, icon('menu'));
  const isMac = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);
  const search = h('button', { class: 'search-btn', type: 'button', 'aria-label': 'Search and jump (Ctrl+K)', onClick: () => cmdk.openPalette() },
    icon('search'), h('span', { class: 'grow' }, 'Search or jump to…'), h('kbd', {}, isMac ? '⌘K' : 'Ctrl K'));
  const themeBtn = h('button', { class: 'btn ghost icon-only', type: 'button' });
  const paintTheme = () => {
    const dark = theme.effective() === 'dark';
    mount(themeBtn, icon(dark ? 'sun' : 'moon'));
    themeBtn.setAttribute('aria-label', dark ? 'Switch to light theme' : 'Switch to dark theme');
    themeBtn.title = themeBtn.getAttribute('aria-label') + ' (t)';
  };
  themeBtn.addEventListener('click', () => theme.toggle());
  theme.onChange(paintTheme);
  paintTheme();
  const helpBtn = h('button', { class: 'btn ghost icon-only hide-sm', type: 'button', 'aria-label': 'Keyboard shortcuts (?)', title: 'Keyboard shortcuts (?)', onClick: () => cmdk.showHelp() }, icon('keyboard'));
  const u = session.user;
  const userBtn = menuButton(h('button', { class: 'user-btn', type: 'button', 'aria-label': `Account: ${u.username}` },
    h('span', { class: 'avatar', 'aria-hidden': 'true' }, u.username.slice(0, 2)), h('span', { class: 'uname small' }, u.username), icon('chevronDown', 'sm')),
  () => [
    { header: h('div', {}, h('div', { class: 'n' }, u.username), h('div', { class: 'xs muted' }, `Signed in as ${u.role}`)) },
    '-',
    { label: 'Change password', icon: 'lock', onClick: () => renderPassword(false) },
    { label: 'Keyboard shortcuts', icon: 'keyboard', onClick: () => cmdk.showHelp() },
    { label: `Theme: ${theme.preference()}`, icon: 'monitor', onClick: () => theme.setTheme(theme.preference() === 'system' ? 'light' : theme.preference() === 'light' ? 'dark' : 'system') },
    '-',
    { label: 'Sign out', icon: 'logout', danger: true, onClick: logout },
  ]);
  const topbar = h('header', { class: 'topbar' }, menuBtn, crumbs, search, helpBtn, themeBtn, userBtn);
  const content = h('main', { class: 'content', id: 'main', tabindex: '-1' });
  const root = h('div', { class: 'shell' }, sidebar, h('div', { class: 'scrim', onClick: () => root.classList.remove('nav-open') }),
    h('div', { class: 'main' }, topbar, content));
  mount(app, root);
  app.classList.remove('boot');
  shell = { root, content, crumbs, nav, statusPill };
  pollStatus();
}

let statusTimer = 0;
async function pollStatus() {
  clearTimeout(statusTimer);
  if (!shell) return;
  try {
    const sys = await system({ fresh: true });
    const ok = sys.engine && sys.engine.healthy;
    mount(shell.statusPill, h('span', { class: `dot ${ok ? 'good' : 'crit'}` }),
      h('span', { class: 'trunc' }, `${sys.engine ? sys.engine.name : 'engine'} · ${ok ? 'healthy' : 'unhealthy'}`),
      h('span', { class: 'xs muted', style: { marginLeft: 'auto' } }, sys.version || ''));
  } catch { /* the page will surface errors */ }
  statusTimer = setTimeout(pollStatus, 30000);
}

function setCrumbs(parts) {
  if (!shell) return;
  mount(shell.crumbs, parts.map((p, i) => [
    i ? h('span', { class: 'sep', 'aria-hidden': 'true' }, '/') : null,
    i === parts.length - 1 ? h('span', { class: 'cur trunc', 'aria-current': 'page' }, p.label) : h('a', { href: '#' + p.path }, p.label),
  ]));
  document.title = `${parts[parts.length - 1].label} · RateGuard`;
}

/* ------------------------------------------------------------ routing */
function teardown() {
  if (pageAbort) pageAbort.abort();
  if (typeof cleanup === 'function') { try { cleanup(); } catch (e) { console.error(e); } }
  cleanup = null;
}

async function onRoute(r) {
  teardown();
  if (!session.user) {
    if (r.path !== '/login') returnTo = location.hash;
    renderLogin();
    return;
  }
  if (session.user.must_change_password) { renderPassword(true); return; }
  if (r.path === '/login') { router.go('/'); return; }
  if (!shell) buildShell();
  const def = r.route ? r.route.def : null;
  const navPath = def ? (def.parent ? def.parent.path : def.path) : '';
  shell.nav.querySelectorAll('.nav-item').forEach(a => {
    if (a.dataset.path === navPath) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current');
  });
  const content = shell.content;
  content.classList.remove('wide');
  if (!def) {
    setCrumbs([{ label: 'Not found' }]);
    mount(content, h('div', { class: 'empty' }, h('div', { class: 'empty-icon' }, icon('alert')), h('h3', {}, 'Page not found'),
      h('p', {}, 'There’s nothing at ', h('code', {}, r.path), '.'), h('div', { class: 'row' }, h('a', { class: 'btn', href: '#/' }, 'Back to overview'))));
    return;
  }
  if (def.role && !can(def.role)) {
    setCrumbs([{ label: def.label }]);
    mount(content, errorState({ status: 403 }));
    return;
  }
  const crumbs = def.parent ? [{ label: def.parent.label, path: def.parent.path }] : [{ label: def.label, path: def.path }];
  setCrumbs(crumbs);
  pageAbort = new AbortController();
  mount(content);
  window.scrollTo(0, 0);
  try {
    cleanup = await def.page.render({
      root: content, params: r.params, query: r.query, signal: pageAbort.signal,
      crumbs: extra => setCrumbs([...crumbs, ...extra]),
      wide: () => content.classList.add('wide'),
    });
  } catch (e) {
    console.error(e);
    mount(content, errorState(e, () => router.rerender()));
  }
}

function renderLogin(message) {
  shell = null;
  clearTimeout(statusTimer);
  app.classList.remove('boot');
  document.title = 'Sign in · RateGuard';
  login.render({ root: app, message, onSuccess: resp => {
    setSession(resp);
    invalidate();
    const target = returnTo && returnTo !== '#/login' ? returnTo : '#/';
    returnTo = '';
    if (location.hash === target) router.rerender(); else location.hash = target;
  } });
}

function renderPassword(forced) {
  if (forced) { shell = null; clearTimeout(statusTimer); }
  password.render({ root: app, forced, onDone: async () => {
    const me = await api.get('/auth/me');
    setSession(me);
    toast('good', 'Password updated');
    if (forced) router.rerender();
  } });
}

async function logout() {
  if (!(await confirm({ title: 'Sign out of RateGuard?', message: 'You’ll need to sign in again to manage the gateway.', confirmLabel: 'Sign out' }))) return;
  try { await api.post('/auth/logout'); } catch { /* session may already be gone */ }
  setSession(null);
  teardown();
  location.hash = '#/login';
}

api.on('unauthorized', () => {
  if (!session.user) return;
  setSession(null);
  teardown();
  returnTo = location.hash;
  renderLogin('Your session expired. Please sign in again.');
});
api.on('mustchange', () => {
  if (session.user) { session.user.must_change_password = true; teardown(); renderPassword(true); }
});

cmdk.init({
  pages: () => ALL.filter(it => !it.role || can(it.role)),
  actions: () => [
    can('edit') ? { group: 'Actions', label: 'Create policy', icon: 'plus', run: () => router.go('/policies', { new: '1' }) } : null,
    can('edit') ? { group: 'Actions', label: 'Create route', icon: 'plus', run: () => router.go('/routes', { new: '1' }) } : null,
    can('edit') ? { group: 'Actions', label: 'Create consumer', icon: 'plus', run: () => router.go('/consumers', { new: '1' }) } : null,
    { group: 'Actions', label: 'Test a request in the simulator', icon: 'flask', run: () => router.go('/simulator') },
    { group: 'Actions', label: 'Keyboard shortcuts', icon: 'keyboard', run: () => cmdk.showHelp() },
    { group: 'Actions', label: 'Sign out', icon: 'logout', run: logout },
  ].filter(Boolean),
});

/* ------------------------------------------------------------ boot */
async function boot() {
  try {
    setSession(await api.get('/auth/me'));
  } catch (e) {
    if (e.status !== 401) {
      app.classList.remove('boot');
      mount(app, h('div', { class: 'auth-main' }, errorState(e, () => location.reload())));
      return;
    }
    setSession(null);
  }
  router.start(onRoute);
}
boot();
