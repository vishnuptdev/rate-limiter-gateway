// Hash router: "#/consumers/acme?tab=keys" -> {path, params, query}.

const routes = [];
let handler = null;
let current = null;

/** route('/consumers/:id', def) */
export function route(pattern, def) {
  const keys = [];
  const re = new RegExp('^' + pattern.replace(/\/:([a-zA-Z_]+)/g, (_, k) => { keys.push(k); return '/([^/]+)'; }) + '/?$');
  routes.push({ pattern, re, keys, def });
}

export function parse(hash = location.hash) {
  const raw = hash.replace(/^#/, '') || '/';
  const [path, qs = ''] = raw.split('?');
  const query = Object.fromEntries(new URLSearchParams(qs));
  for (const r of routes) {
    const m = path.match(r.re);
    if (m) {
      const params = {};
      r.keys.forEach((k, i) => { params[k] = decodeURIComponent(m[i + 1]); });
      return { path, params, query, route: r };
    }
  }
  return { path, params: {}, query, route: null };
}

export function href(path, query) {
  const q = query ? new URLSearchParams(Object.entries(query).filter(([, v]) => v !== '' && v != null)).toString() : '';
  return '#' + path + (q ? '?' + q : '');
}

export function go(path, query) {
  const target = href(path, query);
  if (location.hash === target) dispatch();
  else location.hash = target;
}

/** Update the query string without re-rendering the page. */
export function replaceQuery(query) {
  const cur = parse();
  const target = href(cur.path, { ...cur.query, ...query });
  history.replaceState(history.state, '', target);
  if (current) current.query = parse().query;
}

export const currentRoute = () => current;

function dispatch() {
  current = parse();
  if (handler) handler(current);
}

export function start(fn) {
  handler = fn;
  window.addEventListener('hashchange', dispatch);
  dispatch();
}

export const rerender = () => dispatch();
