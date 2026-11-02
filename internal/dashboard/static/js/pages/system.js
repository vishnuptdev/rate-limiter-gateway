// System info: version, engine/store health, addresses, uptime.
import { h, mount } from '../dom.js';
import { icon } from '../icons.js';
import * as fmt from '../format.js';
import { system } from '../state.js';
import { pageHead, card, badge, errorState, copyButton, skeletonCard } from '../ui.js';
import { addrToURL } from './consumer.js';

export default {
  async render({ root }) {
    const body = h('div', { class: 'grid two' }, skeletonCard(160), skeletonCard(160));
    const refresh = h('button', { class: 'btn', type: 'button' }, icon('refresh', 'sm'), 'Refresh');
    mount(root, pageHead({ title: 'System', lede: 'This RateGuard instance and the backends it depends on.', actions: refresh }), body);
    const draw = async () => {
      let s;
      try { s = await system({ fresh: true }); } catch (e) { mount(body, errorState(e, draw)); return; }
      const eng = s.engine || {};
      const gw = addrToURL(s.data_plane_addr);
      const row = (k, v) => [h('dt', {}, k), h('dd', {}, v)];
      const addr = (label, url) => h('span', { class: 'copy-inline' }, h('code', {}, url || '—'), url ? copyButton(url, { size: 'xs', iconOnly: true, label: `Copy ${label}` }) : null);
      mount(body,
        h('section', { class: 'card' },
          h('div', { class: 'card-head' }, h('h2', {}, 'Health')),
          h('div', { class: 'card-body stack' },
            h('div', { class: `verdict ${eng.healthy ? 'good' : 'crit'}` },
              h('div', { class: 'v-icon' }, icon(eng.healthy ? 'check' : 'alert', 'lg')),
              h('div', { class: 'grow' }, h('div', { class: 'v-title' }, eng.healthy ? 'All systems operational' : 'Rate-limit engine unhealthy'),
                h('div', { class: 'small subtle' }, eng.healthy ? 'The limiter backend is answering normally.' : (eng.error || 'Policies follow their fail mode (open or closed) until it recovers.')))),
            h('dl', { class: 'dl' },
              row('Engine', h('span', { class: 'row' }, h('strong', {}, eng.name || '—'), eng.healthy ? badge('Healthy', 'good', 'check') : badge('Unhealthy', 'crit', 'alert'))),
              row('Config store', h('strong', {}, (s.store && s.store.name) || '—')),
              row('Config version', h('span', { class: 'tnum' }, fmt.int(s.config_version))),
              row('Uptime', `${fmt.uptime(s.uptime_s)} · since ${fmt.dateTime(s.started_at)}`)))),
        h('section', { class: 'card' },
          h('div', { class: 'card-head' }, h('h2', {}, 'Instance')),
          h('div', { class: 'card-body' }, h('dl', { class: 'dl' },
            row('Version', h('code', {}, s.version || '—')),
            row('Go runtime', h('code', {}, s.go_version || '—')),
            row('Instance ID', h('span', { class: 'copy-inline' }, h('code', {}, s.instance_id || '—'), s.instance_id ? copyButton(s.instance_id, { size: 'xs', iconOnly: true, label: 'Copy instance ID' }) : null)),
            row('Data plane', addr('gateway URL', gw)),
            row('Admin', addr('admin URL', addrToURL(s.admin_addr))),
            row('Health checks', h('span', { class: 'small' }, h('code', {}, '/_rlg/healthz'), ' · ', h('code', {}, '/_rlg/readyz'))),
            row('Metrics', h('span', { class: 'small' }, h('code', {}, '/metrics'), h('span', { class: 'muted' }, ' on the admin port (Prometheus; token with read scope)')))))),
        card({ title: 'Endpoints', cls: 'span-2', body: h('div', { class: 'stack tight small' },
          h('div', { class: 'row' }, icon('globe', 'sm'), h('span', { class: 'grow' }, 'Proxy traffic'), h('code', {}, gw ? gw + '/…' : '—')),
          h('div', { class: 'row' }, icon('zap', 'sm'), h('span', { class: 'grow' }, 'Decision API'), h('code', {}, gw ? gw + '/_rlg/v1/check' : '—')),
          h('div', { class: 'row' }, icon('server', 'sm'), h('span', { class: 'grow' }, 'Admin API'), h('code', {}, location.origin + '/api'))) }));
    };
    refresh.addEventListener('click', draw);
    await draw();
  },
};
