// views/overview.js: the console's front page (UI brief, section 6).
//
// Device card, session gauge and sparkline (polls /api/sessions every 10 s), recent denies (tail of the
// syslog file that takes RT_FLOW, or on-box reporting, or the security log buffer), top policies by
// live sessions, a mini zone-pair matrix, warnings, the "managed from" card and quick links with
// filters pre-filled. Every tile is device data or an explicit state; nothing is decorative.

import { h, icon, put, stateCard, skeleton, setTicking } from '../dom.js';
import * as fmt from '../format.js';
import { Gauge } from '../widgets/gauge.js';
import { Sparkline } from '../widgets/sparkline.js';

const SESSIONS_EVERY_S = 10;
const DENIES_EVERY_S = 15;
const HISTORY = 60; // sparkline points: 10 minutes at 10 s
const DENY_TAG = 'RT_FLOW_SESSION_DENY';
const TICKER_ROWS = 5;
const SEP = ' \u00b7 ';
const ARROW = '\u2192';

export const view = {
  id: 'overview',
  title: 'Overview',
  icon: 'M4 4h6.5v8H4z M13.5 4H20v5h-6.5z M13.5 12H20v8h-6.5z M4 15h6.5v5H4z',
  mount(el, ctx) {
    const ov = new Overview(el, ctx);
    return { update: (route) => ov.update(route), unmount: () => ov.destroy() };
  },
};

// ---- helpers -------------------------------------------------------------------------------------

function quote(v) {
  const s = String(v);
  return /^[A-Za-z0-9._\-/*:|]+$/.test(s) ? s : `"${s.replace(/"/g, '\\"')}"`;
}

function modelName(model) {
  return model ? String(model).toUpperCase().replace(/^VSRX/, 'vSRX') : '';
}

function scopeKindLabel(id) {
  if (id.startsWith('lsys:')) return `Logical system ${id.slice(5)}`;
  if (id.startsWith('tenant:')) return `Tenant system ${id.slice(7)}`;
  return 'Root system';
}

function tile(cls, title, iconName) {
  const meta = h('div', { class: 'tile-meta' });
  const body = h('div', { class: 'tile-body' }, skeleton(3));
  const foot = h('div', { class: 'tile-foot', hidden: true });
  const titleId = `ov-${cls}-title`;
  const el = h(
    'section',
    { class: ['tile', `ov-${cls}`], 'aria-labelledby': titleId },
    h('div', { class: 'tile-head' }, h('h2', { class: 'tile-title', id: titleId }, icon(iconName), title), meta),
    body,
    foot,
  );
  return { el, meta, body, foot };
}

function errorState(res, what) {
  if (res.status === 0) return { status: 'offline', message: res.data.error };
  if (res.status === 429) return { status: 'failed', message: `${what}: reading too often; J-Wicket will try again.` };
  return { status: 'failed', message: res.data.error || `${what} failed (HTTP ${res.status}).` };
}

/** Extract the fields of one RT_FLOW_SESSION_DENY line (structured-data, BSD text or buffer form). */
export function parseDeny(line) {
  const out = { line, time: null, src: null, sport: null, dst: null, dport: null, proto: null, policy: null, from: null, to: null, app: null, iface: null, reason: null };
  const sd = {};
  const re = /([a-z][a-z0-9-]*)="([^"]*)"/g;
  let m;
  while ((m = re.exec(line)) !== null) sd[m[1]] = m[2];
  const iso = /^(?:<\d+>\d?\s*)?(\d{4}-\d\d-\d\d)[T.](\d\d:\d\d:\d\d)/.exec(line);
  const bsd = /^(?:<\d+>)?([A-Z][a-z]{2}\s+\d{1,2}\s+(\d\d:\d\d:\d\d))/.exec(line);
  out.time = iso ? iso[2] : bsd ? bsd[2] : null;
  if (sd['source-address']) {
    out.src = sd['source-address'];
    out.sport = sd['source-port'] || null;
    out.dst = sd['destination-address'] || null;
    out.dport = sd['destination-port'] || null;
    out.proto = sd['protocol-id'] || null;
    out.policy = sd['policy-name'] || null;
    out.from = sd['source-zone-name'] || null;
    out.to = sd['destination-zone-name'] || null;
    out.app = sd.application && sd.application !== 'UNKNOWN' ? sd.application : sd['service-name'] || null;
    out.iface = sd['packet-incoming-interface'] || null;
    out.reason = sd.reason || null;
    return out;
  }
  const t = /session denied\s+([0-9A-Fa-f:.]+)\/(\d+)->([0-9A-Fa-f:.]+)\/(\d+)\s+(.*)$/.exec(line);
  if (!t) return out;
  [, out.src, out.sport, out.dst, out.dport] = t;
  const rest = t[5].split(/\s+/).filter(Boolean);
  let i = 0;
  if (/^0x[0-9a-f]+$/i.test(rest[i] || '')) i += 1;
  out.app = rest[i] || null;
  i += 1;
  const pm = /^(\d+)\((\d+)\)$/.exec(rest[i] || '');
  if (pm) {
    out.proto = pm[1];
    i += 1;
  }
  out.policy = rest[i] || null;
  out.from = rest[i + 1] || null;
  out.to = rest[i + 2] || null;
  const ifc = rest.find((x) => /^[a-z]{2,6}-?\d+(\/\d+)*\.\d+$/.test(x) || /^(reth|ae|irb|lo|st)\d+\.\d+$/.test(x));
  if (ifc) out.iface = ifc;
  return out;
}

const PROTO = { 1: 'icmp', 6: 'tcp', 17: 'udp', 47: 'gre', 50: 'esp', 58: 'icmp6', 132: 'sctp' };

function protoName(p) {
  if (!p) return '';
  return PROTO[p] || String(p).toLowerCase();
}

// ---- the view ------------------------------------------------------------------------------------

class Overview {
  constructor(el, ctx) {
    this.el = el;
    this.ctx = ctx;
    this.dead = false;
    this.paused = false;
    this.history = [];
    this.prevIds = null;
    this.sess = null; // last /api/sessions payload
    this.sessError = null;
    this.sessAt = 0;
    this.sessStats = { added: null, ended: null };
    this.denySource = null; // { kind: 'file'|'report'|'buffer', id, label, params }
    this.denySources = null;
    this.denyCursor = null;
    this.denies = [];
    this.denyTotal = 0;
    this.denyNew = 0;
    this.denyWindow = 0;
    this.denyError = null;
    this.denyInfo = null;
    this.denyAt = 0;
    this.timers = { sess: 0, deny: 0, ago: 0 };
    this.build();
    this.offs = [
      ctx.store.on('inventory', () => this.renderInventory()),
      ctx.store.on('scope', () => this.onScope()),
    ];
    this.onRefresh = () => this.refresh();
    this.onToggleLive = () => this.togglePause();
    document.addEventListener('jwicket:refresh', this.onRefresh);
    document.addEventListener('jwicket:toggle-live', this.onToggleLive);
    this.timers.ago = setInterval(() => this.renderAges(), 5000);
    this.start();
  }

  async start() {
    await this.ctx.store.inventory();
    if (this.dead) return;
    this.renderInventory();
    this.pollSessions();
    setTimeout(() => this.pollDenies(), 700);
  }

  update() {
    // The overview has no view parameters of its own; scope changes arrive through the store.
  }

  destroy() {
    this.dead = true;
    clearTimeout(this.timers.sess);
    clearTimeout(this.timers.deny);
    clearInterval(this.timers.ago);
    for (const off of this.offs) off();
    document.removeEventListener('jwicket:refresh', this.onRefresh);
    document.removeEventListener('jwicket:toggle-live', this.onToggleLive);
    this.ctx.ui.setLive('overview', false);
  }

  // -- layout --

  build() {
    this.title = h('h1', { class: 'view-title' }, 'Overview');
    this.sub = h('p', { class: 'view-sub' }, 'Reading the device\u2026');
    this.livePill = h('button', { class: 'live-pill', type: 'button', on: { click: () => this.togglePause() } });
    const refresh = h(
      'button',
      { class: 'btn', type: 'button', title: 'Read the device again (r)', on: { click: () => this.refresh(true) } },
      icon('refresh'),
      'Refresh',
    );
    this.head = h(
      'div',
      { class: 'view-head' },
      h('div', null, this.title, this.sub),
      h('div', { class: 'view-actions' }, this.livePill, refresh),
    );
    this.t = {
      device: tile('device', 'Device', 'server'),
      sessions: tile('sessions', 'Flow sessions', 'sessions'),
      managed: tile('managed', 'Managed from', 'broadcast'),
      denies: tile('denies', 'Recent denies', 'ban'),
      top: tile('top', 'Top policies by live sessions', 'policies'),
      matrix: tile('matrix', 'Zone pairs', 'grid'),
      warnings: tile('warnings', 'Warnings', 'alert'),
      links: tile('links', 'Jump to', 'arrow'),
    };
    this.grid = h('div', { class: 'ov-grid' }, Object.values(this.t).map((t) => t.el));
    put(this.el, this.head, this.grid);
    this.buildSessionsTile();
    this.renderLivePill();
  }

  buildSessionsTile() {
    const t = this.t.sessions;
    this.gauge = new Gauge({ size: 116, stroke: 9, label: 'Active sessions of the device maximum' });
    this.spark = new Sparkline({ height: 34, label: 'Active sessions per poll' });
    this.sessActive = h('span', { class: 'big-num' }, '\u2014');
    this.sessOf = h('span', { class: 'of' }, '');
    this.sparkLo = h('span', null, '');
    this.sparkHi = h('span', null, '');
    this.statNew = h('b', null, '\u2014');
    this.statEnded = h('b', null, '\u2014');
    this.statRows = h('b', null, '\u2014');
    this.sessNote = h('div', null);
    this.sessContent = h(
      'div',
      null,
      h(
        'div',
        { class: 'sess-main' },
        this.gauge.el,
        h(
          'div',
          { class: 'sess-figs' },
          this.sessActive,
          this.sessOf,
          h(
            'div',
            { class: 'sess-spark' },
            h('div', { class: 'sess-spark-head' }, h('span', null, 'active, last 10 min'), h('span', null, this.sparkLo, ' \u2013 ', this.sparkHi)),
            this.spark.el,
          ),
        ),
      ),
      h(
        'div',
        { class: 'sess-stats' },
        h('div', { class: 'stat up', title: 'Sessions in this poll that were not in the previous one' }, this.statNew, h('span', null, 'new')),
        h('div', { class: 'stat down', title: 'Sessions in the previous poll that are gone now' }, this.statEnded, h('span', null, 'ended')),
        h('div', { class: 'stat', title: 'Rows the device listed (J-Wicket lists at most 500 here)' }, this.statRows, h('span', null, 'listed')),
      ),
      this.sessNote,
    );
    this.sessAgo = h('span', null, '');
    const link = h(
      'a',
      { href: this.ctx.href('sessions', {}), on: { click: (e) => { e.preventDefault(); this.ctx.navigate('sessions', {}); } } },
      'Open Sessions',
      icon('arrow-right'),
    );
    put(t.foot, this.sessAgo, h('span', { class: 'spacer' }), link);
    t.foot.hidden = false;
  }

  renderLivePill() {
    const live = !this.paused;
    this.livePill.className = `live-pill${live ? '' : ' paused'}`;
    put(this.livePill, 
      h('span', { class: 'dot', 'aria-hidden': 'true' }),
      live ? 'LIVE' : 'PAUSED',
      h('span', { class: 'sub' }, live ? `${SESSIONS_EVERY_S} s` : 'space'),
    );
    this.livePill.setAttribute('aria-pressed', live ? 'false' : 'true');
    this.livePill.setAttribute('aria-label', live ? `Live: sessions every ${SESSIONS_EVERY_S} s, denies every ${DENIES_EVERY_S} s. Pause (space).` : 'Paused. Resume live updates (space).');
    this.livePill.title = live ? 'Pause live updates (space)' : 'Resume live updates (space)';
    this.ctx.ui.setLive('overview', live);
  }

  togglePause() {
    this.paused = !this.paused;
    this.renderLivePill();
    this.ctx.ui.announce(this.paused ? 'Overview paused.' : 'Overview live.');
    if (!this.paused) {
      this.pollSessions();
      setTimeout(() => this.pollDenies(), 400);
    } else {
      clearTimeout(this.timers.sess);
      clearTimeout(this.timers.deny);
    }
  }

  async refresh(fromButton = false) {
    if (fromButton) this.ctx.ui.toast('Refreshing from the device\u2026', 'info');
    await this.ctx.store.inventory(true);
    if (this.dead) return;
    this.pollSessions(true);
    setTimeout(() => this.pollDenies(true), 400);
  }

  onScope() {
    for (const k of ['device', 'matrix', 'managed', 'warnings', 'links']) put(this.t[k].body, skeleton(3));
    this.renderLivePill();
    this.renderSessions();
    this.renderTop();
    // Sessions are read for the root system only; the poll stops elsewhere and restarts on return.
    if (this.ctx.store.scope === 'root' && !this.paused) this.pollSessions();
  }

  renderAges() {
    if (this.sessAt) this.sessAgo.textContent = `updated ${fmt.ago(this.sessAt)}`;
    if (this.denyAgo && this.denyAt) this.denyAgo.textContent = `updated ${fmt.ago(this.denyAt)}`;
    const snap = this.ctx.store.lastInventory;
    if (snap && this.readAgo) this.readAgo.textContent = fmt.ago(snap.meta.read_at);
  }

  // -- inventory tiles --

  renderInventory() {
    if (this.dead) return;
    const snap = this.ctx.store.lastInventory;
    const err = this.ctx.store.inventoryError;
    if (!snap) {
      const card = err ? stateCard(err.status === 0 ? { status: 'offline', message: err.message } : { status: 'failed', message: err.message }) : skeleton(3);
      for (const k of ['device', 'matrix', 'managed', 'warnings']) put(this.t[k].body, card.cloneNode(true));
      this.sub.textContent = err ? 'The device could not be read.' : 'Reading the device\u2026';
      this.renderLinks();
      return;
    }
    const dev = snap.device || {};
    this.sub.textContent = [
      dev.status === 'ok' ? dev.hostname : null,
      (snap.meta.scopes || []).find((s) => s.id === snap.meta.scope)?.label || scopeKindLabel(snap.meta.scope || 'root'),
      `read ${fmt.time(snap.meta.read_at)} UTC`,
      `as ${(snap.meta.read_as || {}).user || '?'}`,
    ]
      .filter(Boolean)
      .join(SEP);
    this.renderDevice(snap);
    this.renderManaged(snap);
    this.renderMatrix(snap);
    this.renderWarnings();
    this.renderTop();
    this.renderLinks();
  }

  renderDevice(snap) {
    const t = this.t.device;
    const dev = snap.device || {};
    const ha = snap.ha || {};
    const meta = snap.meta || {};
    this.readAgo = h('span', null, fmt.ago(meta.read_at));
    put(t.meta, h('span', null, `read ${fmt.time(meta.read_at)} UTC`), h('span', { class: 'faint' }, '\u00b7'), this.readAgo);
    const parts = [];
    if (dev.status === 'ok') {
      parts.push(
        h('div', { class: 'dev-id' }, h('span', { class: 'dev-host' }, dev.hostname || 'unnamed device')),
        h(
          'div',
          { class: 'dev-sub' },
          dev.model ? h('span', { class: 'pill muted' }, modelName(dev.model)) : null,
          h('span', { class: 'pill sky' }, `Junos ${dev.version || 'release not reported'}`),
          this.haBadge(ha),
        ),
      );
      const versions = [...new Set((dev.nodes || []).map((n) => n.version).filter(Boolean))];
      if (versions.length > 1) parts.push(h('p', { class: 'act-reject small' }, `Nodes report different releases: ${versions.join(', ')}`));
    } else {
      parts.push(stateCard({ status: dev.status || 'failed', message: dev.message, title: 'Device facts could not be read', compact: true }));
    }
    parts.push(this.haBlock(ha, dev));
    parts.push(this.inventoryCounts(snap));
    const scopes = meta.scopes || [];
    const scopeInfo = scopes.find((s) => s.id === meta.scope);
    const ra = meta.read_as || {};
    const src = meta.source || {};
    parts.push(
      h(
        'dl',
        { class: 'kv dev-facts' },
        h('dt', null, 'Scope'),
        h(
          'dd',
          null,
          scopeInfo ? scopeInfo.label : scopeKindLabel(meta.scope || 'root'),
          scopes.length > 1 ? h('span', { class: 'faint' }, `${SEP}${fmt.plural(scopes.length, 'scope')} on this device`) : null,
          snap.scope && snap.scope.inactive ? [' ', h('span', { class: 'pill reject' }, 'deactivated')] : null,
        ),
        h('dt', null, 'Read as'),
        h(
          'dd',
          null,
          h('span', { class: 'mono strong' }, ra.user || '?'),
          h(
            'span',
            { class: ra.backend === 'lab-token' ? 'act-reject' : 'faint' },
            ra.backend === 'lab-token'
              ? `${SEP}lab token: the daemon's account, not you`
              : ra.backend === 'fixture'
                ? `${SEP}fixture replay, not a Junos session`
                : `${SEP}your own Junos session and login class`,
          ),
        ),
        h('dt', null, 'Source'),
        h(
          'dd',
          null,
          `${src.database === 'committed' ? 'committed configuration' : `${src.database || 'unknown'} configuration`}${SEP}${src.inheritance ? 'inheritance expanded' : 'inheritance not expanded'}`,
        ),
      ),
    );
    put(t.body, ...parts);
  }

  haBadge(ha) {
    if (ha.status && ha.status !== 'ok') return h('span', { class: 'ha-badge' }, `HA ${ha.status}`);
    if (ha.mode === 'standalone') return h('span', { class: 'ha-badge' }, 'standalone');
    if (ha.mode === 'chassis-cluster') return h('span', { class: 'ha-badge cluster' }, `chassis cluster${ha.cluster_id ? ` ${ha.cluster_id}` : ''}`);
    if (ha.mode === 'mnha') return h('span', { class: 'ha-badge cluster' }, 'multinode HA');
    return h('span', { class: 'ha-badge' }, 'HA unknown');
  }

  haBlock(ha, dev) {
    if (ha.status && ha.status !== 'ok') {
      return h('div', { class: 'dev-ha' }, stateCard({ status: ha.status, message: ha.message, title: 'High availability status could not be read', compact: true }));
    }
    if (ha.mode !== 'chassis-cluster') {
      // Standalone can carry a reason ("Chassis cluster status was not available ..."); say it.
      return ha.message ? h('div', { class: 'dev-ha' }, h('p', { class: 'small muted' }, ha.message)) : null;
    }
    const hosts = new Map((dev.nodes || []).map((n) => [n.node, n.hostname]));
    return h(
      'div',
      { class: 'dev-ha' },
      (ha.redundancy_groups || []).map((g) =>
        h(
          'div',
          { class: 'rg-row' },
          h('span', { class: 'rg-id' }, `RG${g.id}`),
          (g.nodes || []).map((n) => {
            const primary = String(n.status || '').toLowerCase() === 'primary';
            return h(
              'span',
              { class: ['rg-node', primary && 'primary'], title: `${n.name}${hosts.get(n.name) ? ` (${hosts.get(n.name)})` : ''}: ${n.status || 'status not reported'}, priority ${n.priority || '?'}` },
              n.name,
              hosts.get(n.name) ? h('span', { class: 'prio' }, hosts.get(n.name)) : null,
              h('span', { class: 'prio' }, `${n.status || '?'} ${n.priority || ''}`.trim()),
            );
          }),
        ),
      ),
      h('p', { class: 'xsmall faint' }, ha.local_node ? `This page is served by ${ha.local_node}.` : 'Which node serves this page is not reported.'),
    );
  }

  inventoryCounts(snap) {
    const scope = snap.scope;
    if (!scope) {
      const cfg = snap.config || {};
      return h(
        'div',
        { class: 'inv-counts-state' },
        stateCard({ status: cfg.status || 'failed', message: cfg.message, title: 'The configuration could not be read', compact: true }),
      );
    }
    const go = (viewId, params) => (e) => {
      e.preventDefault();
      this.ctx.navigate(viewId, params);
    };
    const count = (label, section, value, sub, viewId, params, meter) => {
      const ok = section && section.status === 'ok';
      return h(
        'a',
        { class: 'inv-count', href: this.ctx.href(viewId, params), on: { click: go(viewId, params) }, title: ok ? `${label}: ${sub}` : `${label}: ${section ? section.status : 'not read'}` },
        h('b', null, ok ? fmt.num(value) : '\u2014'),
        h('span', null, ok ? label : `${label}: ${section ? section.status : 'not read'}`),
        ok && meter ? meter : null,
      );
    };
    const pol = scope.policies || {};
    const rows = pol.rows || [];
    const active = rows.filter((r) => !r.inactive_reason);
    const n = (a) => active.filter((r) => r.action === a).length;
    const total = Math.max(1, rows.length);
    const seg = (cls, v) => (v ? h('i', { class: cls, style: { '--w': `${(v / total) * 100}%` } }) : null);
    const meter = h(
      'div',
      { class: 'meter', 'aria-hidden': 'true' },
      seg('permit', n('permit')),
      seg('deny', n('deny')),
      seg('reject', n('reject')),
      seg('inactive', rows.length - active.length),
    );
    const zones = scope.zones || {};
    const books = scope.address_books || {};
    const apps = scope.applications || {};
    const addrCount = (books.rows || []).reduce((s, b) => s + (b.addresses || []).length + (b.sets || []).length, 0);
    return h(
      'div',
      { class: 'inv-counts' },
      count('policies', pol, rows.length, `${n('permit')} permit, ${n('deny')} deny, ${n('reject')} reject, ${rows.length - active.length} inactive`, 'policies', {}, meter),
      count('zones', zones, (zones.rows || []).length, `${(zones.rows || []).reduce((s, z) => s + (z.interfaces || []).length, 0)} interfaces`, 'objects', { tab: 'zones' }),
      count('addresses', books, addrCount, `${(books.rows || []).length} address books`, 'objects', { tab: 'address-books' }),
      count('applications', apps, (apps.rows || []).length, 'custom applications and sets', 'objects', { tab: 'applications' }),
    );
  }

  renderManaged(snap) {
    const t = this.t.managed;
    const mg = snap.management || {};
    const cfg = snap.config || {};
    put(t.meta, mg.status === 'ok' ? h('span', null, mg.managed ? fmt.plural((mg.clients || []).length, 'client') : 'none') : null);
    if (mg.status !== 'ok') {
      put(t.body, 
        stateCard({
          status: mg.status || 'failed',
          title: 'Not known',
          message: cfg.status && cfg.status !== 'ok' ? 'Central management is read from the configuration, which could not be read.' : mg.message,
          hint: 'Another system may also manage this device.',
          compact: true,
        }),
      );
      return;
    }
    if (!mg.managed) {
      put(t.body, 
        h(
          'div',
          { class: 'mg-none' },
          icon('check-circle'),
          h(
            'div',
            null,
            h('p', null, 'No outbound-SSH management client is configured.'),
            h('p', { class: 'small faint' }, 'Security Director, Mist and similar managers connect this way. Operators and scripts using the CLI or NETCONF are not listed here.'),
          ),
        ),
      );
      return;
    }
    put(t.body, 
      ...(mg.clients || []).map((c) =>
        h(
          'div',
          { class: 'mg-client' },
          h('span', { class: 'mg-name' }, icon('broadcast'), c.client),
          (c.targets || []).length ? h('span', { class: 'mg-targets' }, c.targets.map((x) => h('span', { class: 'zone' }, x))) : null,
          (c.services || []).length ? h('span', { class: 'mg-targets' }, c.services.map((s) => h('span', { class: 'pill gold' }, s))) : null,
        ),
      ),
      h('p', { class: 'mg-note' }, 'Another system holds a management connection (outbound SSH). Changes made there can overwrite this configuration without J-Wicket knowing.'),
    );
  }

  renderMatrix(snap) {
    const t = this.t.matrix;
    const scope = snap.scope;
    if (!scope) {
      t.meta.replaceChildren();
      put(t.body, stateCard({ status: (snap.config || {}).status || 'failed', message: (snap.config || {}).message, compact: true }));
      return;
    }
    const pol = scope.policies || {};
    if (pol.status !== 'ok') {
      put(t.body, stateCard({ status: pol.status, message: pol.message, compact: true }));
      return;
    }
    const pairs = pol.zone_pairs || [];
    const zoneNames = new Set(((scope.zones && scope.zones.rows) || []).map((z) => z.name));
    for (const p of pairs) {
      zoneNames.add(p.from);
      zoneNames.add(p.to);
    }
    const weight = new Map();
    for (const p of pairs) {
      weight.set(p.from, (weight.get(p.from) || 0) + p.count);
      weight.set(p.to, (weight.get(p.to) || 0) + p.count);
    }
    const all = [...zoneNames];
    const zones = all.sort((a, b) => (weight.get(b) || 0) - (weight.get(a) || 0) || a.localeCompare(b)).slice(0, 7);
    const byPair = new Map(pairs.map((p) => [`${p.from}\u0000${p.to}`, p]));
    const live = this.liveByPair();
    put(t.meta, h('span', null, `${fmt.plural((pol.rows || []).length, 'policy')}${SEP}${pol.global_count || 0} global`));
    if (!zones.length) {
      put(t.body, stateCard({ status: 'empty', message: 'No security zones are configured in this scope.', compact: true }));
      return;
    }
    const cells = [h('div', { class: 'mx-corner', title: 'Rows: from-zone. Columns: to-zone.' }, h('span', null, `from ${ARROW}`))];
    for (const z of zones) cells.push(h('div', { class: 'mx-col', title: `to ${z}` }, h('span', null, z)));
    for (const from of zones) {
      cells.push(h('div', { class: 'mx-rowh', title: `from ${from}` }, h('span', null, from)));
      for (const to of zones) {
        const p = byPair.get(`${from}\u0000${to}`);
        const sessions = live ? live.get(`${from}\u0000${to}`) || 0 : null;
        const params = { q: `from:${quote(from)} to:${quote(to)}` };
        const label = p
          ? `${from} to ${to}: ${fmt.plural(p.count, 'policy')} (${p.permit} permit, ${p.deny} deny, ${p.reject} reject, ${p.inactive} inactive)${sessions !== null ? `, ${fmt.plural(sessions, 'live session')}` : ''}`
          : `${from} to ${to}: no zone-pair policy, so global policies and then the default policy apply`;
        const total = p ? Math.max(1, p.count) : 1;
        const mix = p
          ? h(
              'span',
              { class: 'mx-mix', 'aria-hidden': 'true' },
              ['permit', 'deny', 'reject', 'inactive'].map((k) => (p[k] ? h('i', { class: k, style: { '--w': `${(p[k] / total) * 100}%` } }) : null)),
            )
          : null;
        cells.push(
          h(
            'a',
            {
              class: ['mx-cell', !p && 'empty', from === to && 'self'],
              href: this.ctx.href('policies', params),
              title: label,
              'aria-label': label,
              on: { click: (e) => { e.preventDefault(); this.ctx.navigate('policies', params); } },
            },
            p ? h('b', null, String(p.count)) : h('span', { 'aria-hidden': 'true' }, '\u00b7'),
            sessions ? h('span', { class: 'live' }, fmt.compact(sessions)) : null,
            mix,
          ),
        );
      }
    }
    const grid = h('div', { class: 'mx', style: { gridTemplateColumns: `minmax(44px, auto) repeat(${zones.length}, minmax(0, 1fr))` } }, cells);
    const more = all.length > zones.length ? h('p', { class: 'xsmall faint' }, `${all.length - zones.length} more zones in Policies.`) : null;
    const dp = pol.default_policy || 'not reported';
    const legend = h(
      'div',
      { class: 'mx-legend' },
      h('span', null, h('i', { class: 'permit' }), 'permit'),
      h('span', null, h('i', { class: 'deny' }), 'deny'),
      h('span', null, h('i', { class: 'reject' }), 'reject'),
      live ? h('span', null, h('i', { class: 'live' }), 'live sessions') : null,
    );
    put(t.body, grid, more, legend);
    put(
      t.foot,
      h(
        'span',
        { class: 'eval-hint', title: 'Junos evaluation order: the zone pair\u2019s policies in order, then global policies, then the default policy' },
        h('span', null, 'no match'),
        icon('chevron-right'),
        h('span', { class: 'step' }, `${pol.global_count || 0} global`),
        icon('chevron-right'),
        h('span', { class: ['step', pol.default_policy ? (/deny|reject/.test(dp) ? 'act-deny' : /permit/.test(dp) ? 'act-permit' : null) : null], title: 'Default policy' }, pol.default_policy ? dp : 'default not reported'),
      ),
    );
    t.foot.hidden = false;
  }

  /** Live sessions per zone pair, from the last poll and the policy index (null when not known). */
  liveByPair() {
    const s = this.sess;
    if (!s || !s.sessions || s.sessions.status !== 'ok' || this.ctx.store.scope !== 'root') return null;
    const idx = this.ctx.store.policyIndex();
    const out = new Map();
    for (const r of s.sessions.rows || []) {
      const p = r.policy && idx.get(r.policy);
      if (!p || p.ambiguous || p.kind !== 'zone' || p.from.length !== 1 || p.to.length !== 1) continue;
      const key = `${p.from[0]}\u0000${p.to[0]}`;
      out.set(key, (out.get(key) || 0) + 1);
    }
    return out;
  }

  renderWarnings() {
    const t = this.t.warnings;
    const snap = this.ctx.store.lastInventory;
    const items = [];
    if (snap) {
      for (const w of snap.warnings || []) items.push({ text: w, src: 'device', cls: /fixture/i.test(w) ? 'fixture' : '' });
      for (const w of (snap.scope && snap.scope.warnings) || []) items.push({ text: w, src: 'scope', cls: '' });
      const cfg = snap.config || {};
      if (cfg.status && cfg.status !== 'ok') items.push({ text: `Configuration: ${cfg.message || cfg.status}`, src: cfg.status, cls: 'bad' });
      const dev = snap.device || {};
      if (dev.status && dev.status !== 'ok') items.push({ text: `Device facts: ${dev.message || dev.status}`, src: dev.status, cls: 'bad' });
      const saysInactive = ((snap.scope && snap.scope.warnings) || []).some((w) => /deactivated|inactive/i.test(w));
      if (snap.scope && snap.scope.inactive && !saysInactive) items.push({ text: 'This scope is deactivated in the configuration: nothing in it is in effect.', src: 'scope', cls: 'bad' });
    }
    if (this.sessError && this.sessError.status !== 'unsupported') items.push({ text: `Sessions: ${this.sessError.message || this.sessError.status}`, src: this.sessError.status, cls: 'bad' });
    if (this.denyError) items.push({ text: `Recent denies: ${this.denyError.message || this.denyError.status}`, src: this.denyError.status, cls: this.denyError.status === 'denied' ? 'info' : 'bad' });
    put(t.meta, items.length ? h('span', { class: ['badge', items.some((i) => i.cls === 'bad') ? 'deny' : 'amber'] }, String(items.length)) : null);
    if (!snap && !items.length) return;
    if (!items.length) {
      put(t.body, h('div', { class: 'mg-none' }, icon('check-circle'), h('p', null, 'No warnings from the last read.')));
      return;
    }
    put(t.body, 
      h(
        'ul',
        { class: 'warn-list' },
        items.map((w) => h('li', { class: ['warn-item', w.cls] }, icon(w.cls === 'fixture' ? 'info' : w.cls === 'info' ? 'lock' : 'alert'), h('span', null, w.text), h('span', { class: 'warn-src' }, w.src))),
      ),
    );
  }

  // -- sessions --

  async pollSessions(now = false) {
    clearTimeout(this.timers.sess);
    if (this.dead) return;
    if (this.ctx.store.scope !== 'root') {
      this.renderSessions();
      return;
    }
    if (this.paused && !now) return;
    if (this.inflightSess) return;
    this.inflightSess = true;
    const res = await this.ctx.api.get('/api/sessions', { scope: 'root' });
    this.inflightSess = false;
    if (this.dead || res.status === 401) return;
    let next = SESSIONS_EVERY_S * 1000;
    if (res.ok) {
      this.applySessions(res.data);
      const min = Number(res.data.meta && res.data.meta.min_interval_s) || 0;
      next = Math.max(next, min * 1000);
    } else if (res.status === 429) {
      next = Math.max(next, (res.retryAfter || 2) * 1000);
    } else {
      this.sessError = res.status === 400 ? { status: 'unsupported', message: res.data.error } : errorState(res, 'Sessions');
      this.renderSessions();
      this.renderWarnings();
      next = 30000;
    }
    if (!this.paused && !this.dead && this.ctx.store.scope === 'root') this.timers.sess = setTimeout(() => this.pollSessions(), next);
  }

  applySessions(data) {
    this.sessError = null;
    this.ctx.ui.noteFixture(data.meta);
    const table = data.sessions || {};
    const summary = data.summary || {};
    const complete = table.status === 'ok' && !table.truncated;
    if (complete) {
      const ids = new Set((table.rows || []).map((r) => r.id));
      if (this.prevIds) {
        let added = 0;
        let ended = 0;
        for (const id of ids) if (!this.prevIds.has(id)) added += 1;
        for (const id of this.prevIds) if (!ids.has(id)) ended += 1;
        this.sessStats = { added, ended };
        if (added) this.ctx.ui.announce(`${fmt.plural(added, 'new session')} since the last poll.`);
      }
      this.prevIds = ids;
    } else {
      this.prevIds = null;
      this.sessStats = { added: null, ended: null };
    }
    if (summary.status === 'ok' && Number.isFinite(summary.active)) {
      this.history.push(summary.active);
      if (this.history.length > HISTORY) this.history.shift();
    }
    this.sess = data;
    this.sessAt = Date.now();
    this.ctx.store.setSessionsLast(data);
    this.renderSessions();
    this.renderTop();
    const snap = this.ctx.store.lastInventory;
    if (snap) {
      this.renderMatrix(snap);
      this.renderLinks();
    }
    this.renderWarnings();
  }

  renderSessions() {
    const t = this.t.sessions;
    if (this.ctx.store.scope !== 'root') {
      t.meta.replaceChildren();
      put(t.body, 
        stateCard({
          status: 'unsupported',
          title: 'Sessions are read for the whole device',
          message: 'Flow sessions are listed for the root system only in this release (Spec 004); logical and tenant systems are not separated yet.',
          hint: null,
          actions: [h('button', { class: 'btn sm', type: 'button', on: { click: () => this.ctx.navigate('overview', { scope: 'root' }) } }, 'Show the root system')],
          compact: true,
        }),
      );
      t.foot.hidden = true;
      return;
    }
    t.foot.hidden = false;
    if (this.sessError) {
      t.meta.replaceChildren();
      put(t.body, stateCard({ ...this.sessError, compact: true }));
      return;
    }
    const data = this.sess;
    if (!data) return;
    const summary = data.summary || {};
    const table = data.sessions || {};
    if (summary.status !== 'ok' && table.status !== 'ok' && table.status !== 'refused') {
      t.meta.replaceChildren();
      put(t.body, stateCard({ status: table.status || summary.status || 'failed', message: table.message || summary.message, compact: true }));
      return;
    }
    if (t.body.firstChild !== this.sessContent) put(t.body, this.sessContent);
    const active = summary.status === 'ok' ? summary.active : table.status === 'ok' ? (table.rows || []).length : null;
    const max = summary.status === 'ok' ? summary.max : null;
    this.gauge.update(active, max, {
      text: max ? fmt.pct(active, max) : '\u2014',
      sub: max ? 'of maximum' : 'max unknown',
    });
    setTicking(this.sessActive, fmt.num(active));
    this.sessOf.textContent = max ? `active of ${fmt.num(max)} maximum` : summary.status === 'ok' ? 'active (maximum not reported)' : `summary ${summary.status}: ${summary.message || ''}`;
    this.spark.update(this.history);
    this.sparkLo.textContent = this.history.length ? fmt.num(Math.min(...this.history)) : '\u2014';
    this.sparkHi.textContent = this.history.length ? fmt.num(Math.max(...this.history)) : '\u2014';
    const { added, ended } = this.sessStats;
    setTicking(this.statNew, added === null ? '\u2014' : `+${fmt.num(added)}`);
    setTicking(this.statEnded, ended === null ? '\u2014' : `\u2212${fmt.num(ended)}`);
    this.statRows.textContent = table.status === 'ok' ? fmt.num((table.rows || []).length) : table.status === 'refused' ? 'none' : '\u2014';
    let note = null;
    if (table.status === 'refused') {
      note = stateCard({ status: 'refused', message: table.message, hint: 'The gauge still counts every session; Sessions lists them with a filter.', compact: true });
    } else if (table.status !== 'ok') {
      note = stateCard({ status: table.status || 'failed', message: table.message, compact: true });
    } else if (table.truncated) {
      note = h('p', { class: 'xsmall faint' }, `The device listed ${fmt.num(table.returned)} sessions; the first ${fmt.num((table.rows || []).length)} are counted here, so new and ended are not shown.`);
    }
    put(this.sessNote, ...(note ? [note] : []));
    if (note) this.sessNote.style.marginTop = '12px';
    put(t.meta, h('span', null, data.meta && data.meta.read_at ? `${fmt.time(data.meta.read_at)} UTC` : ''));
    this.sessAgo.textContent = `updated ${fmt.ago(this.sessAt)}`;
  }

  renderTop() {
    const t = this.t.top;
    if (this.ctx.store.scope !== 'root') {
      t.meta.replaceChildren();
      put(t.body, stateCard({ status: 'unsupported', title: 'Needs the root system', message: 'Live sessions are read for the whole device, so this list is shown in the root system.', hint: null, compact: true }));
      return;
    }
    if (this.sessError) {
      t.meta.replaceChildren();
      put(t.body, stateCard({ ...this.sessError, compact: true }));
      return;
    }
    const data = this.sess;
    if (!data) return;
    const table = data.sessions || {};
    if (table.status !== 'ok') {
      t.meta.replaceChildren();
      put(t.body, 
        stateCard(
          table.status === 'refused'
            ? { status: 'refused', title: 'Too many sessions to count by policy', message: 'The device has more sessions than J-Wicket lists at once. Open Sessions and filter by zone, port or address.', hint: null, compact: true }
            : { status: table.status || 'failed', message: table.message, compact: true },
        ),
      );
      return;
    }
    const rows = table.rows || [];
    const by = new Map();
    for (const r of rows) {
      const name = r.policy || '(no policy reported)';
      const e = by.get(name) || { name, count: 0, bytes: 0, real: Boolean(r.policy) };
      e.count += 1;
      e.bytes += ((r.in && r.in.bytes) || 0) + ((r.out && r.out.bytes) || 0);
      by.set(name, e);
    }
    const top = [...by.values()].sort((a, b) => b.count - a.count || b.bytes - a.bytes).slice(0, 7);
    put(t.meta, h('span', null, table.truncated ? `first ${fmt.num(rows.length)} of ${fmt.num(table.returned)}` : `of ${fmt.plural(rows.length, 'session')}`));
    if (!top.length) {
      put(t.body, stateCard({ status: 'empty', title: 'No active sessions', message: 'The device listed no flow sessions in this poll.', compact: true }));
      return;
    }
    const idx = this.ctx.store.policyIndex();
    const snapNow = this.ctx.store.lastInventory;
    const known = Boolean(snapNow && snapNow.scope && snapNow.scope.policies && snapNow.scope.policies.status === 'ok');
    const max = top[0].count;
    put(t.body, 
      h(
        'ol',
        { class: 'top-list' },
        top.map((e, i) => {
          const p = idx.get(e.name);
          const zones = p
            ? `${p.from.length ? p.from.join(',') : 'any'} ${ARROW} ${p.to.length ? p.to.join(',') : 'any'}${p.kind === 'global' ? ' (global)' : ''}`
            : e.real && known
              ? 'not in the root inventory'
              : '';
          const action = p ? p.action : 'unknown';
          const toSessions = (ev) => {
            ev.preventDefault();
            this.ctx.navigate('sessions', e.real ? { q: `policy:${quote(e.name)}` } : {});
          };
          return h(
            'li',
            null,
            h(
              'div',
              { class: 'top-row' },
              h('span', { class: 'top-rank' }, String(i + 1)),
              h(
                'span',
                { class: 'top-name' },
                e.real
                  ? h(
                      'button',
                      {
                        class: 'policy-link',
                        type: 'button',
                        title: `Open policy ${e.name}`,
                        on: { click: () => this.ctx.navigate('policies', { q: `name:${quote(e.name)}`, sel: p ? p.id : null }) },
                      },
                      e.name,
                    )
                  : h('span', { class: 'muted' }, e.name),
                h('span', { class: 'top-zones' }, zones),
              ),
              h('a', { class: 'top-count', href: this.ctx.href('sessions', e.real ? { q: `policy:${quote(e.name)}` } : {}), title: `Sessions of ${e.name}`, on: { click: toSessions } }, fmt.num(e.count)),
              h('span', { class: ['bar', action === 'permit' ? 'permit' : action === 'deny' ? 'deny' : action === 'reject' ? 'reject' : 'muted'], 'aria-hidden': 'true' }, h('i', { style: { '--w': `${(e.count / max) * 100}%` } })),
            ),
          );
        }),
      ),
    );
  }

  // -- recent denies --

  chooseDenySource(sources) {
    const files = sources.files || [];
    const rtflow = files.find((f) => /RT_FLOW/i.test(f.match || '') && (/DENY/i.test(f.match || '') || /RT_FLOW_SESSION|RT_FLOW$|RT_FLOW[^_]/i.test(f.match || '')))
      || files.find((f) => /RT_FLOW/i.test(f.match || ''));
    if (rtflow) return { kind: 'file', id: rtflow.id, label: rtflow.name, sub: `match "${rtflow.match}"` };
    const dbs = sources.databases || [];
    if (dbs.some((d) => d.id === 'report')) return { kind: 'report', id: 'report', label: 'on-box reporting', sub: 'session-deny' };
    if (dbs.some((d) => d.id === 'buffer')) return { kind: 'buffer', id: 'buffer', label: 'security log buffer', sub: 'routing engine' };
    return null;
  }

  async pollDenies(now = false) {
    clearTimeout(this.timers.deny);
    if (this.dead || (this.paused && !now) || this.inflightDeny) return;
    this.inflightDeny = true;
    try {
      await this.readDenies();
    } finally {
      this.inflightDeny = false;
    }
    if (this.dead) return;
    this.renderDenies();
    this.renderWarnings();
    this.renderLinks();
    if (!this.paused && this.denySource && !this.denyError) this.timers.deny = setTimeout(() => this.pollDenies(), DENIES_EVERY_S * 1000);
  }

  async readDenies() {
    if (!this.denySources) {
      const res = await this.ctx.api.get('/api/logs/sources');
      if (this.dead || res.status === 401) return;
      if (!res.ok) {
        this.denyError = errorState(res, 'Log sources');
        return;
      }
      const src = res.data.sources || {};
      if (src.status !== 'ok') {
        this.denyError = { status: src.status || 'failed', message: src.message };
        return;
      }
      this.denySources = src;
      this.denySource = this.chooseDenySource(src);
      if (!this.denySource) {
        const tr = src.traffic || {};
        this.denyInfo = tr.where || 'No syslog file on this device takes RT_FLOW messages.';
        return;
      }
    }
    const s = this.denySource;
    if (!s) return;
    let res;
    if (s.kind === 'file') {
      const params = { source: s.id, contains: DENY_TAG, lines: this.denyCursor ? 200 : 50 };
      if (this.denyCursor) params.cursor = this.denyCursor;
      res = await this.ctx.api.get('/api/logs', params);
    } else if (s.kind === 'report') {
      res = await this.ctx.api.get('/api/logs', { source: 'report', type: s.sub === 'session-all' ? 'session-all' : 'session-deny', count: s.sub === 'session-all' ? 200 : 50 });
    } else {
      res = await this.ctx.api.get('/api/logs', { source: 'buffer' });
    }
    if (this.dead || res.status === 401) return;
    if (res.status === 429) return;
    if (!res.ok) {
      this.denyError = errorState(res, 'Logs');
      return;
    }
    const log = res.data.log || {};
    if (log.status !== 'ok') {
      if (s.kind === 'report' && s.sub === 'session-deny' && log.status !== 'denied') {
        // Some releases answer only the combined report; read it and keep the denies.
        s.sub = 'session-all';
        await new Promise((r) => setTimeout(r, 1700));
        if (!this.dead) await this.readDenies();
        return;
      }
      this.denyError = { status: log.status || 'failed', message: log.message };
      return;
    }
    this.denyError = null;
    this.denyAt = Date.now();
    const lines = (log.lines || []).filter((ln) => ln.includes(DENY_TAG) || /session denied/.test(ln));
    if (s.kind === 'file') {
      if (log.reset) {
        this.denies = [];
        this.denyTotal = 0;
      }
      const fresh = Boolean(this.denyCursor) && !log.reset;
      if (fresh) this.denyNew += lines.length;
      else this.denyTotal = lines.length + (log.dropped || 0);
      if (fresh) this.denyTotal += lines.length;
      this.denyWindow = log.window || 0;
      this.denyCursor = log.cursor || this.denyCursor;
      const parsed = lines.map(parseDeny);
      for (const p of parsed) p.fresh = fresh;
      this.denies = [...parsed.reverse(), ...this.denies.map((d) => ({ ...d, fresh: false }))].slice(0, 100);
    } else {
      // Report and buffer reads return a window; de-duplicate against what is already shown.
      const seen = new Set(this.denies.map((d) => d.line));
      const parsed = lines.map(parseDeny);
      const added = parsed.filter((p) => !seen.has(p.line));
      const first = !this.denies.length && !this.denyTotal;
      for (const p of added) p.fresh = !first;
      if (!first) this.denyNew += added.length;
      this.denyTotal += added.length;
      this.denies = [...added.reverse(), ...this.denies.map((d) => ({ ...d, fresh: false }))].slice(0, 100);
    }
  }

  renderDenies() {
    const t = this.t.denies;
    const s = this.denySource;
    if (this.denyError) {
      t.meta.replaceChildren();
      put(t.body, stateCard({ ...this.denyError, compact: true }));
      t.foot.hidden = true;
      return;
    }
    if (!s) {
      const tr = (this.denySources && this.denySources.traffic) || {};
      put(t.meta, tr.effective_mode ? h('span', null, `log mode ${tr.effective_mode}`) : null);
      put(t.body, 
        stateCard({
          status: 'info',
          title: tr.effective_mode === 'stream' ? 'Traffic logs leave the device' : 'No on-box source for denies',
          message: this.denyInfo || tr.where,
          hint: 'Logs shows every source this device has, and why.',
          actions: [h('button', { class: 'btn sm', type: 'button', on: { click: () => this.ctx.navigate('logs', {}) } }, 'Where are my logs?')],
        }),
      );
      t.foot.hidden = true;
      return;
    }
    this.denyLive = this.denyLive || h('button', { class: 'live-pill', type: 'button', on: { click: () => this.togglePause() } });
    this.denyLive.className = `live-pill${this.paused ? ' paused' : ''}`;
    put(this.denyLive, h('span', { class: 'dot', 'aria-hidden': 'true' }), this.paused ? 'PAUSED' : 'LIVE', h('span', { class: 'sub' }, this.paused ? 'space' : `${DENIES_EVERY_S} s`));
    this.denyLive.setAttribute('aria-label', this.paused ? 'Paused. Resume (space).' : `Live every ${DENIES_EVERY_S} s. Pause (space).`);
    put(t.meta, h('span', { class: 'ellipsis', title: 'Logs are device-wide' }, this.ctx.store.scope === 'root' ? s.label : `${s.label} (device-wide)`), this.denyLive);
    const head = h(
      'div',
      { class: 'denies-head' },
      h('span', { class: 'big-num' }, fmt.num(this.denyTotal)),
      h(
        'span',
        { class: 'small muted' },
        s.kind === 'file'
          ? `in the last ${fmt.num(this.denyWindow)} lines of ${s.label}`
          : s.kind === 'report'
            ? 'in on-box reporting'
            : 'in the routing engine buffer',
        this.denyNew ? h('span', { class: 'pill gold' }, `+${fmt.num(this.denyNew)} while open`) : null,
      ),
    );
    if (!this.denies.length) {
      put(t.body, head, stateCard({ status: 'empty', title: 'No denied sessions', message: `No ${DENY_TAG} lines ${s.kind === 'file' ? `in ${s.label}` : 'yet'}.`, compact: true }));
    } else {
      // Collapse repeats of the same flow (scanners, retries) into one row with a count.
      const groups = [];
      const byKey = new Map();
      for (const d of this.denies) {
        const key = `${d.src}|${d.dst}|${d.dport}|${d.proto}|${d.policy}`;
        const g = byKey.get(key);
        if (g) {
          g.count += 1;
          continue;
        }
        const entry = { ...d, count: 1 };
        byKey.set(key, entry);
        groups.push(entry);
      }
      put(t.body, head, h('div', { class: 'ticker', role: 'list' }, groups.slice(0, TICKER_ROWS).map((d) => this.denyRow(d))));
    }
    this.denyAgo = this.denyAgo || h('span', null, '');
    this.denyAgo.textContent = this.denyAt ? `updated ${fmt.ago(this.denyAt)}` : '';
    const params = { source: s.kind === 'file' ? s.id : s.id, q: `tag:${DENY_TAG}` };
    put(t.foot, 
      this.denyAgo,
      h('span', { class: 'spacer' }),
      h('a', { href: this.ctx.href('logs', params), on: { click: (e) => { e.preventDefault(); this.ctx.navigate('logs', params); } } }, 'Open in Logs', icon('arrow-right')),
    );
    t.foot.hidden = false;
  }

  denyRow(d) {
    const proto = protoName(d.proto);
    const q = [`tag:${DENY_TAG}`, d.src ? `src:${quote(d.src)}` : null, d.dport ? `dport:${d.dport}` : null].filter(Boolean).join(' ');
    const source = this.denySource ? this.denySource.id : null;
    const open = (e) => {
      e.preventDefault();
      this.ctx.navigate('logs', { source, q });
    };
    const label = `Denied ${d.src || '?'} to ${d.dst || '?'} port ${d.dport || '?'} ${proto}${d.policy ? ` by policy ${d.policy}` : ''}${d.count > 1 ? `, ${d.count} times` : ''}`;
    const policy =
      d.policy && d.policy !== 'N/A'
        ? h('button', { class: 'policy-link', type: 'button', title: `Open policy ${d.policy}`, on: { click: () => this.ctx.navigate('policies', { q: `name:${quote(d.policy)}` }) } }, d.policy)
        : h('span', { class: 'faint mono', title: 'The log line names no policy' }, 'policy N/A');
    return h(
      'div',
      { class: ['tick-row', d.fresh && 'row-new'], role: 'listitem' },
      h('span', { class: 'tick-time' }, d.time || '\u2014'),
      h(
        'a',
        { class: 'tick-flow', href: this.ctx.href('logs', { source, q }), title: `Show these denies in Logs: ${q}`, 'aria-label': label, on: { click: open } },
        h('span', { class: 'ip' }, d.src || '?'),
        h('span', { class: 'arrow' }, ARROW),
        h('span', { class: 'ip' }, d.dst || '?'),
        d.dport ? h('span', { class: 'port' }, `:${d.dport}`) : null,
        proto ? h('span', { class: 'pill sky' }, proto) : null,
      ),
      h('span', { class: 'tick-meta' }, d.count > 1 ? h('span', { class: 'badge deny', title: `${d.count} denies of this flow in the window` }, `\u00d7${d.count}`) : null),
      h(
        'span',
        { class: 'tick-sub' },
        d.from ? h('span', { class: 'zone' }, d.from) : null,
        d.from || d.to ? h('span', { class: 'arrow' }, ARROW) : null,
        d.to ? h('span', { class: 'zone' }, d.to) : null,
        policy,
        d.app ? h('span', { class: 'mono' }, d.app) : null,
        d.iface ? h('span', { class: 'iface' }, d.iface) : null,
      ),
    );
  }

  // -- quick links --

  renderLinks() {
    const t = this.t.links;
    const snap = this.ctx.store.lastInventory;
    const links = [];
    const add = (viewId, label, q, extra = {}) => links.push({ viewId, label, q, params: { ...extra, ...(q ? { q } : {}) } });
    const scope = snap && snap.scope;
    const rows = (scope && scope.policies && scope.policies.status === 'ok' && scope.policies.rows) || [];
    const inactive = rows.filter((r) => r.inactive_reason).length;
    if (inactive) add('policies', `${fmt.plural(inactive, 'inactive policy')}`, 'inactive:true');
    const blocking = rows.filter((r) => r.action === 'deny' || r.action === 'reject').length;
    if (blocking) add('policies', `${fmt.plural(blocking, 'deny or reject policy', 'deny or reject policies')}`, 'action:deny|reject');
    const groups = (scope && scope.groups) || [];
    if (groups.length) {
      const g = [...groups].sort((a, b) => b.policies - a.policies)[0];
      add('policies', `${fmt.plural(g.policies, 'policy')} from group ${g.name}`, `group:${quote(g.name)}`);
    }
    const s = this.sess;
    const table = s && s.sessions && s.sessions.status === 'ok' ? s.sessions.rows || [] : [];
    if (table.length && this.ctx.store.scope === 'root') {
      const top = (key) => {
        const m = new Map();
        for (const r of table) {
          const v = key(r);
          if (v !== null && v !== undefined && v !== '') m.set(v, (m.get(v) || 0) + 1);
        }
        return [...m.entries()].sort((a, b) => b[1] - a[1])[0] || null;
      };
      const src = top((r) => r.in && r.in.src);
      if (src) add('sessions', `Top talker ${src[0]}${SEP}${fmt.plural(src[1], 'session')}`, `src:${quote(src[0])}`);
      const dport = top((r) => r.in && r.in.dport);
      if (dport) add('sessions', `Busiest port ${dport[0]}${SEP}${fmt.plural(dport[1], 'session')}`, `dport:${dport[0]}`);
      const natted = table.filter((r) => r.nat && (r.nat.source || r.nat.destination)).length;
      if (natted) add('sessions', `${fmt.plural(natted, 'session')} with NAT`, 'nat!=none');
    }
    if (this.denySource) add('logs', 'Session denies', `tag:${DENY_TAG}`, { source: this.denySource.id });
    add('logs', 'Commits and configuration changes', 'tag:UI_COMMIT*', { source: 'file:messages' });
    if (!links.length) {
      put(t.body, skeleton(2));
      return;
    }
    put(t.body, 
      h(
        'div',
        { class: 'links' },
        links.slice(0, 8).map((l) => {
          const v = { policies: 'policies', sessions: 'sessions', logs: 'logs' }[l.viewId];
          const sp = new URLSearchParams(l.params);
          const [key, ...rest] = (l.q || '').split(':');
          return h(
            'a',
            {
              class: 'qlink',
              href: this.ctx.href(v, sp),
              on: { click: (e) => { e.preventDefault(); this.ctx.navigate(v, l.params); } },
            },
            h('span', { class: 'qlink-icon' }, icon(v)),
            h('span', { class: 'qlink-label' }, l.label),
            h('span', { class: 'qlink-q' }, `${v} `, l.q && rest.length ? [h('b', null, `${key}:`), rest.join(':')] : l.q),
            icon('chevron-right'),
          );
        }),
      ),
    );
  }
}
