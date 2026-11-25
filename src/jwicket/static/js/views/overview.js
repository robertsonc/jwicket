// views/overview.js: the console's front page (UI brief, section 6).
//
// System health first (routing-engine and data-plane CPU and memory, charted over 10 minutes, with
// load, temperature and uptime), then incident tiles: flow sessions (gauge and trend), recent denies (tail of the syslog file that
// takes RT_FLOW, or on-box reporting, or the security log buffer), warnings; then top policies by
// live sessions and a mini zone-pair matrix; then the device card (identity, HA, scope, read-as,
// source, time zone, central management) and quick links with filters pre-filled. Every tile is
// device data or an explicit state; nothing is decorative.
//
// Polling cost (SES-13): the gauge and its sparkline read the table-wide summary alone
// (GET /api/sessions?rows=none) every 30 s: 1 RPC, or none when the gauge was read in the last 5 s.
// Top policies, the zone-pair matrix and the quick links need the session list: a full read (2
// RPCs, a summary and the list) every 120 s, and only while the Overview is shown. That is 3 RPCs a
// minute instead of 4, each of which Junos may log as UI_NETCONF_CMD (inferred, Spec 004 section
// 7.12). Both start from this sign-in's last
// reads (the Sessions view's list, the shell's summary) when those are fresh. A faster gauge is an
// owner decision (OD-10).
//
// A 429 (another read of this session is running, or J-Wicket's per-session read floor) is never
// shown as an error or as data: the tiles keep what they have and read again after Retry-After.
//
// Device text (names, addresses, log fields) is shown through dom.vis(), so a hidden or
// direction-changing character is a visible badge; titles and aria labels use format.plain().

import { h, icon, put, stateCard, skeleton, setTicking, viewSub, vis } from '../dom.js';
import * as fmt from '../format.js';
import { Gauge } from '../widgets/gauge.js';
import { Sparkline } from '../widgets/sparkline.js';
import { TimeChart } from '../widgets/timechart.js';

const SUMMARY_EVERY_S = 30;
const LIST_EVERY_S = 120;
const HEALTH_EVERY_S = 10; // two RPCs per read; the server allows one read per 5 s per operator
const HEALTH_WINDOW_MS = 10 * 60 * 1000;
// Health samples outlive the view (module scope), so leaving the Overview and coming back keeps the
// last 10 minutes instead of starting an empty chart. Cleared on sign-out with the page.
const HEALTH_LOG = [];
const DENIES_EVERY_S = 15;
const RETRY_S = 30;
const HISTORY = 20; // sparkline points: 10 minutes at 30 s
const DENY_TAG = 'RT_FLOW_SESSION_DENY';
const TICKER_ROWS = 10;
const TOP_ROWS = 8;
const MATRIX_ZONES = 7;
const SEP = ' \u00b7 ';
const ARROW = '\u2192';
const DASH = '\u2014';
// A read that failed for a reason that will not change by itself: no retry, no RETRYING pill.
const FINAL = new Set(['denied', 'unsupported']);
const IDLE_LABEL = 'Live reads paused: no activity. Move the pointer or press a key to resume.';
const BUSY_MESSAGE = 'J-Wicket could not read the device because other reads for your session kept it busy. It tries again in 30 s.';

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

/** Device text as nodes: every hidden or direction-changing character shown as a badge. */
const v = (s) => vis(s ?? '', { all: true });
/** Device text for titles and aria labels: such characters written as "<U+XXXX>". */
const pl = (s) => fmt.plain(s ?? '', { all: true });

function quote(value) {
  const s = String(value);
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

function isFiltered(data) {
  return Boolean(data && data.meta && data.meta.device_filters && Object.keys(data.meta.device_filters).length);
}

/**
 * When a summary was read, on this browser's clock: the reply's own read time minus the summary's age
 * on the server's clock (a reused gauge can be a few seconds older than the reply).
 */
function summaryAt(data) {
  const s = (data && data.summary) || {};
  const replied = Date.parse((data && data.meta && data.meta.read_at) || '');
  const read = Date.parse(s.read_at || '');
  const age = Number.isFinite(replied) && Number.isFinite(read) ? Math.max(0, replied - read) : 0;
  return Date.now() - age;
}

/**
 * The Policies row id ("sel") for a policy named on a log line. A name used in several zone pairs
 * is resolved with the line's own zones (a global policy with no zones applies to any); null when
 * the inventory does not know the name or the zones do not single one row out.
 */
function policySel(idx, name, from, to) {
  const p = idx ? idx.get(name) : null;
  if (!p) return null;
  if (!p.ambiguous) return p.id || null;
  const fits = (list, z) => !list || !list.length || (z !== null && z !== undefined && list.includes(z));
  const hits = (p.all || []).filter((e) => fits(e.from, from) && fits(e.to, to));
  return hits.length === 1 ? hits[0].id || null : null;
}

function mean(values) {
  const ok = values.filter((v) => Number.isFinite(v));
  return ok.length ? ok.reduce((a, b) => a + b, 0) / ok.length : null;
}

/** The routing engine to show: the master (or the only one) of the first node. */
function primaryEngine(part) {
  const list = part && part.status === 'ok' ? part.engines || [] : [];
  return list.find((e) => e.mastership === 'master') || list[0] || null;
}

function healthSample(data) {
  const re = primaryEngine(data.route_engine);
  const units = data.spu && data.spu.status === 'ok' ? data.spu.units || [] : [];
  const s = {
    t: Date.now(), // the browser's clock, like the chart's time axis (read_at has 1 s resolution)
    reCpu: re && re.cpu ? re.cpu.busy : null,
    reMem: re && re.memory ? re.memory.util : null,
    spuCpu: mean(units.map((u) => u.cpu)),
    spuMem: mean(units.map((u) => u.memory)),
  };
  return [s.reCpu, s.reMem, s.spuCpu, s.spuMem].some((v) => Number.isFinite(v)) ? s : null;
}

function uptime(seconds) {
  const d = Math.floor(seconds / 86400);
  const hrs = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return d ? `${d} d ${hrs} h` : hrs ? `${hrs} h ${m} min` : `${m} min`;
}

function stateWord(status) {
  return { denied: 'denied for your login class', unsupported: 'not available on this device', failed: 'read failed' }[status] || 'not read';
}

function tile(cls, title, iconName) {
  const meta = h('div', { class: 'tile-meta' });
  const body = h('div', { class: 'tile-body' }, skeleton(3));
  const foot = h('div', { class: 'tile-foot', hidden: true });
  const titleId = `ov-${cls}-title`;
  const heading = h('h2', { class: 'tile-title', id: titleId }, icon(iconName), title);
  const el = h('section', { class: ['tile', `ov-${cls}`], 'aria-labelledby': titleId }, h('div', { class: 'tile-head' }, heading, meta), body, foot);
  return { el, meta, body, foot, heading };
}

/** The state for an HTTP failure of a live read (a 429 is handled by the callers: it is not one). */
function errorState(res, what) {
  if (res.status === 0) return { status: 'offline', message: res.data.error };
  if (res.internal) return { status: 'internal', message: res.data.error };
  return { status: 'failed', message: res.data.error || `${what} failed (HTTP ${res.status}).` };
}

function isFixtureNote(text) {
  return /^fixture data\b/i.test(String(text || ''));
}

/** A global policy applies to a zone pair when its from/to are empty (any) or name the zone. */
function globalApplies(row, from, to) {
  const f = row.from || [];
  const t = row.to || [];
  return (!f.length || f.includes(from)) && (!t.length || t.includes(to));
}

// The same strings as the Policies view's default-policy labels (POL-UI-02), kept here on purpose
// rather than imported from views/policies.js.
const ANCESTOR_BECAUSE = {
  policies: ' (because [edit security policies] is deactivated)',
  security: ' (because [edit security] is deactivated)',
};

/** The default-policy step of the evaluation-order footer (POL-SL-01). */
function defaultStep(pol, scopeLabel) {
  const act = pol.default_policy;
  if (act) {
    const group = pol.default_policy_group ? `, from group ${pl(pol.default_policy_group)}` : '';
    return { text: String(act), cls: /deny|reject/.test(act) ? 'act-deny' : /permit/.test(act) ? 'act-permit' : null, tip: `Default policy: configured${group}` };
  }
  const off = pol.default_policy_inactive;
  if (off) {
    const why = pol.default_policy_inactive_reason;
    const because = !why || why === 'self' ? '' : ANCESTOR_BECAUSE[why] || (why === 'scope' ? ` (because ${pl(scopeLabel)} is deactivated)` : ` (because of a deactivated ${why})`);
    return {
      text: `deny-all (${off} deactivated)`,
      cls: 'act-deny',
      tip:
        `Default policy: Junos default: the configured default-policy ${pl(off)} is deactivated${because}. ` +
        `default-policy ${pl(off)} is written in the configuration but deactivated (inactive:), so it is not in effect; the Junos default, deny-all, decides. ` +
        '(That the default then applies is J-Wicket\u2019s reading: inferred.)',
    };
  }
  return { text: 'deny-all (Junos default)', cls: 'act-deny', tip: 'Default policy: not configured (Junos default: deny-all)' };
}

/**
 * The device's configured time zone (snapshot `clock`, B-12): "configured", never "in effect", since
 * Junos applies a change to every process only after a reboot. Times are shown in UTC (Logs can
 * show log times in the configured zone, LG-02).
 */
function timeZoneText(snap) {
  const cfg = snap.config || {};
  const clock = snap.clock;
  if (cfg.status && cfg.status !== 'ok') return { text: `not known (configuration not read: ${cfg.status})`, note: null };
  if (!clock || typeof clock !== 'object') return { text: 'not known (not reported)', note: null };
  if (clock.status !== 'ok') return { text: `not known (${clock.status})`, note: clock.message || null };
  if (clock.time_zone) return { text: `${clock.time_zone} (configured; Junos applies a change to every process only after a reboot)`, note: null };
  if (clock.deactivated) {
    return {
      // JUNOS-02: "configured" wording only (B-12); that the default then applies is inferred.
      text: `not configured (time-zone ${clock.deactivated} is deactivated); Junos default: UTC`,
      note: `time-zone ${clock.deactivated} is in the configuration but deactivated (inactive:). That the Junos default, UTC, then applies is J-Wicket's reading (inferred); Junos applies a time-zone change to every process only after a reboot.`,
    };
  }
  return { text: 'UTC (no time-zone configured: the Junos default)', note: null };
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

// ---- the view ------------------------------------------------------------------------------------

class Overview {
  constructor(el, ctx) {
    this.el = el;
    this.ctx = ctx;
    this.dead = false;
    // Aborted on unmount, so a read still waiting in api.js (pacing, Retry-After) is not sent after the
    // Overview has gone (SES-13: these reads run only while the Overview is shown).
    this.ctl = new AbortController();
    this.paused = false;
    this.idle = Boolean(ctx.ui.isIdle && ctx.ui.isIdle()); // the shell's idle pause (SL-08)
    this.idleEndedAt = 0;
    this.history = [];
    this.summary = null; // { summary, at }: the last table-wide summary (summary-only or full read)
    this.sumErr = null; // the summary read failed (HTTP)
    this.sum429 = 0; // summary reads answered 429 in a row
    this.sess = null; // the last full /api/sessions payload (unfiltered)
    this.listAt = 0;
    this.listErr = null;
    this.list429 = 0;
    this.denySource = null; // { kind: 'file'|'report'|'buffer', id, name, label, live, note }
    this.denySources = null;
    this.denyCursor = null;
    this.denies = [];
    this.denyTotal = 0;
    this.denyNew = 0;
    this.denyWindow = 0;
    this.denyError = null;
    this.denyInfo = null;
    this.denyAt = 0;
    this.denyWait = 0; // no deny read before this time (a 429's Retry-After)
    this.denyWaiting = false; // the last deny read was answered 429
    this.denyDisabled = false; // security log disable
    this.health = null; // last /api/health payload
    this.healthError = null;
    this.healthAt = 0;
    this.timers = { sum: 0, list: 0, deny: 0, ago: 0, health: 0 };
    this.build();
    this.offs = [
      ctx.store.on('inventory', () => this.renderInventory()),
      ctx.store.on('scope', () => this.onScope()),
      ctx.store.on('inventory-state', () => {
        if (!this.ctx.store.lastInventory) this.renderInventory();
      }),
    ];
    this.onRefresh = () => this.refresh();
    this.onToggleLive = () => this.togglePause();
    this.onIdle = (e) => this.setIdle(Boolean(e && e.detail && e.detail.idle));
    document.addEventListener('jwicket:refresh', this.onRefresh);
    document.addEventListener('jwicket:toggle-live', this.onToggleLive);
    window.addEventListener('jwicket:idle', this.onIdle);
    this.timers.ago = setInterval(() => this.renderAges(), 5000);
    this.start();
  }

  async start() {
    await this.ctx.store.inventory();
    if (this.dead) return;
    this.renderInventory();
    if (this.ctx.store.scope === 'root') this.startSessions();
    else this.renderSessions();
    this.timers.deny = setTimeout(() => this.pollDenies(), 700);
    this.pollHealth();
  }

  /** Start both session reads, from this sign-in's last reads when those are fresh. */
  startSessions() {
    if (this.paused || this.dead) return;
    const store = this.ctx.store;
    const now = Date.now();
    const sum = store.sessionsSummary;
    const sumAge = sum ? now - sum.at : Infinity;
    if (!this.summary && sum && sumAge >= 0 && sumAge < SUMMARY_EVERY_S * 1000) {
      this.applySummary({ summary: sum.summary, meta: {} }, { fromStore: true, at: sum.at });
      this.timers.sum = setTimeout(() => this.pollSummary(), SUMMARY_EVERY_S * 1000 - sumAge);
    } else {
      this.pollSummary();
    }
    // The Sessions view may just have listed the table: start from that list instead of a new read.
    const last = store.sessionsLast;
    const at = last && last.meta && last.meta.read_at ? Date.parse(last.meta.read_at) : NaN;
    const age = Number.isFinite(at) ? now - at : Infinity;
    if (!this.sess && last && last.sessions && !isFiltered(last) && age >= 0 && age < LIST_EVERY_S * 1000) {
      this.applyList(last, { fromStore: true });
      this.timers.list = setTimeout(() => this.pollList(), LIST_EVERY_S * 1000 - age);
    } else if (!this.sess || now - this.listAt >= LIST_EVERY_S * 1000) {
      this.pollList();
    } else {
      this.timers.list = setTimeout(() => this.pollList(), LIST_EVERY_S * 1000 - (now - this.listAt));
    }
  }

  update() {
    // The overview has no view parameters of its own; scope changes arrive through the store.
  }

  destroy() {
    this.dead = true;
    this.ctl.abort();
    for (const k of ['sum', 'list', 'deny', 'health']) clearTimeout(this.timers[k]);
    clearInterval(this.timers.ago);
    for (const off of this.offs) off();
    document.removeEventListener('jwicket:refresh', this.onRefresh);
    document.removeEventListener('jwicket:toggle-live', this.onToggleLive);
    window.removeEventListener('jwicket:idle', this.onIdle);
    this.ctx.ui.setLive('overview', false);
  }

  // -- layout --

  build() {
    this.title = h('h1', { class: 'view-title' }, 'Overview');
    this.sub = h('p', { class: 'view-sub' }, 'Reading the device\u2026');
    this.livePill = h('button', { class: 'live-pill', type: 'button', on: { click: () => this.onPillClick() } });
    const refresh = h(
      'button',
      { class: 'btn', type: 'button', title: 'Read the device again (r)', on: { click: () => this.refresh(true) } },
      icon('refresh'),
      'Refresh',
    );
    this.head = h(
      'div',
      { class: 'view-head' },
      h('div', { class: 'view-titles' }, this.title, this.sub),
      h('div', { class: 'view-actions' }, this.livePill, refresh),
    );
    // Incident first: sessions and denies, then what explains them, then who and what the device is.
    this.t = {
      warnings: tile('warnings', 'Warnings', 'alert'),
      health: tile('health', 'System health', 'server'),
      sessions: tile('sessions', 'Flow sessions', 'sessions'),
      denies: tile('denies', 'Recent denies', 'ban'),
      top: tile('top', 'Top policies by live sessions', 'policies'),
      matrix: tile('matrix', 'Zone pairs', 'grid'),
      device: tile('device', 'Device', 'server'),
      links: tile('links', 'Jump to', 'arrow'),
    };
    this.grid = h('div', { class: 'ov-grid' }, Object.values(this.t).map((t) => t.el));
    put(this.el, this.head, this.grid);
    this.buildSessionsTile();
    this.buildHealthTile();
    this.renderLivePill();
  }

  buildHealthTile() {
    const t = this.t.health;
    const series = [
      { id: 're', label: 'Routing engine' },
      { id: 'spu', label: 'Data plane (SPU)' },
    ];
    this.cpuChart = new TimeChart({ title: 'CPU busy', series, windowMs: HEALTH_WINDOW_MS, height: 150, describe: 'percent busy, routing engine and data plane' });
    this.memChart = new TimeChart({ title: 'Memory used', series, windowMs: HEALTH_WINDOW_MS, height: 150, describe: 'percent used, routing engine and data plane' });
    this.hStats = h('dl', { class: 'hl-stats' });
    this.hNote = h('p', { class: 'hl-note' });
    this.healthContent = h('div', { class: 'hl-body' }, this.hStats, h('div', { class: 'hl-charts' }, this.cpuChart.el, this.memChart.el), this.hNote);
    this.healthAgo = h('span', null, '');
    const cmds = h('span', { class: 'hl-cmds mono', title: 'The Junos commands these figures come from' }, 'show chassis routing-engine \u00b7 show security monitoring');
    put(t.foot, this.healthAgo, h('span', { class: 'spacer' }), cmds);
    t.foot.hidden = false;
    this.renderHealthCharts();
  }

  buildSessionsTile() {
    const t = this.t.sessions;
    this.gauge = new Gauge({ size: 80, stroke: 7, label: 'Active sessions of the device maximum' });
    // Zero-based: a few sessions more or less is a flat line, a flood is not.
    this.spark = new Sparkline({ height: 34, label: 'Active sessions per poll', min: 0 });
    this.sessBig = h('span', { class: 'big-num', hidden: true }, DASH);
    this.sessOf = h('span', { class: 'sess-of' }, '');
    this.sparkRange = h('span', { class: 'sess-range' }, '');
    this.sessNote = h('div', { class: 'sess-note' });
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
          this.sessBig,
          h('div', { class: 'sess-spark-head' }, h('span', null, 'active, last 10 min'), this.sparkRange),
          this.spark.el,
          this.sessOf,
        ),
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

  /** The session reads are failing for a reason that may pass (not denied, not unsupported). */
  sessFailing() {
    const failing = (e) => e && !FINAL.has(e.status);
    const table = this.sess && this.sess.sessions;
    const sum = this.summary && this.summary.summary;
    return Boolean(
      failing(this.sumErr) ||
        failing(this.listErr) ||
        (table && table.status === 'count-unknown' && table.reason === 'summary-failed') ||
        (sum && sum.status && sum.status !== 'ok' && !FINAL.has(sum.status)),
    );
  }

  /** A live read is failing for a reason that may pass. */
  retrying() {
    return (
      this.sessFailing() ||
      Boolean(this.denyError && !FINAL.has(this.denyError.status)) ||
      Boolean(this.healthError && !FINAL.has(this.healthError.status))
    );
  }

  renderLivePill() {
    const live = !this.paused;
    const idle = live && this.idle;
    const retrying = live && !idle && this.retrying();
    this.livePill.className = `live-pill${live && !idle ? '' : ' paused'}${idle ? ' idle' : ''}${retrying ? ' retrying' : ''}`;
    put(
      this.livePill,
      h('span', { class: 'dot', 'aria-hidden': 'true' }),
      !live || idle ? 'PAUSED' : retrying ? 'RETRYING' : 'LIVE',
      h('span', { class: 'sub' }, !live ? 'space' : idle ? 'idle' : `${retrying ? RETRY_S : SUMMARY_EVERY_S} s`),
    );
    this.livePill.setAttribute('aria-pressed', live ? 'false' : 'true');
    this.livePill.setAttribute(
      'aria-label',
      !live
        ? 'Paused. Resume live updates (space).'
        : idle
          ? IDLE_LABEL
          : retrying
            ? `Live, but a read is failing; trying again every ${RETRY_S} s. Pause (space).`
            : `Live: health every ${HEALTH_EVERY_S} s, the session gauge every ${SUMMARY_EVERY_S} s, the session list every ${LIST_EVERY_S / 60} min, denies every ${DENIES_EVERY_S} s. Pause (space).`,
    );
    this.livePill.title = idle ? IDLE_LABEL : live ? 'Pause live updates (space)' : 'Resume live updates (space)';
    this.ctx.ui.setLive('overview', live);
  }

  /** The shell's idle pause began or ended: the reads wait in api.js; the pills say so. */
  setIdle(idle) {
    if (this.dead || idle === this.idle) return;
    this.idle = idle;
    if (!idle) this.idleEndedAt = Date.now();
    this.renderLivePill();
    if (this.denyLive) this.renderDenies();
  }

  onPillClick() {
    // The click that ends an idle pause (pointer input) resumes the reads; it does not also pause.
    if (Date.now() - this.idleEndedAt < 800) return;
    this.togglePause();
  }

  togglePause() {
    this.paused = !this.paused;
    this.renderLivePill();
    if (this.denyLive) this.renderDenies();
    this.ctx.ui.announce(this.paused ? 'Overview paused.' : 'Overview live.');
    if (!this.paused) {
      if (this.ctx.store.scope === 'root') this.startSessions();
      this.pollHealth();
      this.timers.deny = setTimeout(() => this.pollDenies(), 400);
    } else {
      for (const k of ['sum', 'list', 'deny', 'health']) clearTimeout(this.timers[k]);
    }
  }

  async refresh(fromButton = false) {
    if (fromButton) this.ctx.ui.toast('Refreshing from the device\u2026', 'info');
    await this.ctx.store.inventory(true);
    if (this.dead) return;
    this.pollSummary(true);
    this.pollList(true);
    this.pollHealth(true);
    this.timers.deny = setTimeout(() => this.pollDenies(true), 400);
  }

  onScope() {
    for (const k of ['device', 'matrix', 'warnings', 'links']) put(this.t[k].body, skeleton(3));
    this.renderLivePill();
    this.renderSessions();
    this.renderTop();
    // Sessions are read for the root system only; the polls stop elsewhere and restart on return.
    if (this.ctx.store.scope === 'root' && !this.paused) this.startSessions();
    else {
      clearTimeout(this.timers.sum);
      clearTimeout(this.timers.list);
    }
  }

  renderAges() {
    if (this.summary) this.sessAgo.textContent = `updated ${fmt.ago(this.summary.at)}`;
    if (this.topAgo && this.listAt) this.topAgo.textContent = `updated ${fmt.ago(this.listAt)}`;
    if (this.healthAt && this.healthAgo) this.healthAgo.textContent = `updated ${fmt.ago(this.healthAt)}`;
    if (this.denyAgo && this.denyAt) this.denyAgo.textContent = `updated ${fmt.ago(this.denyAt)}`;
    const snap = this.ctx.store.lastInventory;
    if (snap && this.readAgo) this.readAgo.textContent = fmt.ago(snap.meta.read_at);
  }

  // -- inventory tiles --

  /** The shell's last inventory error when it is about this scope (OBJ-31). */
  inventoryError() {
    const err = this.ctx.store.inventoryError;
    return err && (!err.scope || err.scope === this.ctx.store.scope) ? err : null;
  }

  /** The card for a tile while there is no snapshot: waiting, busy, failed, or a skeleton. */
  inventoryCard() {
    const waiting = this.ctx.store.inventoryWaiting;
    const err = this.inventoryError();
    if (waiting) return stateCard({ status: 'waiting', compact: true });
    if (!err) return skeleton(3);
    const again = [h('button', { class: 'btn sm', type: 'button', on: { click: () => this.ctx.store.inventory(true) } }, 'Read again')];
    // F7: the message already says when it tries again, so the S-3 hint would repeat it.
    if (err.status === 'busy') return stateCard({ status: 'busy', message: BUSY_MESSAGE, hint: null, actions: again, compact: true });
    if (err.status === 0) return stateCard({ status: 'offline', message: err.message, actions: again, compact: true });
    if (err.status === 'internal') return stateCard({ status: 'internal', message: err.message, actions: again, compact: true });
    return stateCard({ status: 'failed', message: err.message, actions: again, compact: true });
  }

  renderInventory() {
    if (this.dead) return;
    const snap = this.ctx.store.lastInventory;
    if (!snap) {
      const waiting = this.ctx.store.inventoryWaiting;
      const err = this.inventoryError();
      for (const k of ['device', 'matrix', 'warnings']) put(this.t[k].body, this.inventoryCard());
      this.sub.textContent = waiting
        ? 'Waiting for another read of your session to finish\u2026'
        : err && err.status === 'busy'
          ? 'Not read yet: other reads for your session kept J-Wicket busy.'
          : err
            ? 'The device could not be read.'
            : 'Reading the device\u2026';
      this.renderLinks();
      return;
    }
    const dev = snap.device || {};
    const meta = snap.meta || {};
    const scopeId = meta.scope || 'root';
    const ra = meta.read_as || {};
    viewSub(this.sub, {
      host: dev.status === 'ok' ? dev.hostname : null,
      scope: this.ctx.ui.scopeLabel ? this.ctx.ui.scopeLabel(scopeId) : scopeKindLabel(scopeId),
      readAt: meta.read_at,
      user: ra.user || '?',
      backend: ra.backend,
      config: snap.config,
      source: meta.source,
    });
    this.renderDevice(snap);
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
        h(
          'div',
          { class: 'dev-id' },
          h('span', { class: 'dev-host dev-text' }, v(dev.hostname || 'unnamed device')),
          dev.model ? h('span', { class: 'pill muted dev-text' }, v(modelName(dev.model))) : null,
          h('span', { class: 'pill sky dev-text' }, v(`Junos ${dev.version || 'release not reported'}`)),
          this.haBadge(ha),
        ),
      );
      const versions = [...new Set((dev.nodes || []).map((n) => n.version).filter(Boolean))];
      if (versions.length > 1) parts.push(h('p', { class: 'act-reject small dev-text' }, v(`Nodes report different releases: ${versions.join(', ')}`)));
    } else {
      parts.push(stateCard({ status: dev.status || 'failed', message: dev.message, title: 'Device facts could not be read', compact: true }));
    }
    parts.push(this.haBlock(ha, dev));
    parts.push(this.inventoryCounts(snap));
    const scopes = meta.scopes || [];
    const scopeInfo = scopes.find((s) => s.id === meta.scope);
    const ra = meta.read_as || {};
    const src = meta.source || {};
    const cfg = snap.config || {};
    const configRead = !cfg.status || cfg.status === 'ok';
    const tz = timeZoneText(snap);
    parts.push(
      h(
        'dl',
        { class: 'kv dev-facts' },
        h('dt', null, 'Scope'),
        h(
          'dd',
          null,
          h('span', { class: 'dev-text' }, v(scopeInfo ? scopeInfo.label : scopeKindLabel(meta.scope || 'root'))),
          scopes.length > 1 ? h('span', { class: 'faint' }, `${SEP}${fmt.plural(scopes.length, 'scope')} on this device`) : null,
          snap.scope && snap.scope.inactive ? [' ', h('span', { class: 'pill reject' }, 'deactivated')] : null,
        ),
        h('dt', null, 'Read as'),
        h(
          'dd',
          null,
          h('span', { class: 'mono strong dev-text' }, v(ra.user || '?')),
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
          configRead
            ? `${src.database === 'committed' ? 'committed configuration' : `${src.database || 'unknown'} configuration`}${SEP}${src.inheritance ? 'inheritance expanded' : 'inheritance not expanded'}`
            : h('span', { class: 'faint' }, `configuration not read (${cfg.status})`),
        ),
        h('dt', null, 'Time zone'),
        h(
          'dd',
          null,
          h('span', { class: ['dev-text', !configRead || (snap.clock && snap.clock.status !== 'ok') ? 'faint' : null], title: 'J-Wicket shows times in UTC; Logs can show log times in the configured device zone.' }, v(tz.text)),
          tz.note ? h('span', { class: 'faint small dev-text' }, ' ', vis(tz.note)) : null,
        ),
        h('dt', null, 'Managed from'),
        h('dd', null, this.managedFacts(snap)),
      ),
    );
    put(t.body, ...parts);
  }

  /** Central management (outbound SSH): who else may change this configuration (CRT-01, CRT-02). */
  managedFacts(snap) {
    const mg = snap.management || {};
    const cfg = snap.config || {};
    if (mg.status !== 'ok') {
      if (cfg.status && cfg.status !== 'ok') {
        return h('span', { class: 'faint', title: 'Another system may also manage this device.' }, `not known: the configuration was not read (${cfg.status})`);
      }
      return h(
        'span',
        { class: 'faint dev-text', title: 'Another system may also manage this device.' },
        mg.message ? vis(`not known: ${mg.message}`) : `not known (${mg.status || 'failed'})`,
      );
    }
    const clients = (mg.clients || []).filter((c) => c && c.client !== undefined && c.client !== null);
    const active = clients.filter((c) => !c.inactive);
    const off = clients.filter((c) => c.inactive);
    if (!clients.length) {
      return h('span', { class: 'faint', title: 'Security Director, Mist and similar managers connect this way. Operators and scripts using the CLI or NETCONF are not listed here.' }, 'no outbound-SSH client configured');
    }
    const row = (c) =>
      h(
        'div',
        { class: ['mg-client', c.inactive && 'is-off'] },
        h('span', { class: 'mg-name dev-text' }, icon('broadcast'), v(c.client)),
        c.inactive ? h('span', { class: 'pill muted', title: `outbound-ssh client ${pl(c.client)} is in the configuration but deactivated (inactive:), so it is not in effect.` }, 'deactivated') : null,
        (c.targets || []).map((x) => h('span', { class: 'mono faint dev-text' }, v(x))),
        (c.services || []).map((s) => h('span', { class: ['pill', 'dev-text', c.inactive && 'muted'] }, v(s))),
      );
    if (!active.length) {
      return h(
        'div',
        { class: 'mg-list' },
        h('span', { class: 'faint dev-text' }, v(`No active outbound-SSH client. Configured but deactivated: ${off.map((c) => c.client).join(', ')}.`)),
        off.map(row),
      );
    }
    return h(
      'div',
      { class: 'mg-list' },
      active.map(row),
      off.map(row),
      h('span', { class: 'mg-note' }, 'Changes made there can overwrite this configuration without J-Wicket knowing.'),
    );
  }

  haBadge(ha) {
    if (ha.status && ha.status !== 'ok') return h('span', { class: 'ha-badge' }, `HA ${ha.status}`);
    if (ha.mode === 'standalone') {
      // CRT-11: the server says why standalone is not certain (a fallback filter, a failed read).
      return ha.message ? h('span', { class: 'ha-badge', title: fmt.plain(ha.message) }, 'standalone?') : h('span', { class: 'ha-badge' }, 'standalone');
    }
    if (ha.mode === 'chassis-cluster') return h('span', { class: 'ha-badge cluster dev-text' }, v(`chassis cluster${ha.cluster_id ? ` ${ha.cluster_id}` : ''}`));
    if (ha.mode === 'mnha') return h('span', { class: 'ha-badge cluster' }, 'multinode HA');
    return h('span', { class: 'ha-badge' }, 'HA unknown');
  }

  haBlock(ha, dev) {
    if (ha.status && ha.status !== 'ok') {
      return h('div', { class: 'dev-ha' }, stateCard({ status: ha.status, message: ha.message, title: 'High availability status could not be read', compact: true }));
    }
    if (ha.mode !== 'chassis-cluster') {
      // Standalone can carry a reason ("Chassis cluster status was not available ..."); say it.
      return ha.message ? h('div', { class: 'dev-ha' }, h('p', { class: 'small muted dev-text' }, vis(ha.message))) : null;
    }
    const hosts = new Map((dev.nodes || []).map((n) => [n.node, n.hostname]));
    return h(
      'div',
      { class: 'dev-ha' },
      (ha.redundancy_groups || []).map((g) =>
        h(
          'div',
          { class: 'rg-row' },
          h('span', { class: 'rg-id dev-text' }, v(`RG${g.id}`)),
          (g.nodes || []).map((n) => {
            const primary = String(n.status || '').toLowerCase() === 'primary';
            const host = hosts.get(n.name);
            return h(
              'span',
              { class: ['rg-node', 'dev-text', primary && 'primary'], title: pl(`${n.name}${host ? ` (${host})` : ''}: ${n.status || 'status not reported'}, priority ${n.priority || '?'}`) },
              v(n.name),
              host ? h('span', { class: 'prio' }, v(host)) : null,
              h('span', { class: 'prio' }, v(`${n.status || '?'} ${n.priority || ''}`.trim())),
            );
          }),
        ),
      ),
      h('p', { class: 'xsmall faint dev-text' }, ha.local_node ? v(`This page is served by ${ha.local_node}.`) : 'Which node serves this page is not reported.'),
      ha.message ? h('p', { class: 'small muted dev-text' }, vis(ha.message)) : null,
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
        h('b', null, ok ? fmt.num(value) : DASH),
        h('span', null, ok ? label : `${label}: ${section ? section.status : 'not read'}`),
        ok && meter ? meter : null,
      );
    };
    const pol = scope.policies || {};
    const rows = pol.rows || [];
    const active = rows.filter((r) => !r.inactive_reason);
    const n = (a) => active.filter((r) => r.action === a).length;
    const total = Math.max(1, rows.length);
    const seg = (cls, value) => (value ? h('i', { class: cls, style: { '--w': `${(value / total) * 100}%` } }) : null);
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

  // -- zone-pair matrix: the same zone order, axes, cell anatomy and legend as the Policies view --

  renderMatrix(snap) {
    const t = this.t.matrix;
    const scope = snap.scope;
    put(t.meta, h('span', { title: 'Rows: from-zone. Columns: to-zone.' }, 'from \u2193  to \u2192'));
    if (!scope) {
      put(t.body, stateCard({ status: (snap.config || {}).status || 'failed', message: (snap.config || {}).message, compact: true }));
      t.foot.hidden = true;
      return;
    }
    const pol = scope.policies || {};
    if (pol.status !== 'ok') {
      put(t.body, stateCard({ status: pol.status, message: pol.message, compact: true }));
      t.foot.hidden = true;
      return;
    }
    const pairs = pol.zone_pairs || [];
    const rows = pol.rows || [];
    // Configuration order: the zones as configured, then any zone only a policy names.
    const all = [];
    const add = (z) => {
      if (z && z !== '?' && !all.includes(z)) all.push(z);
    };
    for (const z of (scope.zones && scope.zones.status === 'ok' && scope.zones.rows) || []) add(z.name);
    for (const r of rows) {
      if (r.kind === 'global') continue;
      (r.from || []).forEach(add);
      (r.to || []).forEach(add);
    }
    for (const p of pairs) {
      add(p.from);
      add(p.to);
    }
    const zones = all.slice(0, MATRIX_ZONES);
    const byPair = new Map(pairs.map((p) => [`${p.from}\u0000${p.to}`, p]));
    // Only globals in effect count; a deactivated one decides nothing.
    const globals = rows.filter((r) => r.kind === 'global' && !r.inactive);
    const globalsOff = rows.filter((r) => r.kind === 'global' && r.inactive).length;
    const live = this.liveByPair();
    if (!zones.length) {
      put(t.body, stateCard({ status: 'empty', message: 'No security zones are configured in this scope.', compact: true }));
      t.foot.hidden = true;
      return;
    }
    const cells = [h('div', { class: 'mx-corner', 'aria-hidden': 'true' })];
    for (const z of zones) cells.push(h('div', { class: 'mx-col dev-text', title: `to ${pl(z)}` }, h('span', null, v(z))));
    for (const from of zones) {
      cells.push(h('div', { class: 'mx-rowh dev-text', title: `from ${pl(from)}` }, h('span', null, v(from))));
      for (const to of zones) {
        const p = byPair.get(`${from}\u0000${to}`);
        const has = Boolean(p && p.count);
        const sessions = live ? live.get(`${from}\u0000${to}`) || 0 : null;
        const globalsHere = globals.filter((g) => globalApplies(g, from, to)).length;
        const params = { q: `from:${quote(from)} to:${quote(to)}` };
        const liveText = sessions ? `, ${fmt.plural(sessions, 'live session')}` : '';
        const label = has
          ? `${pl(from)} ${ARROW} ${pl(to)}: ${fmt.plural(p.count, 'policy')} (${p.permit} permit, ${p.deny} deny, ${p.reject} reject, ${p.inactive} inactive)${liveText}`
          : `${pl(from)} ${ARROW} ${pl(to)}: no zone-pair policy, so Junos checks ${globalsHere ? fmt.plural(globalsHere, 'global policy', 'global policies') : 'the global policies (none apply)'} and then the default policy${liveText}`;
        const children = [];
        if (has) {
          const bar = h('span', { class: 'mx-bar', 'aria-hidden': 'true' });
          for (const k of ['permit', 'deny', 'reject', 'inactive']) {
            if (!p[k]) continue;
            const segEl = h('i', { class: k });
            segEl.style.flexGrow = String(p[k]);
            bar.append(segEl);
          }
          children.push(h('b', { class: 'mx-n' }, String(p.count)), bar);
        } else {
          children.push(h('span', { class: 'mx-g' }, globalsHere ? `${globalsHere} global` : 'default'));
        }
        if (sessions) children.push(h('span', { class: 'mx-live', title: `${fmt.plural(sessions, 'live session')} in the last list read` }, fmt.compact(sessions)));
        cells.push(
          h(
            'a',
            {
              class: ['mx-cell', has ? 'has' : 'empty'],
              href: this.ctx.href('policies', params),
              title: label,
              'aria-label': label,
              on: { click: (e) => { e.preventDefault(); this.ctx.navigate('policies', params); } },
            },
            children,
          ),
        );
      }
    }
    const grid = h('div', { class: 'mx', style: { gridTemplateColumns: `minmax(44px, auto) repeat(${zones.length}, minmax(0, 1fr))` } }, cells);
    const more = all.length > zones.length ? h('p', { class: 'xsmall faint' }, `${all.length - zones.length} more zones in Policies.`) : null;
    const legend = h(
      'div',
      { class: 'mx-legend' },
      h('span', null, h('i', { class: 'permit' }), 'permit'),
      h('span', null, h('i', { class: 'deny' }), 'deny'),
      h('span', null, h('i', { class: 'reject' }), 'reject'),
      h('span', null, h('i', { class: 'inactive' }), 'inactive'),
      live ? h('span', null, h('i', { class: 'live' }), 'live sessions') : null,
    );
    put(t.body, grid, more, legend);
    const dflt = defaultStep(pol, this.ctx.ui.scopeLabel ? this.ctx.ui.scopeLabel(this.ctx.store.scope) : scopeKindLabel(this.ctx.store.scope));
    put(
      t.foot,
      h(
        'span',
        { class: 'eval-hint', title: 'Junos evaluation order: the zone pair\u2019s policies in order, then global policies, then the default policy' },
        h('span', null, 'no match'),
        icon('chevron-right'),
        h('span', { class: 'step', title: globalsOff ? `${globalsOff} global policies are deactivated` : null }, `${globals.length} global`),
        icon('chevron-right'),
        h('span', { class: ['step', dflt.cls], title: dflt.tip }, dflt.text),
      ),
    );
    t.foot.hidden = false;
  }

  /** The listed rows without backup copies of cluster sessions (SES-08), and how many were dropped. */
  countedRows() {
    const table = this.sess && this.sess.sessions;
    const rows = (table && table.status === 'ok' && table.rows) || [];
    const q = this.ctx.query;
    const backups = q && typeof q.sessionCopies === 'function' ? q.sessionCopies(rows).backups : new Set();
    const counted = backups.size ? rows.filter((r) => !backups.has(r.id)) : rows;
    return { rows: counted, dropped: rows.length - counted.length };
  }

  /** Live sessions per zone pair, from the last list read and the policy index (null when not known). */
  liveByPair() {
    const s = this.sess;
    if (!s || this.listErr || !s.sessions || s.sessions.status !== 'ok' || this.ctx.store.scope !== 'root') return null;
    const idx = this.ctx.store.policyIndex();
    const out = new Map();
    for (const r of this.countedRows().rows) {
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
      // The fixture banner already says this on every screen; the tile keeps real warnings.
      const bannerShown = Boolean(snap.meta && snap.meta.fixture);
      for (const w of snap.warnings || []) if (!(bannerShown && isFixtureNote(w))) items.push({ text: w, src: 'device', cls: isFixtureNote(w) ? 'fixture' : '' });
      for (const w of (snap.scope && snap.scope.warnings) || []) if (!(bannerShown && isFixtureNote(w))) items.push({ text: w, src: 'scope', cls: '' });
      const cfg = snap.config || {};
      if (cfg.status && cfg.status !== 'ok') items.push({ text: `Configuration: ${cfg.message || cfg.status}`, src: cfg.status, cls: cfg.status === 'denied' ? 'info' : 'bad' });
      const dev = snap.device || {};
      if (dev.status && dev.status !== 'ok') items.push({ text: `Device facts: ${dev.message || dev.status}`, src: dev.status, cls: 'bad' });
      const saysInactive = ((snap.scope && snap.scope.warnings) || []).some((w) => /deactivated|inactive/i.test(w));
      if (snap.scope && snap.scope.inactive && !saysInactive) items.push({ text: 'This scope is deactivated in the configuration: nothing in it is in effect.', src: 'scope', cls: 'bad' });
    }
    // Failing live reads have their own state card in their tile; here they are one line.
    const failing = [];
    if (this.sessFailing()) failing.push('Flow sessions');
    if (this.denyError && !FINAL.has(this.denyError.status)) failing.push('Recent denies');
    if (failing.length) items.push({ text: `${fmt.plural(failing.length, 'live read')} failing (${failing.join(', ')}); each tile says why. J-Wicket tries again every ${RETRY_S} s.`, src: 'live', cls: 'bad' });
    this.t.warnings.el.classList.toggle('is-empty', Boolean(snap) && !items.length);
    put(t.meta, items.length ? h('span', { class: ['badge', items.some((i) => i.cls === 'bad') ? 'deny' : 'amber'] }, String(items.length)) : null);
    if (!snap && !items.length) return;
    if (!items.length) {
      put(t.body, h('div', { class: 'mg-none' }, icon('check-circle'), h('p', null, 'No warnings from the last read.')));
      return;
    }
    put(
      t.body,
      h(
        'ul',
        { class: 'warn-list' },
        items.map((w) => h('li', { class: ['warn-item', w.cls] }, icon(w.cls === 'fixture' ? 'info' : w.cls === 'info' ? 'lock' : 'alert'), h('span', { class: 'dev-text' }, vis(w.text)), h('span', { class: 'warn-src' }, w.src))),
      ),
    );
  }

  // -- sessions --

  schedule(name, fn, ms) {
    clearTimeout(this.timers[name]);
    if (!this.paused && !this.dead && this.ctx.store.scope === 'root') this.timers[name] = setTimeout(fn, ms);
  }

  /** The gauge and sparkline: the table-wide summary alone (rows=none), every 30 s. */
  async pollSummary(now = false) {
    clearTimeout(this.timers.sum);
    if (this.dead) return;
    if (this.ctx.store.scope !== 'root') {
      this.renderSessions();
      return;
    }
    if ((this.paused && !now) || this.inflightSum) return;
    this.inflightSum = true;
    const res = await this.ctx.api.get('/api/sessions', { scope: 'root', rows: 'none' }, { signal: this.ctl.signal });
    this.inflightSum = false;
    if (this.dead || res.status === 401 || res.aborted) return;
    const wasRetrying = this.retrying();
    let next = SUMMARY_EVERY_S * 1000;
    if (res.ok) {
      this.sum429 = 0;
      this.sumErr = null;
      this.applySummary(res.data);
      const min = Number(res.data.meta && res.data.meta.min_interval_s) || 0;
      next = Math.max(next, min * 1000);
      const st = (res.data.summary || {}).status;
      if (FINAL.has(st)) {
        // Denied or unsupported will not change by itself: stop until a refresh.
        if (wasRetrying !== this.retrying()) this.renderLivePill();
        return;
      }
    } else if (res.status === 429) {
      // SL-04: not an error. With nothing shown yet, try again after the Retry-After; else keep the cadence.
      this.sum429 += 1;
      if (!this.summary) next = Math.max(1, Number(res.retryAfter) || 1) * 1000;
      this.renderSessions();
    } else {
      this.sumErr = res.status === 400 ? { status: 'unsupported', message: res.data.error } : errorState(res, 'Session summary');
      this.renderSessions();
      this.renderWarnings();
      this.renderLivePill();
      if (FINAL.has(this.sumErr.status)) return;
      next = RETRY_S * 1000;
    }
    if (wasRetrying !== this.retrying()) this.renderLivePill();
    this.schedule('sum', () => this.pollSummary(), next);
  }

  /** Top policies, the matrix and the quick links: the session list, every 120 s. */
  async pollList(now = false) {
    clearTimeout(this.timers.list);
    if (this.dead) return;
    if (this.ctx.store.scope !== 'root') {
      this.renderTop();
      return;
    }
    if ((this.paused && !now) || this.inflightList) return;
    this.inflightList = true;
    const res = await this.ctx.api.get('/api/sessions', { scope: 'root' }, { signal: this.ctl.signal });
    this.inflightList = false;
    if (this.dead || res.status === 401 || res.aborted) return;
    const wasRetrying = this.retrying();
    let next = LIST_EVERY_S * 1000;
    if (res.ok) {
      this.list429 = 0;
      this.listErr = null;
      this.applyList(res.data);
      const min = Number(res.data.meta && res.data.meta.min_interval_s) || 0;
      next = Math.max(next, min * 1000);
      const table = res.data.sessions || {};
      if (table.status === 'count-unknown' && table.reason === 'summary-failed') next = RETRY_S * 1000;
      else if (table.status === 'failed') next = RETRY_S * 1000;
      else if (FINAL.has(table.status) || (table.status === 'count-unknown' && table.reason === 'no-count')) {
        // Will not change by asking again (no-count is how this device's summary replies): stop.
        if (wasRetrying !== this.retrying()) this.renderLivePill();
        return;
      }
    } else if (res.status === 429) {
      this.list429 += 1;
      if (!this.sess) next = Math.max(1, Number(res.retryAfter) || 1) * 1000;
      this.renderTop();
    } else {
      this.listErr = res.status === 400 ? { status: 'unsupported', message: res.data.error } : errorState(res, 'Sessions');
      this.renderSessions();
      this.renderTop();
      this.renderLinks();
      this.renderWarnings();
      this.renderLivePill();
      const snap = this.ctx.store.lastInventory;
      if (snap) this.renderMatrix(snap);
      if (FINAL.has(this.listErr.status)) return;
      next = RETRY_S * 1000;
    }
    if (wasRetrying !== this.retrying()) this.renderLivePill();
    this.schedule('list', () => this.pollList(), next);
  }

  applySummary(data, { fromStore = false, at = null } = {}) {
    this.ctx.ui.noteFixture(data.meta);
    const summary = data.summary || {};
    this.summary = { summary, at: at || summaryAt(data) };
    if (summary.status === 'ok' && Number.isFinite(summary.active)) {
      this.history.push(summary.active);
      if (this.history.length > HISTORY) this.history.shift();
    }
    if (!fromStore) this.ctx.store.setSessionsLast(data);
    this.renderSessions();
    this.renderWarnings();
  }

  applyList(data, { fromStore = false } = {}) {
    this.ctx.ui.noteFixture(data.meta);
    this.sess = data;
    this.listAt = fromStore && data.meta && data.meta.read_at ? Date.parse(data.meta.read_at) : Date.now();
    // The gauge and its sparkline follow the summary-only read, one point per 30 s; the list's own
    // (table-wide) summary is shown only until that first read arrives.
    const s = data.summary;
    if (s && s.status === 'ok' && !this.summary) this.summary = { summary: s, at: fromStore ? this.listAt : summaryAt(data) };
    if (!fromStore) this.ctx.store.setSessionsLast(data);
    this.renderSessions();
    this.renderTop();
    const snap = this.ctx.store.lastInventory;
    if (snap) {
      this.renderMatrix(snap);
      this.renderLinks();
    }
    this.renderWarnings();
  }

  // -- health --

  async pollHealth(now = false) {
    if (this.dead) return;
    if (this.paused && !now) return;
    if (this.inflightHealth) return;
    clearTimeout(this.timers.health);
    this.inflightHealth = true;
    const res = await this.ctx.api.get('/api/health', null, { signal: this.ctl.signal });
    this.inflightHealth = false;
    if (this.dead || res.status === 401) return;
    let next = HEALTH_EVERY_S * 1000;
    if (res.ok) {
      const hadError = Boolean(this.healthError);
      this.healthError = null;
      this.health = res.data;
      this.healthAt = Date.now();
      this.ctx.ui.noteFixture(res.data.meta);
      const sample = healthSample(res.data);
      if (sample) {
        HEALTH_LOG.push(sample);
        while (HEALTH_LOG.length && sample.t - HEALTH_LOG[0].t > HEALTH_WINDOW_MS) HEALTH_LOG.shift();
      }
      const final = ['route_engine', 'spu'].every((k) => FINAL.has((res.data[k] || {}).status));
      this.renderHealth();
      this.renderAges();
      if (hadError) this.renderLivePill();
      if (final) return; // neither part can be read by this login class: nothing to poll for
    } else if (res.status === 429) {
      next = Math.max(next, (res.retryAfter || 5) * 1000);
    } else {
      this.healthError = errorState(res, 'System health');
      this.renderHealth();
      this.renderLivePill();
      next = RETRY_S * 1000;
    }
    if (!this.paused && !this.dead) this.timers.health = setTimeout(() => this.pollHealth(), next);
  }

  renderHealth() {
    const t = this.t.health;
    if (this.healthError) {
      t.meta.replaceChildren();
      put(t.body, stateCard({ ...this.healthError, compact: true }));
      return;
    }
    const data = this.health;
    if (!data) return;
    const reP = data.route_engine || {};
    const spuP = data.spu || {};
    if (reP.status !== 'ok' && spuP.status !== 'ok') {
      t.meta.replaceChildren();
      put(t.body, stateCard({ status: reP.status || 'failed', message: reP.message || spuP.message, compact: true }));
      return;
    }
    if (t.body.firstChild !== this.healthContent) put(t.body, this.healthContent);
    const re = primaryEngine(reP);
    const units = spuP.status === 'ok' ? spuP.units || [] : [];
    const spuCpu = mean(units.map((u) => u.cpu));
    const spuMem = mean(units.map((u) => u.memory));
    const spuNote = units.length > 1 ? `mean of ${units.length} SPUs` : '';
    const stat = (label, value, sub, cls) => h('div', { class: ['hl-stat', cls] }, h('dt', null, label), h('dd', null, h('span', { class: 'hl-val num' }, value), sub ? h('span', { class: 'hl-sub' }, sub) : null));
    const pct = (v) => (Number.isFinite(v) ? `${Math.round(v)}%` : DASH);
    const level = (v) => (Number.isFinite(v) && v >= 90 ? 'is-crit' : Number.isFinite(v) && v >= 75 ? 'is-warn' : null);
    const items = [];
    if (re) {
      const mem = re.memory || {};
      items.push(
        stat('RE CPU', pct(re.cpu && re.cpu.busy), re.cpu ? `user ${pct(re.cpu.user)} · system ${pct(re.cpu.system)}` : '', level(re.cpu && re.cpu.busy)),
        stat('RE memory', pct(mem.util), Number.isFinite(mem.used_mb) && Number.isFinite(mem.total_mb) ? `${fmt.num(mem.used_mb)} of ${fmt.num(mem.total_mb)} MB` : '', level(mem.util)),
      );
    } else {
      items.push(stat('Routing engine', DASH, reP.status === 'ok' ? 'no figures' : stateWord(reP.status)));
    }
    if (units.length) {
      const flows = units.reduce((a, u) => a + (u.flow_sessions || 0), 0);
      items.push(
        stat('Data-plane CPU', pct(spuCpu), spuNote, level(spuCpu)),
        stat('Data-plane memory', pct(spuMem), spuNote || `${fmt.compact(flows)} flow sessions`, level(spuMem)),
      );
    } else {
      items.push(stat('Data plane', DASH, stateWord(spuP.status)));
    }
    if (re) {
      const load = (re.load || []).map((v) => (Number.isFinite(v) ? v.toFixed(2) : DASH));
      items.push(
        stat('Load average', load[0] || DASH, load.length ? `5 min ${load[1]} · 15 min ${load[2]}` : ''),
        stat('RE temperature', Number.isFinite(re.temperature_c) ? `${re.temperature_c} °C` : DASH, Number.isFinite(re.cpu_temperature_c) ? `CPU ${re.cpu_temperature_c} °C` : ''),
        stat('Uptime', Number.isFinite(re.uptime_s) ? uptime(re.uptime_s) : DASH, re.status ? `status ${re.status}` : ''),
      );
    }
    put(this.hStats, items);
    const engines = (reP.engines || []).length;
    const notes = [];
    if (engines > 1) notes.push(`${engines} routing engines; showing ${re && re.node ? `${re.node} ` : ''}${re && re.mastership ? re.mastership : 'the first'}.`);
    if (reP.status !== 'ok') notes.push(`Routing engine: ${reP.message || stateWord(reP.status)}`);
    if (spuP.status !== 'ok') notes.push(`Data plane: ${spuP.message || stateWord(spuP.status)}`);
    this.hNote.textContent = notes.join(' ');
    this.hNote.hidden = !notes.length;
    t.meta.textContent = re && re.model ? re.model : '';
    this.renderHealthCharts();
  }

  renderHealthCharts() {
    this.cpuChart.update(HEALTH_LOG.map((s) => ({ t: s.t, v: { re: s.reCpu, spu: s.spuCpu } })));
    this.memChart.update(HEALTH_LOG.map((s) => ({ t: s.t, v: { re: s.reMem, spu: s.spuMem } })));
  }

  renderSessions() {
    const t = this.t.sessions;
    if (this.ctx.store.scope !== 'root') {
      t.meta.replaceChildren();
      put(t.body,
        stateCard({
          status: 'unsupported',
          title: 'Flow sessions are read for the root system only',
          message: 'Junos reads the root logical system by default for this read (inferred from the RPC schema); logical and tenant systems are not read yet.',
          hint: null,
          actions: [h('button', { class: 'btn sm', type: 'button', on: { click: () => this.ctx.navigate('overview', { scope: 'root' }) } }, 'Show the root system')],
          compact: true,
        }),
      );
      t.foot.hidden = true;
      return;
    }
    t.foot.hidden = false;
    if (this.sumErr) {
      t.meta.replaceChildren();
      put(t.body, stateCard({ ...this.sumErr, compact: true }));
      return;
    }
    if (!this.summary) {
      // SL-04: a second 429 before anything was read says so; otherwise the skeleton stays.
      if (this.sum429 >= 2) put(t.body, stateCard({ status: 'waiting', message: 'Waiting to read the session summary: another read of your session is running.', compact: true }));
      return;
    }
    const summary = this.summary.summary || {};
    const ok = summary.status === 'ok';
    if (!ok && FINAL.has(summary.status)) {
      // Denied or unsupported: the list is the same RPC and fares no better; one card says it.
      put(t.meta, h('span', null, `${fmt.time(this.summary.at)} UTC`));
      put(t.body, stateCard({ status: summary.status, message: summary.message, compact: true }));
      this.sessAgo.textContent = `updated ${fmt.ago(this.summary.at)}`;
      return;
    }
    if (t.body.firstChild !== this.sessContent) put(t.body, this.sessContent);
    // Never the number of listed rows: only the summary counts sessions (SES-08).
    const active = ok && Number.isFinite(summary.active) ? summary.active : null;
    const max = ok && Number.isFinite(summary.max) ? summary.max : null;
    const frac = max && active !== null ? active / max : null;
    // Under 10 % a percentage says nothing ("<0.1%"): the ring carries the count itself.
    const small = frac !== null && frac < 0.1;
    if (!ok) {
      // F4: the ring holds about 8 characters; the line under it gives 'summary <status>: <message>'.
      const st = String(summary.status || 'failed');
      this.gauge.update(null, null, { text: DASH, sub: st.length <= 8 ? st : 'not read' });
    } else {
      this.gauge.update(active, max, {
        text: frac === null ? fmt.compact(active) : small ? fmt.compact(active) : fmt.pct(active, max),
        sub: max ? `of ${fmt.compact(max)}` : 'max ?',
      });
    }
    this.sessBig.hidden = !ok || small || frac === null;
    if (!this.sessBig.hidden) setTicking(this.sessBig, fmt.num(active));
    const sessOf = !ok
      ? `summary ${summary.status || 'failed'}${summary.message ? `: ${summary.message}` : ''}`
      : max
        ? `${fmt.num(active)} active of ${fmt.num(max)} maximum (${fmt.pct(active, max)})`
        : active !== null
          ? `${fmt.num(active)} active (maximum not reported)`
          : 'active count not reported';
    put(this.sessOf, vis(sessOf));
    this.spark.update(this.history);
    if (this.history.length) {
      const lo = Math.min(...this.history);
      const hi = Math.max(...this.history);
      this.sparkRange.textContent = lo === hi ? fmt.num(lo) : `${fmt.num(lo)}\u2013${fmt.num(hi)}`;
    } else {
      this.sparkRange.textContent = '';
    }
    put(this.sessNote, ...this.listNote());
    put(t.meta, h('span', null, `${fmt.time(this.summary.at)} UTC`));
    this.sessAgo.textContent = `updated ${fmt.ago(this.summary.at)}`;
  }

  /** Under the gauge: why the list is missing or partial (refused, count unknown, failed, truncated). */
  listNote() {
    const table = (this.sess && this.sess.sessions) || null;
    if (this.listErr || !table) return [];
    if (table.status === 'refused') {
      return [stateCard({ status: 'refused', message: table.message, hint: 'The gauge still counts every session; Sessions lists them with a filter.', compact: true })];
    }
    if (table.status === 'count-unknown') {
      const why = table.reason === 'summary-failed' ? 'the session summary failed' : 'the summary reports no count';
      return [stateCard({ status: 'count-unknown', title: `Sessions not listed: the count is unknown (${why})`, hint: null, compact: true })];
    }
    if (table.status !== 'ok') return [stateCard({ status: table.status || 'failed', message: table.message, compact: true })];
    if (table.truncated) {
      const listed = Number.isFinite(table.sessions_returned) ? table.sessions_returned : table.returned;
      return [h('p', { class: 'xsmall faint' }, `The device listed ${fmt.num(listed)} sessions; the first ${fmt.num(this.countedRows().rows.length)} are counted by policy here.`)];
    }
    return [];
  }

  renderTop() {
    const t = this.t.top;
    this.topAgo = null;
    if (this.ctx.store.scope !== 'root') {
      t.meta.replaceChildren();
      put(t.body, stateCard({ status: 'unsupported', title: 'Needs the root system', message: 'Live sessions are read for the root system only, so this list is shown there.', hint: null, compact: true }));
      return;
    }
    if (this.listErr) {
      t.meta.replaceChildren();
      put(t.body,
        stateCard({
          status: this.listErr.status,
          title: FINAL.has(this.listErr.status) ? undefined : 'Needs the session list, which failed',
          message: FINAL.has(this.listErr.status) ? this.listErr.message : 'Live sessions cannot be counted by policy until the sessions read works again.',
          hint: null,
          compact: true,
        }),
      );
      return;
    }
    const data = this.sess;
    if (!data) {
      if (this.list429 >= 2) put(t.body, stateCard({ status: 'waiting', message: 'Waiting to read the session list: another read of your session is running.', compact: true }));
      return;
    }
    const table = data.sessions || {};
    this.topAgo = h('span', null, `updated ${fmt.ago(this.listAt)}`);
    if (table.status === 'count-unknown') {
      put(t.meta, this.topAgo);
      put(t.body, stateCard({ status: 'count-unknown', title: 'Not counted by policy: the session list was not read (count unknown)', hint: null, compact: true }));
      return;
    }
    if (table.status !== 'ok') {
      put(t.meta, this.topAgo);
      put(t.body,
        stateCard(
          table.status === 'refused'
            ? { status: 'refused', title: 'Too many sessions to count by policy', message: 'The device has more sessions than J-Wicket lists at once. Open Sessions and filter by zone, port or address.', hint: null, compact: true }
            : { status: table.status || 'failed', message: table.message, compact: true },
        ),
      );
      return;
    }
    const { rows, dropped } = this.countedRows();
    const by = new Map();
    for (const r of rows) {
      const name = r.policy || '(no policy reported)';
      const e = by.get(name) || { name, count: 0, bytes: 0, real: Boolean(r.policy) };
      e.count += 1;
      e.bytes += ((r.in && r.in.bytes) || 0) + ((r.out && r.out.bytes) || 0);
      by.set(name, e);
    }
    const top = [...by.values()].sort((a, b) => b.count - a.count || b.bytes - a.bytes).slice(0, TOP_ROWS);
    const listed = Number.isFinite(table.sessions_returned) ? table.sessions_returned : table.returned;
    put(
      t.meta,
      h('span', null, table.truncated ? `first ${fmt.num(rows.length)} of ${fmt.num(listed)}` : `of ${fmt.plural(rows.length, 'session')}`),
      dropped ? h('span', { title: 'Each cluster session is listed by both nodes; the copy on the other node is left out.' }, '· backup copies not counted') : null,
      h('span', null, '· ', this.topAgo),
    );
    if (!top.length) {
      put(t.body, stateCard({ status: 'empty', title: 'No active sessions', message: 'The device listed no flow sessions in this read.', compact: true }));
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
                        class: 'policy-link dev-text',
                        type: 'button',
                        title: `Open policy ${pl(e.name)}`,
                        on: { click: () => this.ctx.navigate('policies', { q: `name:${quote(e.name)}`, sel: p ? p.id : null }) },
                      },
                      v(e.name),
                    )
                  : h('span', { class: 'muted' }, e.name),
                h('span', { class: 'top-zones dev-text' }, v(zones)),
              ),
              h('a', { class: 'top-count', href: this.ctx.href('sessions', e.real ? { q: `policy:${quote(e.name)}` } : {}), title: `Sessions of ${pl(e.name)}`, on: { click: toSessions } }, fmt.num(e.count)),
              h('span', { class: ['bar', action === 'permit' ? 'permit' : action === 'deny' ? 'deny' : action === 'reject' ? 'reject' : 'muted'], 'aria-hidden': 'true' }, h('i', { style: { '--w': `${(e.count / max) * 100}%` } })),
            ),
          );
        }),
      ),
    );
  }

  // -- recent denies --

  /**
   * Where to read denies from (CRT-12): an active syslog file that takes RT_FLOW (one matching DENY or
   * the session messages first), else on-box reporting unless the device's release does not support
   * it, else the security log buffer, else, as the only candidate left, a deactivated RT_FLOW file
   * (Junos no longer writes it, but older lines may still be there): no LIVE pill, read once.
   */
  chooseDenySource(sources) {
    const files = sources.files || [];
    const takes = (f) => /RT_FLOW/i.test(f.match || '');
    const prefer = (f) => /DENY/i.test(f.match || '') || /RT_FLOW_SESSION|RT_FLOW$|RT_FLOW[^_]/i.test(f.match || '');
    const pick = (list) => list.find(prefer) || list[0] || null;
    const file = pick(files.filter((f) => takes(f) && !f.inactive));
    if (file) return { kind: 'file', id: file.id, name: file.name, label: file.name, sub: `match "${file.match}"`, live: true };
    const dbs = sources.databases || [];
    const report = dbs.find((d) => d.id === 'report');
    if (report && report.supported !== false) return { kind: 'report', id: 'report', name: 'on-box reporting', label: 'on-box reporting', sub: 'session-deny', live: true, note: report.note || null };
    if (dbs.some((d) => d.id === 'buffer')) return { kind: 'buffer', id: 'buffer', name: 'the security log buffer', label: 'security log buffer', sub: 'routing engine', live: true };
    const off = pick(files.filter((f) => takes(f) && f.inactive));
    if (off) return { kind: 'file', id: off.id, name: off.name, label: `${off.name} (deactivated: Junos no longer writes it)`, sub: `match "${off.match}"`, live: false };
    return null;
  }

  async pollDenies(now = false) {
    clearTimeout(this.timers.deny);
    if (this.dead || (this.paused && !now) || this.inflightDeny) return;
    this.inflightDeny = true;
    const hadError = Boolean(this.denyError);
    const wasRetrying = this.retrying();
    try {
      await this.readDenies();
    } finally {
      this.inflightDeny = false;
    }
    if (this.dead) return;
    this.renderDenies();
    this.renderWarnings();
    this.renderLinks();
    if (hadError !== Boolean(this.denyError) || wasRetrying !== this.retrying()) this.renderLivePill();
    if (this.paused) return;
    const wait = this.denyWait - Date.now();
    if (this.denyWaiting && wait > 0) {
      // SL-03: a 429 is neither an error nor data: read again after its Retry-After.
      this.timers.deny = setTimeout(() => this.pollDenies(), Math.max(1000, wait));
      return;
    }
    if (this.denyError) {
      // Denied or unsupported will not change by itself; anything else is tried again.
      if (!FINAL.has(this.denyError.status)) this.timers.deny = setTimeout(() => this.pollDenies(), RETRY_S * 1000);
      return;
    }
    if (this.denySource && this.denySource.live) this.timers.deny = setTimeout(() => this.pollDenies(), DENIES_EVERY_S * 1000);
  }

  /** A 429 for a deny read: keep what is shown, and wait at least the Retry-After. */
  noteDenyWait(res) {
    this.denyWaiting = true;
    this.denyWait = Date.now() + Math.max(1, Number(res.retryAfter) || 1) * 1000;
  }

  async readDenies() {
    this.denyWaiting = false;
    if (!this.denySources) {
      const res = await this.ctx.api.get('/api/logs/sources', null, { signal: this.ctl.signal });
      if (this.dead || res.status === 401 || res.aborted) return;
      if (res.status === 429) {
        this.noteDenyWait(res);
        return;
      }
      if (!res.ok) {
        this.denyError = errorState(res, 'Log sources');
        return;
      }
      const src = res.data.sources || {};
      if (src.status !== 'ok') {
        this.denyError = { status: src.status || 'failed', message: src.message };
        return;
      }
      this.denyError = null;
      this.denySources = src;
      this.denySource = this.chooseDenySource(src);
      this.denyDisabled = Boolean(src.traffic && src.traffic.disabled);
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
      res = await this.ctx.api.get('/api/logs', params, { signal: this.ctl.signal });
    } else if (s.kind === 'report') {
      res = await this.ctx.api.get('/api/logs', { source: 'report', type: s.sub === 'session-all' ? 'session-all' : 'session-deny', count: s.sub === 'session-all' ? 200 : 50 }, { signal: this.ctl.signal });
    } else {
      res = await this.ctx.api.get('/api/logs', { source: 'buffer' }, { signal: this.ctl.signal });
    }
    if (this.dead || res.status === 401 || res.aborted) return;
    if (res.status === 429) {
      this.noteDenyWait(res);
      return;
    }
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
    if (log.disabled) this.denyDisabled = true;
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
    // CRT-12: what the device says about on-box reporting on this model or release, on the title.
    t.heading.title = s && s.note ? fmt.plain(s.note) : '';
    // A short list keeps its own height instead of filling two rows with empty tile.
    t.el.classList.toggle('is-short', Boolean(this.denyError) || !s || this.denies.length < 5);
    if (this.denyError) {
      t.meta.replaceChildren();
      put(t.body, stateCard({ ...this.denyError, compact: true }));
      t.foot.hidden = true;
      return;
    }
    if (!this.denySources) {
      if (this.denyWaiting) put(t.body, stateCard({ status: 'waiting', message: 'Waiting to read the log sources: another read of your session is running.', compact: true }));
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
    let pill = null;
    if (s.live) {
      const idle = !this.paused && this.idle;
      this.denyLive = this.denyLive || h('button', { class: 'live-pill', type: 'button', on: { click: () => this.onPillClick() } });
      this.denyLive.className = `live-pill${this.paused || idle ? ' paused' : ''}${idle ? ' idle' : ''}`;
      put(this.denyLive, h('span', { class: 'dot', 'aria-hidden': 'true' }), this.paused || idle ? 'PAUSED' : 'LIVE', h('span', { class: 'sub' }, this.paused ? 'space' : idle ? 'idle' : `${DENIES_EVERY_S} s`));
      this.denyLive.setAttribute('aria-label', this.paused ? 'Paused. Resume (space).' : idle ? IDLE_LABEL : `Live every ${DENIES_EVERY_S} s. Pause (space).`);
      pill = this.denyLive;
    } else {
      this.denyLive = null;
    }
    const where = this.ctx.store.scope === 'root' ? s.label : `${s.label} (device-wide)`;
    put(t.meta, h('span', { class: 'ellipsis dev-text', title: pl(`${where}. Logs are device-wide.`) }, v(where)), pill);
    this.denyAgo = this.denyAgo || h('span', null, '');
    this.denyAgo.textContent = this.denyAt ? `updated ${fmt.ago(this.denyAt)}` : '';
    const params = { source: s.id, q: `tag:${DENY_TAG}` };
    put(t.foot,
      this.denyAgo,
      h('span', { class: 'spacer' }),
      h('a', { href: this.ctx.href('logs', params), on: { click: (e) => { e.preventDefault(); this.ctx.navigate('logs', params); } } }, 'Open in Logs', icon('arrow-right')),
    );
    t.foot.hidden = false;
    if (!this.denyAt) {
      // SL-03: nothing read yet. A 429 says so; no head figure, and never "No denied sessions".
      put(t.body, this.denyWaiting ? stateCard({ status: 'waiting', message: `Waiting to read ${s.name}: another read of your session is running.`, compact: true }) : skeleton(3));
      return;
    }
    const head = h(
      'div',
      { class: 'denies-head' },
      h('span', { class: 'big-num' }, fmt.num(this.denyTotal)),
      h(
        'span',
        { class: 'small muted dev-text' },
        s.kind === 'file'
          ? v(`in the last ${fmt.num(this.denyWindow)} lines of ${s.name}`)
          : s.kind === 'report'
            ? 'in on-box reporting'
            : 'in the routing engine buffer',
        this.denyNew ? h('span', { class: 'pill' }, `+${fmt.num(this.denyNew)} while open`) : null,
      ),
    );
    if (!this.denies.length) {
      put(
        t.body,
        head,
        this.denyDisabled
          ? stateCard({ status: 'info', title: 'Security logging is disabled', message: `Security logging is disabled (security log disable): the device writes no new denies. Older records may still be in ${s.name}.`, compact: true })
          : stateCard({ status: 'empty', title: 'No denied sessions', message: `No ${DENY_TAG} lines ${s.kind === 'file' ? `in ${s.name}` : 'yet'}.`, compact: true }),
      );
      return;
    }
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
    t.el.classList.toggle('is-short', groups.length < 5);
    put(t.body, head, h('div', { class: 'ticker', role: 'list' }, groups.slice(0, TICKER_ROWS).map((d) => this.denyRow(d))));
  }

  /** "tcp" for 6, "esp" for 50 (SES-38: the shared protocol table). */
  protoName(p) {
    if (p === null || p === undefined || p === '') return '';
    const q = this.ctx.query;
    const names = q && typeof q.protoNames === 'function' ? q.protoNames(p) : [String(p).toLowerCase()];
    return names[0] || String(p).toLowerCase();
  }

  denyRow(d) {
    const proto = this.protoName(d.proto);
    const q = [`tag:${DENY_TAG}`, d.src ? `src:${quote(d.src)}` : null, d.dport ? `dport:${quote(d.dport)}` : null].filter(Boolean).join(' ');
    const source = this.denySource ? this.denySource.id : null;
    const open = (e) => {
      e.preventDefault();
      this.ctx.navigate('logs', { source, q });
    };
    const label = pl(`Denied ${d.src || '?'} to ${d.dst || '?'} port ${d.dport || '?'} ${proto}${d.policy ? ` by policy ${d.policy}` : ''}${d.count > 1 ? `, ${d.count} times` : ''}`);
    const policy =
      d.policy && d.policy !== 'N/A'
        ? h('button', { class: 'policy-link dev-text', type: 'button', title: `Open policy ${pl(d.policy)}`, on: { click: () => this.ctx.navigate('policies', { q: `name:${quote(d.policy)}`, sel: policySel(this.ctx.store.policyIndex(), d.policy, d.from, d.to) }) } }, v(d.policy))
        : h('span', { class: 'faint mono', title: 'The log line names no policy' }, 'policy N/A');
    return h(
      'div',
      { class: ['tick-row', d.fresh && 'row-new'], role: 'listitem' },
      h('span', { class: 'tick-time' }, d.time || DASH),
      h(
        'a',
        { class: 'tick-flow', href: this.ctx.href('logs', { source, q }), title: `Show these denies in Logs: ${pl(q)}`, 'aria-label': label, on: { click: open } },
        h('span', { class: 'ip dev-text' }, v(d.src || '?')),
        h('span', { class: 'arrow' }, ARROW),
        // Address and port in one run: "203.0.113.2:22", never "203.0.113.2 :22".
        h('span', { class: 'ip dev-text' }, v(d.dst || '?'), d.dport ? h('span', { class: 'port' }, v(`:${d.dport}`)) : null),
        proto ? h('span', { class: 'pill sky dev-text' }, v(proto)) : null,
      ),
      h('span', { class: 'tick-meta' }, d.count > 1 ? h('span', { class: 'badge deny', title: `${d.count} denies of this flow in the window` }, `\u00d7${d.count}`) : null),
      h(
        'span',
        { class: 'tick-sub' },
        d.from ? h('span', { class: 'zone dev-text' }, v(d.from)) : null,
        d.from || d.to ? h('span', { class: 'arrow' }, ARROW) : null,
        d.to ? h('span', { class: 'zone dev-text' }, v(d.to)) : null,
        policy,
        d.app ? h('span', { class: 'mono dev-text' }, v(d.app)) : null,
        d.iface ? h('span', { class: 'iface dev-text' }, v(d.iface)) : null,
      ),
    );
  }

  // -- quick links --

  /** Whether a link into Logs would land on a source this login class cannot read. */
  logsDenied() {
    return Boolean(this.denyError && this.denyError.status === 'denied');
  }

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
    const table = !this.listErr && this.sess && this.sess.sessions && this.sess.sessions.status === 'ok' ? this.countedRows().rows : [];
    if (table.length && this.ctx.store.scope === 'root') {
      const top = (key) => {
        const m = new Map();
        for (const r of table) {
          const value = key(r);
          if (value !== null && value !== undefined && value !== '') m.set(value, (m.get(value) || 0) + 1);
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
    // Links into Logs only where this login class can read logs, and only to sources that exist.
    if (!this.logsDenied()) {
      if (this.denySource) add('logs', 'Session denies', `tag:${DENY_TAG}`, { source: this.denySource.id });
      const files = (this.denySources && this.denySources.files) || null;
      const messages = files ? files.find((f) => f.name === 'messages') : null;
      if (!files || messages) add('logs', 'Commits and configuration changes', 'tag:UI_COMMIT*', { source: messages ? messages.id : 'file:messages' });
    }
    if (!links.length) {
      put(t.body, snap ? stateCard({ status: 'empty', message: 'Nothing to jump to from what this login class can read.', compact: true }) : skeleton(2));
      return;
    }
    put(t.body,
      h(
        'div',
        { class: 'links' },
        links.slice(0, 8).map((l) => {
          const target = { policies: 'policies', sessions: 'sessions', logs: 'logs' }[l.viewId];
          const sp = new URLSearchParams(l.params);
          const [key, ...rest] = (l.q || '').split(':');
          return h(
            'a',
            {
              class: 'qlink',
              href: this.ctx.href(target, sp),
              on: { click: (e) => { e.preventDefault(); this.ctx.navigate(target, l.params); } },
            },
            h('span', { class: 'qlink-icon' }, icon(target)),
            h('span', { class: 'qlink-label dev-text' }, v(l.label)),
            h('span', { class: 'qlink-q dev-text' }, `${target} `, l.q && rest.length ? [h('b', null, `${key}:`), v(rest.join(':'))] : v(l.q)),
            icon('chevron-right'),
          );
        }),
      ),
    );
  }
}
