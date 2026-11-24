// views/sessions.js: live flow sessions (UI brief, sections 4 and 9).
//
// One poll = GET /api/sessions with the device-side part of the query (plan(): src, dst, sport, dport,
// proto, app, iface), then the rest of the query runs here over the rows the device returned
// (compile()). Every poll is a NETCONF read that Junos logs, so the default interval is the server's
// suggested one (5 s) and never faster than meta.min_interval_s.
//
// Live diff: rows are keyed by id. New rows wash gold; rows that disappeared stay one poll struck
// through, then leave. Each session's byte counters are remembered (memory only, this tab, for the
// session's lifetime) to compute a live rate from the delta between polls and to draw its sparkline.
// Nothing read from the device is written to browser storage; localStorage holds UI preferences only
// (columns, interval, facets rail).
//
// The table's DOM rows are keyed by session id too (RowWindow below): a poll patches the cells that
// changed in place, so the focused row, the opener of the detail panel and the selection stay on the
// session the operator chose while rows re-sort underneath.

import { Gauge } from '../widgets/gauge.js';
import { Sparkline } from '../widgets/sparkline.js';
import { FlowDiagram, flowModel } from '../widgets/flowdiagram.js';

const INTERVALS = [2, 5, 10, 30];
const LIMITS = [500, 1000, 2000];
const DEFAULT_LIMIT = 500;
const POLL_HISTORY = 72;
const RATE_HISTORY = 120;
const MAX_TRACKED = 8000;
const FLASH_MS = 1900;
const MOBILE_W = 700;
const RETRY_S = 15;
const ZONE_KEYS = new Set(['zone', 'from', 'to']);
const SEP = ' · ';
const ARROW = '→';
const DASH = '—';
const PREF = {
  cols: 'jwicket.sessions.columns',
  every: 'jwicket.sessions.interval',
  facets: 'jwicket.sessions.facets',
  metric: 'jwicket.sessions.facet-metric',
};

const ICON = ['M4 8h13.5', 'M14.5 4.8l3.2 3.2-3.2 3.2', 'M20 16H6.5', 'M9.5 12.8L6.3 16l3.2 3.2'];

export const view = {
  id: 'sessions',
  title: 'Sessions',
  icon: ICON.join(' '),
  mount(el, ctx) {
    const v = new SessionsView(el, ctx);
    return { update: (route) => v.update(route), unmount: () => v.destroy() };
  },
};

// ---- helpers -------------------------------------------------------------------------------------

function prefGet(key) {
  try {
    return window.localStorage.getItem(key);
  } catch (_err) {
    return null;
  }
}

function prefSet(key, value) {
  try {
    if (value === null || value === undefined) window.localStorage.removeItem(key);
    else window.localStorage.setItem(key, String(value));
  } catch (_err) {
    // Storage blocked: the preference lasts for this page only.
  }
}

/** A query value, quoted when the lexer needs it. */
function qv(v) {
  const s = String(v);
  return /^[A-Za-z0-9._\-/:*]+$/.test(s) && !/^[-!]/.test(s) ? s : `"${s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

/** "10.0.0.1:443", "[2001:db8::1]:443" */
function hp(ip, port) {
  if (!ip) return DASH;
  const host = String(ip).includes(':') ? `[${ip}]` : String(ip);
  return port === null || port === undefined || port === '' ? host : `${host}:${port}`;
}

function sum(a, b) {
  const x = Number.isFinite(a) ? a : null;
  const y = Number.isFinite(b) ? b : null;
  if (x === null && y === null) return null;
  return (x || 0) + (y || 0);
}

function ipSortKey(ip) {
  if (!ip) return null;
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip);
  if (m) return ((Number(m[1]) * 256 + Number(m[2])) * 256 + Number(m[3])) * 256 + Number(m[4]);
  return `~${String(ip).toLowerCase()}`;
}

function cmp(a, b) {
  const na = a === null || a === undefined || a === '';
  const nb = b === null || b === undefined || b === '';
  if (na || nb) return na === nb ? 0 : na ? 1 : -1; // empty last, whatever the direction
  if (typeof a === 'number' && typeof b === 'number') return a - b;
  if (typeof a === 'number') return -1;
  if (typeof b === 'number') return 1;
  return String(a).localeCompare(String(b), 'en', { numeric: true });
}

function nodeOf(location) {
  const m = /node\s*(\d+)/i.exec(String(location || ''));
  return m ? m[1] : null;
}

const REDUCED = typeof matchMedia === 'function' ? matchMedia('(prefers-reduced-motion: reduce)') : null;

/** Set a counter's text; when it changed, replay a short tick (Web Animations: no forced layout). */
function tick(el, text) {
  const next = String(text);
  if (el.textContent === next) return;
  el.textContent = next;
  if (REDUCED && REDUCED.matches) return;
  if (typeof el.animate === 'function') {
    el.animate([{ transform: 'translateY(-30%)', opacity: 0.3 }, { transform: 'none', opacity: 1 }], { duration: 240, easing: 'cubic-bezier(.2,.7,.2,1)' });
  }
}

function csvCell(value) {
  let text = value === null || value === undefined ? '' : Array.isArray(value) ? value.join(' ') : String(value);
  // Spreadsheet formula injection: neutralise cells a spreadsheet would evaluate (as the server does).
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

function fileStamp(date) {
  const d = date instanceof Date ? date : new Date(date);
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getUTCFullYear()}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}T${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`;
}

function safeName(s) {
  return String(s || 'device').replace(/[^A-Za-z0-9._-]+/g, '-').slice(0, 60) || 'device';
}

/** The HA role a row carries, if any: a state-like field with Active/Backup (reply tags vary by release). */
function haRole(r) {
  for (const v of [r.state, r.status]) {
    if (/^\s*(active|backup)\s*$/i.test(String(v || ''))) return String(v).trim().toLowerCase();
  }
  for (const [k, v] of Object.entries(r.extra || {})) {
    if (/state|role|ha|status/i.test(k) && /^\s*(active|backup|stand-?alone|warm)\s*$/i.test(String(v))) return String(v).trim().toLowerCase();
  }
  return null;
}

/**
 * A rate for the table cell: at most 8 characters ("6.9 kB/s", "69 kB/s", "314 kB/s") so it fits
 * its column; the detail panel and tooltips keep format.rate's precision.
 */
function rateShort(v, fmt) {
  if (!Number.isFinite(v)) return DASH;
  if (v > 0 && v < 1) return '<1 B/s';
  if (v < 1000) return `${Math.round(v)} B/s`;
  const units = ['kB', 'MB', 'GB', 'TB'];
  let x = v / 1000;
  let i = 0;
  while (x >= 999.5 && i < units.length - 1) {
    x /= 1000;
    i += 1;
  }
  return `${x < 9.95 ? x.toFixed(1) : Math.round(x)} ${units[i]}/s`;
}

/** Seconds as an operator reads a timeout: "59 s" under two minutes, else "3m 04s". */
function secs(n, fmt) {
  const v = Number(n);
  if (!Number.isFinite(v)) return DASH;
  return v < 120 ? `${Math.max(0, Math.round(v))} s` : fmt.duration(v);
}

/**
 * An address split for middle truncation: the head may be cut with an ellipsis when the column is
 * too narrow, the tail (last group) and the port never are. "2001:db8::1" -> ["2001:db8:", ":1"].
 */
function splitTail(text) {
  const s = String(text);
  const cut = Math.max(s.lastIndexOf('.'), s.lastIndexOf(':'));
  const at = cut > 0 && cut < s.length - 1 ? cut : Math.max(1, s.length - 3);
  return [s.slice(0, at), s.slice(at)];
}

/** The data-fk (focus key) of the focused element inside root, if any. */
function focusKeyIn(root) {
  const a = document.activeElement;
  if (!a || !root || a === root || !root.contains(a)) return null;
  return a.dataset && a.dataset.fk ? a.dataset.fk : null;
}

/** Put focus back on the element with that focus key inside root (after a section was rebuilt). */
function refocus(root, fk) {
  if (!fk || !root) return;
  const a = document.activeElement;
  if (a && a !== document.body && root.contains(a)) return;
  for (const el of root.querySelectorAll('[data-fk]')) {
    if (el.dataset.fk === fk && typeof el.focus === 'function') {
      el.focus({ preventScroll: true });
      return;
    }
  }
}

/** Replace root's children; the focused control (by data-fk) is focused again in the new content. */
function swapKeepFocus(put, root, ...children) {
  const fk = focusKeyIn(root);
  put(root, ...children);
  if (fk) refocus(root, fk);
}

// ---- keyed row window ----------------------------------------------------------------------------

/**
 * A fixed-row-height virtual list whose DOM rows are keyed (by session id), not by index. A sync
 * re-places each row at its index and lets patch(node, i) update what changed; a node keeps its
 * identity while its key stays in the window, so focus, the panel opener and the selection survive
 * re-sorting. The focused row stays rendered even when scrolled out of the window, and DOM order is
 * index order without moving the focused node (moving it would blur it).
 */
class RowWindow {
  constructor({ container, rowHeight, overscan = 10, keyOf, create, patch, onWindow }) {
    this.container = container;
    this.rowHeight = Math.max(1, Number(rowHeight) || 28);
    this.overscan = overscan;
    this.keyOf = keyOf;
    this.create = create;
    this.patch = patch;
    this.onWindow = onWindow || null;
    this.count = 0;
    this.nodes = new Map(); // key -> node
    this.range = { start: 0, end: -1, first: 0, last: -1 };
    this.scrollTop = 0;
    this.viewH = 0;
    this.offset = 0;
    container.classList.add('vlist');
    this.body = document.createElement('div');
    this.body.className = 'vlist-body';
    this.body.setAttribute('role', 'rowgroup');
    container.append(this.body);
    this.schedule = () => {
      if (!this.raf) this.raf = requestAnimationFrame(() => {
        this.raf = 0;
        this.sync(false);
      });
    };
    this.onScroll = () => {
      this.scrollTop = this.container.scrollTop;
      this.schedule();
    };
    container.addEventListener('scroll', this.onScroll, { passive: true });
    this.ro = typeof ResizeObserver === 'function' ? new ResizeObserver(() => this.measure(true)) : null;
    if (this.ro) this.ro.observe(container);
    this.measure(false);
  }

  /** Read the scroller geometry (only here, on resize and on scroll: never in the middle of a poll). */
  measure(sync) {
    if (!this.body) return;
    this.viewH = this.container.clientHeight || this.viewH;
    this.offset = this.body.offsetTop;
    this.scrollTop = this.container.scrollTop;
    if (sync) this.schedule();
  }

  win() {
    const rh = this.rowHeight;
    const top = Math.max(0, this.scrollTop - this.offset);
    const height = this.viewH || 600;
    const first = Math.max(0, Math.min(this.count - 1, Math.floor(top / rh)));
    const last = Math.max(-1, Math.min(this.count - 1, Math.ceil((top + height) / rh) - 1));
    return { first, last, start: Math.max(0, first - this.overscan), end: Math.min(this.count - 1, last + this.overscan) };
  }

  setCount(n) {
    this.count = Math.max(0, n | 0);
    this.body.style.height = `${this.count * this.rowHeight}px`;
  }

  setRowHeight(px) {
    const next = Math.max(1, Number(px) || this.rowHeight);
    if (next === this.rowHeight) return;
    const firstVisible = this.range.first;
    this.rowHeight = next;
    this.setCount(this.count);
    this.reset();
    this.scrollToIndex(firstVisible, 'start');
  }

  /** Drop every DOM row (the columns or the layout changed); the next sync builds them again. */
  reset() {
    for (const node of this.nodes.values()) node.remove();
    this.nodes.clear();
  }

  focusedNode() {
    const a = document.activeElement;
    if (!a || a === document.body || !this.body.contains(a)) return null;
    for (const node of this.nodes.values()) if (node.contains(a)) return node;
    return null;
  }

  /** Place and patch the rows of the window. Every row is patched when `all` (a new poll). */
  sync(all = true) {
    if (!this.body) return;
    const w = this.win();
    this.range = w;
    if (this.onWindow) this.onWindow(w);
    const keys = new Map(); // key -> index
    for (let i = w.start; i <= w.end; i += 1) keys.set(this.keyOf(i), i);
    const focused = this.focusedNode();
    if (focused && !keys.has(focused.dataset.key)) {
      // Keep the focused row rendered (and focused) wherever it now sits, if it is still listed.
      const at = this.indexOf ? this.indexOf(focused.dataset.key) : -1;
      if (at >= 0) keys.set(focused.dataset.key, at);
    }
    let lostFocus = false;
    for (const [key, node] of this.nodes) {
      if (!keys.has(key)) {
        if (node === focused) lostFocus = true;
        node.remove();
        this.nodes.delete(key);
      }
    }
    const order = [...keys.entries()].sort((a, b) => a[1] - b[1]);
    const list = [];
    for (const [key, i] of order) {
      let node = this.nodes.get(key);
      if (!node) {
        node = this.create(i);
        node.dataset.key = key;
        node.classList.add('vlist-row');
        node.style.height = `${this.rowHeight}px`;
        this.nodes.set(key, node);
      } else if (all || node._i !== i) {
        this.patch(node, i);
      }
      if (node._i !== i) {
        node._i = i;
        node.style.top = `${i * this.rowHeight}px`;
      }
      list.push(node);
    }
    // DOM order = index order, moving the other nodes around the focused one.
    let cur = this.body.firstChild;
    for (const node of list) {
      if (node === cur) {
        cur = cur.nextSibling;
        continue;
      }
      if (node === focused && node.parentNode === this.body) {
        while (cur && cur !== node) {
          const nx = cur.nextSibling;
          this.body.append(cur);
          cur = nx;
        }
        cur = node.nextSibling;
        continue;
      }
      this.body.insertBefore(node, cur);
    }
    if (lostFocus && typeof this.onFocusLost === 'function') this.onFocusLost();
  }

  /** Patch one row now (selection changed), if it is rendered. */
  patchKey(key) {
    const node = this.nodes.get(key);
    if (node && Number.isInteger(node._i)) this.patch(node, node._i);
  }

  nodeFor(key) {
    return this.nodes.get(key) || null;
  }

  rowAt(i) {
    if (i < 0 || i >= this.count) return null;
    return this.nodes.get(this.keyOf(i)) || null;
  }

  /** align: 'nearest' (default), 'start', 'center' or 'end'. */
  scrollToIndex(i, align = 'nearest') {
    if (!this.count) return;
    this.measure(false);
    const idx = Math.max(0, Math.min(this.count - 1, i | 0));
    const rh = this.rowHeight;
    const off = this.offset;
    const view = this.viewH;
    const top = off + idx * rh;
    const cur = this.scrollTop;
    let next = cur;
    // The sticky header covers the first `off` pixels of the viewport.
    if (align === 'start') next = top - off;
    else if (align === 'center') next = top - (view - rh) / 2;
    else if (align === 'end') next = top - view + rh;
    else if (top < cur + off) next = top - off;
    else if (top + rh > cur + view) next = top + rh - view;
    next = Math.max(0, Math.round(next));
    if (next !== cur) {
      this.container.scrollTop = next;
      this.scrollTop = this.container.scrollTop;
    }
    this.sync(false);
  }

  destroy() {
    if (this.raf) cancelAnimationFrame(this.raf);
    this.container.removeEventListener('scroll', this.onScroll);
    if (this.ro) this.ro.disconnect();
    this.nodes.clear();
    if (this.body) this.body.remove();
    this.body = null;
  }
}

// ---- columns -------------------------------------------------------------------------------------

// w: minimum width in px; fr: share of spare width; prio: lower survives longer when the table is
// narrower than every column (automatic column fit). Each row is its own CSS grid, so widths are
// fixed or fr (never content-sized, which would misalign the rows). Source and destination fit any
// IPv4 address with a 5-digit port (21 monospace characters); the zones width follows the zone names
// in the inventory (see zonesWidth()).
const COLUMNS = [
  { id: 'status', label: '', title: 'Status', w: 18, prio: 0, fixed: true },
  { id: 'id', label: 'ID', title: 'Session ID', w: 62, prio: 11, sort: 'id', num: true },
  { id: 'policy', label: 'Policy', w: 90, fr: 1.1, prio: 3, sort: 'policy' },
  { id: 'zones', label: 'Zones', title: 'From-zone → to-zone (from the policy)', w: 110, prio: 5.5, sort: 'zones', onlyWith: 'zones' },
  { id: 'proto', label: 'Proto', title: 'Protocol', w: 46, prio: 3.5, sort: 'proto' },
  { id: 'src', label: 'Source', title: 'Client address and port', w: 156, fr: 1, prio: 1, sort: 'src' },
  { id: 'dst', label: 'Destination', title: 'Destination as the client sent it', w: 156, fr: 1, prio: 1, sort: 'dst' },
  { id: 'nat', label: 'NAT', title: 'Source NAT (translated source) and destination NAT (translated destination)', w: 168, fr: 0.4, prio: 4, sort: 'nat' },
  { id: 'app', label: 'App', title: 'Application', w: 88, fr: 0.5, prio: 9, sort: 'app' },
  { id: 'iface', label: 'In → out', title: 'Ingress and egress interface', w: 172, prio: 10, sort: 'iface' },
  { id: 'bytes', label: 'Bytes ↑↓', title: '↑ from the client, ↓ from the server', w: 86, prio: 2, sort: 'bytes', num: true },
  { id: 'pkts', label: 'Pkts', title: 'Packets, both directions', w: 54, prio: 12, sort: 'pkts', num: true },
  { id: 'rate', label: 'Rate', title: 'Rate in bytes per second between the last two polls (dim = average since the session started, until the second poll)', w: 66, prio: 2, sort: 'rate', num: true },
  { id: 'dur', label: 'Age', title: 'Duration: how long the session has existed', w: 58, prio: 5, sort: 'dur', num: true },
  { id: 'timeout', label: 'Timeout', title: 'Idle timeout remaining (bar: of the configured timeout; amber under 20 %)', w: 70, prio: 7, sort: 'timeout', num: true },
  { id: 'node', label: 'Node', title: 'Cluster node or SPU', w: 110, prio: 6.5, sort: 'node', onlyWith: 'location' },
];
const COL_BY_ID = new Map(COLUMNS.map((c) => [c.id, c]));

const SORTS = {
  id: (r) => Number(r.session_id) || ipSortKey(r.session_id) || ipSortKey(r.id),
  policy: (r) => r.policy,
  zones: (r) => (r._zones ? `${r._zones.fromText} ${r._zones.toText}` : null),
  proto: (r) => (r.in || {}).proto,
  src: (r) => ipSortKey((r.in || {}).src),
  dst: (r) => ipSortKey((r.in || {}).dst),
  nat: (r) => (r.nat && (r.nat.source || r.nat.destination) ? (r.nat.source ? 1 : 0) + (r.nat.destination ? 2 : 0) : null),
  app: (r) => r.application,
  iface: (r) => (r.in || {}).iface,
  bytes: (r) => r._bytes,
  pkts: (r) => r._pkts,
  rate: (r) => r.rate,
  dur: (r) => r.duration,
  timeout: (r) => r.timeout,
  node: (r) => r.location,
};

const SORT_LABEL = {
  'dur': 'newest first', '-dur': 'oldest first', '-rate': 'fastest first', 'rate': 'slowest first',
  '-bytes': 'most bytes first', 'bytes': 'fewest bytes first', 'timeout': 'expiring first',
};

// ---- facets --------------------------------------------------------------------------------------

// One neutral bar colour for every group (signal colours mean something: violet is NAT, amber a
// warning); teal stays for interfaces, which is what teal means everywhere in J-Wicket. A bar turns
// gold when it is hovered or is a filter already applied.
const FACETS = [
  { id: 'src', title: 'Source', key: 'src', get: (r) => (r.in || {}).src },
  { id: 'dst', title: 'Destination', key: 'dst', get: (r) => (r.in || {}).dst },
  { id: 'dport', title: 'Destination port', key: 'dport', get: (r) => (r.in || {}).dport },
  { id: 'app', title: 'Application', key: 'app', get: (r) => r.application },
  { id: 'policy', title: 'Policy', key: 'policy', get: (r) => r.policy },
  { id: 'iface', title: 'Interface', key: 'iface', cls: 'teal', get: (r) => (r.in || {}).iface, get2: (r) => (r.out || {}).iface },
];
const METRICS = [
  { id: 'count', label: 'Sessions', title: 'Top 8 by number of sessions' },
  { id: 'bytes', label: 'Bytes', title: 'Top 8 by bytes, both directions' },
  { id: 'rate', label: 'Rate', title: 'Top 8 by live rate' },
];

// ---- the view ------------------------------------------------------------------------------------

class SessionsView {
  constructor(el, ctx) {
    this.el = el;
    this.ctx = ctx;
    this.h = ctx.dom.h;
    this.fmt = ctx.format;
    this.q = ctx.query;
    this.dead = false;

    const every = Number(prefGet(PREF.every));
    this.every = INTERVALS.includes(every) ? every : null; // null: the server's suggestion
    this.paused = false;
    this.hold = false;
    this.showBackups = false;
    this.facetsOpen = prefGet(PREF.facets) !== 'closed';
    this.facetsTouched = prefGet(PREF.facets) !== null;
    this.metric = METRICS.some((m) => m.id === prefGet(PREF.metric)) ? prefGet(PREF.metric) : 'count';
    this.manualCols = this.readCols();

    // query state: `text` is what the bar holds, `goodText` the last query that parsed (the one
    // applied, and the one written to the shareable hash).
    this.text = '';
    this.goodText = '';
    this.zoneIgnored = [];
    this.device = {};
    this.deviceKey = '{}';
    this.match = () => true;
    this.plan = null;
    this.queryError = null;
    this.serverError = null;
    this.sort = 'dur';
    this.limit = DEFAULT_LIMIT;
    this.selId = null;
    this.wantSel = null;

    // poll state
    this.payload = null;
    this.readAt = 0;
    this.lastOkAt = 0;
    this.failure = null;
    this.inflight = null;
    this.pollSeq = 0;
    this.polls = 0;
    this.timer = 0;
    this.nextAt = 0;
    this.history = [];

    // diff state (per device-filter set)
    this.known = new Map(); // id -> { firstAt, lastBytes, lastAt, hist: [rate], newAt, polls }
    this.current = []; // view-model rows of the last poll
    this.ended = new Map(); // id -> view-model row (struck, one poll)
    this.prevIds = null;
    this.prevComplete = false;
    this.order = new Map();
    this.stats = { added: null, ended: null };
    this.backupCount = 0;

    // display state
    this.rows = []; // what the grid shows, in order
    this.indexById = new Map();
    this.cols = [];
    this.mobile = false;
    this.cardW = 0;
    this.tabId = null; // the row that takes Tab (roving tabindex)
    this.detail = null;
    this.menu = null;
    this.hover = null;
    this.sigs = { notices: '', state: '', facets: '', strip: '' };

    this.build();
    this.booting = true;
    this.readRoute(ctx.route, true);
    this.booting = false;
    this.offs = [
      ctx.store.on('inventory', () => this.onInventory()),
      ctx.store.on('scope', () => this.onScope()),
    ];
    this.listeners = [
      ['jwicket:toggle-live', () => this.togglePause()],
      ['jwicket:refresh', () => this.poll(true)],
      ['jwicket:density', () => this.fitRows()],
      ['jwicket:escape', () => this.onEscape()],
      ['keydown', (e) => this.onKey(e)],
    ];
    for (const [type, fn] of this.listeners) document.addEventListener(type, fn);
    this.ageTimer = setInterval(() => this.renderAge(), 1000);
    ctx.store.inventory().then(() => {
      if (!this.dead) this.onInventory();
    });
    this.poll(true);
  }

  // ---- lifecycle -------------------------------------------------------------------------------

  onInventory() {
    if (this.dead) return;
    const idx = this.ctx.store.policyIndex();
    for (const r of this.current) r._zones = this.zonesOf(r.policy, idx);
    for (const r of this.ended.values()) r._zones = this.zonesOf(r.policy, idx);
    this.compileBrowser();
    this.renderSub();
    this.colKey = null; // the zones column depends on the inventory (shown, and its width)
    this.fitColumns();
    this.recompute();
    this.renderNotices();
    if (this.detail) this.detail.update();
  }

  onScope() {
    if (this.dead) return;
    if (this.ctx.store.scope === 'root') {
      this.poll(true);
    } else {
      clearTimeout(this.timer);
      this.timer = 0;
      if (this.inflight) this.inflight.abort();
      this.inflight = null;
      this.nextAt = 0;
      this.renderNext();
    }
    this.renderAll();
    this.renderFacets();
  }

  update(route) {
    this.readRoute(route, false);
  }

  destroy() {
    this.dead = true;
    clearTimeout(this.timer);
    clearInterval(this.ageTimer);
    if (this.inflight) this.inflight.abort();
    for (const off of this.offs) off();
    for (const [type, fn] of this.listeners) document.removeEventListener(type, fn);
    if (this.ro) this.ro.disconnect();
    if (this.facetTimer) cancelAnimationFrame(this.facetTimer);
    if (this.list) this.list.destroy();
    if (this.bar) this.bar.destroy();
    this.closeMenu();
    if (this.detail) this.detail.destroy();
    this.detail = null;
    this.ctx.ui.setLive('sessions', false);
  }

  readRoute(route, first) {
    const p = route && route.params ? route.params : new URLSearchParams();
    const q = p.get('q') || '';
    const sort = p.get('sort');
    const lim = Number(p.get('limit'));
    const limit = LIMITS.includes(lim) ? lim : DEFAULT_LIMIT;
    const sel = p.get('sel') || null;
    const backups = p.get('backups') === 'show';
    let changed = false;
    if (sort && (SORTS[sort.replace(/^-/, '')]) && sort !== this.sort) {
      this.sort = sort;
      changed = true;
    }
    if (backups !== this.showBackups) {
      this.showBackups = backups;
      changed = true;
    }
    if (limit !== this.limit) {
      this.limit = limit;
      if (!first) this.poll(true);
    }
    // The hash holds the last query that parsed; a bar holding a query with an error is left alone.
    if (first || q !== this.goodText) {
      if (this.bar) this.bar.setValue(q);
      this.applyQuery(q, { fromRoute: true });
    } else if (changed) {
      this.recompute();
    }
    if (sel !== this.selId) {
      if (sel) {
        this.wantSel = sel;
        this.selId = sel;
        this.tryOpenWanted();
      } else if (this.detail) {
        this.ctx.ui.closePanel();
      }
    }
    this.renderHeader();
  }

  /** Every URL parameter of this view, from the current state. */
  params(extra = {}) {
    const out = {};
    if (this.goodText) out.q = this.goodText;
    if (this.sort !== 'dur') out.sort = this.sort;
    if (this.limit !== DEFAULT_LIMIT) out.limit = this.limit;
    if (this.showBackups) out.backups = 'show';
    if (this.selId) out.sel = this.selId;
    return { ...out, ...extra };
  }

  saveRoute(push = false) {
    this.ctx.setParams(this.params(), { replace: !push });
  }

  // ---- layout ----------------------------------------------------------------------------------

  build() {
    const { h } = this;
    const { icon } = this.ctx.dom;
    this.el.classList.add('view-fill', 'sx-view');

    // head: title, read-as line, live controls
    this.sub = h('p', { class: 'view-sub' }, 'Reading the session table…');
    this.livePill = h('button', { class: 'live-pill', type: 'button', on: { click: () => this.togglePause() } });
    this.intervalSeg = h('div', { class: 'seg sx-every', role: 'group', 'aria-label': 'Poll interval' });
    this.refreshBtn = h('button', { class: 'btn', type: 'button', title: 'Read the session table now (r)', on: { click: () => this.poll(true) } }, icon('refresh'), h('span', { class: 'sx-hide-sm' }, 'Refresh'));
    const head = h(
      'div',
      { class: 'view-head sx-head' },
      h('div', { class: 'sx-titles' }, h('h1', { class: 'view-title' }, 'Sessions'), this.sub),
      h('div', { class: 'view-actions sx-live' }, this.livePill, this.intervalSeg, this.refreshBtn),
    );

    // strip: gauge, sessions per poll, new / ended / listed / shown, last read
    this.gauge = new Gauge({ size: 76, stroke: 7, label: 'Active sessions of the device maximum' });
    this.spark = new Sparkline({ height: 34, label: 'Matching sessions per poll' });
    this.activeNum = h('span', { class: 'sx-big num' }, DASH);
    this.activeOf = h('span', { class: 'sx-of' }, '');
    this.sparkRange = h('span', { class: 'sx-cap-meta num' }, '');
    this.statNew = h('b', { class: 'num' }, DASH);
    this.statEnded = h('b', { class: 'num' }, DASH);
    this.statListed = h('b', { class: 'num' }, DASH);
    // "137 listed", plus "· 60 shown" only when the browser-side filter keeps fewer rows.
    this.statShown = h('em', { class: 'sx-shown num', hidden: true }, '');
    this.readTime = h('span', { class: 'sx-read-t num' }, DASH);
    this.readAgo = h('span', { class: 'sx-read-ago' }, '');
    this.nextBar = h('i', { class: 'sx-next-i' });
    const stat = (cls, el, label, title, extra = null) => h('div', { class: ['sx-stat', cls], title }, h('span', { class: 'sx-stat-v' }, el, extra), h('span', { class: 'sx-stat-l' }, label));
    this.strip = h(
      'section',
      { class: 'sx-strip', 'aria-label': 'Session table summary' },
      h(
        'div',
        { class: 'sx-gauge' },
        this.gauge.el,
        h('div', { class: 'sx-gfig' }, h('span', { class: 'sx-cap' }, 'Active sessions'), this.activeNum, this.activeOf),
      ),
      h(
        'div',
        { class: 'sx-trend' },
        h('div', { class: 'sx-cap-row' }, h('span', { class: 'sx-cap' }, 'Matching, per poll'), this.sparkRange),
        this.spark.el,
      ),
      h(
        'div',
        { class: 'sx-stats' },
        stat('up', this.statNew, 'new', 'Sessions in this poll that were not in the previous one'),
        stat('down', this.statEnded, 'ended', 'Sessions in the previous poll that are gone now'),
        stat('listed', this.statListed, 'listed', 'Rows the device returned for the device-side filters (and, when the browser-side filter keeps fewer, how many are shown)', this.statShown),
      ),
      h('div', { class: 'sx-read' }, h('span', { class: 'sx-cap' }, 'Last read'), this.readTime, this.readAgo),
      h('div', { class: 'sx-next', 'aria-hidden': 'true' }, this.nextBar),
    );

    // query bar
    const QB = this.ctx.QueryBar;
    this.qbHost = h('div', { class: 'sx-qb' });
    if (QB && this.q) {
      this.bar = new QB({
        view: 'sessions',
        placeholder: 'Filter sessions: dport:443 src:10.10.0.0/16 policy:allow-web bytes>1M -app:junos-dns-udp',
        value: '',
        onChange: (text) => this.applyQuery(text, {}),
        getContext: () => ({ rows: this.current, inventory: this.ctx.store.lastInventory }),
      });
      this.qbHost.append(this.bar.el);
    }

    // notices and the grid toolbar
    this.notices = h('div', { class: 'sx-notices', role: 'status' });
    this.holdBtn = h(
      'button',
      { class: 'btn sm', type: 'button', 'aria-pressed': 'false', title: 'Stop live re-sorting so rows do not move; new rows go on top', on: { click: () => this.toggleHold() } },
      icon('pause'),
      'Hold order',
    );
    this.sortNote = h('span', { class: 'sx-sortnote' }, '');
    this.facetBtn = h('button', { class: 'btn sm', type: 'button', 'aria-pressed': 'false', 'aria-controls': 'sx-facets', title: 'Top values of the current result (click a bar to filter)', on: { click: () => this.toggleFacets() } }, icon('filter'), 'Facets');
    this.colBtn = h('button', { class: 'btn sm', type: 'button', 'aria-haspopup': 'true', 'aria-expanded': 'false', on: { click: () => this.openColumnsMenu() } }, icon('grid'), h('span', { class: 'sx-hide-sm' }, 'Columns'));
    this.exportBtn = h('button', { class: 'btn sm', type: 'button', 'aria-haspopup': 'true', 'aria-expanded': 'false', title: 'Download the rows on screen (made in the browser, no new device read)', on: { click: () => this.openExportMenu() } }, icon('download'), h('span', { class: 'sx-hide-sm' }, 'Export'));
    this.sortBtn = h('button', { class: 'btn sm sx-sortmenu-btn', type: 'button', 'aria-haspopup': 'true', 'aria-expanded': 'false', on: { click: () => this.openSortMenu() } }, icon('rows'), 'Sort');
    // A stale chip while reads fail (the table keeps the last good read), and one faint line when a
    // column is hidden for a reason the operator should know.
    this.staleChip = h('span', { class: 'sx-stale', hidden: true, role: 'status' });
    this.toolNote = h('span', { class: 'sx-toolnote', hidden: true });
    this.tools = h('div', { class: 'sx-tools' }, this.holdBtn, this.sortNote, this.staleChip, this.toolNote, h('span', { class: 'spacer' }), this.sortBtn, this.facetBtn, this.colBtn, this.exportBtn);
    const tools = this.tools;

    // grid
    this.gridHead = h('div', { class: 'sx-hrow', role: 'row', 'aria-rowindex': '1' });
    // The scroller takes focus only when the focused row leaves the table (tabindex -1): the rows
    // themselves are the Tab stop (roving tabindex).
    this.scroller = h('div', { class: 'sx-scroll', tabindex: '-1' }, h('div', { class: 'sx-headwrap', role: 'rowgroup' }, this.gridHead));
    this.skel = h('div', { class: 'sx-skel', hidden: true, 'aria-hidden': 'true' });
    this.grid = h('div', { class: 'sx-grid', role: 'grid', 'aria-label': 'Flow sessions', 'aria-rowcount': '1', 'aria-colcount': '1', 'aria-describedby': 'sx-grid-keys' }, this.scroller, h('p', { class: 'sr-only', id: 'sx-grid-keys' }, 'Arrow keys, Page Up, Page Down, Home and End move between sessions; Enter opens one. Right and Left arrows move through the values of a row; Enter filters by the value, Alt+Enter excludes it.'));
    this.gridState = h('div', { class: 'sx-gstate', hidden: true });
    this.hov = h(
      'div',
      { class: 'sx-hov', hidden: true, on: { pointerenter: () => this.keepHover(), pointerleave: () => this.hideHover(true) } },
      h('button', { class: 'sx-hov-b', type: 'button', tabindex: '-1', title: 'Filter by this value', dataset: { act: 'eq' }, on: { click: (e) => this.hoverAct(e, false) } }, '='),
      h('button', { class: 'sx-hov-b', type: 'button', tabindex: '-1', title: 'Exclude this value', dataset: { act: 'ne' }, on: { click: (e) => this.hoverAct(e, true) } }, '≠'),
      h('button', { class: 'sx-hov-b go', type: 'button', tabindex: '-1', title: 'Open this policy', dataset: { act: 'go' }, on: { click: (e) => this.hoverGo(e) } }, '↗'),
    );
    this.gridCard = h('section', { class: 'sx-gridcard', 'aria-label': 'Sessions table' }, this.grid, this.gridState, this.hov);
    this.facets = h('aside', { class: 'sx-facets', id: 'sx-facets', 'aria-label': 'Facets' });
    this.body = h('div', { class: 'sx-body' }, this.gridCard, this.facets);

    this.el.append(head, this.strip, this.qbHost, this.notices, tools, this.body);

    this.list = new RowWindow({
      container: this.scroller,
      rowHeight: this.rowHeight(),
      overscan: 6,
      keyOf: (i) => (this.rows[i] ? this.rows[i].id : `#${i}`),
      create: (i) => this.createRow(i),
      patch: (node, i) => this.patchRow(node, i),
      onWindow: (w) => this.chooseTabRow(w),
    });
    this.list.indexOf = (key) => (this.indexById.has(key) ? this.indexById.get(key) : -1);
    this.list.onFocusLost = () => {
      // The focused session left the table: keep the keyboard in the grid without landing on
      // (and so acting on) a session the operator did not choose.
      if (!this.dead && this.scroller.isConnected) this.scroller.focus({ preventScroll: true });
    };
    this.scroller.append(this.skel);
    this.scroller.addEventListener('click', (e) => this.onGridClick(e));
    this.scroller.addEventListener('dblclick', (e) => this.onGridDblClick(e));
    this.scroller.addEventListener('pointerover', (e) => this.onGridOver(e));
    this.scroller.addEventListener('pointerleave', () => this.hideHover(true));
    this.scroller.addEventListener('pointermove', (e) => {
      this.pointer = { x: e.clientX, y: e.clientY };
    }, { passive: true });
    this.scroller.addEventListener('scroll', () => this.hideHover(false), { passive: true });
    this.scroller.addEventListener('keydown', (e) => this.onGridKey(e));
    this.gridHead.addEventListener('click', (e) => this.onHeadClick(e));

    const fit = this.ctx.dom.rafBatch(() => this.fitColumns());
    // The card width comes from the observer, so a poll never has to read layout to fit columns.
    this.ro = typeof ResizeObserver === 'function'
      ? new ResizeObserver((entries) => {
        for (const e of entries) if (e.contentRect && e.contentRect.width) this.cardW = e.contentRect.width;
        fit();
      })
      : null;
    if (this.ro) this.ro.observe(this.gridCard);
    this.fitColumns();
    this.renderLive();
    this.renderInterval();
    this.renderFacetsToggle();
    this.renderStrip();
  }

  rowHeight() {
    if (this.mobile) return document.documentElement.dataset.density === 'comfortable' ? 78 : 70;
    const v = parseFloat(getComputedStyle(document.documentElement).getPropertyValue('--row-h'));
    return Number.isFinite(v) && v > 12 ? v + 2 : 28;
  }

  fitRows() {
    if (this.list) this.list.setRowHeight(this.rowHeight());
  }

  // ---- columns ---------------------------------------------------------------------------------

  readCols() {
    const raw = prefGet(PREF.cols);
    if (!raw) return null;
    const ids = raw.split(',').filter((id) => COL_BY_ID.has(id) && id !== 'status');
    return ids.length ? ids : null;
  }

  available(col) {
    if (col.onlyWith === 'location') return this.hasLocation;
    if (col.onlyWith === 'zones') return this.zoneState().ok !== false;
    return true;
  }

  /**
   * Whether zones can be known: they come only from the policy -> zone map of the inventory.
   * {ok: true} | {ok: null, why: 'loading'} | {ok: false, why: 'denied'|'failed'|'unsupported', message}
   */
  zoneState() {
    const snap = this.ctx.store.lastInventory;
    if (!snap) {
      const err = this.ctx.store.inventoryError;
      return err ? { ok: false, why: err.status === 403 ? 'denied' : 'failed', message: err.message } : { ok: null, why: 'loading' };
    }
    const pol = snap.scope && snap.scope.policies;
    if (pol && pol.status === 'ok') return { ok: true };
    const st = (pol && pol.status) || (snap.config && snap.config.status) || 'failed';
    return { ok: false, why: st === 'denied' || st === 'unsupported' ? st : 'failed', message: (pol && pol.message) || (snap.config && snap.config.message) || null };
  }

  /** Width of a monospace character in the rows (measured once; 6.9 px at 11.5 px). */
  charWidth() {
    if (this.charW) return this.charW;
    const probe = this.h('span', { class: 'sx-row sx-probe', 'aria-hidden': 'true' }, '0123456789'.repeat(4));
    this.grid.append(probe);
    const w = probe.getBoundingClientRect().width / 40;
    probe.remove();
    if (!(w > 3 && w < 20)) return 6.9; // not laid out yet (detached): measure again next time
    this.charW = w;
    return w;
  }

  /** The zones column fits the longest "from → to" of the policies in the inventory. */
  zonesWidth() {
    const idx = this.ctx.store.policyIndex();
    let n = 13; // "untrust→trust"
    const txt = (zs) => (zs.length ? (zs.length === 1 ? zs[0] : `${zs[0]} +${zs.length - 1}`) : 'any');
    for (const p of idx.values()) n = Math.max(n, txt(p.from || []).length + txt(p.to || []).length);
    return Math.ceil(Math.min(220, Math.max(72, n * this.charWidth() + 10 + 15)));
  }

  fitColumns() {
    if (this.dead) return;
    const width = this.cardW || this.gridCard.clientWidth || 1000;
    if (!this.cardW && this.gridCard.clientWidth) this.cardW = this.gridCard.clientWidth;
    const mobile = width < MOBILE_W;
    const modeChanged = mobile !== this.mobile;
    this.mobile = mobile;
    this.grid.classList.toggle('sx-mobile', mobile);
    this.el.classList.toggle('sx-is-mobile', mobile);
    if (modeChanged && !this.facetsTouched && this.facetBtn) {
      this.facetsOpen = !mobile; // phones: facets on request, the table first
      this.renderFacetsToggle();
    }
    const zw = this.zonesWidth();
    const widthOf = (c) => (c.id === 'zones' ? zw : c.w);
    let cols;
    if (this.manualCols) {
      cols = COLUMNS.filter((c) => c.fixed || (this.manualCols.includes(c.id) && this.available(c)));
    } else {
      const avail = width - 2;
      const candidates = COLUMNS.filter((c) => this.available(c)).slice().sort((a, b) => a.prio - b.prio);
      const pick = new Set();
      let total = 0;
      // Strict priority: the first column that does not fit ends the list, so a less important
      // narrow column never shows while a more important wide one is hidden.
      for (const c of candidates) {
        if (!c.fixed && total + widthOf(c) > avail && pick.size >= 5) break;
        pick.add(c.id);
        total += widthOf(c);
      }
      cols = COLUMNS.filter((c) => pick.has(c.id));
    }
    // The zones column is hidden when zones cannot be known; say why, once, in the toolbar.
    const zs = this.zoneState();
    const zonesWanted = !this.manualCols || this.manualCols.includes('zones');
    if (zs.ok === false && zonesWanted && !mobile) {
      this.toolNote.textContent = zs.why === 'denied'
        ? 'Zones hidden: your login class cannot read the policy configuration they come from.'
        : 'Zones hidden: the policy configuration they come from could not be read.';
      this.toolNote.hidden = false;
    } else {
      this.toolNote.hidden = true;
    }
    const key = `${cols.map((c) => c.id).join(',')}|${zw}`;
    if (key !== this.colKey || modeChanged) {
      this.colKey = key;
      this.cols = cols;
      const tpl = cols.map((c) => (c.fr ? `minmax(${widthOf(c)}px, ${c.fr}fr)` : `${widthOf(c)}px`)).join(' ');
      const min = cols.reduce((n, c) => n + widthOf(c), 0);
      this.grid.style.setProperty('--sx-cols', tpl);
      this.grid.style.setProperty('--sx-min', `${mobile ? 0 : min}px`);
      this.grid.setAttribute('aria-colcount', String(mobile ? 1 : cols.length));
      this.renderHeader();
      if (modeChanged) this.list.setRowHeight(this.rowHeight());
      this.list.reset();
      this.list.sync(true);
      this.renderSkeleton();
    }
  }

  setManualCols(ids) {
    this.manualCols = ids;
    prefSet(PREF.cols, ids ? ids.join(',') : null);
    this.colKey = null;
    this.fitColumns();
  }

  renderHeader() {
    if (!this.gridHead) return;
    const { h } = this;
    const [skey, dir] = this.sort.startsWith('-') ? [this.sort.slice(1), 'descending'] : [this.sort, 'ascending'];
    const cells = this.cols.map((c, i) => {
      const sorted = c.sort && c.sort === skey;
      const attrs = { class: ['sx-hc', `c-${c.id}`, c.num && 'num-col', sorted && 'sorted'], role: 'columnheader', 'aria-colindex': String(i + 1), title: c.title || null };
      if (c.sort) attrs['aria-sort'] = sorted ? dir : 'none';
      if (!c.sort) return h('div', attrs, h('span', { class: 'sr-only' }, c.title || c.label));
      return h(
        'div',
        attrs,
        h(
          'button',
          { class: 'sx-sortbtn', type: 'button', dataset: { sort: c.sort }, title: `${c.title || c.label}: sort${sorted ? (dir === 'ascending' ? ' descending' : ' ascending') : ''}` },
          h('span', null, c.label),
          h('span', { class: 'sx-sortmark', 'aria-hidden': 'true' }, sorted ? (dir === 'ascending' ? '▲' : '▼') : ''),
        ),
      );
    });
    if (this.mobile) {
      cells.length = 0;
      cells.push(h('div', { class: 'sx-hc sx-mhead', role: 'columnheader', 'aria-colindex': '1' }, 'Sessions', h('span', { class: 'faint' }, `\u00a0· sorted ${SORT_LABEL[this.sort] || `by ${(COL_BY_ID.get(skey) || {}).label || skey}${dir === 'descending' ? ' ▼' : ' ▲'}`}`)));
    }
    this.gridHead.replaceChildren(...cells);
    this.sortNote.textContent = `Sorted: ${SORT_LABEL[this.sort] || `${(COL_BY_ID.get(skey) || {}).label || skey} ${dir === 'descending' ? '▼' : '▲'}`}${this.hold ? ' · order held' : ''}`;
  }

  onHeadClick(e) {
    const btn = e.target instanceof Element ? e.target.closest('.sx-sortbtn') : null;
    if (!btn) return;
    const key = btn.dataset.sort;
    const cur = this.sort.replace(/^-/, '');
    const numeric = (COLUMNS.find((c) => c.sort === key) || {}).num;
    let next;
    if (cur === key) next = this.sort.startsWith('-') ? key : `-${key}`;
    else next = numeric && key !== 'dur' && key !== 'timeout' && key !== 'id' ? `-${key}` : key;
    this.sort = next;
    this.order.clear();
    this.saveRoute(false);
    this.renderHeader();
    this.recompute({ facets: false });
  }

  // ---- query -----------------------------------------------------------------------------------

  applyQuery(text, { push = false, fromRoute = false } = {}) {
    this.text = String(text || '');
    if (!this.q) return;
    const parsed = this.q.parse(this.text, { view: 'sessions' });
    if (parsed.error) {
      // The table keeps the last good filter: keep its chips visible (marked "still applied") and
      // keep the hash on it, so a reload or a shared link shows what the table shows.
      this.queryError = parsed.error;
      this.renderPlan();
      this.renderNotices();
      return;
    }
    this.queryError = null;
    this.serverError = null;
    if (this.bar) this.bar.setError(null);
    this.goodText = this.text;
    this.ast = parsed.ast;
    this.plan = this.q.plan(parsed.ast, 'sessions');
    this.compileBrowser();
    const key = JSON.stringify(this.plan.device || {});
    if (!fromRoute) this.saveRoute(push);
    if (key !== this.deviceKey) {
      this.device = { ...(this.plan.device || {}) };
      this.deviceKey = key;
      this.resetDiff();
      if (!this.dead && this.list && !this.booting) this.poll(true);
    }
    this.recompute();
  }

  compileBrowser() {
    if (!this.q) return;
    const c = { policyIndex: this.ctx.store.policyIndex(), inventory: this.ctx.store.lastInventory };
    const F = this.q.FIELDS.sessions;
    // Zone keys read the policy -> zone map of the inventory. Without it every zone is unknown, so
    // zone terms are not evaluated at all (a negated one would otherwise keep every session).
    let browser = this.plan ? this.plan.browser : null;
    let all = this.ast || null;
    this.zoneIgnored = [];
    this.zoneIgnoredTop = new Set();
    if (this.zoneState().ok !== true && (this.hasZoneTerm(browser) || this.hasZoneTerm(all))) {
      const items = browser ? (browser.type === 'and' ? browser.items : [browser]) : [];
      const keptItems = [];
      for (const it of items) {
        const pruned = this.pruneZones(it);
        if (pruned === it) keptItems.push(it);
        else {
          const text = this.q.toQueryString(it);
          if (pruned === null) {
            this.zoneIgnored.push(text);
            this.zoneIgnoredTop.add(text);
          } else {
            keptItems.push(pruned);
            this.zoneIgnored.push(...this.zoneTerms(it));
          }
        }
      }
      browser = keptItems.length === 0 ? null : keptItems.length === 1 ? keptItems[0] : { type: 'and', items: keptItems };
      all = all ? this.pruneZones(all) : null;
    }
    this.matchBrowser = browser ? this.q.compile(browser, F, c) : () => true;
    this.browserActive = Boolean(browser);
    // While the device re-reads for a new device filter, the old rows are shown through the whole
    // query (device terms included), dimmed, so the table answers at once and never lies.
    this.matchAll = all ? this.q.compile(all, F, c) : () => true;
    this.match = this.stale ? this.matchAll : this.matchBrowser;
    this.renderPlan();
  }

  hasZoneTerm(node) {
    if (!node) return false;
    if (node.type === 'and' || node.type === 'or') return node.items.some((n) => this.hasZoneTerm(n));
    if (node.type === 'not') return this.hasZoneTerm(node.item);
    return node.type === 'term' && Boolean(node.key) && ZONE_KEYS.has(this.keyName(node.key));
  }

  /** The AST without zone terms (null when nothing is left to evaluate). Unknown inside OR or NOT is unknown. */
  pruneZones(node) {
    if (!node || !this.hasZoneTerm(node)) return node;
    if (node.type === 'term') return null;
    if (node.type === 'not') return null;
    if (node.type === 'or') return null;
    const kept = node.items.map((n) => this.pruneZones(n)).filter(Boolean);
    return kept.length === 0 ? null : kept.length === 1 ? kept[0] : { ...node, items: kept };
  }

  /** The zone parts of an item, as typed: "zone:dmz", "-from:trust", "(zone:a OR zone:b)". */
  zoneTerms(node) {
    if (!node || !this.hasZoneTerm(node)) return [];
    if (node.type === 'and') return node.items.flatMap((n) => this.zoneTerms(n));
    return [this.q.toQueryString(node)];
  }

  /** Chips and the explain sentence under the bar: the applied plan, its zone terms marked when they cannot be evaluated. */
  renderPlan() {
    if (!this.bar) return;
    this.qbHost.classList.toggle('sx-qb-stale', Boolean(this.queryError));
    if (!this.plan || !this.ast) {
      this.bar.setPlan(null);
      return;
    }
    const ignored = this.zoneIgnoredTop || new Set();
    const explain = this.plan.explain.map((e) => {
      const out = { ...e };
      if (ignored.has(e.text)) out.where = 'ignored'; // neither device nor browser: not applied
      if (this.queryError) {
        // Positions point into the last good text, not the one in the bar: no remove buttons.
        delete out.pos;
        delete out.end;
      }
      return out;
    });
    this.bar.setPlan({ ...this.plan, explain });
    // QueryBar draws chips for "device" and "browser" only: label the other ones here.
    for (const chip of this.bar.el.querySelectorAll('.qb-chip')) {
      const t = chip.querySelector('.qb-chip-text');
      const w = chip.querySelector('.qb-chip-where');
      const off = t && ignored.has(t.textContent);
      chip.classList.toggle('sx-chip-off', Boolean(off));
      if (off && w) {
        w.textContent = 'not applied';
        chip.title = 'Zone filters need the policy configuration (zones come from the policy each session matched); it is not available, so this term is not evaluated.';
      }
      chip.classList.toggle('sx-chip-still', Boolean(this.queryError));
      if (this.queryError) chip.title = `Still applied: the query in the bar has an error, so the table keeps this filter. ${chip.title || ''}`.trim();
    }
  }

  /** Add key:value (or -key:value) to the query, as clicking a value does. */
  addTerm(key, value, exclude = false) {
    if (!this.q || value === null || value === undefined || value === '') return;
    const term = `${exclude ? '-' : ''}${key}:${qv(value)}`;
    const opposite = `${exclude ? '' : '-'}${key}:${qv(value)}`;
    // While the bar holds a query with an error, a click builds on the filter actually applied.
    let text = (this.queryError ? this.goodText : this.text).trim();
    const parsed = this.q.parse(text, { view: 'sessions' });
    if (parsed.ast) {
      const items = parsed.ast.type === 'and' ? parsed.ast.items : [parsed.ast];
      const strs = items.map((it) => (it.type === 'or' ? `(${this.q.toQueryString(it)})` : this.q.toQueryString(it)));
      if (strs.includes(term)) {
        this.ctx.ui.toast(`Already filtering by ${term}.`, 'info');
        return;
      }
      const oi = strs.indexOf(opposite);
      if (oi >= 0) text = strs.filter((_, i) => i !== oi).join(' ');
      else if (parsed.ast.type === 'or') text = `(${text})`;
    }
    text = text ? `${text} ${term}` : term;
    if (this.bar) this.bar.setValue(text);
    this.applyQuery(text, { push: true });
    const where = this.plan && this.plan.device && Object.keys(this.plan.device).length && /^(src|dst|sport|dport|proto|app|iface)$/.test(key) && !exclude ? ' (device filter: a new read)' : '';
    this.ctx.ui.announce(`Filter ${term} added${where}.`);
  }

  // ---- polling ---------------------------------------------------------------------------------

  intervalS() {
    const meta = (this.payload && this.payload.meta) || {};
    const min = Number(meta.min_interval_s) || 0;
    const base = this.every || Number(meta.suggested_interval_s) || 5;
    return Math.max(base, min);
  }

  async poll(force = false) {
    clearTimeout(this.timer);
    this.timer = 0;
    if (this.dead) return;
    if (this.ctx.store.scope !== 'root') {
      this.renderAll();
      this.renderLive();
      return;
    }
    if (this.paused && !force) return;
    if (this.inflight) {
      // A new device filter supersedes the read in flight.
      if (this.inflight.key === this.deviceKey && !force) return;
      this.inflight.abort();
    }
    const params = { scope: 'root', ...this.device };
    if (this.limit !== DEFAULT_LIMIT) params.limit = String(this.limit);
    const ctl = new AbortController();
    ctl.key = this.deviceKey;
    this.inflight = ctl;
    const seq = (this.pollSeq += 1);
    const key = this.deviceKey;
    this.strip.classList.add('reading');
    const res = await this.ctx.api.get('/api/sessions', params, { signal: ctl.signal });
    if (this.inflight === ctl) this.inflight = null;
    if (this.dead || res.aborted || seq !== this.pollSeq) return;
    this.strip.classList.remove('reading');
    if (res.status === 401) return; // the shell returns to sign-in
    let wait = this.intervalS() * 1000;
    if (res.ok) {
      this.failure = null;
      if (key === this.deviceKey) this.apply(res.data);
      const st = res.data && res.data.sessions && res.data.sessions.status;
      // A login class that may not list sessions, or a device that cannot, will not change by asking
      // again every few seconds (and each ask is a logged RPC): stop until the operator refreshes.
      this.halted = st === 'denied' || st === 'unsupported' ? st : null;
      if (this.halted) this.renderLive();
    } else if (res.status === 429) {
      wait = Math.max(wait, (res.retryAfter || 2) * 1000);
    } else if (res.status === 400) {
      // The server refused a filter value (its validation is the contract): show it under the bar.
      this.serverError = (res.data && res.data.error) || 'The device filter was not accepted.';
      if (this.bar) this.bar.setError(this.serverError);
      this.renderAll();
      return; // no retry until the query changes
    } else {
      this.failure = {
        status: res.status === 0 ? 'offline' : 'failed',
        message: (res.data && res.data.error) || `The session read failed (HTTP ${res.status}).`,
        at: Date.now(),
      };
      wait = Math.max(wait, 15000);
      this.renderAll();
    }
    this.schedule(wait);
  }

  schedule(wait = this.intervalS() * 1000) {
    clearTimeout(this.timer);
    this.timer = 0;
    if (this.dead || this.paused || this.halted || this.ctx.store.scope !== 'root' || this.serverError) {
      this.nextAt = 0;
      this.renderNext();
      return;
    }
    this.nextAt = Date.now() + wait;
    this.timer = setTimeout(() => this.poll(false), wait);
    this.renderNext(wait);
  }

  togglePause() {
    this.paused = !this.paused;
    this.renderLive();
    this.ctx.ui.announce(this.paused ? 'Sessions paused.' : 'Sessions live.');
    if (this.paused) {
      clearTimeout(this.timer);
      this.timer = 0;
      this.nextAt = 0;
      this.renderNext();
    } else {
      this.poll(true);
    }
  }

  setEvery(s) {
    this.every = s;
    prefSet(PREF.every, s);
    this.renderInterval();
    this.renderLive();
    if (!this.paused) this.schedule();
  }

  resetDiff() {
    this.known.clear();
    this.ended.clear();
    this.prevIds = null;
    this.prevComplete = false;
    this.order.clear();
    this.history = [];
    this.stats = { added: null, ended: null };
    this.stale = Boolean(this.payload);
    this.match = this.stale ? this.matchAll || this.match : this.matchBrowser || this.match;
    this.grid.classList.toggle('stale', this.stale);
  }

  // ---- applying a poll -------------------------------------------------------------------------

  apply(data) {
    const ui = this.ctx.ui;
    ui.noteFixture(data.meta);
    this.ctx.store.setSessionsLast(data);
    const now = Date.now();
    this.payload = data;
    this.readAt = now;
    this.lastOkAt = now;
    this.polls += 1;
    if (this.stale) {
      this.stale = false;
      this.current = [];
      this.match = this.matchBrowser || this.match;
      this.grid.classList.remove('stale');
    }
    const table = data.sessions || {};
    const idx = this.ctx.store.policyIndex();

    if (table.status !== 'ok') {
      this.current = [];
      this.ended.clear();
      this.prevIds = null;
      this.prevComplete = false;
      this.stats = { added: null, ended: null };
    } else {
      const complete = !table.truncated;
      const reliable = complete && this.prevComplete && this.prevIds !== null;
      const ids = new Set();
      const rows = [];
      let hasLocation = false;
      for (const raw of table.rows || []) {
        if (!raw || raw.id === null || raw.id === undefined) continue;
        const id = String(raw.id);
        if (ids.has(id)) continue;
        ids.add(id);
        const a = raw.in || {};
        const b = raw.out || {};
        const bytes = sum(a.bytes, b.bytes);
        const pkts = sum(a.packets, b.packets);
        let k = this.known.get(id);
        if (!k) {
          k = { firstAt: now, lastBytes: null, lastAt: 0, hist: [], newAt: this.prevIds !== null && reliable ? now : 0, polls: 0 };
          this.known.set(id, k);
        }
        let rate = null;
        let live = false;
        if (k.lastBytes !== null && Number.isFinite(bytes) && now > k.lastAt) {
          rate = Math.max(0, (bytes - k.lastBytes) / ((now - k.lastAt) / 1000));
          live = true;
          k.hist.push(rate);
          if (k.hist.length > RATE_HISTORY) k.hist.shift();
        } else if (Number.isFinite(bytes) && Number(raw.duration) > 0) {
          rate = bytes / Number(raw.duration);
        }
        k.lastBytes = Number.isFinite(bytes) ? bytes : k.lastBytes;
        k.lastAt = now;
        k.polls += 1;
        if (raw.location) hasLocation = true;
        rows.push(this.viewModel(raw, { id, bytes, pkts, rate, live, k, idx }));
      }
      // Ended: in the previous poll, gone now (only when both lists were complete).
      for (const [id, r] of this.ended) if (r._endedPoll < this.polls) this.ended.delete(id);
      let endedNow = 0;
      if (reliable) {
        for (const prev of this.current) {
          if (ids.has(prev.id) || prev._ended) continue;
          this.ended.set(prev.id, { ...prev, _ended: now, _endedPoll: this.polls, rate: 0, _live: false });
          endedNow += 1;
        }
      }
      for (const id of this.known.keys()) if (!ids.has(id) && !this.ended.has(id)) this.known.delete(id);
      if (this.known.size > MAX_TRACKED) {
        for (const id of [...this.known.keys()].slice(0, this.known.size - MAX_TRACKED)) this.known.delete(id);
      }
      this.markBackups(rows);
      const added = rows.filter((r) => r._newAt === now).length;
      this.stats = reliable ? { added, ended: endedNow } : { added: null, ended: null };
      if (reliable && (added || endedNow)) {
        ui.announce(`${this.fmt.plural(added, 'new session')}, ${this.fmt.num(endedNow)} ended.`);
      }
      this.current = rows;
      this.prevIds = ids;
      this.prevComplete = complete;
      if (hasLocation !== Boolean(this.hasLocation)) {
        this.hasLocation = hasLocation;
        this.colKey = null; // the node column appears only when rows carry a location
      }
    }
    const matching = Number.isFinite(data.matching) ? data.matching : table.status === 'ok' ? (table.rows || []).length : null;
    if (matching !== null) {
      this.history.push(matching);
      if (this.history.length > POLL_HISTORY) this.history.shift();
    }
    if (this.colKey === null) this.fitColumns();
    this.recompute();
    this.renderAll();
    this.tryOpenWanted();
    if (this.detail) this.detail.update();
  }

  zonesOf(policy, idx) {
    if (!policy || !idx) return null;
    // One shared object per policy and inventory (rows of the same policy have the same zones).
    if (this.zoneCacheFor !== idx) {
      this.zoneCacheFor = idx;
      this.zoneCache = new Map();
    }
    if (this.zoneCache.has(policy)) return this.zoneCache.get(policy);
    const z = this.zonesFromIndex(policy, idx);
    this.zoneCache.set(policy, z);
    return z;
  }

  zonesFromIndex(policy, idx) {
    const p = idx.get(policy);
    if (!p) return null;
    const from = p.from || [];
    const to = p.to || [];
    const txt = (zs) => (zs.length ? (zs.length === 1 ? zs[0] : `${zs[0]} +${zs.length - 1}`) : 'any');
    return {
      from: from.length === 1 ? from[0] : null,
      to: to.length === 1 ? to[0] : null,
      fromAll: from,
      toAll: to,
      fromText: txt(from),
      toText: txt(to),
      global: p.kind === 'global',
      ambiguous: Boolean(p.ambiguous),
      id: p.id,
    };
  }

  /** The row as the table uses it: the API row itself (fresh from this poll), annotated in place. */
  viewModel(raw, { id, bytes, pkts, rate, live, k, idx }) {
    const r = raw;
    r.id = id;
    r.rate = rate;
    r._live = live;
    r._bytes = bytes;
    r._pkts = pkts;
    r._newAt = k.newAt;
    r._firstAt = k.firstAt;
    r._zones = this.zonesOf(raw.policy, idx);
    r._role = haRole(raw);
    r._backup = false;
    return r;
  }

  /** On a chassis cluster each session is listed by both nodes; mark the backup copies. */
  markBackups(rows) {
    let count = 0;
    const bySid = new Map();
    for (const r of rows) {
      if (!r.location) continue;
      const list = bySid.get(r.session_id) || [];
      list.push(r);
      bySid.set(r.session_id, list);
    }
    for (const r of rows) {
      if (r._role === 'backup') {
        r._backup = true;
        r._backupWhy = 'the device marks this copy Backup';
      }
    }
    for (const list of bySid.values()) {
      if (list.length < 2 || list.some((r) => r._role)) continue;
      // No role field: a copy with zero counters next to one with traffic is the backup copy.
      const busy = list.filter((r) => (r._bytes || 0) > 0 || (r._pkts || 0) > 0);
      if (busy.length >= 1 && busy.length < list.length) {
        for (const r of list) {
          if (!busy.includes(r)) {
            r._backup = true;
            r._backupWhy = 'inferred: the same session on another node, with zero counters';
          }
        }
      }
    }
    for (const r of rows) if (r._backup) count += 1;
    this.backupCount = count;
  }

  // ---- filtering, sorting, facets --------------------------------------------------------------

  recompute({ facets = true } = {}) {
    if (!this.list) return;
    const keepBackups = this.showBackups;
    const rows = [];
    let listed = 0;
    let shown = 0;
    let maxRate = 0;
    const match = this.match;
    const take = (r) => {
      if (!keepBackups && r._backup) return;
      if (!r._ended) listed += 1;
      let ok = true;
      try {
        ok = match(r);
      } catch (_err) {
        ok = true;
      }
      if (!ok) return;
      rows.push(r);
      if (!r._ended) shown += 1;
      if (Number.isFinite(r.rate) && r.rate > maxRate) maxRate = r.rate;
    };
    for (const r of this.current) take(r);
    for (const r of this.ended.values()) take(r);
    const key = this.sort.replace(/^-/, '');
    const desc = this.sort.startsWith('-');
    const get = SORTS[key] || SORTS.dur;
    // Sort keys once per row, not once per comparison.
    for (const r of rows) {
      r._sk = get(r);
      r._tk = Number(r.session_id) || r.id;
    }
    const by = (a, b) => {
      const c = cmp(a._sk, b._sk);
      return (desc ? -c : c) || cmp(a._tk, b._tk);
    };
    let ordered = rows;
    if (this.hold && this.order.size) {
      const fresh = [];
      const kept = [];
      for (const r of rows) (this.order.has(r.id) ? kept : fresh).push(r);
      fresh.sort(by);
      kept.sort((a, b) => this.order.get(a.id) - this.order.get(b.id));
      ordered = fresh.concat(kept);
    } else {
      rows.sort(by);
    }
    this.order = new Map();
    this.indexById = this.order;
    for (let i = 0; i < ordered.length; i += 1) this.order.set(ordered[i].id, i);
    this.rows = ordered;
    this.listedCount = listed;
    this.shownCount = shown;
    this.maxRate = maxRate;
    this.grid.setAttribute('aria-rowcount', String(ordered.length + 1));
    this.list.setCount(ordered.length);
    this.list.sync(true);
    this.reshowHover();
    if (this.bar) {
      const ok = this.payload && this.payload.sessions && this.payload.sessions.status === 'ok';
      this.bar.setStatus(this.browserActive && ok ? `${this.fmt.num(this.shownCount)} of ${this.fmt.num(this.listedCount)}` : '');
    }
    if (facets) this.scheduleFacets();
    this.renderStats();
    this.renderGridState();
  }

  /**
   * Facets are recomputed in the next animation frame (a separate, short piece of work that paints
   * in the same frame as the rows), and only while the rail is shown.
   */
  scheduleFacets() {
    if (!this.facetsOpen || this.facetTimer) return;
    this.facetTimer = requestAnimationFrame(() => {
      this.facetTimer = 0;
      if (!this.dead) this.renderFacets();
    });
  }

  facetData() {
    const metric = this.metric;
    const aggs = FACETS.map(() => new Map());
    const missing = FACETS.map(() => 0);
    let total = 0;
    for (const r of this.rows) {
      if (r._ended) continue;
      total += 1;
      const w = metric === 'bytes' ? r._bytes || 0 : metric === 'rate' ? (r._live ? r.rate || 0 : 0) : 1;
      for (let fi = 0; fi < FACETS.length; fi += 1) {
        const f = FACETS[fi];
        const agg = aggs[fi];
        const v = f.get(r);
        const has = v !== null && v !== undefined && v !== '';
        if (has) agg.set(v, (agg.get(v) || 0) + w);
        if (f.get2) {
          const v2 = f.get2(r);
          if (v2 !== null && v2 !== undefined && v2 !== '' && v2 !== v) agg.set(v2, (agg.get(v2) || 0) + w);
          else if (!has && (v2 === null || v2 === undefined || v2 === '')) missing[fi] += 1;
        } else if (!has) {
          missing[fi] += 1;
        }
      }
    }
    return FACETS.map((f, fi) => {
      const agg = aggs[fi];
      const top = [...agg.entries()].sort((a, b) => b[1] - a[1] || cmp(a[0], b[0])).slice(0, 8);
      return { ...f, top, distinct: agg.size, missing: missing[fi], total };
    });
  }

  // ---- rendering: head, strip, notices ---------------------------------------------------------

  renderAll() {
    this.el.classList.toggle('sx-offscope', this.ctx.store.scope !== 'root');
    this.grid.classList.toggle('stale', Boolean(this.stale || this.failure));
    const staleSince = this.failure && this.payload && this.payload.meta ? this.payload.meta.read_at : null;
    this.staleChip.hidden = !staleSince;
    this.staleChip.textContent = staleSince ? `stale since ${this.fmt.time(staleSince)} UTC` : '';
    this.renderSub();
    this.renderStrip();
    this.renderNotices();
    this.renderGridState();
    this.renderLive();
  }

  renderSub() {
    const fmt = this.fmt;
    const snap = this.ctx.store.lastInventory;
    const dev = snap && snap.device && snap.device.status === 'ok' ? snap.device : null;
    const meta = this.payload && this.payload.meta;
    const user = (meta && meta.read_as && meta.read_as.user) || (this.ctx.store.session && this.ctx.store.session.user) || '';
    const root = this.ctx.store.scope === 'root';
    const parts = [dev && dev.hostname, root ? 'root system' : 'flow sessions are read for the root system', root && meta && `read ${fmt.time(meta.read_at)} UTC`, user && `as ${user}`].filter(Boolean);
    this.sub.textContent = parts.join(SEP);
  }

  renderLive() {
    const { h } = this;
    const scopeOk = this.ctx.store.scope === 'root';
    const stopped = Boolean(this.halted) || !scopeOk || Boolean(this.serverError);
    const running = !this.paused && !stopped;
    // What the pill says is what the view is doing: reading for the first time, retrying after a
    // failed read (every 15 s), live, paused or stopped.
    const mode = !running ? (stopped ? 'stopped' : 'paused') : this.failure ? 'retry' : !this.payload ? 'reading' : 'live';
    const s = this.intervalS();
    const sig = `${mode}|${s}|${this.halted}|${scopeOk}`;
    if (sig === this.liveSig) return;
    this.liveSig = sig;
    const text = { live: 'LIVE', reading: 'READING…', retry: 'RETRY', paused: 'PAUSED', stopped: 'STOPPED' }[mode];
    const sub = { live: `${s} s`, reading: '', retry: `${Math.max(RETRY_S, s)} s`, paused: 'space', stopped: this.halted || (scopeOk ? 'filter' : 'scope') }[mode];
    this.livePill.className = ['live-pill', mode !== 'live' && 'paused', mode === 'retry' && 'sx-retry', mode === 'reading' && 'sx-first'].filter(Boolean).join(' ');
    this.livePill.replaceChildren(...[h('span', { class: 'dot', 'aria-hidden': 'true' }), text, sub ? h('span', { class: 'sub' }, sub) : null].filter(Boolean));
    const label = {
      live: `Live: the session table is read every ${s} s. Pause (space).`,
      reading: 'Reading the session table for the first time. Pause (space).',
      retry: `The last read failed; J-Wicket tries again every ${Math.max(RETRY_S, s)} s. Pause (space).`,
      paused: 'Paused. Resume live updates (space).',
      stopped: 'Not reading: see the message below. Refresh (r) reads once more.',
    }[mode];
    this.livePill.setAttribute('aria-pressed', running ? 'false' : 'true');
    this.livePill.setAttribute('aria-label', label);
    this.livePill.title = label;
    this.ctx.ui.setLive('sessions', mode === 'live' || mode === 'reading');
  }

  renderInterval() {
    const { h } = this;
    const meta = (this.payload && this.payload.meta) || {};
    const min = Number(meta.min_interval_s) || 0;
    const cur = this.intervalS();
    const key = `${min}|${cur}|${meta.suggested_interval_s}`;
    if (key === this.intervalKey) return;
    this.intervalKey = key;
    this.intervalSeg.replaceChildren(
      ...INTERVALS.map((s) =>
        h(
          'button',
          {
            type: 'button',
            'aria-pressed': s === cur ? 'true' : 'false',
            disabled: s < min ? true : null,
            title: s < min ? `The device allows a read every ${min} s at most` : `Read every ${s} s${s === Number(meta.suggested_interval_s) ? ' (suggested: each read adds a line to the device log)' : ''}`,
            on: { click: () => this.setEvery(s) },
          },
          `${s}s`,
        ),
      ),
    );
  }

  renderNext(wait) {
    // The hairline under the strip fills until the next read (Web Animations: no forced layout).
    if (this.nextAnim) this.nextAnim.cancel();
    this.nextAnim = null;
    if (!wait || this.paused || typeof this.nextBar.animate !== 'function' || (REDUCED && REDUCED.matches)) return;
    this.nextAnim = this.nextBar.animate([{ transform: 'scaleX(0)' }, { transform: 'scaleX(1)' }], { duration: Math.max(200, wait), easing: 'linear', fill: 'forwards' });
  }

  renderStrip() {
    const fmt = this.fmt;
    const data = this.payload;
    const s = data && data.summary;
    if (s && s.status === 'ok' && Number.isFinite(s.active)) {
      this.gauge.update(s.active, s.max, { text: Number.isFinite(s.max) ? fmt.pct(s.active, s.max) : DASH, sub: '' });
      tick(this.activeNum, fmt.num(s.active));
      this.activeOf.textContent = Number.isFinite(s.max) ? `of ${fmt.num(s.max)} maximum` : 'maximum not reported';
      this.activeOf.title = '';
    } else {
      this.gauge.update(null, null, { text: DASH, sub: '' });
      this.activeNum.textContent = DASH;
      this.activeOf.textContent = s && s.status && s.status !== 'ok' ? `summary ${s.status}` : '';
      this.activeOf.title = (s && s.message) || '';
    }
    this.spark.update(this.history);
    if (this.history.length) {
      const lo = Math.min(...this.history);
      const hi = Math.max(...this.history);
      this.sparkRange.textContent = lo === hi ? fmt.num(lo) : `${fmt.num(lo)}–${fmt.num(hi)}`;
    } else {
      this.sparkRange.textContent = '';
    }
    this.renderStats();
    this.renderAge();
    this.renderInterval();
  }

  renderStats() {
    const fmt = this.fmt;
    const st = this.stats;
    const set = (el, text) => tick(el, text);
    set(this.statNew, st.added === null ? DASH : st.added ? `+${fmt.num(st.added)}` : '0');
    set(this.statEnded, st.ended === null ? DASH : st.ended ? `−${fmt.num(st.ended)}` : '0');
    // Gold is an event: only a real count of new sessions is gold, not a zero or an unknown.
    this.statNew.closest('.sx-stat').classList.toggle('hot', Boolean(st.added));
    const table = this.payload && this.payload.sessions;
    const ok = table && table.status === 'ok';
    const listed = ok ? this.listedCount ?? (table.rows || []).length : null;
    set(this.statListed, listed === null ? DASH : fmt.num(listed));
    const differs = ok && this.browserActive && this.shownCount !== listed;
    if (differs) set(this.statShown, `· ${fmt.num(this.shownCount)} shown`);
    this.statShown.hidden = !differs;
    this.statListed.closest('.sx-stat').classList.toggle('filtered', Boolean(differs));
  }

  renderAge() {
    if (!this.payload) return;
    this.readTime.textContent = `${this.fmt.time(this.payload.meta && this.payload.meta.read_at)} UTC`;
    const stale = this.failure ? ` · ${this.failure.status === 'offline' ? 'no answer' : 'read failed'}` : '';
    this.readAgo.textContent = `${this.fmt.ago(this.lastOkAt)}${stale}`;
    this.readAgo.classList.toggle('bad', Boolean(this.failure));
  }

  renderNotices() {
    const { h } = this;
    const { icon } = this.ctx.dom;
    const fmt = this.fmt;
    const out = [];
    const sig = [];
    const note = (cls, iconName, text, ...actions) => {
      sig.push(cls, text, actions.filter(Boolean).length);
      return h('div', { class: ['sx-note', cls] }, icon(iconName), h('span', { class: 'sx-note-t' }, text), ...actions);
    };
    const btn = (label, fn, fk) => h('button', { class: 'btn sm', type: 'button', dataset: { fk: fk || label }, on: { click: fn } }, label);
    if (this.queryError) {
      const still = this.goodText ? `Still showing: ${this.goodText}.` : 'Still showing every session.';
      out.push(note('warn', 'alert', `The query has an error (${String(this.queryError.message).replace(/\.$/, '')}). ${still}`));
    }
    if (this.zoneIgnored && this.zoneIgnored.length) {
      const zs = this.zoneState();
      const terms = this.zoneIgnored.join(', ');
      const text = zs.why === 'loading'
        ? `Reading the policy configuration: ${terms} ${this.zoneIgnored.length === 1 ? 'is' : 'are'} applied once it arrives (zones come from the policy each session matched).`
        : `Zone filters need the policy configuration, which ${zs.why === 'denied' ? 'your login class cannot read' : 'could not be read'}, so ${terms} ${this.zoneIgnored.length === 1 ? 'is' : 'are'} not applied. An interface filter (iface:…) narrows by zone on the device instead.`;
      out.push(note(zs.why === 'loading' ? 'info' : 'warn', 'zone', text));
    }
    // A failed read with an earlier one on screen: this banner (the table stays, dimmed). With
    // nothing read yet, the state card in place of the table says it once.
    if (this.failure && this.payload) {
      const when = ` Showing the read from ${fmt.time(this.payload.meta && this.payload.meta.read_at)} UTC.`;
      out.push(note('bad', this.failure.status === 'offline' ? 'wifi' : 'alert', `${this.failure.message}${when} Retrying every ${RETRY_S} s.`, btn('Retry now', () => this.poll(true), 'retry')));
    }
    const table = this.payload && this.payload.sessions;
    if (table && table.status === 'ok' && table.truncated) {
      const total = Number.isFinite(table.returned) ? table.returned : table.device_count;
      const more = this.limit < LIMITS[LIMITS.length - 1]
        ? btn(`Show up to ${fmt.num(LIMITS[LIMITS.length - 1])}`, () => {
          this.limit = LIMITS[LIMITS.length - 1];
          this.saveRoute(false);
          this.resetDiff();
          this.poll(true);
        })
        : null;
      out.push(note('warn', 'filter', `The device returned ${fmt.num(total)} sessions; J-Wicket kept the first ${fmt.num((table.rows || []).length)} (limit ${fmt.num(this.limit)}). New and ended are not tracked while the list is cut; narrow the query with a device filter.`, more));
    }
    if (this.backupCount && !this.showBackups) {
      out.push(note('info', 'cluster', `Chassis cluster: ${fmt.plural(this.backupCount, 'backup copy', 'backup copies')} hidden (every session is listed by both nodes).`, btn('Show backup copies', () => this.setBackups(true), 'backups')));
    } else if (this.backupCount && this.showBackups) {
      out.push(note('info', 'cluster', `Showing ${fmt.plural(this.backupCount, 'backup copy', 'backup copies')} next to the active ones.`, btn('Hide backup copies', () => this.setBackups(false), 'backups')));
    }
    // Rebuilt only when the text changes (a focused button inside survives every poll).
    const key = JSON.stringify(sig);
    if (key === this.sigs.notices) return;
    this.sigs.notices = key;
    swapKeepFocus(this.ctx.dom.put, this.notices, ...out);
    this.notices.hidden = !out.length;
  }

  setBackups(show) {
    this.showBackups = show;
    this.saveRoute(false);
    this.recompute();
    this.renderNotices();
  }

  toggleHold() {
    this.hold = !this.hold;
    this.holdBtn.setAttribute('aria-pressed', this.hold ? 'true' : 'false');
    this.ctx.ui.announce(this.hold ? 'Row order held: rows stay where they are; new rows go on top.' : 'Rows re-sort on every poll.');
    this.renderHeader();
    if (!this.hold) this.recompute({ facets: false });
  }

  // ---- rendering: explicit states in place of the grid -----------------------------------------

  renderGridState() {
    const { h } = this;
    const { stateCard } = this.ctx.dom;
    const fmt = this.fmt;
    const btn = (label, fn, cls = 'btn sm') => h('button', { class: cls, type: 'button', dataset: { fk: label }, on: { click: fn } }, label);
    let card = null;
    let sig = null;
    // solo: no table to show, so no table chrome (toolbar, facets, frame); hard: nothing on this
    // view can be read at all, so the strip and the query bar go too and the card leads the view.
    let solo = false;
    let hard = false;
    let loading = false;
    const table = this.payload && this.payload.sessions;
    const history = h(
      'button',
      { class: 'btn sm', type: 'button', dataset: { fk: 'history' }, title: 'Sessions that closed are in the traffic log (RT_FLOW) or the on-box report, in Logs', on: { click: () => this.ctx.navigate('logs', { source: 'report' }) } },
      this.ctx.dom.icon('logs'),
      'Session history: Logs → on-box report',
    );
    if (!this.q || !this.ctx.QueryBar) {
      sig = 'engine';
      solo = hard = true;
      card = () => stateCard({ status: 'failed', title: 'The query engine did not load', message: 'Reload the page. If it keeps failing, the J-Wicket build on this device may be incomplete.', hint: null });
    } else if (this.ctx.store.scope !== 'root') {
      sig = 'scope';
      solo = hard = true;
      card = () => stateCard({
        status: 'unsupported',
        title: 'Sessions are listed for the root system only',
        message: 'This release reads the session table of the whole device (Spec 004); logical and tenant systems are not separated yet.',
        hint: null,
        // The shell's scope switcher is the one control that changes scope (a hash without
        // scope=... does not return to root), so the button opens it.
        actions: [btn('Choose the root system', () => this.openScopeSwitcher()), history],
      });
    } else if (this.serverError) {
      sig = `server|${this.serverError}`;
      solo = true;
      card = () => stateCard({ status: 'failed', title: 'The device filter was not accepted', message: this.serverError, hint: 'Fix the value in the query; nothing is read until then.' });
    } else if (!this.payload || (table && table.status === 'loading')) {
      if (this.failure) {
        sig = `fail|${this.failure.status}|${this.failure.message}`;
        solo = true;
        card = () => stateCard({ status: this.failure.status, message: this.failure.message, hint: `J-Wicket tries again every ${RETRY_S} s.`, actions: [btn('Retry now', () => this.poll(true))] });
      } else {
        loading = true;
      }
    } else if (!table || table.status !== 'ok') {
      const st = (table && table.status) || 'failed';
      sig = `table|${st}|${table && table.message}|${st === 'refused' ? JSON.stringify([this.payload.matching, this.narrowing().map((s) => s.term), this.plan && this.plan.explain.map((e) => e.text)]) : ''}`;
      solo = true;
      hard = st === 'denied' || st === 'unsupported';
      card = () => this.stateFor(table || { status: 'failed' }, hard ? [history] : null);
    } else if (!this.rows.length) {
      const listed = this.listedCount || 0;
      if (listed && this.browserActive) {
        sig = `empty-browser|${listed}|${this.deviceSentence()}|${this.q.toQueryString(this.plan.browser)}`;
        card = () => stateCard({
          status: 'empty',
          title: 'No session matches the browser filter',
          message: `The device listed ${fmt.plural(listed, 'session')} for ${this.deviceSentence()}; none match ${this.q.toQueryString(this.plan.browser)}.`,
          actions: [btn('Clear the browser filter', () => this.clearBrowserPart())],
        });
      } else if (this.backupCount && !this.showBackups && this.current.length) {
        sig = 'empty-backups';
        card = () => stateCard({ status: 'empty', title: 'Only backup copies', message: 'Every listed row is a backup copy on the other cluster node.', actions: [btn('Show backup copies', () => this.setBackups(true))] });
      } else {
        sig = `empty|${this.deviceSentence()}`;
        card = () => stateCard({
          status: 'empty',
          title: Object.keys(this.device).length ? 'No session matches the device filter' : 'No active sessions',
          message: Object.keys(this.device).length ? `The device has no session for ${this.deviceSentence()}.` : 'The device listed no flow sessions in this poll.',
          hint: 'The table refreshes on its own while live.',
        });
      }
    }
    this.el.classList.toggle('sx-solo', solo);
    this.el.classList.toggle('sx-solo-hard', hard);
    this.el.classList.toggle('sx-nodata', !this.payload && !loading);
    if (sig !== this.sigs.state) {
      // Rebuilt only when what it says changes: a focused button inside survives every poll.
      this.sigs.state = sig;
      swapKeepFocus(this.ctx.dom.put, this.gridState, card ? card() : null);
    }
    this.gridState.hidden = !card;
    this.grid.hidden = Boolean(card);
    this.skel.hidden = !loading;
    if (loading && !this.skel.firstChild) this.renderSkeleton();
    this.exportBtn.disabled = !this.rows.length;
  }

  /** While nothing has been read: the real header and twelve rows shaped like the columns. */
  renderSkeleton() {
    if (!this.skel || this.skel.hidden) {
      if (this.skel) this.skel.replaceChildren();
      return;
    }
    const { h } = this;
    const widths = [70, 55, 85, 60, 75, 50, 90, 65];
    const rows = [];
    const rh = this.rowHeight();
    for (let i = 0; i < 12; i += 1) {
      const row = h('div', { class: ['sx-row', 'sx-skrow', this.mobile && 'm', i % 2 && 'odd'] });
      row.style.height = `${rh}px`;
      if (this.mobile) {
        const cell = h('div', { class: 'sx-c sx-mcell' });
        for (const [j, cls] of ['m-src', 'm-dst', 'm-meta'].entries()) {
          const b = h('span', { class: ['sk-line', cls] });
          b.style.width = `${widths[(i + j) % widths.length]}%`;
          cell.append(b);
        }
        row.append(cell);
      } else {
        for (const [ci, c] of this.cols.entries()) {
          const cell = h('div', { class: ['sx-c', `c-${c.id}`, c.num && 'num-col'] });
          if (c.id === 'status') cell.append(h('span', { class: 'sx-dot sk' }));
          else {
            const b = h('span', { class: 'sk-line' });
            b.style.width = `${widths[(i + ci) % widths.length]}%`;
            cell.append(b);
          }
          row.append(cell);
        }
      }
      rows.push(row);
    }
    this.skel.replaceChildren(...rows);
  }

  openScopeSwitcher() {
    const chip = document.getElementById('chip-scope');
    if (chip) chip.click();
    else this.ctx.navigate('sessions', { ...this.params(), scope: 'root' });
  }

  deviceSentence() {
    const entries = Object.entries(this.device);
    return entries.length ? entries.map(([k, v]) => `${k}=${v}`).join(', ') : 'the whole table';
  }

  clearBrowserPart() {
    if (!this.plan) return;
    const kept = this.plan.explain.filter((e) => e.where === 'device' && !e.refine).map((e) => e.text);
    const text = kept.join(' ');
    if (this.bar) this.bar.setValue(text);
    this.applyQuery(text, { push: true });
  }

  stateFor(table, extra = null) {
    const { h } = this;
    const { stateCard } = this.ctx.dom;
    const fmt = this.fmt;
    const status = table.status || 'failed';
    if (status === 'refused') {
      const matching = this.payload && Number.isFinite(this.payload.matching) ? this.payload.matching : null;
      const sugg = this.narrowing();
      const chips = sugg.map((s) =>
        h(
          'button',
          { class: 'sx-sugg', type: 'button', dataset: { fk: s.term }, title: `${s.why}. Adds ${s.term} to the query (filtered on the device).`, on: { click: () => this.addTerm(s.key, s.value, false) } },
          h('span', { class: 'sx-sugg-t' }, s.term),
          h('span', { class: 'sx-sugg-w' }, s.why),
        ),
      );
      const browserOnly = this.plan && this.plan.explain.filter((e) => e.where === 'browser').map((e) => e.text);
      return h(
        'div',
        { class: 'sx-refused' },
        stateCard({
          status: 'refused',
          title: matching !== null ? `${fmt.num(matching)} sessions match: too many to list in one go` : 'Too many sessions to list in one go',
          message: table.message ? String(table.message).replace(/^[\d,.\s]+sessions match\.\s*/i, '') : null,
          hint: browserOnly && browserOnly.length
            ? `${browserOnly.join(', ')} ${browserOnly.length === 1 ? 'is' : 'are'} filtered in the browser, after the device has listed the rows, so ${browserOnly.length === 1 ? 'it does' : 'they do'} not make the list shorter. Add a device filter: src, dst, sport, dport, proto, app or iface.`
            : 'Add a device filter (src, dst, sport, dport, proto, app or iface). Each one below narrows the read on the device itself.',
          actions: chips.length ? [h('div', { class: 'sx-suggs' }, chips)] : null,
        }),
      );
    }
    if (status === 'denied') {
      return stateCard({ status: 'denied', message: table.message, hint: 'Listing flow sessions needs the Junos view permission for security operational commands. J-Wicket reads as you and adds no rights.', actions: extra });
    }
    if (status === 'unsupported') {
      return stateCard({ status: 'unsupported', message: table.message, title: 'This device does not list flow sessions here', actions: extra });
    }
    return stateCard({ status: status === 'session-lost' ? 'session-lost' : 'failed', message: table.message, actions: [h('button', { class: 'btn sm', type: 'button', dataset: { fk: 'try' }, on: { click: () => this.poll(true) } }, 'Try again')] });
  }

  /** The canonical sessions key for a typed key or alias ("pol" -> "policy"). */
  keyName(key) {
    const F = (this.q && this.q.FIELDS.sessions) || {};
    const low = String(key).toLowerCase();
    for (const [name, def] of Object.entries(F)) if (name === low || (def.aliases || []).includes(low)) return name;
    return low;
  }

  /** One-click device filters that make a refused list shorter. */
  narrowing() {
    const out = [];
    const seen = new Set();
    const add = (key, value, why) => {
      const term = `${key}:${qv(value)}`;
      if (seen.has(term) || out.length >= 8 || (this.device && this.device[key] !== undefined)) return;
      seen.add(term);
      out.push({ key, value: String(value), term, why });
    };
    const snap = this.ctx.store.lastInventory;
    const zones = (snap && snap.scope && snap.scope.zones && snap.scope.zones.rows) || [];
    const ifaceOf = (zone) => ((zones.find((z) => z.name === zone) || {}).interfaces || []).map((i) => i.name);
    // Browser-only terms that name a policy or a zone: their interfaces narrow on the device.
    const idx = this.ctx.store.policyIndex();
    const walk = (node) => {
      if (!node) return;
      if (node.type === 'and' || node.type === 'or') node.items.forEach(walk);
      if (node.type !== 'term' || !node.key || node.values.length !== 1) return;
      const k = this.keyName(node.key);
      const v = node.values[0].text;
      if (k === 'policy' && idx.get(v)) {
        for (const z of idx.get(v).from || []) for (const i of ifaceOf(z)) add('iface', i, `zone ${z}, where ${v} starts`);
      }
      if (['zone', 'from', 'to'].includes(k)) for (const i of ifaceOf(v)) add('iface', i, `interface of zone ${v}`);
    };
    walk(this.plan && this.plan.browser);
    add('proto', 'udp', 'UDP only');
    add('proto', 'icmp', 'ICMP only');
    add('dport', '443', 'HTTPS');
    add('dport', '53', 'DNS');
    for (const z of zones) for (const i of (z.interfaces || []).map((x) => x.name).slice(0, 2)) add('iface', i, `zone ${z.name}`);
    return out;
  }

  // ---- rendering: rows -------------------------------------------------------------------------

  /** A clickable value (filter by it; Alt excludes). Focusable with the arrow keys inside a row. */
  fx(key, value, display, cls) {
    if (value === null || value === undefined || value === '') return this.h('span', { class: ['faint', cls] }, display ?? DASH);
    return this.h('span', { class: ['fx', cls], tabindex: '-1', dataset: { k: key, v: String(value), fk: `${key}=${value}` } }, display ?? String(value));
  }

  /**
   * An address whose middle is cut (never its last group) when the column is too narrow. An IPv4
   * address (at most 15 characters) always fits its column, so it stays one text node.
   */
  addr(text) {
    if (String(text).length <= 15) return String(text);
    const [head, tail] = splitTail(text);
    return [this.h('span', { class: 'ip-h' }, head), this.h('span', { class: 'ip-t' }, tail)];
  }

  /** What a cell shows depends only on this string: equal signatures, no DOM work. */
  cellSig(c, r) {
    const a = r.in || {};
    const b = r.out || {};
    switch (c.id) {
      case 'status': return `${this.statusOf(r).cls}|${r.state}|${r.status}|${r._backupWhy || ''}`;
      case 'id': return r.session_id || r.id;
      case 'policy': return r.policy || '';
      case 'zones': {
        const z = r._zones;
        return z ? `${z.fromText}|${z.toText}|${z.from}|${z.to}|${z.global}|${z.ambiguous}` : `-|${r.policy || ''}`;
      }
      case 'proto': return a.proto || '';
      case 'src': return `${a.src}|${a.sport}`;
      case 'dst': return `${a.dst}|${a.dport}`;
      case 'nat': {
        const n = r.nat || {};
        return `${n.source}|${n.destination}|${b.dst}|${b.dport}|${b.src}|${b.sport}|${a.src}|${a.sport}|${a.dst}|${a.dport}`;
      }
      case 'app': return r.application || '';
      case 'iface': return `${a.iface}|${b.iface}`;
      case 'bytes': return `${a.bytes}|${b.bytes}`;
      case 'pkts': return `${a.packets}|${b.packets}`;
      case 'rate': {
        const w = this.maxRate > 0 && Number.isFinite(r.rate) ? Math.round(Math.sqrt(r.rate / this.maxRate) * 100) : 0;
        return `${Boolean(r._ended)}|${r._live}|${rateShort(r.rate, this.fmt)}|${w}`;
      }
      case 'dur': return String(r.duration);
      case 'timeout': return `${r.timeout}|${r.configured_timeout}`;
      case 'node': return `${r.location}|${r._backup}`;
      default: return '';
    }
  }

  statusOf(r) {
    const cls = r._ended ? 'ended' : r._backup ? 'backup' : r._newAt && Date.now() - r._newAt < FLASH_MS * 2 ? 'new' : /^valid$/i.test(r.state || 'valid') ? 'ok' : 'warn';
    const label = r._ended ? 'ended since the last poll' : r._backup ? `backup copy (${r._backupWhy})` : `${r.state || 'state unknown'}${r.status ? `, ${r.status}` : ''}`;
    return { cls, label };
  }

  cellContent(c, r) {
    const { h } = this;
    const fmt = this.fmt;
    const a = r.in || {};
    const b = r.out || {};
    switch (c.id) {
      case 'status': {
        const { cls, label } = this.statusOf(r);
        return h('span', { class: ['sx-dot', cls], title: label }, h('span', { class: 'sr-only' }, label));
      }
      case 'id':
        return h('span', { class: 'sx-id num' }, r.session_id || r.id);
      case 'policy':
        return this.fx('policy', r.policy, r.policy || DASH, 'sx-pol');
      case 'zones': {
        const z = r._zones;
        if (!z) return h('span', { class: 'faint', title: r.policy ? `Policy ${r.policy} is not in the inventory of this scope (a default policy?)` : '' }, DASH);
        if (z.global && !z.fromAll.length && !z.toAll.length) return h('span', { class: 'faint', title: 'A global policy without from- or to-zones: the zones are not known from the policy' }, 'global');
        return h(
          'span',
          { class: 'sx-zones', title: z.ambiguous ? `Policy name used in several zone pairs: ${z.fromAll.join(', ')} → ${z.toAll.join(', ')}` : null },
          z.from ? this.fx('from', z.from, z.from, 'sx-zone') : h('span', { class: 'sx-zone faint' }, z.fromText),
          h('span', { class: 'sx-arr' }, ARROW),
          z.to ? this.fx('to', z.to, z.to, 'sx-zone') : h('span', { class: 'sx-zone faint' }, z.toText),
        );
      }
      case 'proto':
        return this.fx('proto', a.proto, a.proto, 'sx-proto');
      case 'src':
        return this.endpoint(a.src, a.sport, 'src', 'sport');
      case 'dst':
        return this.endpoint(a.dst, a.dport, 'dst', 'dport');
      case 'nat':
        return this.natCell(r);
      case 'app':
        return this.fx('app', r.application, r.application || DASH, 'sx-app');
      case 'iface':
        return h('span', { class: 'sx-ifs' }, this.fx('iface', a.iface, a.iface, 'iface'), h('span', { class: 'sx-arr' }, ARROW), this.fx('iface', b.iface, b.iface, 'iface'));
      case 'bytes':
        return h(
          'span',
          { class: 'sx-bytes num', title: `${fmt.num(a.bytes)} bytes from the client, ${fmt.num(b.bytes)} from the server` },
          h('span', { class: 'up' }, '↑', fmt.compact(a.bytes)),
          h('span', { class: 'down' }, '↓', fmt.compact(b.bytes)),
        );
      case 'pkts':
        return h('span', { class: 'num', title: `${fmt.num(a.packets)} packets from the client, ${fmt.num(b.packets)} from the server` }, fmt.compact(r._pkts));
      case 'rate': {
        const w = this.maxRate > 0 && Number.isFinite(r.rate) ? Math.sqrt(r.rate / this.maxRate) : 0;
        const bar = h('i', null);
        bar.style.setProperty('--w', `${Math.round(w * 100)}%`);
        // A live rate (from two polls) is bright; the average since the start is dim, no glyph.
        return h(
          'span',
          { class: ['sx-rate', r._live ? 'live' : 'avg'], title: r._ended ? 'ended' : `${fmt.rate(r.rate)}: ${r._live ? 'bytes per second between the last two polls' : 'dim, the average since the session started; the live rate appears after the next poll'}` },
          h('span', { class: 'sx-rate-v num' }, r._ended || !Number.isFinite(r.rate) ? DASH : rateShort(r.rate, fmt)),
          h('span', { class: 'sx-rbar', 'aria-hidden': 'true' }, bar),
        );
      }
      case 'dur':
        return h('span', { class: 'num' }, fmt.duration(r.duration));
      case 'timeout': {
        const cfg = Number(r.configured_timeout);
        const left = Number(r.timeout);
        const frac = cfg > 0 && Number.isFinite(left) ? Math.max(0, Math.min(1, left / cfg)) : null;
        const bar = h('i', null);
        if (frac !== null) bar.style.setProperty('--w', `${Math.round(frac * 100)}%`);
        return h(
          'span',
          { class: ['sx-to', frac !== null && frac < 0.2 && 'low'], title: Number.isFinite(left) ? `${secs(left, fmt)} left of ${Number.isFinite(cfg) ? secs(cfg, fmt) : '?'}` : 'timeout not reported' },
          h('span', { class: 'num' }, Number.isFinite(left) ? fmt.duration(left) : DASH),
          frac !== null ? h('span', { class: 'sx-tbar', 'aria-hidden': 'true' }, bar) : null,
        );
      }
      case 'node':
        return h('span', { class: 'sx-node' }, this.fx('node', r.location, r.location || DASH, 'mono'), r._backup ? h('span', { class: 'pill muted' }, 'backup') : null);
      default:
        return null;
    }
  }

  endpoint(ip, port, ipKey, portKey) {
    const { h } = this;
    if (!ip) return h('span', { class: 'faint' }, DASH);
    const v6 = String(ip).includes(':');
    const ipEl = this.fx(ipKey, ip, this.addr(v6 ? `[${ip}]` : ip), 'ip');
    return h(
      'span',
      { class: 'sx-ep', title: hp(ip, port) },
      ipEl,
      port !== null && port !== undefined ? [h('span', { class: 'sx-colon' }, ':'), this.fx(portKey, port, String(port), 'port')] : null,
    );
  }

  /** A translated address:port (violet); the port is never cut, the address only in the middle. */
  natEp(key, ip, port) {
    const { h } = this;
    if (!ip) return h('span', { class: 'faint' }, DASH);
    const v6 = String(ip).includes(':');
    const kids = [...this.addr(v6 ? `[${ip}]` : ip)];
    if (port !== null && port !== undefined && port !== '') kids.push(h('span', { class: 'ip-p' }, `:${port}`));
    return this.fx(key, ip, kids, 'nat');
  }

  natCell(r) {
    const { h } = this;
    const n = r.nat || {};
    const b = r.out || {};
    if (!n.source && !n.destination) return h('span', { class: 'faint sx-nonat' }, 'none');
    const parts = [];
    const tips = [];
    if (n.source) {
      parts.push(this.fx('nat', 'src', 'SNAT', 'sx-natb'));
      tips.push(`source NAT: ${hp((r.in || {}).src, (r.in || {}).sport)} → ${hp(b.dst, b.dport)}`);
    }
    if (n.destination) {
      parts.push(this.fx('nat', 'dst', 'DNAT', 'sx-natb'));
      tips.push(`destination NAT: ${hp((r.in || {}).dst, (r.in || {}).dport)} → ${hp(b.src, b.sport)}`);
    }
    if (n.source && !n.destination) parts.push(this.natEp('natsrc', b.dst, b.dport));
    else if (n.destination) parts.push(h('span', { class: 'sx-arr' }, ARROW), this.natEp('natdst', b.src, b.sport));
    return h('span', { class: 'sx-nat', title: tips.join('; ') }, parts);
  }

  /** Which row takes Tab: the selected one when it is rendered, else the first visible one. */
  chooseTabRow(w) {
    const sel = this.selId && this.indexById.has(this.selId) ? this.indexById.get(this.selId) : -1;
    const next = sel >= w.start && sel <= w.end ? this.selId : this.rows[w.first] ? this.rows[w.first].id : null;
    if (next === this.tabId) return;
    const prev = this.tabId;
    this.tabId = next;
    // The row that held the Tab stop gives it up now (it may not be patched in this sync).
    const old = prev ? this.list.nodeFor(prev) : null;
    if (old) old.tabIndex = -1;
    const cur = next ? this.list.nodeFor(next) : null;
    if (cur) cur.tabIndex = 0;
  }

  createRow(i) {
    const node = this.h('div', { class: 'sx-row', role: 'row' });
    node._sigs = [];
    node._cells = [];
    if (this.mobile) {
      const cell = this.h('div', { class: 'sx-c sx-mcell', role: 'gridcell', 'aria-colindex': '1' });
      node.append(cell);
      node._cells.push(cell);
    } else {
      this.cols.forEach((c, ci) => {
        const cell = this.h('div', { class: ['sx-c', `c-${c.id}`, c.num && 'num-col'], role: 'gridcell', 'aria-colindex': String(ci + 1) });
        node.append(cell);
        node._cells.push(cell);
      });
    }
    this.patchRow(node, i, true);
    return node;
  }

  /** Bring a row node up to date for rows[i]: attributes, then only the cells whose signature changed. */
  patchRow(node, i, created = false) {
    const r = this.rows[i];
    if (!r) return;
    const sel = this.selId === r.id;
    const age = r._newAt ? Date.now() - r._newAt : Infinity;
    const fresh = age < FLASH_MS;
    const cls = ['sx-row', 'vlist-row', fresh && 'sx-new', r._ended && 'sx-ended', r._backup && 'sx-backup', i % 2 && 'odd'].filter(Boolean).join(' ');
    if (node._cls !== cls) {
      // A row that becomes fresh while already on screen does not restart its wash.
      if (fresh && created) node.style.animationDelay = `-${Math.round(age)}ms`;
      node.className = cls;
      node._cls = cls;
    }
    const attrs = `${i}|${sel}|${this.tabId === r.id}`;
    if (node._attrs !== attrs) {
      node._attrs = attrs;
      node.setAttribute('aria-rowindex', String(i + 2));
      node.setAttribute('aria-selected', sel ? 'true' : 'false');
      node.tabIndex = this.tabId === r.id ? 0 : -1;
      node.dataset.id = r.id;
    }
    if (this.mobile) {
      const sig = this.mobileSig(r);
      if (node._sigs[0] !== sig) {
        node._sigs[0] = sig;
        const cell = node._cells[0];
        const fk = focusKeyIn(cell);
        cell.replaceChildren(...this.mobileCell(r));
        if (fk) refocus(cell, fk);
      }
      return;
    }
    for (let ci = 0; ci < this.cols.length; ci += 1) {
      const c = this.cols[ci];
      const sig = this.cellSig(c, r);
      if (node._sigs[ci] === sig) continue;
      node._sigs[ci] = sig;
      const cell = node._cells[ci];
      const fk = focusKeyIn(cell);
      const content = this.cellContent(c, r);
      if (content) cell.replaceChildren(content);
      else cell.replaceChildren();
      if (fk) refocus(cell, fk);
    }
  }

  mobileSig(r) {
    const a = r.in || {};
    const n = r.nat || {};
    const b = r.out || {};
    return [this.statusOf(r).cls, a.src, a.sport, a.dst, a.dport, a.proto, r.policy, r.application, n.source, n.destination, b.src, b.sport, b.dst, b.dport,
      r._ended, r._live, rateShort(r.rate, this.fmt), b.bytes, r.duration].join('|');
  }

  /**
   * Phone card, three 12 px lines:  ● source:port            ↓bytes · age
   *                                   → destination:port            rate
   *                                   policy · proto · NAT (the whole line)
   */
  mobileCell(r) {
    const { h } = this;
    const fmt = this.fmt;
    const a = r.in || {};
    const cell = (cls, ...kids) => h('div', { class: ['sx-m', cls] }, ...kids);
    const rate = r._ended ? 'ended' : rateShort(r.rate, fmt);
    return [
      cell('m-dot', this.cellContent(COL_BY_ID.get('status'), r)),
      cell('m-src', this.endpoint(a.src, a.sport, 'src', 'sport')),
      cell('m-size', h('span', { class: 'num' }, `↓${fmt.bytes((r.out || {}).bytes)} · ${fmt.duration(r.duration)}`)),
      cell('m-dst', h('span', { class: 'sx-arr' }, ARROW), this.endpoint(a.dst, a.dport, 'dst', 'dport')),
      cell(
        'm-meta',
        this.fx('policy', r.policy, r.policy || DASH, 'sx-pol'),
        a.proto ? [h('span', { class: 'sep' }, SEP), this.fx('proto', a.proto, a.proto, 'sx-proto')] : null,
        r.nat && (r.nat.source || r.nat.destination) ? [h('span', { class: 'sep' }, SEP), this.natCell(r)] : null,
        r.application ? [h('span', { class: 'sep' }, SEP), this.fx('app', r.application, r.application, 'sx-app')] : null,
      ),
      cell('m-rate', h('span', { class: ['num', r._live ? 'live' : 'avg'] }, rate)),
    ];
  }

  // ---- grid interaction ------------------------------------------------------------------------

  rowIndexOf(el) {
    const row = el instanceof Element ? el.closest('.sx-row') : null;
    if (!row || !row.dataset.id) return -1;
    return this.indexById.has(row.dataset.id) ? this.indexById.get(row.dataset.id) : -1;
  }

  onGridClick(e) {
    const t = e.target instanceof Element ? e.target : null;
    if (!t || this.gridHead.contains(t)) return;
    const sel = window.getSelection ? window.getSelection() : null;
    if (sel && !sel.isCollapsed && sel.toString()) return; // selecting text to copy, not filtering
    const token = t.closest('.fx');
    if (token && this.scroller.contains(token)) {
      e.preventDefault();
      this.addTerm(token.dataset.k, token.dataset.v, e.altKey);
      return;
    }
    const i = this.rowIndexOf(t);
    if (i >= 0) this.select(i, { open: true, focus: true });
  }

  onGridDblClick(e) {
    const i = this.rowIndexOf(e.target);
    if (i >= 0) this.select(i, { open: true });
  }

  /**
   * Keyboard in the table (role=grid, row focus): Up/Down, Page Up/Down, Home/End move the
   * selection with the focus; Enter opens the session. Right/Left walk the values of the focused
   * row; on a value, Enter filters by it and Alt+Enter excludes it; Escape returns to the row.
   */
  onGridKey(e) {
    const t = e.target instanceof Element ? e.target : null;
    if (!t || e.metaKey || e.ctrlKey) return;
    const value = t.classList.contains('fx') ? t : null;
    const row = t.closest('.sx-row');
    const onScroller = t === this.scroller;
    if (!row && !onScroller) return;
    const i = row ? this.rowIndexOf(row) : this.rows.findIndex((r) => r.id === this.selId);
    const page = Math.max(1, Math.floor((this.list.viewH - this.list.offset) / this.list.rowHeight) - 1);
    const move = (to) => {
      e.preventDefault();
      if (!this.rows.length) return;
      this.select(Math.max(0, Math.min(this.rows.length - 1, to)), { focus: true });
    };
    switch (e.key) {
      case 'ArrowDown': return move(i < 0 ? 0 : i + 1);
      case 'ArrowUp': return move(i < 0 ? 0 : i - 1);
      case 'PageDown': return move((i < 0 ? 0 : i) + page);
      case 'PageUp': return move((i < 0 ? 0 : i) - page);
      case 'Home': return move(0);
      case 'End': return move(this.rows.length - 1);
      default: break;
    }
    if (!row) return;
    const values = [...row.querySelectorAll('.fx')].filter((el) => el.getClientRects().length);
    if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
      e.preventDefault();
      const at = value ? values.indexOf(value) : -1;
      const next = e.key === 'ArrowRight' ? at + 1 : at - 1;
      if (next >= 0 && next < values.length) values[next].focus({ preventScroll: false });
      else if (next < 0 && value) row.focus({ preventScroll: true });
      return;
    }
    if (e.key === 'Escape' && value) {
      e.preventDefault();
      e.stopPropagation();
      row.focus({ preventScroll: true });
      return;
    }
    if (e.key === 'Enter') {
      e.preventDefault();
      if (value) {
        this.addTerm(value.dataset.k, value.dataset.v, e.altKey);
        return;
      }
      if (i >= 0) this.select(i, { open: true });
    }
  }

  select(i, { open = false, focus = false, scroll = true } = {}) {
    const r = this.rows[i];
    if (!r) return;
    const prev = this.selId;
    this.selId = r.id;
    if (scroll) this.list.scrollToIndex(i, 'nearest');
    // The selection moves by patching the two rows' attributes: no node is replaced.
    if (prev && prev !== r.id) this.list.patchKey(prev);
    this.chooseTabRow(this.list.range);
    this.list.patchKey(r.id);
    const node = this.list.nodeFor(r.id);
    if (focus && node) node.focus({ preventScroll: true });
    if (open) this.openDetail(r.id);
    else if (this.detail) this.openDetail(r.id);
    this.saveRoute(false);
  }

  onKey(e) {
    if (this.dead || e.defaultPrevented || e.metaKey || e.ctrlKey || e.altKey) return;
    const t = e.target;
    if (t instanceof Element) {
      if (t.closest('input, textarea, select, [contenteditable="true"], .layer, .dialog, .menu')) return;
    }
    if (!this.el.isConnected) return;
    if (e.key === 'j' || e.key === 'k') {
      if (!this.rows.length) return;
      e.preventDefault();
      const cur = this.rows.findIndex((r) => r.id === this.selId);
      const next = cur < 0 ? 0 : Math.max(0, Math.min(this.rows.length - 1, cur + (e.key === 'j' ? 1 : -1)));
      const inGrid = this.scroller.contains(document.activeElement);
      this.select(next, { focus: inGrid || !this.detail });
    } else if (e.key === 'Enter' && (t === document.body || t === document.getElementById('main') || (t instanceof Element && t.classList.contains('sx-row')))) {
      const cur = this.rows.findIndex((r) => r.id === this.selId);
      if (cur >= 0) {
        e.preventDefault();
        this.select(cur, { open: true });
      }
    }
  }

  onEscape() {
    this.closeMenu();
    this.hideHover(false);
  }

  // hover = / ≠ buttons: one floating element, placed next to the value under the pointer
  onGridOver(e) {
    const t = e.target instanceof Element ? e.target : null;
    if (!t || this.mobile) return;
    const token = t.closest('.fx');
    if (!token) return;
    this.showHover(token);
  }

  showHover(token) {
    clearTimeout(this.hoverTimer);
    const card = this.gridCard.getBoundingClientRect();
    const r = token.getBoundingClientRect();
    this.hover = { k: token.dataset.k, v: token.dataset.v };
    this.hov.hidden = false;
    this.hov.querySelector('[data-act="go"]').hidden = this.hover.k !== 'policy';
    this.hov.title = `${this.hover.k}:${this.hover.v}`;
    const w = this.hov.offsetWidth || 48;
    let x = r.right - card.left + 2;
    if (x + w > card.width - 4) x = Math.max(4, r.left - card.left - w - 2);
    this.hov.style.left = `${Math.round(x)}px`;
    this.hov.style.top = `${Math.round(r.top - card.top + r.height / 2 - 10)}px`;
    for (const el of this.scroller.querySelectorAll('.fx.hot')) el.classList.remove('hot');
    token.classList.add('hot');
  }

  keepHover() {
    clearTimeout(this.hoverTimer);
  }

  hideHover(delayed) {
    clearTimeout(this.hoverTimer);
    const go = () => {
      this.hov.hidden = true;
      this.hover = null;
      for (const el of this.scroller.querySelectorAll('.fx.hot')) el.classList.remove('hot');
    };
    if (delayed) this.hoverTimer = setTimeout(go, 160);
    else go();
  }

  reshowHover() {
    if (!this.hover || !this.pointer || this.hov.hidden) return;
    const el = document.elementFromPoint(this.pointer.x, this.pointer.y);
    const token = el instanceof Element ? el.closest('.fx') : null;
    if (token && this.scroller.contains(token)) this.showHover(token);
    else if (!(el instanceof Element && this.hov.contains(el))) this.hideHover(false);
  }

  hoverAct(e, exclude) {
    e.preventDefault();
    if (!this.hover) return;
    const { k, v } = this.hover;
    this.hideHover(false);
    this.addTerm(k, v, exclude);
  }

  hoverGo(e) {
    e.preventDefault();
    if (!this.hover) return;
    const { v } = this.hover;
    this.hideHover(false);
    this.openPolicy(v);
  }

  /**
   * Where a policy sits in Junos evaluation order, from the inventory: {n, of, where}. The device's
   * policy index is an internal ID, so the position comes from the configuration order (seq).
   */
  policyPosition(name) {
    if (!name) return null;
    const p = this.ctx.store.policyIndex().get(name);
    if (!p || p.ambiguous || !Number.isFinite(Number(p.seq))) return null;
    const pol = this.ctx.store.lastInventory && this.ctx.store.lastInventory.scope && this.ctx.store.lastInventory.scope.policies;
    if (!pol) return null;
    if (p.kind === 'global') {
      const of = Number(pol.global_count);
      return Number.isFinite(of) && of > 0 ? { n: Number(p.seq), of, where: 'the global policies' } : null;
    }
    if ((p.from || []).length !== 1 || (p.to || []).length !== 1) return null;
    const pair = (pol.zone_pairs || []).find((zp) => zp.from === p.from[0] && zp.to === p.to[0]);
    return pair && pair.count ? { n: Number(p.seq), of: Number(pair.count), where: `${p.from[0]} ${ARROW} ${p.to[0]}` } : null;
  }

  openPolicy(name) {
    const idx = this.ctx.store.policyIndex();
    const p = idx.get(name);
    this.ctx.navigate('policies', { q: `name:${qv(name)}`, sel: p && !p.ambiguous ? p.id : null });
  }

  // ---- facets ----------------------------------------------------------------------------------

  toggleFacets() {
    this.facetsOpen = !this.facetsOpen;
    this.facetsTouched = true;
    prefSet(PREF.facets, this.facetsOpen ? 'open' : 'closed');
    this.renderFacetsToggle();
    this.renderFacets();
  }

  renderFacetsToggle() {
    this.facetBtn.setAttribute('aria-pressed', this.facetsOpen ? 'true' : 'false');
    this.body.classList.toggle('facets-open', this.facetsOpen);
    this.facets.hidden = !this.facetsOpen;
  }

  /** Positive top-level key:value terms of the applied query ("dport:443"): those facet bars are gold. */
  activeTerms() {
    const out = new Set();
    if (!this.ast || !this.q) return out;
    const items = this.ast.type === 'and' ? this.ast.items : [this.ast];
    for (const it of items) {
      if (it.type !== 'term' || !it.key || (it.op !== ':' && it.op !== '=')) continue;
      for (const v of it.values) out.add(`${this.keyName(it.key)}:${v.text}`);
    }
    return out;
  }

  renderFacets() {
    if (!this.facetsOpen || !this.facets) return;
    const { h } = this;
    const fmt = this.fmt;
    const table = this.payload && this.payload.sessions;
    if (!table || table.status !== 'ok') {
      if (this.sigs.facets === 'none') return;
      this.sigs.facets = 'none';
      this.ctx.dom.put(this.facets, h('div', { class: 'fc-head' }, h('h2', { class: 'fc-title' }, 'Facets')), h('p', { class: 'fc-empty' }, 'Facets appear when the device lists sessions.'));
      return;
    }
    const data = this.facetData();
    const active = this.activeTerms();
    // Rebuilt only when the bars would change: a focused facet button survives the poll.
    const sig = JSON.stringify([this.metric, [...active], data.map((f) => [f.top, f.distinct, f.missing, f.total])]);
    if (sig === this.sigs.facets) return;
    this.sigs.facets = sig;
    const val = (n) => (this.metric === 'bytes' ? fmt.bytes(n) : this.metric === 'rate' ? fmt.rate(n) : fmt.num(n));
    const seg = h(
      'div',
      { class: 'seg fc-metric', role: 'group', 'aria-label': 'Rank facets by' },
      METRICS.map((m) =>
        h('button', { type: 'button', 'aria-pressed': m.id === this.metric ? 'true' : 'false', title: m.title, dataset: { fk: `metric:${m.id}` }, on: { click: () => this.setMetric(m.id) } }, m.label),
      ),
    );
    const groups = data.map((f) => {
      const max = f.top.length ? f.top[0][1] : 0;
      const items = f.top.map(([v, n]) => {
        const bar = h('i', null);
        bar.style.setProperty('--w', `${max > 0 ? Math.max(2, Math.round((n / max) * 100)) : 0}%`);
        const label = String(v);
        const on = active.has(`${f.key}:${label}`);
        return h(
          'li',
          { class: ['fc-item', on && 'on'] },
          h(
            'button',
            {
              class: 'fc-btn',
              type: 'button',
              'aria-pressed': on ? 'true' : null,
              title: on ? `Already filtering by ${f.key}:${label}` : `Filter by ${f.key}:${label} (Alt-click: exclude)`,
              dataset: { fk: `${f.key}=${label}` },
              on: { click: (e) => this.addTerm(f.key, v, e.altKey) },
            },
            h('span', { class: 'fc-label' }, label),
            h('span', { class: 'fc-n num' }, val(n)),
            h('span', { class: ['fc-bar', f.cls], 'aria-hidden': 'true' }, bar),
          ),
          h('button', { class: 'fc-x', type: 'button', title: `Exclude ${f.key}:${label}`, 'aria-label': `Exclude ${f.key} ${label}`, dataset: { fk: `${f.key}!=${label}` }, on: { click: () => this.addTerm(f.key, v, true) } }, '≠'),
        );
      });
      const empty = !f.top.length
        ? h('p', { class: 'fc-empty' }, f.missing && f.total ? `Not reported for ${f.total === 1 ? 'this session' : `these ${fmt.plural(f.total, 'session')}`}.` : 'No sessions.')
        : null;
      return h(
        'section',
        { class: 'fc-group', 'aria-label': f.title },
        h('h3', { class: 'fc-gtitle' }, f.title, h('span', { class: 'fc-distinct num' }, f.distinct ? `${fmt.num(f.distinct)} distinct` : '')),
        empty,
        f.top.length ? h('ul', { class: 'fc-list' }, items) : null,
      );
    });
    const total = data[0] ? data[0].total : 0;
    swapKeepFocus(this.ctx.dom.put, this.facets,
      h('div', { class: 'fc-head' }, h('h2', { class: 'fc-title' }, 'Top 8'), seg),
      h('div', { class: 'fc-groups' }, groups),
      h('p', { class: 'fc-foot' }, `Over the ${total === 1 ? 'session' : fmt.plural(total, 'session')} shown. Click: filter${SEP}Alt-click: exclude.`),
    );
  }

  setMetric(id) {
    this.metric = id;
    prefSet(PREF.metric, id);
    this.renderFacets();
  }

  // ---- menus -----------------------------------------------------------------------------------

  closeMenu(focusBtn = false) {
    if (!this.menu) return;
    const { el, btn, onDoc } = this.menu;
    el.remove();
    document.removeEventListener('pointerdown', onDoc, true);
    btn.setAttribute('aria-expanded', 'false');
    this.menu = null;
    if (focusBtn) btn.focus({ preventScroll: true });
  }

  openMenu(btn, title, items) {
    const wasOpen = this.menu && this.menu.btn === btn;
    this.closeMenu();
    if (wasOpen) return;
    const { h } = this;
    const el = h('div', { class: 'menu menu-fixed sx-menu', role: 'menu', 'aria-label': title }, h('div', { class: 'menu-head' }, title), items);
    const focusables = () => [...el.querySelectorAll('[role^="menuitem"]')];
    el.addEventListener('keydown', (e) => {
      const list = focusables();
      const at = list.indexOf(document.activeElement);
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        list[Math.min(list.length - 1, at + 1)].focus();
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        list[Math.max(0, at - 1)].focus();
      } else if (e.key === 'Escape') {
        e.preventDefault();
        e.stopPropagation();
        this.closeMenu(true);
      } else if (e.key === 'Tab') {
        this.closeMenu();
      }
    });
    const onDoc = (e) => {
      if (!el.contains(e.target) && !btn.contains(e.target)) this.closeMenu();
    };
    document.addEventListener('pointerdown', onDoc, true);
    document.body.append(el);
    const r = btn.getBoundingClientRect();
    const w = el.offsetWidth;
    // Keep the whole menu on screen: below the button when it fits, else above it, and never under
    // the phone-width bottom navigation (the rail moves there).
    const rail = document.getElementById('rail');
    const rr = rail ? rail.getBoundingClientRect() : null;
    const floor = rr && rr.height && rr.top > window.innerHeight / 2 ? rr.top : window.innerHeight;
    const below = floor - r.bottom - 14;
    const above = r.top - 14;
    const natural = el.scrollHeight;
    if (natural > below && above > below) {
      const mh = Math.min(natural, above);
      el.style.maxHeight = `${Math.floor(mh)}px`;
      el.style.top = `${Math.round(r.top - 6 - mh)}px`;
    } else {
      el.style.maxHeight = `${Math.floor(Math.max(120, below))}px`;
      el.style.top = `${Math.round(r.bottom + 6)}px`;
    }
    el.style.left = `${Math.round(Math.max(8, Math.min(window.innerWidth - w - 8, r.right - w)))}px`;
    btn.setAttribute('aria-expanded', 'true');
    this.menu = { el, btn, onDoc };
    const first = focusables()[0];
    if (first) first.focus({ preventScroll: true });
  }

  menuItem(label, onClick, { checked = null, meta = null, iconName = null, keepOpen = false } = {}) {
    const { h } = this;
    const { icon } = this.ctx.dom;
    const role = checked === null ? 'menuitem' : 'menuitemcheckbox';
    return h(
      'div',
      {
        role,
        tabindex: '-1',
        'aria-checked': checked === null ? null : checked ? 'true' : 'false',
        class: ['sx-mi', checked && 'on'],
        on: {
          click: () => {
            onClick();
            if (!keepOpen) this.closeMenu(true);
          },
          keydown: (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault();
              e.currentTarget.click();
            }
          },
        },
      },
      checked !== null ? h('span', { class: 'sx-check', 'aria-hidden': 'true' }, checked ? icon('check') : null) : iconName ? icon(iconName) : null,
      h('span', { class: 'opt-label' }, label),
      meta ? h('span', { class: 'opt-meta' }, meta) : null,
    );
  }

  openColumnsMenu() {
    const { h } = this;
    const current = new Set(this.cols.map((c) => c.id));
    const items = COLUMNS.filter((c) => !c.fixed).map((c) =>
      this.menuItem(c.title && c.label.length < 3 ? c.title : c.label, () => {
        const ids = COLUMNS.filter((x) => !x.fixed && (x.id === c.id ? !current.has(x.id) : current.has(x.id))).map((x) => x.id);
        this.setManualCols(ids.length ? ids : null);
        this.closeMenu();
        this.openColumnsMenu();
      }, { checked: current.has(c.id), meta: c.onlyWith && !this.available(c) ? 'cluster only' : null, keepOpen: true }),
    );
    const comfy = document.documentElement.dataset.density === 'comfortable';
    this.openMenu(this.colBtn, 'Columns', [
      ...items,
      h('div', { class: 'sx-msep', role: 'separator' }),
      this.menuItem(this.manualCols ? 'Fit columns to the width (automatic)' : 'Automatic: columns fit the width', () => this.setManualCols(null), { iconName: 'sidebar', meta: this.manualCols ? null : 'on' }),
      this.menuItem(comfy ? 'Dense rows' : 'Comfortable rows', () => this.toggleDensity(), { iconName: 'rows' }),
    ]);
  }

  toggleDensity() {
    // Row density is a shell preference (rail foot, palette, this menu): the shell stores it and
    // dispatches jwicket:density, which refits the rows.
    if (typeof this.ctx.ui.toggleDensity === 'function') this.ctx.ui.toggleDensity();
  }

  openSortMenu() {
    const choices = [
      ['dur', 'Newest first'], ['-dur', 'Oldest first'], ['-rate', 'Fastest (live rate)'], ['-bytes', 'Most bytes'],
      ['timeout', 'Expiring first'], ['src', 'Source address'], ['dst', 'Destination address'], ['policy', 'Policy'], ['id', 'Session ID'],
    ];
    this.openMenu(this.sortBtn, 'Sort sessions', choices.map(([key, label]) => this.menuItem(label, () => {
      this.sort = key;
      this.order.clear();
      this.saveRoute(false);
      this.renderHeader();
      this.recompute({ facets: false });
    }, { checked: this.sort === key })));
  }

  openExportMenu() {
    const n = this.rows.filter((r) => !r._ended).length;
    this.openMenu(this.exportBtn, `Export ${this.fmt.plural(n, 'row')} on screen`, [
      this.menuItem('CSV (spreadsheet)', () => this.exportAs('csv'), { iconName: 'download', meta: '.csv' }),
      this.menuItem('JSON (with the stamp)', () => this.exportAs('json'), { iconName: 'download', meta: '.json' }),
      this.menuItem('Copy a link to this view', () => this.ctx.ui.copy(location.href, 'Link copied. It holds the query and sort, not device data.'), { iconName: 'link' }),
    ]);
  }

  // ---- export ----------------------------------------------------------------------------------

  stamp() {
    const snap = this.ctx.store.lastInventory;
    const dev = snap && snap.device && snap.device.status === 'ok' ? snap.device : {};
    const meta = (this.payload && this.payload.meta) || {};
    const table = (this.payload && this.payload.sessions) || {};
    return {
      generator: 'J-Wicket',
      kind: 'flow sessions (current view)',
      device: dev.hostname || null,
      model: dev.model || null,
      junos: dev.version || null,
      read_as: (meta.read_as && meta.read_as.user) || (this.ctx.store.session && this.ctx.store.session.user) || null,
      read_at: meta.read_at || null,
      exported_at: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
      query: this.text,
      device_filters: meta.device_filters || {},
      browser_filter: this.plan && this.plan.browser ? this.q.toQueryString(this.plan.browser) : '',
      sort: this.sort,
      rows: this.rows.filter((r) => !r._ended).length,
      listed: this.listedCount || 0,
      limit: meta.limit || this.limit,
      truncated: Boolean(table.truncated),
      backup_copies_hidden: this.showBackups ? 0 : this.backupCount,
      fixture: Boolean(meta.fixture),
    };
  }

  exportRow(r) {
    const a = r.in || {};
    const b = r.out || {};
    const n = r.nat || {};
    const z = r._zones || {};
    return {
      session_id: r.session_id,
      location: r.location,
      state: r.state,
      status: r.status,
      policy: r.policy,
      policy_index: r.policy_index,
      from_zone: z.fromAll ? z.fromAll.join(' ') : '',
      to_zone: z.toAll ? z.toAll.join(' ') : '',
      protocol: a.proto,
      source_address: a.src,
      source_port: a.sport,
      destination_address: a.dst,
      destination_port: a.dport,
      nat_source_address: n.source ? b.dst : '',
      nat_source_port: n.source ? b.dport : '',
      nat_destination_address: n.destination ? b.src : '',
      nat_destination_port: n.destination ? b.sport : '',
      application: r.application,
      ingress_interface: a.iface,
      egress_interface: b.iface,
      bytes_from_client: a.bytes,
      bytes_from_server: b.bytes,
      packets_from_client: a.packets,
      packets_from_server: b.packets,
      rate_bytes_per_s: Number.isFinite(r.rate) ? Math.round(r.rate) : '',
      rate_kind: r._live ? 'live' : 'average',
      duration_s: r.duration,
      timeout_s: r.timeout,
      configured_timeout_s: r.configured_timeout,
      backup_copy: r._backup ? 'yes' : '',
    };
  }

  exportAs(kind) {
    const rows = this.rows.filter((r) => !r._ended).map((r) => this.exportRow(r));
    const st = this.stamp();
    let blob;
    if (kind === 'json') {
      const extra = this.rows.filter((r) => !r._ended).map((r) => ({ ...this.exportRow(r), extra: r.extra || {} }));
      blob = new Blob([`${JSON.stringify({ stamp: st, sessions: extra }, null, 2)}\n`], { type: 'application/json' });
    } else {
      const lines = [];
      const title = `# J-Wicket flow sessions from ${st.device || 'unknown device'} read ${st.read_at || '?'} as ${st.read_as || '?'}; exported ${st.exported_at}; query: ${st.query || '(none)'}; device filters: ${Object.entries(st.device_filters).map(([k, v]) => `${k}=${v}`).join(' ') || 'none'}; ${st.rows} rows${st.truncated ? ` (device list cut at ${st.limit})` : ''}${st.fixture ? '; FIXTURE DATA, synthetic' : ''}`;
      lines.push(csvCell(title));
      const keys = rows.length ? Object.keys(rows[0]) : Object.keys(this.exportRow({}));
      lines.push(keys.join(','));
      for (const r of rows) lines.push(keys.map((k) => csvCell(r[k])).join(','));
      blob = new Blob([`${lines.join('\r\n')}\r\n`], { type: 'text/csv;charset=utf-8' });
    }
    const url = URL.createObjectURL(blob);
    const name = `jwicket-sessions-${safeName(st.device)}-${fileStamp(new Date())}.${kind}`;
    const a = this.h('a', { href: url, download: name, class: 'sr-only' });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 4000);
    this.ctx.ui.toast(`Exported ${this.fmt.plural(rows.length, 'session')} as ${kind.toUpperCase()} (${name}). Made in the browser from the last read.`, 'ok');
  }

  // ---- detail panel ----------------------------------------------------------------------------

  byId(id) {
    return this.current.find((r) => r.id === id) || this.ended.get(id) || null;
  }

  tryOpenWanted() {
    if (!this.wantSel || !this.payload) return;
    const id = this.wantSel;
    const r = this.byId(id);
    const table = this.payload.sessions;
    if (!r && !(table && table.status === 'ok')) return;
    this.wantSel = null;
    if (r) {
      const i = this.rows.findIndex((x) => x.id === id);
      if (i >= 0) this.list.scrollToIndex(i, 'center');
      this.openDetail(id);
    } else {
      this.ctx.ui.toast(`Session ${id} is not in the current list (it ended, or the filter excludes it).`, 'warn');
      this.selId = null;
      this.saveRoute(false);
    }
  }

  openDetail(id) {
    if (this.detail && this.detail.id === id) {
      this.detail.update();
      return;
    }
    const d = new SessionDetail(this, id);
    const title = `Session ${d.row ? d.row.session_id : id}`;
    if (this.detail && this.panelHandle && typeof this.panelHandle.setTitle === 'function') {
      // Moving through sessions (j / k) with the panel open: swap the content, keep the focus.
      this.detail.destroy();
      this.detail = d;
      this.detailHost.replaceChildren(d.el);
      this.panelHandle.setTitle(title);
      if (this.panelHandle.el) this.panelHandle.el.scrollTop = 0;
      d.update();
      return;
    }
    if (this.detail) this.detail.destroy();
    this.detail = d;
    this.detailHost = this.h('div', { class: 'sx-dhost' }, d.el);
    this.panelHandle = this.ctx.ui.panel({
      title,
      content: this.detailHost,
      wide: true,
      onClose: () => {
        const closedId = this.detail ? this.detail.id : id;
        if (this.detail) this.detail.destroy();
        this.detail = null;
        this.panelHandle = null;
        if (!this.dead) {
          const prev = this.selId;
          this.selId = null;
          this.saveRoute(false);
          if (prev) this.list.patchKey(prev);
          // The shell has put focus back on the opener if it still exists; when the opener was the
          // row (or a value in it) and the table has moved on, the session's row takes it.
          const a = document.activeElement;
          if (!a || a === document.body || !a.isConnected) {
            const node = this.list.nodeFor(closedId);
            if (node) node.focus({ preventScroll: true });
            else if (this.scroller.isConnected) this.scroller.focus({ preventScroll: true });
          }
        }
      },
    }) || null;
    d.update();
  }
}

// ---- the detail panel ------------------------------------------------------------------------------

class SessionDetail {
  constructor(view, id) {
    this.v = view;
    this.id = id;
    this.ctx = view.ctx;
    this.h = view.h;
    this.fmt = view.fmt;
    this.row = view.byId(id);
    this.lastSeen = this.row;
    this.sigs = {};
    this.build();
  }

  destroy() {
    if (this.flow) this.flow.destroy();
  }

  /** Rebuild a section only when sig changed; the focused control in it is focused again. */
  section(name, el, sig, build) {
    if (this.sigs[name] === sig) return false;
    this.sigs[name] = sig;
    swapKeepFocus(this.ctx.dom.put, el, ...[].concat(build()));
    return true;
  }

  filterBtn(key, value, label, cls) {
    const { h } = this;
    if (value === null || value === undefined || value === '') return h('span', { class: 'faint' }, DASH);
    return h(
      'span',
      { class: 'sx-dvw' },
      h('button', { class: ['sx-dv', cls], type: 'button', dataset: { fk: `${key}=${value}` }, title: `Filter sessions by ${key}:${value} (Alt-click: exclude)`, on: { click: (e) => this.v.addTerm(key, value, e.altKey) } }, label ?? String(value)),
      h('span', { class: 'sx-dvacts' }, h('button', { class: 'sx-dvx', type: 'button', dataset: { fk: `${key}!=${value}` }, title: `Exclude ${key}:${value}`, 'aria-label': `Exclude ${key} ${value}`, on: { click: () => this.v.addTerm(key, value, true) } }, '≠')),
    );
  }

  build() {
    const { h } = this;
    this.pillsEl = h('div', { class: 'sx-d-pills' });
    this.seenEl = h('p', { class: 'xsmall faint' }, '');
    this.msgEl = h('p', { class: 'sx-d-msg', hidden: true }, '');
    this.headEl = h('div', { class: 'sx-d-head' }, this.pillsEl, this.seenEl, this.msgEl);
    this.goneEl = h('div', { class: 'sx-d-gone', hidden: true });
    this.flow = new FlowDiagram({
      onFilter: (k, v, ex) => this.v.addTerm(k, v, ex),
      onPolicy: (name) => this.v.openPolicy(name),
    });
    this.rateEl = h('span', { class: 'sx-d-rate num' }, DASH);
    this.rateSub = h('span', { class: 'sx-d-ratesub' }, '');
    this.spark = new Sparkline({ height: 42, label: 'Bytes per second of this session, per poll', className: 'gold', area: false });
    // Until two polls have given a rate: a dashed baseline and how many polls so far.
    this.sparkPh = h('span', { class: 'sx-d-sparkph', 'aria-hidden': 'true' });
    this.sparkNote = h('p', { class: 'xsmall faint' }, '');
    this.upEl = h('b', { class: 'num' }, DASH);
    this.downEl = h('b', { class: 'num' }, DASH);
    this.wingsEl = h('div', { class: 'sx-d-wings' });
    // Timeout: text and bar updated in place.
    this.toLeft = h('span', { class: 'num strong' }, DASH);
    this.toOf = h('span', { class: 'muted' }, '');
    this.toAge = h('span', { class: 'muted' }, '');
    this.toBarI = h('i', null);
    this.toBar = h('span', { class: 'bar sx-d-tobar' }, this.toBarI);
    this.timeoutEl = h(
      'div',
      { class: 'sx-d-timeout' },
      h('div', { class: 'sx-d-tline' }, this.toLeft, this.toOf, h('span', { class: 'spacer' }), this.toAge),
      this.toBar,
      h('p', { class: 'xsmall faint' }, 'Idle timeout: the session expires when no packet arrives for this long. Traffic resets it.'),
    );
    this.kvEl = h('dl', { class: 'kv sx-d-kv' });
    this.extraEl = h('div', null);
    this.cliEl = h('div', { class: 'sx-d-cli' });
    this.actions = h('div', { class: 'sx-d-actions' });
    this.el = h(
      'div',
      { class: 'sx-detail' },
      this.headEl,
      this.goneEl,
      h('figure', { class: 'sx-d-flow', 'aria-label': 'Flow diagram' }, this.flow.el, h('figcaption', { class: 'xsmall faint' }, 'Click an address, zone or interface to filter by it (Alt-click excludes); the policy opens in Policies. Violet: changed by NAT.')),
      h(
        'section',
        { class: 'panel-section' },
        h('h3', null, 'Traffic'),
        h(
          'div',
          { class: 'sx-d-traffic' },
          h('div', { class: 'sx-d-ratebox' }, h('span', { class: 'sx-cap' }, 'Live rate'), this.rateEl, this.rateSub),
          h('div', { class: 'sx-d-spark' }, this.spark.el, this.sparkPh, this.sparkNote),
          h('div', { class: 'sx-d-totals' }, h('div', { class: 'sx-stat' }, this.upEl, h('span', null, '↑ from client')), h('div', { class: 'sx-stat' }, this.downEl, h('span', null, '↓ from server'))),
        ),
      ),
      h('section', { class: 'panel-section' }, h('h3', null, 'Both wings'), this.wingsEl),
      h('section', { class: 'panel-section' }, h('h3', null, 'Timeout'), this.timeoutEl),
      h('section', { class: 'panel-section' }, h('h3', null, 'Session'), this.kvEl),
      this.extraEl,
      h('section', { class: 'panel-section' }, h('h3', null, 'Next steps'), this.actions, this.cliEl),
    );
    this.actionsFor = null;
  }

  /**
   * Refresh from the view's latest data (after every poll while the panel is open). Numbers are
   * updated in place; a section is rebuilt only when what it shows changed, so the focused control
   * (a filter button, the policy link) keeps the focus and the panel's focus trap holds.
   */
  update() {
    const v = this.v;
    const r = v.byId(this.id);
    this.row = r;
    if (r) this.lastSeen = r;
    const shown = r || this.lastSeen;
    if (!shown) {
      this.goneEl.hidden = false;
      this.section('gone', this.goneEl, 'gone', () => this.ctx.dom.stateCard({ status: 'empty', title: `Session ${this.id} is not in the current list`, message: 'It ended, or the device filter excludes it.', compact: true }));
      return;
    }
    this.goneEl.hidden = true;
    const state = r ? (r._ended ? 'ended' : 'live') : 'gone';
    this.renderHead(shown, state);
    const z = shown._zones || {};
    this.flow.update(flowModel({ ...shown, _ended: state !== 'live' }, { from: z.from, to: z.to, position: v.policyPosition(shown.policy) }));
    this.renderTraffic(shown, state);
    this.renderWings(shown);
    this.renderTimeout(shown);
    this.renderKv(shown);
    this.renderExtra(shown);
    if (this.actionsFor !== shown.id) this.renderActions(shown);
  }

  renderHead(r, state) {
    const { h } = this;
    const fmt = this.fmt;
    const sig = JSON.stringify([state, this.v.paused, r.state, r.status, r._role, r._backup, r._backupWhy, r.location]);
    this.section('pills', this.pillsEl, sig, () => {
      const pills = [];
      if (state === 'live') pills.push(h('span', { class: 'live-badge' }, h('span', { class: 'dot', 'aria-hidden': 'true' }), this.v.paused ? 'PAUSED' : 'LIVE'));
      // Ended is closed, not denied: muted grey, never the deny red.
      else if (state === 'ended') pills.push(h('span', { class: 'pill muted' }, 'ENDED'));
      else pills.push(h('span', { class: 'pill muted' }, 'NOT LISTED'));
      if (r.state) pills.push(h('span', { class: ['pill', /^valid$/i.test(r.state) ? 'permit' : 'amber'] }, r.state));
      if (r.status) pills.push(h('span', { class: ['pill', /^normal$/i.test(r.status) ? 'muted' : 'amber'], title: 'Session status: Normal, or a NAT flag (Auth, Transparent, Expired)' }, r.status));
      if (r._role) pills.push(h('span', { class: ['pill', r._role === 'backup' ? 'muted' : 'sky'] }, `HA ${r._role}`));
      else if (r._backup) pills.push(h('span', { class: 'pill muted', title: r._backupWhy }, 'backup copy'));
      if (r.location) pills.push(h('span', { class: 'pill teal' }, r.location));
      return pills;
    });
    const k = this.v.known.get(r.id);
    this.seenEl.textContent = r._firstAt ? `first seen in this tab ${fmt.time(new Date(r._firstAt))} UTC${k ? ` · ${fmt.plural(k.polls, 'poll')}` : ''}` : '';
    const msg = state === 'ended'
      ? 'Gone from the table since the last poll: it closed or timed out. The values are the last ones read.'
      : state === 'gone'
        ? 'Not in the current list: it ended, or the device filter now excludes it. The values are the last ones read.'
        : '';
    this.msgEl.textContent = msg;
    this.msgEl.hidden = !msg;
  }

  renderTraffic(r, state) {
    const fmt = this.fmt;
    const k = this.v.known.get(r.id);
    const hist = k ? k.hist.slice() : [];
    this.rateEl.textContent = state !== 'live' || !Number.isFinite(r.rate) ? DASH : fmt.rate(r.rate);
    this.rateEl.classList.toggle('avg', state !== 'live' || !r._live);
    this.rateSub.textContent = state !== 'live' ? (state === 'ended' ? 'ended' : 'not listed') : r._live ? 'between the last two polls' : 'average since start (live rate after the next poll)';
    const enough = hist.length >= 3; // the sparkline draws from three points
    this.spark.el.hidden = !enough;
    this.sparkPh.hidden = enough;
    if (enough) this.spark.update(hist, { min: 0 });
    const polls = k ? k.polls : 1;
    const peak = hist.length ? ` · peak ${fmt.rate(Math.max(...hist))}` : '';
    this.sparkNote.textContent = enough || state !== 'live'
      ? `${fmt.plural(polls, 'poll')} in this tab${peak}` // the same count as the header line; rates are one fewer
      : `collecting · ${fmt.plural(polls, 'poll')}${peak}`;
    tick(this.upEl, fmt.bytes((r.in || {}).bytes));
    tick(this.downEl, fmt.bytes((r.out || {}).bytes));
  }

  renderWings(r) {
    const { h } = this;
    const fmt = this.fmt;
    const n = r.nat || {};
    const w = (x) => (x ? [x.direction, x.src, x.sport, x.dst, x.dport, x.iface, x.tunnel] : null);
    const sig = JSON.stringify([w(r.in), w(r.out), n.source, n.destination]);
    const rebuilt = this.section('wings', this.wingsEl, sig, () => {
      this.wingNums = [];
      const head = h('tr', null, ['Wing', 'Source', 'Destination', 'Interface', 'Packets', 'Bytes'].map((t, i) => h('th', { class: i >= 4 ? 'num-col' : null, scope: 'col' }, t)));
      const row = (label, wing, srcKey, dstKey) => {
        if (!wing) return h('tr', null, h('td', null, label), h('td', { colspan: '5', class: 'faint' }, 'no reverse wing (one-winged session)'));
        const pk = h('td', { class: 'num num-col' }, '');
        const by = h('td', { class: 'num num-col' }, '');
        this.wingNums.push([pk, by, label === '→ request' ? 'in' : 'out']);
        return h(
          'tr',
          null,
          h('td', null, h('span', { class: 'sx-wing' }, label), wing.direction ? h('span', { class: 'faint xsmall' }, ` ${wing.direction}`) : null),
          h('td', { class: 'mono' }, this.filterBtn(srcKey, wing.src, hp(wing.src, wing.sport), 'ip')),
          h('td', { class: 'mono' }, this.filterBtn(dstKey, wing.dst, hp(wing.dst, wing.dport), 'ip')),
          h('td', { class: 'mono' }, this.filterBtn('iface', wing.iface, wing.iface, 'iface'), wing.tunnel && wing.tunnel !== '0' ? h('span', { class: 'faint xsmall' }, ` tunnel ${wing.tunnel}`) : null),
          pk,
          by,
        );
      };
      return [
        h(
          'table',
          { class: 'table sx-d-table' },
          h('thead', null, head),
          h('tbody', null, row('→ request', r.in, 'src', 'dst'), row('← reply', r.out, n.destination ? 'natdst' : 'dst', n.source ? 'natsrc' : 'src')),
        ),
        h('p', { class: 'xsmall faint' }, 'The reply wing carries the translated addresses: under source NAT its destination is the translated source; under destination NAT its source is the real server.'),
      ];
    });
    for (const [pk, by, side] of this.wingNums || []) {
      const wing = r[side] || {};
      const p = fmt.num(wing.packets);
      const b = fmt.bytes(wing.bytes);
      if (rebuilt || pk.textContent !== p) pk.textContent = p;
      if (rebuilt || by.textContent !== b) by.textContent = b;
    }
  }

  renderTimeout(r) {
    const fmt = this.fmt;
    const cfg = Number(r.configured_timeout);
    const left = Number(r.timeout);
    const frac = cfg > 0 && Number.isFinite(left) ? Math.max(0, Math.min(1, left / cfg)) : null;
    this.toLeft.textContent = Number.isFinite(left) ? secs(left, fmt) : DASH;
    this.toOf.textContent = Number.isFinite(cfg) && cfg > 0 ? ` left of ${secs(cfg, fmt)}` : ' left';
    this.toAge.textContent = `age ${fmt.duration(r.duration)}`;
    this.toBar.hidden = frac === null;
    if (frac !== null) this.toBarI.style.setProperty('--w', `${Math.round(frac * 100)}%`);
    // Muted while there is time; amber when under a fifth of the configured timeout is left.
    this.toBar.classList.toggle('low', frac !== null && frac < 0.2);
  }

  renderKv(r) {
    const { h } = this;
    const fmt = this.fmt;
    const z = r._zones;
    const pos = this.v.policyPosition(r.policy);
    const sig = JSON.stringify([r.session_id || r.id, r.policy, r.policy_index, z && [z.from, z.to, z.fromText, z.toText], (r.in || {}).proto, r.application, r.state, r.status, r.location, pos]);
    const rebuilt = this.section('kv', this.kvEl, sig, () => {
      const pol = r.policy
        ? h(
          'span',
          { class: 'sx-dvw' },
          h('button', { class: 'policy-link', type: 'button', dataset: { fk: 'policy-open' }, title: `Open ${r.policy} in Policies`, on: { click: () => this.v.openPolicy(r.policy) } }, r.policy),
          h(
            'span',
            { class: 'sx-dvacts' },
            h('button', { class: 'sx-dvx eq', type: 'button', dataset: { fk: 'policy=' }, title: `Filter sessions by policy:${r.policy}`, 'aria-label': `Filter by policy ${r.policy}`, on: { click: () => this.v.addTerm('policy', r.policy, false) } }, '='),
            h('button', { class: 'sx-dvx', type: 'button', dataset: { fk: 'policy!=' }, title: `Exclude policy:${r.policy}`, 'aria-label': `Exclude policy ${r.policy}`, on: { click: () => this.v.addTerm('policy', r.policy, true) } }, '≠'),
          ),
        )
        : h('span', { class: 'faint' }, DASH);
      const zones = z
        ? h('span', null, z.from ? this.filterBtn('from', z.from, z.from, 'zone') : h('span', { class: 'faint' }, z.fromText), h('span', { class: 'sx-arr' }, ` ${ARROW} `), z.to ? this.filterBtn('to', z.to, z.to, 'zone') : h('span', { class: 'faint' }, z.toText))
        : h('span', { class: 'faint' }, r.policy ? 'not known (the policy is not in this scope’s inventory, or the inventory cannot be read)' : DASH);
      // The policy index is Junos' internal ID; the rule position (evaluation order) is separate.
      const idx = r.policy_index
        ? h('span', null, h('span', { class: 'mono', title: 'Junos policy index: an internal ID, not the position of the rule' }, `id ${r.policy_index}`),
          pos ? h('span', { class: 'faint' }, ` · rule ${pos.n} of ${pos.of} in ${pos.where}`) : null)
        : h('span', { class: 'faint' }, DASH);
      this.startEl = h('span', { class: 'mono' }, DASH);
      const pairs = [
        ['Session ID', h('span', { class: 'mono' }, r.session_id || r.id)],
        ['Policy', pol],
        ['Policy index', idx],
        ['Zones', zones],
        ['Protocol', this.filterBtn('proto', (r.in || {}).proto, (r.in || {}).proto, 'mono')],
        ['Application', this.filterBtn('app', r.application, r.application, 'mono')],
        ['State', h('span', null, r.state || DASH)],
        ['Status', h('span', null, r.status || DASH)],
        ['Location', r.location ? this.filterBtn('node', r.location, r.location, 'mono') : h('span', { class: 'faint' }, 'not reported (single node)')],
        ['Started', this.startEl],
      ];
      return pairs.flatMap(([k, v]) => [h('dt', null, k), h('dd', null, v)]);
    });
    // Start: the read time minus the session's age, in UTC; the device's own number in the tooltip.
    const readAt = this.v.payload && this.v.payload.meta ? Date.parse(this.v.payload.meta.read_at) : NaN;
    const start = Number.isFinite(readAt) && Number.isFinite(Number(r.duration)) ? new Date(readAt - Number(r.duration) * 1000) : null;
    const text = start ? fmt.stamp(start) : DASH;
    if (rebuilt || this.startEl.textContent !== text) this.startEl.textContent = text;
    this.startEl.title = `The read time minus the session's age.${r.start_time ? ` The device reports start time ${r.start_time} (seconds since boot on some releases, epoch seconds on others).` : ''}`;
  }

  renderExtra(r) {
    const { h } = this;
    const extra = Object.entries(r.extra || {});
    this.section('extra', this.extraEl, JSON.stringify(extra), () => (extra.length
      ? h(
        'section',
        { class: 'panel-section' },
        h('h3', null, 'More from the device'),
        h('dl', { class: 'kv sx-d-kv' }, extra.flatMap(([k, val]) => [h('dt', { class: 'mono' }, k), h('dd', { class: 'mono' }, val)])),
        h('p', { class: 'xsmall faint' }, 'Fields J-Wicket does not model yet, shown as the device sent them.'),
      )
      : []));
  }

  renderActions(r) {
    const { h } = this;
    const { icon } = this.ctx.dom;
    this.actionsFor = r.id;
    const sid = r.session_id || r.id;
    const node = nodeOf(r.location);
    const cli = `show security flow session session-identifier ${sid}${node !== null ? ` node ${node}` : ''}`;
    const a = r.in || {};
    const b = r.out || {};
    const z = r._zones;
    const proto = a.proto && /^(tcp|udp|icmp|icmp6|\d+)$/i.test(a.proto) ? a.proto.toLowerCase() : null;
    // Policy lookup happens after destination NAT: the policy sees the original source and the
    // translated destination.
    const dstIp = r.nat && r.nat.destination ? b.src : a.dst;
    const dstPort = r.nat && r.nat.destination ? b.sport : a.dport;
    const match = z && z.from && z.to && a.src && dstIp
      ? `show security match-policies from-zone ${z.from} to-zone ${z.to} source-ip ${a.src} destination-ip ${dstIp}${a.sport !== null && a.sport !== undefined ? ` source-port ${a.sport}` : ''}${dstPort !== null && dstPort !== undefined ? ` destination-port ${dstPort}` : ''}${proto ? ` protocol ${proto}` : ''}`
      : null;
    const copyBtn = (text, label, fk) => h('button', { class: 'btn ghost sm icon', type: 'button', title: label, 'aria-label': label, dataset: { fk }, on: { click: () => this.ctx.ui.copy(text, 'CLI command copied.') } }, icon('copy'));
    swapKeepFocus(this.ctx.dom.put, this.actions,
      r.policy ? h('button', { class: 'btn sm', type: 'button', dataset: { fk: 'act-policy' }, on: { click: () => this.v.openPolicy(r.policy) } }, icon('policies'), 'Open policy') : null,
      h('button', { class: 'btn sm', type: 'button', dataset: { fk: 'act-logs' }, title: `Logs with session id ${sid} (RT_FLOW create, close, deny)`, on: { click: () => this.ctx.navigate('logs', { q: `session:${sid}` }) } }, icon('logs'), 'Show logs for this session'),
      h('button', { class: 'btn sm primary', type: 'button', dataset: { fk: 'act-cli' }, on: { click: () => this.ctx.ui.copy(cli, 'CLI command copied.') } }, icon('terminal'), 'Copy as CLI'),
    );
    swapKeepFocus(this.ctx.dom.put, this.cliEl,
      h('p', { class: 'xsmall faint' }, 'This session on the device:'),
      h('code', { class: 'cli' }, cli, copyBtn(cli, 'Copy this command', 'cli-1')),
      match ? h('p', { class: 'xsmall faint' }, 'Which policy matches this flow (Junos evaluates; J-Wicket does not guess):') : null,
      match ? h('code', { class: 'cli' }, match, copyBtn(match, 'Copy this command', 'cli-2')) : null,
    );
  }
}
