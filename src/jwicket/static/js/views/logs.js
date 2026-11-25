// views/logs.js: the live log tail (UI brief, sections 5 and 9).
//
// Sources come from /api/logs/sources: syslog files (cursor tail), the on-box reporting database
// (live = move `start` forward and de-duplicate) and the routing-engine security log buffer (live =
// move `since` forward and de-duplicate). Lines are tokenised lazily (only when a row is drawn) and
// memoised per row; the stream is a variable-height virtual list so wrapped lines stay exact.
//
// The query bar is the shared engine: the device-capable part (substring contains/exclude for files,
// the report expression, start/stop/since) goes to the device and shows as gold chips; the rest
// filters here. J-Wicket's own NETCONF reads (UI_NETCONF_CMD for the signed-in user) are hidden by
// default and counted.
//
// Nothing read from the device is stored in the browser: lines live in memory for this view only.
// localStorage holds display preferences (wrap, compact, top values, window size, interval) only.
//
// Compact (the default) changes only what is painted: the stream shows HH:MM:SS.mmm with a divider row
// where the date changes, hides the RFC 5424 <pri>, "-" and SD-ID boilerplate (and the host while the
// window holds one host), and paints RT_FLOW lines as a summary (5-tuple, policy, zones, NAT, reason)
// followed by the remaining fields. Copy line, the decoded panel and the tokenizer stay exact.

import { Histogram, clock } from '../widgets/histogram.js';

const ICON = 'M5 5.5h14M5 9.5h9M5 13.5h14M5 17.5h6M15 17.5h4';
const INTERVALS = [2, 5, 10, 30];
const WINDOWS = [2000, 5000, 10000];
const DEFAULT_WINDOW = 5000;
const API_MAX_LINES = 2000;
const REPORT_COUNT = 1000;
const FAIL_BACKOFF_S = 10;
const SOURCES_RETRY_S = 30; // the log configuration stayed busy (429s): read it again by itself
// A refilter checks lines newest first for at most this long; the new lines of one read for at most
// APPEND_BUDGET_MS. A slow pattern then leaves older lines unchecked (and says so) instead of freezing
// the tab (LOG-02; query.regexRisk refuses the worst patterns first).
const FILTER_BUDGET_MS = 150;
const APPEND_BUDGET_MS = 50;
const PREF = {
  wrap: 'jwicket.logs.wrap',
  compact: 'jwicket.logs.compact',
  facets: 'jwicket.logs.facets',
  window: 'jwicket.logs.window',
  interval: 'jwicket.logs.interval',
  zone: 'jwicket.logs.zone',
};
// Close-reason group -> pill colour. The 28 reasons are Junos's documented ones (Session Close Log
// Fields, Table 2); the grouping is J-Wicket's own (inferred), see logparse.CLOSE_REASONS.
const CR_PILL = { normal: 'teal', reset: 'amber', timeout: 'muted', error: 'deny', admin: 'sky', other: 'muted' };
const IDLE_LABEL = 'Live reads paused: no activity. Move the pointer or press a key to resume.';
const CLICKABLE = new Set(['ip', 'port', 'proto', 'zone', 'policy', 'iface', 'nat', 'num', 'str', 'bad', 'good', 'user', 'val', 'tag', 'daemon', 'host', 'pid']);
const FLOW_FAMS = new Set(['create', 'close', 'deny']);
const SEP = ' \u00b7 ';
const OVERSCAN = 10;
const PARSE_SLICE = 300;
const PROBE_CHARS = 24;
const GUTTER_PX = 30; // .lg-row padding-left + padding-right, kept in step with logs.css
const NARROW_MQ = '(max-width: 640px)';
const LINE_CAP = 4000; // characters painted per line in the stream; the panel and Copy line keep it all
const CTL_EXTRA = 5; // a control character paints as "U+XXXX": five columns more than it takes
const NEW_WASH_MAX = 6; // a read with more new lines flashes the gutter only
const NEW_MS = 1000;
const FACET_MIN_MS = 900;
// row.fs bits: which window totals a row is counted in (kept so trimming can subtract it again)
const FS_SELF = 1;
const FS_COUNT = 2;
const FS_HIST = 4;
const FS_VIS = 8;
const FS_MATCH = 16;
// Top values over the filtered window: [id, label, query key]
const FACETS = [
  ['src', 'Sources', 'src'],
  ['dst', 'Destinations', 'dst'],
  ['dport', 'Destination ports', 'dport'],
  ['policy', 'Policies', 'policy'],
  ['reason', 'Reasons', 'reason'],
  ['pair', 'Zone pairs', null],
];
const FACET_TOP = 8;
const REPORT_FAMILY = { 'session-close': 'close', 'session-create': 'create', 'session-deny': 'deny', screen: 'screen', 'idp-all': 'idp', 'utm-all': 'idp', threat: 'idp', 'ipsec-vpn': 'vpn' };
const AGES = [['15m', '15 min'], ['1h', '1 h'], ['24h', '24 h']];
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const WEEKDAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

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

function prefGet(key) {
  try {
    return window.localStorage.getItem(key);
  } catch (_err) {
    return null;
  }
}

function prefSet(key, value) {
  try {
    window.localStorage.setItem(key, String(value));
  } catch (_err) {
    // storage blocked: the preference lasts for this page only
  }
}

function pad2(n) {
  return String(n).padStart(2, '0');
}

const REDUCED = typeof matchMedia === 'function' ? matchMedia('(prefers-reduced-motion: reduce)') : null;

/** Counter text with the shell's tick motion, through the Web Animations API (no forced reflow). */
function tick(el, text) {
  if (el.textContent === text) return;
  el.textContent = text;
  if ((REDUCED && REDUCED.matches) || typeof el.animate !== 'function') return;
  el.animate([{ transform: 'translateY(-35%)', opacity: 0.25 }, { transform: 'none', opacity: 1 }], { duration: 260, easing: 'cubic-bezier(.2,.7,.2,1)' });
}

// ---- device time zone (LG-02) -------------------------------------------------------------------------

const ZONE_FMT = new Map();
const ZONE_OFF = new Map();

function zoneFormat(zone) {
  if (!ZONE_FMT.has(zone)) {
    let f = null;
    try {
      f = new Intl.DateTimeFormat('en-US', { timeZone: zone, hour12: false, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch (_err) {
      f = null;
    }
    ZONE_FMT.set(zone, f);
  }
  return ZONE_FMT.get(zone);
}

/** Milliseconds `zone` is ahead of UTC at the instant `utcMs` (cached per quarter hour), through Intl. */
function zoneOffset(utcMs, zone) {
  const f = zoneFormat(zone);
  if (!f || !Number.isFinite(utcMs)) return 0;
  const key = `${zone}|${Math.floor(utcMs / 900000)}`;
  const hit = ZONE_OFF.get(key);
  if (hit !== undefined) return hit;
  const whole = Math.floor(utcMs / 1000) * 1000;
  const p = {};
  for (const part of f.formatToParts(new Date(whole))) p[part.type] = part.value;
  const asUtc = Date.UTC(Number(p.year), Number(p.month) - 1, Number(p.day), Number(p.hour) % 24, Number(p.minute), Number(p.second));
  const off = asUtc - whole;
  if (ZONE_OFF.size > 4000) ZONE_OFF.clear();
  ZONE_OFF.set(key, off);
  return off;
}

/** "UTC+1", "UTC\u22125:30" for an offset in ms. */
function utcOffsetLabel(ms) {
  const m = Math.round(ms / 60000);
  const a = Math.abs(m);
  return `UTC${m >= 0 ? '+' : '\u2212'}${Math.floor(a / 60)}${a % 60 ? `:${pad2(a % 60)}` : ''}`;
}

function isoNoZone(ms) {
  return new Date(ms).toISOString().slice(0, 19);
}

function reportStart(ms) {
  return isoNoZone(ms);
}

function bufferSince(ms) {
  const iso = isoNoZone(ms);
  return `${iso.slice(0, 10)}.${iso.slice(11, 19)}`;
}

/** "HH:MM:SS" or "HH:MM:SS.mmm" (UTC) for the compact time column. */
function shortClock(ms, withMs) {
  const d = new Date(ms);
  const base = `${pad2(d.getUTCHours())}:${pad2(d.getUTCMinutes())}:${pad2(d.getUTCSeconds())}`;
  return withMs ? `${base}.${String(d.getUTCMilliseconds()).padStart(3, '0')}` : base;
}

function dayKey(ms) {
  return Math.floor(ms / 86400000);
}

function dayLabel(ms) {
  const d = new Date(ms);
  return `${WEEKDAYS[d.getUTCDay()]} ${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}`;
}

function hostOnly(v) {
  if (v === null || v === undefined) return null;
  const s = String(v).trim();
  if (!s || /^(?:N\/A|NA|None|NONE|UNKNOWN|unknown|-|0x0)$/.test(s)) return null;
  const slash = s.indexOf('/');
  return slash > 0 ? s.slice(0, slash) : s;
}

function stampMs(ms, withMs = true) {
  const d = new Date(ms);
  const base = `${d.getUTCFullYear()}-${pad2(d.getUTCMonth() + 1)}-${pad2(d.getUTCDate())} ${pad2(d.getUTCHours())}:${pad2(d.getUTCMinutes())}:${pad2(d.getUTCSeconds())}`;
  return withMs ? `${base}.${String(d.getUTCMilliseconds()).padStart(3, '0')}` : base;
}

/** Whether the line's own timestamp carries a fraction of a second (BSD lines usually do not). */
function hasMs(p) {
  return Boolean(p && p.ts && /[:.]\d\d\.\d/.test(p.ts));
}

const SAFE_VALUE = /^[A-Za-z0-9._\-/*@:]+$/;
const SAFE_FREE = /^[A-Za-z0-9._\-/*@]+$/;

/** Query text for a value: bare when the grammar reads it back unchanged, quoted otherwise. */
function quoteValue(v, keyed) {
  const s = String(v);
  const ok = keyed ? SAFE_VALUE : SAFE_FREE;
  if (s && ok.test(s) && !/^[-!]/.test(s) && !/^(and|or|not)$/i.test(s)) return s;
  return `"${s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

function termText(key, value) {
  return key ? `${key}:${quoteValue(value, true)}` : quoteValue(value, false);
}

function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function safeName(s) {
  return String(s || '').toLowerCase().replace(/[^a-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 48) || 'x';
}

function csvCell(v) {
  if (v === null || v === undefined) return '';
  let s = String(v);
  // Spreadsheet formula injection: a cell that starts with = + - @ (or a control) is text.
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

const PLACEHOLDER = /^(?:N\/A|NA|None|NONE|UNKNOWN|unknown|-|0x0|)$/;
const isPlaceholder = (v) => v === undefined || v === null || PLACEHOLDER.test(String(v).trim());

function sessionIdOf(p) {
  const fromFlow = p.flow && Number.isFinite(p.flow.sessionId) ? p.flow.sessionId : null;
  const raw = fromFlow !== null ? fromFlow : Number((p.fields && (p.fields['session-id'] || p.fields['session-id-32'])) || NaN);
  return Number.isFinite(raw) && raw > 0 ? raw : null;
}

/** Buffer events carry fields the rendered line does not: fold them into a parse result copy. */
function withEvent(p, ev, severities) {
  if (!ev) return p;
  const f = { ...(p.fields || {}) };
  const put = (k, v) => {
    if (v !== null && v !== undefined && v !== '' && f[k] === undefined) f[k] = String(v);
  };
  put('source-address', ev.src);
  put('source-port', ev.sport);
  put('destination-address', ev.dst);
  put('destination-port', ev.dport);
  put('policy-name', ev.policy);
  put('protocol', ev.protocol);
  put('interface-name', ev.interface);
  put('username', ev.user);
  put('result', ev.result);
  let severity = p.severity;
  if (!Number.isInteger(severity) && ev.severity) {
    const i = severities.indexOf(String(ev.severity).toLowerCase());
    if (i >= 0) severity = i;
  }
  return { ...p, fields: f, severity };
}

// ---- the stream: a variable-height virtual list ----------------------------------------------------

class LineList {
  constructor(scroller, { render, onScroll, h }) {
    this.sc = scroller;
    this.renderRow = render;
    this.onScroll = onScroll;
    this.body = h('div', { class: 'lg-body', role: 'rowgroup' });
    this.probe = h('span', { class: 'lg-probe', 'aria-hidden': 'true' }, '0'.repeat(PROBE_CHARS));
    scroller.append(this.body, this.probe);
    this.items = [];
    this.tops = new Float64Array(1);
    this.lh = 20;
    this.markerH = 30;
    this.dayH = 20;
    this.wrapPad = 4;
    this.wrap = false;
    this.twoLine = false; // compact + wrap at phone width: the head (time, tag) on a line of its own
    this.wantEnd = false;
    this.ch = 7.2;
    this.cpl = 160;
    this.maxLen = 0;
    this.nodes = new Map();
    this.range = { start: 0, end: -1, first: 0, last: -1 };
    this.programmatic = 0;
    this.viewH = 0;
    this._raf = 0;
    this._onScroll = () => {
      this._schedule();
      if (this.onScroll) this.onScroll(Date.now() - this.programmatic < 120);
    };
    scroller.addEventListener('scroll', this._onScroll, { passive: true });
    this._ro = typeof ResizeObserver === 'function' ? new ResizeObserver(() => this.measure()) : null;
    if (this._ro) this._ro.observe(scroller);
    this.measure();
  }

  _schedule() {
    if (this._raf) return;
    this._raf = requestAnimationFrame(() => {
      this._raf = 0;
      if (this.wantEnd) {
        // Once per frame, after every height write: one layout, not one per call.
        this.wantEnd = false;
        this.pendingDy = 0;
        this.setScroll(Number.MAX_SAFE_INTEGER);
      } else if (this.pendingDy) {
        const dy = this.pendingDy;
        this.pendingDy = 0;
        this.setScroll(this.sc.scrollTop + dy);
      } else {
        this.reconcile(false);
      }
    });
  }

  /** Painted length (row.pl) and, for two-line rows, the head's length (row.ph) come from the view. */
  heightOf(row) {
    if (row.marker) return row.marker.kind === 'day' ? this.dayH : this.markerH;
    if (!this.wrap) return this.lh;
    const len = row.pl === undefined ? row.len : row.pl;
    let lines;
    // Two-line rows: the head, then one line of summary (cut with an ellipsis; the panel has it all).
    if (this.twoLine && row.ph) lines = Math.max(1, Math.ceil(row.ph / this.cpl)) + 1;
    else lines = Math.max(1, Math.ceil(len / this.cpl));
    return lines * this.lh + this.wrapPad;
  }

  measure() {
    if (!this.body) return;
    const cs = getComputedStyle(this.sc);
    this.viewH = this.sc.clientHeight;
    const lh = parseFloat(cs.getPropertyValue('--lg-lh')) || 20;
    const ch = this.probe.getBoundingClientRect().width / PROBE_CHARS || this.ch;
    const avail = Math.max(120, this.sc.clientWidth - GUTTER_PX - 2);
    const cpl = Math.max(24, Math.floor(avail / ch - 0.5));
    const changed = lh !== this.lh || Math.abs(ch - this.ch) > 0.005 || (this.wrap && cpl !== this.cpl);
    this.lh = lh;
    this.ch = ch;
    this.cpl = cpl;
    this.body.style.setProperty('--lg-cpl', String(cpl));
    if (changed) this.relayout();
    else this._schedule();
  }

  setWrap(on, twoLine = this.twoLine) {
    this.wrap = Boolean(on);
    this.twoLine = Boolean(twoLine);
    this.body.classList.toggle('is-wrap', this.wrap);
    this.body.classList.toggle('is-two', this.wrap && this.twoLine);
    this.measure();
    this.relayout();
  }

  /** Keep the first visible row where it is while every height is recomputed. */
  relayout() {
    const anchor = this.anchor();
    this.recompute(0);
    this.reconcile(true);
    if (anchor) this.restore(anchor);
  }

  anchor() {
    const n = this.items.length;
    if (!n) return null;
    const i = this.indexAt(this.sc.scrollTop);
    const row = this.items[i];
    return row ? { seq: row.seq, offset: this.tops[i] - this.sc.scrollTop, atEnd: this.atEnd() } : null;
  }

  restore(anchor, indexOf) {
    if (!anchor) return;
    if (anchor.atEnd) {
      this.scrollToEnd();
      return;
    }
    const i = indexOf ? indexOf(anchor.seq) : this.items.findIndex((r) => r.seq === anchor.seq);
    if (i < 0) return;
    this.setScroll(this.tops[i] - anchor.offset);
  }

  recompute(from) {
    const n = this.items.length;
    if (this.tops.length < n + 1) {
      const next = new Float64Array(Math.max(n + 1, this.tops.length * 2));
      next.set(this.tops.subarray(0, Math.min(this.tops.length, from + 1)));
      this.tops = next;
    }
    const start = Math.max(0, Math.min(from, n));
    if (start === 0) {
      this.tops[0] = 0;
      this.maxLen = 0;
    }
    for (let i = start; i < n; i += 1) {
      const row = this.items[i];
      this.tops[i + 1] = this.tops[i] + this.heightOf(row);
      const len = row.pl === undefined ? row.len : row.pl;
      if (!row.marker && len > this.maxLen) this.maxLen = len;
    }
    this.body.style.height = `${this.tops[n]}px`;
    this.body.style.setProperty('--lg-maxch', String(Math.max(40, this.maxLen)));
  }

  /** New items: every drawn row is dropped and the visible ones are drawn on the next frame. */
  setItems(items) {
    this.items = items;
    this.recompute(0);
    for (const node of this.nodes.values()) node.remove();
    this.nodes.clear();
    this._schedule();
  }

  /** Rows were pushed to the end of `items` starting at index `from`. */
  appended(from, { draw = true } = {}) {
    this.recompute(from);
    if (draw) this.reconcile(false);
  }

  indexAt(y) {
    const n = this.items.length;
    if (!n) return 0;
    let lo = 0;
    let hi = n - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (this.tops[mid] <= y) lo = mid;
      else hi = mid - 1;
    }
    return lo;
  }

  /** Draw the rows in (and near) the viewport. `scrollTop` may be passed when it was just set. */
  reconcile(rerender, scrollTop) {
    if (!this.body) return;
    const n = this.items.length;
    if (rerender) {
      for (const node of this.nodes.values()) node.remove();
      this.nodes.clear();
    }
    if (!n) {
      for (const node of this.nodes.values()) node.remove();
      this.nodes.clear();
      this.range = { start: 0, end: -1, first: 0, last: -1 };
      return;
    }
    const top = scrollTop === undefined ? this.sc.scrollTop : scrollTop;
    const view = this.viewH || this.sc.clientHeight || 400;
    const first = this.indexAt(top);
    const last = this.indexAt(top + view - 1);
    const start = Math.max(0, first - OVERSCAN);
    const end = Math.min(n - 1, last + OVERSCAN);
    const want = new Set();
    for (let i = start; i <= end; i += 1) want.add(this.items[i].seq);
    for (const [seq, node] of this.nodes) {
      if (!want.has(seq)) {
        node.remove();
        this.nodes.delete(seq);
      }
    }
    let prev = null;
    for (let i = start; i <= end; i += 1) {
      const row = this.items[i];
      let node = this.nodes.get(row.seq);
      if (!node) {
        node = this.renderRow(row);
        this.nodes.set(row.seq, node);
        if (prev) prev.after(node);
        else this.body.prepend(node);
      }
      const y = this.tops[i];
      const hh = this.tops[i + 1] - y;
      if (node._y !== y) {
        node.style.top = `${y}px`;
        node._y = y;
      }
      if (node._h !== hh) {
        node.style.height = `${hh}px`;
        node._h = hh;
      }
      if (node._ix !== i) {
        node.setAttribute('aria-rowindex', String(i + 1));
        node._ix = i;
      }
      prev = node;
    }
    this.range = { start, end, first, last };
  }

  /** Re-render the node of one row, if it is drawn. */
  refreshRow(row) {
    const node = this.nodes.get(row.seq);
    if (!node) return;
    const next = this.renderRow(row);
    next.style.top = node.style.top;
    next.style.height = node.style.height;
    next._y = node._y;
    next._h = node._h;
    next._ix = node._ix;
    next.setAttribute('aria-rowindex', node.getAttribute('aria-rowindex') || '');
    node.replaceWith(next);
    this.nodes.set(row.seq, next);
  }

  nodeOf(seq) {
    return this.nodes.get(seq) || null;
  }

  setScroll(y) {
    this.wantEnd = false;
    this.programmatic = Date.now();
    const n = this.items.length;
    const max = Math.max(0, (this.tops[n] || 0) - (this.viewH || this.sc.clientHeight));
    const next = Math.max(0, Math.min(max, y));
    this.sc.scrollTop = next;
    this.reconcile(false, next);
  }

  scrollToIndex(i, align = 'nearest') {
    const n = this.items.length;
    if (!n) return;
    const idx = Math.max(0, Math.min(n - 1, i));
    const y = this.tops[idx];
    const hh = this.tops[idx + 1] - y;
    const view = this.sc.clientHeight;
    const cur = this.sc.scrollTop;
    let next = cur;
    if (align === 'center') next = y - (view - hh) / 2;
    else if (align === 'start') next = y;
    else if (y < cur) next = y - 4;
    else if (y + hh > cur + view) next = y + hh - view + 4;
    if (next !== cur) this.setScroll(next);
  }

  /** Moves the scroll position by `dy` px on the next frame (rows above the viewport went away). */
  nudge(dy) {
    if (!dy) return;
    this.pendingDy = (this.pendingDy || 0) + dy;
    this._schedule();
  }

  /** Scrolls to the newest row on the next frame (several calls in one task scroll once). */
  scrollToEnd() {
    this.wantEnd = true;
    this._schedule();
  }

  atEnd(slack = 24) {
    if (this.wantEnd) return true;
    const total = this.tops[this.items.length] || 0;
    return this.sc.scrollTop + (this.viewH || this.sc.clientHeight) >= total - slack;
  }

  destroy() {
    if (this._raf) cancelAnimationFrame(this._raf);
    this.sc.removeEventListener('scroll', this._onScroll);
    if (this._ro) this._ro.disconnect();
    this.nodes.clear();
    this.body.remove();
    this.probe.remove();
    this.body = null;
  }
}

// ---- the view ---------------------------------------------------------------------------------------

class LogsView {
  constructor(el, ctx) {
    this.el = el;
    this.ctx = ctx;
    this.dom = ctx.dom;
    this.fmt = ctx.format;
    this.q = ctx.query;
    this.lp = ctx.logparse;
    this.dead = false;
    this.timers = { poll: 0, ago: 0, sources: 0 };
    this.offs = [];
    this.sources = null; // /api/logs/sources payload (sources)
    this.sourceList = [];
    this.src = null;
    this.reportType = 'session-all';
    this.rows = [];
    this.bySeq = new Map();
    this.seen = new Map();
    this.visible = [];
    this.seq = 0;
    this.readGen = 0;
    this.cursor = null;
    this.newest = null; // ms of the newest line read (report, buffer)
    this.meta = null;
    this.lastRead = null; // {at, ok, message}
    this.deviceInfo = null; // {window, dropped, returned} for files; {returned, limited} otherwise
    this.inflight = false;
    this.abort = null;
    this.failed = null; // a state that stops the tail: {status, message, title}
    this.notice = null; // a transient problem with the last poll
    this.paused = false;
    this.follow = true;
    this.unseen = 0;
    this.selSeq = null;
    this.curSeq = null;
    this.showSelf = false;
    this.selfHidden = 0;
    this.famOff = new Set();
    this.famCounts = null;
    this.denyReasons = new Set(); // reason values seen on DENY lines: never shown as close reasons
    this.hist = { times: [], series: [] };
    this.queryText = '';
    this.plan = null;
    this.deviceKey = '';
    this.pred = () => true;
    this.predTime = () => true;
    this.timeRange = null;
    this.markRe = null;
    this.matchCount = 0;
    this.hints = null;
    this.hintGen = 0;
    this.readAs = (ctx.store.session && ctx.store.session.user) || '';
    this.panelSeq = null;
    this.reopening = false;
    this.narrowMq = typeof matchMedia === 'function' ? matchMedia(NARROW_MQ) : null;
    this.narrow = Boolean(this.narrowMq && this.narrowMq.matches);
    // Phone width defaults to Compact + Wrap (two-line rows); a stored choice wins.
    const wrapPref = prefGet(PREF.wrap);
    this.wrap = wrapPref === null ? this.narrow : wrapPref === '1';
    this.compact = prefGet(PREF.compact) !== '0';
    const facetPref = prefGet(PREF.facets);
    this.facetsOn = facetPref === null ? typeof innerWidth !== 'number' || innerWidth >= 1280 : facetPref === '1';
    this.facets = FACETS.map(() => new Map());
    this.facetsAt = 0;
    this.hostCounts = new Map();
    this.singleHost = null;
    this.pkey = '';
    this.filterGen = 0;
    this.reportOk = new Set();
    this.famsExpanded = false;
    this.clockChecked = false;
    this.fields = null;
    const w = Number(prefGet(PREF.window));
    this.windowMax = WINDOWS.includes(w) ? w : DEFAULT_WINDOW;
    const iv = Number(prefGet(PREF.interval));
    this.interval = INTERVALS.includes(iv) ? iv : 5;
    this.whereOpen = false;
    this.whereAuto = true;
    this.firstDone = false; // a read of this source has been ingested (LOG-09)
    this.limited = null; // 429s in a row on this source: { src, n, reason, since, interval, retryAfter } (LOG-07)
    this.unchecked = []; // rows (oldest first) the last refilter's time budget did not reach (LOG-02)
    this.filterCut = null; // that refilter: { ms, checked, total, time }
    this.appendCut = []; // new lines whose filter ran out of time (live then pauses)
    this.idle = Boolean(ctx.ui.isIdle?.()); // the shell's idle pause (SL-08)
    this.zoneOn = prefGet(PREF.zone) === '1'; // show times in the configured device zone (LG-02)
    this.zoneName = null; // that zone while the toggle is on and the zone is convertible

    if (!this.q || !this.lp) {
      el.append(
        this.dom.stateCard({
          status: 'failed',
          title: 'The log engines did not load',
          message: 'query.js or logparse.js failed to load, so lines cannot be parsed or filtered.',
          hint: 'Reload the page. If it keeps failing, the J-Wicket build on this device may be incomplete.',
        }),
      );
      this.broken = true;
      return;
    }
    this.families = this.lp.FAMILIES.map((f) => ({ id: f.id, label: f.label }));
    this.famIndex = new Map(this.families.map((f, i) => [f.id, i]));
    this.fields = this.logFields();
    this.zoneName = this.activeZone();
    this.build();
    this.bind();
    this.readRoute(ctx.route, true);
    this.updateHints();
    this.loadSources();
  }

  // ---- layout -------------------------------------------------------------------------------------

  build() {
    const { h, icon } = this.dom;
    this.el.classList.add('view-fill', 'lg-view');

    this.subEl = h('p', { class: 'view-sub lg-sub' }, 'Reading the log configuration\u2026');
    this.srcGroup = h('div', { class: 'lg-sources', role: 'group', 'aria-label': 'Log source' });
    this.typeSel = h('select', { class: 'lg-select lg-type', 'aria-label': 'Report type', hidden: true, on: { change: () => this.setReportType(this.typeSel.value) } });
    this.whereBtn = h('button', { class: 'lg-where-btn', type: 'button', 'aria-expanded': 'false', 'aria-controls': 'lg-where', on: { click: () => this.toggleWhere() } });
    this.livePill = h('button', { class: 'live-pill', type: 'button', on: { click: () => this.togglePause() } });
    this.ivSeg = h(
      'div',
      { class: 'seg lg-iv', role: 'group', 'aria-label': 'Read every' },
      INTERVALS.map((s) =>
        h('button', { type: 'button', dataset: { s }, 'aria-pressed': 'false', title: `Read every ${s} s`, on: { click: () => this.setInterval(s) } }, `${s}s`),
      ),
    );
    this.exportBtn = h(
      'button',
      { class: 'btn', type: 'button', 'aria-haspopup': 'menu', 'aria-expanded': 'false', title: 'Export the filtered lines (made in this browser, no device read)', on: { click: () => this.toggleExportMenu() } },
      icon('download'),
      h('span', { class: 'lg-btn-label' }, 'Export'),
    );
    this.exportWrap = h('div', { class: 'lg-menu-wrap' }, this.exportBtn);
    const refresh = h(
      'button',
      { class: 'btn icon', type: 'button', title: 'Read the source again from the start (r)', 'aria-label': 'Read again', on: { click: () => this.refresh(true) } },
      icon('refresh'),
    );
    this.head = h(
      'header',
      { class: 'view-head lg-head' },
      h('div', { class: 'lg-titles' }, h('h1', { class: 'view-title' }, 'Logs'), this.subEl),
      h('div', { class: 'view-actions lg-actions' }, this.livePill, this.ivSeg, this.exportWrap, refresh),
    );
    this.srcRow = h('div', { class: 'lg-srcrow' }, this.srcGroup, this.typeSel, this.whereBtn);

    this.whereEl = h('section', { id: 'lg-where', class: 'lg-where', 'aria-label': 'Where traffic logs are', hidden: true });

    this.bar = this.ctx.QueryBar
      ? new this.ctx.QueryBar({
          view: 'logs',
          value: '',
          placeholder: 'Filter lines: words, tag:RT_FLOW_SESSION_DENY, src:10.10.0.0/16, -dport:53, sev>=warning, /regex/',
          label: 'Filter log lines',
          onChange: (text, parsed) => this.onQuery(text, parsed),
          getContext: () => ({ rows: this.rowsForSuggest(), inventory: this.ctx.store.lastInventory }),
        })
      : null;
    const k = (x) => h('kbd', null, x);
    this.queryHint = h(
      'p',
      { class: 'lg-qhint' },
      h('span', { class: 'lg-qh-wide' }, 'Click any value in a line to filter by it, ', k('Alt'), '-click to exclude'),
      h('span', { class: 'lg-qh-narrow' }, 'Tap a value to filter by it; open a line for = and \u2260'),
      h('span', { class: 'lg-qh-wide' }, k('n'), ' ', k('N'), ' next and previous match'),
      h('span', { class: 'lg-qh-wide' }, k('f'), ' follow'),
      h('span', { class: 'lg-qh-wide' }, 'drag the chart to pick a time range'),
    );
    this.queryEl = h('div', { class: 'lg-query' }, this.bar ? this.bar.el : null, this.queryHint);

    // timeline: family toggles (also the histogram legend), time presets and the histogram
    this.famEl = h('div', { class: 'lg-fams', role: 'group', 'aria-label': 'Event families: click to show only one (again: all), Alt-click to hide one, Shift-click to add or remove one' });
    this.famBtns = new Map();
    for (const f of this.families) {
      const count = h('span', { class: 'lg-fam-n' }, '0');
      const btn = h(
        'button',
        {
          class: ['lg-fam', `fam-${f.id}`],
          type: 'button',
          'aria-pressed': 'true',
          dataset: { fam: f.id },
          on: { click: (e) => this.toggleFamily(f.id, e) },
        },
        h('span', { class: 'lg-fam-sw', 'aria-hidden': 'true' }),
        h('span', { class: 'lg-fam-label' }, f.label),
        count,
      );
      this.famBtns.set(f.id, { btn, count });
      this.famEl.append(btn);
    }
    this.famMore = h('button', { class: 'lg-fam lg-fam-more', type: 'button', 'aria-expanded': 'false', on: { click: () => { this.famsExpanded = !this.famsExpanded; this.renderFams(); } } });
    this.famEl.append(this.famMore);
    this.rangeEl = h('div', { class: 'lg-range' });
    // LG-02: offered only when the configured device zone is one this browser can convert to.
    this.zoneBtn = h('button', { class: 'lg-zone-btn', type: 'button', 'aria-pressed': 'false', hidden: true, on: { click: () => this.toggleZone() } });
    this.ageSeg = h(
      'div',
      { class: 'seg lg-ages', role: 'group', 'aria-label': 'Time range' },
      AGES.map(([v, label]) => h('button', { type: 'button', dataset: { age: v }, 'aria-pressed': 'false', title: `Only the last ${label} (age<${v}); report and buffer sources ask the device for it`, on: { click: () => this.setAge(v) } }, label)),
      h('button', { type: 'button', dataset: { age: 'custom' }, 'aria-pressed': 'false', title: 'Type a time range: adds time>= and time<= to the query (or drag across the chart)', on: { click: () => this.customRange() } }, 'Custom'),
      h('button', { type: 'button', dataset: { age: 'all' }, 'aria-pressed': 'true', title: 'Every line in the window', on: { click: () => this.setAge(null) } }, 'All'),
    );
    this.histogram = new Histogram({
      series: this.families,
      label: 'Log lines over time, stacked by event family',
      unit: 'line',
      legend: true,
      onBrush: (r) => this.onBrush(r),
    });
    this.timeline = h(
      'section',
      { class: 'tile lg-timeline', 'aria-label': 'Timeline' },
      h('div', { class: 'lg-tl-head' }, this.famEl, h('div', { class: 'lg-tl-side' }, this.rangeEl, this.zoneBtn, this.ageSeg)),
      h('div', { class: 'lg-tl-legend' }, this.histogram.legendEl),
      this.histogram.el,
    );

    // stream
    this.countEl = h('span', { class: 'lg-count' });
    this.hostEl = h('span', { class: 'lg-hostchip', hidden: true });
    this.matchEl = h('span', { class: 'lg-matchnav', hidden: true });
    this.selfEl = h('span', { class: 'lg-selfwrap' });
    this.followBtn = h('button', { class: 'btn sm lg-follow', type: 'button', title: 'Follow the newest line (f)', on: { click: () => this.toggleFollow() } }, icon('arrow', { class: 'lg-down' }), h('span', { class: 'lg-btn-label' }, 'Follow'));
    this.compactBtn = h(
      'button',
      { class: 'btn sm', type: 'button', title: 'Compact (c): short times, no repeated header, RT_FLOW lines as a summary. Copy line and the decoded panel keep the exact line.', 'aria-pressed': this.compact ? 'true' : 'false', on: { click: () => this.toggleCompact() } },
      icon('menu'),
      h('span', { class: 'lg-btn-label' }, 'Compact'),
    );
    this.wrapBtn = h('button', { class: 'btn sm', type: 'button', title: 'Wrap long lines (w)', 'aria-pressed': this.wrap ? 'true' : 'false', on: { click: () => this.toggleWrap() } }, icon('rows'), h('span', { class: 'lg-btn-label' }, 'Wrap'));
    this.facetsBtn = h(
      'button',
      { class: 'btn sm', type: 'button', title: 'Top values in the filtered window: sources, destinations, ports, policies, reasons, zone pairs', 'aria-pressed': this.facetsOn ? 'true' : 'false', 'aria-controls': 'lg-facets', on: { click: () => this.toggleFacets() } },
      icon('grid'),
      h('span', { class: 'lg-btn-label' }, 'Top'),
    );
    this.winSel = h(
      'select',
      { class: 'lg-select', 'aria-label': 'Lines kept in this window', title: 'Lines kept in this browser window (memory only)', on: { change: () => this.setWindow(Number(this.winSel.value)) } },
      WINDOWS.map((n) => h('option', { value: String(n) }, `${this.fmt.compact(n)} lines`)),
    );
    this.winSel.value = String(this.windowMax);
    this.streamBar = h(
      'div',
      { class: 'lg-bar' },
      this.countEl,
      this.hostEl,
      this.matchEl,
      this.selfEl,
      h('span', { class: 'spacer' }),
      this.followBtn,
      this.compactBtn,
      this.wrapBtn,
      this.facetsBtn,
      this.winSel,
    );
    this.noticeEl = h('div', { class: 'lg-notice', role: 'status', hidden: true });
    this.scroller = h('div', {
      class: 'lg-scroll',
      role: 'grid',
      tabindex: '0',
      'aria-label': 'Log lines',
      'aria-readonly': 'true',
      'aria-rowcount': '0',
      'aria-colcount': '1',
    });
    this.newPill = h('button', { class: 'lg-newpill', type: 'button', hidden: true, on: { click: () => this.jumpToEnd() } });
    this.hintEl = h('div', { class: 'lg-hint', 'aria-hidden': 'true', hidden: true });
    this.hoverBar = h(
      'div',
      { class: 'lg-hoverbar', hidden: true },
      h('button', { class: 'btn sm icon', type: 'button', title: 'Copy this line exactly (y)', 'aria-label': 'Copy this line', on: { click: () => this.hoverRow && this.copyLine(this.hoverRow) } }, icon('copy')),
      h('button', { class: 'btn sm icon', type: 'button', title: 'Decode this line (Enter)', 'aria-label': 'Decode this line', on: { click: () => this.hoverRow && this.select(this.hoverRow, { open: true }) } }, icon('info')),
    );
    this.stateEl = h('div', { class: 'lg-state', hidden: true });
    this.streamWrap = h('div', { class: 'lg-wrap' }, this.scroller, this.newPill, this.hintEl, this.hoverBar, this.stateEl);
    this.footEl = h('div', { class: 'lg-foot', role: 'status', 'aria-live': 'off' });
    this.stream = h('section', { class: 'tile lg-stream', 'aria-label': 'Log stream' }, this.streamBar, this.noticeEl, this.streamWrap, this.footEl);
    this.facetsEl = h('aside', { id: 'lg-facets', class: 'tile lg-facets', 'aria-label': 'Top values in the filtered window', hidden: !this.facetsOn });
    this.facetsEl.addEventListener('click', (e) => this.onFacetClick(e));
    this.mainEl = h('div', { class: ['lg-main', this.facetsOn && 'has-facets'] }, this.stream, this.facetsEl);
    // Nothing could be read: the explanation sits under the header instead of inside an empty frame.
    this.blockEl = h('section', { class: 'lg-block', 'aria-label': 'Why there are no lines', hidden: true });

    this.el.append(this.head, this.srcRow, this.blockEl, this.whereEl, this.queryEl, this.timeline, this.mainEl);

    this.list = new LineList(this.scroller, { h, render: (row) => this.renderRow(row), onScroll: (programmatic) => this.onScroll(programmatic) });
    this.updatePaintKey();
    this.list.body.classList.toggle('is-compact', this.compact);
    this.list.setWrap(this.wrap, this.twoLineMode());
    this.renderLive();
    this.renderFollow();
    this.showState({ status: 'loading', title: 'Reading the log configuration', message: 'J-Wicket asks the device which log files and databases exist.', skeleton: true });
  }

  bind() {
    const on = (target, type, fn, opts) => {
      target.addEventListener(type, fn, opts);
      this.offs.push(() => target.removeEventListener(type, fn, opts));
    };
    on(document, 'jwicket:toggle-live', () => this.togglePause());
    on(document, 'jwicket:refresh', () => this.refresh(false));
    on(document, 'jwicket:next-match', () => this.nextMatch(1));
    on(document, 'jwicket:prev-match', () => this.nextMatch(-1));
    on(document, 'jwicket:toggle-follow', () => this.toggleFollow());
    on(document, 'jwicket:escape', () => this.clearSelection());
    on(document, 'jwicket:density', () => this.list.measure());
    on(document, 'keydown', (e) => this.onKey(e));
    on(document, 'pointerdown', (e) => {
      if (this.menu && !this.exportWrap.contains(e.target)) this.closeExportMenu();
    }, true);
    on(this.scroller, 'click', (e) => this.onStreamClick(e));
    on(this.scroller, 'mouseover', (e) => this.onHover(e));
    on(this.scroller, 'mouseleave', (e) => {
      if (!(e.relatedTarget instanceof Node && this.hoverBar.contains(e.relatedTarget))) this.hideHover();
    });
    on(this.streamWrap, 'mouseleave', () => this.hideHover());
    on(this.scroller, 'keydown', (e) => this.onGridKey(e));
    on(this.scroller, 'focus', () => {
      // Keyboard focus lands on a row; a mouse click selects the row it hits instead.
      if (this.selSeq === null && this.visible.length && this.scroller.matches(':focus-visible')) {
        const r = this.list.range;
        const row = this.visible[Math.min(this.visible.length - 1, Math.max(0, r.first))];
        if (row) this.select(row, { scroll: false });
      }
    });
    on(window, 'jwicket:idle', (e) => this.setIdle(Boolean(e && e.detail && e.detail.idle)));
    this.offs.push(this.ctx.store.on('inventory', () => {
      this.updateHints();
      if (this.activeZone() !== this.zoneName) this.applyZone();
      else this.list.reconcile(true);
      this.renderSub();
    }));
    this.offs.push(this.ctx.store.on('sessions', () => this.refreshLiveLink()));
    this.offs.push(this.ctx.store.on('scope', () => this.renderSub()));
    if (this.narrowMq) {
      on(this.narrowMq, 'change', () => {
        this.narrow = this.narrowMq.matches;
        this.repaint();
      });
    }
    this.timers.ago = setInterval(() => this.renderFoot(), 1000);
  }

  destroy() {
    this.dead = true;
    clearTimeout(this.timers.poll);
    clearTimeout(this.timers.sources);
    clearTimeout(this.facetsTimer);
    clearInterval(this.timers.ago);
    if (this.abort) this.abort.abort();
    for (const off of this.offs) off();
    this.offs = [];
    if (this.bar) this.bar.destroy();
    if (this.histogram) this.histogram.destroy();
    if (this.list) this.list.destroy();
    this.closeExportMenu();
    this.ctx.ui.setLive('logs', false);
    this.rows = [];
    this.visible = [];
    this.bySeq.clear();
    this.seen.clear();
    this.el.replaceChildren();
  }

  // ---- route --------------------------------------------------------------------------------------

  readRoute(route, initial) {
    const p = route.params;
    const hide = new Set(String(p.get('hide') || '').split(',').filter((id) => this.famIndex.has(id)));
    const famChanged = hide.size !== this.famOff.size || [...hide].some((x) => !this.famOff.has(x));
    this.famOff = hide;
    const showSelf = p.get('self') === 'show';
    const selfChanged = showSelf !== this.showSelf;
    this.showSelf = showSelf;
    // A link without a type means session-all, whatever was chosen before.
    const type = p.get('type');
    this.reportType = type && /^[a-z-]{2,32}$/.test(type) ? type : 'session-all';
    this.wantSource = p.get('source') || null;
    const q = p.get('q') || '';
    if (initial || q !== this.queryText) {
      this.queryText = q;
      if (this.bar) this.bar.setValue(q);
      this.applyQuery(q, this.bar ? this.bar.parsed : this.q.parse(q, { view: 'logs' }), { fromRoute: true });
    }
    if (!initial && (famChanged || selfChanged)) {
      this.renderFams();
      this.refilter();
    }
  }

  update(route) {
    if (this.broken || this.dead) return;
    const before = this.src && this.src.id;
    const beforeType = this.reportType;
    this.readRoute(route, false);
    if (this.sources) {
      const want = this.wantSource ? this.sourceList.find((s) => s.id === this.wantSource) : null;
      if (want && (want.id !== before || (want.kind === 'report' && beforeType !== this.reportType))) this.switchSource(want, { keepRoute: true });
    }
  }

  writeRoute() {
    const params = {};
    if (this.src) params.source = this.src.id;
    if (this.src && this.src.kind === 'report' && this.reportType !== 'session-all') params.type = this.reportType;
    if (this.queryText) params.q = this.queryText;
    if (this.famOff.size) params.hide = [...this.famOff].join(',');
    if (this.showSelf) params.self = 'show';
    this.ctx.setParams(params, { replace: true });
  }

  // ---- sources ------------------------------------------------------------------------------------

  async loadSources() {
    clearTimeout(this.timers.sources);
    this.timers.sources = 0;
    // Another tab or window of this session may be reading: wait for it (up to 5 tries) instead of
    // failing, and say so on the loading card.
    const res = await this.ctx.api.get('/api/logs/sources', null, {
      retry429: { attempts: 5 },
      onWait: () => {
        if (this.dead || this.sources) return;
        this.showState({ status: 'loading', title: 'Reading the log configuration', message: 'Waiting for another read on your session to finish\u2026', skeleton: true });
      },
    });
    if (this.dead || res.aborted) return;
    if (res.status === 401) return;
    if (!res.ok) {
      if (res.status === 429) {
        // Still busy after the retries: a state of this session, never a device failure. Try again in 30 s.
        this.failSources({ status: 'busy', message: null, retryLabel: 'Retry' });
        this.timers.sources = setTimeout(() => {
          this.timers.sources = 0;
          if (!this.dead && !this.sources) this.loadSources();
        }, SOURCES_RETRY_S * 1000);
        return;
      }
      this.failSources({ status: res.status === 0 ? 'offline' : res.internal ? 'internal' : 'failed', message: res.data.error || `The log sources could not be read (HTTP ${res.status}).` });
      return;
    }
    this.ctx.ui.noteFixture(res.data.meta);
    if (res.data.meta && res.data.meta.read_as && res.data.meta.read_as.user) this.readAs = res.data.meta.read_as.user;
    if (res.data.meta && Number(res.data.meta.suggested_interval_s) && prefGet(PREF.interval) === null) {
      const s = Number(res.data.meta.suggested_interval_s);
      if (INTERVALS.includes(s)) this.interval = s;
    }
    const src = res.data.sources || {};
    if (src.status !== 'ok') {
      this.failSources({ status: src.status || 'failed', message: src.message });
      return;
    }
    this.sources = src;
    this.el.classList.remove('is-blocked');
    this.selfNote = src.self_noise || '';
    this.sourceList = this.buildSourceList(src);
    const tr = src.traffic || {};
    // Say it up front when traffic logs are not on the box (on narrow screens the button says it).
    const wide = typeof matchMedia !== 'function' || !matchMedia('(max-width: 640px)').matches;
    if (wide && this.whereAuto && (tr.effective_mode === 'stream' || !this.sourceList.some((s) => s.traffic === 'yes'))) this.whereOpen = true;
    this.renderSources();
    this.renderWhere();
    const want = (this.wantSource && this.sourceList.find((s) => s.id === this.wantSource)) || this.defaultSource();
    this.switchSource(want, { keepRoute: Boolean(this.wantSource) });
  }

  failSources(state) {
    this.sources = null;
    this.sourceList = [];
    this.el.classList.add('is-blocked');
    this.renderSources();
    this.renderWhere();
    const denied = state.status === 'denied';
    this.subEl.textContent = state.status === 'busy' ? 'The log configuration was not read yet.' : 'The log configuration could not be read.';
    this.showState({
      status: state.status,
      title: denied ? 'Your Junos login class cannot read the log configuration' : undefined,
      message: denied && /login class does not allow/i.test(state.message || '') ? null : state.message,
      hint: denied
        ? 'J-Wicket first reads the syslog and security log settings to learn which logs exist, and your class may not read them. Reading a log file ("show log") also needs the trace permission, which the read-only class does not have. Ask your Junos administrator.'
        : undefined,
      actions: [this.retryButton(() => this.loadSources(), state.retryLabel)],
    });
    this.renderLive();
    this.renderBar();
    this.renderFoot();
  }

  buildSourceList(src) {
    const list = [];
    const mode = (src.traffic && src.traffic.effective_mode) || null;
    for (const f of src.files || []) {
      const traffic = /RT_FLOW/i.test(f.match || '') ? 'yes' : (f.contents || []).some((c) => /^(any|user) (any|info)$/.test(c)) ? 'maybe' : 'no';
      const meta = [];
      if (f.match) meta.push(`match ${f.match}`);
      if ((f.contents || []).length) meta.push(f.contents.join(', '));
      if (f.structured_data) meta.push('structured data');
      const entry = { id: f.id, kind: 'file', name: f.name, label: f.name, meta: meta.join(SEP) || 'syslog file', file: f, traffic, structured: Boolean(f.structured_data), badges: [] };
      if (f.inactive) {
        // Deactivated in the configuration: Junos stops writing it, but the file may still be on disk.
        entry.meta = 'deactivated: Junos no longer writes it; older lines may still be there';
        entry.metaCls = 'is-off';
      } else if (f.assumed) {
        entry.meta = 'not in the configuration (assumed default file)';
        entry.metaTitle = 'No syslog file named messages is configured; J-Wicket assumes the default file, and reading it may fail on this device.';
      }
      list.push(entry);
    }
    for (const d of src.databases || []) {
      if (d.id === 'report') {
        const entry = { id: 'report', kind: 'report', name: d.name || 'On-box reporting', label: 'on-box report', meta: 'reporting database', types: (d.types || []).slice(), traffic: 'yes', badges: [], note: d.note || null, supported: d.supported !== false };
        // The in-detail report queries came with Junos OS 23.1R1 (the server's note says which release runs).
        if (d.supported === false) {
          entry.btnLabel = 'on-box report \u00b7 needs Junos 23.1R1';
          entry.metaTitle = d.note || null;
        }
        // LOG-10: the amber note badge whenever the report has a note, supported or not.
        if (d.note) entry.badges.push({ text: 'note', cls: 'is-note', title: d.note });
        if (d.disabled) entry.badges.push({ text: 'logging disabled', cls: 'is-off', title: 'security log disable is configured: the device writes no new security logs; records written before may still be read.' });
        list.push(entry);
      } else if (d.id === 'buffer') {
        const entry = { id: 'buffer', kind: 'buffer', name: d.name || 'Security log buffer', label: 'log buffer', meta: mode === 'stream-event' ? 'routing engine, stream-event mode' : mode === 'event' ? 'routing engine, event mode' : 'routing engine', traffic: 'yes', badges: [], disabled: Boolean(d.disabled) };
        if (d.disabled) entry.badges.push({ text: 'logging disabled', cls: 'is-off', title: 'security log disable is configured: the device writes no new security logs; records written before may still be read.' });
        list.push(entry);
      }
    }
    return list;
  }

  defaultSource() {
    const L = this.sourceList;
    return L.find((s) => s.kind === 'file' && s.traffic === 'yes') || L.find((s) => s.kind === 'report') || L.find((s) => s.kind === 'buffer') || L.find((s) => s.id === 'file:messages') || L[0] || null;
  }

  renderSources() {
    const { h, put, icon } = this.dom;
    const esc = (v) => this.lp.escapeControls(String(v ?? ''));
    put(
      this.srcGroup,
      this.sourceList.map((s) =>
        h(
          'button',
          {
            class: ['lg-src', `kind-${s.kind}`, s.metaCls === 'is-off' && 'is-inactive', ((s.badges || []).length || s.btnLabel) && 'has-badges'],
            type: 'button',
            'aria-pressed': this.src && this.src.id === s.id ? 'true' : 'false',
            dataset: { id: s.id },
            title: [`${esc(s.name)}${SEP}${esc(s.meta)}`, s.metaTitle, ...(s.badges || []).map((b) => `${b.text}: ${esc(b.title)}`)].filter(Boolean).join('\n'),
            on: { click: () => this.switchSource(s) },
          },
          icon(s.kind === 'file' ? 'logs' : s.kind === 'report' ? 'grid' : 'layers', { class: 'lg-src-ico' }),
          h(
            'span',
            { class: 'lg-src-txt dev-text' },
            h('span', { class: 'lg-src-name' }, this.vis(s.btnLabel || s.label)),
            h('span', { class: ['lg-src-meta', s.metaCls], title: s.metaTitle || null }, this.vis(s.meta)),
          ),
          (s.badges || []).map((b) => h('span', { class: ['lg-src-badge', b.cls], title: esc(b.title) }, b.text)),
          s.traffic === 'yes' ? h('span', { class: 'lg-src-flow', title: 'Holds traffic (RT_FLOW) logs' }, 'flow') : null,
        ),
      ),
    );
    const current = this.src ? this.srcGroup.querySelector('[aria-pressed="true"]') : null;
    if (current) {
      // Keep the chosen source in view inside the strip (narrow screens scroll it sideways).
      const g = this.srcGroup;
      const left = current.offsetLeft - g.offsetLeft;
      if (left < g.scrollLeft || left + current.offsetWidth > g.scrollLeft + g.clientWidth) g.scrollLeft = Math.max(0, left - 12);
    }
    const tr = (this.sources && this.sources.traffic) || null;
    let label = 'Where are my traffic logs?';
    let cls = '';
    if (tr && tr.effective_mode === 'stream') {
      cls = 'is-off';
      label = 'Traffic logs leave the device';
    }
    this.whereBtn.className = `lg-where-btn ${cls}`.trim();
    put(this.whereBtn, icon(cls ? 'broadcast' : 'help'), h('span', null, label), icon('chevron-down', { class: 'chev' }));
    this.whereBtn.hidden = !tr;
    this.whereBtn.setAttribute('aria-expanded', this.whereOpen ? 'true' : 'false');
    const types = this.src && this.src.kind === 'report' ? this.src.types || [] : [];
    this.typeSel.hidden = !types.length;
    if (types.length) {
      put(this.typeSel, types.map((t) => h('option', { value: t }, `report: ${t}`)));
      this.typeSel.value = types.includes(this.reportType) ? this.reportType : types[0];
    }
  }

  toggleWhere() {
    this.whereOpen = !this.whereOpen;
    this.whereAuto = false;
    this.renderWhere();
    this.whereBtn.setAttribute('aria-expanded', this.whereOpen ? 'true' : 'false');
  }

  renderWhere() {
    const { h, put, icon } = this.dom;
    const tr = this.sources && this.sources.traffic;
    // With nothing to read, the traffic-log card is part of the explanation: always shown.
    this.whereEl.hidden = !(tr && (this.whereOpen || this.el.classList.contains('is-nodata')));
    if (!tr) return;
    const mode = tr.effective_mode || 'unknown';
    const modeCls = mode === 'stream' ? 'amber' : mode === 'event' ? 'permit' : mode === 'stream-event' ? 'sky' : 'muted';
    const onBox = this.sourceList.filter((s) => s.traffic === 'yes');
    const maybe = this.sourceList.filter((s) => s.traffic === 'maybe');
    const streams = tr.streams || [];
    const facts = [
      h('dt', null, 'Mode'),
      h('dd', { class: 'dev-text' }, h('span', { class: ['pill', modeCls] }, this.vis(mode)), h('span', { class: 'faint' }, ' ', this.vis(tr.mode_basis || ''))),
    ];
    if (tr.mode_inactive) {
      facts.push(h('dt', null, 'Configured mode'), h('dd', { class: 'dev-text' }, h('span', { class: 'mono' }, this.vis(tr.mode_inactive)), ', deactivated, not in effect'));
    }
    if (streams.length) {
      facts.push(
        h('dt', null, 'Streams'),
        h(
          'dd',
          { class: 'lg-streams' },
          streams.map((s) => {
            // Where a stream goes: a host (host:port), a RADIUS server, or a local stream file.
            let where;
            if (s.file !== null && s.file !== undefined) where = [h('b', { class: 'mono' }, 'local stream file ', this.vis(s.file)), h('span', { class: 'faint' }, ' \u00b7 J-Wicket cannot read stream files yet')];
            else if (s.radius !== null && s.radius !== undefined) where = h('b', { class: 'mono' }, 'RADIUS ', this.vis(s.radius));
            else where = h('b', { class: 'mono' }, this.vis(`${s.host || '?'}${s.port ? `:${s.port}` : ''}`));
            return h(
              'span',
              { class: ['lg-stream-host', 'dev-text', s.inactive && 'is-inactive'] },
              icon('broadcast'),
              where,
              s.inactive ? h('span', { class: 'pill muted', title: 'This stream is deactivated in the configuration, so it is not in effect.' }, 'deactivated') : null,
              h('span', { class: 'faint' }, this.vis([s.name, s.format, (s.category || []).filter(Boolean).join('/')].filter(Boolean).join(SEP))),
            );
          }),
        ),
      );
    }
    facts.push(
      h('dt', null, 'On-box reporting'),
      h('dd', null, tr.report_inactive ? 'configured but deactivated' : tr.report ? 'Enabled: a local report database keeps a copy.' : 'Not enabled.'),
    );
    if (tr.disabled) facts.push(h('dt', null, 'Security logging'), h('dd', null, 'disabled (security log disable)'));
    // The format as configured, verbatim; J-Wicket does not interpret it.
    facts.push(
      h('dt', null, 'Format'),
      h('dd', { class: 'dev-text' }, tr.format ? [h('span', { class: 'mono' }, this.vis(tr.format)), ' (security log format, as configured)'] : 'not set'),
    );
    const jump = (s) =>
      h('button', { class: ['btn', 'sm', this.src && this.src.id === s.id && 'is-current'], type: 'button', on: { click: () => this.switchSource(s) } }, icon(s.kind === 'file' ? 'logs' : s.kind === 'report' ? 'grid' : 'layers'), this.vis(s.label));
    put(
      this.whereEl,
      h(
        'div',
        { class: ['lg-where-card', mode === 'stream' && 'is-off'] },
        h('div', { class: 'lg-where-icon' }, icon(mode === 'stream' ? 'broadcast' : 'help', { size: 20 })),
        h(
          'div',
          { class: 'lg-where-body' },
          h('h2', { class: 'lg-where-title' }, 'Where are my traffic logs?'),
          h('p', { class: 'lg-where-text dev-text' }, this.vis(tr.where || 'The security log mode is not known.')),
          h('dl', { class: 'kv lg-where-kv' }, facts),
          h(
            'div',
            { class: 'lg-where-jump' },
            onBox.length ? h('span', { class: 'faint' }, 'Read them here:') : h('span', { class: 'faint' }, 'Nothing on this device holds traffic logs that J-Wicket can read.'),
            onBox.map(jump),
            maybe.length ? h('span', { class: 'faint' }, 'May also hold some:') : null,
            maybe.map(jump),
          ),
          h('p', { class: 'lg-where-cli' }, h('span', { class: 'faint' }, 'Check on the device: '), h('code', null, 'show configuration security log')),
        ),
        // With nothing to read the card is part of the explanation, so it cannot be closed.
        this.el.classList.contains('is-nodata') ? null : h('button', { class: 'btn ghost icon lg-where-x', type: 'button', 'aria-label': 'Close', title: 'Close', on: { click: () => this.toggleWhere() } }, icon('close')),
      ),
    );
  }

  switchSource(s, { keepRoute = false } = {}) {
    if (!s) {
      this.src = null;
      this.showState({ status: 'empty', title: 'No log source', message: 'The device reported no syslog file or log database.' });
      return;
    }
    const sameType = this.src && this.src.id === s.id && (s.kind !== 'report' || this.src.reportType === this.reportType);
    if (sameType && this.rows.length) return;
    this.src = s;
    if (s.kind === 'report') {
      if (!s.types.includes(this.reportType)) this.reportType = s.types.includes('session-all') ? 'session-all' : s.types[0];
      s.reportType = this.reportType;
    }
    this.renderSources();
    this.renderWhere();
    this.applyQuery(this.queryText, this.bar ? this.bar.parsed : this.q.parse(this.queryText, { view: 'logs' }), { silent: true });
    if (!keepRoute || this.wantSource !== s.id) this.writeRoute();
    this.wantSource = s.id;
    this.restart();
  }

  setReportType(t) {
    if (!this.src || this.src.kind !== 'report' || t === this.reportType) return;
    this.reportType = t;
    this.src.reportType = t;
    this.writeRoute();
    this.restart();
  }

  // ---- the read loop ------------------------------------------------------------------------------

  resetRows() {
    this.rows = [];
    this.bySeq.clear();
    this.seen.clear();
    this.visible = [];
    this.cursor = null;
    this.newest = null;
    this.deviceInfo = null;
    this.unseen = 0;
    this.selSeq = null;
    this.curSeq = null;
    this.selfHidden = 0;
    this.hist = { times: [], series: [] };
    this.hostCounts.clear();
    this.facets = FACETS.map(() => new Map());
    this.facetsDirty = true;
    this.lastDay = null;
    this.newestFrame = null;
    this.unchecked = [];
    this.appendCut = [];
    this.filterCut = null;
    this.denyReasons.clear();
    if (this.singleHost !== null) {
      this.singleHost = null;
      this.updatePaintKey();
      this.renderHost();
    }
    this.list.setItems(this.visible);
  }

  restart() {
    this.readGen += 1;
    clearTimeout(this.timers.poll);
    if (this.abort) this.abort.abort();
    this.abort = null;
    this.inflight = false;
    this.failed = null;
    this.notice = null;
    this.follow = true;
    this.clockChecked = false;
    this.firstDone = false;
    this.limited = null;
    this.disabledNoted = false;
    this.resetRows();
    this.renderFollow();
    this.renderNotice();
    if (!this.src) return;
    this.showState({ status: 'loading', title: `Reading ${this.src.label}`, message: 'The first read returns the newest lines; then J-Wicket asks only for what is new.', skeleton: true });
    this.refilter();
    this.renderSub();
    this.poll(true);
  }

  refresh(fromButton) {
    if (fromButton) this.ctx.ui.toast(`Reading ${this.src ? this.src.label : 'the logs'} again from the device\u2026`, 'info');
    if (!this.sources) {
      this.loadSources();
      return;
    }
    this.restart();
  }

  readParams(initial) {
    const s = this.src;
    const dev = (this.plan && this.plan.device) || {};
    if (s.kind === 'file') {
      const p = { source: s.id, lines: initial ? Math.min(API_MAX_LINES, this.windowMax) : API_MAX_LINES };
      if (dev.contains) p.contains = dev.contains;
      if (dev.exclude) p.exclude = dev.exclude;
      if (!initial && this.cursor) p.cursor = this.cursor;
      return p;
    }
    if (s.kind === 'report') {
      const p = { source: 'report', type: this.reportType, count: REPORT_COUNT };
      if (dev.expression) p.expression = dev.expression;
      let start = dev.start || null;
      if (!initial && this.newest !== null) {
        const live = reportStart(this.newest);
        if (!start || live > start) start = live;
      }
      if (start) p.start = start;
      if (dev.stop) p.stop = dev.stop;
      return p;
    }
    const p = { source: 'buffer' };
    let since = dev.since || null;
    if (!initial && this.newest !== null) {
      // One second of overlap: events later in the newest second may not have been in the last read.
      const live = bufferSince(this.newest - 1000);
      if (!since || live > since) since = live;
    }
    if (since) p.since = since;
    return p;
  }

  liveCapable() {
    if (!this.src || this.failed) return false;
    const dev = (this.plan && this.plan.device) || {};
    if (this.src.kind === 'report' && dev.stop && this.newest !== null && reportStart(this.newest) >= dev.stop) return false;
    return true;
  }

  schedule(seconds) {
    clearTimeout(this.timers.poll);
    if (this.dead || this.paused || !this.liveCapable()) {
      this.renderLive();
      return;
    }
    const wait = Math.max(seconds || 0, this.interval, (this.meta && Number(this.meta.min_interval_s)) || 0);
    this.nextAt = Date.now() + wait * 1000;
    this.timers.poll = setTimeout(() => this.poll(false), wait * 1000);
    this.renderLive();
  }

  async poll(initial) {
    clearTimeout(this.timers.poll);
    if (this.dead || !this.src) return;
    if (!initial && this.paused) return;
    // Until a read of this source has been ingested, every read is a first read (no cursor, the newest
    // lines, no flash, no gap markers): a 429 on the first read must not turn the retry into a tail.
    initial = initial || !this.firstDone;
    const gen = this.readGen;
    const src = this.src;
    const params = this.readParams(initial);
    this.inflight = true;
    this.nextAt = null;
    this.renderFoot();
    this.abort = new AbortController();
    const res = await this.ctx.api.get('/api/logs', params, { signal: this.abort.signal });
    if (this.dead || gen !== this.readGen) return;
    this.inflight = false;
    this.abort = null;
    if (res.aborted) return;
    if (res.status === 401) {
      this.failed = { status: 'session-lost', message: res.data.error };
      this.renderLive();
      return;
    }
    if (res.status === 429) {
      this.noteLimited(res, src, initial);
      this.schedule(res.retryAfter || 2);
      return;
    }
    // A 200 (or any other answer) ends a run of 429s.
    this.clearLimited();
    if (res.data && res.data.meta) {
      this.meta = res.data.meta;
      this.ctx.ui.noteFixture(res.data.meta);
      if (res.data.meta.read_as && res.data.meta.read_as.user) this.readAs = res.data.meta.read_as.user;
    }
    if (res.status === 400) {
      const message = res.data.error || 'The device read was refused.';
      this.lastRead = { at: Date.now(), ok: false, message };
      if (this.bar) this.bar.setError(`The device read was refused: ${message}`);
      this.failed = { status: 'failed', title: 'The device read was refused', message };
      if (!this.rows.length) this.showState({ ...this.failed, hint: 'Change the query; the part sent to the device is shown in gold.' });
      this.renderLive();
      this.renderFoot();
      return;
    }
    if (!res.ok) {
      const message = res.data.error || `The log read failed (HTTP ${res.status}).`;
      this.lastRead = { at: Date.now(), ok: false, message };
      if (initial && !this.rows.length) {
        this.showState({ status: res.status === 0 ? 'offline' : res.internal ? 'internal' : 'failed', message, actions: [this.retryButton(() => this.restart())] });
      } else {
        this.notice = { kind: 'warn', text: `The last read failed: ${message} J-Wicket tries again in ${FAIL_BACKOFF_S} s.` };
        this.renderNotice();
      }
      this.renderFoot();
      this.schedule(FAIL_BACKOFF_S);
      return;
    }
    const log = res.data.log || {};
    if (log.status !== 'ok') {
      this.lastRead = { at: Date.now(), ok: false, message: log.message || log.status };
      const st = this.logState(log, src);
      if (!this.rows.length || log.status === 'denied' || log.status === 'unsupported') {
        this.failed = st;
        this.showState(st);
        this.renderLive();
      } else {
        this.notice = { kind: 'warn', text: `The last read failed (${log.status}): ${log.message || 'no detail'}. Trying again in ${FAIL_BACKOFF_S} s.` };
        this.renderNotice();
        this.schedule(FAIL_BACKOFF_S);
      }
      this.renderFoot();
      return;
    }
    if (this.notice && this.notice.kind === 'warn') {
      this.notice = null;
      this.renderNotice();
    }
    if (this.bar) this.bar.setError(null);
    this.lastRead = { at: Date.now(), ok: true };
    if (src.kind === 'report') this.reportOk.add(this.reportType);
    // Parse big reads in slices so the first paint never blocks the page for long (parse results are
    // memoised by logparse, so ingest() below reuses them).
    const lines = Array.isArray(log.lines) ? log.lines : [];
    if (lines.length > PARSE_SLICE) {
      for (let i = 0; i < lines.length; i += PARSE_SLICE) {
        const end = Math.min(lines.length, i + PARSE_SLICE);
        for (let j = i; j < end; j += 1) this.lp.parse(String(lines[j]));
        await new Promise((r) => setTimeout(r, 0));
        if (this.dead || gen !== this.readGen) return;
      }
    }
    this.ingest(log, src, initial, params);
    if (!this.failed) this.firstDone = true;
    this.schedule();
  }

  /**
   * A 429 on a log read. The floor is J-Wicket's own (per signed-in session, shared by every tab and
   * window of it), not the device's. After the second in a row, or the first on a first read, say why.
   */
  noteLimited(res, src, initial) {
    const prev = this.limited && this.limited.src === src.id ? this.limited : null;
    const data = res.data || {};
    const interval = Number(data.interval_s);
    this.limited = {
      src: src.id,
      n: (prev ? prev.n : 0) + 1,
      reason: res.reason || (typeof data.reason === 'string' ? data.reason : null),
      since: prev ? prev.since : Date.now(),
      interval: Number.isFinite(interval) && interval > 0 ? interval : null,
      retryAfter: Math.max(1, Math.ceil(res.retryAfter || 2)),
    };
    const L = this.limited;
    if (L.n >= 2 || initial) {
      let text;
      if (L.reason === 'busy') text = `Another read on your session is still running (a slow device or another tab). J-Wicket waits ${L.retryAfter} s, as the server asked.`;
      else if (L.reason === 'rate' && L.interval !== null) text = `J-Wicket reads ${this.lp.escapeControls(src.label)} at most once every ${String(L.interval)} s for your session, and another J-Wicket tab or window of this session seems to be reading it too. This tab waits its turn (next read in ${L.retryAfter} s).`;
      else text = `J-Wicket was asked to wait ${L.retryAfter} s before reading ${this.lp.escapeControls(src.label)} again.`;
      this.notice = { kind: 'info', tag: 'limited', text };
      this.renderNotice();
    }
    this.renderFoot();
  }

  /** Any answer other than a 429 ends a run of them. */
  clearLimited() {
    if (!this.limited) return;
    this.limited = null;
    if (this.notice && this.notice.tag === 'limited') {
      this.notice = null;
      this.renderNotice();
    }
  }

  logState(log, src) {
    if (log.status === 'denied') {
      return {
        status: 'denied',
        title: `Your Junos login class cannot read ${src.label}`,
        message: log.message,
        hint: src.kind === 'file' ? 'Reading a syslog file ("show log") needs the trace permission; the read-only class does not have it.' : 'Ask your Junos administrator for a class that can read security logs.',
      };
    }
    if (src.kind === 'report' && (log.status === 'unsupported' || log.status === 'failed')) return this.reportState(log, src);
    if (log.status === 'unsupported') {
      const { h, icon } = this.dom;
      const others = this.sourceList.filter((x) => x.id !== src.id && x.traffic === 'yes');
      return {
        status: 'unsupported',
        title: src.kind === 'file' ? `${src.label} cannot be read on this device` : `${src.name} is not available on this device`,
        message: log.message,
        hint: src.file && src.file.assumed ? 'J-Wicket assumed the default "messages" file; this device may not have it.' : undefined,
        actions: others.map((x) => h('button', { class: 'btn sm', type: 'button', on: { click: () => this.switchSource(x) } }, icon(x.kind === 'file' ? 'logs' : x.kind === 'report' ? 'grid' : 'layers'), `Read ${x.label} instead`)),
      };
    }
    return { status: log.status || 'failed', message: log.message, actions: [this.retryButton(() => this.restart())] };
  }

  /**
   * One report type failed. That says nothing about on-box reporting as a whole (other types may
   * work) and, in fixture mode, nothing about a device: say which type, and offer session-all with
   * the matching family filter.
   */
  reportState(log, src) {
    const { h, icon } = this.dom;
    const type = this.reportType;
    if (src.supported === false) {
      // No report type works on this release: the server says which release runs; no other-type action.
      const others = this.sourceList.filter((x) => x.id !== src.id && x.traffic === 'yes');
      return {
        status: 'unsupported',
        title: 'The on-box report queries are not available on this release',
        message: log.message || src.note || null,
        hint: 'J-Wicket reads on-box reporting with the in-detail report queries, which this device does not have. Other sources may still hold traffic logs.',
        actions: others.map((x) => h('button', { class: 'btn sm', type: 'button', on: { click: () => this.switchSource(x) } }, icon(x.kind === 'file' ? 'logs' : 'layers'), 'Read ', this.vis(x.label), ' instead')),
      };
    }
    const fixture = Boolean((this.meta && this.meta.fixture) || (this.ctx.store.session && this.ctx.store.session.fixture));
    const fam = REPORT_FAMILY[type];
    const allOk = this.reportOk.has('session-all');
    const actions = [];
    let message;
    if (type !== 'session-all' && (src.types || []).includes('session-all')) {
      const q = fam ? `family:${fam}` : '';
      message = allOk
        ? `session-all works here${fam ? `: filter it with family:${fam} for the same lines` : ''}.`
        : `Try session-all${fam ? ` and filter it with family:${fam}` : ''}.`;
      actions.push(
        h('button', { class: 'btn sm', type: 'button', on: { click: () => this.useSessionAll(q) } }, icon('grid'), `Read session-all${q ? ` with ${q}` : ''}`),
      );
    } else {
      message = log.message && !/does not support or has not enabled/i.test(log.message) ? log.message : null;
    }
    actions.push(this.retryButton(() => this.restart()));
    return {
      status: log.status === 'failed' ? 'failed' : 'unsupported',
      title: `The ${type} report returned nothing this console can read`,
      message,
      hint: fixture
        ? 'This is fixture data: the fixture has no lines for this report type. It says nothing about a real device.'
        : `On-box reporting itself may still work: a single report type can be unavailable (a feature without its licence, or not configured) while others answer. Check on the device: show security log report in-detail ${type}`,
      actions,
    };
  }

  useSessionAll(q) {
    if (!this.src || this.src.kind !== 'report') return;
    this.reportType = 'session-all';
    this.src.reportType = 'session-all';
    if (q && !this.queryText.includes(q)) {
      this.queryText = this.queryText ? `${this.queryText} ${q}` : q;
      if (this.bar) this.bar.setValue(this.queryText);
      this.applyQuery(this.queryText, this.bar ? this.bar.parsed : this.q.parse(this.queryText, { view: 'logs' }), { silent: true });
    }
    this.renderSources();
    this.writeRoute();
    this.restart();
  }

  ingest(log, src, initial, params = {}) {
    const lines = Array.isArray(log.lines) ? log.lines : [];
    let items;
    if (src.kind === 'buffer') {
      const events = Array.isArray(log.events) ? log.events : [];
      const offset = events.length === lines.length ? 0 : null;
      items = lines.map((line, i) => ({ line: String(line), ev: offset === null ? null : events[i] }));
      if (log.disabled && !lines.length && initial) {
        this.failed = { status: 'unsupported', title: 'Security logging to the buffer is disabled', message: 'The device reports that security logs are not written to the routing-engine buffer.' };
        this.showState(this.failed);
        this.renderLive();
        return;
      }
      // The reply's own flag, or `security log disable` in the configuration (the source's flag).
      if ((log.disabled || src.disabled) && lines.length && !this.disabledNoted) {
        this.disabledNoted = true;
        // JUNOS-08: the documentation says only that the statement disables security logging; that the
        // lines shown were written before it is J-Wicket's reading.
        this.notice = { kind: 'info', text: 'Security logging is disabled (security log disable); J-Wicket reads the lines shown as written before that (inferred).' };
        this.renderNotice();
      }
    } else {
      items = lines.map((line) => ({ line: String(line), ev: null }));
    }
    if (src.kind !== 'file') items = this.timeOrder(items);
    if (src.kind === 'file') {
      this.cursor = log.cursor || this.cursor;
      this.deviceInfo = {
        window: log.window,
        dropped: initial ? log.dropped || 0 : (this.deviceInfo && this.deviceInfo.dropped) || 0,
        returned: lines.length,
        // Lines the device had after the cursor (the whole window on a first read), before the device filter.
        scanned: Number.isFinite(log.scanned) ? log.scanned : null,
        initial,
        devTerms: Boolean(params.contains || params.exclude),
      };
    } else {
      this.deviceInfo = { returned: lines.length, limited: src.kind === 'report' && lines.length >= REPORT_COUNT };
    }
    const markers = [];
    if (!initial && log.reset) {
      const at = clock(Date.now());
      markers.push({ kind: 'reset', text: `${src.label} was rotated or rewritten at ${at} (browser clock). A fresh tail starts here.` });
      this.notice = { kind: 'info', text: `${src.label} was rotated or rewritten at ${at}: J-Wicket started a fresh tail. The point is marked in the stream; lines before it are kept.` };
      this.renderNotice();
      this.ctx.ui.announce(`${src.label} was rotated; a fresh tail started.`);
    }
    if (!initial && log.dropped > 0) {
      markers.push({ kind: 'gap', text: `${this.fmt.num(log.dropped)} lines arrived faster than one read returns and were skipped here.` });
    }
    if (!initial && src.kind === 'report' && lines.length >= REPORT_COUNT) {
      // Live report reads send a start time and no 'descending'; which end of a capped reply the device
      // keeps is not confirmed (Q-LOG-01).
      markers.push({ kind: 'gap', text: `The device returned its limit of ${this.fmt.num(REPORT_COUNT)} lines; J-Wicket reads on from the newest one. If this device returns newest first without 'descending' (not yet confirmed, Q-LOG-01), lines before this point may be missing.` });
    }
    const dedupe = src.kind !== 'file' || Boolean(log.reset);
    const before = this.seq;
    this.append(items, markers, dedupe, initial);
    this.checkClocks(initial, src, before, Boolean(params.cursor));
  }

  /**
   * Time-zone sanity. Lines a cursor read just returned were written moments ago: if their zone-less
   * times sit far from the device's UTC clock, the device logs in local time and every time here (read
   * as UTC) is off by that offset. With a configured zone J-Wicket can convert (LG-02), this is a
   * cross-check of that zone. Also says when this browser's clock is off the device's. A first read is
   * never compared: its lines may be hours old.
   */
  checkClocks(initial, src, beforeSeq, cursorRead) {
    const server = this.meta && this.meta.read_at ? Date.parse(this.meta.read_at) : NaN;
    if (!Number.isFinite(server)) return;
    const notes = [];
    if (initial && !this.skewNoted) {
      const skew = Date.now() - server;
      if (Math.abs(skew) > 120000) {
        this.skewNoted = true;
        notes.push(`This browser's clock is ${this.fmt.duration(Math.round(Math.abs(skew) / 1000))} ${skew > 0 ? 'ahead of' : 'behind'} the device's, so age filters (age<15m) are off by that much.`);
      }
    }
    if (cursorRead && src.kind === 'file' && !this.clockChecked) {
      let fresh = null;
      for (let i = this.rows.length - 1; i >= 0 && this.rows[i].seq > beforeSeq; i -= 1) {
        const r = this.rows[i];
        if (!r.marker && Number.isFinite(r.p.time) && !r.p.zoned) {
          fresh = r;
          break;
        }
      }
      if (fresh) {
        this.clockChecked = true;
        const label = this.lp.escapeControls(src.label);
        const d = fresh.p.time - server; // as written (read as UTC) minus the device's UTC clock
        const zone = this.deviceZone();
        if (zone) {
          const expect = zoneOffset(server, zone);
          const off = d - expect;
          if (Math.abs(off) > 20 * 60000) {
            const n = Math.abs(Math.round(off / 900000) / 4);
            notes.push(`${label}: lines look ${n} h off the configured zone (${zone}, ${utcOffsetLabel(expect)} now): new lines are stamped about ${utcOffsetLabel(Math.round(d / 900000) * 900000)}. A time-zone change takes effect for all processes only after a reboot, and security log utc-timestamp stamps security logs in UTC whatever the zone (J-Wicket does not read that setting); either may explain it (J-Wicket's reading).`);
          } else if (!this.zoneName && Math.abs(d) > 20 * 60000) {
            notes.push(`New lines in ${label} are stamped about ${utcOffsetLabel(expect)}, as the configured time zone ${zone} is now. J-Wicket reads them as UTC, so the chart, ages and time ranges are off by that much; "Show times in the device zone" reads them in ${zone}.`);
          }
        } else if (Math.abs(d) > 20 * 60000) {
          const q = Math.round(d / 900000) / 4;
          const off = `UTC${q >= 0 ? '+' : '\u2212'}${Math.abs(q)}`;
          notes.push(`New lines in ${label} are stamped ${this.fmt.duration(Math.round(Math.abs(d) / 1000))} ${d > 0 ? 'ahead of' : 'behind'} the device's UTC clock. Their times carry no zone, so the device probably logs in local time (about ${off}); J-Wicket reads them as UTC, so the chart, ages and time ranges are off by that much.`);
        }
      }
    }
    if (notes.length) {
      this.notice = { kind: 'info', text: notes.join(' ') };
      this.renderNotice();
    }
  }

  timeOrder(items) {
    let sorted = true;
    let prev = -Infinity;
    const keyed = items.map((it, i) => {
      const t = this.lp.parse(it.line).time;
      const k = Number.isFinite(t) ? t : prev;
      if (k < prev) sorted = false;
      prev = Math.max(prev, k);
      return { it, k, i };
    });
    if (sorted) return items;
    keyed.sort((a, b) => a.k - b.k || a.i - b.i);
    return keyed.map((x) => x.it);
  }

  makeRow(line, ev) {
    let p = this.lp.parse(line);
    if (ev) p = withEvent(p, ev, this.lp.SEVERITIES || []);
    const fam = this.famIndex.has(p.family) ? p.family : 'other';
    const fk = this.facetKeys(p);
    const row = {
      seq: (this.seq += 1),
      line,
      p,
      fam,
      famIx: this.famIndex.get(fam),
      time: this.frameOf(p),
      self: this.lp.isSelfRead(p, this.readAs),
      sid: sessionIdOf(p),
      len: line.length,
      nctl: this.lp.countControls ? this.lp.countControls(line) : 0,
      fk: fk.keys,
      pair: fk.pair,
      added: Date.now(),
      flash: null,
      toks: null,
      tg: -1,
      ptoks: null,
      pk: '',
      fs: 0,
      marker: null,
    };
    return row;
  }

  markerRow(marker) {
    return { seq: (this.seq += 1), line: '', p: null, fam: 'other', famIx: 0, time: null, self: false, sid: null, len: 0, pl: 0, added: Date.now(), marker };
  }

  append(items, markers, dedupe, initial) {
    const added = [];
    for (const m of markers) added.push(this.markerRow(m));
    const batch = new Map();
    for (const it of items) {
      if (dedupe) {
        const n = (batch.get(it.line) || 0) + 1;
        batch.set(it.line, n);
        if (n <= (this.seen.get(it.line) || 0)) continue;
      }
      const row = this.makeRow(it.line, it.ev);
      added.push(row);
      // The next report start / buffer since comes from the time as written (read as UTC), as before
      // LG-02: the zone the device reads those parameters in is unknown.
      const t = row.p.time;
      if (Number.isFinite(t) && (this.newest === null || t > this.newest)) this.newest = t;
      if (row.time !== null && (this.newestFrame === null || row.time > this.newestFrame)) this.newestFrame = row.time;
      if (row.fam === 'deny' && row.fk && row.fk[4] !== null) this.denyReasons.add(row.fk[4]);
    }
    // A marker with nothing after it says nothing: drop markers when no lines followed.
    const lines = added.filter((r) => !r.marker);
    if (!lines.length) {
      if (initial) this.afterIngest(0, initial);
      else this.renderFoot();
      return;
    }
    // A few new lines get a brief wash; a burst only flashes the gutter so the stream stays readable.
    if (!initial) {
      const flash = lines.length <= NEW_WASH_MAX ? 'wash' : 'gut';
      for (const r of lines) r.flash = flash;
    }
    for (const row of added) {
      this.rows.push(row);
      this.bySeq.set(row.seq, row);
      if (!row.marker) {
        this.seen.set(row.line, (this.seen.get(row.line) || 0) + 1);
        this.hostAdd(row, 1);
      }
    }
    const excess = this.rows.length - this.windowMax;
    const removed = excess > 0 ? this.trimFront(excess) : [];
    for (const r of removed) if (!r.marker) this.hostAdd(r, -1);
    if (this.checkHosts() || !this.famCounts) {
      // The host column appeared or went away (Compact): every row paints differently.
      this.updatePaintKey();
      for (const r of this.rows) this.measureRow(r);
      this.refilter();
    } else {
      for (const r of lines) this.measureRow(r);
      // Steady state: subtract what left the window, then filter only what arrived.
      const shift = this.forgetRows(removed);
      this.filterAppend(added);
      if (!this.follow && shift) this.list.nudge(-shift);
    }
    this.afterIngest(lines.length, initial);
  }

  /** Removes the oldest `k` rows from the window; returns them. */
  trimFront(k) {
    const removed = this.rows.splice(0, k);
    for (const row of removed) {
      this.bySeq.delete(row.seq);
      if (!row.marker) {
        const n = (this.seen.get(row.line) || 0) - 1;
        if (n > 0) this.seen.set(row.line, n);
        else this.seen.delete(row.line);
      }
      if (row.seq === this.selSeq) this.selSeq = null;
      if (row.seq === this.curSeq) this.curSeq = null;
    }
    return removed;
  }

  /**
   * Takes trimmed rows out of the window totals (family counts, histogram, matches, top values) and
   * drops them from the head of the visible list, without filtering the window again. Returns how
   * far (px) the first row still shown moved up, so a reader who is not following keeps their place.
   */
  forgetRows(removed) {
    if (!removed.length) return 0;
    const maxSeq = removed[removed.length - 1].seq;
    // Unchecked rows are the oldest of the window: trimming takes them first. When the last one goes,
    // every line left has been checked and the cut marker goes too.
    if (this.unchecked.length) {
      let u = 0;
      while (u < this.unchecked.length && this.unchecked[u].seq <= maxSeq) u += 1;
      if (u) this.unchecked.splice(0, u);
      if (!this.unchecked.length) this.filterCut = null;
    }
    if (this.appendCut.length) this.appendCut = this.appendCut.filter((r) => r.seq > maxSeq);
    let hist = 0;
    for (const row of removed) {
      if (row.marker) continue;
      const fs = row.fs || 0;
      if (fs & FS_SELF) this.selfHidden -= 1;
      if (fs & FS_COUNT) this.famCounts[row.famIx] -= 1;
      if (fs & FS_HIST) hist += 1;
      if (fs & FS_VIS) {
        this.facetAdd(row, -1);
        if (fs & FS_MATCH) this.matchCount -= 1;
      }
    }
    // Histogram entries are pushed in row order, so the trimmed rows own the first `hist` of them.
    if (hist) {
      this.hist.times.splice(0, hist);
      this.hist.series.splice(0, hist);
    }
    const v = this.visible;
    let k = 0;
    while (k < v.length && v[k].seq <= maxSeq) k += 1;
    // A gap or rotation marker with nothing before it says nothing (the filter's cut marker does, while
    // unchecked lines remain above it).
    while (k < v.length && v[k].marker && v[k].marker.kind !== 'day' && !(v[k].marker.kind === 'cut' && this.unchecked.length)) k += 1;
    if (!k) return 0;
    const before = this.list.tops[k] || 0;
    v.splice(0, k);
    let at = 0;
    if (this.compact && v.length && !v[0].marker && v[0].time !== null) {
      v.unshift(this.dividerFor(v[0]));
      at = 1;
    }
    if (!v.some((r) => !r.marker)) this.lastDay = null;
    this.list.recompute(0);
    this.facetsDirty = true;
    return before - (this.list.tops[at] || 0);
  }

  setWindow(n) {
    if (!WINDOWS.includes(n)) return;
    this.windowMax = n;
    prefSet(PREF.window, n);
    const excess = this.rows.length - n;
    if (excess > 0) {
      for (const r of this.trimFront(excess)) if (!r.marker) this.hostAdd(r, -1);
      if (this.checkHosts()) this.repaint();
      else this.refilter();
    }
    this.renderBar();
    this.ctx.ui.toast(`Keeping the newest ${this.fmt.num(n)} lines in this window.`, 'info');
  }

  afterIngest(addedCount, initial) {
    if (initial) {
      this.hideState();
      if (!this.rows.length) {
        const filtered = this.plan && this.plan.device && Object.keys(this.plan.device).length;
        this.showState({
          status: 'empty',
          title: filtered ? 'No line matched the device-side filter' : `${this.src.label} has no lines yet`,
          message: filtered ? 'The device found nothing for the gold terms in the query. New matches appear here as they arrive.' : 'New lines appear here as they arrive.',
          code: false,
          actions: filtered ? [this.dom.h('button', { class: 'btn sm', type: 'button', on: { click: () => this.setQuery('') } }, this.dom.icon('close'), 'Clear the query')] : null,
        });
      }
      this.list.scrollToEnd();
    } else if (addedCount) {
      if (this.stateKind !== 'nomatch') this.hideState();
      this.ctx.ui.announce(`${this.fmt.plural(addedCount, 'new log line')}`);
    }
    if (this.follow) this.list.scrollToEnd();
    this.renderAll();
  }

  // ---- filtering ----------------------------------------------------------------------------------

  onQuery(text, parsed) {
    this.queryText = text;
    this.applyQuery(text, parsed, {});
    this.writeRoute();
  }

  /** Splits the browser part of the plan into time terms (drawn on the histogram) and the rest. */
  splitTime(ast) {
    if (!ast) return { rest: null, time: null, lo: null, hi: null };
    const items = ast.type === 'and' ? ast.items : [ast];
    const timeItems = [];
    const rest = [];
    let lo = null;
    let hi = null;
    for (const it of items) {
      const key = it.type === 'term' && it.key ? String(it.key).toLowerCase() : '';
      if ((key === 'time' || key === 'ts' || key === 'timestamp') && it.values.length === 1 && /[<>]=?/.test(it.op || '')) {
        const t = this.q.parseTime(it.values[0].text);
        if (t) {
          timeItems.push(it);
          if (it.op === '>=' || it.op === '>') lo = Math.max(lo === null ? -Infinity : lo, it.op === '>' ? t.hi + 1 : t.lo);
          else hi = Math.min(hi === null ? Infinity : hi, it.op === '<' ? t.lo - 1 : t.hi);
          continue;
        }
      }
      rest.push(it);
    }
    const join = (list) => (list.length === 0 ? null : list.length === 1 ? list[0] : { type: 'and', items: list });
    return { rest: join(rest), time: join(timeItems), lo, hi, items: timeItems };
  }

  applyQuery(text, parsed, { silent = false, fromRoute = false } = {}) {
    if (!parsed) parsed = this.q.parse(text, { view: 'logs' });
    if (parsed.error) {
      // Keep the last good filter while the text does not parse; the bar shows the error.
      return;
    }
    const kind = (this.src && this.src.kind) || 'file';
    // In Logs `app` also matches the Junos application (service-name), as it does in Sessions. The
    // report database's `application` key is the layer-7 name, so a Junos application name is not
    // sent to the device as application=...: it is matched here.
    const held = kind === 'report' ? this.junosAppTerms(parsed.ast) : [];
    const planAst = held.length ? this.withoutItems(parsed.ast, held) : parsed.ast;
    const plan = this.q.plan(planAst, `logs:${kind}`);
    if (held.length) {
      const items = parsed.ast.type === 'and' ? parsed.ast.items : [parsed.ast];
      const byPos = new Map(plan.explain.map((e) => [e.pos, e]));
      plan.explain = items.map((it) => byPos.get(it.gpos ?? it.pos) || { text: this.q.toQueryString(it), where: 'browser', pos: it.gpos ?? it.pos, end: it.gend ?? it.end });
    }
    if (kind === 'report' && (plan.expression || held.length)) {
      // The report expression's accepted keys and its != >= <= forms are inferred, not verified on a
      // device (research note 51): the device narrows, and the browser checks every term again.
      plan.browser = parsed.ast;
      for (const e of plan.explain) if (e.where === 'device') e.refine = true;
    }
    this.plan = plan;
    if (this.bar) this.bar.setPlan(plan);
    const split = this.splitTime(plan.browser);
    const ctx = { now: Date.now() };
    this.pred = this.q.compile(split.rest, this.fields, ctx);
    this.predTime = this.q.compile(split.time, this.fields, ctx);
    this.timeRange = split.lo !== null || split.hi !== null ? { lo: split.lo === null ? -Infinity : split.lo, hi: split.hi === null ? Infinity : split.hi } : null;
    const terms = this.markTerms(parsed.ast);
    terms.sort((a, b) => b.length - a.length);
    this.markRe = terms.length ? new RegExp(terms.map(escapeRe).join('|'), 'gi') : null;
    this.curSeq = null;
    const key = JSON.stringify(plan.device || {});
    const deviceChanged = key !== this.deviceKey;
    this.deviceKey = key;
    if (silent) return;
    if (deviceChanged && this.src && this.sources) {
      this.restart();
      return;
    }
    if (this.failed && this.failed.title === 'The device read was refused') {
      this.restart();
      return;
    }
    if (!fromRoute || this.rows.length) this.refilter();
  }

  /** Top-level positive app terms whose value is a Junos application (junos-*, or one in the inventory). */
  junosAppTerms(ast) {
    if (!ast) return [];
    const inv = this.ctx.store.lastInventory;
    const apps = new Set((((inv && inv.scope && inv.scope.applications) || {}).rows || []).map((a) => a.name));
    const items = ast.type === 'and' ? ast.items : [ast];
    return items.filter((it) => {
      if (it.type !== 'term' || !it.key || !['app', 'application'].includes(String(it.key).toLowerCase())) return false;
      return (it.values || []).some((v) => v.kind !== 'regex' && (/^junos-/i.test(v.text) || apps.has(v.text)));
    });
  }

  withoutItems(ast, drop) {
    const items = (ast.type === 'and' ? ast.items : [ast]).filter((it) => !drop.includes(it));
    if (!items.length) return null;
    return items.length === 1 ? items[0] : { ...ast, type: 'and', items };
  }

  /**
   * Strings to mark in lines: positive free text and values of keys that appear verbatim in a line
   * (src:, policy:, tag:), not values that never do (family:idp, sev>=warning, nat:src, bytes>1M).
   */
  markTerms(ast) {
    const keys = this.fieldKeyMap();
    const out = new Set();
    const walk = (node, negated) => {
      if (!node) return;
      if (node.type === 'and' || node.type === 'or') node.items.forEach((n) => walk(n, negated));
      else if (node.type === 'not') walk(node.item, !negated);
      else if (node.type === 'term' && !negated && (node.op === null || node.op === ':' || node.op === '=')) {
        if (node.key) {
          const name = keys.get(String(node.key).toLowerCase());
          const def = name ? this.q.FIELDS.logs[name] : null;
          if (!def || !(def.verbatim || def.contains)) return;
        }
        for (const v of node.values) {
          if (v.kind === 'regex' || !v.text) continue;
          let t = v.text;
          if (t.includes('*')) t = t.split('*').sort((a, b) => b.length - a.length)[0];
          if (/\/\d+$/.test(t) && this.q.parseNet && this.q.parseNet(t)) continue; // a CIDR block is not literal text
          if (t.length >= 2) out.add(t);
        }
      }
    };
    walk(ast, false);
    return [...out];
  }

  /**
   * Filters the whole window again. Candidate lines (not markers, not your own hidden reads) are
   * checked newest first within FILTER_BUDGET_MS: a slow pattern (a /regex/ that backtracks on long
   * lines) stops early instead of freezing the tab, and the lines it did not reach are neither shown
   * nor counted; the notice, a marker, the count, the empty state and the export menu say so.
   */
  refilter() {
    this.filterGen += 1;
    const counts = new Array(this.families.length).fill(0);
    const vis = [];
    const times = [];
    const series = [];
    let selfHidden = 0;
    let matches = 0;
    this.facets = FACETS.map(() => new Map());
    const cand = [];
    for (let i = this.rows.length - 1; i >= 0; i -= 1) {
      const row = this.rows[i];
      if (row.marker) continue;
      row.fs = 0;
      if (row.self && !this.showSelf) {
        selfHidden += 1;
        row.fs = FS_SELF;
        continue;
      }
      cand.push(row);
    }
    const res = this.q.filterTimed(cand, (row) => this.pred(row.p), FILTER_BUDGET_MS);
    const pass = new Set(res.rows);
    // Lines past `checked` (older) were not reached: kept apart, oldest first.
    this.unchecked = res.complete ? [] : cand.slice(res.checked).reverse();
    const oldest = !res.complete && res.checked ? cand[res.checked - 1] : null;
    const cutSeq = res.complete ? -Infinity : oldest ? oldest.seq : Infinity;
    this.appendCut = [];
    for (const row of this.rows) {
      if (row.marker) {
        if (row.seq > cutSeq) vis.push(row);
        continue;
      }
      if (!pass.has(row)) continue;
      const famOn = !this.famOff.has(row.fam);
      if (famOn && row.time !== null) {
        times.push(row.time);
        series.push(row.famIx);
        row.fs |= FS_HIST;
      }
      if (!this.predTime(row.p)) continue;
      counts[row.famIx] += 1;
      row.fs |= FS_COUNT;
      if (!famOn) continue;
      vis.push(row);
      row.fs |= FS_VIS;
      this.facetAdd(row, 1);
      if (this.markRe) {
        this.markRe.lastIndex = 0;
        if (this.markRe.test(row.line)) {
          matches += 1;
          row.fs |= FS_MATCH;
        }
      }
    }
    // Markers between nothing are noise: drop leading/consecutive markers in the visible list.
    const tidy = this.tidyMarkers(vis);
    if (!res.complete) {
      let at = null;
      for (let i = res.checked - 1; i >= 0 && at === null; i -= 1) if (cand[i].time !== null) at = cand[i].time;
      this.filterCut = { ms: Math.round(res.ms), checked: res.checked, total: cand.length, time: at };
      // Above the oldest checked line (or alone, when none was checked): the lines above were not checked.
      tidy.unshift(this.cutMarker(oldest ? oldest.seq : (this.rows.length ? this.rows[this.rows.length - 1].seq + 0.5 : 0)));
    } else {
      this.filterCut = null;
    }
    this.visible = this.withDividers(tidy);
    this.famCounts = counts;
    this.selfHidden = selfHidden;
    this.matchCount = matches;
    this.hist = { times, series };
    this.facetsDirty = true;
    const anchor = this.follow ? null : this.list.anchor();
    this.list.setItems(this.visible);
    if (this.follow) this.list.scrollToEnd();
    else if (anchor) this.list.restore(anchor, (seq) => this.indexOfSeq(seq));
    this.unseen = 0;
    this.renderAll();
  }

  /** The marker above the oldest line a time-boxed refilter checked; `seq` sorts it just before that line. */
  cutMarker(seq) {
    const ms = this.filterCut ? this.filterCut.ms : FILTER_BUDGET_MS;
    return { seq: seq - 0.75, line: '', p: null, fam: 'other', famIx: 0, time: null, self: false, sid: null, len: 0, pl: 0, marker: { kind: 'cut', text: `Lines above were not checked: the filter stopped after ${ms} ms` } };
  }

  tidyMarkers(vis) {
    const out = [];
    for (const row of vis) {
      if (row.marker && (!out.length || out[out.length - 1].marker)) {
        if (out.length && out[out.length - 1].marker) out[out.length - 1] = row;
        else if (!out.length) continue;
        continue;
      }
      out.push(row);
    }
    while (out.length && out[out.length - 1].marker) out.pop();
    return out;
  }

  /** Compact: a 20 px row with the date before the first line of each day (times show no date). */
  withDividers(vis) {
    this.lastDay = null;
    if (!this.compact) return vis;
    const out = [];
    for (const row of vis) {
      if (!row.marker && row.time !== null) {
        const d = dayKey(row.time);
        if (d !== this.lastDay) {
          out.push(this.dividerFor(row));
          this.lastDay = d;
        }
      }
      out.push(row);
    }
    return out;
  }

  dividerFor(row) {
    // seq sits between the row and the one before it, so the visible list stays sorted by seq.
    return { seq: row.seq - 0.5, line: '', p: null, fam: 'other', famIx: 0, time: row.time, self: false, sid: null, len: 0, pl: 0, marker: { kind: 'day', text: dayLabel(row.time), zoned: Boolean(row.p && row.p.zoned) } };
  }

  /**
   * Filters only the lines a read added, within APPEND_BUDGET_MS. When the filter cannot keep up, the
   * lines it did not reach are not shown, and the live tail pauses until the query changes.
   */
  filterAppend(added) {
    const from = this.visible.length;
    let visibleAdded = 0;
    let pendingMarker = null;
    const cand = [];
    for (const row of added) {
      if (row.marker) continue;
      row.fs = 0;
      if (row.self && !this.showSelf) {
        this.selfHidden += 1;
        row.fs = FS_SELF;
        continue;
      }
      cand.push(row);
    }
    const res = this.q.filterTimed(cand, (row) => this.pred(row.p), APPEND_BUDGET_MS);
    const pass = new Set(res.rows);
    const late = res.complete ? null : new Set(cand.slice(res.checked));
    for (const row of added) {
      if (row.marker) {
        pendingMarker = row;
        continue;
      }
      if (late && late.has(row)) continue;
      if (!pass.has(row)) continue;
      const famOn = !this.famOff.has(row.fam);
      if (famOn && row.time !== null) {
        this.hist.times.push(row.time);
        this.hist.series.push(row.famIx);
        row.fs |= FS_HIST;
      }
      if (!this.predTime(row.p)) continue;
      this.famCounts[row.famIx] += 1;
      row.fs |= FS_COUNT;
      if (!famOn) continue;
      if (pendingMarker && this.visible.some((x) => !x.marker)) this.visible.push(pendingMarker);
      pendingMarker = null;
      if (this.compact && row.time !== null) {
        const d = dayKey(row.time);
        if (d !== this.lastDay) {
          this.visible.push(this.dividerFor(row));
          this.lastDay = d;
        }
      }
      this.visible.push(row);
      row.fs |= FS_VIS;
      this.facetAdd(row, 1);
      visibleAdded += 1;
      if (this.markRe) {
        this.markRe.lastIndex = 0;
        if (this.markRe.test(row.line)) {
          this.matchCount += 1;
          row.fs |= FS_MATCH;
        }
      }
    }
    if (late) {
      for (const row of late) this.appendCut.push(row);
      if (!this.paused) {
        this.paused = true;
        clearTimeout(this.timers.poll);
        this.renderLive();
      }
      this.notice = { kind: 'warn', tag: 'append', text: `Live paused: the filter needed more than ${APPEND_BUDGET_MS} ms for the new lines; unchecked lines are not shown. Change the query, then resume (space).` };
      this.renderNotice();
    }
    if (this.visible.length > from) {
      // When following, afterIngest() scrolls to the end and draws once there.
      this.list.appended(from, { draw: !this.follow });
      if (!this.follow) this.unseen += visibleAdded;
      this.facetsDirty = true;
    }
  }

  indexOfSeq(seq) {
    const v = this.visible;
    let lo = 0;
    let hi = v.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      const s = v[mid].seq;
      if (s === seq) return mid;
      if (s < seq) lo = mid + 1;
      else hi = mid - 1;
    }
    return -1;
  }

  /** Click: only this family (again: all). Alt-click: hide it. Shift-click: add or remove it. */
  toggleFamily(id, e) {
    const all = this.families.map((f) => f.id);
    if (e && e.altKey) {
      if (this.famOff.has(id)) this.famOff.delete(id);
      else this.famOff.add(id);
    } else if (e && (e.shiftKey || e.metaKey || e.ctrlKey)) {
      if (this.famOff.has(id)) this.famOff.delete(id);
      else if (this.famOff.size < all.length - 1) this.famOff.add(id);
    } else {
      const only = this.famOff.size === all.length - 1 && !this.famOff.has(id);
      this.famOff = only ? new Set() : new Set(all.filter((x) => x !== id));
    }
    this.writeRoute();
    this.refilter();
  }

  toggleSelf() {
    this.showSelf = !this.showSelf;
    this.writeRoute();
    this.refilter();
  }

  onBrush(range) {
    const base = this.withoutTimeTerms(this.queryText);
    let next = base;
    if (range) {
      const lo = Math.floor(range.lo / 1000) * 1000;
      const hi = Math.floor(range.hi / 1000) * 1000;
      const fmt = (ms) => isoNoZone(ms);
      next = `${base ? `${base} ` : ''}time>=${fmt(lo)} time<=${fmt(hi)}`;
    }
    this.setQuery(next.trim());
    this.ctx.ui.announce(range ? `Time range ${clock(range.lo)} to ${clock(range.hi)} (${this.zoneShort()})` : 'Time range cleared');
  }

  setQuery(text) {
    this.queryText = text;
    if (this.bar) this.bar.setValue(text);
    this.applyQuery(text, this.bar ? this.bar.parsed : this.q.parse(text, { view: 'logs' }), {});
    this.writeRoute();
  }

  /** Click-to-filter: AND `term` (or its exclusion) onto the query; replaces the opposite term. */
  addTerm(term, exclude) {
    const t = exclude ? `-${term}` : term;
    const opposite = exclude ? term : `-${term}`;
    let text = this.queryText.trim();
    const cur = text ? this.q.parse(text, { view: 'logs' }) : { ast: null, error: null };
    if (cur.ast) {
      const items = cur.ast.type === 'and' ? cur.ast.items : [cur.ast];
      const same = (it, want) => this.q.toQueryString(it) === this.q.toQueryString(this.q.parse(want).ast);
      if (items.some((it) => same(it, t))) {
        this.ctx.ui.toast(`Already filtering by ${t}.`, 'info');
        return;
      }
      const drop = items.find((it) => same(it, opposite));
      if (drop) {
        const a = drop.gpos ?? drop.pos;
        const b = drop.gend ?? drop.end;
        text = `${text.slice(0, a)} ${text.slice(b)}`.replace(/\s{2,}/g, ' ').trim();
      } else if (cur.ast.type === 'or') {
        text = `(${text})`; // "a OR b" then a new term must AND the whole, not just b
      }
    }
    const next = text ? `${text} ${t}` : t;
    const check = this.q.parse(next, { view: 'logs' });
    if (check.error) {
      this.ctx.ui.toast(`That value cannot be added as a filter: ${check.error.message}`, 'warn');
      return;
    }
    this.setQuery(next);
    this.ctx.ui.toast(`${exclude ? 'Excluding' : 'Filtering by'} ${term}`, 'ok');
  }

  tokenTerm(tk) {
    if (tk.nc || tk.t === 'ctl' || tk.t === 'cap') return null;
    const v = tk.q !== undefined && tk.q !== null ? tk.q : tk.v;
    let value = String(v).trim();
    if (tk.t === 'port' && !tk.q) value = value.replace(/^[/:]/, '');
    if (tk.t === 'str') value = value.replace(/^['"]|['"]$/g, '');
    // Invisible and direction-changing characters never go into the query: they match as a wildcard.
    if (this.lp.CONTROL_RE && this.lp.CONTROL_RE.test(value)) value = value.split('').map((c) => (this.lp.CONTROL_RE.test(c) ? '*' : c)).join('').replace(/\*+/g, '*');
    if (!value || value === '*') return null;
    if (tk.k) return termText(tk.k, value);
    if (tk.t === 'pid') return termText(null, value.replace(/^\[|\]$/g, ''));
    return termText(null, value);
  }

  rowsForSuggest() {
    const out = [];
    for (let i = this.rows.length - 1; i >= 0 && out.length < 3000; i -= 1) if (!this.rows[i].marker) out.push(this.rows[i].p);
    return out;
  }

  updateHints() {
    const inv = this.ctx.store.lastInventory;
    const scope = inv && inv.scope;
    if (!scope) {
      this.hints = null;
      return;
    }
    const zones = ((scope.zones && scope.zones.rows) || []).map((z) => z.name).filter(Boolean);
    const ifaces = ((scope.zones && scope.zones.rows) || []).flatMap((z) => (z.interfaces || []).map((i) => i.name)).filter(Boolean);
    const policies = ((scope.policies && scope.policies.rows) || []).map((p) => p.name).filter(Boolean);
    this.hints = { zones: new Set(zones), policies: new Set(policies), ifaces: new Set(ifaces) };
    this.hintGen += 1;
  }

  tokensOf(row) {
    if (row.tg !== this.hintGen || !row.toks) {
      row.toks = this.hints ? this.lp.tokenize(row.line, this.hints) : this.lp.tokenize(row.line);
      row.tg = this.hintGen;
    }
    return row.toks;
  }

  markRanges(line) {
    const re = this.markRe;
    if (!re) return null;
    re.lastIndex = 0;
    const out = [];
    let m;
    let guard = 0;
    while ((m = re.exec(line)) && guard < 200) {
      guard += 1;
      if (!m[0].length) {
        re.lastIndex += 1;
        continue;
      }
      const s = m.index;
      const e = s + m[0].length;
      if (out.length && s <= out[out.length - 1][1]) out[out.length - 1][1] = Math.max(out[out.length - 1][1], e);
      else out.push([s, e]);
    }
    return out.length ? out : null;
  }

  // ---- painting -----------------------------------------------------------------------------------

  twoLineMode() {
    return Boolean(this.compact && this.wrap && this.narrow);
  }

  /** The paint key: rows measured under another key are measured (and painted) again. */
  updatePaintKey() {
    const key = `${this.compact ? 'c' : 'r'}${this.twoLineMode() ? '2' : '1'}|${this.compact ? this.singleHost || '' : ''}|${this.zoneName || ''}`;
    const changed = key !== this.pkey;
    this.pkey = key;
    return changed;
  }

  /** Compact, wrap or the width class changed: measure every row again and rebuild the list. */
  repaint() {
    this.updatePaintKey();
    for (const row of this.rows) this.measureRow(row);
    this.compactBtn.setAttribute('aria-pressed', this.compact ? 'true' : 'false');
    this.wrapBtn.setAttribute('aria-pressed', this.wrap ? 'true' : 'false');
    this.list.wrap = this.wrap;
    this.list.twoLine = this.twoLineMode();
    this.list.body.classList.toggle('is-wrap', this.wrap);
    this.list.body.classList.toggle('is-two', this.wrap && this.list.twoLine);
    this.list.body.classList.toggle('is-compact', this.compact);
    this.list.measure();
    this.refilter();
  }

  hostAdd(row, d) {
    const host = row.p && row.p.host;
    if (!host) return;
    const n = (this.hostCounts.get(host) || 0) + d;
    if (n > 0) this.hostCounts.set(host, n);
    else this.hostCounts.delete(host);
  }

  /** Whether the "one host in the window" answer changed (Compact then hides or shows the host). */
  checkHosts() {
    const single = this.hostCounts.size === 1 ? this.hostCounts.keys().next().value : null;
    if (single === this.singleHost) return false;
    this.singleHost = single;
    this.renderHost();
    return this.compact;
  }

  /** Sets row.pl (painted columns) and row.ph (two-line head columns) for the virtual list. */
  measureRow(row) {
    if (row.marker || row.pk === this.pkey) return;
    row.pk = this.pkey;
    row.ptoks = null;
    let len;
    let head = 0;
    if (!this.compact) {
      len = row.len + row.nctl * CTL_EXTRA;
    } else if (row.p.flow) {
      const m = this.flowModel(row);
      len = m.len;
      head = m.head;
    } else {
      len = row.len + row.nctl * CTL_EXTRA;
      for (const ed of this.compactEdits(row)) {
        const cut = row.nctl ? this.lp.countControls(row.line.slice(ed.s, ed.e)) : 0;
        len += (ed.rep ? ed.rep.v.length : 0) - (ed.e - ed.s) - cut * CTL_EXTRA;
      }
    }
    row.full = len;
    row.capNote = len > LINE_CAP ? ` … ${this.fmt.num(len - LINE_CAP)} more characters: open the line to read it all` : null;
    row.pl = row.capNote ? LINE_CAP + row.capNote.length : len;
    row.ph = this.twoLineMode() ? head : 0;
  }

  tsToken(row) {
    const p = row.p;
    let zone;
    if (this.zoneName) zone = p.zoned ? `shown in the device zone ${this.zoneName} (configured)` : `no zone in the line; read in the device zone ${this.zoneName} (configured)`;
    else zone = p.zoned ? 'UTC' : 'device clock, no zone in the line (read as UTC)';
    return { t: 'ts', v: shortClock(row.time, hasMs(p)), title: `${this.lp.escapeControls(p.ts)} · ${zone}` };
  }

  /** Header edits for a compact non-RT_FLOW line: [{s, e, rep}] over the raw line, sorted. */
  compactEdits(row) {
    const p = row.p;
    const hd = p.hdr || {};
    const out = [];
    if (hd.pri) out.push({ s: hd.pri[0], e: hd.pri[1], rep: null });
    if (hd.ts && row.time !== null) out.push({ s: hd.ts[0], e: hd.ts[1], rep: this.tsToken(row) });
    if (hd.host && (p.host === null || p.host === this.singleHost)) out.push({ s: hd.host[0], e: hd.host[1], rep: null });
    if (hd.procid) out.push({ s: hd.procid[0], e: hd.procid[1], rep: null });
    if (hd.sdid) out.push({ s: hd.sdid[0], e: hd.sdid[1], rep: { t: 'sdid', v: '[', title: `structured data ${p.sdid || ''}`.trim() } });
    out.sort((x, y) => x.s - y.s);
    return out;
  }

  /** Cuts and replaces header ranges in a token list (tokens are shared: never mutated). */
  cutTokens(toks, edits) {
    if (!edits.length) return toks;
    const out = [];
    let pos = 0;
    let ei = 0;
    const piece = (tk, a, b) => {
      const o = { ...tk, v: tk.v.slice(a, b) };
      if (tk.t !== 'text' && o.q === undefined) o.q = tk.v;
      return o;
    };
    for (const tk of toks) {
      const s = pos;
      const e = pos + tk.v.length;
      pos = e;
      let at = s;
      while (at < e) {
        while (ei < edits.length && edits[ei].e <= at) ei += 1;
        const ed = edits[ei];
        if (!ed || ed.s >= e) {
          out.push(at === s ? tk : piece(tk, at - s));
          break;
        }
        if (ed.s > at) {
          out.push(piece(tk, at - s, ed.s - s));
          at = ed.s;
        }
        if (!ed.done) {
          if (ed.rep) out.push(ed.rep);
          ed.done = true;
        }
        at = Math.min(e, ed.e);
      }
    }
    return out;
  }

  /** Control characters paint as a visible "U+XXXX" badge (6 columns). */
  expandCtl(toks) {
    if (!toks.some((t) => t.t === 'ctl' || (this.lp.CONTROL_RE && this.lp.CONTROL_RE.test(t.v)))) return toks;
    const out = [];
    for (const tk of toks) {
      if (tk.t === 'ctl') {
        const name = this.lp.controlName(tk.v);
        out.push({ t: 'ctl', v: name, nc: 1, title: `A hidden ${name} character is here (shown, not applied)` });
        continue;
      }
      if (!this.lp.CONTROL_RE.test(tk.v)) {
        out.push(tk);
        continue;
      }
      let buf = '';
      for (const ch of tk.v) {
        if (this.lp.CONTROL_RE.test(ch)) {
          if (buf) out.push({ ...tk, v: buf, q: tk.q !== undefined ? tk.q : tk.v });
          buf = '';
          const name = this.lp.controlName(ch);
          out.push({ t: 'ctl', v: name, nc: 1, title: `A hidden ${name} character is here (shown, not applied)` });
        } else {
          buf += ch;
        }
      }
      if (buf) out.push({ ...tk, v: buf, q: tk.q !== undefined ? tk.q : tk.v });
    }
    return out;
  }

  /** Compact RT_FLOW row: time, family badge, then the summary; `head` columns form line 1 when two-line. */
  flowModel(row, keep = false) {
    const p = row.p;
    const two = this.twoLineMode();
    const head = [];
    if (row.time !== null) head.push(this.tsToken(row));
    else if (p.ts) head.push({ t: 'ts', v: p.ts });
    head.push({ t: 'text', v: ' ' });
    if (p.host && p.host !== this.singleHost) head.push({ t: 'host', v: p.host, k: 'host' }, { t: 'text', v: ' ' });
    const badge = this.lp.flowBadge(p) || p.tag || 'RT_FLOW';
    head.push({ t: 'tag', v: badge, k: 'tag', q: p.tag, title: p.tag, badge: 1 });
    head.push({ t: 'text', v: two ? ' ' : ' '.repeat(Math.max(1, 7 - badge.length)) });
    const h2 = this.expandCtl(head);
    const body = this.expandCtl(this.lp.summary(p, { pad: !two, rest: !two }) || []);
    let hl = 0;
    for (const t of h2) hl += t.v.length;
    let len = hl;
    for (const t of body) len += t.v.length;
    const m = { len, head: hl, hn: h2.length };
    if (keep) m.toks = h2.concat(body);
    return m;
  }

  /** The tokens painted for a row in the current mode (memoised per row). */
  paintOf(row) {
    if (row.pk !== this.pkey) this.measureRow(row);
    if (row.ptoks && row.ptg === this.hintGen) return row.ptoks;
    let toks;
    row.phn = 0;
    if (!this.compact) {
      toks = this.expandCtl(this.tokensOf(row));
    } else if (row.p.flow) {
      const m = this.flowModel(row, true);
      toks = m.toks;
      row.phn = this.twoLineMode() ? m.hn : 0;
    } else {
      toks = this.expandCtl(this.cutTokens(this.tokensOf(row), this.compactEdits(row)));
    }
    if (row.capNote) toks = this.capTokens(toks, row.capNote);
    row.ptoks = toks;
    row.ptg = this.hintGen;
    return toks;
  }

  /** At most LINE_CAP columns of a very long line, then a note; the panel and Copy line keep it all. */
  capTokens(toks, note) {
    const out = [];
    let n = 0;
    for (const tk of toks) {
      if (n + tk.v.length <= LINE_CAP) {
        out.push(tk);
        n += tk.v.length;
        continue;
      }
      const rest = LINE_CAP - n;
      if (rest > 0) out.push({ ...tk, v: tk.v.slice(0, rest), q: tk.q !== undefined ? tk.q : tk.v });
      break;
    }
    out.push({ t: 'cap', v: note, nc: 1 });
    return out;
  }

  // ---- rendering rows -----------------------------------------------------------------------------

  /**
   * Appends display tokens to `box(i)` (the element for token i); marks search hits in the painted
   * text. Returns whether any mark was made.
   */
  fillTokens(box, toks, { interactive = false, fam = 'other' } = {}) {
    let ranges = null;
    if (this.markRe) {
      let text = '';
      for (const t of toks) text += t.v;
      ranges = this.markRanges(text);
    }
    let pos = 0;
    let ri = 0;
    for (let ti = 0; ti < toks.length; ti += 1) {
      const tk = toks[ti];
      const target = typeof box === 'function' ? box(ti) : box;
      const v = tk.v;
      const s = pos;
      const e = pos + v.length;
      pos = e;
      let el = target;
      if (tk.t !== 'text' || tk.f || tk.title) {
        const span = document.createElement('span');
        let cls = tk.t === 'text' ? '' : `tk-${tk.t}`;
        if (tk.t === 'tag') cls += ` fam-${fam}`;
        if (tk.badge) cls += ' lg-badge';
        if (tk.f) cls += ' lg-faint';
        if (interactive && CLICKABLE.has(tk.t) && !tk.nc && v.trim()) {
          cls += ' tk-click';
          span.dataset.ti = String(ti);
        }
        if (cls) span.className = cls.trim();
        if (tk.title) span.title = tk.title;
        target.append(span);
        el = span;
      }
      while (ranges && ri < ranges.length && ranges[ri][1] <= s) ri += 1;
      if (!ranges || ri >= ranges.length || ranges[ri][0] >= e) {
        el.append(v);
        continue;
      }
      let at = s;
      let k = ri;
      while (at < e) {
        const r = ranges[k];
        if (!r || r[0] >= e) {
          el.append(v.slice(at - s));
          break;
        }
        if (r[0] > at) {
          el.append(v.slice(at - s, r[0] - s));
          at = r[0];
        }
        const stop = Math.min(e, r[1]);
        const mark = document.createElement('mark');
        mark.className = 'lg-hit';
        mark.textContent = v.slice(at - s, stop - s);
        el.append(mark);
        at = stop;
        if (r[1] <= e) k += 1;
      }
    }
    return Boolean(ranges);
  }

  renderRow(row) {
    const node = document.createElement('div');
    node.setAttribute('role', 'row');
    node.id = `lg-r-${String(row.seq).replace('.', '-')}`;
    node.dataset.seq = String(row.seq);
    if (row.marker && row.marker.kind === 'day') {
      node.className = 'lg-row lg-day';
      const cell = document.createElement('span');
      cell.setAttribute('role', 'gridcell');
      cell.className = 'lg-day-text';
      const zone = document.createElement('span');
      zone.className = 'lg-day-zone';
      if (this.zoneName) {
        zone.textContent = `times in ${this.zoneName} (device zone, configured)`;
        zone.title = row.marker.zoned
          ? `The lines carry their time zone; times are shown in the device's configured zone ${this.zoneName}.`
          : `These lines carry no time zone; J-Wicket reads them in the device's configured zone ${this.zoneName}. A time-zone change takes effect for all processes only after a reboot.`;
      } else {
        zone.textContent = row.marker.zoned ? 'times in UTC' : 'device clock, read as UTC';
        zone.title = row.marker.zoned
          ? 'The lines carry their time zone; times are shown in UTC.'
          : 'These lines carry no time zone. J-Wicket reads them as UTC; if the device logs in local time, times are off by its UTC offset.';
      }
      cell.append(document.createTextNode(row.marker.text), zone);
      node.append(cell);
      return node;
    }
    if (row.marker) {
      node.className = `lg-row lg-marker is-${row.marker.kind}`;
      const cell = document.createElement('span');
      cell.setAttribute('role', 'gridcell');
      cell.className = 'lg-marker-text';
      cell.append(this.dom.icon(row.marker.kind === 'reset' ? 'refresh' : row.marker.kind === 'cut' ? 'filter' : 'alert'), document.createTextNode(row.marker.text));
      node.append(cell);
      return node;
    }
    let cls = `lg-row fam-${row.fam}`;
    if (row.seq === this.selSeq) cls += ' is-sel';
    if (row.seq === this.curSeq) cls += ' is-cur';
    if (row.self) cls += ' is-self';
    else if (Number.isInteger(row.p.severity) && row.p.severity <= 3) cls += ' is-err';
    if (row.flash && Date.now() - row.added < NEW_MS) cls += row.flash === 'wash' ? ' is-new' : ' is-new-gut';
    node.className = cls;
    if (row.seq === this.selSeq) node.setAttribute('aria-selected', 'true');
    // The gutter carries the family stripe and the search bead; it stays put when long lines scroll.
    const gut = document.createElement('span');
    gut.className = 'lg-gut';
    gut.setAttribute('aria-hidden', 'true');
    const cell = document.createElement('span');
    cell.setAttribute('role', 'gridcell');
    cell.className = 'lg-text';
    const toks = this.paintOf(row);
    let hit;
    if (row.phn) {
      const head = document.createElement('span');
      head.className = 'lg-c-head';
      const body = document.createElement('span');
      body.className = 'lg-c-body';
      hit = this.fillTokens((i) => (i < row.phn ? head : body), toks, { interactive: true, fam: row.fam });
      cell.append(head, body);
    } else {
      hit = this.fillTokens(cell, toks, { interactive: true, fam: row.fam });
    }
    if (this.compact && row.p.flow) node.classList.add('is-sum');
    // The bead says the raw line matches, even when the match is in a part Compact does not paint.
    if (hit || (row.fs & FS_MATCH)) node.classList.add('has-hit');
    node.append(gut, cell);
    return node;
  }

  // ---- interaction --------------------------------------------------------------------------------

  rowOfEvent(e) {
    const el = e.target instanceof Element ? e.target.closest('.lg-row') : null;
    if (!el) return null;
    return this.bySeq.get(Number(el.dataset.seq)) || null;
  }

  onStreamClick(e) {
    const row = this.rowOfEvent(e);
    if (!row || row.marker) return;
    const sel = window.getSelection ? window.getSelection() : null;
    if (sel && !sel.isCollapsed && String(sel).trim()) return; // selecting text, not clicking
    const tkEl = e.target.closest('[data-ti]');
    if (tkEl) {
      const tk = this.paintOf(row)[Number(tkEl.dataset.ti)];
      const term = tk ? this.tokenTerm(tk) : null;
      if (term) {
        e.preventDefault();
        this.addTerm(term, e.altKey);
        return;
      }
    }
    this.select(row, { open: true });
  }

  onHover(e) {
    const row = this.rowOfEvent(e);
    const tkEl = e.target instanceof Element ? e.target.closest('[data-ti]') : null;
    const wrapBox = this.streamWrap.getBoundingClientRect();
    if (row && !row.marker) {
      const node = this.list.nodeOf(row.seq);
      if (node) {
        const r = node.getBoundingClientRect();
        this.hoverRow = row;
        this.hoverBar.hidden = false;
        const top = Math.max(0, Math.min(wrapBox.height - 26, r.top - wrapBox.top + (this.list.wrap ? 2 : (r.height - 24) / 2)));
        this.hoverBar.style.top = `${Math.round(top)}px`;
      }
    } else {
      this.hoverBar.hidden = true;
    }
    if (row && tkEl) {
      const tk = this.paintOf(row)[Number(tkEl.dataset.ti)];
      const term = tk ? this.tokenTerm(tk) : null;
      if (term) {
        const { h, put } = this.dom;
        put(this.hintEl, h('b', { class: 'mono' }, term), h('span', null, 'click: filter'), h('span', null, 'Alt: exclude'));
        this.hintEl.hidden = false;
        const r = tkEl.getBoundingClientRect();
        const w = this.hintEl.offsetWidth || 200;
        let left = r.left - wrapBox.left;
        left = Math.max(4, Math.min(wrapBox.width - w - 4, left));
        let top = r.top - wrapBox.top - 26;
        if (top < 2) top = r.bottom - wrapBox.top + 4;
        this.hintEl.style.left = `${Math.round(left)}px`;
        this.hintEl.style.top = `${Math.round(top)}px`;
        return;
      }
    }
    this.hintEl.hidden = true;
  }

  hideHover() {
    this.hintEl.hidden = true;
    this.hoverBar.hidden = true;
    this.hoverRow = null;
  }

  onScroll(programmatic) {
    this.hintEl.hidden = true;
    this.hoverBar.hidden = true;
    if (programmatic) return;
    const atEnd = this.list.atEnd();
    if (this.follow && !atEnd) {
      this.follow = false;
      this.renderFollow();
    } else if (!this.follow && atEnd && this.unseen) {
      this.unseen = 0;
      this.renderNewPill();
    }
  }

  isTyping(el) {
    if (!el || el === document.body) return false;
    if (el.isContentEditable) return true;
    const tag = el.tagName;
    if (tag === 'TEXTAREA' || tag === 'SELECT') return true;
    if (tag === 'INPUT') {
      const type = (el.getAttribute('type') || 'text').toLowerCase();
      return !['button', 'checkbox', 'radio', 'submit', 'reset', 'range'].includes(type);
    }
    return false;
  }

  onKey(e) {
    if (e.defaultPrevented || e.metaKey || e.ctrlKey || e.altKey) return;
    if (this.isTyping(e.target) || document.querySelector('.layer')) return;
    if (!this.el.isConnected) return;
    const key = e.key;
    if (key === 'j' || key === 'k') {
      e.preventDefault();
      this.moveSelection(key === 'j' ? 1 : -1, true);
    } else if (key === 'c') {
      e.preventDefault();
      this.toggleCompact();
    } else if (key === 'w') {
      e.preventDefault();
      this.toggleWrap();
    } else if (key === 'y' && this.selSeq !== null) {
      const row = this.bySeq.get(this.selSeq);
      if (row) {
        e.preventDefault();
        this.copyLine(row);
      }
    } else if (key === 'Enter' && this.selSeq !== null && (e.target === this.scroller || e.target === document.body || e.target.id === 'main')) {
      const row = this.bySeq.get(this.selSeq);
      if (row) {
        e.preventDefault();
        this.select(row, { open: true });
      }
    }
  }

  onGridKey(e) {
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    const k = e.key;
    if (k === 'ArrowDown' || k === 'ArrowUp') {
      e.preventDefault();
      this.moveSelection(k === 'ArrowDown' ? 1 : -1, false);
    } else if (k === 'PageDown' || k === 'PageUp') {
      e.preventDefault();
      const per = Math.max(1, Math.floor(this.scroller.clientHeight / this.list.lh) - 1);
      this.moveSelection((k === 'PageDown' ? 1 : -1) * per, false);
    } else if (k === 'Home' || k === 'End') {
      e.preventDefault();
      const rows = this.visible.filter((r) => !r.marker);
      const row = k === 'Home' ? rows[0] : rows[rows.length - 1];
      if (row) this.select(row, { scroll: true });
      if (k === 'End') {
        this.follow = true;
        this.renderFollow();
      }
    }
  }

  moveSelection(delta, keepPanel) {
    if (!this.visible.length) return;
    let i = this.selSeq === null ? -1 : this.indexOfSeq(this.selSeq);
    if (i < 0) {
      const r = this.list.range;
      i = delta > 0 ? Math.max(0, r.first) - 1 : Math.min(this.visible.length, r.last + 1);
    }
    let j = i + delta;
    j = Math.max(0, Math.min(this.visible.length - 1, j));
    // Step over markers (day headers, cut and gap notes) in the direction of travel, staying in
    // bounds: a list that starts with a day header must still let j select its first line.
    const step = delta > 0 ? 1 : -1;
    while (this.visible[j] && this.visible[j].marker && j + step >= 0 && j + step < this.visible.length) j += step;
    const row = this.visible[j];
    if (!row || row.marker) return;
    if (this.follow && delta < 0) {
      this.follow = false;
      this.renderFollow();
    }
    this.select(row, { scroll: true, open: keepPanel && this.panelSeq !== null });
  }

  select(row, { open = false, scroll = false } = {}) {
    if (!row || row.marker) return;
    const prev = this.selSeq;
    this.selSeq = row.seq;
    if (prev !== null && prev !== row.seq) {
      const old = this.list.nodeOf(prev);
      if (old) {
        old.classList.remove('is-sel');
        old.removeAttribute('aria-selected');
      }
    }
    const node = this.list.nodeOf(row.seq);
    if (node) {
      node.classList.add('is-sel');
      node.setAttribute('aria-selected', 'true');
    }
    this.scroller.setAttribute('aria-activedescendant', `lg-r-${row.seq}`);
    if (scroll) {
      const i = this.indexOfSeq(row.seq);
      if (i >= 0) this.list.scrollToIndex(i);
      const n = this.list.nodeOf(row.seq);
      if (n) {
        n.classList.add('is-sel');
        n.setAttribute('aria-selected', 'true');
      }
    }
    if (open) this.openDetail(row);
  }

  clearSelection() {
    const prev = [this.selSeq, this.curSeq];
    this.selSeq = null;
    this.curSeq = null;
    for (const seq of prev) {
      const row = seq !== null ? this.bySeq.get(seq) : null;
      if (row) this.list.refreshRow(row);
    }
    this.scroller.removeAttribute('aria-activedescendant');
    this.renderMatchNav();
  }

  nextMatch(dir) {
    if (!this.markRe) {
      this.ctx.ui.toast('Add a word or value to the query first: n and N jump between its matches.', 'info');
      return;
    }
    const v = this.visible;
    if (!v.length) return;
    let i = this.curSeq !== null ? this.indexOfSeq(this.curSeq) : this.selSeq !== null ? this.indexOfSeq(this.selSeq) : dir > 0 ? -1 : v.length;
    for (let step = 0; step < v.length; step += 1) {
      i += dir;
      if (i >= v.length) i = 0;
      if (i < 0) i = v.length - 1;
      const row = v[i];
      if (row.marker) continue;
      this.markRe.lastIndex = 0;
      if (this.markRe.test(row.line)) {
        const prev = this.curSeq !== null ? this.bySeq.get(this.curSeq) : null;
        this.curSeq = row.seq;
        if (prev) this.list.refreshRow(prev);
        if (this.follow) {
          this.follow = false;
          this.renderFollow();
        }
        this.select(row, { scroll: true, open: this.panelSeq !== null });
        this.list.scrollToIndex(i, 'center');
        this.list.refreshRow(row);
        this.revealMark(row);
        this.renderMatchNav();
        return;
      }
    }
    this.ctx.ui.toast('No line in view matches.', 'info');
  }

  /** Long unwrapped lines: scroll sideways so the first mark of `row` is in view. */
  revealMark(row) {
    if (this.list.wrap) return;
    const node = this.list.nodeOf(row.seq);
    const mark = node && node.querySelector('.lg-hit');
    if (!mark) return;
    const sr = this.scroller.getBoundingClientRect();
    const mr = mark.getBoundingClientRect();
    if (mr.left < sr.left + 24 || mr.right > sr.right - 24) {
      this.scroller.scrollLeft = Math.max(0, this.scroller.scrollLeft + (mr.left - sr.left) - 160);
    }
  }

  toggleFollow() {
    this.follow = !this.follow;
    if (this.follow) this.jumpToEnd();
    this.renderFollow();
  }

  jumpToEnd() {
    this.follow = true;
    this.unseen = 0;
    this.list.scrollToEnd();
    this.renderFollow();
  }

  toggleWrap() {
    this.wrap = !this.wrap;
    prefSet(PREF.wrap, this.wrap ? '1' : '0');
    this.repaint();
  }

  toggleCompact() {
    this.compact = !this.compact;
    prefSet(PREF.compact, this.compact ? '1' : '0');
    this.repaint();
    this.renderHost();
    this.ctx.ui.announce(this.compact ? 'Compact lines; Copy line and the panel keep the exact line' : 'Full lines as written');
  }

  toggleFacets() {
    this.facetsOn = !this.facetsOn;
    prefSet(PREF.facets, this.facetsOn ? '1' : '0');
    this.facetsBtn.setAttribute('aria-pressed', this.facetsOn ? 'true' : 'false');
    this.facetsEl.hidden = !this.facetsOn;
    this.mainEl.classList.toggle('has-facets', this.facetsOn);
    this.facetsDirty = true;
    this.renderFacets(true);
    this.list.measure();
  }

  // ---- top values ---------------------------------------------------------------------------------

  /** Facet keys of a line: [src, dst, dport, policy, reason, zone pair] (null when absent). */
  facetKeys(p) {
    const f = p.fields || {};
    const fl = p.flow;
    const real = (v) => (isPlaceholder(v) ? null : String(v));
    // "unknown" is one of Junos's documented close reasons, not a placeholder (LOG-05).
    const realReason = (v) => (v === null || v === undefined || this.lp.isPlaceholderValue('reason', v) ? null : String(v));
    const src = fl ? fl.src : hostOnly(f['source-address']);
    const dst = fl ? fl.dst : hostOnly(f['destination-address']);
    const dportRaw = fl ? fl.dport : f['destination-port'];
    const dport = dportRaw !== null && dportRaw !== undefined && /^\d+$/.test(String(dportRaw)) ? String(dportRaw) : null;
    const policy = fl ? fl.policy : real(f['policy-name']);
    const reason = realReason(fl ? fl.reason : f.reason);
    const from = fl ? fl.from : real(f['source-zone-name']);
    const to = fl ? fl.to : real(f['destination-zone-name']);
    const pair = from || to ? [from, to] : null;
    return { keys: [src, dst, dport, policy, reason, pair ? `${from || '?'} → ${to || '?'}` : null], pair };
  }

  facetAdd(row, d) {
    const keys = row.fk;
    if (!keys) return;
    for (let i = 0; i < keys.length; i += 1) {
      const key = keys[i];
      if (key === null || key === undefined) continue;
      const map = this.facets[i];
      const n = (map.get(key) || 0) + d;
      if (n > 0) map.set(key, n);
      else map.delete(key);
      if (i === 5 && d > 0 && row.pair) {
        if (!this.pairOf) this.pairOf = new Map();
        this.pairOf.set(key, row.pair);
      }
    }
  }

  /** Redraws the top-values rail (at most about once a second while live). */
  renderFacets(force = false) {
    if (!this.facetsOn || this.dead) return;
    if (!force && !this.facetsDirty) return;
    const now = Date.now();
    if (!force && now - this.facetsAt < FACET_MIN_MS) {
      if (!this.facetsTimer) this.facetsTimer = setTimeout(() => { this.facetsTimer = 0; this.renderFacets(true); }, FACET_MIN_MS - (now - this.facetsAt));
      return;
    }
    this.facetsAt = now;
    this.facetsDirty = false;
    const { h, put } = this.dom;
    const shown = this.visible.reduce((n, r) => n + (r.marker ? 0 : 1), 0);
    const sections = [];
    FACETS.forEach(([id, label], i) => {
      const map = this.facets[i];
      if (!map || !map.size) return;
      const top = [...map.entries()].sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1)).slice(0, FACET_TOP);
      const max = top[0][1];
      sections.push(
        h(
          'section',
          { class: 'lg-fc' },
          h('h3', { class: 'lg-fc-title' }, label, h('span', { class: 'faint' }, map.size > FACET_TOP ? ` top ${FACET_TOP} of ${this.fmt.num(map.size)}` : ` ${this.fmt.num(map.size)}`)),
          h(
            'ol',
            { class: 'lg-fc-list' },
            top.map(([value, n]) => {
              const bar = h('span', { class: 'lg-fc-bar', 'aria-hidden': 'true' });
              bar.style.setProperty('--w', `${Math.max(2, Math.round((n / max) * 100))}%`);
              return h(
                'li',
                null,
                h(
                  'button',
                  {
                    class: ['lg-fc-item', `fc-${id}`],
                    type: 'button',
                    dataset: { fc: String(i), value },
                    title: `${label}: ${this.lp.escapeControls(value)} · ${this.fmt.plural(n, 'line')}. Click to filter, Alt-click to exclude.`,
                  },
                  bar,
                  id === 'reason' ? this.reasonDot(value) : null,
                  h('span', { class: 'lg-fc-v mono dev-text' }, this.vis(value)),
                  h('span', { class: 'lg-fc-n mono' }, this.fmt.num(n)),
                ),
              );
            }),
          ),
        ),
      );
    });
    put(
      this.facetsEl,
      h('div', { class: 'lg-fc-head' }, h('h2', { class: 'lg-fc-h' }, 'Top values'), h('span', { class: 'faint' }, `over ${this.fmt.plural(shown, 'line')} shown`)),
      sections.length ? sections : h('p', { class: 'lg-fc-empty faint' }, 'No addresses, ports, policies or zones in the lines shown.'),
    );
  }

  onFacetClick(e) {
    const btn = e.target instanceof Element ? e.target.closest('.lg-fc-item') : null;
    if (!btn) return;
    const i = Number(btn.dataset.fc);
    const value = btn.dataset.value;
    const def = FACETS[i];
    if (!def) return;
    let term;
    if (def[0] === 'pair') {
      const pair = (this.pairOf && this.pairOf.get(value)) || null;
      if (!pair) return;
      const parts = [pair[0] ? termText('from', pair[0]) : null, pair[1] ? termText('to', pair[1]) : null].filter(Boolean);
      term = parts.length > 1 ? `(${parts.join(' ')})` : parts[0];
    } else {
      term = this.tokenTerm({ t: 'val', v: value, k: def[2] });
    }
    if (term) this.addTerm(term, e.altKey);
  }

  // ---- close reasons (LOG-06) ----------------------------------------------------------------------

  /** Title of a close reason: documented (Table 2) with J-Wicket's group, or shown as written. */
  reasonTitle(cr) {
    if (!cr) return null;
    if (!cr.documented) return "Not in Junos's documented close reasons; shown as written.";
    return `${cr.text}: a documented Junos close reason (Session Close Log Fields, Table 2); J-Wicket groups it as ${cr.group}.`;
  }

  /** A close-reason pill coloured by J-Wicket's group (an undocumented reason is muted). */
  closePill(reason, { small = false } = {}) {
    const { h } = this.dom;
    const cr = this.lp.closeReason(reason);
    if (!cr) return h('span', { class: ['pill', 'muted', small && 'lg-cr-sm'] }, 'closed');
    const group = cr.documented ? cr.group : 'other';
    return h(
      'span',
      { class: ['pill', CR_PILL[group] || 'muted', `cr-${group}`, !cr.documented && 'cr-undoc', small && 'lg-cr-sm', 'dev-text'], title: this.reasonTitle(cr) },
      this.vis(reason),
    );
  }

  /** The group dot in the Reasons facet. A reason seen only on DENY lines keeps the denied style. */
  reasonDot(value) {
    const { h } = this.dom;
    const cr = this.lp.closeReason(value);
    if (!cr) return null;
    if (!cr.documented && this.denyReasons.has(value)) {
      return h('span', { class: 'lg-fc-dot cr-deny', 'aria-hidden': 'true', title: 'A deny reason (RT_FLOW_SESSION_DENY), shown as written.' });
    }
    const group = cr.documented ? cr.group : 'other';
    return h('span', { class: ['lg-fc-dot', `cr-${group}`, !cr.documented && 'cr-undoc'], 'aria-hidden': 'true', title: this.reasonTitle(cr) });
  }

  renderHost() {
    const host = this.compact ? this.singleHost : null;
    this.hostEl.hidden = !host;
    if (!host) return;
    const { put, icon, h } = this.dom;
    put(this.hostEl, icon('server'), h('span', { class: 'mono' }, this.vis(host)));
    this.hostEl.title = `Every line in this window is from ${this.lp.escapeControls(host)}, so Compact leaves the host out of each line.`;
  }

  /** Device text for the panel and chips: control characters become visible "U+XXXX" badges. */
  vis(value) {
    const s = String(value ?? '');
    if (!this.lp.CONTROL_RE || !this.lp.CONTROL_RE.test(s)) return s;
    const { h } = this.dom;
    const out = [];
    let buf = '';
    for (const ch of s) {
      if (this.lp.CONTROL_RE.test(ch)) {
        if (buf) out.push(buf);
        buf = '';
        const name = this.lp.controlName(ch);
        out.push(h('span', { class: 'tk-ctl', title: `A hidden ${name} character is here (shown, not applied)` }, name));
      } else {
        buf += ch;
      }
    }
    if (buf) out.push(buf);
    return out;
  }

  // ---- time range presets -------------------------------------------------------------------------

  /** Query text without its time and age terms. */
  withoutTimeTerms(text) {
    const parsed = this.q.parse(text, { view: 'logs' });
    if (parsed.error || !parsed.ast) return text;
    const items = parsed.ast.type === 'and' ? parsed.ast.items : [parsed.ast];
    const cuts = [];
    for (const it of items) {
      const key = it.type === 'term' && it.key ? String(it.key).toLowerCase() : '';
      if (['time', 'ts', 'timestamp', 'age', 'ago', 'last'].includes(key) && /[<>]=?/.test(it.op || '')) cuts.push([it.gpos ?? it.pos, it.gend ?? it.end]);
    }
    if (!cuts.length) return text;
    let base = text;
    cuts.sort((a, b) => b[0] - a[0]);
    for (const [a, b] of cuts) base = `${base.slice(0, a)} ${base.slice(b)}`;
    return base.replace(/\s{2,}/g, ' ').replace(/(^|\s)(AND|and|&&)(\s+(AND|and|&&))+(\s|$)/g, '$1$2$5').replace(/^\s*(AND|and|&&)\s+|\s+(AND|and|&&)\s*$/g, '').trim();
  }

  setAge(v) {
    const base = this.withoutTimeTerms(this.queryText);
    this.setQuery(v ? `${base ? `${base} ` : ''}age<${v}`.trim() : base);
  }

  customRange() {
    const base = this.withoutTimeTerms(this.queryText);
    const t = this.hist.times;
    let lo = Infinity;
    let hi = -Infinity;
    for (const x of t) {
      if (x < lo) lo = x;
      if (x > hi) hi = x;
    }
    if (!Number.isFinite(lo)) {
      hi = Date.now();
      lo = hi - 3600000;
    }
    const fmt = (ms) => isoNoZone(Math.floor(ms / 60000) * 60000).slice(0, 16);
    this.setQuery(`${base ? `${base} ` : ''}time>=${fmt(lo)} time<=${fmt(hi + 60000)}`);
    if (this.bar) this.bar.focus();
    this.ctx.ui.toast(`Edit the two times in the query (${this.zoneShort()}); report and buffer sources send them to the device as written.`, 'info');
  }

  renderAges() {
    const text = this.queryText;
    let cur = 'all';
    const parsed = text ? this.q.parse(text, { view: 'logs' }) : null;
    if (parsed && !parsed.error && parsed.ast) {
      const items = parsed.ast.type === 'and' ? parsed.ast.items : [parsed.ast];
      for (const it of items) {
        const key = it.type === 'term' && it.key ? String(it.key).toLowerCase() : '';
        if (['age', 'ago', 'last'].includes(key) && it.values && it.values.length === 1) {
          const v = it.values[0].text;
          cur = AGES.some(([a]) => a === v) && (it.op === '<' || it.op === '<=') ? v : 'custom';
        } else if (['time', 'ts', 'timestamp'].includes(key) && /[<>]=?/.test(it.op || '')) {
          cur = 'custom';
        }
      }
    }
    for (const b of this.ageSeg.querySelectorAll('button')) b.setAttribute('aria-pressed', b.dataset.age === cur ? 'true' : 'false');
  }

  /** FIELDS.logs, except that `app` also matches the Junos service (app:junos-https, as in Sessions). */
  logFields() {
    const base = this.q.FIELDS.logs;
    const out = Object.assign({}, base);
    for (const sym of Object.getOwnPropertySymbols(base)) Object.defineProperty(out, sym, { value: base[sym], enumerable: false });
    // time: and age: follow the clock the times are shown in (LG-02); without the device zone they are
    // exactly the parser's time, as before.
    if (base.time) out.time = { ...base.time, get: (r) => this.frameOf(r) };
    if (base.age) {
      out.age = {
        ...base.age,
        get: (r, c) => {
          const t = this.instantOf(r);
          return Number.isFinite(t) ? ((c && c.now) || Date.now()) / 1000 - t / 1000 : null;
        },
      };
    }
    if (base.app) {
      out.app = {
        ...base.app,
        label: 'application: layer 7 (SSL) or Junos application (junos-https)',
        get: (r) => {
          const f = (r && r.fields) || {};
          return [f.application, f['application-name'], f['service-name']].filter((v) => v !== undefined && v !== null && v !== '' && !isPlaceholder(v));
        },
      };
    }
    return out;
  }

  togglePause() {
    if (!this.src || this.failed) return;
    this.paused = !this.paused;
    this.ctx.ui.announce(this.paused ? 'Log tail paused.' : 'Log tail live.');
    if (this.paused) {
      clearTimeout(this.timers.poll);
      this.renderLive();
      this.renderFoot();
    } else {
      // Lines a read's filter did not reach are checked again (newest first, time-boxed) first.
      if (this.appendCut.length) this.refilter();
      this.renderLive();
      if (!this.inflight) this.poll(false);
    }
  }

  /** The shell's idle pause (no operator input): reads wait in api.js; the pill and footer say so. */
  setIdle(idle) {
    if (this.dead || idle === this.idle) return;
    this.idle = idle;
    this.renderLive();
    this.renderFoot();
  }

  // ---- device time zone (LG-02) -------------------------------------------------------------------

  /** The configured device zone when this browser can convert to it (an IANA name), else null. */
  deviceZone() {
    const inv = this.ctx.store.lastInventory;
    const dz = this.fmt.deviceZone(inv ? inv.clock : null);
    return dz && dz.convertible && dz.zone ? dz.zone : null;
  }

  /** The zone times are shown in: the device zone while the toggle is on, else null (UTC frame). */
  activeZone() {
    return this.zoneOn ? this.deviceZone() : null;
  }

  /**
   * The time a line is drawn and filtered at (the "frame"). Without the device zone: as written, read
   * as UTC (zone-less lines), or UTC (lines that carry a zone). With it: zone-less lines as written
   * (read in the configured zone), and lines with a zone converted to it.
   */
  frameOf(p) {
    if (!p || !Number.isFinite(p.time)) return null;
    if (p.zoned && this.zoneName) return p.time + zoneOffset(p.time, this.zoneName);
    return p.time;
  }

  /** The real instant of a line, for ages: a zone-less time is read in the device zone when it is on. */
  instantOf(p) {
    if (!p || !Number.isFinite(p.time)) return null;
    if (!p.zoned && this.zoneName) {
      const u = this.fmt.naiveToUtc(p.time, this.zoneName);
      return Number.isFinite(u) ? u : p.time;
    }
    return p.time;
  }

  toggleZone() {
    this.zoneOn = !this.zoneOn;
    prefSet(PREF.zone, this.zoneOn ? '1' : '0');
    this.applyZone();
    this.ctx.ui.announce(this.zoneName ? `Times shown in the device zone ${this.zoneName}.` : 'Times shown as written, read as UTC.');
  }

  /** The zone frame changed: every row's time, the paint, the filter and the chart follow. */
  applyZone() {
    this.zoneName = this.activeZone();
    this.newestFrame = null;
    for (const row of this.rows) {
      if (row.marker) continue;
      row.time = this.frameOf(row.p);
      if (row.time !== null && (this.newestFrame === null || row.time > this.newestFrame)) this.newestFrame = row.time;
    }
    this.applyQuery(this.queryText, this.bar ? this.bar.parsed : this.q.parse(this.queryText, { view: 'logs' }), { silent: true });
    this.repaint();
    this.renderSub();
    if (this.panelSeq !== null) {
      const row = this.bySeq.get(this.panelSeq);
      if (row) this.openDetail(row);
    }
  }

  /** "UTC", "device clock" or the device zone: the clock of the times shown, short. */
  zoneShort() {
    if (this.zoneName) return this.zoneName;
    return this.zoneNote() === 'UTC' ? 'UTC' : 'device clock';
  }

  /** The clock of one line's time, short. */
  zoneTag(p) {
    if (this.zoneName) return this.zoneName;
    return p && p.zoned ? 'UTC' : 'device clock';
  }

  setInterval(s) {
    if (!INTERVALS.includes(s)) return;
    this.interval = s;
    prefSet(PREF.interval, s);
    this.renderLive();
    if (!this.paused && !this.inflight && this.liveCapable()) this.schedule();
  }

  /**
   * Copies the line as the device wrote it, except that invisible and direction-changing characters
   * are written as <U+XXXX>: pasted into a terminal or ticket they would reorder or hide text.
   */
  copyLine(row) {
    const n = row.nctl || 0;
    const text = n ? this.lp.escapeControls(row.line) : row.line;
    this.ctx.ui.copy(text, n ? `Log line copied; ${this.fmt.plural(n, 'hidden character')} written as <U+XXXX>.` : 'Log line copied.');
  }

  retryButton(fn, label = 'Try again') {
    const { h, icon } = this.dom;
    return h('button', { class: 'btn sm', type: 'button', on: { click: fn } }, icon('refresh'), label);
  }

  // ---- export -------------------------------------------------------------------------------------

  toggleExportMenu() {
    if (this.menu) {
      this.closeExportMenu();
      return;
    }
    const { h, icon } = this.dom;
    const count = this.visible.filter((r) => !r.marker).length;
    const item = (fmt, label, detail) =>
      h(
        'button',
        { class: 'lg-menu-item', type: 'button', role: 'menuitem', on: { click: () => { this.closeExportMenu(); this.exportLines(fmt); } } },
        icon('download'),
        h('span', null, h('b', null, label), h('span', { class: 'faint' }, detail)),
      );
    this.menu = h(
      'div',
      {
        class: 'lg-menu',
        role: 'menu',
        'aria-label': 'Export',
        on: {
          keydown: (e) => {
            const items = [...this.menu.querySelectorAll('[role="menuitem"]')];
            const at = items.indexOf(document.activeElement);
            if (e.key === 'Escape') {
              e.preventDefault();
              e.stopPropagation();
              this.closeExportMenu();
              this.exportBtn.focus();
            } else if (e.key === 'ArrowDown') {
              e.preventDefault();
              items[Math.min(items.length - 1, at + 1)].focus();
            } else if (e.key === 'ArrowUp') {
              e.preventDefault();
              items[Math.max(0, at - 1)].focus();
            } else if (e.key === 'Tab') {
              this.closeExportMenu();
            }
          },
        },
      },
      h('div', { class: 'lg-menu-head' }, `${this.fmt.plural(count, 'line')} in view`),
      item('log', 'Raw lines (.log)', 'exactly as the device wrote them'),
      item('csv', 'CSV (.csv)', 'time, tag, addresses, policy, line'),
      item('json', 'JSON (.json)', 'lines with parsed fields'),
      this.uncheckedCount()
        ? h('p', { class: 'lg-menu-note is-cut' }, `Exports only the ${this.fmt.plural(count, 'line')} shown: the filter stopped before checking ${this.fmt.plural(this.uncheckedCount(), 'line')}, which are not included.`)
        : null,
      h('p', { class: 'lg-menu-note' }, 'Made in this browser from what is on screen; no device read, no row cap.'),
    );
    this.exportWrap.append(this.menu);
    this.exportBtn.setAttribute('aria-expanded', 'true');
    const first = this.menu.querySelector('[role="menuitem"]');
    if (first) first.focus();
  }

  closeExportMenu() {
    if (!this.menu) return;
    this.menu.remove();
    this.menu = null;
    this.exportBtn.setAttribute('aria-expanded', 'false');
  }

  exportLines(fmt) {
    const rows = this.visible.filter((r) => !r.marker);
    if (!rows.length) {
      this.ctx.ui.toast('Nothing to export: no line is in view.', 'warn');
      return;
    }
    const inv = this.ctx.store.lastInventory;
    const host = (inv && inv.device && inv.device.status === 'ok' && inv.device.hostname) || 'device';
    const now = new Date();
    const session = this.ctx.store.session || {};
    const fixture = Boolean((this.meta && this.meta.fixture) || session.fixture);
    const meta = {
      exported_at: now.toISOString(),
      device: host,
      source: this.src ? this.src.id : null,
      report_type: this.src && this.src.kind === 'report' ? this.reportType : undefined,
      query: this.queryText || '',
      device_filter: (this.plan && this.plan.device) || {},
      hidden_families: [...this.famOff],
      own_reads_hidden: !this.showSelf,
      read_as: this.readAs || session.user || null,
      fixture,
      lines: rows.length,
    };
    let body;
    let type;
    if (fmt === 'log') {
      const head = [
        `# J-Wicket log export${fixture ? ' - FIXTURE DATA, synthetic, not read from a device' : ''}`,
        `# device ${host} - source ${meta.source}${meta.report_type ? ` (${meta.report_type})` : ''} - read as ${meta.read_as}`,
        `# exported ${meta.exported_at} - ${rows.length} lines - query: ${meta.query || '(none)'}`,
      ];
      body = `${head.join('\n')}\n${rows.map((r) => r.line).join('\n')}\n`;
      type = 'text/plain';
    } else if (fmt === 'csv') {
      const cols = ['time_utc', 'host', 'daemon', 'tag', 'family', 'severity', 'src', 'sport', 'dst', 'dport', 'protocol', 'policy', 'from_zone', 'to_zone', 'session_id', 'reason', 'line'];
      const out = [cols.join(',')];
      for (const r of rows) {
        const p = r.p;
        const f = p.fields || {};
        const fl = p.flow || {};
        const val = (x) => (isPlaceholder(x) ? '' : x);
        out.push(
          [
            r.time !== null ? new Date(r.time).toISOString() : '',
            p.host, p.daemon, p.tag, r.fam, Number.isInteger(p.severity) ? (this.lp.SEVERITIES || [])[p.severity] : '',
            val(f['source-address']), val(f['source-port']), val(f['destination-address']), val(f['destination-port']),
            fl.protocol || val(f['protocol-id']) || val(f.protocol), val(f['policy-name']), val(f['source-zone-name']), val(f['destination-zone-name']),
            r.sid || '', this.lp.isPlaceholderValue('reason', f.reason) ? '' : f.reason, r.line,
          ].map(csvCell).join(','),
        );
      }
      body = `${out.join('\r\n')}\r\n`;
      type = 'text/csv';
    } else {
      body = JSON.stringify(
        {
          meta,
          lines: rows.map((r) => ({
            line: r.line,
            time: r.time !== null ? new Date(r.time).toISOString() : null,
            format: r.p.format,
            host: r.p.host,
            daemon: r.p.daemon,
            tag: r.p.tag,
            family: r.fam,
            severity: Number.isInteger(r.p.severity) ? r.p.severity : null,
            fields: r.p.fields || {},
          })),
        },
        null,
        2,
      );
      type = 'application/json';
    }
    const stamp = now.toISOString().replace(/[-:]/g, '').slice(0, 15);
    const name = `jwicket-logs-${safeName(host)}-${safeName(this.src ? this.src.label : 'logs')}-${stamp}${fixture ? '-fixture' : ''}.${fmt}`;
    const url = URL.createObjectURL(new Blob([body], { type }));
    const a = this.dom.h('a', { href: url, download: name, class: 'sr-only', tabindex: '-1' });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 4000);
    this.ctx.ui.toast(`Exported ${this.fmt.plural(rows.length, 'line')} as ${name}.`, 'ok');
  }

  // ---- the decoded panel --------------------------------------------------------------------------

  openDetail(row) {
    const { h, icon } = this.dom;
    const p = row.p;
    const content = h('div', { class: 'lg-detail' });
    const famLabel = (this.families[row.famIx] || {}).label || row.fam;
    const sev = Number.isInteger(p.severity) ? (this.lp.SEVERITIES || [])[p.severity] : null;
    content.append(
      h(
        'div',
        { class: 'lg-d-head' },
        h('span', { class: ['lg-d-fam', `fam-${row.fam}`] }, h('span', { class: 'lg-fam-sw', 'aria-hidden': 'true' }), famLabel),
        p.tag ? h('span', { class: ['lg-d-tag', 'mono', 'dev-text', `fam-${row.fam}`] }, this.vis(p.tag)) : null,
        sev ? h('span', { class: ['pill', p.severity <= 3 ? 'deny' : p.severity === 4 ? 'reject' : 'muted'], title: p.severitySource ? `severity from ${p.severitySource}` : null }, sev) : null,
        row.self ? h('span', { class: 'pill gold', title: this.selfNote || '' }, 'your J-Wicket read') : null,
        h('span', { class: 'spacer' }),
        h(
          'span',
          {
            class: 'lg-d-time mono',
            title: this.zoneName
              ? `As written: ${this.lp.escapeControls(p.ts || '(no time)')}. Shown in the device's configured zone ${this.zoneName}${p.zoned ? '' : ' (the line carries no zone; J-Wicket reads it in that zone)'}.`
              : p.zoned ? `As written: ${this.lp.escapeControls(p.ts)}` : `As written: ${this.lp.escapeControls(p.ts || '(no time)')}. The line carries no time zone; J-Wicket reads it as UTC. If the device logs in local time, this is off by its UTC offset.`,
          },
          row.time !== null ? stampMs(row.time, hasMs(p)) : this.vis(p.ts || 'no time'),
          row.time !== null ? h('span', { class: 'lg-d-zone' }, ` ${this.zoneTag(p)}`) : null,
        ),
      ),
    );
    const sentence = this.lp.decode(p);
    if (sentence) {
      const parts = sentence.split(SEP);
      content.append(
        h(
          'div',
          { class: ['lg-d-sentence', `fam-${row.fam}`] },
          h('p', { class: 'lg-d-lead' }, this.vis(parts[0])),
          parts.length > 1 ? h('ul', { class: 'lg-d-facts' }, parts.slice(1).map((x) => h('li', null, this.vis(x)))) : null,
        ),
      );
    } else {
      content.append(h('p', { class: 'lg-d-none' }, 'J-Wicket has no decoder for this message. Its parts are listed below; click a value to filter by it.'));
    }
    if (p.flow) content.append(this.flowStrip(p.flow, row));
    if (row.sid || (p.flow && FLOW_FAMS.has(row.fam))) content.append(this.timelineSection(row));
    if (p.flow) {
      const test = this.testSection(p.flow);
      if (test) content.append(test);
    }
    content.append(this.fieldsSection(row));
    const raw = h('div', { class: 'lg-d-raw' });
    this.fillTokens(raw, this.expandCtl(this.tokensOf(row)), { fam: row.fam });
    content.append(
      h(
        'section',
        { class: 'panel-section' },
        h('h3', null, 'Line as written'),
        h('div', { class: 'cli lg-d-cli' }, raw, h('button', { class: 'btn sm icon', type: 'button', 'aria-label': 'Copy line', title: 'Copy line', on: { click: () => this.copyLine(row) } }, icon('copy'))),
      ),
    );
    const actions = [
      h('button', { class: 'btn sm icon', type: 'button', title: 'Previous line (k)', 'aria-label': 'Previous line', on: { click: () => this.moveSelection(-1, true) } }, icon('chevron-left')),
      h('button', { class: 'btn sm icon', type: 'button', title: 'Next line (j)', 'aria-label': 'Next line', on: { click: () => this.moveSelection(1, true) } }, icon('chevron-right')),
      h('button', { class: 'btn sm', type: 'button', title: 'Copy the line (c)', on: { click: () => this.copyLine(row) } }, icon('copy'), 'Copy line'),
    ];
    this.reopening = this.panelSeq !== null;
    this.panelSeq = row.seq;
    this.ctx.ui.panel({
      title: `${famLabel}${row.sid ? ` \u00b7 session ${row.sid}` : ''}`,
      content,
      wide: true,
      actions,
      onClose: () => {
        if (this.reopening) {
          this.reopening = false;
          return;
        }
        this.panelSeq = null;
        this.liveLinkEl = null;
      },
    });
    this.reopening = false;
    this.refreshLiveLink();
  }

  flowStrip(fl, row) {
    const { h, icon } = this.dom;
    const hp = (ip, port) => this.vis(ip ? `${ip.includes(':') ? `[${ip}]` : ip}${port !== null && port !== undefined ? `:${port}` : ''}` : '?');
    const zone = (z, key) => (z ? h('button', { class: 'zone lg-d-zone', type: 'button', title: `Filter ${key}:${this.lp.escapeControls(z)}`, on: { click: (e) => { const t = this.tokenTerm({ t: 'zone', v: z, k: key }); if (t) this.addTerm(t, e.altKey); } } }, this.vis(z)) : h('span', { class: 'faint' }, 'zone ?'));
    const policy = fl.policy
      ? h('button', { class: 'policy-link', type: 'button', title: `Open policy ${this.lp.escapeControls(fl.policy)} in Policies`, on: { click: () => this.ctx.navigate('policies', { q: `name:${quoteValue(fl.policy, true)}`, sel: policySel(this.ctx.store.policyIndex(), fl.policy, fl.from, fl.to) }) } }, this.vis(fl.policy))
      : h('span', { class: 'faint mono' }, 'no policy');
    // Deny lines keep the denied style and never get a close-reason badge.
    const verdict = row.fam === 'deny' ? h('span', { class: 'pill deny' }, 'denied') : row.fam === 'close' ? this.closePill(fl.reason) : h('span', { class: 'pill permit' }, 'permitted');
    const nat = [];
    if (fl.snat) nat.push(h('div', { class: 'lg-d-nat' }, h('span', { class: 'pill violet' }, 'SNAT'), h('span', { class: 'mono' }, hp(fl.src, fl.sport)), icon('arrow'), h('span', { class: 'mono nat' }, hp(fl.natSrc, fl.natSport)), fl.snatRule ? h('span', { class: 'faint' }, `rule ${fl.snatRule}`) : null));
    if (fl.dnat) nat.push(h('div', { class: 'lg-d-nat' }, h('span', { class: 'pill violet' }, 'DNAT'), h('span', { class: 'mono' }, hp(fl.dst, fl.dport)), icon('arrow'), h('span', { class: 'mono nat' }, hp(fl.natDst, fl.natDport)), fl.dnatRule ? h('span', { class: 'faint' }, `rule ${fl.dnatRule}`) : null));
    const stats = [];
    if (fl.bytesClient !== null || fl.bytesServer !== null) {
      // Exact byte counts: the decoded sentence above rounds (decimal kB/MB, as format.bytes), the counters do not.
      const side = (arrow, who, b, pk) => h('span', { title: `${this.fmt.bytes(b || 0)}` }, h('span', { class: 'faint' }, `${arrow} ${who} `), h('b', { class: 'mono' }, `${this.fmt.num(b || 0)} B`), pk !== null ? h('span', { class: 'faint' }, ` in ${this.fmt.plural(pk, 'packet')}`) : null);
      stats.push(side('\u2191', 'from client', fl.bytesClient, fl.packetsClient));
      stats.push(side('\u2193', 'from server', fl.bytesServer, fl.packetsServer));
    }
    if (fl.elapsed !== null) stats.push(h('span', null, h('span', { class: 'faint' }, 'lasted '), h('b', { class: 'mono' }, this.fmt.duration(fl.elapsed))));
    if (fl.app) stats.push(h('span', null, h('span', { class: 'faint' }, 'app '), h('b', { class: 'mono' }, this.vis(fl.app))));
    if (fl.service) stats.push(h('span', null, h('span', { class: 'faint' }, 'service '), h('b', { class: 'mono' }, this.vis(fl.service))));
    if (fl.iface) stats.push(h('span', null, h('span', { class: 'faint' }, 'in '), h('b', { class: 'mono iface' }, this.vis(fl.iface))));
    return h(
      'section',
      { class: 'panel-section' },
      h('h3', null, 'Flow'),
      h(
        'div',
        { class: ['lg-d-flow', `fam-${row.fam}`] },
        h('div', { class: 'lg-d-end' }, h('span', { class: 'lg-d-role' }, 'client'), h('span', { class: 'mono lg-d-ep' }, hp(fl.src, fl.sport))),
        h('span', { class: 'lg-d-arr', 'aria-hidden': 'true' }, icon('arrow')),
        h('div', { class: 'lg-d-mid' }, h('div', { class: 'lg-d-zones' }, zone(fl.from, 'from'), icon('arrow'), zone(fl.to, 'to')), h('div', { class: 'lg-d-pol' }, policy, verdict), h('div', { class: 'lg-d-proto faint mono' }, this.vis([fl.protocol ? fl.protocol.toUpperCase() : null, fl.service].filter(Boolean).join(SEP)))),
        h('span', { class: 'lg-d-arr', 'aria-hidden': 'true' }, icon('arrow')),
        h(
          'div',
          { class: 'lg-d-end' },
          h('span', { class: 'lg-d-role', title: fl.dnat ? 'The server address as the client sent it, before destination NAT; the translated address is below' : null }, fl.dnat ? 'server \u00b7 before DNAT' : 'server'),
          h('span', { class: 'mono lg-d-ep' }, hp(fl.dst, fl.dport)),
        ),
      ),
      nat.length ? h('div', { class: 'lg-d-nats' }, nat) : null,
      stats.length ? h('div', { class: 'lg-d-stats' }, stats) : null,
    );
  }

  timelineSection(row) {
    const { h, icon } = this.dom;
    const fl = row.p.flow || {};
    let related;
    let title;
    if (row.sid) {
      related = this.rows.filter((r) => !r.marker && r.sid === row.sid && FLOW_FAMS.has(r.fam));
      title = `Session ${row.sid}`;
    } else {
      related = this.rows.filter((r) => {
        if (r.marker || !r.p.flow || r.fam !== row.fam) return false;
        const f = r.p.flow;
        return f.src === fl.src && f.dst === fl.dst && f.dport === fl.dport;
      });
      title = 'The same flow in this window';
    }
    related.sort((a, b) => (a.time ?? 0) - (b.time ?? 0) || a.seq - b.seq);
    const shown = related.slice(-24);
    const evLabel = { create: 'CREATE', close: 'CLOSE', deny: 'DENY' };
    const items = shown.map((r) => {
      const f = r.p.flow || {};
      let what = '';
      let pill = null;
      if (r.fam === 'close') {
        pill = this.closePill(f.reason, { small: true });
        what = [f.elapsed !== null ? this.fmt.duration(f.elapsed) : null, f.bytesClient !== null || f.bytesServer !== null ? `${this.fmt.num((f.bytesClient || 0) + (f.bytesServer || 0))} B` : null].filter(Boolean).join(SEP);
      }
      else if (r.fam === 'create') what = [f.policy ? `via ${f.policy}` : null, f.snat ? `SNAT ${f.natSrc}:${f.natSport}` : null, f.dnat ? `DNAT \u2192 ${f.natDst}:${f.natDport}` : null].filter(Boolean).join(SEP);
      else what = [f.policy ? `by ${f.policy}` : null, f.sport !== null ? `from port ${f.sport}` : null, f.reason].filter(Boolean).join(SEP);
      return h(
        'li',
        { class: ['lg-tl-item', `fam-${r.fam}`, r.seq === row.seq && 'is-here'] },
        h('span', { class: 'lg-tl-dot', 'aria-hidden': 'true' }),
        h('span', { class: 'lg-tl-time mono' }, r.time !== null ? stampMs(r.time, hasMs(r.p)).slice(11) : '?'),
        h('span', { class: ['lg-tl-ev', `fam-${r.fam}`] }, evLabel[r.fam] || r.fam),
        h('span', { class: 'lg-tl-what dev-text' }, pill, pill && what ? ' ' : null, pill && !what ? null : this.vis(what || '\u2014')),
        r.seq === row.seq
          ? h('span', { class: 'pill gold' }, 'this line')
          : h('button', { class: 'btn ghost sm', type: 'button', on: { click: () => { const v = this.indexOfSeq(r.seq) >= 0; if (v) this.select(r, { scroll: true, open: true }); else this.openDetail(r); } } }, 'Show'),
      );
    });
    const missing = [];
    if (row.sid) {
      const fams = new Set(related.map((r) => r.fam));
      const devFiltered = this.plan && this.plan.device && Object.keys(this.plan.device).length && this.queryText !== `session:${row.sid}`;
      if (!fams.has('create') && !fams.has('deny')) {
        missing.push(devFiltered
          ? `The CREATE line is not in this window: the query's device-side filter may leave it out. "Only session ${row.sid}" reads every line of this session.`
          : 'The CREATE line is not in this window (older, on another source, or not logged: session-init logging is set per policy).');
      }
      if (!fams.has('close') && !fams.has('deny')) missing.push('No CLOSE line yet: the session may still be open.');
    }
    this.liveLinkEl = h('div', { class: 'lg-d-live', hidden: true });
    this.liveLinkFor = row;
    const filterBtn = row.sid
      ? h('button', { class: 'btn sm', type: 'button', on: { click: () => this.setQuery(`session:${row.sid}`) } }, icon('filter'), `Only session ${row.sid}`)
      : fl.src
        ? h('button', { class: 'btn sm', type: 'button', on: { click: () => this.setQuery([`src:${quoteValue(fl.src, true)}`, fl.dst ? `dst:${quoteValue(fl.dst, true)}` : null, fl.dport !== null ? `dport:${fl.dport}` : null].filter(Boolean).join(' ')) } }, icon('filter'), 'Only this flow')
        : null;
    return h(
      'section',
      { class: 'panel-section' },
      h('h3', null, 'Session timeline', h('span', { class: 'lg-d-h3note' }, ` \u00b7 ${this.zoneShort() === 'UTC' ? 'times UTC' : this.zoneShort()}`)),
      h('div', { class: 'lg-d-tlhead' }, h('b', null, title), h('span', { class: 'faint' }, `${this.fmt.plural(related.length, 'line')} in this window`), h('span', { class: 'spacer' }), filterBtn),
      h('ol', { class: 'lg-tl' }, items),
      missing.length ? h('ul', { class: 'lg-d-missing' }, missing.map((m) => h('li', null, m))) : null,
      this.liveLinkEl,
    );
  }

  /** Sessions query for a flow: terms the device filters (src, sport, dst, dport, proto) plus the id. */
  sessionTerms(fl, sid) {
    const proto = fl.protocol && !/\s/.test(fl.protocol) ? fl.protocol : fl.protocolId;
    return [
      fl.src ? `src:${quoteValue(fl.src, true)}` : null,
      fl.sport !== null && fl.sport !== undefined ? `sport:${fl.sport}` : null,
      fl.dst ? `dst:${quoteValue(fl.dst, true)}` : null,
      fl.dport !== null && fl.dport !== undefined ? `dport:${fl.dport}` : null,
      proto !== null && proto !== undefined ? `proto:${proto}` : null,
      sid ? `id:${sid}` : null,
    ].filter(Boolean).join(' ');
  }

  /**
   * What is known about the session now. A CLOSE line is the end of it, a DENY line means none was
   * created; for CREATE the last Sessions read is checked on the 5-tuple, not the id alone (Junos
   * reuses session ids).
   */
  refreshLiveLink() {
    const el = this.liveLinkEl;
    const row = this.liveLinkFor;
    if (!el || !row || this.panelSeq === null) return;
    const { h, put, icon } = this.dom;
    const fl = row.p.flow;
    if (!fl) {
      el.hidden = true;
      return;
    }
    el.hidden = false;
    const at = row.time !== null ? `${stampMs(row.time, hasMs(row.p)).slice(11)} ${this.zoneName || row.p.zoned ? this.zoneTag(row.p) : '(device clock)'}` : null;
    const terms = this.sessionTerms(fl, null);
    const go = (sel) => this.ctx.navigate('sessions', sel ? { q: terms, sel } : { q: terms });
    const btn = (label, sel) => h('button', { class: 'btn sm', type: 'button', title: `Sessions with ${terms}`, on: { click: () => go(sel) } }, icon('sessions'), label);
    if (row.fam === 'close') {
      put(
        el,
        h('span', { class: 'lg-live-dot is-closed', 'aria-hidden': 'true' }),
        h('span', null, h('b', null, 'Closed'), at ? ` at ${at}` : '', fl.elapsed !== null ? ` after ${this.fmt.duration(fl.elapsed)}` : '', fl.reason ? [' ', this.closePill(fl.reason, { small: true })] : '', '. This line is the end of the session.'),
        btn('Same flow in Sessions now'),
      );
      return;
    }
    if (row.fam === 'deny') {
      put(
        el,
        h('span', { class: 'lg-live-dot is-denied', 'aria-hidden': 'true' }),
        h('span', null, h('b', null, 'Denied'), fl.policy ? [' by ', this.vis(fl.policy)] : '', '; no session was created, so Sessions has nothing to show for it.'),
      );
      return;
    }
    const last = this.ctx.store.sessionsLast;
    const sessions = last && last.sessions;
    if (!sessions) {
      put(el, h('span', { class: 'lg-live-dot is-unknown', 'aria-hidden': 'true' }), h('span', null, 'Sessions have not been read in this tab yet, so J-Wicket cannot say whether this session is still open.'), btn('Look for it in Sessions'));
      return;
    }
    const readMs = last.meta && last.meta.read_at ? Date.parse(last.meta.read_at) : NaN;
    const readAt = Number.isFinite(readMs) ? `${this.fmt.time(last.meta.read_at)} UTC` : 'an earlier read';
    if (sessions.status !== 'ok') {
      put(el, h('span', { class: 'lg-live-dot is-unknown', 'aria-hidden': 'true' }), h('span', null, `The last Sessions read (${readAt}) was ${sessions.status}, so J-Wicket cannot say whether this session is open.`), btn('Look for it in Sessions'));
      return;
    }
    const proto = fl.protocol && !/\s/.test(fl.protocol) ? fl.protocol : null;
    const same = (r) => {
      const w = r.in || {};
      if (fl.src && w.src !== fl.src) return false;
      if (fl.dst && w.dst !== fl.dst) return false;
      if (fl.sport !== null && Number(w.sport) !== fl.sport) return false;
      if (fl.dport !== null && Number(w.dport) !== fl.dport) return false;
      if (proto && w.proto && String(w.proto).toLowerCase() !== proto) return false;
      return !row.sid || String(r.session_id ?? r.id) === String(row.sid);
    };
    const hit = (sessions.rows || []).find(same);
    const closed = row.sid ? this.rows.find((r) => !r.marker && r.sid === row.sid && r.fam === 'close' && r.seq > row.seq) : null;
    if (closed) {
      const cf = closed.p.flow || {};
      put(el, h('span', { class: 'lg-live-dot is-closed', 'aria-hidden': 'true' }), h('span', null, h('b', null, 'Closed'), closed.time !== null ? ` at ${stampMs(closed.time, hasMs(closed.p)).slice(11)}` : '', cf.reason ? [' ', this.closePill(cf.reason, { small: true })] : '', ': its CLOSE line is in this window (timeline above).'));
      return;
    }
    if (hit) {
      const bytes = ((hit.in && hit.in.bytes) || 0) + ((hit.out && hit.out.bytes) || 0);
      put(
        el,
        h('span', { class: 'lg-live-dot is-live', 'aria-hidden': 'true' }),
        h('span', null, h('b', null, 'Still open'), ` in the Sessions read at ${readAt} (same 5-tuple${row.sid ? ' and id' : ''})`, hit.duration !== null && hit.duration !== undefined ? ` · ${this.fmt.duration(hit.duration)} old` : '', bytes ? ` · ${this.fmt.bytes(bytes)} so far` : '', hit.location ? ` · ${hit.location}` : ''),
        btn('Open in Sessions', hit.id),
      );
      return;
    }
    const older = Number.isFinite(readMs) && row.time !== null && readMs < row.time;
    put(
      el,
      h('span', { class: 'lg-live-dot', 'aria-hidden': 'true' }),
      h('span', null, older ? `The last Sessions read (${readAt}) is older than this line, so it cannot show this session.` : `Not in the last Sessions read (${readAt}): it has ended, or that read was filtered or capped.`),
      btn('Look for it in Sessions'),
    );
  }

  /** The exact CLI to ask the device which policy matches this flow now (brief rule 8). */
  testSection(fl) {
    const { h, icon } = this.dom;
    if (!fl.src || !fl.dst || !fl.from || !fl.to) return null;
    const proto = ['tcp', 'udp', 'icmp'].includes(fl.protocol) ? fl.protocol : fl.protocolId;
    const vals = [fl.from, fl.to, fl.src, fl.dst, fl.sport, fl.dport, proto, fl.lsys].filter((v) => v !== null && v !== undefined);
    const safe = vals.every((v) => /^[A-Za-z0-9._:/-]+$/.test(String(v)));
    const body = [];
    if (!safe) {
      body.push(h('p', { class: 'faint' }, 'A value in this line holds characters a CLI command cannot carry, so no command is offered.'));
    } else {
      const parts = ['show security match-policies', `from-zone ${fl.from}`, `to-zone ${fl.to}`, `source-ip ${fl.src}`, `destination-ip ${fl.dst}`];
      if (fl.sport !== null) parts.push(`source-port ${fl.sport}`);
      if (fl.dport !== null) parts.push(`destination-port ${fl.dport}`);
      if (proto !== null && proto !== undefined) parts.push(`protocol ${proto}`);
      const cli = parts.join(' ');
      const full = fl.lsys ? `set cli logical-system ${fl.lsys}\n${cli}` : cli;
      body.push(
        h('div', { class: 'cli lg-d-cli' }, h('code', null, full), h('button', { class: 'btn sm icon', type: 'button', 'aria-label': 'Copy the command', title: 'Copy the command', on: { click: () => this.ctx.ui.copy(full, 'Command copied.') } }, icon('copy'))),
        h('p', { class: 'faint lg-d-note' }, 'Junos answers for the configuration as it is now, which may differ from when this line was logged. J-Wicket does not reimplement the policy matcher.'),
      );
    }
    const pair = `${fl.from} → ${fl.to}`;
    if (!safe) return h('section', { class: 'panel-section' }, h('h3', null, 'Test on the device'), body);
    body.push(
      h(
        'div',
        { class: 'lg-d-acts' },
        h('button', { class: 'btn sm', type: 'button', title: `The policies of zone pair ${pair}, in evaluation order`, on: { click: () => this.ctx.navigate('policies', { q: `from:${quoteValue(fl.from, true)} to:${quoteValue(fl.to, true)}` }) } }, icon('policies'), 'Policies for ', this.vis(pair)),
      ),
    );
    return h('section', { class: 'panel-section' }, h('h3', null, 'Test on the device'), body);
  }

  fieldsSection(row) {
    const { h, icon } = this.dom;
    const p = row.p;
    const fieldKeys = this.fieldKeyMap();
    const rows = [];
    const add = (label, value, key, opts = {}) => {
      if (value === null || value === undefined || value === '') return;
      const v = String(value);
      // "unknown" is a documented close reason: kept for the reason field (LOG-05).
      const ph = this.lp.isPlaceholderValue(label, v);
      const term = opts.term !== undefined ? opts.term : ph ? null : key ? termText(key, v) : null;
      rows.push(
        h(
          'tr',
          { class: ph ? 'is-ph' : null },
          h('th', { scope: 'row', class: 'mono dev-text' }, this.vis(label)),
          h('td', { class: 'mono' }, opts.cls ? h('span', { class: opts.cls }, this.vis(v)) : this.vis(v)),
          h(
            'td',
            { class: 'lg-d-act' },
            term
              ? [
                  h('button', { class: 'btn ghost sm icon', type: 'button', title: `Filter: ${term}`, 'aria-label': `Filter by ${label} ${v}`, on: { click: () => this.addTerm(term, false) } }, '='),
                  h('button', { class: 'btn ghost sm icon', type: 'button', title: `Exclude: -${term}`, 'aria-label': `Exclude ${label} ${v}`, on: { click: () => this.addTerm(term, true) } }, '\u2260'),
                ]
              : null,
          ),
        ),
      );
    };
    add('format', p.format, null);
    if (p.ts) add('time', p.ts, null);
    add('host', p.host, 'host');
    add('process', p.daemon ? `${p.daemon}${p.pid ? `[${p.pid}]` : ''}` : null, 'daemon', { term: p.daemon ? termText('daemon', p.daemon) : null });
    add('tag', p.tag, 'tag');
    if (Number.isInteger(p.severity)) add('severity', `${(this.lp.SEVERITIES || [])[p.severity] || p.severity} (${p.severity})`, 'sev', { term: termText('sev', (this.lp.SEVERITIES || [])[p.severity] || String(p.severity)) });
    if (p.facility !== null && p.facility !== undefined) add('facility', p.facility, null);
    if (p.sdid) add('sd-id', p.sdid, null);
    const fields = p.fields || {};
    const keys = Object.keys(fields);
    for (const k of keys) {
      const qk = fieldKeys.get(k.toLowerCase()) || null;
      const cls = /address/.test(k) ? (/^nat-/.test(k) ? 'nat' : 'ip') : /interface/.test(k) ? 'iface' : null;
      add(k, fields[k], qk, { cls, term: this.lp.isPlaceholderValue(k, fields[k]) ? null : this.tokenTerm({ t: 'val', v: String(fields[k]), k: qk }) });
    }
    const fieldsTable = rows.length ? h('table', { class: 'lg-d-fields' }, h('tbody', null, rows.splice(0))) : null;
    // Lines without structured data: the typed tokens of the message are a second table.
    let partsTable = null;
    if (p.format !== 'rfc5424' || !p.sdid) {
      const seen = new Set();
      const toks = this.tokensOf(row).filter((t) => t.t !== 'text' && !['ts', 'host', 'daemon', 'pid', 'tag', 'pri', 'key', 'sdid', 'arrow', 'ctl'].includes(t.t) && t.v.trim());
      for (const t of toks) {
        const k = `${t.t}|${t.v}`;
        if (seen.has(k) || seen.size >= 40) continue;
        seen.add(k);
        add(t.k || t.t, t.q || t.v, null, { term: this.tokenTerm(t), cls: `tk-${t.t}` });
      }
      if (rows.length) partsTable = h('table', { class: 'lg-d-fields' }, h('tbody', null, rows));
    }
    return h(
      'section',
      { class: 'panel-section' },
      h('h3', null, keys.length ? `Fields (${keys.length})` : 'Header'),
      fieldsTable || h('p', { class: 'faint' }, 'No fields.'),
      partsTable ? h('h3', { class: 'lg-d-sub' }, 'Parts of the message') : null,
      partsTable,
    );
  }

  fieldKeyMap() {
    if (this._fieldKeys) return this._fieldKeys;
    const map = new Map();
    for (const [name, def] of Object.entries(this.q.FIELDS.logs)) {
      map.set(name, name);
      for (const a of def.aliases || []) if (!map.has(a)) map.set(a, name);
    }
    // structured-data names that the query language reads through other keys
    map.set('session-id-32', 'session');
    map.set('packet-incoming-interface', 'iface');
    this._fieldKeys = map;
    return map;
  }

  // ---- status rendering ---------------------------------------------------------------------------

  showState(opts) {
    const { put, stateCard, skeleton, h } = this.dom;
    const bad = ['denied', 'unsupported', 'failed', 'offline', 'session-lost', 'busy', 'internal'].includes(opts.status);
    // Nothing was read: the explanation sits right under the header, not centred in an empty frame,
    // and the timeline and stream step aside.
    const block = bad && !this.rows.length;
    if (block) {
      const actions = [...(opts.actions || []), this.sessionsAction()].filter(Boolean);
      put(this.blockEl, stateCard({ ...opts, actions, compact: false }));
      this.blockEl.hidden = false;
      this.stateEl.hidden = true;
      this.stateEl.replaceChildren();
    } else {
      this.blockEl.hidden = true;
      this.blockEl.replaceChildren();
      put(this.stateEl, h('div', { class: 'lg-state-in' }, stateCard({ ...opts, compact: false }), opts.skeleton ? skeleton(4) : null));
      this.stateEl.hidden = false;
    }
    this.stateKind = opts.kind || opts.status;
    this.el.classList.toggle('is-nodata', block);
    this.renderWhere();
  }

  hideState() {
    this.stateEl.hidden = true;
    this.stateEl.replaceChildren();
    this.blockEl.hidden = true;
    this.blockEl.replaceChildren();
    this.stateKind = null;
    if (this.el.classList.contains('is-nodata')) {
      this.el.classList.remove('is-nodata');
      this.renderWhere();
    }
  }

  /** Logs failing does not mean Sessions does: they are read with different RPCs and permissions. */
  sessionsAction() {
    const { h, icon } = this.dom;
    const last = this.ctx.store.sessionsLast;
    const ok = Boolean(last && last.sessions && last.sessions.status === 'ok');
    return h(
      'button',
      { class: 'btn sm ghost', type: 'button', title: 'Live flow sessions are read with another request and permission', on: { click: () => this.ctx.navigate('sessions', {}) } },
      icon('sessions'),
      ok ? 'Live sessions are still available: Sessions' : 'Live sessions are read separately: Sessions',
      icon('arrow-right'),
    );
  }

  /** Lines are in the window but none passes the filters: say why instead of a blank stream. */
  renderNoMatch() {
    if (this.failed || !this.src || this.stateKind === 'loading') return;
    const total = this.rows.reduce((n, r) => n + (r.marker ? 0 : 1), 0);
    const shown = this.visible.reduce((n, r) => n + (r.marker ? 0 : 1), 0);
    if (!total || shown) {
      if (this.stateKind === 'nomatch') this.hideState();
      return;
    }
    const { h, icon } = this.dom;
    const why = [];
    const actions = [];
    if (this.queryText) {
      why.push('the query');
      actions.push(h('button', { class: 'btn sm', type: 'button', on: { click: () => this.setQuery('') } }, icon('close'), 'Clear the query'));
    }
    if (this.famOff.size) {
      why.push(`${this.fmt.plural(this.famOff.size, 'hidden family', 'hidden families')}`);
      actions.push(h('button', { class: 'btn sm', type: 'button', on: { click: () => { this.famOff = new Set(); this.writeRoute(); this.refilter(); } } }, icon('filter'), 'Show every family'));
    }
    if (this.selfHidden === total) why.push('your own J-Wicket reads being hidden');
    const dev = this.plan && this.plan.device && Object.keys(this.plan.device).length;
    const devNote = dev && this.queryText ? ` The device returned these ${this.fmt.plural(total, 'line')} for the gold terms; the exact field match in the browser then left none.` : '';
    const unchecked = this.uncheckedCount();
    const checked = Math.max(0, total - this.selfHidden - unchecked);
    const key = `${total}|${why.join(',')}|${unchecked}`;
    if (this.stateKind === 'nomatch' && this.noMatchKey === key) return;
    this.noMatchKey = key;
    this.showState({
      status: 'empty',
      kind: 'nomatch',
      title: unchecked
        ? `None of the ${this.fmt.num(checked)} lines checked match; the filter stopped before the rest`
        : `None of the ${this.fmt.plural(total, 'line')} in this window match`,
      message: why.length ? `Filtered out by ${why.join(' and ')}.${devNote}` : null,
      hint: 'New lines that match appear here as they arrive.',
      actions,
      code: false,
    });
  }

  /** Lines the filter has not checked: older ones a refilter did not reach, and new ones of a read. */
  uncheckedCount() {
    return this.unchecked.length + this.appendCut.length;
  }

  /** The query bar's notice while a refilter stopped early; a complete refilter clears it. */
  renderCut() {
    if (!this.bar) return;
    const c = this.filterCut;
    if (!c || !this.unchecked.length) {
      if (this.cutShown) this.bar.setNotice('');
      this.cutShown = false;
      return;
    }
    const time = c.time !== null ? `${clock(c.time)} ${this.zoneShort()}` : 'the oldest line checked';
    this.bar.setNotice(
      `Filter stopped after ${c.ms} ms at line ${this.fmt.num(c.checked)} of ${this.fmt.num(c.total)} (newest first, back to ${time}). Older lines were not checked and are not shown. Use a plain word or a keyed term, simplify the /regex/, or keep fewer lines.`,
      'warn',
    );
    this.cutShown = true;
  }

  renderAll() {
    this.renderCut();
    this.renderFams();
    this.renderBar();
    this.renderMatchNav();
    this.renderNewPill();
    this.renderFoot();
    this.renderRange();
    this.renderAges();
    this.histogram.setEmptyText(this.rows.length ? 'No line with a time passes the filters' : 'No timed lines to chart yet');
    this.histogram.setNote(this.zoneNote());
    this.histogram.update({ times: this.hist.times, series: this.hist.series, selection: this.timeRange ? this.histSel() : null });
    this.scroller.setAttribute('aria-rowcount', String(this.visible.length));
    // The how-to row is for a first look; once lines are in, token hover hints and ? say the same.
    this.queryHint.hidden = this.rows.length > 0;
    this.renderNoMatch();
    this.renderFacets();
  }

  /** "UTC" when the newest line carries its zone; else the device clock, read as UTC; or the device zone. */
  zoneNote() {
    if (this.zoneName) return `device zone ${this.zoneName} (configured)`;
    for (let i = this.rows.length - 1; i >= 0 && i >= this.rows.length - 50; i -= 1) {
      const r = this.rows[i];
      if (!r.marker && r.time !== null) return r.p.zoned ? 'UTC' : 'device clock, read as UTC';
    }
    return 'UTC';
  }

  histSel() {
    const r = this.timeRange;
    if (!r) return null;
    const t = this.hist.times;
    let lo = r.lo;
    let hi = r.hi;
    if (!Number.isFinite(lo) || !Number.isFinite(hi)) {
      let min = Infinity;
      let max = -Infinity;
      for (const x of t) {
        if (x < min) min = x;
        if (x > max) max = x;
      }
      if (!Number.isFinite(lo)) lo = min;
      if (!Number.isFinite(hi)) hi = max;
    }
    return Number.isFinite(lo) && Number.isFinite(hi) ? { lo, hi } : null;
  }

  renderRange() {
    const { h, put, icon } = this.dom;
    const sel = this.timeRange ? this.histSel() : null;
    if (sel) {
      put(
        this.rangeEl,
        h('span', { class: 'lg-range-txt' }, icon('clock'), h('b', { class: 'mono' }, `${clock(sel.lo)} \u2013 ${clock(sel.hi)}`), h('span', { class: 'faint' }, this.zoneShort())),
        h('button', { class: 'btn ghost sm', type: 'button', title: 'Clear the time range (double-click the chart)', on: { click: () => this.onBrush(null) } }, icon('close'), 'Clear'),
      );
    } else {
      this.rangeEl.replaceChildren();
    }
    this.rangeEl.hidden = !sel;
  }

  renderFams() {
    const counts = this.famCounts || new Array(this.families.length).fill(0);
    const only = this.famOff.size === this.families.length - 1;
    let folded = 0;
    for (const [i, f] of this.families.entries()) {
      const { btn, count } = this.famBtns.get(f.id);
      const n = counts[i] || 0;
      const on = !this.famOff.has(f.id);
      btn.setAttribute('aria-pressed', on ? 'true' : 'false');
      btn.classList.toggle('is-zero', n === 0);
      // Families with no line (and not hidden on purpose) fold into one "+N" chip.
      const fold = n === 0 && on && !only && !this.famsExpanded;
      btn.hidden = fold;
      if (fold) folded += 1;
      tick(count, this.fmt.compact(n));
      const click = on && only ? 'Click to show every family' : `Click to show only ${f.label}`;
      btn.title = `${f.label}: ${this.fmt.plural(n, 'line')}. ${click}; Alt-click to ${on ? 'hide' : 'show'} it; Shift-click to add or remove it.`;
      btn.setAttribute('aria-label', `${f.label}, ${n} lines, ${on ? 'shown' : 'hidden'}`);
    }
    const empty = this.families.filter((f, i) => !(counts[i] || 0) && !this.famOff.has(f.id)).length;
    this.famMore.hidden = !folded && !(this.famsExpanded && empty);
    this.famMore.textContent = this.famsExpanded ? 'Fold empty' : `+${folded} with no lines`;
    this.famMore.setAttribute('aria-expanded', this.famsExpanded ? 'true' : 'false');
    this.famMore.title = this.famsExpanded ? 'Fold the families with no line in the window' : `Show the ${folded} families with no line in the window`;
  }

  renderBar() {
    const { h, put, icon } = this.dom;
    const shown = this.visible.reduce((n, r) => n + (r.marker ? 0 : 1), 0);
    const total = this.rows.reduce((n, r) => n + (r.marker ? 0 : 1), 0);
    if (!this.countNum) {
      this.countNum = h('b', { class: 'mono lg-count-n' });
      this.countOf = h('span', { class: 'faint' });
      this.countWord = h('span', { class: 'faint' });
      this.countWin = h('span', { class: 'faint lg-win' });
      put(this.countEl, this.countNum, this.countOf, this.countWord, this.countWin);
    }
    tick(this.countNum, this.fmt.num(shown));
    const unchecked = this.uncheckedCount();
    if (unchecked) {
      // The filter stopped early: say how many lines were checked at all.
      const checked = Math.max(0, total - this.selfHidden - unchecked);
      this.countOf.textContent = ` of ${this.fmt.num(checked)} checked`;
      this.countWord.textContent = ` \u00b7 ${this.fmt.num(total)} in window`;
      this.countWin.textContent = '';
      this.countEl.title = `The filter checked ${this.fmt.plural(checked, 'line')}; ${this.fmt.plural(unchecked, 'line')} were not checked and are not shown.`;
    } else {
      this.countOf.textContent = shown !== total ? ` of ${this.fmt.num(total)}` : '';
      this.countWord.textContent = ` ${total === 1 && shown === total ? 'line' : 'lines'}`;
      this.countWin.textContent = ` \u00b7 keeps ${this.fmt.compact(this.windowMax)}`;
      this.countEl.removeAttribute('title');
    }
    if (this.selfHidden || this.showSelf) {
      put(
        this.selfEl,
        h(
          'button',
          {
            class: ['lg-self', this.showSelf && 'is-shown'],
            type: 'button',
            'aria-pressed': this.showSelf ? 'true' : 'false',
            title: this.selfNote || 'Junos logs every NETCONF request; these lines are your own J-Wicket reads.',
            on: { click: () => this.toggleSelf() },
          },
          icon('user'),
          this.showSelf
            ? h('span', null, 'Your J-Wicket reads shown', h('span', { class: 'faint' }, ' \u00b7 hide'))
            : h('span', null, h('b', { class: 'mono' }, this.fmt.num(this.selfHidden)), ` of your own J-Wicket ${this.selfHidden === 1 ? 'read' : 'reads'} hidden`, h('span', { class: 'lg-self-show' }, ' \u00b7 show')),
        ),
      );
    } else {
      this.selfEl.replaceChildren();
    }
  }

  renderMatchNav() {
    const { h, put, icon } = this.dom;
    if (!this.markRe) {
      this.matchEl.hidden = true;
      return;
    }
    this.matchEl.hidden = false;
    let pos = '';
    if (this.curSeq !== null) {
      let k = 0;
      for (const r of this.visible) {
        if (r.marker) continue;
        this.markRe.lastIndex = 0;
        if (this.markRe.test(r.line)) k += 1;
        if (r.seq === this.curSeq) break;
      }
      pos = `${this.fmt.num(k)}/`;
    }
    put(
      this.matchEl,
      h('span', { class: 'lg-mn-txt' }, h('mark', { class: 'lg-hit' }, 'ab'), ` ${pos}${this.fmt.num(this.matchCount)} marked`),
      h('button', { class: 'btn ghost sm icon', type: 'button', title: 'Previous match (N)', 'aria-label': 'Previous match', on: { click: () => this.nextMatch(-1) } }, icon('chevron-left')),
      h('button', { class: 'btn ghost sm icon', type: 'button', title: 'Next match (n)', 'aria-label': 'Next match', on: { click: () => this.nextMatch(1) } }, icon('chevron-right')),
    );
  }

  renderFollow() {
    this.followBtn.setAttribute('aria-pressed', this.follow ? 'true' : 'false');
    this.followBtn.title = this.follow ? 'Following the newest line: scroll up or press f to stop' : 'Follow the newest line (f)';
    this.renderNewPill();
  }

  renderNewPill() {
    const { h, put, icon } = this.dom;
    const n = this.unseen;
    if (this.follow || !n) {
      this.newPill.hidden = true;
      return;
    }
    put(this.newPill, icon('arrow', { class: 'lg-down' }), `${this.fmt.num(n)} new ${n === 1 ? 'line' : 'lines'}`);
    this.newPill.hidden = false;
  }

  renderNotice() {
    const { h, put, icon } = this.dom;
    if (!this.notice) {
      this.noticeEl.hidden = true;
      return;
    }
    put(this.noticeEl, icon(this.notice.kind === 'info' ? 'refresh' : 'alert'), h('span', null, this.notice.text), h('button', { class: 'btn ghost sm icon', type: 'button', 'aria-label': 'Dismiss', on: { click: () => { this.notice = null; this.renderNotice(); } } }, icon('close')));
    this.noticeEl.className = `lg-notice is-${this.notice.kind}`;
    this.noticeEl.hidden = false;
  }

  renderLive() {
    const { h, put } = this.dom;
    const can = this.src && !this.failed && this.liveCapable();
    const live = can && !this.paused;
    // The shell's idle pause: the tail is on, but reads wait for operator activity (SL-08).
    const idle = live && this.idle;
    this.livePill.className = `live-pill${live && !idle ? '' : ' paused'}${idle ? ' lg-idle' : ''}`;
    this.livePill.disabled = !can;
    put(
      this.livePill,
      h('span', { class: 'dot', 'aria-hidden': 'true' }),
      idle ? 'PAUSED' : live ? 'LIVE' : can ? 'PAUSED' : 'STOPPED',
      h('span', { class: 'sub' }, idle ? 'idle' : live ? `${this.interval} s` : can ? 'space' : ''),
    );
    this.livePill.setAttribute('aria-pressed', live ? 'false' : 'true');
    this.livePill.setAttribute('aria-label', idle ? IDLE_LABEL : live ? `Live: reading new lines every ${this.interval} s. Pause (space).` : can ? 'Paused. Resume the live tail (space).' : 'The live tail is stopped.');
    this.livePill.title = idle ? IDLE_LABEL : live ? 'Pause the live tail (space)' : can ? 'Resume the live tail (space)' : 'Nothing to tail';
    for (const b of this.ivSeg.querySelectorAll('button')) b.setAttribute('aria-pressed', Number(b.dataset.s) === this.interval ? 'true' : 'false');
    this.ctx.ui.setLive('logs', Boolean(live));
  }

  /**
   * LG-02: the toggle for the device's configured time zone, shown when this browser can convert to
   * it. "Configured", never "in effect": Junos applies a time-zone change to every process only after
   * a reboot.
   */
  renderZoneBtn() {
    const zone = this.deviceZone();
    this.zoneBtn.hidden = !zone;
    if (!zone) return;
    this.zoneBtn.textContent = `Show times in the device zone (${zone}, configured)`;
    this.zoneBtn.setAttribute('aria-pressed', this.zoneName ? 'true' : 'false');
    this.zoneBtn.title = this.zoneName
      ? `Times are shown in ${zone}, the time zone in the device's configuration; lines without a zone are read in it. Click to show them as written, read as UTC.`
      : `Read lines without a zone in ${zone}, the time zone in the device's configuration, and show every time in it. A time-zone change takes effect for all processes only after a reboot.`;
  }

  renderSub() {
    const { h, put } = this.dom;
    this.renderZoneBtn();
    const s = this.src;
    if (!s) return;
    const scope = this.ctx.store.scope;
    const parts = [h('b', { class: 'mono dev-text' }, s.kind === 'report' ? `report ${this.reportType}` : s.kind === 'buffer' ? 'security log buffer' : this.vis(s.label))];
    if (s.kind === 'file') parts.push(h('span', null, 'tail with a cursor: each read returns only new lines'));
    else if (s.kind === 'buffer') parts.push(h('span', null, 'each read asks for events since the newest one seen'));
    else parts.push(h('span', null, 'each read moves the start time to the newest line seen'));
    parts.push(h('span', null, 'read as ', h('b', { class: 'mono' }, this.readAs || '?')));
    if (scope && scope !== 'root') {
      const name = scope.split(':')[1] || '';
      parts.push(h('span', { class: 'lg-scope-note', title: 'Logs are read for the whole device. RT_FLOW lines of a logical system carry its name (the lsys: key).' }, 'device-wide logs, not scoped'));
      if (scope.startsWith('lsys:') && name) {
        parts.push(h('button', { class: 'lg-scope-btn', type: 'button', title: `Add lsys:${name} to the query`, on: { click: () => this.addTerm(termText('lsys', name), false) } }, `only ${name}`));
      }
    }
    put(this.subEl, parts.map((p, i) => (i ? [h('span', { class: 'lg-dot', 'aria-hidden': 'true' }, SEP), p] : p)));
  }

  renderFoot() {
    if (this.dead) return;
    const { h, put } = this.dom;
    const parts = [];
    const lr = this.lastRead;
    const L = this.limited;
    if (this.idle && !this.paused && this.liveCapable()) {
      // Reads wait in api.js while the shell's idle pause holds; "reading…" would be untrue.
      parts.push(h('span', null, 'paused: no activity'));
    } else if (this.inflight) {
      parts.push(h('span', { class: 'lg-reading' }, 'reading\u2026'));
    } else if (L && this.src && L.src === this.src.id) {
      // In place of the stale "read … ago": the reads were refused by J-Wicket's own floor or a busy read.
      const next = this.nextAt ? Math.max(0, Math.ceil((this.nextAt - Date.now()) / 1000)) : L.retryAfter;
      parts.push(h('span', { class: 'act-reject', title: L.reason === 'busy' ? 'Another read on your session was still running.' : 'J-Wicket reads each source at most once every few seconds per signed-in session; another tab or window of this session is reading too.' }, `rate-limited \u00d7${L.n}`));
      if (!this.paused) parts.push(h('span', null, `next in ${next} s`));
    } else if (lr) {
      parts.push(h('span', { class: lr.ok ? null : 'act-deny' }, `${lr.ok ? 'read' : 'read failed'} ${clock(lr.at)} (${this.fmt.ago(lr.at)})`));
    }
    if (!this.inflight && !L && this.nextAt && !this.paused && !this.idle && this.liveCapable()) {
      const s = Math.max(0, Math.ceil((this.nextAt - Date.now()) / 1000));
      parts.push(h('span', null, `next in ${s} s`));
    } else if (this.paused) parts.push(h('span', null, 'paused'));
    const di = this.deviceInfo;
    if (di && this.src && this.src.kind === 'file' && Number.isFinite(di.window)) {
      const num = (n) => this.fmt.num(n);
      if (di.initial) {
        // The first read: how much of the device's window the newest lines came from.
        if (di.devTerms) parts.push(h('span', { title: 'The device filtered its whole window with the gold terms; the newest matches were returned.' }, `${num(di.returned)} of ${num(di.window)} lines in the device window match`));
        else parts.push(h('span', null, `device window ${num(di.window)} lines`));
      } else if (di.scanned !== null) {
        if (di.devTerms) parts.push(h('span', null, `last read: ${num(di.scanned)} new ${di.scanned === 1 ? 'line' : 'lines'} on the device, ${num(di.returned)} matched the device filter`));
        else parts.push(h('span', null, `last read: ${num(di.scanned)} new ${di.scanned === 1 ? 'line' : 'lines'}`));
      }
      if (di.dropped) parts.push(h('span', { title: 'The first read returns the newest matching lines only' }, `${num(di.dropped)} older not read`));
    }
    if (di && this.src && this.src.kind === 'report' && di.limited) parts.push(h('span', { class: 'act-reject' }, `report limit ${this.fmt.num(REPORT_COUNT)} reached`));
    if (this.newestFrame !== null && this.src && this.src.kind !== 'file') parts.push(h('span', null, `newest ${clock(this.newestFrame)}${this.zoneName ? ` ${this.zoneName}` : ''}`));
    if (this.meta && this.meta.fixture) parts.push(h('span', { class: 'pill gold' }, 'fixture'));
    if (this.selfHidden && !this.showSelf) {
      parts.push(h('span', { class: 'lg-foot-note', title: this.selfNote }, this.selfNote || 'Junos logs every J-Wicket read as UI_NETCONF_CMD; yours are hidden.'));
    }
    put(this.footEl, parts.map((p, i) => (i ? [h('span', { class: 'lg-dot', 'aria-hidden': 'true' }, SEP), p] : p)));
  }
}

export const view = {
  id: 'logs',
  title: 'Logs',
  icon: ICON,
  mount(el, ctx) {
    const v = new LogsView(el, ctx);
    return {
      update: (route) => v.update(route),
      unmount: () => v.destroy(),
    };
  },
};

export default view;
