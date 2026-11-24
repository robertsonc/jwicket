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
// localStorage holds display preferences (wrap, window size, interval) and nothing else.

import { Histogram, clock } from '../widgets/histogram.js';

const ICON = 'M5 5.5h14M5 9.5h9M5 13.5h14M5 17.5h6M15 17.5h4';
const INTERVALS = [2, 5, 10, 30];
const WINDOWS = [2000, 5000, 10000];
const DEFAULT_WINDOW = 5000;
const API_MAX_LINES = 2000;
const REPORT_COUNT = 1000;
const FAIL_BACKOFF_S = 10;
const PREF = { wrap: 'jwicket.logs.wrap', window: 'jwicket.logs.window', interval: 'jwicket.logs.interval' };
const CLICKABLE = new Set(['ip', 'port', 'proto', 'zone', 'policy', 'iface', 'nat', 'num', 'str', 'bad', 'good', 'user', 'val', 'tag', 'daemon', 'host', 'pid']);
const FLOW_FAMS = new Set(['create', 'close', 'deny']);
const SEP = ' \u00b7 ';
const OVERSCAN = 10;
const PARSE_SLICE = 300;
const PROBE_CHARS = 24;
const GUTTER_PX = 30; // .lg-row padding-left + padding-right, kept in step with logs.css

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
    this.wrapPad = 4;
    this.wrap = false;
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
      this.reconcile(false);
    });
  }

  heightOf(row) {
    if (row.marker) return this.markerH;
    if (!this.wrap) return this.lh;
    const lines = Math.max(1, Math.ceil(row.len / this.cpl));
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

  setWrap(on) {
    this.wrap = Boolean(on);
    this.body.classList.toggle('is-wrap', this.wrap);
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
      if (!row.marker && row.len > this.maxLen) this.maxLen = row.len;
    }
    this.body.style.height = `${this.tops[n]}px`;
    this.body.style.setProperty('--lg-maxch', String(Math.max(40, this.maxLen)));
  }

  setItems(items) {
    this.items = items;
    this.recompute(0);
    this.reconcile(true);
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

  scrollToEnd() {
    this.setScroll(Number.MAX_SAFE_INTEGER);
  }

  atEnd(slack = 24) {
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
    this.timers = { poll: 0, ago: 0 };
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
    this.wrap = prefGet(PREF.wrap) === '1';
    const w = Number(prefGet(PREF.window));
    this.windowMax = WINDOWS.includes(w) ? w : DEFAULT_WINDOW;
    const iv = Number(prefGet(PREF.interval));
    this.interval = INTERVALS.includes(iv) ? iv : 5;
    this.whereOpen = false;
    this.whereAuto = true;

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

    // timeline: family toggles (also the histogram legend) and the histogram
    this.famEl = h('div', { class: 'lg-fams', role: 'group', 'aria-label': 'Event families: click to show or hide, Alt-click to show only one' });
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
          on: { click: (e) => this.toggleFamily(f.id, e.altKey || e.shiftKey) },
        },
        h('span', { class: 'lg-fam-sw', 'aria-hidden': 'true' }),
        h('span', { class: 'lg-fam-label' }, f.label),
        count,
      );
      this.famBtns.set(f.id, { btn, count });
      this.famEl.append(btn);
    }
    this.rangeEl = h('div', { class: 'lg-range' });
    this.histogram = new Histogram({
      series: this.families,
      label: 'Log lines over time, stacked by event family',
      unit: 'line',
      onBrush: (r) => this.onBrush(r),
    });
    this.timeline = h(
      'section',
      { class: 'tile lg-timeline', 'aria-label': 'Timeline' },
      h('div', { class: 'lg-tl-head' }, this.famEl, this.rangeEl),
      this.histogram.el,
    );

    // stream
    this.countEl = h('span', { class: 'lg-count' });
    this.matchEl = h('span', { class: 'lg-matchnav', hidden: true });
    this.selfEl = h('span', { class: 'lg-selfwrap' });
    this.followBtn = h('button', { class: 'btn sm lg-follow', type: 'button', title: 'Follow the newest line (f)', on: { click: () => this.toggleFollow() } }, icon('arrow', { class: 'lg-down' }), 'Follow');
    this.wrapBtn = h('button', { class: 'btn sm', type: 'button', title: 'Wrap long lines', 'aria-pressed': this.wrap ? 'true' : 'false', on: { click: () => this.toggleWrap() } }, icon('rows'), 'Wrap');
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
      this.matchEl,
      this.selfEl,
      h('span', { class: 'spacer' }),
      this.followBtn,
      this.wrapBtn,
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
      h('button', { class: 'btn sm icon', type: 'button', title: 'Copy this line (c)', 'aria-label': 'Copy this line', on: { click: () => this.hoverRow && this.copyLine(this.hoverRow) } }, icon('copy')),
      h('button', { class: 'btn sm icon', type: 'button', title: 'Decode this line (Enter)', 'aria-label': 'Decode this line', on: { click: () => this.hoverRow && this.select(this.hoverRow, { open: true }) } }, icon('info')),
    );
    this.stateEl = h('div', { class: 'lg-state', hidden: true });
    this.streamWrap = h('div', { class: 'lg-wrap' }, this.scroller, this.newPill, this.hintEl, this.hoverBar, this.stateEl);
    this.footEl = h('div', { class: 'lg-foot', role: 'status', 'aria-live': 'off' });
    this.stream = h('section', { class: 'tile lg-stream', 'aria-label': 'Log stream' }, this.streamBar, this.noticeEl, this.streamWrap, this.footEl);

    this.el.append(this.head, this.srcRow, this.whereEl, this.queryEl, this.timeline, this.stream);

    this.list = new LineList(this.scroller, { h, render: (row) => this.renderRow(row), onScroll: (programmatic) => this.onScroll(programmatic) });
    this.list.setWrap(this.wrap);
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
    this.offs.push(this.ctx.store.on('inventory', () => {
      this.updateHints();
      this.list.reconcile(true);
      this.renderSub();
    }));
    this.offs.push(this.ctx.store.on('sessions', () => this.refreshLiveLink()));
    this.offs.push(this.ctx.store.on('scope', () => this.renderSub()));
    this.timers.ago = setInterval(() => this.renderFoot(), 1000);
  }

  destroy() {
    this.dead = true;
    clearTimeout(this.timers.poll);
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
    const type = p.get('type');
    if (type && /^[a-z-]{2,32}$/.test(type)) this.reportType = type;
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

  async loadSources(force = false) {
    const res = await this.ctx.api.get('/api/logs/sources');
    if (this.dead) return;
    if (res.status === 401) return;
    if (!res.ok) {
      if (res.status === 429 && !force) {
        setTimeout(() => !this.dead && this.loadSources(true), (res.retryAfter || 2) * 1000);
        return;
      }
      this.failSources({ status: res.status === 0 ? 'offline' : 'failed', message: res.data.error || `The log sources could not be read (HTTP ${res.status}).` });
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
    this.subEl.textContent = 'The log configuration could not be read.';
    this.showState({
      status: state.status,
      title: denied ? 'Your Junos login class cannot read the log configuration' : undefined,
      message: denied && /login class does not allow/i.test(state.message || '') ? null : state.message,
      hint: denied
        ? 'J-Wicket first reads the syslog and security log settings to learn which logs exist, and your class may not read them. Reading a log file ("show log") also needs the trace permission, which the read-only class does not have. Ask your Junos administrator.'
        : undefined,
      actions: [this.retryButton(() => this.loadSources(true))],
    });
    this.renderLive();
    this.renderBar();
    this.renderFoot();
  }

  buildSourceList(src) {
    const list = [];
    for (const f of src.files || []) {
      const traffic = /RT_FLOW/i.test(f.match || '') ? 'yes' : (f.contents || []).some((c) => /^(any|user) (any|info)$/.test(c)) ? 'maybe' : 'no';
      const meta = [];
      if (f.match) meta.push(`match ${f.match}`);
      if ((f.contents || []).length) meta.push(f.contents.join(', '));
      if (f.structured_data) meta.push('structured data');
      if (f.assumed) meta.push('default file');
      list.push({ id: f.id, kind: 'file', name: f.name, label: f.name, meta: meta.join(SEP) || 'syslog file', file: f, traffic, structured: Boolean(f.structured_data) });
    }
    for (const d of src.databases || []) {
      if (d.id === 'report') {
        list.push({ id: 'report', kind: 'report', name: d.name || 'On-box reporting', label: 'on-box report', meta: 'reporting database', types: (d.types || []).slice(), traffic: 'yes' });
      } else if (d.id === 'buffer') {
        list.push({ id: 'buffer', kind: 'buffer', name: d.name || 'Security log buffer', label: 'log buffer', meta: 'routing engine, event mode', traffic: 'yes' });
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
    put(
      this.srcGroup,
      this.sourceList.map((s) =>
        h(
          'button',
          {
            class: ['lg-src', `kind-${s.kind}`],
            type: 'button',
            'aria-pressed': this.src && this.src.id === s.id ? 'true' : 'false',
            dataset: { id: s.id },
            title: `${s.name}${SEP}${s.meta}`,
            on: { click: () => this.switchSource(s) },
          },
          icon(s.kind === 'file' ? 'logs' : s.kind === 'report' ? 'grid' : 'layers', { class: 'lg-src-ico' }),
          h('span', { class: 'lg-src-txt' }, h('span', { class: 'lg-src-name' }, s.label), h('span', { class: 'lg-src-meta' }, s.meta)),
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
    this.whereEl.hidden = !(tr && this.whereOpen);
    if (!tr) return;
    const mode = tr.effective_mode || 'unknown';
    const modeCls = mode === 'stream' ? 'amber' : mode === 'event' ? 'permit' : mode === 'stream-event' ? 'sky' : 'muted';
    const onBox = this.sourceList.filter((s) => s.traffic === 'yes');
    const maybe = this.sourceList.filter((s) => s.traffic === 'maybe');
    const streams = tr.streams || [];
    const facts = [
      h('dt', null, 'Mode'),
      h('dd', null, h('span', { class: ['pill', modeCls] }, mode), h('span', { class: 'faint' }, ` ${tr.mode_basis || ''}`)),
    ];
    if (streams.length) {
      facts.push(
        h('dt', null, 'Streamed to'),
        h(
          'dd',
          { class: 'lg-streams' },
          streams.map((s) =>
            h(
              'span',
              { class: 'lg-stream-host' },
              icon('broadcast'),
              h('b', { class: 'mono' }, `${s.host || '?'}${s.port ? `:${s.port}` : ''}`),
              h('span', { class: 'faint' }, [s.name, s.format, (s.category || []).filter(Boolean).join('/')].filter(Boolean).join(SEP)),
            ),
          ),
        ),
      );
    }
    facts.push(h('dt', null, 'On-box reporting'), h('dd', null, tr.report ? 'Enabled: a local report database keeps a copy.' : 'Not enabled.'));
    const jump = (s) =>
      h('button', { class: ['btn', 'sm', this.src && this.src.id === s.id && 'is-current'], type: 'button', on: { click: () => this.switchSource(s) } }, icon(s.kind === 'file' ? 'logs' : s.kind === 'report' ? 'grid' : 'layers'), s.label);
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
          h('p', { class: 'lg-where-text' }, tr.where || 'The security log mode is not known.'),
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
        h('button', { class: 'btn ghost icon lg-where-x', type: 'button', 'aria-label': 'Close', title: 'Close', on: { click: () => this.toggleWhere() } }, icon('close')),
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
    this.resetRows();
    this.firstSeqLive = Infinity;
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
      this.loadSources(true);
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
      this.schedule(res.retryAfter || 2);
      return;
    }
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
        this.showState({ status: res.status === 0 ? 'offline' : 'failed', message, actions: [this.retryButton(() => this.restart())] });
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
    this.ingest(log, src, initial);
    this.schedule();
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

  ingest(log, src, initial) {
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
    } else {
      items = lines.map((line) => ({ line: String(line), ev: null }));
    }
    if (src.kind !== 'file') items = this.timeOrder(items);
    if (src.kind === 'file') {
      this.cursor = log.cursor || this.cursor;
      this.deviceInfo = { window: log.window, dropped: initial ? log.dropped || 0 : (this.deviceInfo && this.deviceInfo.dropped) || 0, returned: lines.length };
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
      markers.push({ kind: 'gap', text: `The device returned its limit of ${this.fmt.num(REPORT_COUNT)} lines; some lines before this point may be missing.` });
    }
    const dedupe = src.kind !== 'file' || Boolean(log.reset);
    this.append(items, markers, dedupe, initial);
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
    const row = {
      seq: (this.seq += 1),
      line,
      p,
      fam,
      famIx: this.famIndex.get(fam),
      time: Number.isFinite(p.time) ? p.time : null,
      self: this.lp.isSelfRead(p, this.readAs),
      sid: sessionIdOf(p),
      len: line.length,
      added: Date.now(),
      toks: null,
      tg: -1,
      marker: null,
    };
    return row;
  }

  markerRow(marker) {
    return { seq: (this.seq += 1), line: '', p: null, fam: 'other', famIx: 0, time: null, self: false, sid: null, len: 0, added: Date.now(), marker };
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
      if (row.time !== null && (this.newest === null || row.time > this.newest)) this.newest = row.time;
    }
    // A marker with nothing after it says nothing: drop markers when no lines followed.
    if (!added.some((r) => !r.marker)) {
      if (initial) this.afterIngest(0, initial);
      else this.renderFoot();
      return;
    }
    for (const row of added) {
      this.rows.push(row);
      this.bySeq.set(row.seq, row);
      if (!row.marker) this.seen.set(row.line, (this.seen.get(row.line) || 0) + 1);
    }
    const excess = this.rows.length - this.windowMax;
    if (excess > 0) {
      const unseen = this.unseen;
      this.trimFront(excess);
      this.refilter();
      if (!this.follow) this.unseen = unseen + added.filter((r) => !r.marker && this.indexOfSeq(r.seq) >= 0).length;
    } else {
      this.filterAppend(added);
    }
    this.afterIngest(added.filter((r) => !r.marker).length, initial);
  }

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
    }
  }

  setWindow(n) {
    if (!WINDOWS.includes(n)) return;
    this.windowMax = n;
    prefSet(PREF.window, n);
    const excess = this.rows.length - n;
    if (excess > 0) {
      this.trimFront(excess);
      this.refilter();
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
    if (initial) this.firstSeqLive = this.seq;
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
    const plan = this.q.plan(parsed.ast, `logs:${kind}`);
    if (kind === 'report' && plan.expression) {
      // The report expression's accepted keys and its != >= <= forms are inferred, not verified on a
      // device (research note 51): the device narrows, and the browser checks every term again.
      plan.browser = parsed.ast;
      for (const e of plan.explain) if (e.where === 'device') e.refine = true;
    }
    this.plan = plan;
    if (this.bar) this.bar.setPlan(plan);
    const split = this.splitTime(plan.browser);
    const ctx = { now: Date.now() };
    this.pred = this.q.compile(split.rest, this.q.FIELDS.logs, ctx);
    this.predTime = this.q.compile(split.time, this.q.FIELDS.logs, ctx);
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

  /** 0: one of your own hidden reads; 1: filtered out by the query; 2: passes the query. */
  passes(row) {
    if (row.self && !this.showSelf) return 0;
    if (!this.pred(row.p)) return 1;
    return 2;
  }

  refilter() {
    const counts = new Array(this.families.length).fill(0);
    const vis = [];
    const times = [];
    const series = [];
    let selfHidden = 0;
    let matches = 0;
    for (const row of this.rows) {
      if (row.marker) {
        vis.push(row);
        continue;
      }
      const r = this.passes(row);
      if (r === 0) {
        selfHidden += 1;
        continue;
      }
      if (r === 1) continue;
      const famOn = !this.famOff.has(row.fam);
      if (famOn && row.time !== null) {
        times.push(row.time);
        series.push(row.famIx);
      }
      if (!this.predTime(row.p)) continue;
      counts[row.famIx] += 1;
      if (!famOn) continue;
      vis.push(row);
      if (this.markRe) {
        this.markRe.lastIndex = 0;
        if (this.markRe.test(row.line)) matches += 1;
      }
    }
    // Markers between nothing are noise: drop leading/consecutive markers in the visible list.
    this.visible = this.tidyMarkers(vis);
    this.famCounts = counts;
    this.selfHidden = selfHidden;
    this.matchCount = matches;
    this.hist = { times, series };
    const anchor = this.follow ? null : this.list.anchor();
    this.list.setItems(this.visible);
    if (this.follow) this.list.scrollToEnd();
    else if (anchor) this.list.restore(anchor, (seq) => this.indexOfSeq(seq));
    this.unseen = 0;
    this.renderAll();
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

  filterAppend(added) {
    const from = this.visible.length;
    let visibleAdded = 0;
    let pendingMarker = null;
    for (const row of added) {
      if (row.marker) {
        pendingMarker = row;
        continue;
      }
      const r = this.passes(row);
      if (r === 0) {
        this.selfHidden += 1;
        continue;
      }
      if (r === 1) continue;
      const famOn = !this.famOff.has(row.fam);
      if (famOn && row.time !== null) {
        this.hist.times.push(row.time);
        this.hist.series.push(row.famIx);
      }
      if (!this.predTime(row.p)) continue;
      this.famCounts[row.famIx] += 1;
      if (!famOn) continue;
      if (pendingMarker && this.visible.length) this.visible.push(pendingMarker);
      pendingMarker = null;
      this.visible.push(row);
      visibleAdded += 1;
      if (this.markRe) {
        this.markRe.lastIndex = 0;
        if (this.markRe.test(row.line)) this.matchCount += 1;
      }
    }
    if (this.visible.length > from) {
      // When following, afterIngest() scrolls to the end and draws once there.
      this.list.appended(from, { draw: !this.follow });
      if (!this.follow) this.unseen += visibleAdded;
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

  toggleFamily(id, solo) {
    if (solo) {
      const only = this.famOff.size === this.families.length - 1 && !this.famOff.has(id);
      this.famOff = only ? new Set() : new Set(this.families.map((f) => f.id).filter((x) => x !== id));
    } else if (this.famOff.has(id)) {
      this.famOff.delete(id);
    } else {
      this.famOff.add(id);
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
    const text = this.queryText;
    const parsed = this.q.parse(text, { view: 'logs' });
    let base = text;
    if (!parsed.error && parsed.ast) {
      const split = this.splitTime(parsed.ast);
      const cuts = (split.items || []).map((it) => [it.gpos ?? it.pos, it.gend ?? it.end]).sort((a, b) => b[0] - a[0]);
      for (const [a, b] of cuts) base = `${base.slice(0, a)} ${base.slice(b)}`;
      base = base.replace(/\s{2,}/g, ' ').replace(/(^|\s)(AND|and|&&)(\s+(AND|and|&&))+(\s|$)/g, '$1$2$5').replace(/^\s*(AND|and|&&)\s+|\s+(AND|and|&&)\s*$/g, '').trim();
    }
    let next = base;
    if (range) {
      const lo = Math.floor(range.lo / 1000) * 1000;
      const hi = Math.floor(range.hi / 1000) * 1000;
      const fmt = (ms) => isoNoZone(ms);
      next = `${base ? `${base} ` : ''}time>=${fmt(lo)} time<=${fmt(hi)}`;
    }
    this.setQuery(next.trim());
    this.ctx.ui.announce(range ? `Time range ${clock(range.lo)} to ${clock(range.hi)}` : 'Time range cleared');
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
    const v = tk.q !== undefined && tk.q !== null ? tk.q : tk.v;
    let value = String(v).trim();
    if (tk.t === 'port' && !tk.q) value = value.replace(/^[/:]/, '');
    if (tk.t === 'str') value = value.replace(/^['"]|['"]$/g, '');
    if (!value) return null;
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

  // ---- rendering rows -----------------------------------------------------------------------------

  /** Appends the highlighted tokens of `row` to `target`; returns whether any search mark was made. */
  fillTokens(target, row, interactive) {
    const toks = this.tokensOf(row);
    const ranges = this.markRanges(row.line);
    let pos = 0;
    let ri = 0;
    for (let ti = 0; ti < toks.length; ti += 1) {
      const tk = toks[ti];
      const v = tk.v;
      const s = pos;
      const e = pos + v.length;
      pos = e;
      let box = target;
      if (tk.t !== 'text') {
        const span = document.createElement('span');
        let cls = `tk-${tk.t}`;
        if (tk.t === 'tag') cls += ` fam-${row.fam}`;
        if (interactive && CLICKABLE.has(tk.t) && v.trim()) {
          cls += ' tk-click';
          span.dataset.ti = String(ti);
        }
        span.className = cls;
        target.append(span);
        box = span;
      }
      while (ranges && ri < ranges.length && ranges[ri][1] <= s) ri += 1;
      if (!ranges || ri >= ranges.length || ranges[ri][0] >= e) {
        box.append(v);
        continue;
      }
      let at = s;
      let k = ri;
      while (at < e) {
        const r = ranges[k];
        if (!r || r[0] >= e) {
          box.append(v.slice(at - s));
          break;
        }
        if (r[0] > at) {
          box.append(v.slice(at - s, r[0] - s));
          at = r[0];
        }
        const stop = Math.min(e, r[1]);
        const mark = document.createElement('mark');
        mark.className = 'lg-hit';
        mark.textContent = v.slice(at - s, stop - s);
        box.append(mark);
        at = stop;
        if (r[1] <= e) k += 1;
      }
    }
    return Boolean(ranges);
  }

  renderRow(row) {
    const node = document.createElement('div');
    node.setAttribute('role', 'row');
    node.id = `lg-r-${row.seq}`;
    node.dataset.seq = String(row.seq);
    if (row.marker) {
      node.className = `lg-row lg-marker is-${row.marker.kind}`;
      const cell = document.createElement('span');
      cell.setAttribute('role', 'gridcell');
      cell.className = 'lg-marker-text';
      cell.append(this.dom.icon(row.marker.kind === 'reset' ? 'refresh' : 'alert'), document.createTextNode(row.marker.text));
      node.append(cell);
      return node;
    }
    let cls = `lg-row fam-${row.fam}`;
    if (row.seq === this.selSeq) cls += ' is-sel';
    if (row.seq === this.curSeq) cls += ' is-cur';
    if (row.self) cls += ' is-self';
    else if (Number.isInteger(row.p.severity) && row.p.severity <= 3) cls += ' is-err';
    if (Date.now() - row.added < 1600 && this.lastRead && !this.firstPaint(row)) cls += ' is-new';
    node.className = cls;
    if (row.seq === this.selSeq) node.setAttribute('aria-selected', 'true');
    // The gutter carries the family stripe and the search bead; it stays put when long lines scroll.
    const gut = document.createElement('span');
    gut.className = 'lg-gut';
    gut.setAttribute('aria-hidden', 'true');
    const cell = document.createElement('span');
    cell.setAttribute('role', 'gridcell');
    cell.className = 'lg-text';
    if (this.fillTokens(cell, row, true)) node.classList.add('has-hit');
    node.append(gut, cell);
    return node;
  }

  firstPaint(row) {
    // Lines from the first read of a source do not flash.
    return row.seq <= (this.firstSeqLive || 0);
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
      const tk = this.tokensOf(row)[Number(tkEl.dataset.ti)];
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
      const tk = this.tokensOf(row)[Number(tkEl.dataset.ti)];
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
    } else if (key === 'c' && this.selSeq !== null) {
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
    while (this.visible[j] && this.visible[j].marker && j > 0 && j < this.visible.length - 1) j += delta > 0 ? 1 : -1;
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
    this.wrapBtn.setAttribute('aria-pressed', this.wrap ? 'true' : 'false');
    this.list.setWrap(this.wrap);
    if (this.follow) this.list.scrollToEnd();
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
      this.renderLive();
      if (!this.inflight) this.poll(false);
    }
  }

  setInterval(s) {
    if (!INTERVALS.includes(s)) return;
    this.interval = s;
    prefSet(PREF.interval, s);
    this.renderLive();
    if (!this.paused && !this.inflight && this.liveCapable()) this.schedule();
  }

  copyLine(row) {
    this.ctx.ui.copy(row.line, 'Log line copied.');
  }

  retryButton(fn) {
    const { h, icon } = this.dom;
    return h('button', { class: 'btn sm', type: 'button', on: { click: fn } }, icon('refresh'), 'Try again');
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
            r.sid || '', val(f.reason), r.line,
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
        p.tag ? h('span', { class: ['lg-d-tag', 'mono', `fam-${row.fam}`] }, p.tag) : null,
        sev ? h('span', { class: ['pill', p.severity <= 3 ? 'deny' : p.severity === 4 ? 'reject' : 'muted'], title: p.severitySource ? `severity from ${p.severitySource}` : null }, sev) : null,
        row.self ? h('span', { class: 'pill gold', title: this.selfNote || '' }, 'your J-Wicket read') : null,
        h('span', { class: 'spacer' }),
        h('span', { class: 'lg-d-time mono' }, row.time !== null ? stampMs(row.time, hasMs(p)) : p.ts || 'no time'),
      ),
    );
    const sentence = this.lp.decode(p);
    if (sentence) {
      const parts = sentence.split(SEP);
      content.append(
        h(
          'div',
          { class: ['lg-d-sentence', `fam-${row.fam}`] },
          h('p', { class: 'lg-d-lead' }, parts[0]),
          parts.length > 1 ? h('ul', { class: 'lg-d-facts' }, parts.slice(1).map((x) => h('li', null, x))) : null,
        ),
      );
    } else {
      content.append(h('p', { class: 'lg-d-none' }, 'J-Wicket has no decoder for this message. Its parts are listed below; click a value to filter by it.'));
    }
    if (p.flow) content.append(this.flowStrip(p.flow, row));
    if (row.sid || (p.flow && FLOW_FAMS.has(row.fam))) content.append(this.timelineSection(row));
    content.append(this.fieldsSection(row));
    const raw = h('div', { class: 'lg-d-raw' });
    this.fillTokens(raw, row, false);
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
    const hp = (ip, port) => (ip ? `${ip.includes(':') ? `[${ip}]` : ip}${port !== null && port !== undefined ? `:${port}` : ''}` : '?');
    const zone = (z, key) => (z ? h('button', { class: 'zone lg-d-zone', type: 'button', title: `Filter ${key}:${z}`, on: { click: (e) => this.addTerm(termText(key, z), e.altKey) } }, z) : h('span', { class: 'faint' }, 'zone ?'));
    const policy = fl.policy
      ? h('button', { class: 'policy-link', type: 'button', title: `Open policy ${fl.policy} in Policies`, on: { click: () => this.ctx.navigate('policies', { q: `name:${quoteValue(fl.policy, true)}` }) } }, fl.policy)
      : h('span', { class: 'faint mono' }, 'no policy');
    const verdict = row.fam === 'deny' ? h('span', { class: 'pill deny' }, 'denied') : row.fam === 'close' ? h('span', { class: 'pill teal' }, fl.reason || 'closed') : h('span', { class: 'pill permit' }, 'permitted');
    const nat = [];
    if (fl.snat) nat.push(h('div', { class: 'lg-d-nat' }, h('span', { class: 'pill violet' }, 'SNAT'), h('span', { class: 'mono' }, hp(fl.src, fl.sport)), icon('arrow'), h('span', { class: 'mono nat' }, hp(fl.natSrc, fl.natSport)), fl.snatRule ? h('span', { class: 'faint' }, `rule ${fl.snatRule}`) : null));
    if (fl.dnat) nat.push(h('div', { class: 'lg-d-nat' }, h('span', { class: 'pill violet' }, 'DNAT'), h('span', { class: 'mono' }, hp(fl.dst, fl.dport)), icon('arrow'), h('span', { class: 'mono nat' }, hp(fl.natDst, fl.natDport)), fl.dnatRule ? h('span', { class: 'faint' }, `rule ${fl.dnatRule}`) : null));
    const stats = [];
    if (fl.bytesClient !== null || fl.bytesServer !== null) {
      // Exact byte counts: the decoded sentence above rounds (1024-based), the counters do not.
      const side = (arrow, who, b, pk) => h('span', { title: `${this.fmt.bytes(b || 0)}` }, h('span', { class: 'faint' }, `${arrow} ${who} `), h('b', { class: 'mono' }, `${this.fmt.num(b || 0)} B`), pk !== null ? h('span', { class: 'faint' }, ` in ${this.fmt.plural(pk, 'packet')}`) : null);
      stats.push(side('\u2191', 'from client', fl.bytesClient, fl.packetsClient));
      stats.push(side('\u2193', 'from server', fl.bytesServer, fl.packetsServer));
    }
    if (fl.elapsed !== null) stats.push(h('span', null, h('span', { class: 'faint' }, 'lasted '), h('b', { class: 'mono' }, this.fmt.duration(fl.elapsed))));
    if (fl.app) stats.push(h('span', null, h('span', { class: 'faint' }, 'app '), h('b', { class: 'mono' }, fl.app)));
    if (fl.iface) stats.push(h('span', null, h('span', { class: 'faint' }, 'in '), h('b', { class: 'mono iface' }, fl.iface)));
    return h(
      'section',
      { class: 'panel-section' },
      h('h3', null, 'Flow'),
      h(
        'div',
        { class: ['lg-d-flow', `fam-${row.fam}`] },
        h('div', { class: 'lg-d-end' }, h('span', { class: 'lg-d-role' }, 'client'), h('span', { class: 'mono lg-d-ep' }, hp(fl.src, fl.sport))),
        h('span', { class: 'lg-d-arr', 'aria-hidden': 'true' }, icon('arrow')),
        h('div', { class: 'lg-d-mid' }, h('div', { class: 'lg-d-zones' }, zone(fl.from, 'from'), icon('arrow'), zone(fl.to, 'to')), h('div', { class: 'lg-d-pol' }, policy, verdict), h('div', { class: 'lg-d-proto faint mono' }, [fl.protocol ? fl.protocol.toUpperCase() : null, fl.service].filter(Boolean).join(SEP))),
        h('span', { class: 'lg-d-arr', 'aria-hidden': 'true' }, icon('arrow')),
        h('div', { class: 'lg-d-end' }, h('span', { class: 'lg-d-role' }, fl.dnat ? 'server (as the client sent it)' : 'server'), h('span', { class: 'mono lg-d-ep' }, hp(fl.dst, fl.dport))),
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
      if (r.fam === 'close') what = [f.reason, f.elapsed !== null ? this.fmt.duration(f.elapsed) : null, f.bytesClient !== null || f.bytesServer !== null ? `${this.fmt.num((f.bytesClient || 0) + (f.bytesServer || 0))} B` : null].filter(Boolean).join(SEP);
      else if (r.fam === 'create') what = [f.policy ? `via ${f.policy}` : null, f.snat ? `SNAT ${f.natSrc}:${f.natSport}` : null, f.dnat ? `DNAT \u2192 ${f.natDst}:${f.natDport}` : null].filter(Boolean).join(SEP);
      else what = [f.policy ? `by ${f.policy}` : null, f.sport !== null ? `from port ${f.sport}` : null, f.reason].filter(Boolean).join(SEP);
      return h(
        'li',
        { class: ['lg-tl-item', `fam-${r.fam}`, r.seq === row.seq && 'is-here'] },
        h('span', { class: 'lg-tl-dot', 'aria-hidden': 'true' }),
        h('span', { class: 'lg-tl-time mono' }, r.time !== null ? stampMs(r.time, hasMs(r.p)).slice(11) : '?'),
        h('span', { class: ['lg-tl-ev', `fam-${r.fam}`] }, evLabel[r.fam] || r.fam),
        h('span', { class: 'lg-tl-what' }, what || '\u2014'),
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
      h('h3', null, 'Session timeline'),
      h('div', { class: 'lg-d-tlhead' }, h('b', null, title), h('span', { class: 'faint' }, `${this.fmt.plural(related.length, 'line')} in this window`), h('span', { class: 'spacer' }), filterBtn),
      h('ol', { class: 'lg-tl' }, items),
      missing.length ? h('ul', { class: 'lg-d-missing' }, missing.map((m) => h('li', null, m))) : null,
      this.liveLinkEl,
    );
  }

  refreshLiveLink() {
    const el = this.liveLinkEl;
    const row = this.liveLinkFor;
    if (!el || !row || this.panelSeq === null) return;
    const { h, put, icon } = this.dom;
    if (!row.sid) {
      el.hidden = true;
      return;
    }
    el.hidden = false;
    const last = this.ctx.store.sessionsLast;
    const rowsNow = (last && last.sessions && last.sessions.rows) || [];
    const found = rowsNow.find((r) => String(r.session_id) === String(row.sid));
    const open = () => this.ctx.navigate('sessions', found ? { q: `id:${row.sid}`, sel: found.id } : { q: `id:${row.sid}` });
    const btn = (label) => h('button', { class: 'btn sm', type: 'button', on: { click: open } }, icon('sessions'), label);
    if (!last || !last.sessions) {
      put(el, h('span', { class: 'lg-live-dot is-unknown', 'aria-hidden': 'true' }), h('span', null, 'Sessions have not been read in this tab yet, so J-Wicket cannot say whether this session is still open.'), btn('Look for it in Sessions'));
      return;
    }
    const hit = found;
    const readAt = last.meta && last.meta.read_at ? this.fmt.time(last.meta.read_at) : '?';
    if (hit) {
      const bytes = ((hit.in && hit.in.bytes) || 0) + ((hit.out && hit.out.bytes) || 0);
      put(
        el,
        h('span', { class: 'lg-live-dot is-live', 'aria-hidden': 'true' }),
        h('span', null, h('b', null, 'Still open'), ` in the Sessions read at ${readAt} UTC`, hit.duration !== null && hit.duration !== undefined ? ` · ${this.fmt.duration(hit.duration)} old` : '', bytes ? ` · ${this.fmt.bytes(bytes)} so far` : '', hit.location ? ` · ${hit.location}` : ''),
        btn('Open in Sessions'),
      );
    } else {
      put(el, h('span', { class: 'lg-live-dot', 'aria-hidden': 'true' }), h('span', null, `Not in the last Sessions read (${readAt} UTC): it has ended, started after that read, or the read was filtered or capped.`), btn('Look for it in Sessions'));
    }
  }

  fieldsSection(row) {
    const { h, icon } = this.dom;
    const p = row.p;
    const fieldKeys = this.fieldKeyMap();
    const rows = [];
    const add = (label, value, key, opts = {}) => {
      if (value === null || value === undefined || value === '') return;
      const v = String(value);
      const ph = isPlaceholder(v);
      const term = opts.term !== undefined ? opts.term : ph ? null : key ? termText(key, v) : null;
      rows.push(
        h(
          'tr',
          { class: ph ? 'is-ph' : null },
          h('th', { scope: 'row', class: 'mono' }, label),
          h('td', { class: 'mono' }, opts.cls ? h('span', { class: opts.cls }, v) : v),
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
      add(k, fields[k], qk, { cls, term: isPlaceholder(fields[k]) ? null : qk ? termText(qk, fields[k]) : termText(null, fields[k]) });
    }
    const fieldsTable = rows.length ? h('table', { class: 'lg-d-fields' }, h('tbody', null, rows.splice(0))) : null;
    // Lines without structured data: the typed tokens of the message are a second table.
    let partsTable = null;
    if (p.format !== 'rfc5424' || !p.sdid) {
      const seen = new Set();
      const toks = this.tokensOf(row).filter((t) => t.t !== 'text' && !['ts', 'host', 'daemon', 'pid', 'tag', 'pri', 'key', 'sdid', 'arrow'].includes(t.t) && t.v.trim());
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
    const card = stateCard({ ...opts, compact: false });
    put(this.stateEl, h('div', { class: 'lg-state-in' }, card, opts.skeleton ? skeleton(4) : null));
    this.stateEl.hidden = false;
    this.stateKind = opts.kind || opts.status;
    // Nothing was read: the timeline has nothing to say, so it steps aside for the explanation.
    const bad = ['denied', 'unsupported', 'failed', 'offline', 'session-lost'].includes(opts.status);
    this.el.classList.toggle('is-nodata', bad && !this.rows.length);
  }

  hideState() {
    this.stateEl.hidden = true;
    this.stateEl.replaceChildren();
    this.stateKind = null;
    this.el.classList.remove('is-nodata');
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
    const key = `${total}|${why.join(',')}`;
    if (this.stateKind === 'nomatch' && this.noMatchKey === key) return;
    this.noMatchKey = key;
    this.showState({
      status: 'empty',
      kind: 'nomatch',
      title: `None of the ${this.fmt.plural(total, 'line')} in this window match`,
      message: why.length ? `Filtered out by ${why.join(' and ')}.` : null,
      hint: 'New lines that match appear here as they arrive.',
      actions,
      code: false,
    });
  }

  renderAll() {
    this.renderFams();
    this.renderBar();
    this.renderMatchNav();
    this.renderNewPill();
    this.renderFoot();
    this.renderRange();
    this.histogram.setEmptyText(this.rows.length ? 'No line with a time passes the filters' : 'No timed lines to chart yet');
    this.histogram.update({ times: this.hist.times, series: this.hist.series, selection: this.timeRange ? this.histSel() : null });
    this.scroller.setAttribute('aria-rowcount', String(this.visible.length));
    this.renderNoMatch();
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
        h('span', { class: 'lg-range-txt' }, icon('clock'), h('b', { class: 'mono' }, `${clock(sel.lo)} \u2013 ${clock(sel.hi)}`)),
        h('button', { class: 'btn ghost sm', type: 'button', title: 'Clear the time range (double-click the chart)', on: { click: () => this.onBrush(null) } }, icon('close'), 'Clear'),
      );
    } else {
      this.rangeEl.replaceChildren();
    }
    this.rangeEl.hidden = !sel;
  }

  renderFams() {
    const counts = this.famCounts || new Array(this.families.length).fill(0);
    for (const [i, f] of this.families.entries()) {
      const { btn, count } = this.famBtns.get(f.id);
      const n = counts[i] || 0;
      const on = !this.famOff.has(f.id);
      btn.setAttribute('aria-pressed', on ? 'true' : 'false');
      btn.classList.toggle('is-zero', n === 0);
      tick(count, this.fmt.compact(n));
      btn.title = `${f.label}: ${this.fmt.plural(n, 'line')} match${n === 1 ? 'es' : ''}. ${on ? 'Click to hide' : 'Click to show'}; Alt-click to show only this family.`;
      btn.setAttribute('aria-label', `${f.label}, ${n} lines, ${on ? 'shown' : 'hidden'}`);
    }
  }

  renderBar() {
    const { h, put, icon } = this.dom;
    const shown = this.visible.reduce((n, r) => n + (r.marker ? 0 : 1), 0);
    const total = this.rows.reduce((n, r) => n + (r.marker ? 0 : 1), 0);
    put(
      this.countEl,
      h('b', { class: 'mono' }, this.fmt.num(shown)),
      shown !== total ? h('span', { class: 'faint' }, ` of ${this.fmt.num(total)}`) : null,
      h('span', { class: 'faint' }, ` ${total === 1 && shown === total ? 'line' : 'lines'}`),
      h('span', { class: 'faint lg-win' }, ` \u00b7 keeps ${this.fmt.compact(this.windowMax)}`),
    );
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
    this.livePill.className = `live-pill${live ? '' : ' paused'}`;
    this.livePill.disabled = !can;
    put(
      this.livePill,
      h('span', { class: 'dot', 'aria-hidden': 'true' }),
      live ? 'LIVE' : can ? 'PAUSED' : 'STOPPED',
      h('span', { class: 'sub' }, live ? `${this.interval} s` : can ? 'space' : ''),
    );
    this.livePill.setAttribute('aria-pressed', live ? 'false' : 'true');
    this.livePill.setAttribute('aria-label', live ? `Live: reading new lines every ${this.interval} s. Pause (space).` : can ? 'Paused. Resume the live tail (space).' : 'The live tail is stopped.');
    this.livePill.title = live ? 'Pause the live tail (space)' : can ? 'Resume the live tail (space)' : 'Nothing to tail';
    for (const b of this.ivSeg.querySelectorAll('button')) b.setAttribute('aria-pressed', Number(b.dataset.s) === this.interval ? 'true' : 'false');
    this.ctx.ui.setLive('logs', Boolean(live));
  }

  renderSub() {
    const { h, put } = this.dom;
    const s = this.src;
    if (!s) return;
    const scope = this.ctx.store.scope;
    const parts = [h('b', { class: 'mono' }, s.kind === 'report' ? `report ${this.reportType}` : s.kind === 'buffer' ? 'security log buffer' : s.label)];
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
    if (this.inflight) parts.push(h('span', { class: 'lg-reading' }, 'reading\u2026'));
    else if (lr) parts.push(h('span', { class: lr.ok ? null : 'act-deny' }, `${lr.ok ? 'read' : 'read failed'} ${clock(lr.at)} (${this.fmt.ago(lr.at)})`));
    if (!this.inflight && this.nextAt && !this.paused && this.liveCapable()) {
      const s = Math.max(0, Math.ceil((this.nextAt - Date.now()) / 1000));
      parts.push(h('span', null, `next in ${s} s`));
    } else if (this.paused) parts.push(h('span', null, 'paused'));
    const di = this.deviceInfo;
    if (di && this.src && this.src.kind === 'file' && Number.isFinite(di.window)) {
      parts.push(h('span', null, `device window ${this.fmt.num(di.window)} lines`));
      if (di.dropped) parts.push(h('span', { title: 'The first read returns the newest matching lines only' }, `${this.fmt.num(di.dropped)} older not read`));
    }
    if (di && this.src && this.src.kind === 'report' && di.limited) parts.push(h('span', { class: 'act-reject' }, `report limit ${this.fmt.num(REPORT_COUNT)} reached`));
    if (this.newest !== null && this.src && this.src.kind !== 'file') parts.push(h('span', null, `newest ${clock(this.newest)}`));
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
