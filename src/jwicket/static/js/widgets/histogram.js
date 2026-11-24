// histogram.js: the stacked event-rate strip above the Logs stream.
//
//   const hist = new Histogram({ series: [{ id, label }], label, onBrush(range | null), unit: 'line', legend });
//   el.append(hist.el);
//   hist.update({ times: [ms, ...], series: [seriesIndex, ...], selection: { lo, hi } | null });
//   hist.setNote('UTC');  // the clock the axis is in, shown in the legend
// With `legend: true` the bucket size, clock and brush hint go to `hist.legendEl` (place it above the
// chart) instead of the top-right corner of the plot, where it covered the newest bars.
//
// Events per bucket over the time span of the data, stacked by series (event family). Bucket size is
// a "nice" step chosen from the pixel width. Brush (drag) to select a time range, click a bar to
// select its bucket, double-click (or Escape) to clear; keyboard: arrows move, Shift+arrows extend,
// Enter selects. Times are shown as the log lines carry them (the device's clock), never re-zoned.
//
// Strict CSP: SVG through createElementNS (dom.svg), text through textContent, positions through
// CSSOM. Series colours come from the .fam-<id> classes (fill) in css/app.css.

import { h, svg, rafBatch } from '../dom.js';

const STEPS_S = [1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400, 172800, 604800];
const MIN_BAR_PX = 6;
const MAX_BUCKETS = 150;
const MIN_SPAN_MS = 60000;
const PAD = { left: 30, right: 8, top: 8, bottom: 17 };
const CLICK_DELAY_MS = 240;

function pad2(n) {
  return String(n).padStart(2, '0');
}

/** "08:31" or "08:31:20" for a ms epoch, read in UTC (the API's and the parser's convention). */
export function clock(ms, seconds = true) {
  const d = new Date(ms);
  const hm = `${pad2(d.getUTCHours())}:${pad2(d.getUTCMinutes())}`;
  return seconds ? `${hm}:${pad2(d.getUTCSeconds())}` : hm;
}

function stepLabel(ms) {
  const s = ms / 1000;
  if (s < 60) return `${s} s`;
  if (s < 3600) return `${s / 60} min`;
  if (s < 86400) return `${s / 3600} h`;
  return `${s / 86400} d`;
}

/** A bucket size (ms) that keeps bars at least MIN_BAR_PX wide over `spanMs`. */
export function chooseStep(spanMs, widthPx) {
  const maxBuckets = Math.max(8, Math.min(MAX_BUCKETS, Math.floor(widthPx / MIN_BAR_PX)));
  for (const s of STEPS_S) if (spanMs / (s * 1000) <= maxBuckets) return s * 1000;
  return STEPS_S[STEPS_S.length - 1] * 1000;
}

function niceMax(v) {
  if (v <= 4) return Math.max(1, v);
  const p = 10 ** Math.floor(Math.log10(v));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
  return 10 * p;
}

function plural(n, word) {
  return `${n.toLocaleString('en-US')} ${n === 1 ? word : `${word}s`}`;
}

export class Histogram {
  constructor({ series = [], label = 'Events over time', onBrush = null, unit = 'line', legend = false } = {}) {
    this.series = series;
    this.note = 'UTC';
    this.legendEl = legend ? h('span', { class: 'hg-legend', 'aria-hidden': 'true' }) : null;
    this.label = label;
    this.unit = unit;
    this.onBrush = typeof onBrush === 'function' ? onBrush : null;
    this.times = [];
    this.ser = [];
    this.sel = null;
    this.geo = null;
    this.drag = null;
    this.kb = null; // keyboard cursor: { i, anchor }
    this.clickTimer = 0;
    this.hoverI = -1;

    this.svg = svg('svg', {
      class: 'hg-svg',
      role: 'img',
      tabindex: '0',
      focusable: 'true',
      'aria-label': label,
      'aria-roledescription': 'histogram',
    });
    this.tip = h('div', { class: 'hg-tip', role: 'tooltip', hidden: true });
    this.empty = h('div', { class: 'hg-empty', hidden: true }, 'No timed lines to chart yet');
    this.el = h('div', { class: 'hg' }, this.svg, this.tip, this.empty);
    this.layers = {
      grid: svg('g', { class: 'hg-grid' }),
      bars: svg('g', { class: 'hg-bars' }),
      axis: svg('g', { class: 'hg-axis' }),
      sel: svg('g', { class: 'hg-selg' }),
      hover: svg('rect', { class: 'hg-hover', x: 0, y: 0, width: 0, height: 0, visibility: 'hidden' }),
      cursor: svg('rect', { class: 'hg-cursor', x: 0, y: 0, width: 0, height: 0, visibility: 'hidden' }),
      brush: svg('rect', { class: 'hg-brush', x: 0, y: 0, width: 0, height: 0, visibility: 'hidden' }),
    };
    this.svg.append(this.layers.grid, this.layers.hover, this.layers.bars, this.layers.sel, this.layers.cursor, this.layers.brush, this.layers.axis);

    this._render = rafBatch(() => this.render());
    // The size comes from the observer: reading clientWidth in render() would force a layout in the
    // same frame the log stream has just written its rows.
    this.size = null;
    this._ro = typeof ResizeObserver === 'function'
      ? new ResizeObserver((entries) => {
        const r = entries[entries.length - 1].contentRect;
        this.size = { w: Math.round(r.width), h: Math.round(r.height) };
        this._render();
      })
      : null;
    if (this._ro) this._ro.observe(this.el);
    this._bind();
  }

  /** times: ms epochs; series: index into `series` for each time; selection: {lo, hi} ms or null. */
  update({ times, series, selection } = {}) {
    if (times) this.times = times;
    if (series) this.ser = series;
    if (selection !== undefined) this.sel = selection;
    this._render();
  }

  /** The clock the times are in ("UTC", "device clock, read as UTC"), named in the legend. */
  setNote(text) {
    const next = String(text || '');
    if (next === this.note) return;
    this.note = next;
    this._render();
  }

  /** The text shown when there is nothing to chart. */
  setEmptyText(text) {
    this.empty.textContent = String(text || 'Nothing to chart');
  }

  setSelection(selection) {
    this.sel = selection || null;
    this._render();
  }

  destroy() {
    clearTimeout(this.clickTimer);
    this._render.cancel();
    if (this._ro) this._ro.disconnect();
    this.el.remove();
  }

  // ---- geometry ---------------------------------------------------------------------------------

  _compute(width, height) {
    const n = this.times.length;
    if (!n || width < 60 || height < 24) return null;
    let t0 = Infinity;
    let t1 = -Infinity;
    for (let i = 0; i < n; i += 1) {
      const t = this.times[i];
      if (t < t0) t0 = t;
      if (t > t1) t1 = t;
    }
    if (!Number.isFinite(t0)) return null;
    // A few stragglers long before the bulk (an old line at the top of a file) would squeeze every
    // bar into a corner: leave them out of the axis and say how many there are.
    let earlier = 0;
    if (n >= 20 && t1 - t0 > MIN_SPAN_MS) {
      const sorted = Float64Array.from(this.times).sort();
      const limit = Math.max(5, Math.floor(n * 0.03));
      let best = -1;
      let gap = 0;
      for (let i = 0; i < Math.min(limit, n - 1); i += 1) {
        const g = sorted[i + 1] - sorted[i];
        if (g > gap) {
          gap = g;
          best = i;
        }
      }
      if (best >= 0 && gap > 0.6 * (t1 - t0)) {
        earlier = best + 1;
        t0 = sorted[best + 1];
      }
    }
    const clipAt = t0;
    if (t1 - t0 < MIN_SPAN_MS) t0 = t1 - MIN_SPAN_MS;
    const plotW = Math.max(10, width - PAD.left - PAD.right);
    const plotH = Math.max(8, height - PAD.top - PAD.bottom);
    const step = chooseStep(t1 - t0, plotW);
    const start = Math.floor(t0 / step) * step;
    const end = (Math.floor(t1 / step) + 1) * step;
    const buckets = Math.max(1, Math.round((end - start) / step));
    const S = Math.max(1, this.series.length);
    const counts = new Uint32Array(buckets * S);
    const totals = new Uint32Array(buckets);
    for (let i = 0; i < n; i += 1) {
      if (earlier && this.times[i] < clipAt) continue;
      const b = Math.min(buckets - 1, Math.max(0, Math.floor((this.times[i] - start) / step)));
      const s = Math.min(S - 1, Math.max(0, this.ser[i] | 0));
      counts[b * S + s] += 1;
      totals[b] += 1;
    }
    let peak = 0;
    let peakAt = 0;
    for (let b = 0; b < buckets; b += 1) {
      if (totals[b] > peak) {
        peak = totals[b];
        peakAt = b;
      }
    }
    return { width, height, plotW, plotH, step, start, end, buckets, S, counts, totals, peak, peakAt, max: niceMax(peak), bw: plotW / buckets, n: n - earlier, earlier };
  }

  _x(t) {
    const g = this.geo;
    return PAD.left + ((t - g.start) / (g.end - g.start)) * g.plotW;
  }

  _t(x) {
    const g = this.geo;
    const f = Math.min(1, Math.max(0, (x - PAD.left) / g.plotW));
    return g.start + f * (g.end - g.start);
  }

  _bucketAt(x) {
    const g = this.geo;
    if (!g) return -1;
    return Math.min(g.buckets - 1, Math.max(0, Math.floor((x - PAD.left) / g.bw)));
  }

  _bucketRange(i, j = i) {
    const g = this.geo;
    const a = Math.min(i, j);
    const b = Math.max(i, j);
    return { lo: g.start + a * g.step, hi: g.start + (b + 1) * g.step - 1 };
  }

  // ---- drawing ----------------------------------------------------------------------------------

  render() {
    const width = this.size ? this.size.w : Math.round(this.el.clientWidth);
    const height = this.size ? this.size.h : Math.round(this.el.clientHeight);
    this.geo = this._compute(width, height);
    const L = this.layers;
    this.svg.setAttribute('width', String(Math.max(0, width)));
    this.svg.setAttribute('height', String(Math.max(0, height)));
    this.svg.setAttribute('viewBox', `0 0 ${Math.max(1, width)} ${Math.max(1, height)}`);
    L.grid.replaceChildren();
    L.bars.replaceChildren();
    L.axis.replaceChildren();
    L.sel.replaceChildren();
    this.empty.hidden = Boolean(this.geo) || width < 60;
    if (this.legendEl && !this.geo) this.legendEl.textContent = '';
    if (!this.geo) {
      this.svg.setAttribute('aria-label', `${this.label}: nothing to chart yet.`);
      this._hideHover();
      return;
    }
    const g = this.geo;
    const base = PAD.top + g.plotH;
    // grid: baseline, mid and top lines with the scale
    L.grid.append(
      svg('line', { class: 'hg-gl hg-base', x1: PAD.left, x2: PAD.left + g.plotW, y1: base + 0.5, y2: base + 0.5 }),
      svg('line', { class: 'hg-gl', x1: PAD.left, x2: PAD.left + g.plotW, y1: PAD.top + 0.5, y2: PAD.top + 0.5 }),
      svg('line', { class: 'hg-gl', x1: PAD.left, x2: PAD.left + g.plotW, y1: Math.round(PAD.top + g.plotH / 2) + 0.5, y2: Math.round(PAD.top + g.plotH / 2) + 0.5 }),
    );
    L.axis.append(
      svg('text', { class: 'hg-y', x: PAD.left - 5, y: PAD.top + 4, 'text-anchor': 'end' }, String(g.max)),
      svg('text', { class: 'hg-y', x: PAD.left - 5, y: base + 1, 'text-anchor': 'end' }, '0'),
    );
    // bars, stacked bottom-up in series order
    const gap = g.bw >= 5 ? 1 : 0;
    const scale = g.plotH / g.max;
    for (let b = 0; b < g.buckets; b += 1) {
      if (!g.totals[b]) continue;
      const x = PAD.left + b * g.bw + gap / 2;
      const w = Math.max(1, g.bw - gap);
      let y = base;
      let top = -1;
      for (let s = 0; s < g.S; s += 1) if (g.counts[b * g.S + s]) top = s;
      for (let s = 0; s < g.S; s += 1) {
        const c = g.counts[b * g.S + s];
        if (!c) continue;
        const hgt = Math.max(1, c * scale);
        y -= hgt;
        // A 1 px gap above each segment but the top one separates hues that differ in hue only.
        const sepPx = s !== top && hgt >= 3 ? 1 : 0;
        const id = (this.series[s] && this.series[s].id) || 'other';
        L.bars.append(svg('rect', { class: `hg-bar fam-${id}`, x: x.toFixed(2), y: (y + sepPx).toFixed(2), width: w.toFixed(2), height: (hgt - sepPx).toFixed(2) }));
      }
    }
    // x ticks: a multiple of the step, at least ~78 px apart
    const minGap = 78;
    const stepsPerTick = Math.max(1, Math.ceil(minGap / g.bw));
    const tickMs = this._niceTick(stepsPerTick * g.step);
    const seconds = tickMs < 60000;
    for (let t = Math.ceil(g.start / tickMs) * tickMs; t <= g.end; t += tickMs) {
      const x = this._x(t);
      if (x < PAD.left + 14 || x > PAD.left + g.plotW - 14) continue;
      L.axis.append(
        svg('line', { class: 'hg-tick', x1: Math.round(x) + 0.5, x2: Math.round(x) + 0.5, y1: base, y2: base + 3 }),
        svg('text', { class: 'hg-x', x: Math.round(x), y: height - 4, 'text-anchor': 'middle' }, clock(t, seconds)),
      );
    }
    if (g.earlier) {
      L.axis.append(svg('text', { class: 'hg-earlier', x: PAD.left + 4, y: PAD.top + 4, 'text-anchor': 'start' }, `\u25c2 ${plural(g.earlier, this.unit)} earlier, not drawn`));
    }
    const hint = this.onBrush && !this.sel && g.plotW > (this.legendEl ? 360 : 420) ? ' \u00b7 drag to pick a time range' : '';
    if (this.legendEl) this.legendEl.textContent = `per ${stepLabel(g.step)} \u00b7 ${this.note}${hint}`;
    else L.axis.append(svg('text', { class: 'hg-step', x: PAD.left + g.plotW, y: PAD.top + 4, 'text-anchor': 'end' }, `per ${stepLabel(g.step)}${hint}`));
    // selection
    if (this.sel && Number.isFinite(this.sel.lo) && Number.isFinite(this.sel.hi)) {
      const x0 = Math.max(PAD.left, Math.min(PAD.left + g.plotW, this._x(this.sel.lo)));
      const x1 = Math.max(PAD.left, Math.min(PAD.left + g.plotW, this._x(this.sel.hi)));
      const top = PAD.top - 3;
      const hh = g.plotH + 3;
      if (x0 > PAD.left) L.sel.append(svg('rect', { class: 'hg-dim', x: PAD.left, y: top, width: (x0 - PAD.left).toFixed(2), height: hh }));
      if (x1 < PAD.left + g.plotW) L.sel.append(svg('rect', { class: 'hg-dim', x: x1.toFixed(2), y: top, width: (PAD.left + g.plotW - x1).toFixed(2), height: hh }));
      L.sel.append(svg('rect', { class: 'hg-sel', x: x0.toFixed(2), y: top + 0.5, width: Math.max(2, x1 - x0).toFixed(2), height: hh - 1, rx: 2 }));
    }
    const sum = `${plural(g.n, this.unit)}${g.earlier ? ` (and ${g.earlier} earlier, not drawn)` : ''} from ${clock(g.start, seconds)} to ${clock(g.end, seconds)} (${this.note}), ${plural(g.buckets, 'bar')} of ${stepLabel(g.step)}; busiest ${clock(g.start + g.peakAt * g.step)}: ${plural(g.peak, this.unit)}.`;
    const how = this.onBrush ? ' Drag, or use the arrow keys and Enter, to select a time range; Escape clears it.' : '';
    const selText = this.sel ? ` Selected ${clock(this.sel.lo)} to ${clock(this.sel.hi)}.` : '';
    this.svg.setAttribute('aria-label', `${this.label}: ${sum}${selText}${how}`);
    if (this.kb) this._drawCursor();
    if (this.hoverI >= 0 && this.hoverI < g.buckets) this._drawHover(this.hoverI);
  }

  _niceTick(ms) {
    for (const s of STEPS_S) if (s * 1000 >= ms) return s * 1000;
    return ms;
  }

  _drawHover(i) {
    const g = this.geo;
    const r = this.layers.hover;
    r.setAttribute('x', (PAD.left + i * g.bw).toFixed(2));
    r.setAttribute('y', String(PAD.top - 3));
    r.setAttribute('width', Math.max(1, g.bw).toFixed(2));
    r.setAttribute('height', String(g.plotH + 3));
    r.setAttribute('visibility', 'visible');
  }

  _drawCursor() {
    const g = this.geo;
    const r = this.layers.cursor;
    if (!g || !this.kb) {
      r.setAttribute('visibility', 'hidden');
      return;
    }
    const a = Math.min(this.kb.i, this.kb.anchor);
    const b = Math.max(this.kb.i, this.kb.anchor);
    r.setAttribute('x', (PAD.left + a * g.bw).toFixed(2));
    r.setAttribute('y', String(PAD.top - 3));
    r.setAttribute('width', Math.max(2, (b - a + 1) * g.bw).toFixed(2));
    r.setAttribute('height', String(g.plotH + 3));
    r.setAttribute('visibility', 'visible');
  }

  _hideHover() {
    this.hoverI = -1;
    this.layers.hover.setAttribute('visibility', 'hidden');
    this.tip.hidden = true;
  }

  _showTip(i, clientX) {
    const g = this.geo;
    if (!g || i < 0) return;
    const lo = g.start + i * g.step;
    const seconds = g.step < 60000;
    const rows = [];
    for (let s = g.S - 1; s >= 0; s -= 1) {
      const c = g.counts[i * g.S + s];
      if (!c) continue;
      const ser = this.series[s] || { id: 'other', label: 'Other' };
      rows.push(h('li', null, h('span', { class: `hg-sw fam-${ser.id}`, 'aria-hidden': 'true' }), h('span', { class: 'hg-tl' }, ser.label), h('b', null, c.toLocaleString('en-US'))));
    }
    this.tip.replaceChildren(
      h('div', { class: 'hg-th' }, `${clock(lo, true)} – ${clock(lo + g.step - 1, seconds || g.step < 3600000)} ${this.note === 'UTC' ? 'UTC' : 'device clock'}`, h('b', null, plural(g.totals[i], this.unit))),
      rows.length ? h('ul', null, rows) : h('p', { class: 'hg-tn' }, 'Nothing in this interval'),
    );
    this.tip.hidden = false;
    const box = this.el.getBoundingClientRect();
    const tw = this.tip.offsetWidth || 180;
    let left = clientX - box.left + 12;
    if (left + tw > box.width - 4) left = clientX - box.left - tw - 12;
    this.tip.style.left = `${Math.max(4, Math.round(left))}px`;
  }

  // ---- interaction ------------------------------------------------------------------------------

  _localX(e) {
    const box = this.svg.getBoundingClientRect();
    return e.clientX - box.left;
  }

  _emit(range) {
    if (!this.onBrush) return;
    try {
      this.onBrush(range);
    } catch (err) {
      console.error(err);
    }
  }

  _bind() {
    const s = this.svg;
    s.addEventListener('pointerdown', (e) => {
      if (e.button !== 0 || !this.geo || !this.onBrush) return;
      const x = this._localX(e);
      if (x < PAD.left - 4 || x > PAD.left + this.geo.plotW + 4) return;
      e.preventDefault();
      s.focus({ preventScroll: true });
      try {
        s.setPointerCapture(e.pointerId);
      } catch (_err) {
        // capture is a nicety
      }
      this.drag = { x0: x, x1: x, id: e.pointerId };
    });
    s.addEventListener('pointermove', (e) => {
      if (!this.geo) return;
      const x = this._localX(e);
      if (this.drag) {
        this.drag.x1 = x;
        const a = Math.max(PAD.left, Math.min(this.drag.x0, x));
        const b = Math.min(PAD.left + this.geo.plotW, Math.max(this.drag.x0, x));
        const r = this.layers.brush;
        r.setAttribute('x', a.toFixed(2));
        r.setAttribute('y', String(PAD.top - 3));
        r.setAttribute('width', Math.max(0, b - a).toFixed(2));
        r.setAttribute('height', String(this.geo.plotH + 3));
        r.setAttribute('visibility', Math.abs(this.drag.x1 - this.drag.x0) >= 3 ? 'visible' : 'hidden');
        this.tip.hidden = true;
        return;
      }
      if (x < PAD.left || x > PAD.left + this.geo.plotW) {
        this._hideHover();
        return;
      }
      const i = this._bucketAt(x);
      this.hoverI = i;
      this._drawHover(i);
      this._showTip(i, e.clientX);
    });
    s.addEventListener('pointerleave', () => {
      if (!this.drag) this._hideHover();
    });
    const finish = (e, cancelled) => {
      const d = this.drag;
      if (!d) return;
      this.drag = null;
      this.layers.brush.setAttribute('visibility', 'hidden');
      try {
        s.releasePointerCapture(e.pointerId);
      } catch (_err) {
        // already released
      }
      if (cancelled || !this.geo) return;
      if (Math.abs(d.x1 - d.x0) >= 4) {
        const a = this._bucketAt(Math.min(d.x0, d.x1));
        const b = this._bucketAt(Math.max(d.x0, d.x1));
        clearTimeout(this.clickTimer);
        this._emit(this._bucketRange(a, b));
        return;
      }
      // A click selects that bar's interval, unless a double-click (clear) follows.
      const i = this._bucketAt(d.x0);
      clearTimeout(this.clickTimer);
      this.clickTimer = setTimeout(() => {
        if (this.geo && i >= 0 && this.geo.totals[i]) this._emit(this._bucketRange(i));
      }, CLICK_DELAY_MS);
    };
    s.addEventListener('pointerup', (e) => finish(e, false));
    s.addEventListener('pointercancel', (e) => finish(e, true));
    s.addEventListener('dblclick', (e) => {
      e.preventDefault();
      clearTimeout(this.clickTimer);
      this._emit(null);
    });
    s.addEventListener('keydown', (e) => this._onKey(e));
    s.addEventListener('blur', () => {
      this.kb = null;
      this._drawCursor();
    });
  }

  _onKey(e) {
    const g = this.geo;
    if (!g || !this.onBrush) return;
    const key = e.key;
    if (key === 'Escape' || key === 'Delete' || key === 'Backspace') {
      if (this.sel || this.kb) {
        e.preventDefault();
        e.stopPropagation();
        this.kb = null;
        this._drawCursor();
        if (this.sel) this._emit(null);
      }
      return;
    }
    if (key === 'ArrowLeft' || key === 'ArrowRight' || key === 'Home' || key === 'End') {
      e.preventDefault();
      if (!this.kb) {
        const start = this.sel ? this._bucketAt(this._x(this.sel.lo) + 0.5) : g.buckets - 1;
        this.kb = { i: start, anchor: start };
      } else {
        let i = this.kb.i;
        if (key === 'ArrowLeft') i -= 1;
        else if (key === 'ArrowRight') i += 1;
        else if (key === 'Home') i = 0;
        else i = g.buckets - 1;
        i = Math.max(0, Math.min(g.buckets - 1, i));
        this.kb = { i, anchor: e.shiftKey ? this.kb.anchor : i };
      }
      this._drawCursor();
      const r = this.layers.cursor.getBoundingClientRect();
      this._showTip(this.kb.i, r.left + r.width / 2);
      return;
    }
    if (key === 'Enter' && this.kb) {
      e.preventDefault();
      this._emit(this._bucketRange(this.kb.anchor, this.kb.i));
    }
  }
}

export default Histogram;
