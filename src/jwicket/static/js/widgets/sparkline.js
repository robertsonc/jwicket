// widgets/sparkline.js: a small SVG trend line that stays calm.
//
//   const s = new Sparkline({ height: 36, label: 'Active sessions per poll', min: 0 });
//   parent.append(s.el); s.update([3, 5, 4, 8]);
//   sparkline(values, opts) -> <svg> for one-off use.
//
// Scale rules, so noise never looks like an incident:
// * The vertical span is at least 20 % of the largest value (and at least 1), centred on the data:
//   133 -> 138 sessions is a gentle slope, not a crash.
// * A series that never goes below zero is never drawn below the baseline, so a flat 0 lies on the
//   floor and a flat 151 sits higher up: they no longer look the same.
// * `min: 0` (or any fixed min/max) pins that end of the axis, e.g. a zero-based count.
// * Until three points exist the area is not filled and a faint "collecting" note shows.
//
// The outer <svg> is in pixels (so the note is never stretched); the line lives in an inner <svg>
// that stretches to the width (preserveAspectRatio none, non-scaling strokes), so the newest-value
// dot stays round.

import { svg } from '../dom.js';

const W = 200;
const PAD = 3;
const MIN_POINTS = 3;

/** The [lo, hi] the series is drawn against (exported for tests and for callers that label axes). */
export function scaleFor(values, { min = null, max = null } = {}) {
  const pts = (values || []).map(Number).filter((v) => Number.isFinite(v));
  if (!pts.length) return null;
  const dataLo = Math.min(...pts);
  const dataHi = Math.max(...pts);
  const span = Math.max(dataHi - dataLo, 0.2 * Math.max(Math.abs(dataHi), Math.abs(dataLo)), 1);
  let lo;
  let hi;
  if (min !== null && max !== null) {
    lo = min;
    hi = max > min ? max : min + span;
  } else if (min !== null) {
    lo = min;
    hi = Math.max(dataHi, min + span);
  } else if (max !== null) {
    hi = max;
    lo = Math.min(dataLo, max - span);
  } else {
    const mid = (dataLo + dataHi) / 2;
    lo = mid - span / 2;
    hi = mid + span / 2;
    if (dataLo >= 0 && lo < 0) {
      // Counts: never below the floor; a flat zero lies on the baseline.
      hi -= lo;
      lo = 0;
    }
  }
  return [lo, hi];
}

// Where the note's middle sits, in percent of the drawn height: chosen so its text box (about 14 px)
// stays inside both the default 34 px chart and the 28 px one at phone width.
const NOTE_LOW = '78%';
const NOTE_HIGH = '29%';

export class Sparkline {
  constructor({ height = 36, label = '', className = '', area = true, min = null, max = null } = {}) {
    this.height = height;
    this.area = area;
    this.fixedMin = min;
    this.fixedMax = max;
    this.label = label;
    this.areaPath = svg('path', { class: 'spark-area', 'vector-effect': 'non-scaling-stroke' });
    this.linePath = svg('path', { class: 'spark-line', 'vector-effect': 'non-scaling-stroke' });
    this.base = svg('line', { class: 'spark-base', x1: 0, x2: W, y1: height - 0.5, y2: height - 0.5, 'vector-effect': 'non-scaling-stroke' });
    this.dot = svg('path', { class: 'spark-dot', 'vector-effect': 'non-scaling-stroke' });
    // Bottom left: a zero-based line sits high, a centred one in the middle; neither meets the note.
    // y in percent of the drawn height: CSS can draw the chart shorter than `height` (28 px at phone
    // width), and a pixel y would then put the note below the chart.
    this.note = svg('text', { class: 'spark-note', x: 0, y: NOTE_LOW, 'dominant-baseline': 'middle' });
    this.plot = svg(
      'svg',
      { class: 'spark-plot', viewBox: `0 0 ${W} ${height}`, preserveAspectRatio: 'none', x: 0, y: 0, width: '100%', height: '100%' },
      this.base,
      area ? this.areaPath : null,
      this.linePath,
      this.dot,
    );
    this.el = svg(
      'svg',
      { class: ['spark', className], width: '100%', height, role: 'img', 'aria-label': label || 'trend' },
      this.plot,
      this.note,
    );
  }

  update(values, { min = this.fixedMin, max = this.fixedMax } = {}) {
    const pts = (values || []).map(Number).filter((v) => Number.isFinite(v));
    const collecting = pts.length < MIN_POINTS;
    this.el.classList.toggle('collecting', collecting);
    this.note.textContent = collecting ? (pts.length ? 'collecting…' : 'no data yet') : '';
    if (!pts.length) {
      this.note.setAttribute('y', NOTE_LOW);
      this.linePath.setAttribute('d', '');
      this.areaPath.setAttribute('d', '');
      this.dot.setAttribute('d', '');
      this.el.setAttribute('aria-label', `${this.label || 'trend'}: no data yet`);
      return;
    }
    const [lo, hi] = scaleFor(pts, { min, max });
    const h = this.height;
    const n = pts.length;
    const x = (i) => (n === 1 ? W : (i / (n - 1)) * W);
    const y = (v) => {
      const f = Math.max(0, Math.min(1, (v - lo) / (hi - lo)));
      return PAD + (1 - f) * (h - PAD * 2);
    };
    let d = '';
    for (let i = 0; i < n; i += 1) d += `${i ? 'L' : 'M'}${x(i).toFixed(2)} ${y(pts[i]).toFixed(2)}`;
    if (n === 1) d = `M0 ${y(pts[0]).toFixed(2)}L${W} ${y(pts[0]).toFixed(2)}`;
    this.linePath.setAttribute('d', d);
    if (this.area) this.areaPath.setAttribute('d', collecting ? '' : `${d}L${W} ${h}L${x(0)} ${h}Z`);
    const last = pts[n - 1];
    this.dot.setAttribute('d', `M${W} ${y(last).toFixed(2)}h0`);
    // F6: the "collecting" note goes on the side the line is not on, so the line never strikes it out.
    this.note.setAttribute('y', collecting && y(last) > h / 2 ? NOTE_HIGH : NOTE_LOW);
    this.el.setAttribute(
      'aria-label',
      `${this.label || 'trend'}: ${n} ${n === 1 ? 'point' : 'points'}, lowest ${Math.min(...pts)}, highest ${Math.max(...pts)}, latest ${last}${collecting ? ' (still collecting)' : ''}`,
    );
  }
}

export function sparkline(values, opts = {}) {
  const s = new Sparkline(opts);
  s.update(values, opts);
  return s.el;
}
