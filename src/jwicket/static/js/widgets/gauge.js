// widgets/gauge.js: a 270-degree ring gauge (open at the bottom), like an instrument dial.
//
//   const g = new Gauge({ size: 72, label: 'Active sessions of maximum' });
//   parent.append(g.el); g.update(165, 524288, { text: '165', sub: 'of 524k' });
//
// Level classes on the svg: ok (< 70 %), warn (>= 70 %), crit (>= 90 %), idle (no data). The only
// tick marks are at 70 % and 90 %, where the colour changes; a ring under 96 px gets the class `sm`
// (smaller centre text).

import { svg } from '../dom.js';

const SWEEP = 0.75;
const START = 135; // degrees, measured clockwise from 3 o'clock
export const WARN_AT = 0.7;
export const CRIT_AT = 0.9;

export class Gauge {
  constructor({ size = 120, stroke = 9, label = 'gauge' } = {}) {
    const c = size / 2;
    const r = (size - stroke) / 2 - 3;
    this.circ = 2 * Math.PI * r;
    this.label = label;
    const rot = `rotate(${START} ${c} ${c})`;
    this.arc = svg('circle', {
      class: 'gauge-arc', cx: c, cy: c, r, 'stroke-width': stroke, 'stroke-linecap': 'round',
      'stroke-dasharray': `0 ${this.circ}`, transform: rot,
    });
    this.value = svg('text', { class: 'gauge-value', x: c, y: c - size * 0.03, 'text-anchor': 'middle', 'dominant-baseline': 'central' });
    this.sub = svg('text', { class: 'gauge-sub', x: c, y: c + size * 0.17, 'text-anchor': 'middle', 'dominant-baseline': 'central' });
    // Notches just inside the ring at the thresholds, so they read as marks on the scale.
    const ticks = [WARN_AT, CRIT_AT].map((f) => {
      const a = ((START + f * 360 * SWEEP) * Math.PI) / 180;
      const r2 = r - stroke / 2 - 1.5;
      const r1 = r2 - 5;
      return svg('line', {
        class: 'gauge-tick',
        x1: (c + r1 * Math.cos(a)).toFixed(2), y1: (c + r1 * Math.sin(a)).toFixed(2),
        x2: (c + r2 * Math.cos(a)).toFixed(2), y2: (c + r2 * Math.sin(a)).toFixed(2),
      }, svg('title', null, `${Math.round(f * 100)} %`));
    });
    this.el = svg(
      'svg',
      { class: ['gauge', 'idle', size < 96 && 'sm'], viewBox: `0 0 ${size} ${size}`, width: size, height: size, role: 'img', 'aria-label': label },
      svg('circle', {
        class: 'gauge-track', cx: c, cy: c, r, 'stroke-width': stroke, 'stroke-linecap': 'round',
        'stroke-dasharray': `${(this.circ * SWEEP).toFixed(2)} ${this.circ.toFixed(2)}`, transform: rot,
      }),
      ticks,
      this.arc,
      this.value,
      this.sub,
    );
  }

  update(value, max, { text, sub } = {}) {
    const v = Number(value);
    const m = Number(max);
    const known = value !== null && value !== undefined && Number.isFinite(v) && Number.isFinite(m) && m > 0;
    const frac = known ? Math.max(0, Math.min(1, v / m)) : 0;
    // A non-zero value always shows a visible sliver, so "almost empty" never reads as "no data".
    const len = known && v > 0 ? Math.max(this.circ * SWEEP * frac, 2.5) : 0;
    this.arc.setAttribute('stroke-dasharray', `${len.toFixed(2)} ${this.circ.toFixed(2)}`);
    this.el.classList.remove('ok', 'warn', 'crit', 'idle');
    this.el.classList.add(!known ? 'idle' : frac >= CRIT_AT ? 'crit' : frac >= WARN_AT ? 'warn' : 'ok');
    this.value.textContent = text !== undefined ? String(text) : known ? `${Math.round(frac * 100)}%` : '—';
    this.sub.textContent = sub !== undefined ? String(sub) : '';
    this.el.setAttribute('aria-label', known ? `${this.label}: ${v} of ${m} (${(frac * 100).toFixed(1)}%)` : `${this.label}: not known`);
  }
}

export function gauge(value, max, opts = {}) {
  const g = new Gauge(opts);
  g.update(value, max, opts);
  return g.el;
}
