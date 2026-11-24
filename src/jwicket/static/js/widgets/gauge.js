// widgets/gauge.js: a 270-degree ring gauge (open at the bottom), like an instrument dial.
//
//   const g = new Gauge({ size: 120, label: 'Active sessions of maximum' });
//   parent.append(g.el); g.update(165, 524288, { text: '165', sub: 'of 524k' });
//
// Level classes on the svg: ok (< 70 %), warn (>= 70 %), crit (>= 90 %), idle (no data).

import { svg } from '../dom.js';

const SWEEP = 0.75;

export class Gauge {
  constructor({ size = 120, stroke = 9, label = 'gauge' } = {}) {
    const c = size / 2;
    const r = (size - stroke) / 2 - 3;
    this.circ = 2 * Math.PI * r;
    this.label = label;
    const rot = `rotate(135 ${c} ${c})`;
    this.arc = svg('circle', {
      class: 'gauge-arc', cx: c, cy: c, r, 'stroke-width': stroke, 'stroke-linecap': 'round',
      'stroke-dasharray': `0 ${this.circ}`, transform: rot,
    });
    this.value = svg('text', { class: 'gauge-value', x: c, y: c - 2, 'text-anchor': 'middle', 'dominant-baseline': 'central' });
    this.sub = svg('text', { class: 'gauge-sub', x: c, y: c + 17, 'text-anchor': 'middle', 'dominant-baseline': 'central' });
    const ticks = [];
    for (let i = 0; i <= 4; i += 1) {
      const a = ((135 + i * (270 / 4)) * Math.PI) / 180;
      const r1 = r + stroke / 2 + 2;
      const r2 = r1 + 3;
      ticks.push(svg('line', {
        class: 'gauge-tick',
        x1: (c + r1 * Math.cos(a)).toFixed(2), y1: (c + r1 * Math.sin(a)).toFixed(2),
        x2: (c + r2 * Math.cos(a)).toFixed(2), y2: (c + r2 * Math.sin(a)).toFixed(2),
      }));
    }
    this.el = svg(
      'svg',
      { class: 'gauge idle', viewBox: `0 0 ${size} ${size}`, width: size, height: size, role: 'img', 'aria-label': label },
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
    const known = Number.isFinite(v) && Number.isFinite(m) && m > 0;
    const frac = known ? Math.max(0, Math.min(1, v / m)) : 0;
    // A non-zero value always shows a visible sliver, so "almost empty" never reads as "no data".
    const len = known && v > 0 ? Math.max(this.circ * SWEEP * frac, 2.5) : 0;
    this.arc.setAttribute('stroke-dasharray', `${len.toFixed(2)} ${this.circ.toFixed(2)}`);
    this.el.classList.remove('ok', 'warn', 'crit', 'idle');
    this.el.classList.add(!known ? 'idle' : frac >= 0.9 ? 'crit' : frac >= 0.7 ? 'warn' : 'ok');
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
