// widgets/sparkline.js: a small SVG trend line. Stretches to its container's width
// (preserveAspectRatio none, non-scaling strokes), so the dot at the newest value stays round.
//
//   const s = new Sparkline({ height: 36, label: 'Active sessions per poll' });
//   parent.append(s.el); s.update([3, 5, 4, 8]);
//   sparkline(values, opts) -> <svg> for one-off use.

import { svg } from '../dom.js';

const W = 200;

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
    this.el = svg(
      'svg',
      {
        class: ['spark', className],
        viewBox: `0 0 ${W} ${height}`,
        preserveAspectRatio: 'none',
        height,
        role: 'img',
        'aria-label': label || 'trend',
      },
      this.base,
      area ? this.areaPath : null,
      this.linePath,
      this.dot,
    );
  }

  update(values, { min = this.fixedMin, max = this.fixedMax } = {}) {
    const pts = (values || []).map(Number).filter((v) => Number.isFinite(v));
    if (!pts.length) {
      this.linePath.setAttribute('d', '');
      this.areaPath.setAttribute('d', '');
      this.dot.setAttribute('d', '');
      this.el.setAttribute('aria-label', `${this.label || 'trend'}: no data yet`);
      return;
    }
    let lo = min === null ? Math.min(...pts) : min;
    let hi = max === null ? Math.max(...pts) : max;
    if (hi === lo) {
      // A flat series sits in the middle, not on the floor.
      lo -= 1;
      hi += 1;
    }
    const pad = 3;
    const h = this.height;
    const n = pts.length;
    const x = (i) => (n === 1 ? W : (i / (n - 1)) * W);
    const y = (v) => pad + (1 - (v - lo) / (hi - lo)) * (h - pad * 2);
    let d = '';
    for (let i = 0; i < n; i += 1) d += `${i ? 'L' : 'M'}${x(i).toFixed(2)} ${y(pts[i]).toFixed(2)}`;
    if (n === 1) d = `M0 ${y(pts[0]).toFixed(2)}L${W} ${y(pts[0]).toFixed(2)}`;
    this.linePath.setAttribute('d', d);
    if (this.area) this.areaPath.setAttribute('d', `${d}L${W} ${h}L${n === 1 ? 0 : x(0)} ${h}Z`);
    const last = pts[n - 1];
    this.dot.setAttribute('d', `M${W} ${y(last).toFixed(2)}h0`);
    this.el.setAttribute(
      'aria-label',
      `${this.label || 'trend'}: ${n} points, lowest ${Math.min(...pts)}, highest ${Math.max(...pts)}, latest ${last}`,
    );
  }
}

export function sparkline(values, opts = {}) {
  const s = new Sparkline(opts);
  s.update(values, opts);
  return s.el;
}
