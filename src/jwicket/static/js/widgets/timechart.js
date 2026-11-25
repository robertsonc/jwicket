// widgets/timechart.js: a small multi-series time chart for percentages (Overview health).
//
//   const c = new TimeChart({ title: 'CPU', series: [{ id: 're', label: 'Routing engine' }, ...] });
//   parent.append(c.el); c.update([{ t: Date.now(), v: { re: 28, spu: 4 } }, ...]);
//
// One y-axis, fixed 0 to 100 %, so 3 % never looks like an incident. Lines are 2 px with a 10 %
// wash under each; series colours are the scheme's --series-1, --series-2 (marks only: every label
// and value is in text colours, identity comes from the line key beside it). A legend is always
// shown (two series or more) with each series' latest value; the newest point carries a dot.
// Hover or focus the plot for a crosshair that snaps to the nearest sample and lists every series;
// arrow keys move it, Escape hides it. "Table" shows the same samples as a table.
//
// The line SVG stretches to the width (preserveAspectRatio none, non-scaling strokes); every text
// and dot is HTML positioned through CSS custom properties, so nothing is distorted and no inline
// style is needed (strict CSP).

import { h, svg, put } from '../dom.js';

const VW = 1000;
const VH = 100;
const TICKS = [0, 25, 50, 75, 100];
const DASH = '—';

function fmtPct(v) {
  return Number.isFinite(v) ? `${Math.round(v)}%` : DASH;
}

function clock(t) {
  const d = new Date(t);
  const p = (n) => String(n).padStart(2, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

export class TimeChart {
  constructor({ title, series, windowMs = 10 * 60 * 1000, height = 132, describe = '' }) {
    this.title = title;
    this.series = series.map((s, i) => ({ ...s, cls: `tc-s${i + 1}` }));
    this.windowMs = windowMs;
    this.samples = [];
    this.hover = -1;
    this.tableOpen = false;

    this.values = {};
    const legend = h('ul', { class: 'tc-legend', 'aria-label': `${title}: latest values` },
      this.series.map((s) => {
        this.values[s.id] = h('strong', { class: 'tc-legend-val num' }, DASH);
        return h('li', null, h('span', { class: ['tc-key', s.cls], 'aria-hidden': 'true' }), h('span', { class: 'tc-legend-label' }, s.label), this.values[s.id]);
      }));
    this.tableBtn = h('button', { class: 'btn ghost sm tc-table-btn', type: 'button', 'aria-pressed': 'false', on: { click: () => this.toggleTable() } }, 'Table');

    this.grid = svg('g', { class: 'tc-grid' }, TICKS.map((v) => svg('line', { x1: 0, x2: VW, y1: VH - v, y2: VH - v, 'vector-effect': 'non-scaling-stroke' })));
    this.marks = svg('g', null);
    this.plotSvg = svg('svg', { class: 'tc-svg', viewBox: `0 0 ${VW} ${VH}`, preserveAspectRatio: 'none', 'aria-hidden': 'true', focusable: 'false' }, this.grid, this.marks);
    this.dots = h('div', { class: 'tc-dots', 'aria-hidden': 'true' });
    this.cross = h('div', { class: 'tc-cross', hidden: true, 'aria-hidden': 'true' });
    this.tip = h('div', { class: 'tc-tip', hidden: true, role: 'status', 'aria-live': 'off' });
    this.empty = h('div', { class: 'tc-empty' }, 'Collecting…');
    const yAxis = h('div', { class: 'tc-y', 'aria-hidden': 'true' }, TICKS.map((v) => {
      const lab = h('span', null, `${v}%`);
      lab.style.setProperty('--y', String(v / 100));
      return lab;
    }));
    this.plot = h('div', {
      class: 'tc-plot',
      tabindex: '0',
      role: 'group',
      'aria-label': `${title} over the last ${Math.round(windowMs / 60000)} minutes${describe ? `: ${describe}` : ''}. Use the arrow keys to read values, or open the table.`,
      on: {
        pointermove: (e) => this.onPointer(e),
        pointerleave: () => this.setHover(-1),
        focus: () => this.setHover(this.samples.length - 1),
        blur: () => this.setHover(-1),
        keydown: (e) => this.onKey(e),
      },
    }, this.plotSvg, this.dots, this.cross, this.tip, this.empty);
    this.xStart = h('span', null, `${Math.round(windowMs / 60000)} min ago`);
    this.xEnd = h('span', null, 'now');
    const xAxis = h('div', { class: 'tc-x', 'aria-hidden': 'true' }, this.xStart, this.xEnd);
    this.table = h('div', { class: 'tc-table', hidden: true });

    // The axis labels and the plot are siblings in the frame: both read --tc-h, so it goes on the
    // frame. On the plot alone, the labels fell back to the 132 px default and sat too high.
    const frame = h('div', { class: 'tc-frame' }, yAxis, this.plot);
    frame.style.setProperty('--tc-h', `${height}px`);
    this.el = h('figure', { class: 'tc' },
      h('figcaption', { class: 'tc-head' }, h('span', { class: 'tc-title' }, title), legend, this.tableBtn),
      frame,
      xAxis,
      this.table);
  }

  /** samples: [{ t: ms, v: { [seriesId]: number|null } }], oldest first. */
  update(samples) {
    this.samples = samples.slice();
    const last = this.samples[this.samples.length - 1];
    for (const s of this.series) this.values[s.id].textContent = fmtPct(last ? last.v[s.id] : null);
    this.draw();
    if (this.hover >= 0) this.setHover(Math.min(this.hover, this.samples.length - 1));
    if (this.tableOpen) this.drawTable();
  }

  xOf(t) {
    const end = this.samples.length ? this.samples[this.samples.length - 1].t : Date.now();
    return Math.min(1, Math.max(0, 1 - (end - t) / this.windowMs));
  }

  draw() {
    const marks = [];
    const dots = [];
    this.empty.hidden = this.samples.length >= 2;
    for (const s of this.series) {
      // Runs of consecutive known values; a missing reading breaks the line rather than inventing one.
      const runs = [];
      let run = [];
      for (const p of this.samples) {
        const v = p.v[s.id];
        if (Number.isFinite(v)) run.push([this.xOf(p.t) * VW, VH - Math.min(100, Math.max(0, v))]);
        else if (run.length) { runs.push(run); run = []; }
      }
      if (run.length) runs.push(run);
      for (const r of runs) {
        if (r.length < 2) continue;
        const d = r.map(([x, y], i) => `${i ? 'L' : 'M'}${x.toFixed(1)} ${y.toFixed(2)}`).join('');
        marks.push(svg('path', { class: ['tc-area', s.cls], d: `${d}L${r[r.length - 1][0].toFixed(1)} ${VH}L${r[0][0].toFixed(1)} ${VH}Z` }));
        marks.push(svg('path', { class: ['tc-line', s.cls], d, 'vector-effect': 'non-scaling-stroke' }));
      }
      const last = this.samples[this.samples.length - 1];
      if (last && Number.isFinite(last.v[s.id])) {
        const dot = h('span', { class: ['tc-dot', s.cls] });
        dot.style.setProperty('--x', String(this.xOf(last.t)));
        dot.style.setProperty('--y', String(Math.min(100, Math.max(0, last.v[s.id])) / 100));
        dots.push(dot);
      }
    }
    put(this.marks, marks);
    put(this.dots, dots);
  }

  onPointer(e) {
    if (!this.samples.length) return;
    const box = this.plot.getBoundingClientRect();
    const frac = (e.clientX - box.left) / Math.max(1, box.width);
    let best = 0;
    let bestD = Infinity;
    this.samples.forEach((p, i) => {
      const d = Math.abs(this.xOf(p.t) - frac);
      if (d < bestD) { bestD = d; best = i; }
    });
    this.setHover(best);
  }

  onKey(e) {
    if (!this.samples.length) return;
    let i = this.hover < 0 ? this.samples.length - 1 : this.hover;
    if (e.key === 'ArrowLeft') i = Math.max(0, i - 1);
    else if (e.key === 'ArrowRight') i = Math.min(this.samples.length - 1, i + 1);
    else if (e.key === 'Home') i = 0;
    else if (e.key === 'End') i = this.samples.length - 1;
    else if (e.key === 'Escape') { this.setHover(-1); return; }
    else return;
    e.preventDefault();
    this.setHover(i);
  }

  setHover(i) {
    this.hover = i;
    const p = this.samples[i];
    if (i < 0 || !p) {
      this.cross.hidden = true;
      this.tip.hidden = true;
      this.tip.setAttribute('aria-live', 'off');
      return;
    }
    const x = this.xOf(p.t);
    this.cross.style.setProperty('--x', String(x));
    this.tip.style.setProperty('--x', String(x));
    this.tip.classList.toggle('is-left', x > 0.6);
    put(this.tip,
      h('div', { class: 'tc-tip-time' }, clock(p.t)),
      this.series.map((s) => h('div', { class: 'tc-tip-row' },
        h('span', { class: ['tc-key', s.cls], 'aria-hidden': 'true' }),
        h('strong', { class: 'num' }, fmtPct(p.v[s.id])),
        h('span', { class: 'tc-tip-label' }, s.label))));
    this.cross.hidden = false;
    this.tip.hidden = false;
    // Announce only for keyboard reading (focus inside the plot), not for every pointer move.
    this.tip.setAttribute('aria-live', document.activeElement === this.plot ? 'polite' : 'off');
  }

  toggleTable() {
    this.tableOpen = !this.tableOpen;
    this.tableBtn.setAttribute('aria-pressed', String(this.tableOpen));
    this.table.hidden = !this.tableOpen;
    if (this.tableOpen) this.drawTable();
  }

  drawTable() {
    const rows = this.samples.slice().reverse();
    put(this.table, h('table', { class: 'table tc-tbl' },
      h('caption', { class: 'sr-only' }, `${this.title}, newest first`),
      h('thead', null, h('tr', null, h('th', { scope: 'col' }, 'Time'), this.series.map((s) => h('th', { scope: 'col', class: 'num' }, s.label)))),
      h('tbody', null, rows.map((p) => h('tr', null, h('td', { class: 'mono' }, clock(p.t)), this.series.map((s) => h('td', { class: 'num' }, fmtPct(p.v[s.id]))))))));
  }
}
