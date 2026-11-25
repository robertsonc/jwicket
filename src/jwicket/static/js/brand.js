// brand.js: the J-Wicket emblem ("Sentinel Gate") and the colour schemes.
//
// The emblem is an octagonal frame, a white "J" with chamfered corners, a mint dot and a mint line
// with an arrow passing through it, and two mint bracket pieces. Its geometry is traced from the
// brand board (docs/brand/ holds the standalone files and the guide); the same points are in
// index.html (boot screen, sign-in), static/logo.svg (the favicon: docs/brand/app-icon-small.svg, with
// its 12-unit frame) and docs/brand/*.svg, so change them together (tests/test_static.py checks).
// Colours come from CSS (app.css "logo mark"): the brand's own, the same in every scheme, following
// night or day only.

import { svg } from './dom.js';

export const EMBLEM_VIEWBOX = '15 13 236 236';

/** The emblem's parts, in paint order: [tag, attributes]. */
export const EMBLEM_PARTS = [
  ['polygon', { class: 'lg-frame', points: '99,37 171,37 215.5,68 215.5,192 170,224.5 100,224.5 54.5,192 54.5,68', fill: 'none', 'stroke-width': 4, 'stroke-linejoin': 'round' }],
  ['polygon', { class: 'lg-j', points: '70,60 120,60 134,74 134,165 101,198 70,198 70,176 92,176 111,157 111,83 70,83' }],
  ['rect', { class: 'lg-acc', x: 20, y: 126.5, width: 59, height: 10 }],
  ['rect', { class: 'lg-acc', x: 87, y: 121, width: 20.5, height: 21, rx: 4 }],
  ['rect', { class: 'lg-acc', x: 143, y: 126.5, width: 96, height: 10 }],
  ['polygon', { class: 'lg-acc', points: '160,60 195,60 206,71 206,106 183,106 183,83 160,83' }],
  ['polygon', { class: 'lg-acc', points: '183,157 206,157 206,190 194,202 160,202 160,180 183,180' }],
  ['polyline', { class: 'lg-acc-stroke', points: '220,111 240,131.5 220,152', fill: 'none', 'stroke-width': 10, 'stroke-linejoin': 'miter', 'stroke-miterlimit': 4 }],
];

/**
 * The emblem as an inline <svg class="logo-mark">, decorative (aria-hidden): the text next to it or
 * the control around it carries the name. `attrs` adds to or overrides the <svg> attributes, for
 * example { class: 'logo-mark fd-mark', x, y, width, height } to nest it in another drawing.
 */
export function logoMark(attrs = {}) {
  return svg(
    'svg',
    { class: 'logo-mark', viewBox: EMBLEM_VIEWBOX, 'aria-hidden': 'true', focusable: 'false', ...attrs },
    EMBLEM_PARTS.map(([tag, a]) => svg(tag, a)),
  );
}

// ---- colour schemes (app.css "colour schemes") ------------------------------------------------------

/**
 * The schemes, the default first. index.html sets data-scheme to the default on <html> so the first
 * paint already has its colours; HPE's tokens are app.css's bare :root rules, so data-scheme="hpe"
 * (or none) gets them.
 */
export const SCHEMES = [
  { id: 'obsidian', label: 'Obsidian & Phosphor', short: 'Obsidian', detail: 'The default. NOC: cyan telemetry, teal healthy, coral critical' },
  { id: 'hpe', label: 'HPE', short: 'HPE', detail: 'HPE brand: green accents on slate' },
  { id: 'nordic', label: 'Nordic Steel', short: 'Nordic', detail: 'Colourblind-safe: ice blue allow, magenta deny' },
];

export const DEFAULT_SCHEME = SCHEMES[0].id;

/** A known scheme id, or the default for anything else (nothing stored, storage blocked, an old value). */
export function schemeId(value) {
  return SCHEMES.some((s) => s.id === value) ? value : DEFAULT_SCHEME;
}
