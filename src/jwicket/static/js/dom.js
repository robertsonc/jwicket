// dom.js: the only way J-Wicket builds DOM.
//
// Strict CSP with Trusted Types: text goes in through text nodes, SVG through createElementNS,
// nothing is ever parsed from a string, and styles are set through CSSOM (style: {prop: value}).
// Safe to import from node tests: nothing here touches document or window at import time.
//
// Device text is untrusted: render it with vis() (visSvg() inside SVG), which shows each hidden or
// direction-changing character as a visible badge instead of applying it; titles and labels take
// format.plain().

import { controlParts, hasControls, plain, stamp, time, toDate } from './format.js';

export const SVG_NS = 'http://www.w3.org/2000/svg';

function classString(value) {
  if (!value) return '';
  if (typeof value === 'string') return value;
  if (Array.isArray(value)) return value.map(classString).filter(Boolean).join(' ');
  if (typeof value === 'object') {
    return Object.entries(value)
      .filter(([, on]) => on)
      .map(([name]) => name)
      .join(' ');
  }
  return String(value);
}

function applyStyle(el, style) {
  if (!style || typeof style !== 'object') {
    throw new TypeError('style must be an object of CSS properties (CSP forbids style attributes)');
  }
  for (const [prop, value] of Object.entries(style)) {
    if (value === null || value === undefined || value === false) continue;
    if (prop.startsWith('--') || prop.includes('-')) el.style.setProperty(prop, String(value));
    else el.style[prop] = String(value);
  }
}

function appendChildren(parent, children) {
  for (const child of children) {
    if (child === null || child === undefined || child === false || child === true) continue;
    if (Array.isArray(child)) appendChildren(parent, child);
    else if (typeof child === 'object' && typeof child.nodeType === 'number') parent.append(child);
    else parent.append(document.createTextNode(String(child)));
  }
}

function isAttrs(value) {
  return (
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    typeof value.nodeType !== 'number'
  );
}

function build(el, attrs, children, isSvg) {
  let deferredValue;
  if (attrs) {
    for (const [key, value] of Object.entries(attrs)) {
      if (value === null || value === undefined || value === false) continue;
      if (key === 'class' || key === 'className') {
        const cls = classString(value);
        if (cls) el.setAttribute('class', cls);
      } else if (key === 'dataset') {
        for (const [k, v] of Object.entries(value)) if (v !== null && v !== undefined) el.dataset[k] = String(v);
      } else if (key === 'on') {
        for (const [type, fn] of Object.entries(value)) if (typeof fn === 'function') el.addEventListener(type, fn);
      } else if (key === 'style') {
        applyStyle(el, value);
      } else if (key === 'text') {
        el.textContent = String(value);
      } else if (key === 'value' && !isSvg) {
        deferredValue = value;
      } else if (/^on/i.test(key)) {
        throw new TypeError(`use on: { ${key.slice(2)}: fn } instead of an inline ${key} attribute`);
      } else {
        el.setAttribute(key, value === true ? '' : String(value));
      }
    }
  }
  appendChildren(el, children);
  if (deferredValue !== undefined) {
    if ('value' in el) el.value = String(deferredValue);
    else el.setAttribute('value', String(deferredValue));
  }
  return el;
}

/** h('div', { class: ['a', on && 'b'], dataset: {id: 1}, on: {click: fn}, 'aria-label': 'x' }, ...children) */
export function h(tag, attrs, ...children) {
  if (!isAttrs(attrs)) {
    if (attrs !== undefined) children.unshift(attrs);
    attrs = null;
  }
  return build(document.createElement(tag), attrs, children, false);
}

/** svg('path', { d: 'M0 0h10', class: 'x' }) */
export function svg(tag, attrs, ...children) {
  if (!isAttrs(attrs)) {
    if (attrs !== undefined) children.unshift(attrs);
    attrs = null;
  }
  return build(document.createElementNS(SVG_NS, tag), attrs, children, true);
}

export function clear(el) {
  if (el) el.replaceChildren();
  return el;
}

/** Replace el's children with the given ones; null, undefined and booleans are skipped, arrays flattened. */
export function put(el, ...children) {
  if (!el) return el;
  el.replaceChildren();
  appendChildren(el, children);
  return el;
}

/** Text with the given character indices wrapped in <mark> (palette and search highlights). */
export function marked(text, indices, cls) {
  const str = String(text);
  if (!indices || !indices.length) return [str];
  const set = new Set(indices);
  const out = [];
  let run = '';
  let runHit = false;
  for (let i = 0; i < str.length; i += 1) {
    const hit = set.has(i);
    if (hit !== runHit && run) {
      out.push(runHit ? h('mark', { class: cls }, run) : run);
      run = '';
    }
    runHit = hit;
    run += str[i];
  }
  if (run) out.push(runHit ? h('mark', { class: cls }, run) : run);
  return out;
}

// ---- device text, visibly -------------------------------------------------------------------------

const isHigh = (c) => c >= 0xd800 && c <= 0xdbff;
const isLow = (c) => c >= 0xdc00 && c <= 0xdfff;

/** [start, end) UTF-16 ranges clamped to the string, sorted and merged; never inside a surrogate pair. */
function normMarks(str, marks) {
  const len = str.length;
  if (!Array.isArray(marks) || !marks.length || !len) return [];
  const inPair = (i) => i > 0 && i < len && isHigh(str.charCodeAt(i - 1)) && isLow(str.charCodeAt(i));
  const list = [];
  for (const m of marks) {
    if (!Array.isArray(m) || m.length < 2) continue;
    let a = Math.max(0, Math.min(len, Math.floor(Number(m[0]))));
    let b = Math.max(0, Math.min(len, Math.floor(Number(m[1]))));
    if (!Number.isFinite(a) || !Number.isFinite(b) || b <= a) continue;
    if (inPair(a)) a -= 1;
    if (inPair(b)) b += 1;
    list.push([a, b]);
  }
  list.sort((x, y) => x[0] - y[0] || x[1] - y[1]);
  const out = [];
  for (const m of list) {
    const last = out[out.length - 1];
    if (last && m[0] <= last[1]) last[1] = Math.max(last[1], m[1]);
    else out.push(m);
  }
  return out;
}

function ctlBadge(name) {
  return h('span', { class: 'ctl-badge', title: `A hidden ${name} character is here (shown, not applied)` }, name);
}

/**
 * Device text as nodes to append, with every control or format character shown as a badge
 * (`<span class="ctl-badge">U+202E</span>`) instead of being applied: vis(name, { all: true }) for
 * names (tab and line feed badged too), vis(description) for text that may span lines. Plain runs are
 * strings (they become text nodes when appended). `marks`: [start, end) UTF-16 offsets into the
 * original string, merged and sorted here; marked runs become <mark class={markClass}>, and a badge
 * inside a mark goes inside it. No control and no mark: [String(value ?? '')].
 */
export function vis(value, { all = false, marks = null, markClass = 'hit' } = {}) {
  const str = String(value ?? '');
  const ms = normMarks(str, marks);
  if (!ms.length && !hasControls(str, { all })) return [str];
  const pieces = (s) => controlParts(s, { all }).map((p) => (p.ctl ? ctlBadge(p.ctl) : p.text));
  const out = [];
  let pos = 0;
  for (const [a, b] of ms) {
    if (a > pos) out.push(...pieces(str.slice(pos, a)));
    out.push(h('mark', { class: markClass }, pieces(str.slice(a, b))));
    pos = b;
  }
  if (pos < str.length) out.push(...pieces(str.slice(pos)));
  return out;
}

/**
 * vis() for SVG text: plain runs are strings and each control is <tspan class="ctl-badge">U+202E</tspan>.
 * The caller sets the element's aria-label with format.plain().
 */
export function visSvg(value, { all = false } = {}) {
  const str = String(value ?? '');
  if (!hasControls(str, { all })) return [str];
  return controlParts(str, { all }).map((p) => (p.ctl ? svg('tspan', { class: 'ctl-badge' }, p.ctl) : p.text));
}

// ---- timing helpers ------------------------------------------------------------------------------

export function debounce(fn, ms) {
  let timer = 0;
  let lastArgs = [];
  const wrapped = (...args) => {
    lastArgs = args;
    clearTimeout(timer);
    timer = setTimeout(() => {
      timer = 0;
      fn(...lastArgs);
    }, ms);
  };
  wrapped.cancel = () => {
    clearTimeout(timer);
    timer = 0;
  };
  wrapped.flush = () => {
    if (timer) {
      clearTimeout(timer);
      timer = 0;
      fn(...lastArgs);
    }
  };
  return wrapped;
}

const raf =
  typeof requestAnimationFrame === 'function' ? (cb) => requestAnimationFrame(cb) : (cb) => setTimeout(cb, 16);
const caf = typeof cancelAnimationFrame === 'function' ? (id) => cancelAnimationFrame(id) : (id) => clearTimeout(id);

/** Coalesce calls into one per animation frame, with the latest arguments. */
export function rafBatch(fn) {
  let id = 0;
  let lastArgs = [];
  const run = () => {
    id = 0;
    fn(...lastArgs);
  };
  const wrapped = (...args) => {
    lastArgs = args;
    if (!id) id = raf(run);
  };
  wrapped.cancel = () => {
    if (id) caf(id);
    id = 0;
  };
  wrapped.flush = () => {
    if (id) {
      caf(id);
      run();
    }
  };
  return wrapped;
}

// ---- icons ---------------------------------------------------------------------------------------

// 24x24 stroke icons (path data only). Rendered with stroke="currentColor".
export const ICONS = {
  overview: ['M4 4h6.5v8H4z', 'M13.5 4H20v5h-6.5z', 'M13.5 12H20v8h-6.5z', 'M4 15h6.5v5H4z'],
  policies: ['M12 3l7.5 3v5.2c0 4.4-3.1 8.2-7.5 9.8-4.4-1.6-7.5-5.4-7.5-9.8V6z', 'M8.8 11.8l2.3 2.3 4.3-4.4'],
  sessions: ['M4 8h13.5', 'M14.5 4.8l3.2 3.2-3.2 3.2', 'M20 16H6.5', 'M9.5 12.8L6.3 16l3.2 3.2'],
  logs: ['M5 5.5h14', 'M5 9.5h9', 'M5 13.5h14', 'M5 17.5h6', 'M15 17.5h4'],
  objects: ['M12 3.2l7.8 4.4v8.8L12 20.8l-7.8-4.4V7.6z', 'M4.4 7.7L12 12l7.6-4.3', 'M12 12v8.6'],
  search: ['M10.8 17.6a6.8 6.8 0 1 0 0-13.6 6.8 6.8 0 0 0 0 13.6z', 'M20 20l-4.4-4.4'],
  sun: [
    'M12 16.2a4.2 4.2 0 1 0 0-8.4 4.2 4.2 0 0 0 0 8.4z',
    'M12 2.5v2', 'M12 19.5v2', 'M4.9 4.9l1.4 1.4', 'M17.7 17.7l1.4 1.4', 'M2.5 12h2', 'M19.5 12h2',
    'M4.9 19.1l1.4-1.4', 'M17.7 6.3l1.4-1.4',
  ],
  moon: ['M19.5 14.6A7.8 7.8 0 0 1 9.4 4.5a7.8 7.8 0 1 0 10.1 10.1z'],
  signout: ['M9.5 20H6.2A2.2 2.2 0 0 1 4 17.8V6.2A2.2 2.2 0 0 1 6.2 4h3.3', 'M15.5 16l4-4-4-4', 'M19.3 12H9.5'],
  refresh: ['M19.5 10.5A7.6 7.6 0 0 0 5.8 7.2L4.5 8.8', 'M4.5 4.5v4.3h4.3', 'M4.5 13.5a7.6 7.6 0 0 0 13.7 3.3l1.3-1.6', 'M19.5 19.5v-4.3h-4.3'],
  close: ['M6.5 6.5l11 11', 'M17.5 6.5l-11 11'],
  'chevron-down': ['M6.5 9.5l5.5 5.5 5.5-5.5'],
  'chevron-right': ['M9.5 6.5l5.5 5.5-5.5 5.5'],
  'chevron-left': ['M14.5 6.5L9 12l5.5 5.5'],
  menu: ['M4 7h16', 'M4 12h16', 'M4 17h16'],
  more: ['M6 12h.01', 'M12 12h.01', 'M18 12h.01'],
  keyboard: ['M3.5 6.5h17v11h-17z', 'M7 10h.01', 'M10.5 10h.01', 'M14 10h.01', 'M17.5 10h.01', 'M7.5 14h9'],
  user: ['M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8z', 'M4.8 20.5a7.2 7.2 0 0 1 14.4 0'],
  token: ['M14.5 9.5a4.5 4.5 0 1 0-4.1 4.5', 'M10 14l-6 6', 'M6.5 17.5l2 2', 'M14.5 9.5h.01'],
  broadcast: [
    'M12 13.5a1.6 1.6 0 1 0 0-3.2 1.6 1.6 0 0 0 0 3.2z', 'M8.2 15.6a5.2 5.2 0 0 1 0-7.4',
    'M15.8 8.2a5.2 5.2 0 0 1 0 7.4', 'M5.4 18.5a9.2 9.2 0 0 1 0-13', 'M18.6 5.5a9.2 9.2 0 0 1 0 13',
  ],
  layers: ['M12 4l8.5 4.6L12 13.2 3.5 8.6z', 'M3.5 12.6l8.5 4.6 8.5-4.6', 'M3.5 16.4L12 21l8.5-4.6'],
  server: ['M4 4.5h16v6H4z', 'M4 13.5h16v6H4z', 'M7.5 7.5h.01', 'M7.5 16.5h.01', 'M11 7.5h6', 'M11 16.5h6'],
  tenant: ['M4 20V8.5L12 4l8 4.5V20', 'M9 20v-6h6v6', 'M4 20h16'],
  alert: ['M10.3 4.6L2.9 17.6a2 2 0 0 0 1.7 3h14.8a2 2 0 0 0 1.7-3L13.7 4.6a2 2 0 0 0-3.4 0z', 'M12 9.5v4', 'M12 17h.01'],
  info: ['M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z', 'M12 11v5.5', 'M12 7.8h.01'],
  check: ['M5 12.5l4.5 4.5L19 7.5'],
  'check-circle': ['M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z', 'M8.3 12.3l2.5 2.5 4.9-5'],
  lock: ['M6 10.5h12v9.5H6z', 'M8.8 10.5V7.8a3.2 3.2 0 0 1 6.4 0v2.7'],
  ban: ['M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z', 'M5.6 5.6l12.8 12.8'],
  copy: ['M9 9h11v11H9z', 'M5.5 15H4V4h11v1.5'],
  download: ['M12 4v11', 'M7.5 10.5L12 15l4.5-4.5', 'M5 20h14'],
  pause: ['M8.5 5.5v13', 'M15.5 5.5v13'],
  play: ['M7.5 5.2l11 6.8-11 6.8z'],
  arrow: ['M5 12h14', 'M13.5 6.5L19 12l-5.5 5.5'],
  'arrow-right': ['M5 12h14', 'M13.5 6.5L19 12l-5.5 5.5'],
  filter: ['M4 5h16l-6.2 7.6V19l-3.6 1.6v-8z'],
  clock: ['M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z', 'M12 7.5V12l3 2'],
  bolt: ['M13.2 3L5.5 13.6h6l-.9 7.4 7.9-10.8h-6.1z'],
  globe: ['M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z', 'M3 12h18', 'M12 3c2.6 2.6 3.8 5.6 3.8 9s-1.2 6.4-3.8 9c-2.6-2.6-3.8-5.6-3.8-9s1.2-6.4 3.8-9z'],
  help: ['M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z', 'M9.6 9.3a2.5 2.5 0 1 1 3.5 2.3c-.7.3-1.1.9-1.1 1.6v.6', 'M12 16.8h.01'],
  grid: ['M4 4h16v16H4z', 'M4 9.3h16', 'M4 14.7h16', 'M9.3 4v16', 'M14.7 4v16'],
  rows: ['M4 6h16', 'M4 10h16', 'M4 14h16', 'M4 18h16'],
  sidebar: ['M4 4.5h16v15H4z', 'M9.5 4.5v15'],
  link: ['M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1', 'M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1'],
  zone: ['M4 6.5l5.3-2.5 5.4 2.5L20 4v13.5L14.7 20l-5.4-2.5L4 20z', 'M9.3 4v13.5', 'M14.7 6.5V20'],
  terminal: ['M4 5h16v14H4z', 'M7.5 9.5l3 2.5-3 2.5', 'M12.5 15h4'],
  shield: ['M12 3l7.5 3v5.2c0 4.4-3.1 8.2-7.5 9.8-4.4-1.6-7.5-5.4-7.5-9.8V6z'],
  wifi: ['M12 19h.01', 'M8.5 15.5a5 5 0 0 1 7 0', 'M5.5 12.4a9.2 9.2 0 0 1 13 0'],
  cpu: ['M7 7h10v10H7z', 'M10 4v3', 'M14 4v3', 'M10 17v3', 'M14 17v3', 'M4 10h3', 'M4 14h3', 'M17 10h3', 'M17 14h3'],
  cluster: ['M3.5 5h7v6h-7z', 'M13.5 5h7v6h-7z', 'M8.5 15h7v5h-7z', 'M7 11v2h10v-2', 'M12 13v2'],
  command: ['M9 6.5V17.5', 'M15 6.5V17.5', 'M6.5 9H17.5', 'M6.5 15H17.5'],
};

/** icon('sessions', { size: 16, label: 'Sessions', class: 'x' }) -> <svg>. Decorative unless labelled. */
export function icon(name, opts = {}) {
  const paths = ICONS[name] || (typeof name === 'string' && name.startsWith('M') ? [name] : ICONS.info);
  const size = opts.size || 16;
  const el = svg('svg', {
    viewBox: '0 0 24 24',
    width: size,
    height: size,
    fill: 'none',
    stroke: 'currentColor',
    'stroke-width': opts.stroke || (name === 'more' ? 3 : 1.75),
    'stroke-linecap': 'round',
    'stroke-linejoin': 'round',
    class: ['icon', `icon-${typeof name === 'string' && ICONS[name] ? name : 'custom'}`, opts.class],
    'aria-hidden': opts.label ? null : 'true',
    role: opts.label ? 'img' : null,
    'aria-label': opts.label || null,
    focusable: 'false',
  });
  if (opts.label) el.append(svg('title', null, opts.label));
  for (const d of paths) el.append(svg('path', { d }));
  return el;
}

// ---- explicit state cards (shared by every view) -------------------------------------------------

export const STATE_TITLES = {
  denied: 'Your Junos login class does not allow this',
  unsupported: 'Not supported or not enabled on this device',
  failed: 'The device could not complete this read',
  'session-lost': 'Your device session ended',
  refused: 'Too much to read in one go',
  'count-unknown': 'Not listed: how many sessions match is not known',
  'filter-rejected': 'The device did not accept this filter',
  waiting: 'Waiting for another read',
  busy: 'Other reads for your session kept J-Wicket busy',
  internal: 'J-Wicket could not complete this request',
  offline: 'J-Wicket did not answer',
  empty: 'Nothing to show',
  loading: 'Reading the device',
  info: 'Note',
};

export const STATE_HINTS = {
  denied: 'J-Wicket shows only what your login class may read. Ask your Junos administrator if you need this.',
  unsupported: 'This is a property of the device or its configuration, not a J-Wicket error.',
  failed: 'Refresh to try again. If it keeps failing, check the J-Wicket log on the device.',
  'session-lost': 'Sign in again. J-Wicket keeps no password, so it cannot reconnect for you.',
  offline: 'Check that J-Wicket is running and, through an SSH tunnel, that the tunnel is open.',
  'count-unknown': 'J-Wicket lists sessions only when it knows the count is small enough; nothing failed on the device.',
  'filter-rejected': 'Remove the device filters, or filter in the browser instead.',
  waiting: 'Another read for your session is running (another tab or window of this session?). J-Wicket tries again by itself.',
  busy: 'J-Wicket tries again in 30 s, or read again now.',
  internal: 'This is a J-Wicket fault, not a device failure. Refresh to try again; the J-Wicket log on the device has the details.',
};

/** The state-code chip text where it differs from the status itself. */
export const STATE_CODES = {
  'count-unknown': 'count unknown',
  'filter-rejected': 'filter rejected',
  waiting: 'waiting',
  busy: 'busy',
  internal: 'internal',
};

// Only these interrupt a screen reader (role="alert"); the others are states, not faults.
const ALERT_STATES = new Set(['failed', 'internal']);

// The API's default operator-safe texts (src/jwicket/junos/errors.py); the state title already says them.
const GENERIC_MESSAGES = new Set(
  [
    'Your Junos login class does not allow this.',
    'This device does not support or has not enabled this.',
    'The device could not complete the request.',
  ].map((t) => t.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim()),
);

const STATE_ICONS = {
  denied: 'lock',
  unsupported: 'ban',
  failed: 'alert',
  'session-lost': 'signout',
  refused: 'filter',
  'count-unknown': 'help',
  'filter-rejected': 'filter',
  waiting: 'clock',
  busy: 'clock',
  internal: 'alert',
  offline: 'wifi',
  empty: 'info',
  info: 'info',
  loading: 'clock',
};

/**
 * An explicit state, never sample data:
 * stateCard({ status: 'denied', message, title?, hint?, actions?: [Node], compact? })
 */
export function stateCard({ status = 'failed', message, title, hint, actions, compact = false, code = true } = {}) {
  const key = STATE_TITLES[status] ? status : 'failed';
  const hintText = hint === undefined ? STATE_HINTS[key] : hint;
  const norm = (t) => String(t || '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
  // Server messages often repeat the generic title ("Your Junos login class does not allow this.").
  if (message && (norm(message) === norm(title || STATE_TITLES[key]) || (!title && GENERIC_MESSAGES.has(norm(message))))) message = null;
  return h(
    'div',
    { class: ['state', compact && 'compact'], dataset: { state: key }, role: ALERT_STATES.has(key) ? 'alert' : null },
    h('span', { class: 'state-icon' }, icon(STATE_ICONS[key] || 'info')),
    h(
      'div',
      { class: 'state-text' },
      code && key !== 'empty' && key !== 'info' && key !== 'loading' ? h('span', { class: 'state-code' }, STATE_CODES[status] || status) : null,
      h('span', { class: 'state-title' }, vis(title || STATE_TITLES[key])),
      message ? h('span', { class: 'state-msg' }, vis(message)) : null,
      hintText ? h('span', { class: 'state-hint' }, hintText) : null,
      actions && actions.length ? h('div', { class: 'state-actions' }, actions) : null,
    ),
  );
}

const CONFIG_NOT_READ = {
  denied: 'configuration not read (your login class does not allow it)',
  failed: 'configuration read failed',
  unsupported: 'configuration read not supported',
};

/**
 * The parts of the line under a view title, in order (pure: no DOM):
 *   1. `host` (mono), then `scope`;
 *   2. when `config` is given and its status is not "ok", a muted part saying the configuration was not
 *      read (titled with `config.message`), and the time part then reads "checked HH:MM:SS UTC";
 *   3. otherwise, with `source.database === 'committed'`, "committed config" (", inheritance expanded"
 *      when `source.inheritance`), and the time part reads "read HH:MM:SS UTC";
 *   4. the user: "as <user>", or "lab token: as <user>" when `backend === 'lab-token'`; the user name is
 *      mono, so this part carries `head` (the leading text that is not mono);
 *   5. `extra`: strings become parts; a DOM node is passed through as `{text, node}`.
 * Returns `[{ text, mono?, muted?, title?, head?, node? }]`. Titles are already format.plain().
 */
export function subParts({ host, scope, readAt, user, backend, config, source, extra } = {}) {
  const parts = [];
  if (host) parts.push({ text: String(host), mono: true });
  if (scope) parts.push({ text: String(scope) });
  let timeWord = 'read';
  if (config && typeof config === 'object' && config.status !== 'ok') {
    const status = String(config.status ?? 'unknown');
    const part = { text: CONFIG_NOT_READ[status] || `configuration not read (${status})`, muted: true };
    if (config.message) part.title = plain(config.message);
    parts.push(part);
    timeWord = 'checked';
  } else if (source && typeof source === 'object' && source.database === 'committed') {
    parts.push({
      text: source.inheritance ? 'committed config, inheritance expanded' : 'committed config',
      title: `committed configuration database; group inheritance ${source.inheritance ? 'expanded' : 'not expanded'}`,
    });
  }
  const at = toDate(readAt);
  if (at) parts.push({ text: `${timeWord} ${time(at)} UTC`, title: stamp(at) });
  if (user) {
    const head = backend === 'lab-token' ? 'lab token: as ' : 'as ';
    parts.push({ text: `${head}${user}`, mono: true, head });
  }
  for (const x of [].concat(extra ?? [])) {
    if (x === null || x === undefined || x === '' || x === false) continue;
    if (typeof x === 'object' && typeof x.nodeType === 'number') parts.push({ text: String(x.textContent || ''), node: x });
    else parts.push({ text: String(x) });
  }
  return parts;
}

/**
 * The line under a view title, built the same way in every view from subParts():
 * "host · Scope label · committed config · read HH:MM:SS UTC · as user", device strings through vis().
 * Missing parts are left out; `extra` (strings or nodes) is appended. Fills `el` when given, and
 * returns the nodes.
 *   viewSub(el, { host, scope: ctx.ui.scopeLabel(id), readAt, user, backend, config, source, extra })
 */
export function viewSub(el, opts = {}) {
  const nodes = [];
  subParts(opts || {}).forEach((p, i) => {
    if (i) nodes.push(h('span', { class: 'sub-sep', 'aria-hidden': 'true' }, ' · '));
    if (p.node) {
      nodes.push(p.node);
      return;
    }
    const title = p.title || null;
    if (p.mono && p.head !== undefined) {
      nodes.push(h('span', { title }, p.head, h('span', { class: 'mono' }, vis(p.text.slice(p.head.length), { all: true }))));
    } else {
      nodes.push(h('span', { class: [p.mono && 'mono', p.muted && 'muted'], title }, vis(p.text, { all: true })));
    }
  });
  if (el) put(el, nodes);
  return nodes;
}

/** Skeleton lines while a tile loads. */
export function skeleton(lines = 3) {
  const widths = ['w80', 'w60', 'w40', 'w80', 'w60'];
  return h(
    'div',
    { class: 'sk', 'aria-hidden': 'true' },
    Array.from({ length: lines }, (_, i) => h('div', { class: ['sk-line', widths[i % widths.length]] })),
  );
}

/** Replace text and replay the counter tick animation when the value changed. */
export function setTicking(el, text) {
  const next = String(text);
  if (el.textContent === next) return;
  el.textContent = next;
  el.classList.remove('tick');
  // Reading offsetWidth restarts the CSS animation.
  void el.offsetWidth;
  el.classList.add('tick');
}
