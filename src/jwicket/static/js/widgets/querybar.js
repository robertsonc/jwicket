// QueryBar: the query input shared by Policies, Sessions and Logs.
//
//   const bar = new QueryBar({ view: 'sessions', value, placeholder,
//     onChange(text, parsed) {...}, getContext: () => ({ rows, inventory }) });
//   el.append(bar.el); bar.setPlan(query.plan(parsed.ast, 'sessions')); bar.setError(err); bar.focus();
//
// The text is syntax-coloured by a mirror layer under a transparent <input>; parse errors show inline
// with a caret under the position; device (gold) and browser (sky) chips come from setPlan(); the
// autocomplete list is a WAI-ARIA combobox (aria-activedescendant). Strict CSP: DOM built with
// createElement / createElementNS and textContent only.
//
// Suggested values come from what the device returned (policy, zone, interface names): in the list,
// the chips and the explain line every hidden or direction-changing character is shown as a
// <span class="ctl-badge">U+202E</span> (format.controlParts, as dom.vis does), never applied, and
// aria labels use format.plain(). The input and its colouring mirror keep the exact characters, so
// the caret and the colours stay aligned with what was typed.

import * as query from '../query.js';
import { controlParts, plain } from '../format.js';

const SVG_NS = 'http://www.w3.org/2000/svg';
const CHANGE_MS = 160;
const ERROR_MS = 450;
const MAX_SAVED = 20;
let seq = 0;

const ICONS = {
  search: ['M7 2.5a4.5 4.5 0 1 0 0 9 4.5 4.5 0 0 0 0-9Z', 'M10.4 10.4 13.5 13.5'],
  clear: ['M4.5 4.5l7 7', 'M11.5 4.5l-7 7'],
  star: ['M8 2.2l1.75 3.6 3.95.55-2.86 2.77.68 3.93L8 11.2l-3.52 1.85.68-3.93L2.3 6.35l3.95-.55Z'],
  help: ['M8 14.2A6.2 6.2 0 1 0 8 1.8a6.2 6.2 0 0 0 0 12.4Z', 'M6.2 6.3a1.9 1.9 0 0 1 3.7.5c0 1.3-1.9 1.6-1.9 2.8', 'M8 11.4v.1'],
  remove: ['M5 5l6 6', 'M11 5l-6 6'],
};

function el(tag, cls, attrs) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v === null || v === undefined || v === false) continue;
      e.setAttribute(k, v === true ? '' : String(v));
    }
  }
  return e;
}

function text(tag, cls, value, attrs) {
  const e = el(tag, cls, attrs);
  e.textContent = value;
  return e;
}

/** Append `value` to `parent` as text, each control or format character as a visible badge. */
function appendVisible(parent, value) {
  for (const p of controlParts(String(value ?? ''), { all: true })) {
    if (p.ctl) parent.append(text('span', 'ctl-badge', p.ctl, { title: `A hidden ${p.ctl} character is here (shown, not applied)` }));
    else parent.append(document.createTextNode(p.text));
  }
  return parent;
}

function icon(name) {
  const s = document.createElementNS(SVG_NS, 'svg');
  s.setAttribute('viewBox', '0 0 16 16');
  s.setAttribute('aria-hidden', 'true');
  s.setAttribute('focusable', 'false');
  s.setAttribute('class', `qb-ico qb-ico-${name}`);
  for (const d of ICONS[name]) {
    const p = document.createElementNS(SVG_NS, 'path');
    p.setAttribute('d', d);
    s.appendChild(p);
  }
  return s;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function baseView(view) {
  return String(view || '').split(/[:\-/]/)[0] || 'query';
}

function storageKey(view) {
  return `jwicket.savedQueries.${baseView(view)}`;
}

function loadSaved(view) {
  try {
    const raw = window.localStorage.getItem(storageKey(view));
    const list = raw ? JSON.parse(raw) : [];
    return Array.isArray(list) ? list.filter((s) => typeof s === 'string' && s.trim()).slice(0, MAX_SAVED) : [];
  } catch (_e) {
    return [];
  }
}

function storeSaved(view, list) {
  try {
    window.localStorage.setItem(storageKey(view), JSON.stringify(list.slice(0, MAX_SAVED)));
    return true;
  } catch (_e) {
    return false;
  }
}

/** Drops keywords left dangling when a term is removed ("a AND" -> "a"). */
function tidy(s) {
  let t = s.replace(/\s{2,}/g, ' ').trim();
  for (let i = 0; i < 3; i++) {
    t = t
      .replace(/(^|\s)(AND|and|&&|OR|or|\|\|)\s+(AND|and|&&|OR|or|\|\|)(\s|$)/g, '$1$3$4')
      .replace(/^(AND|and|&&|OR|or|\|\|)(\s+|$)/, '')
      .replace(/(^|\s+)(AND|and|&&|OR|or|\|\||NOT|not|-|!)$/, '')
      .replace(/\(\s*\)/g, '')
      .replace(/\s{2,}/g, ' ')
      .trim();
  }
  return t;
}

const VIEW_NAMES = { sessions: 'sessions', logs: 'logs', policies: 'policies', objects: 'objects' };

export class QueryBar {
  /**
   * @param {{view: string, placeholder?: string, value?: string, label?: string,
   *          onChange?: (text: string, parsed: {ast, error}) => void, onSubmit?: (text: string, parsed) => void,
   *          getContext?: () => ({rows?: any[], inventory?: object})}} opts
   */
  constructor(opts = {}) {
    this.view = opts.view || 'sessions';
    this.onChange = typeof opts.onChange === 'function' ? opts.onChange : () => {};
    this.onSubmit = typeof opts.onSubmit === 'function' ? opts.onSubmit : null;
    this.getContext = typeof opts.getContext === 'function' ? opts.getContext : () => ({});
    this.id = `qb${++seq}`;
    this._text = '';
    this._parsed = { ast: null, error: null };
    this._extError = null;
    this._shownError = null;
    this._plan = null;
    this._items = [];
    this._active = -1;
    this._keyActive = false;
    this._open = false;
    this._timers = { change: 0, error: 0 };
    this._lastEmitted = null;
    this._build(opts);
    this._render();
    this.setValue(opts.value || '');
    this._onFocusEvent = () => {
      if (this.el.isConnected) this.focus();
    };
    this._onDocDown = (ev) => {
      if (!this.el.contains(ev.target)) {
        this._closeList();
        this._toggleHelp(false);
      }
    };
    document.addEventListener('jwicket:focus-query', this._onFocusEvent);
    document.addEventListener('pointerdown', this._onDocDown, true);
  }

  // --- public API -----------------------------------------------------------------------------------

  /** Replaces the text without calling onChange (route changes, programmatic filters). */
  setValue(value) {
    const s = String(value ?? '');
    this._text = s;
    if (this.input.value !== s) this.input.value = s;
    this._parsed = query.parse(s, { view: this.view });
    this._lastEmitted = s;
    this._shownError = this._parsed.error;
    this._render();
    this._closeList();
  }

  /** The current text. */
  get value() {
    return this._text;
  }

  /** The last parse result ({ast, error}) for the current text. */
  get parsed() {
    return this._parsed;
  }

  focus() {
    this.input.focus({ preventScroll: false });
    const n = this.input.value.length;
    try {
      this.input.setSelectionRange(n, n);
    } catch (_e) { /* not focusable yet */ }
  }

  /** Device / browser chips and the explain sentence, from query.plan(). null clears them. */
  setPlan(plan) {
    this._plan = plan || null;
    this._renderPlan();
  }

  /**
   * An error to show under the bar: {pos?, end?, message} or a string; null returns to the
   * parser's own error (if any). Positions are character offsets into the current text.
   */
  setError(err) {
    if (err === null || err === undefined || err === '') this._extError = null;
    else if (typeof err === 'string') this._extError = { message: err };
    else this._extError = { pos: err.pos, end: err.end, message: String(err.message || 'Invalid query') };
    this._renderError();
    this._renderMirror();
  }

  /**
   * A one-line notice under the bar that is not a syntax error, for example "This pattern is too slow
   * for 5,000 lines" or "2 policies match through application any"; "" or null hides it.
   * `kind` is "info" (default) or "warn".
   */
  setNotice(textValue, kind = 'info') {
    this.noticeEl.textContent = textValue || '';
    this.noticeEl.hidden = !textValue;
    this.noticeEl.dataset.kind = kind === 'warn' ? 'warn' : 'info';
  }

  /** A short status shown inside the bar (for example "41 of 150"); "" hides it. */
  setStatus(textValue) {
    this.statusEl.textContent = textValue || '';
    this.statusEl.hidden = !textValue;
  }

  destroy() {
    clearTimeout(this._timers.change);
    clearTimeout(this._timers.error);
    document.removeEventListener('jwicket:focus-query', this._onFocusEvent);
    document.removeEventListener('pointerdown', this._onDocDown, true);
    if (this.el.parentNode) this.el.parentNode.removeChild(this.el);
  }

  // --- DOM ------------------------------------------------------------------------------------------

  _build(opts) {
    const id = this.id;
    const viewName = VIEW_NAMES[baseView(this.view)] || 'results';
    this.el = el('div', 'qb', { role: 'search', 'data-view': baseView(this.view) });
    const label = text('label', 'qb-sr', opts.label || `Filter ${viewName}`, { for: `${id}-input` });
    this.wrap = el('div', 'qb-wrap');
    this.box = el('div', 'qb-box');
    const lead = el('span', 'qb-lead', { 'aria-hidden': 'true' });
    lead.appendChild(icon('search'));
    this.field = el('div', 'qb-field');
    this.mirror = el('div', 'qb-mirror', { 'aria-hidden': 'true' });
    this.input = el('input', 'qb-input', {
      id: `${id}-input`, type: 'text', autocomplete: 'off', autocapitalize: 'off', autocorrect: 'off',
      spellcheck: 'false', enterkeyhint: 'search', role: 'combobox', 'aria-autocomplete': 'list',
      'aria-expanded': 'false', 'aria-controls': `${id}-list`, 'aria-describedby': `${id}-err ${id}-notice ${id}-explain`,
      placeholder: opts.placeholder || `Filter ${viewName}: key:value, words, -exclude, a OR b`,
    });
    this.field.append(this.mirror, this.input);
    this.statusEl = el('span', 'qb-status', { 'aria-live': 'polite' });
    this.statusEl.hidden = true;
    this.clearBtn = el('button', 'qb-btn qb-clear', { type: 'button', 'aria-label': 'Clear the query', title: 'Clear the query' });
    this.clearBtn.appendChild(icon('clear'));
    this.saveBtn = el('button', 'qb-btn qb-save', { type: 'button', 'aria-pressed': 'false', 'aria-label': 'Save this query', title: 'Save this query in this browser (only the query text is kept)' });
    this.saveBtn.appendChild(icon('star'));
    this.helpBtn = el('button', 'qb-btn qb-helpbtn', { type: 'button', 'aria-expanded': 'false', 'aria-controls': `${id}-help`, 'aria-label': 'Query syntax', title: 'Query syntax and keys' });
    this.helpBtn.appendChild(icon('help'));
    this.box.append(lead, this.field, this.statusEl, this.clearBtn, this.saveBtn, this.helpBtn);
    this.list = el('ul', 'qb-list', { id: `${id}-list`, role: 'listbox', 'aria-label': 'Suggestions' });
    this.list.hidden = true;
    this.help = el('div', 'qb-help', { id: `${id}-help`, role: 'region', 'aria-label': 'Query syntax' });
    this.help.hidden = true;
    this.wrap.append(this.box, this.list, this.help);
    this.errEl = el('div', 'qb-err', { id: `${id}-err`, role: 'status', 'aria-live': 'polite' });
    this.errEl.hidden = true;
    this.noticeEl = el('p', 'qb-notice', { id: `${id}-notice`, role: 'status', 'aria-live': 'polite' });
    this.noticeEl.hidden = true;
    this.planEl = el('div', 'qb-plan');
    this.planEl.hidden = true;
    this.chips = el('ul', 'qb-chips', { 'aria-label': 'Where each filter runs' });
    this.explainEl = el('p', 'qb-explain', { id: `${id}-explain` });
    this.planEl.append(this.chips, this.explainEl);
    this.el.append(label, this.wrap, this.errEl, this.noticeEl, this.planEl);

    this.input.addEventListener('input', () => this._onInput());
    this.input.addEventListener('keydown', (ev) => this._onKey(ev));
    this.input.addEventListener('scroll', () => this._syncScroll());
    this.input.addEventListener('focus', () => {
      this.box.classList.add('is-focus');
      if (!this._text.trim()) this._suggest(false);
    });
    this.input.addEventListener('blur', () => {
      this.box.classList.remove('is-focus');
      this._closeList();
    });
    this.input.addEventListener('click', () => {
      if (this._open) this._suggest(false);
    });
    this.input.addEventListener('select', () => this._syncScroll());
    this.list.addEventListener('pointerdown', (ev) => ev.preventDefault());
    this.list.addEventListener('click', (ev) => {
      const li = ev.target instanceof Element ? ev.target.closest('.qb-opt') : null;
      if (!li) return;
      const i = Number(li.dataset.index);
      if (li.dataset.remove && ev.target.closest('.qb-opt-del')) this._removeSaved(i);
      else this._accept(i);
    });
    this.list.addEventListener('pointermove', (ev) => {
      const li = ev.target instanceof Element ? ev.target.closest('.qb-opt') : null;
      if (li) this._setActive(Number(li.dataset.index), false);
    });
    this.clearBtn.addEventListener('click', () => {
      this._replace('', 0);
      this._emit(true);
      this.input.focus();
    });
    this.saveBtn.addEventListener('click', () => this._toggleSaved());
    this.helpBtn.addEventListener('click', () => this._toggleHelp(this.help.hidden));
    this.el.addEventListener('keydown', (ev) => {
      if (ev.key === 'Escape' && !this.help.hidden && ev.target !== this.input) {
        ev.preventDefault();
        ev.stopPropagation();
        this._toggleHelp(false);
        this.helpBtn.focus();
      }
    });
    this.errEl.addEventListener('click', () => {
      const e = this._shownErrorObj();
      if (!e || !Number.isInteger(e.pos)) return;
      this.input.focus();
      const end = Math.min(this._text.length, Math.max(e.pos + 1, e.end || e.pos + 1));
      try {
        this.input.setSelectionRange(Math.min(e.pos, this._text.length), end);
      } catch (_e) { /* ignore */ }
    });
  }

  // --- input handling -------------------------------------------------------------------------------

  _onInput() {
    this._text = this.input.value;
    this._parsed = query.parse(this._text, { view: this.view });
    this._extError = null;
    // Errors appear after a short pause, so half-typed terms are not flagged; fixes show at once.
    clearTimeout(this._timers.error);
    if (!this._parsed.error) this._shownError = null;
    else if (this._shownError) this._shownError = this._parsed.error; // already showing: keep it current
    else this._timers.error = setTimeout(() => {
      this._shownError = this._parsed.error;
      this._renderError();
      this._renderMirror();
      this._renderState();
    }, ERROR_MS);
    this._render();
    this._suggest(false);
    clearTimeout(this._timers.change);
    this._timers.change = setTimeout(() => this._emit(false), CHANGE_MS);
  }

  _emit(force) {
    clearTimeout(this._timers.change);
    if (!force && this._lastEmitted === this._text) return;
    this._lastEmitted = this._text;
    try {
      this.onChange(this._text, this._parsed);
    } catch (err) {
      if (typeof console !== 'undefined') console.warn('QueryBar onChange failed', err);
    }
  }

  _onKey(ev) {
    const n = this._items.length;
    switch (ev.key) {
      case 'ArrowDown':
        ev.preventDefault();
        if (!this._open) this._suggest(true);
        else if (n) this._setActive((this._active + 1) % n, true);
        return;
      case 'ArrowUp':
        ev.preventDefault();
        if (this._open && n) this._setActive(this._active <= 0 ? n - 1 : this._active - 1, true);
        return;
      case 'Enter':
        ev.preventDefault();
        if (this._open && this._active >= 0) {
          this._accept(this._active);
          return;
        }
        this._closeList();
        clearTimeout(this._timers.error);
        this._shownError = this._parsed.error;
        this._render();
        this._emit(true);
        if (this.onSubmit) this.onSubmit(this._text, this._parsed);
        return;
      case 'Tab': {
        // Tab completes only an option the user moved to with the arrow keys, and never fills an
        // empty bar with an example or a saved query: otherwise the list closes and focus moves on,
        // so tabbing past the bar cannot change the filter (or, in Sessions, the device query).
        const item = this._open && this._active >= 0 && this._keyActive ? this._items[this._active] : null;
        const fillsEmpty = item && !this._text.trim() && (item.kind === 'example' || item.kind === 'saved');
        if (item && !ev.shiftKey && !fillsEmpty) {
          ev.preventDefault();
          this._accept(this._active);
          return;
        }
        this._closeList();
        return;
      }
      case 'Escape':
        if (this._open) {
          ev.preventDefault();
          ev.stopPropagation();
          this._closeList();
          return;
        }
        if (!this.help.hidden) {
          ev.preventDefault();
          ev.stopPropagation();
          this._toggleHelp(false);
          return;
        }
        // Leave the bar (the query stays); the shell's own Escape handling still runs.
        this.input.blur();
        return;
      case 'Delete':
        if (this._open && this._active >= 0 && this._items[this._active] && this._items[this._active].kind === 'saved') {
          ev.preventDefault();
          this._removeSaved(this._active);
        }
        return;
      case 'ArrowLeft':
      case 'ArrowRight':
      case 'Home':
      case 'End':
        if (this._open) setTimeout(() => this._suggest(false), 0);
        setTimeout(() => this._syncScroll(), 0);
        return;
      default:
    }
  }

  _replace(textValue, caret) {
    this.input.value = textValue;
    this._text = textValue;
    this._parsed = query.parse(textValue, { view: this.view });
    this._extError = null;
    this._shownError = this._parsed.error && caret >= textValue.length ? null : this._parsed.error;
    try {
      this.input.setSelectionRange(caret, caret);
    } catch (_e) { /* ignore */ }
    this._render();
  }

  // --- autocomplete ---------------------------------------------------------------------------------

  _context() {
    try {
      return this.getContext() || {};
    } catch (_e) {
      return {};
    }
  }

  _suggest(all) {
    if (document.activeElement !== this.input) return;
    const caret = this.input.selectionStart ?? this._text.length;
    const ctx = this._context();
    let items = [];
    try {
      items = query.suggest(this._text, caret, { view: this.view, rows: ctx.rows, inventory: ctx.inventory, all });
    } catch (_e) {
      items = [];
    }
    if (!this._text.trim()) {
      const saved = loadSaved(this.view).map((s) => ({ label: s, insert: s, detail: 'saved query', kind: 'saved', from: 0, to: this._text.length }));
      items = [...saved, ...items.filter((i) => !saved.some((s) => s.insert === i.insert))];
    }
    this._items = items.slice(0, 14);
    this._active = -1;
    this._keyActive = false;
    if (!this._items.length) {
      this._closeList();
      return;
    }
    this._renderList();
    this._openList();
  }

  _openList() {
    this._open = true;
    this.list.hidden = false;
    this.input.setAttribute('aria-expanded', 'true');
    this._toggleHelp(false);
  }

  _closeList() {
    this._open = false;
    this._active = -1;
    this._keyActive = false;
    this.list.hidden = true;
    this.input.setAttribute('aria-expanded', 'false');
    this.input.removeAttribute('aria-activedescendant');
  }

  _setActive(i, scroll) {
    const prev = this.list.querySelector('.qb-opt[aria-selected="true"]');
    if (prev) prev.setAttribute('aria-selected', 'false');
    this._active = i;
    this._keyActive = Boolean(scroll); // moved there with the arrow keys (not the pointer)
    const li = this.list.children[i];
    if (!li) {
      this.input.removeAttribute('aria-activedescendant');
      return;
    }
    li.setAttribute('aria-selected', 'true');
    this.input.setAttribute('aria-activedescendant', li.id);
    if (scroll && typeof li.scrollIntoView === 'function') li.scrollIntoView({ block: 'nearest' });
  }

  _renderList() {
    clear(this.list);
    const frag = document.createDocumentFragment();
    const KIND = { key: 'key', value: 'value', op: 'operator', keyword: 'logic', example: 'example', saved: 'saved' };
    this._items.forEach((item, i) => {
      const li = el('li', `qb-opt qb-opt-${item.kind}`, { id: `${this.id}-opt-${i}`, role: 'option', 'aria-selected': 'false' });
      li.dataset.index = String(i);
      li.append(text('span', 'qb-opt-kind', KIND[item.kind] || item.kind));
      const lab = el('span', 'qb-opt-label');
      const typed = this._typedFor(item);
      const l = String(item.label);
      const at = typed ? l.toLowerCase().indexOf(typed.toLowerCase()) : -1;
      if (at >= 0 && typed) {
        if (at > 0) appendVisible(lab, l.slice(0, at));
        lab.append(appendVisible(el('mark', 'qb-opt-hit'), l.slice(at, at + typed.length)));
        appendVisible(lab, l.slice(at + typed.length));
      } else {
        appendVisible(lab, l);
      }
      li.setAttribute('aria-label', item.detail ? `${plain(l, { all: true })}, ${plain(item.detail, { all: true })}` : plain(l, { all: true }));
      li.append(lab);
      li.append(appendVisible(el('span', 'qb-opt-detail'), item.detail || ''));
      if (item.kind === 'saved') {
        li.dataset.remove = '1';
        const del = el('span', 'qb-opt-del', { title: 'Remove from saved queries (Delete)', 'aria-hidden': 'true' });
        del.appendChild(icon('remove'));
        li.append(del);
      }
      frag.appendChild(li);
    });
    this.list.appendChild(frag);
  }

  _typedFor(item) {
    if (item.kind === 'saved' || item.kind === 'example') return '';
    const frag = this._text.slice(item.from, this.input.selectionStart ?? this._text.length);
    const m = /(?:[:=<>~]|!=)([^|]*)$/.exec(frag);
    return (m ? m[1] : frag).replace(/^"/, '');
  }

  _accept(i) {
    const item = this._items[i];
    if (!item) return;
    const before = this._text.slice(0, item.from);
    let after = this._text.slice(item.to);
    // A key or operator continues into a value; a finished term gets one space after it.
    const continues = /[:=<>~|]$/.test(item.insert);
    let insert = item.insert;
    if (!continues) {
      after = after.replace(/^\s+/, '');
      insert += ' ';
    }
    const caret = before.length + insert.length;
    this._replace(`${before}${insert}${after}`, caret);
    if (continues) {
      this._suggest(false);
    } else {
      this._closeList();
      this._emit(false);
    }
  }

  // --- saved queries and help ----------------------------------------------------------------------

  _toggleSaved() {
    const q = this._text.trim();
    if (!q) return;
    const list = loadSaved(this.view);
    const i = list.indexOf(q);
    if (i >= 0) list.splice(i, 1);
    else list.unshift(q);
    if (!storeSaved(this.view, list)) {
      this.saveBtn.title = 'This browser does not allow saving (storage is blocked)';
      return;
    }
    this._renderState();
  }

  _removeSaved(i) {
    const item = this._items[i];
    if (!item || item.kind !== 'saved') return;
    storeSaved(this.view, loadSaved(this.view).filter((s) => s !== item.insert));
    this._renderState();
    this._suggest(false);
  }

  _toggleHelp(open) {
    if (open && !this.help.firstChild) this._buildHelp();
    this.help.hidden = !open;
    this.helpBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
    if (open) this._closeList();
  }

  _buildHelp() {
    const h = this.help;
    const ops = el('div', 'qb-help-ops');
    ops.append(text('h3', 'qb-help-h', 'Syntax'));
    const rows = [
      ['key:value', 'match a field (case-insensitive, * wildcards)'],
      ['key!=v  -key:v  NOT x', 'exclude'],
      ['a b  a AND b', 'both'],
      ['a OR b  (a b) OR c', 'either, grouped'],
      ['key:v1|v2', 'any of these values'],
      ['bytes>1M  dur>=5m', 'compare sizes (k M G = 1000-based, KiB MiB = 1024) and durations (s m h)'],
      ['src:10.10.0.0/16', 'addresses are CIDR-aware'],
      ['"two words"  /re/i  key~re', 'phrase, regular expression'],
    ];
    const dl = el('dl', 'qb-help-dl');
    for (const [k, v] of rows) dl.append(text('dt', null, k), text('dd', null, v));
    ops.append(dl);
    const keys = el('div', 'qb-help-keys');
    keys.append(text('h3', 'qb-help-h', `Keys for ${VIEW_NAMES[baseView(this.view)] || this.view}`));
    const kl = el('ul', 'qb-help-keylist');
    for (const d of query.describe(this.view)) {
      const li = el('li', d.device ? 'is-device' : null);
      const k = text('code', 'qb-help-key', d.key);
      li.append(k, text('span', 'qb-help-label', d.label));
      if (d.aliases.length) li.title = `Also: ${d.aliases.join(', ')}`;
      if (d.device) li.append(text('span', 'qb-help-dev', 'device'));
      kl.append(li);
    }
    keys.append(kl);
    const ex = el('div', 'qb-help-ex');
    ex.append(text('h3', 'qb-help-h', 'Try'));
    for (const e of query.examples(this.view)) {
      const b = text('button', 'qb-help-try', e, { type: 'button' });
      b.addEventListener('click', () => {
        this._replace(e, e.length);
        this._toggleHelp(false);
        this.input.focus();
        this._emit(true);
      });
      ex.append(b);
    }
    const note = text('p', 'qb-help-note', 'Keys marked "device" can be filtered by the firewall itself; the rest run in this browser over what the device returned.');
    h.append(ops, keys, ex, note);
  }

  // --- rendering ------------------------------------------------------------------------------------

  _shownErrorObj() {
    if (this._extError) return this._extError;
    return this._text.trim() ? this._shownError : null;
  }

  _render() {
    this._renderMirror();
    this._renderError();
    this._renderState();
  }

  _renderState() {
    const has = Boolean(this._text);
    this.clearBtn.hidden = !has;
    this.saveBtn.hidden = !this._text.trim() || Boolean(this._parsed.error);
    const saved = this._text.trim() && loadSaved(this.view).includes(this._text.trim());
    this.saveBtn.setAttribute('aria-pressed', saved ? 'true' : 'false');
    this.saveBtn.setAttribute('aria-label', saved ? 'Remove this query from saved queries' : 'Save this query');
    this.el.dataset.state = this._shownErrorObj() ? 'error' : has ? 'active' : 'empty';
  }

  _renderMirror() {
    const s = this._text;
    clear(this.mirror);
    if (!s) return;
    const err = this._shownErrorObj();
    const ea = err && Number.isInteger(err.pos) ? Math.max(0, Math.min(err.pos, s.length)) : -1;
    const eb = ea >= 0 ? Math.max(ea + 1, Math.min(err.end ?? ea + 1, s.length)) : -1;
    const frag = document.createDocumentFragment();
    let pos = 0;
    for (const tok of query.scan(s, { view: this.view })) {
      const a = pos;
      const b = pos + tok.v.length;
      pos = b;
      const cuts = [a, b];
      if (ea > a && ea < b) cuts.push(ea);
      if (eb > a && eb < b) cuts.push(eb);
      cuts.sort((x, y) => x - y);
      for (let i = 0; i < cuts.length - 1; i++) {
        const x = cuts[i];
        const y = cuts[i + 1];
        if (y <= x) continue;
        const span = text('span', `qb-t-${tok.t}`, s.slice(x, y));
        if (ea >= 0 && x >= ea && y <= eb) span.classList.add('qb-t-errspan');
        frag.appendChild(span);
      }
    }
    if (ea >= s.length) frag.appendChild(text('span', 'qb-t-errspan qb-t-eol', ' '));
    this.mirror.appendChild(frag);
    this._syncScroll();
  }

  _syncScroll() {
    this.mirror.scrollLeft = this.input.scrollLeft;
  }

  _renderError() {
    const err = this._shownErrorObj();
    clear(this.errEl);
    if (!err) {
      this.errEl.hidden = true;
      return;
    }
    this.errEl.hidden = false;
    const msg = el('p', 'qb-err-msg');
    if (Number.isInteger(err.pos)) msg.append(text('span', 'qb-err-at', `col ${err.pos + 1}`));
    msg.append(document.createTextNode(err.message));
    this.errEl.append(msg);
    if (Number.isInteger(err.pos) && this._text) {
      const s = this._text;
      const pos = Math.max(0, Math.min(err.pos, s.length));
      const start = Math.max(0, pos - 48);
      const shown = s.slice(start, start + 96);
      const width = Math.max(1, Math.min((err.end ?? pos + 1) - pos, shown.length - (pos - start) || 1));
      const pre = el('pre', 'qb-err-snippet', { title: 'Show in the query' });
      pre.append(text('span', 'qb-err-line', `${start > 0 ? '…' : ''}${shown}`));
      pre.append(document.createTextNode('\n'));
      pre.append(text('span', 'qb-err-caret', `${' '.repeat(pos - start + (start > 0 ? 1 : 0))}^${'~'.repeat(Math.max(0, width - 1))}`));
      this.errEl.append(pre);
    }
  }

  _renderPlan() {
    const p = this._plan;
    clear(this.chips);
    this.explainEl.textContent = '';
    if (!p || !Array.isArray(p.explain) || !p.explain.length) {
      this.planEl.hidden = true;
      return;
    }
    this.planEl.hidden = false;
    for (const e of p.explain) {
      const dev = e.where === 'device';
      const li = el('li', `qb-chip ${dev ? 'qb-chip-device' : 'qb-chip-browser'}${e.refine ? ' qb-chip-refine' : ''}`);
      li.title = dev
        ? (e.refine ? 'Narrowed on the device, then checked exactly in this browser' : 'Filtered by the device before data is sent')
        : 'Filtered in this browser over what the device returned';
      li.append(text('span', 'qb-chip-where', dev ? 'device' : 'browser'));
      li.append(appendVisible(el('span', 'qb-chip-text'), e.text));
      if (Number.isInteger(e.pos) && Number.isInteger(e.end) && e.end <= this._text.length) {
        const x = el('button', 'qb-chip-x', { type: 'button', 'aria-label': `Remove ${plain(e.text, { all: true })}` });
        x.appendChild(icon('remove'));
        x.addEventListener('click', () => this._removeTerm(e));
        li.append(x);
      }
      this.chips.append(li);
    }
    const sentence = query.explainText(p);
    appendVisible(this.explainEl, sentence);
    if (p.expression) {
      this.explainEl.append(document.createTextNode(' · report expression '));
      this.explainEl.append(text('code', 'qb-expr', p.expression));
    }
  }

  _removeTerm(e) {
    const s = this._text;
    const slice = s.slice(e.pos, e.end);
    const check = query.parse(slice);
    if (!check.ast || query.toQueryString(check.ast) !== e.text) return; // the plan is stale
    const next = tidy(`${s.slice(0, e.pos)} ${s.slice(e.end)}`);
    this._replace(next, next.length);
    this._emit(true);
    this.input.focus();
  }
}

export default QueryBar;
