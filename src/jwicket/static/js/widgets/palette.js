// widgets/palette.js: the Ctrl/Cmd-K command palette. Keyboard-first search over items the shell
// supplies (views, actions, scopes, policies, zones, addresses, applications, recent filters).
//
//   const pal = new Palette({
//     getItems: () => [{ id, group, label, name?, detail, hint: ['g','o'], icon, keywords, recentRank?, run }],
//     getLookups: (text) => [items computed from the text itself],
//   });
//   pal.open(); pal.close(); pal.isOpen; pal.clearRecent()
//
// Ranking (rank(), SL-10): every item is matched on its `name` (the label unless given) in tiers:
// exact, prefix, word-start substring, substring, initials (a word-boundary subsequence), and last
// "every query word is somewhere in the label, detail or keywords". Ties go to the item run most
// recently from the palette, then to the group (GROUP_ORDER), then to the shorter name. With a query
// the list opens with a "Best match" group; with none it opens with "Recent".
//
// A leading ">" searches actions only. getLookups turns what was typed into actions of its own (a
// pasted address, port or session id becomes "Sessions with 10.0.0.1", "Logs for session 42", ...);
// they are not ranked and follow the best matches.
//
// The recently run items are remembered by id, in memory only (names are device data): never in
// browser storage, and the shell clears them at sign-out (clearRecent).
//
// Labels and details are device text: they are rendered with dom.vis(), so a hidden or
// direction-changing character shows as a badge, and aria labels use format.plain().

import { h, icon, vis } from '../dom.js';
import { plain } from '../format.js';

export const GROUP_ORDER = ['Look up', 'Views', 'Scopes', 'Recent filters', 'Actions', 'Policies', 'Zones', 'Addresses', 'Applications', 'Filters'];

const SEPARATORS = new Set([' ', '-', '_', '.', ':', '/', '>', '@', '(', '→', '|']);
const MAX_RESULTS = 60;
const MAX_RECENT = 6;
const MRU_SIZE = 24;
const BEST_PREFIX = 3;

function scoreOne(q, text) {
  const t = text.toLowerCase();
  const at = t.indexOf(q);
  if (at >= 0) {
    let score = 12 + q.length * 3;
    if (at === 0) score += 14;
    else if (SEPARATORS.has(t[at - 1])) score += 9;
    score -= t.length * 0.04;
    return { score, hits: Array.from({ length: q.length }, (_, i) => at + i) };
  }
  const hits = [];
  let score = 0;
  let qi = 0;
  let prev = -2;
  for (let ti = 0; ti < t.length && qi < q.length; ti += 1) {
    if (t[ti] !== q[qi]) continue;
    let s = 1;
    if (ti === 0) s += 7;
    else if (SEPARATORS.has(t[ti - 1])) s += 5;
    if (prev === ti - 1) s += 4;
    else if (prev >= 0) s -= Math.min(3, (ti - prev) * 0.15);
    score += s;
    hits.push(ti);
    prev = ti;
    qi += 1;
  }
  if (qi < q.length) return null;
  return { score: score - t.length * 0.04, hits };
}

/** fuzzy('all web', 'allow-web') -> { score, hits: [indices] } or null. Every word must match. */
export function fuzzy(query, text) {
  const words = String(query || '').toLowerCase().split(/\s+/).filter(Boolean);
  if (!words.length) return { score: 0, hits: [] };
  let score = 0;
  const hits = new Set();
  for (const w of words) {
    const m = scoreOne(w, String(text || ''));
    if (!m) return null;
    score += m.score;
    for (const i of m.hits) hits.add(i);
  }
  return { score, hits: [...hits].sort((a, b) => a - b) };
}

// ---- ranking (SL-10) -------------------------------------------------------------------------------

const norm = (s) => String(s ?? '').normalize('NFC').toLowerCase();
const WORDISH = /[\p{L}\p{N}]/u;

/** A word starts at i: the start of the text, or after a character that is not a letter or digit. */
function wordStart(t, i) {
  return i === 0 || !WORDISH.test(t[i - 1]);
}

const range = (at, n) => Array.from({ length: n }, (_, i) => at + i);

/**
 * Tier 4: each character of q (spaces ignored) found in order in t, each one at a word start or right
 * after the previous matched character. Returns the matched indices, or null. Memoised search, so a
 * repetitive name cannot make it slow.
 */
function initials(q, t) {
  const chars = q.replace(/\s+/g, '');
  if (!chars) return null;
  const memo = new Map();
  const go = (qi, prev) => {
    if (qi === chars.length) return [];
    const key = qi * (t.length + 2) + prev + 1;
    if (memo.has(key)) return memo.get(key);
    let found = null;
    for (let j = prev + 1; j < t.length && !found; j += 1) {
      if (t[j] !== chars[qi]) continue;
      if (!(j === prev + 1 && prev >= 0) && !wordStart(t, j)) continue;
      const rest = go(qi + 1, j);
      if (rest) found = [j, ...rest];
    }
    memo.set(key, found);
    return found;
  };
  return go(0, -1);
}

/** Tiers 0 to 4 of q against one name (both already normalised), or null. */
function nameTier(q, t) {
  if (!q || !t) return null;
  if (t === q) return { tier: 0, hits: range(0, t.length) };
  if (t.startsWith(q)) return { tier: 1, hits: range(0, q.length) };
  const first = t.indexOf(q);
  if (first >= 0) {
    for (let at = first; at >= 0; at = t.indexOf(q, at + 1)) {
      if (wordStart(t, at)) return { tier: 2, hits: range(at, q.length) };
    }
    return { tier: 3, hits: range(first, q.length) };
  }
  const sub = initials(q, t);
  return sub ? { tier: 4, hits: sub } : null;
}

const groupIndex = (g) => {
  const i = GROUP_ORDER.indexOf(g);
  return i < 0 ? GROUP_ORDER.length : i;
};

/**
 * rank(items, text, { recent }) -> [{ item, tier, hits }], best first; items that do not match are
 * left out (and an empty text matches nothing).
 *   tiers, on `name` (default: label), case-insensitive, NFC: 0 exact, 1 prefix, 2 word-start
 *   substring, 3 substring, 4 initials (each matched character at a word start or right after the
 *   previous one), 5 every query word is a substring of label + detail + keywords.
 *   order: tier, then the index in `recent` (item ids, most recent first), then GROUP_ORDER, then the
 *   shorter name, then the label (localeCompare, base sensitivity), then the input order.
 *   hits: label indices for tiers 0 to 4 when the name is the label, else [].
 */
export function rank(items, text, { recent = [] } = {}) {
  const q = norm(text).trim().replace(/\s+/g, ' ');
  if (!q) return [];
  const words = q.split(' ');
  const mru = new Map();
  (recent || []).forEach((id, i) => {
    if (!mru.has(id)) mru.set(id, i);
  });
  const out = [];
  (items || []).forEach((item, index) => {
    if (!item) return;
    const label = String(item.label ?? '');
    const name = item.name !== undefined && item.name !== null ? String(item.name) : label;
    const t = norm(name);
    let tier = null;
    let hits = [];
    const m = nameTier(q, t);
    if (m) {
      tier = m.tier;
      // Indices are into the normalised name: they are label indices only when nothing changed length.
      if (name === label && t.length === label.length) hits = m.hits;
    } else {
      const hay = norm(`${label} ${item.detail || ''} ${item.keywords || ''}`);
      if (words.every((w) => hay.includes(w))) tier = 5;
    }
    if (tier === null) return;
    out.push({ item, tier, hits, index, name, label, mru: mru.has(item.id) ? mru.get(item.id) : Infinity, group: groupIndex(item.group) });
  });
  out.sort(
    (a, b) =>
      a.tier - b.tier ||
      a.mru - b.mru ||
      a.group - b.group ||
      a.name.length - b.name.length ||
      a.label.localeCompare(b.label, 'en', { sensitivity: 'base' }) ||
      a.index - b.index,
  );
  return out.map(({ item, tier, hits }) => ({ item, tier, hits }));
}

// ---- highlights ------------------------------------------------------------------------------------

/** [start, end) ranges from sorted indices. */
function toRanges(indices) {
  const out = [];
  for (const i of indices || []) {
    const last = out[out.length - 1];
    if (last && last[1] === i) last[1] = i + 1;
    else out.push([i, i + 1]);
  }
  return out;
}

/** Ranges of every query word in s (case-insensitive), when lower-casing keeps the offsets. */
function wordRanges(words, s) {
  const str = String(s ?? '');
  const t = norm(str);
  if (t.length !== str.length) return [];
  const out = [];
  for (const w of words) {
    const at = t.indexOf(w);
    if (at >= 0) out.push([at, at + w.length]);
  }
  return out;
}

/** Where to highlight the label and the detail of one ranked row. */
function marksFor(row, text) {
  const q = norm(text).trim().replace(/\s+/g, ' ');
  const words = q ? q.split(' ') : [];
  const it = row.item;
  const label = String(it.label ?? '');
  if (!q) return { label: [], detail: [] };
  if (row.hits && row.hits.length) return { label: toRanges(row.hits), detail: [] };
  if (row.tier !== undefined && row.tier !== null && row.tier <= 4) {
    // Matched on a name that is part of the label ("Logs" in "Go to Logs"): highlight it there.
    const name = norm(it.name ?? label);
    const l = norm(label);
    const at = l.length === label.length ? l.indexOf(name) : -1;
    const m = at >= 0 ? nameTier(q, name) : null;
    return { label: m ? toRanges(m.hits.map((i) => i + at)) : [], detail: [] };
  }
  return { label: wordRanges(words, label), detail: wordRanges(words, it.detail) };
}

// ---- the dialog ------------------------------------------------------------------------------------

let seq = 0;

export class Palette {
  constructor({ getItems, getLookups, placeholder = 'Search views, policies, zones and actions…', onClose } = {}) {
    this.getItems = getItems;
    this.getLookups = typeof getLookups === 'function' ? getLookups : null;
    this.onClose = onClose;
    this.placeholder = placeholder;
    this.results = [];
    this.active = 0;
    this.opener = null;
    this.layer = null;
    this.recent = []; // ids of items run from the palette, most recent first (memory only)
    this.id = `pal-${(seq += 1)}`;
  }

  get isOpen() {
    return Boolean(this.layer);
  }

  /** Forget the recently run items (the shell calls this at sign-out). */
  clearRecent() {
    this.recent = [];
  }

  open(text = '') {
    if (this.layer) {
      this.input.focus();
      this.input.select();
      return;
    }
    this.opener = document.activeElement;
    this.items = (this.getItems && this.getItems()) || [];
    this.input = h('input', {
      class: 'pal-input',
      type: 'text',
      role: 'combobox',
      'aria-expanded': 'true',
      'aria-controls': `${this.id}-list`,
      'aria-autocomplete': 'list',
      'aria-label': 'Search views, policies, zones, addresses, applications and actions, or paste an address, port or session id',
      placeholder: this.placeholder,
      autocomplete: 'off',
      spellcheck: 'false',
      value: text,
      on: { input: () => this.render(), keydown: (e) => this.onKey(e) },
    });
    this.list = h('div', { class: 'pal-list', id: `${this.id}-list`, role: 'listbox', 'aria-label': 'Results' });
    const dialog = h(
      'div',
      { class: 'dialog pal', role: 'dialog', 'aria-modal': 'true', 'aria-label': 'Command palette' },
      h('div', { class: 'pal-input-row' }, icon('search', { size: 18 }), this.input, h('kbd', null, 'Esc')),
      this.list,
      h(
        'div',
        { class: 'pal-foot', 'aria-hidden': 'true' },
        h('span', null, h('kbd', null, '↑'), h('kbd', null, '↓'), 'move'),
        h('span', null, h('kbd', null, '↵'), 'open'),
        h('span', null, h('kbd', null, '>'), 'actions only'),
        h('span', { class: 'spacer' }),
        h('span', null, 'Nothing here is sent anywhere'),
      ),
    );
    this.layer = h(
      'div',
      {
        class: 'layer',
        on: {
          mousedown: (e) => {
            if (e.target === this.layer) {
              e.preventDefault();
              this.close();
            }
          },
        },
      },
      dialog,
    );
    document.body.append(this.layer);
    this.render();
    this.input.focus();
    this.input.select();
  }

  close({ restoreFocus = true } = {}) {
    if (!this.layer) return;
    this.layer.remove();
    this.layer = null;
    const opener = this.opener;
    this.opener = null;
    if (restoreFocus && opener && document.contains(opener) && typeof opener.focus === 'function') {
      opener.focus({ preventScroll: true });
    }
    if (this.onClose) this.onClose();
  }

  /** The rows to show, in order: [{ item, tier, hits, heading }]. */
  compute(text) {
    let query = text.trim();
    let items = this.items;
    const actionsOnly = query.startsWith('>');
    if (actionsOnly) {
      query = query.slice(1).trim();
      items = items.filter((it) => it.group === 'Actions');
    }
    if (!query) return this.idleRows(items, actionsOnly);
    let lookups = [];
    if (this.getLookups && !actionsOnly) {
      try {
        lookups = (this.getLookups(query) || []).map((item) => ({ item, tier: null, hits: [], heading: 'Look up' }));
      } catch (err) {
        console.error(err);
      }
    }
    const ranked = rank(items, query, { recent: this.recent }).slice(0, MAX_RESULTS);
    let best = ranked.filter((r) => r.tier === 0);
    if (!best.length) best = ranked.filter((r) => r.tier === 1).slice(0, BEST_PREFIX);
    const inBest = new Set(best);
    const rows = best.map((r) => ({ ...r, heading: 'Best match' }));
    rows.push(...lookups);
    const rest = ranked.filter((r) => !inBest.has(r));
    for (const g of GROUP_ORDER) {
      for (const r of rest) if (r.item.group === g) rows.push({ ...r, heading: g });
    }
    for (const r of rest) if (!GROUP_ORDER.includes(r.item.group)) rows.push({ ...r, heading: r.item.group || 'Other' });
    return rows;
  }

  /** No query: what was run or filtered recently, then views, scopes and actions. */
  idleRows(items, actionsOnly) {
    const shown = items.filter((it) => it.featured !== false);
    const byId = new Map();
    for (const it of shown) if (it.id && !byId.has(it.id)) byId.set(it.id, it);
    const recent = [];
    for (const id of this.recent) {
      const it = byId.get(id);
      if (it && !recent.includes(it)) recent.push(it);
    }
    const filters = shown
      .filter((it) => Number.isFinite(it.recentRank))
      .sort((a, b) => a.recentRank - b.recentRank);
    for (const it of filters) if (!recent.includes(it)) recent.push(it);
    const top = recent.slice(0, MAX_RECENT);
    const rows = top.map((item) => ({ item, tier: null, hits: [], heading: 'Recent' }));
    const taken = new Set(top);
    for (const g of actionsOnly ? ['Actions'] : ['Views', 'Scopes', 'Actions']) {
      for (const it of shown) if (it.group === g && !taken.has(it)) rows.push({ item: it, tier: null, hits: [], heading: g });
    }
    return rows;
  }

  render() {
    const text = this.input.value;
    this.results = this.compute(text);
    this.active = this.results.length ? 0 : -1;
    const nodes = [];
    let heading = null;
    this.results.forEach((row, i) => {
      const it = row.item;
      if (row.heading !== heading) {
        heading = row.heading;
        nodes.push(h('div', { class: ['pal-group', heading === 'Best match' && 'best'], role: 'presentation' }, heading));
      }
      const marks = marksFor(row, text.trim().startsWith('>') ? text.trim().slice(1) : text);
      const label = String(it.label ?? '');
      const detail = it.detail ? String(it.detail) : '';
      nodes.push(
        h(
          'div',
          {
            class: 'pal-item',
            id: `${this.id}-opt-${i}`,
            role: 'option',
            'aria-selected': i === this.active ? 'true' : 'false',
            'aria-label': detail ? `${plain(label, { all: true })}, ${plain(detail, { all: true })}` : plain(label, { all: true }),
            dataset: { index: i },
            on: {
              mousemove: () => this.setActive(i, false),
              mousedown: (e) => e.preventDefault(),
              click: () => this.run(i),
            },
          },
          icon(it.icon || 'arrow'),
          h('span', { class: 'pal-label dev-text' }, vis(label, { all: true, marks: marks.label })),
          detail ? h('span', { class: 'pal-detail dev-text' }, vis(detail, { all: true, marks: marks.detail })) : null,
          it.hint ? h('span', { class: 'pal-hint', 'aria-hidden': 'true' }, it.hint.map((k) => h('kbd', null, k))) : null,
        ),
      );
    });
    if (!nodes.length) {
      nodes.push(h('div', { class: 'pal-empty' }, 'No match. Try a view, a policy, zone, address or application name, an address, a port or a session id, or ">" for actions.'));
    }
    this.list.replaceChildren(...nodes);
    this.syncActive();
  }

  setActive(i, scroll = true) {
    if (i === this.active) return;
    this.active = i;
    this.syncActive(scroll);
  }

  syncActive(scroll = true) {
    for (const el of this.list.querySelectorAll('.pal-item')) {
      el.setAttribute('aria-selected', Number(el.dataset.index) === this.active ? 'true' : 'false');
    }
    if (this.active >= 0) {
      this.input.setAttribute('aria-activedescendant', `${this.id}-opt-${this.active}`);
      const el = this.list.querySelector(`[data-index="${this.active}"]`);
      if (el && scroll) el.scrollIntoView({ block: 'nearest' });
    } else {
      this.input.removeAttribute('aria-activedescendant');
    }
  }

  /** Remember an item as just run (memory only). */
  noteRun(id) {
    if (!id) return;
    this.recent = [id, ...this.recent.filter((x) => x !== id)].slice(0, MRU_SIZE);
  }

  run(i) {
    const row = this.results[i];
    if (!row) return;
    const it = row.item;
    this.noteRun(it.id);
    this.close({ restoreFocus: !it.keepFocus });
    try {
      it.run();
    } catch (err) {
      console.error(err);
    }
  }

  onKey(e) {
    const n = this.results.length;
    if (e.key === 'ArrowDown' || (e.key === 'n' && e.ctrlKey)) {
      e.preventDefault();
      if (n) this.setActive((this.active + 1) % n);
    } else if (e.key === 'ArrowUp' || (e.key === 'p' && e.ctrlKey)) {
      e.preventDefault();
      if (n) this.setActive((this.active - 1 + n) % n);
    } else if (e.key === 'PageDown') {
      e.preventDefault();
      if (n) this.setActive(Math.min(n - 1, this.active + 8));
    } else if (e.key === 'PageUp') {
      e.preventDefault();
      if (n) this.setActive(Math.max(0, this.active - 8));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      this.run(this.active);
    } else if (e.key === 'Escape') {
      e.preventDefault();
      e.stopPropagation();
      this.close();
    } else if (e.key === 'Tab') {
      e.preventDefault();
    }
  }
}
