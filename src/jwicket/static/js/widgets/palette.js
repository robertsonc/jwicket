// widgets/palette.js: the Ctrl/Cmd-K command palette. Keyboard-first fuzzy search over items the
// shell supplies (views, actions, scopes, policies, zones, recent filters).
//
//   const pal = new Palette({ getItems: () => [{ group, label, detail, hint: ['g','o'], icon, keywords, run }] });
//   pal.open(); pal.close(); pal.isOpen
//
// A leading ">" searches actions only.

import { h, icon, marked } from '../dom.js';

const SEPARATORS = new Set([' ', '-', '_', '.', ':', '/', '>', '@', '(', '→', '|']);

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

let seq = 0;

export class Palette {
  constructor({ getItems, placeholder = 'Search views, policies, zones and actions…', onClose } = {}) {
    this.getItems = getItems;
    this.onClose = onClose;
    this.placeholder = placeholder;
    this.results = [];
    this.active = 0;
    this.opener = null;
    this.layer = null;
    this.id = `pal-${(seq += 1)}`;
  }

  get isOpen() {
    return Boolean(this.layer);
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
      'aria-label': 'Search views, policies, zones and actions',
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

  compute(text) {
    let query = text.trim();
    let items = this.items;
    if (query.startsWith('>')) {
      query = query.slice(1).trim();
      items = items.filter((it) => it.group === 'Actions');
    }
    if (!query) {
      return items.filter((it) => it.featured !== false && ['Recent filters', 'Views', 'Actions', 'Scopes'].includes(it.group));
    }
    const scored = [];
    for (const it of items) {
      const main = fuzzy(query, it.label);
      let score = main ? main.score : -Infinity;
      let hits = main ? main.hits : [];
      if (!main) {
        const extra = fuzzy(query, `${it.detail || ''} ${it.keywords || ''}`);
        if (extra) {
          score = extra.score * 0.55;
          hits = [];
        }
      }
      if (score > -Infinity) scored.push({ ...it, score: score + (it.boost || 0), hits });
    }
    scored.sort((a, b) => b.score - a.score);
    const top = scored.slice(0, 60);
    // Groups in order of their best match; items keep score order within a group.
    const order = [];
    for (const it of top) if (!order.includes(it.group)) order.push(it.group);
    return order.flatMap((g) => top.filter((it) => it.group === g));
  }

  render() {
    this.results = this.compute(this.input.value);
    this.active = this.results.length ? 0 : -1;
    const nodes = [];
    let group = null;
    this.results.forEach((it, i) => {
      if (it.group !== group) {
        group = it.group;
        nodes.push(h('div', { class: 'pal-group', role: 'presentation' }, group));
      }
      nodes.push(
        h(
          'div',
          {
            class: 'pal-item',
            id: `${this.id}-opt-${i}`,
            role: 'option',
            'aria-selected': i === this.active ? 'true' : 'false',
            dataset: { index: i },
            on: {
              mousemove: () => this.setActive(i, false),
              mousedown: (e) => e.preventDefault(),
              click: () => this.run(i),
            },
          },
          icon(it.icon || 'arrow'),
          h('span', { class: 'pal-label' }, marked(it.label, it.hits, null)),
          it.detail ? h('span', { class: 'pal-detail' }, it.detail) : null,
          it.hint ? h('span', { class: 'pal-hint', 'aria-hidden': 'true' }, it.hint.map((k) => h('kbd', null, k))) : null,
        ),
      );
    });
    if (!nodes.length) {
      nodes.push(h('div', { class: 'pal-empty' }, 'No match. Try a view, a policy or zone name, or ">" for actions.'));
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

  run(i) {
    const it = this.results[i];
    if (!it) return;
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
