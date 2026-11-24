// views/objects.js: zones, address books and applications of the current scope (UI brief, section 7).
//
// Three tabs over one inventory snapshot, each with the shared query language (query.js parse /
// validate / compile) over keys defined here, a table and a detail panel:
// * Zones: interfaces, host-inbound traffic at zone and interface level (interface settings take
//   precedence for that interface), screen, provenance, the zone pairs that use the zone.
// * Address books: books with their attachment (zones, global, legacy zone book), addresses and
//   sets, set expansion, which policies use each entry (directly or through a set), provenance.
// * Applications: custom applications and sets, members expanded, which policies use them.
// Every panel is device data or an explicit state. Nothing read from the device is stored.

import {
  qv,
  cliBlock,
  cliPrefix,
  cliWord,
  markNodes,
  provBadges,
  scopeTitle,
  scopeParts,
  subLine,
  inventoryState,
  pairKey,
} from './policies.js';

const ICON = 'M12 3.2l7.8 4.4v8.8L12 20.8l-7.8-4.4V7.6z M4.4 7.7L12 12l7.6-4.3 M12 12v8.6';
const SEP = ' · ';
const ARROW = '→';
const PAGE = 400;
const AGE_TICK_MS = 30000;

const TABS = [
  { id: 'zones', label: 'Zones', icon: 'zone', noun: 'zone' },
  { id: 'address-books', label: 'Address books', icon: 'globe', noun: 'entry', plural: 'entries' },
  { id: 'applications', label: 'Applications', icon: 'bolt', noun: 'application' },
];
const TAB_IDS = TABS.map((t) => t.id);

export const view = {
  id: 'objects',
  title: 'Objects',
  icon: ICON,
  mount(el, ctx) {
    const v = new ObjectsView(el, ctx);
    return { update: (route) => v.update(route), unmount: () => v.destroy() };
  },
};

// ---- helpers -------------------------------------------------------------------------------------

const uniq = (list) => [...new Set(list.filter((x) => x !== null && x !== undefined && x !== ''))];

function topValues(items, get, limit = 40) {
  const counts = new Map();
  for (const it of items.slice(0, 5000)) {
    let vs;
    try {
      vs = get(it);
    } catch (_err) {
      continue;
    }
    for (const v of Array.isArray(vs) ? vs : [vs]) {
      if (v === null || v === undefined || v === '') continue;
      counts.set(String(v), (counts.get(String(v)) || 0) + 1);
    }
  }
  return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, limit).map(([v]) => v);
}

/** A searchable item: `toJSON` gives the free-text haystack the query engine reads. */
function item(fields) {
  const text = fields._text;
  delete fields._text;
  Object.defineProperty(fields, 'toJSON', { value: () => text, enumerable: false });
  return fields;
}

const yesNo = (b) => (b ? ['yes', 'true'] : ['no', 'false']);
// No group, nothing inherited, active: provenance says "direct", which a compact card leaves out.
const isDirect = (o) => !o.group && !(o.inherited || []).length && !o.inactive;
const MD_MQ = '(min-width: 1280px)'; // Zones: list and detail side by side

const FIELDS = {
  zones: {
    name: { aliases: ['zone'], type: 'text', label: 'zone name', get: (r) => r.z.name, values: (rows) => topValues(rows, (r) => r.z.name) },
    iface: { aliases: ['interface', 'if'], type: 'text', label: 'interface in the zone', get: (r) => (r.z.interfaces || []).map((i) => i.name), values: (rows) => topValues(rows, (r) => (r.z.interfaces || []).map((i) => i.name)) },
    service: {
      aliases: ['services', 'system-services', 'svc'],
      type: 'text',
      label: 'host-inbound system service (zone or interface)',
      get: (r) => uniq([...(r.z.services || []), ...(r.z.interfaces || []).flatMap((i) => i.services || [])]),
      values: (rows) => topValues(rows, (r) => [...(r.z.services || []), ...(r.z.interfaces || []).flatMap((i) => i.services || [])]),
    },
    proto: {
      aliases: ['protocol', 'protocols'],
      type: 'text',
      label: 'host-inbound protocol (zone or interface)',
      get: (r) => uniq([...(r.z.protocols || []), ...(r.z.interfaces || []).flatMap((i) => i.protocols || [])]),
      values: (rows) => topValues(rows, (r) => [...(r.z.protocols || []), ...(r.z.interfaces || []).flatMap((i) => i.protocols || [])]),
    },
    screen: { aliases: ['ids'], type: 'text', label: 'screen profile', get: (r) => r.z.screen || 'none', values: (rows) => topValues(rows, (r) => r.z.screen || 'none') },
    group: { aliases: ['groups'], type: 'text', label: 'configuration group (zone or interface)', get: (r) => uniq([r.z.group, ...(r.z.interfaces || []).map((i) => i.group)]), values: (rows) => topValues(rows, (r) => [r.z.group, ...(r.z.interfaces || []).map((i) => i.group)]) },
    inactive: { aliases: ['disabled'], type: 'enum', label: 'yes or no', get: (r) => yesNo(r.z.inactive), values: () => ['yes', 'no'] },
    policies: { aliases: ['used'], type: 'int', label: 'number of policies naming the zone', get: (r) => String(r.policyCount) },
    desc: { aliases: ['description'], type: 'text', contains: true, label: 'description (substring)', get: (r) => r.z.description },
  },
  'address-books': {
    name: { aliases: ['address', 'entry'], type: 'text', label: 'address or address-set name', get: (r) => r.name, values: (rows) => topValues(rows, (r) => r.name) },
    book: { aliases: ['address-book'], type: 'text', label: 'address book', get: (r) => r.book.name, values: (rows) => topValues(rows, (r) => r.book.name) },
    kind: { aliases: ['type'], type: 'enum', label: 'prefix, range, dns, wildcard or set', get: (r) => r.kind, values: (rows) => topValues(rows, (r) => r.kind) },
    addr: { aliases: ['ip', 'value', 'prefix'], type: 'ip', label: 'address value, CIDR-aware (sets: their members)', get: (r) => r.values },
    member: { aliases: ['members', 'contains'], type: 'text', label: 'member of a set (address or nested set)', get: (r) => r.members, values: (rows) => topValues(rows, (r) => r.members) },
    zone: { aliases: ['attach', 'attached'], type: 'text', label: 'zone the book is attached to ("global" for the global book)', get: (r) => r.zones, values: (rows) => topValues(rows, (r) => r.zones) },
    used: { aliases: ['in-use'], type: 'enum', label: 'used by a policy: yes or no', get: (r) => yesNo(r.usedCount > 0), values: () => ['yes', 'no'] },
    group: { aliases: ['groups'], type: 'text', label: 'configuration group', get: (r) => uniq([r.entry.group, r.book.group]), values: (rows) => topValues(rows, (r) => [r.entry.group, r.book.group]) },
    inactive: { aliases: ['disabled'], type: 'enum', label: 'yes or no', get: (r) => yesNo(r.entry.inactive || r.book.inactive), values: () => ['yes', 'no'] },
    desc: { aliases: ['description'], type: 'text', contains: true, label: 'description (substring)', get: (r) => r.entry.description },
  },
  applications: {
    name: { aliases: ['application', 'app'], type: 'text', label: 'application or set name', get: (r) => r.a.name, values: (rows) => topValues(rows, (r) => r.a.name) },
    kind: { aliases: ['type'], type: 'enum', label: 'application or set', get: (r) => r.a.kind, values: () => ['application', 'set'] },
    proto: { aliases: ['protocol'], type: 'text', label: 'protocol (sets: their members)', get: (r) => r.protocols, values: (rows) => topValues(rows, (r) => r.protocols) },
    port: { aliases: ['dport', 'destination-port'], type: 'int', label: 'destination port or range (sets: their members)', get: (r) => r.ports },
    sport: { aliases: ['source-port'], type: 'int', label: 'source port', get: (r) => r.a.source_port },
    member: { aliases: ['members', 'contains'], type: 'text', label: 'member of a set (application or nested set)', get: (r) => [...(r.a.members || []), ...(r.a.sets || [])], values: (rows) => topValues(rows, (r) => [...(r.a.members || []), ...(r.a.sets || [])]) },
    used: { aliases: ['in-use'], type: 'enum', label: 'used by a policy: yes or no', get: (r) => yesNo(r.usedCount > 0), values: () => ['yes', 'no'] },
    group: { aliases: ['groups'], type: 'text', label: 'configuration group', get: (r) => r.a.group, values: (rows) => topValues(rows, (r) => r.a.group) },
    inactive: { aliases: ['disabled'], type: 'enum', label: 'yes or no', get: (r) => yesNo(r.a.inactive), values: () => ['yes', 'no'] },
    desc: { aliases: ['description'], type: 'text', contains: true, label: 'description (substring)', get: (r) => r.a.description },
  },
};

const EXAMPLES = {
  zones: ['service:ssh', 'iface:ge-0/0/0.0', 'service:all|telnet|http', 'screen:none', 'policies:0'],
  'address-books': ['addr:10.20.0.0/24', 'kind:set', 'used:no', 'zone:dmz', 'member:web1'],
  applications: ['port:443', 'proto:udp', 'kind:set', 'used:no', 'member:junos-https'],
};

const OPS_FOR = { int: [':', '>=', '<=', '>', '<', '!='], ip: [':', '!='], text: [':', '!=', '~'], enum: [':', '!='] };

function quoteIfNeeded(v) {
  return /[\s()"'|]/.test(v) ? `"${v.replace(/"/g, '\\"')}"` : v;
}

/** Autocomplete over this view's keys: same shape as query.suggest(). */
function suggestFor(text, caret, fields, rows, examples, all) {
  const s = String(text || '');
  const at = Math.max(0, Math.min(caret ?? s.length, s.length));
  let start = at;
  while (start > 0 && !/[\s()]/.test(s[start - 1])) start -= 1;
  let end = at;
  while (end < s.length && !/[\s)]/.test(s[end])) end += 1;
  let from = start;
  while (from < at && (s[from] === '-' || s[from] === '!')) from += 1;
  const frag = s.slice(from, at);
  const out = [];
  const km = /^([A-Za-z_][\w.-]*)(!=|>=|<=|=|>|<|~|:)(.*)$/s.exec(frag);
  const resolve = (k) => {
    const low = String(k).toLowerCase();
    for (const [name, def] of Object.entries(fields)) if (name === low || (def.aliases || []).includes(low)) return { name, def };
    return null;
  };
  if (km) {
    const hit = resolve(km[1]);
    if (!hit) return [];
    const head = `${km[1]}${km[2]}`;
    const lastPipe = km[3].lastIndexOf('|');
    const prior = lastPipe >= 0 ? km[3].slice(0, lastPipe + 1) : '';
    const typed = (lastPipe >= 0 ? km[3].slice(lastPipe + 1) : km[3]).replace(/^"/, '').toLowerCase();
    let values = [];
    try {
      values = hit.def.values ? hit.def.values(rows) : [];
    } catch (_err) {
      values = [];
    }
    const ranked = [];
    for (const v of values) {
      const low = String(v).toLowerCase();
      if (typed && low === typed) continue;
      if (!typed || low.startsWith(typed)) ranked.push([0, v]);
      else if (low.includes(typed)) ranked.push([1, v]);
    }
    ranked.sort((a, b) => a[0] - b[0]);
    for (const [, v] of ranked.slice(0, 12)) out.push({ label: String(v), insert: `${head}${prior}${quoteIfNeeded(String(v))}`, detail: hit.def.label, kind: 'value', from, to: end });
    return out;
  }
  if (!s.trim()) {
    for (const ex of examples) out.push({ label: ex, insert: ex, detail: 'example', kind: 'example', from: 0, to: s.length });
    return out;
  }
  const low = frag.toLowerCase();
  if (!low && !all) return out;
  const exact = resolve(low);
  if (exact && exact.name === low) {
    for (const op of OPS_FOR[exact.def.type] || [':']) out.push({ label: `${frag}${op}`, insert: `${frag}${op}`, detail: exact.def.label, kind: 'op', from, to: end });
  }
  for (const [name, def] of Object.entries(fields)) {
    if (exact && exact.name === name && name === low) continue;
    const matched = name.startsWith(low) ? name : low.length >= 2 ? (def.aliases || []).find((a) => a.startsWith(low)) : null;
    if (!matched) continue;
    out.push({ label: `${name}:`, insert: `${name}:`, detail: `${def.label}${matched !== name ? ` (alias ${matched})` : ''}`, kind: 'key', from, to: end });
  }
  if (low.length >= 2) {
    for (const [name, def] of Object.entries(fields)) {
      if (!def.values || out.length >= 14) continue;
      let values = [];
      try {
        values = def.values(rows);
      } catch (_err) {
        continue;
      }
      for (const v of values) {
        const sv = String(v);
        if (!sv.toLowerCase().includes(low)) continue;
        out.push({ label: `${name}:${sv}`, insert: `${name}:${quoteIfNeeded(sv)}`, detail: def.label, kind: 'value', from, to: end });
        if (out.length >= 14) break;
      }
    }
  }
  if (low && start > 0) {
    for (const kw of ['AND', 'OR', 'NOT']) if (kw.toLowerCase().startsWith(low) && kw.toLowerCase() !== low) out.push({ label: kw, insert: kw, detail: 'operator', kind: 'keyword', from, to: end });
  }
  return out.slice(0, 14);
}

/**
 * The shared QueryBar with this view's keys: autocomplete and the key help come from FIELDS here
 * (query.js has none for objects). Parse errors are the bar's own; key and value errors come from
 * query.validate() through setError().
 */
function makeBar(ctx, tab, getRows) {
  const Base = ctx.QueryBar;
  if (!Base || !ctx.query) return null;
  const fields = FIELDS[tab];
  const examples = EXAMPLES[tab];
  const canOverride = typeof Base.prototype._renderList === 'function' && typeof Base.prototype._openList === 'function';
  class ObjectsBar extends Base {
    _suggest(all) {
      if (!canOverride || !this.input) {
        super._suggest(all);
        return;
      }
      if (document.activeElement !== this.input) return;
      super._suggest(all); // saved queries (when the bar is empty) come from the base class
      const saved = (this._items || []).filter((i) => i.kind === 'saved');
      const caret = this.input.selectionStart ?? this._text.length;
      let mine = [];
      try {
        mine = suggestFor(this._text, caret, fields, getRows(), examples, all);
      } catch (_err) {
        mine = [];
      }
      this._items = [...saved, ...mine.filter((m) => !saved.some((x) => x.insert === m.insert))].slice(0, 14);
      this._active = -1;
      if (!this._items.length) {
        this._closeList();
        return;
      }
      this._renderList();
      this._openList();
    }

    _buildHelp() {
      if (!canOverride) {
        super._buildHelp();
        return;
      }
      const { h } = ctx.dom;
      const rows = [
        ['key:value', 'match a field (case-insensitive, * wildcards)'],
        ['key!=v  -key:v  NOT x', 'exclude'],
        ['a b  a AND b', 'both'],
        ['a OR b  (a b) OR c', 'either, grouped'],
        ['key:v1|v2', 'any of these values'],
        ['addr:10.20.0.0/16', 'addresses are CIDR-aware'],
        ['port:8000-8100  port>=1024', 'port numbers and ranges'],
        ['"two words"  /re/i  key~re', 'phrase, regular expression'],
      ];
      const tryBtn = (e) =>
        h('button', {
          class: 'qb-help-try',
          type: 'button',
          on: {
            click: () => {
              this._replace(e, e.length);
              this._toggleHelp(false);
              this.input.focus();
              this._emit(true);
            },
          },
        }, e);
      this.help.append(
        h('div', { class: 'qb-help-ops' }, h('h3', { class: 'qb-help-h' }, 'Syntax'), h('dl', { class: 'qb-help-dl' }, rows.map(([k, v]) => [h('dt', null, k), h('dd', null, v)]))),
        h(
          'div',
          { class: 'qb-help-keys' },
          h('h3', { class: 'qb-help-h' }, `Keys for ${TABS.find((t) => t.id === tab).label.toLowerCase()}`),
          h('ul', { class: 'qb-help-keylist' }, Object.entries(fields).map(([k, d]) => h('li', { title: (d.aliases || []).length ? `Also: ${d.aliases.join(', ')}` : null }, h('code', { class: 'qb-help-key' }, k), h('span', { class: 'qb-help-label' }, d.label)))),
        ),
        h('div', { class: 'qb-help-ex' }, h('h3', { class: 'qb-help-h' }, 'Try'), examples.map(tryBtn)),
        h('p', { class: 'qb-help-note' }, 'Everything here is filtered in this browser over the configuration J-Wicket read.'),
      );
    }
  }
  return { Bar: ObjectsBar, fields };
}

// ---- index: who uses what ------------------------------------------------------------------------

function buildIndex(snap) {
  const scope = snap.scope;
  const pol = scope.policies && scope.policies.status === 'ok' ? scope.policies.rows || [] : [];
  const polOk = Boolean(scope.policies && scope.policies.status === 'ok');
  const books = scope.address_books && scope.address_books.status === 'ok' ? scope.address_books.rows || [] : [];
  const apps = scope.applications && scope.applications.status === 'ok' ? scope.applications.rows || [] : [];
  const zones = scope.zones && scope.zones.status === 'ok' ? scope.zones.rows || [] : [];
  const addrDirect = new Map(); // "book|name" -> Set(policy idx)
  const appDirect = new Map(); // name -> Set(policy idx)
  const add = (map, key, idx) => {
    if (!map.has(key)) map.set(key, new Set());
    map.get(key).add(idx);
  };
  pol.forEach((r, idx) => {
    const res = r.resolved || {};
    for (const side of ['source', 'destination']) for (const it of res[side] || []) if (it.book) add(addrDirect, `${it.book}|${it.name}`, idx);
    for (const it of res.application || []) if (it.kind === 'application' || it.kind === 'set') add(appDirect, it.name, idx);
  });
  // set closures (within a book; within the scope's applications)
  const bookSets = new Map();
  for (const b of books) {
    const sets = new Map((b.sets || []).map((s) => [s.name, s]));
    const closure = new Map();
    const close = (name, seen) => {
      if (closure.has(name)) return closure.get(name);
      const out = new Set();
      const s = sets.get(name);
      if (s && !seen.has(name)) {
        seen.add(name);
        for (const a of s.addresses || []) out.add(a);
        for (const n of s.sets || []) {
          out.add(n);
          for (const x of close(n, seen)) out.add(x);
        }
      }
      closure.set(name, out);
      return out;
    };
    for (const name of sets.keys()) close(name, new Set());
    bookSets.set(b.name, { sets, closure });
  }
  const appByName = new Map(apps.map((a) => [a.name, a]));
  const appClosure = new Map();
  const closeApp = (name, seen) => {
    if (appClosure.has(name)) return appClosure.get(name);
    const out = new Set();
    const a = appByName.get(name);
    if (a && a.kind === 'set' && !seen.has(name)) {
      seen.add(name);
      for (const m of a.members || []) {
        out.add(m);
        for (const x of closeApp(m, seen)) out.add(x);
      }
      for (const n of a.sets || []) {
        out.add(n);
        for (const x of closeApp(n, seen)) out.add(x);
      }
    }
    appClosure.set(name, out);
    return out;
  };
  for (const a of apps) closeApp(a.name, new Set());

  /** {direct:[idx], via:[{idx, set}]} for an address-book entry. */
  const addrUse = (bookName, name) => {
    const direct = [...(addrDirect.get(`${bookName}|${name}`) || [])];
    const via = [];
    const bs = bookSets.get(bookName);
    if (bs) {
      for (const [setName, members] of bs.closure) {
        if (!members.has(name)) continue;
        for (const idx of addrDirect.get(`${bookName}|${setName}`) || []) if (!direct.includes(idx) && !via.some((v) => v.idx === idx)) via.push({ idx, set: setName });
      }
    }
    return { direct, via };
  };
  const appUse = (name) => {
    const direct = [...(appDirect.get(name) || [])];
    const via = [];
    for (const [setName, members] of appClosure) {
      if (!members.has(name)) continue;
      for (const idx of appDirect.get(setName) || []) if (!direct.includes(idx) && !via.some((v) => v.idx === idx)) via.push({ idx, set: setName });
    }
    return { direct, via };
  };
  const zoneNames = zones.map((z) => z.name);
  const zoneUse = (z) => {
    const pairs = new Map();
    const globals = [];
    pol.forEach((r, idx) => {
      if (r.kind === 'global') {
        const f = r.from || [];
        const t = r.to || [];
        if (!f.length || f.includes(z) || !t.length || t.includes(z)) globals.push(idx);
        return;
      }
      const from = (r.from || [])[0];
      const to = (r.to || [])[0];
      if (from !== z && to !== z) return;
      const key = pairKey(from, to);
      if (!pairs.has(key)) pairs.set(key, { from, to, idxs: [] });
      pairs.get(key).idxs.push(idx);
    });
    let count = 0;
    for (const p of pairs.values()) count += p.idxs.length;
    return { pairs: [...pairs.values()], globals, count };
  };
  return { scope, pol, polOk, books, apps, zones, zoneNames, bookSets, appByName, appClosure, addrUse, appUse, zoneUse };
}

// ---- the view ------------------------------------------------------------------------------------

class ObjectsView {
  constructor(el, ctx) {
    this.el = el;
    this.ctx = ctx;
    this.h = ctx.dom.h;
    this.fmt = ctx.format;
    this.Q = ctx.query || null;
    this.dead = false;
    this.snap = null;
    this.idx = null;
    this.receivedAt = 0;
    this.tab = 'zones';
    this.texts = { zones: '', 'address-books': '', applications: '' };
    this.asts = { zones: null, 'address-books': null, applications: null };
    this.items = { zones: [], 'address-books': [], applications: [] };
    this.limit = PAGE;
    this.sel = null;
    this.wantSel = null;
    this.cursor = -1;
    this.visible = [];
    this.panelToken = 0;
    this.panelOpen = false;
    this.bars = {};
    this.build();
    this.offs = [ctx.store.on('inventory', (snap) => this.onInventory(snap)), ctx.store.on('scope', () => this.onScope())];
    this.onKeyBound = (e) => this.onKey(e);
    document.addEventListener('keydown', this.onKeyBound);
    this.ageTimer = setInterval(() => this.renderSub(), AGE_TICK_MS);
    this.mdSel = null;
    this.mdPane = null;
    this.mqMD = typeof window.matchMedia === 'function' ? window.matchMedia(MD_MQ) : null;
    this.onMD = () => this.onMDChange();
    if (this.mqMD && this.mqMD.addEventListener) this.mqMD.addEventListener('change', this.onMD);
    this.readRoute(ctx.route, true);
    this.load(false);
  }

  // ---- lifecycle -------------------------------------------------------------------------------

  load(force) {
    const store = this.ctx.store;
    const scope = store.scope;
    const cached = store.lastInventory;
    if (!force && cached && cached.meta && cached.meta.scope === scope) this.onInventory(cached);
    else if (!this.snap) this.renderLoading();
    store.inventory(force).then((snap) => {
      if (this.dead || store.scope !== scope) return;
      if (snap) this.onInventory(snap);
      else this.renderFailed();
    });
  }

  onInventory(snap) {
    if (this.dead || !snap || snap === this.snap) return;
    if (snap.meta && snap.meta.scope && snap.meta.scope !== this.ctx.store.scope) return;
    this.snap = snap;
    this.receivedAt = Date.now();
    this.ctx.ui.noteFixture(snap.meta);
    this.render();
  }

  onScope() {
    if (this.dead) return;
    if (this.panelOpen) this.ctx.ui.closePanel();
    this.snap = null;
    this.idx = null;
    this.sel = null;
    this.mdSel = null;
    this.wantSel = null;
    this.cursor = -1;
    this.load(false);
  }

  update(route) {
    this.readRoute(route, false);
  }

  destroy() {
    this.dead = true;
    clearInterval(this.ageTimer);
    for (const off of this.offs) off();
    document.removeEventListener('keydown', this.onKeyBound);
    if (this.mqMD && this.mqMD.removeEventListener) this.mqMD.removeEventListener('change', this.onMD);
    for (const b of Object.values(this.bars)) if (b) b.destroy();
  }

  /** Zones at 1280 px and wider: the list and one zone's detail side by side (no overlay). */
  isMD() {
    return this.tab === 'zones' && Boolean(this.mqMD && this.mqMD.matches);
  }

  onMDChange() {
    if (this.dead || !this.idx || this.tab !== 'zones') return;
    const zoneSel = this.sel && String(this.sel).startsWith('zone|') ? this.sel : null;
    if (this.isMD()) {
      // Overlay -> pane: keep the zone that was open.
      if (this.panelOpen && zoneSel) {
        this.ctx.ui.closePanel();
        this.sel = zoneSel;
        this.mdSel = zoneSel;
        this.saveRoute(false);
      }
    } else if (zoneSel && !this.panelOpen) {
      // Pane -> narrow: the zone is no longer shown; drop it from the address.
      this.sel = null;
      this.mdSel = null;
      this.saveRoute(false);
    }
    this.renderTab();
  }

  readRoute(route, first) {
    const p = route && route.params ? route.params : new URLSearchParams();
    const tab = TAB_IDS.includes(p.get('tab')) ? p.get('tab') : 'zones';
    const q = p.get('q') || '';
    const sel = p.get('sel') || null;
    const tabChanged = tab !== this.tab;
    if (first || tabChanged) this.showTab(tab, { save: false });
    if (first || tabChanged || q !== this.texts[tab]) this.setText(tab, q, { save: false });
    if (sel !== this.sel) {
      if (sel) {
        this.wantSel = sel;
        this.tryOpenWanted();
      } else if (this.panelOpen) {
        this.sel = null;
        this.ctx.ui.closePanel();
      } else if (this.isMD() && this.sel) {
        // Back to a link without a zone: the pane shows the first zone again.
        this.sel = null;
        this.mdSel = null;
        if (this.idx) this.renderTab();
      }
    }
  }

  saveRoute(push = false) {
    this.ctx.setParams({ tab: this.tab === 'zones' ? null : this.tab, q: this.texts[this.tab] || null, sel: this.sel || null }, { replace: !push });
  }

  // ---- frame -----------------------------------------------------------------------------------

  build() {
    const { h } = this;
    const { icon } = this.ctx.dom;
    this.el.classList.add('pv-view', 'ob-view');
    this.subEl = h('p', { class: 'view-sub pv-sub' }, 'Reading the configuration…');
    this.refreshBtn = h(
      'button',
      { class: 'btn', type: 'button', title: 'Read the configuration again (r)', on: { click: () => this.refresh() } },
      icon('refresh'),
      h('span', { class: 'pv-hide-sm' }, 'Refresh'),
    );
    const head = h(
      'div',
      { class: 'view-head pv-head' },
      h('div', { class: 'pv-titles' }, h('h1', { class: 'view-title' }, 'Objects'), this.subEl),
      h('div', { class: 'view-actions' }, this.refreshBtn),
    );
    this.tabBtns = new Map();
    this.tablist = h(
      'div',
      { class: 'ob-tabs', role: 'tablist', 'aria-label': 'Object kind', on: { keydown: (e) => this.onTabKey(e) } },
      TABS.map((t) => {
        const count = h('span', { class: 'ob-tab-count' });
        const btn = h(
          'button',
          { class: 'ob-tab', type: 'button', role: 'tab', id: `ob-tab-${t.id}`, 'aria-controls': 'ob-panel', 'aria-selected': 'false', tabindex: '-1', on: { click: () => this.showTab(t.id, { save: true, focus: false }) } },
          icon(t.icon),
          h('span', null, t.label),
          count,
        );
        this.tabBtns.set(t.id, { btn, count });
        return btn;
      }),
    );
    this.noticeEl = h('div', { class: 'pv-notices' });
    this.stateEl = h('div', { class: 'pv-state', hidden: true });
    this.loadingEl = h('div', { class: 'pv-loading' }, this.ctx.dom.skeleton(2), this.ctx.dom.skeleton(5));
    this.introEl = h('p', { class: 'ob-intro' });
    this.qbHost = h('div', { class: 'pv-qb' });
    this.tabStateEl = h('div', { class: 'ob-tabstate', hidden: true });
    this.tableHost = h('div', { class: 'pv-tablehost' });
    this.panelEl = h('div', { class: 'ob-panel', id: 'ob-panel', role: 'tabpanel' }, this.introEl, this.qbHost, this.tabStateEl, this.tableHost);
    this.bodyEl = h('div', { class: 'pv-body', hidden: true }, this.tablist, this.panelEl);
    this.el.append(head, this.noticeEl, this.stateEl, this.loadingEl, this.bodyEl);
    // one query bar per tab, kept so each tab remembers its text and saved queries
    for (const t of TABS) {
      const made = makeBar(this.ctx, t.id, () => this.items[t.id]);
      if (!made) continue;
      const bar = new made.Bar({
        view: t.id === 'address-books' ? 'books' : t.id === 'applications' ? 'apps' : 'zones',
        label: `Filter ${t.label.toLowerCase()}`,
        placeholder: {
          zones: 'Filter zones: service:ssh  iface:ge-0/0/0.0  screen:none  -policies:0',
          'address-books': 'Filter addresses: addr:10.20.0.0/24  kind:set  used:no  zone:dmz',
          applications: 'Filter applications: port:443  proto:udp  kind:set  used:no',
        }[t.id],
        value: '',
        onChange: (text, parsed) => this.onQuery(t.id, text, parsed),
      });
      this.bars[t.id] = bar;
    }
    this.tableHost.addEventListener('click', (e) => this.onTableClick(e));
  }

  refresh() {
    this.ctx.store.inventory(true).then((snap) => {
      if (this.dead) return;
      if (snap) this.ctx.ui.toast('Read the configuration again.', 'ok');
      else this.renderFailed();
    });
  }

  renderLoading() {
    this.loadingEl.hidden = false;
    this.bodyEl.hidden = true;
    this.stateEl.hidden = true;
    this.renderSub();
  }

  renderFailed() {
    if (this.snap && this.snap.meta && this.snap.meta.scope === this.ctx.store.scope) {
      this.renderNotices();
      return;
    }
    const st = inventoryState(this.ctx, null, 'objects', () => this.load(true));
    this.loadingEl.hidden = true;
    this.bodyEl.hidden = true;
    this.ctx.dom.put(this.stateEl, st || this.ctx.dom.stateCard({ status: 'failed', message: 'The inventory could not be read.' }));
    this.stateEl.hidden = false;
    this.renderSub();
  }

  renderSub() {
    if (!this.dead) this.ctx.dom.put(this.subEl, ...subLine(this.ctx, this.snap, this.receivedAt));
  }

  renderNotices() {
    const { h } = this;
    const { icon } = this.ctx.dom;
    const out = [];
    const snap = this.snap;
    const err = this.ctx.store.inventoryError;
    if (snap && err) {
      out.push(h('div', { class: 'pv-notice deny', role: 'status' }, icon('alert'), h('span', null, h('b', null, 'The last read failed. '), `${err.message} This page still shows the read from ${this.fmt.time(snap.meta && snap.meta.read_at)} UTC.`)));
    }
    if (snap && snap.scope && snap.scope.inactive) {
      out.push(h('div', { class: 'pv-notice reject', role: 'note' }, icon('alert'), h('span', null, h('b', null, `${scopeTitle(snap, snap.meta.scope)} is deactivated in the configuration. `), 'Nothing in this scope is in effect.')));
    }
    this.ctx.dom.put(this.noticeEl, ...out);
    this.noticeEl.hidden = !out.length;
  }

  render() {
    const { h } = this;
    this.loadingEl.hidden = true;
    this.renderSub();
    this.renderNotices();
    const st = inventoryState(this.ctx, this.snap, 'objects', () => this.load(true));
    if (st) {
      this.idx = null;
      this.bodyEl.hidden = true;
      this.ctx.dom.put(this.stateEl, h('div', { class: 'pv-statewrap' }, h('p', { class: 'pv-state-what' }, 'The zones, address books and applications of this scope are not shown.'), st));
      this.stateEl.hidden = false;
      if (this.panelOpen) this.ctx.ui.closePanel();
      return;
    }
    this.stateEl.hidden = true;
    this.bodyEl.hidden = false;
    this.idx = buildIndex(this.snap);
    this.buildItems();
    this.renderTabs();
    this.renderTab();
    if (this.panelOpen && this.sel) {
      if (!this.openSel(this.sel, { refresh: true })) this.ctx.ui.closePanel();
    }
    this.tryOpenWanted();
  }

  buildItems() {
    const x = this.idx;
    const zoneItems = x.zones.map((z) => {
      const use = x.zoneUse(z.name);
      return item({
        type: 'zone',
        id: `zone|${z.name}`,
        z,
        policyCount: use.count,
        use,
        _text: [z.name, z.description, z.screen, z.group, ...(z.services || []), ...(z.protocols || []), ...(z.interfaces || []).flatMap((i) => [i.name, ...(i.services || []), ...(i.protocols || []), i.group])].filter(Boolean).join(' '),
      });
    });
    const entryItems = [];
    for (const b of x.books) {
      const zones = b.legacy_zone ? [b.legacy_zone] : (b.attach || []).length ? b.attach : b.name === 'global' ? ['global'] : [];
      const bs = x.bookSets.get(b.name);
      const addrByName = new Map((b.addresses || []).map((a) => [a.name, a]));
      for (const a of b.addresses || []) {
        const use = x.addrUse(b.name, a.name);
        entryItems.push(
          item({
            type: 'addr',
            id: `addr|${b.name}|${a.name}`,
            name: a.name,
            kind: a.kind || 'address',
            book: b,
            entry: a,
            zones,
            values: [a.value, a.name].filter(Boolean),
            members: [],
            use,
            usedCount: use.direct.length + use.via.length,
            _text: [a.name, a.kind, a.value, a.description, a.group, b.name, ...zones].filter(Boolean).join(' '),
          }),
        );
      }
      for (const s of b.sets || []) {
        const closure = bs ? bs.closure.get(s.name) || new Set() : new Set();
        const leafValues = [...closure].map((n) => addrByName.get(n)).filter(Boolean).map((a) => a.value);
        const use = x.addrUse(b.name, s.name);
        entryItems.push(
          item({
            type: 'set',
            id: `set|${b.name}|${s.name}`,
            name: s.name,
            kind: 'set',
            book: b,
            entry: s,
            zones,
            values: [s.name, ...leafValues, ...closure],
            members: [...(s.addresses || []), ...(s.sets || [])],
            closure,
            use,
            usedCount: use.direct.length + use.via.length,
            _text: [s.name, 'set', s.description, s.group, b.name, ...zones, ...(s.addresses || []), ...(s.sets || []), ...leafValues].filter(Boolean).join(' '),
          }),
        );
      }
    }
    const appItems = x.apps.map((a) => {
      const closure = x.appClosure.get(a.name) || new Set();
      const leaves = a.kind === 'set' ? [...closure].map((n) => x.appByName.get(n)).filter((m) => m && m.kind === 'application') : [a];
      const use = x.appUse(a.name);
      return item({
        type: 'app',
        id: `app|${a.name}`,
        a,
        closure,
        protocols: uniq(leaves.map((l) => l.protocol)),
        ports: uniq(leaves.map((l) => l.destination_port)),
        use,
        usedCount: use.direct.length + use.via.length,
        _text: [a.name, a.kind, a.protocol, a.destination_port, a.source_port, a.description, a.group, ...(a.members || []), ...(a.sets || [])].filter(Boolean).join(' '),
      });
    });
    this.items = { zones: zoneItems, 'address-books': entryItems, applications: appItems };
  }

  section(key) {
    const s = this.snap && this.snap.scope;
    return s ? s[{ zones: 'zones', 'address-books': 'address_books', applications: 'applications' }[key]] || {} : {};
  }

  renderTabs() {
    for (const t of TABS) {
      const { btn, count } = this.tabBtns.get(t.id);
      const sec = this.section(t.id);
      count.textContent = sec.status === 'ok' ? this.fmt.num(this.items[t.id].length) : sec.status ? '!' : '';
      count.title = sec.status === 'ok' ? '' : `Not read: ${sec.status}`;
      const on = t.id === this.tab;
      btn.setAttribute('aria-selected', on ? 'true' : 'false');
      btn.tabIndex = on ? 0 : -1;
    }
  }

  showTab(id, { save = true, focus = false } = {}) {
    const tab = TAB_IDS.includes(id) ? id : 'zones';
    const changed = tab !== this.tab;
    this.tab = tab;
    this.limit = PAGE;
    this.cursor = -1;
    this.panelEl.setAttribute('aria-labelledby', `ob-tab-${tab}`);
    const bar = this.bars[tab];
    this.ctx.dom.put(this.qbHost, bar ? bar.el : null);
    const intro = {
      zones: 'Each zone’s interfaces, and what the firewall itself answers on them (host-inbound system services and protocols, at zone and interface level).',
      'address-books': 'Address books, the zones they are attached to, their addresses and address sets, and the policies that use each entry.',
      applications: 'Custom applications and application sets of this scope. Predefined junos-* applications come from junos-defaults and are not expanded.',
    }[tab];
    this.introEl.textContent = intro;
    if (this.idx) {
      this.renderTabs();
      this.renderTab();
    } else {
      for (const t of TABS) {
        const { btn } = this.tabBtns.get(t.id);
        btn.setAttribute('aria-selected', t.id === tab ? 'true' : 'false');
        btn.tabIndex = t.id === tab ? 0 : -1;
      }
    }
    if (focus) this.tabBtns.get(tab).btn.focus();
    if (save && changed) {
      if (this.panelOpen) this.ctx.ui.closePanel();
      this.sel = null;
      this.saveRoute(true);
    }
  }

  onTabKey(e) {
    const at = TAB_IDS.indexOf(this.tab);
    let next = null;
    if (e.key === 'ArrowRight') next = TAB_IDS[(at + 1) % TAB_IDS.length];
    else if (e.key === 'ArrowLeft') next = TAB_IDS[(at - 1 + TAB_IDS.length) % TAB_IDS.length];
    else if (e.key === 'Home') next = TAB_IDS[0];
    else if (e.key === 'End') next = TAB_IDS[TAB_IDS.length - 1];
    if (!next) return;
    e.preventDefault();
    this.showTab(next, { save: true, focus: true });
  }

  // ---- query -----------------------------------------------------------------------------------

  setText(tab, text, { save = true } = {}) {
    this.texts[tab] = text;
    const bar = this.bars[tab];
    if (bar) {
      bar.setValue(text);
      this.onQuery(tab, text, bar.parsed, { save });
    } else {
      this.asts[tab] = null;
      if (tab === this.tab && this.idx) this.renderTab();
    }
  }

  onQuery(tab, text, parsed, { save = true } = {}) {
    this.texts[tab] = text;
    const bar = this.bars[tab];
    if (parsed && parsed.error) {
      if (bar) bar.setPlan(null);
      return;
    }
    const ast = parsed ? parsed.ast : null;
    const err = ast && this.Q ? this.Q.validate(ast, FIELDS[tab]) : null;
    if (bar) bar.setError(err);
    if (err) return;
    this.asts[tab] = ast;
    if (bar && this.Q) bar.setPlan(ast ? this.Q.plan(ast, 'policies') : null);
    this.limit = PAGE;
    if (tab === this.tab && this.idx) this.renderTab(save);
    if (save && tab === this.tab) this.saveRoute(false);
  }

  matcher(tab) {
    const ast = this.asts[tab];
    if (!ast || !this.Q) return () => true;
    const fn = this.Q.compile(ast, FIELDS[tab], {});
    return (row) => {
      try {
        return fn(row);
      } catch (_err) {
        return false;
      }
    };
  }

  addFilter(key, value, exclude) {
    const text = this.texts[this.tab] || '';
    const term = `${exclude ? '-' : ''}${key}:${qv(value)}`;
    const has = text.split(/\s+/).includes(term);
    const next = has ? text.split(/\s+/).filter((t) => t !== term).join(' ') : [text.trim(), term].filter(Boolean).join(' ');
    this.setText(this.tab, next);
    this.ctx.ui.announce(has ? `Removed ${key} ${value}` : `${exclude ? 'Excluding' : 'Filtering by'} ${key} ${value}`);
  }

  // ---- tab rendering ---------------------------------------------------------------------------

  renderTab(announce = false) {
    const { h } = this;
    const tab = this.tab;
    const sec = this.section(tab);
    const bar = this.bars[tab];
    if (sec.status !== 'ok') {
      this.tabStateEl.hidden = false;
      this.ctx.dom.put(this.tabStateEl, this.ctx.dom.stateCard({ status: sec.status || 'failed', message: sec.message }));
      this.ctx.dom.put(this.tableHost);
      if (bar) bar.el.hidden = true;
      return;
    }
    if (bar) bar.el.hidden = false;
    this.tabStateEl.hidden = true;
    const all = this.items[tab];
    const match = this.matcher(tab);
    const shown = all.filter(match);
    this.terms = this.asts[tab] && this.Q ? this.Q.highlightTerms(this.asts[tab]) : [];
    if (bar) bar.setStatus(this.asts[tab] ? `${this.fmt.num(shown.length)} of ${this.fmt.num(all.length)}` : '');
    if (!all.length) {
      const empty = {
        zones: ['This scope has no security zones', null],
        'address-books': ['This scope has no address books', 'Policies here can name only “any”.'],
        applications: ['No custom applications or application sets', 'Policies here use predefined junos-* applications only.'],
      }[tab];
      this.visible = [];
      this.ctx.dom.put(this.tableHost, this.ctx.dom.stateCard({ status: 'empty', title: empty[0], message: empty[1], hint: null }));
      return;
    }
    if (!shown.length) {
      this.visible = [];
      this.ctx.dom.put(
        this.tableHost,
        this.ctx.dom.stateCard({
          status: 'empty',
          title: `No ${TABS.find((t) => t.id === tab).label.toLowerCase()} match this query`,
          message: this.texts[tab],
          hint: null,
          actions: [h('button', { class: 'btn sm', type: 'button', on: { click: () => this.setText(tab, '') } }, 'Clear the query')],
        }),
      );
      return;
    }
    const page = shown.slice(0, this.limit);
    this.visible = page;
    let table;
    if (tab === 'zones') table = this.zonesTable(page);
    else if (tab === 'address-books') table = this.booksTable(page);
    else table = this.appsTable(page);
    const more =
      shown.length > page.length
        ? h(
            'div',
            { class: 'ob-more' },
            h('span', null, `Showing ${this.fmt.num(page.length)} of ${this.fmt.num(shown.length)}. Narrow the query, or `),
            h('button', { class: 'btn sm', type: 'button', on: { click: () => { this.limit += PAGE; this.renderTab(); } } }, `show ${this.fmt.num(Math.min(PAGE, shown.length - page.length))} more`),
          )
        : null;
    if (this.isMD()) {
      const pick = page.find((it) => it.id === this.mdSel) || page.find((it) => it.id === this.sel) || page[0];
      this.mdSel = pick ? pick.id : null;
      this.mdPane = h('section', { class: 'ob-md-pane', 'aria-label': pick ? `Zone ${pick.z.name}` : 'Zone' }, pick ? this.zoneDetail(pick) : null);
      this.ctx.dom.put(this.tableHost, h('div', { class: 'ob-md' }, h('div', { class: 'ob-md-list' }, h('div', { class: 'pv-tablecard ob-tablecard' }, table), more), this.mdPane));
    } else {
      this.mdPane = null;
      this.ctx.dom.put(this.tableHost, h('div', { class: 'pv-tablecard ob-tablecard' }, table), more);
    }
    this.markSelected();
    if (announce) this.ctx.ui.announce(`Showing ${shown.length} of ${this.fmt.plural(all.length, TABS.find((t) => t.id === tab).noun, TABS.find((t) => t.id === tab).plural)}.`);
  }

  hl(text, extra) {
    return this.h('span', { class: ['pv-hl', extra] }, markNodes(this.h, text, this.terms));
  }

  token(key, value, cls) {
    return this.h('span', { class: ['pv-v', cls], dataset: { k: key, v: value }, title: `Filter by ${key}:${value} (Alt-click to exclude)` }, markNodes(this.h, value, this.terms));
  }

  svcChips(list, key, kind) {
    const { h } = this;
    if (!list || !list.length) return h('span', { class: 'faint' }, 'none');
    return h(
      'span',
      { class: 'ob-chips' },
      list.map((s) => h('span', { class: ['ob-svc', kind, (s === 'all' || s === 'any-service') && 'wide'], dataset: { k: key, v: s }, title: s === 'all' ? 'all: every system service' : `Filter by ${key}:${s} (Alt-click to exclude)` }, markNodes(h, s, this.terms))),
    );
  }

  rowAttrs(it, i, extraCls) {
    return { class: ['pv-row', 'ob-row', extraCls], dataset: { i: String(i), id: it.id } };
  }

  zonesTable(page) {
    const { h } = this;
    const fmt = this.fmt;
    const rows = page.map((it, i) => {
      const z = it.z;
      const ifaces = z.interfaces || [];
      return h(
        'tr',
        this.rowAttrs(it, i, z.inactive && 'is-inactive'),
        h('th', { scope: 'row', class: 'c-name' }, h('button', { class: 'pv-name', type: 'button', 'aria-haspopup': 'dialog' }, this.hl(z.name)), z.description ? h('div', { class: 'pv-desc' }, z.description) : null),
        h(
          'td',
          { class: ['c-ifaces', !ifaces.length && 'is-empty'], dataset: { label: 'Interfaces' } },
          ifaces.length
            ? h(
                'ul',
                { class: 'ob-ifaces' },
                ifaces.map((f) =>
                  h(
                    'li',
                    null,
                    this.token('iface', f.name, 'iface'),
                    f.group ? h('span', { class: 'pv-badge b-group' }, `group ${f.group}`) : null,
                    (f.services || []).length || (f.protocols || []).length
                      ? h('span', { class: 'ob-own', title: 'This interface has its own host-inbound-traffic settings; they take precedence over the zone’s for this interface' }, 'own: ', [...(f.services || []), ...(f.protocols || [])].join(', '))
                      : h('span', { class: 'ob-inherit faint' }, 'zone settings'),
                  ),
                ),
              )
            : h('span', { class: 'faint' }, 'no interfaces'),
        ),
        h('td', { class: ['c-svc', !(z.services || []).length && 'is-empty'], dataset: { label: 'Services' } }, this.svcChips(z.services, 'service', 'svc')),
        h('td', { class: ['c-proto', !(z.protocols || []).length && 'is-empty'], dataset: { label: 'Protocols' } }, this.svcChips(z.protocols, 'proto', 'proto')),
        h('td', { class: ['c-screen', !z.screen && 'is-empty'], dataset: { label: 'Screen' } }, z.screen ? this.token('screen', z.screen) : h('span', { class: 'faint' }, 'none')),
        h(
          'td',
          { class: 'c-used', dataset: { label: 'Policies' } },
          this.idx.polOk
            ? h('button', { class: 'ob-used', type: 'button', dataset: { zone: z.name }, title: `Show the policies with zone:${z.name}` }, h('b', null, fmt.num(it.use.count)), h('span', null, ` in ${fmt.plural(it.use.pairs.length, 'pair')}`), it.use.globals.length ? h('span', { class: 'faint' }, ` + ${it.use.globals.length} global`) : null)
            : h('span', { class: 'faint' }, '—'),
        ),
        h('td', { class: ['c-prov', isDirect(z) && 'is-empty'], dataset: { label: 'Provenance' } }, h('div', { class: 'pv-badges' }, provBadges(h, z))),
      );
    });
    return h(
      'table',
      { class: 'pv-table ob-table ob-zones' },
      h('caption', { class: 'sr-only' }, 'Security zones'),
      h('colgroup', null, ['name', 'ifaces', 'svc', 'proto', 'screen', 'used', 'prov'].map((c) => h('col', { class: `c-${c}` }))),
      h(
        'thead',
        null,
        h(
          'tr',
          null,
          h('th', { scope: 'col', class: 'c-name' }, 'Zone'),
          h('th', { scope: 'col', class: 'c-ifaces' }, 'Interfaces'),
          h('th', { scope: 'col', class: 'c-svc', title: 'host-inbound-traffic system-services at zone level' }, 'Host-inbound services'),
          h('th', { scope: 'col', class: 'c-proto', title: 'host-inbound-traffic protocols at zone level' }, 'Protocols'),
          h('th', { scope: 'col', class: 'c-screen' }, 'Screen'),
          h('th', { scope: 'col', class: 'c-used' }, 'Policies'),
          h('th', { scope: 'col', class: 'c-prov' }, 'Provenance'),
        ),
      ),
      h('tbody', null, rows),
    );
  }

  bookAttach(b) {
    if (b.legacy_zone) return `zone-level address book of ${b.legacy_zone} (legacy form)`;
    if ((b.attach || []).length) return `attached to ${b.attach.length === 1 ? 'zone' : 'zones'} ${b.attach.join(', ')}`;
    if (b.name === 'global') return 'global: usable from every zone';
    return 'not attached to any zone';
  }

  booksTable(page) {
    const { h } = this;
    const fmt = this.fmt;
    const groups = new Map();
    page.forEach((it, i) => {
      if (!groups.has(it.book.name)) groups.set(it.book.name, []);
      groups.get(it.book.name).push([it, i]);
    });
    const bodies = [];
    for (const [bookName, list] of groups) {
      const b = list[0][0].book;
      const total = (b.addresses || []).length + (b.sets || []).length;
      const head = h(
        'tr',
        { class: 'pv-sec ob-book', dataset: { book: bookName } },
        h(
          'th',
          { colspan: '6', scope: 'colgroup' },
          h(
            'div',
            { class: 'pv-sec-in' },
            h('button', { class: 'ob-bookname', type: 'button', dataset: { book: bookName }, title: `About address book ${bookName}` }, this.ctx.dom.icon('globe'), bookName),
            h('span', { class: 'pv-sec-sub' }, this.bookAttach(b), SEP, list.length === total ? fmt.plural(total, 'entry', 'entries') : `${list.length} of ${fmt.plural(total, 'entry', 'entries')}`),
            ...provBadges(h, b, { direct: false }),
          ),
        ),
      );
      const rows = list.map(([it, i]) => {
        const e = it.entry;
        const isSet = it.type === 'set';
        const value = isSet
          ? h(
              'span',
              { class: 'ob-members' },
              (e.addresses || []).slice(0, 5).map((n) => this.token('member', n)),
              (e.sets || []).slice(0, 3).map((n) => h('span', { class: 'ob-nested' }, h('span', { class: 'pv-tag' }, 'set'), this.token('member', n))),
              (e.addresses || []).length + (e.sets || []).length > 8 ? h('span', { class: 'pv-more' }, `+${(e.addresses || []).length + (e.sets || []).length - 8} more`) : null,
            )
          : h('span', { class: 'ob-value' }, e.value ? this.token('addr', e.value, 'ip') : h('span', { class: 'faint' }, '—'));
        return h(
          'tr',
          this.rowAttrs(it, i, (e.inactive || b.inactive) && 'is-inactive'),
          h('th', { scope: 'row', class: 'c-name' }, h('button', { class: 'pv-name', type: 'button', 'aria-haspopup': 'dialog' }, this.hl(it.name)), e.description ? h('div', { class: 'pv-desc' }, e.description) : null),
          h('td', { class: 'c-kind', dataset: { label: 'Kind' } }, h('span', { class: ['ob-kind', `k-${it.kind}`] }, it.kind)),
          h('td', { class: ['c-value', !isSet && !e.value && 'is-empty'], dataset: { label: isSet ? 'Members' : 'Value' } }, value, isSet ? h('div', { class: 'pv-hint' }, `${fmt.plural([...it.closure].filter((n) => (b.addresses || []).some((a) => a.name === n)).length, 'address', 'addresses')} in all`) : null),
          h('td', { class: 'c-used', dataset: { label: 'Used by' } }, this.usedCell(it)),
          h('td', { class: ['c-prov', isDirect(e) && 'is-empty'], dataset: { label: 'Provenance' } }, h('div', { class: 'pv-badges' }, provBadges(h, e))),
          h('td', { class: ['c-zones', !it.zones.length && 'is-empty'], dataset: { label: 'Zones' } }, it.zones.length ? h('span', { class: 'ob-chips' }, it.zones.map((z) => (z === 'global' ? h('span', { class: 'zone pv-zone-any' }, 'any zone') : h('span', { class: 'zone' }, z)))) : h('span', { class: 'faint' }, 'none')),
        );
      });
      bodies.push(h('tbody', { class: 'pv-group' }, head, rows));
    }
    return h(
      'table',
      { class: 'pv-table ob-table ob-books' },
      h('caption', { class: 'sr-only' }, 'Address book entries'),
      h('colgroup', null, ['name', 'kind', 'value', 'used', 'prov', 'zones'].map((c) => h('col', { class: `c-${c}` }))),
      h(
        'thead',
        null,
        h(
          'tr',
          null,
          h('th', { scope: 'col', class: 'c-name' }, 'Name'),
          h('th', { scope: 'col' }, 'Kind'),
          h('th', { scope: 'col' }, 'Value or members'),
          h('th', { scope: 'col', title: 'Policies naming this entry, directly or through an address set' }, 'Used by'),
          h('th', { scope: 'col' }, 'Provenance'),
          h('th', { scope: 'col', title: 'Zones whose policies can name this entry' }, 'Usable from'),
        ),
      ),
      bodies,
    );
  }

  usedCell(it) {
    const { h } = this;
    if (!this.idx.polOk) return h('span', { class: 'faint' }, '—');
    const d = it.use.direct.length;
    const v = it.use.via.length;
    if (!d && !v) return h('span', { class: 'ob-unused', title: 'No policy in this scope names it, directly or through a set' }, 'unused');
    return h(
      'button',
      { class: 'ob-used', type: 'button', dataset: { used: it.id }, title: 'Open to see which policies use it' },
      h('b', null, this.fmt.num(d + v)),
      h('span', null, ` ${d + v === 1 ? 'policy' : 'policies'}`),
      v ? h('span', { class: 'faint' }, ` (${v} via set)`) : null,
    );
  }

  appsTable(page) {
    const { h } = this;
    const fmt = this.fmt;
    const rows = page.map((it, i) => {
      const a = it.a;
      const isSet = a.kind === 'set';
      return h(
        'tr',
        this.rowAttrs(it, i, a.inactive && 'is-inactive'),
        h('th', { scope: 'row', class: 'c-name' }, h('button', { class: 'pv-name', type: 'button', 'aria-haspopup': 'dialog' }, this.hl(a.name)), a.description ? h('div', { class: 'pv-desc' }, a.description) : null),
        h('td', { class: 'c-kind', dataset: { label: 'Kind' } }, h('span', { class: ['ob-kind', isSet ? 'k-set' : 'k-app'] }, isSet ? 'set' : 'application')),
        h(
          'td',
          { class: ['c-proto', (isSet ? !it.protocols.length : !a.protocol && !a.terms) && 'is-empty'], dataset: { label: 'Protocol' } },
          isSet ? h('span', { class: 'faint' }, it.protocols.length ? it.protocols.join(', ') : '—') : a.protocol ? this.token('proto', a.protocol) : a.terms ? h('span', { class: 'muted' }, `${fmt.plural(a.terms, 'term')}`) : h('span', { class: 'faint' }, '—'),
        ),
        h(
          'td',
          { class: ['c-port', (isSet ? !it.ports.length : !a.destination_port) && 'is-empty'], dataset: { label: 'Port' } },
          isSet ? h('span', { class: 'faint mono' }, it.ports.length ? it.ports.join(', ') : '—') : a.destination_port ? this.token('port', a.destination_port) : h('span', { class: 'faint' }, '—'),
          !isSet && a.source_port ? h('div', { class: 'pv-hint' }, `source ${a.source_port}`) : null,
        ),
        h(
          'td',
          { class: ['c-members', !isSet && 'is-empty'], dataset: { label: 'Members' } },
          isSet
            ? h(
                'span',
                { class: 'ob-members' },
                (a.members || []).slice(0, 6).map((n) => this.token('member', n, /^junos-/.test(n) ? 'is-predef' : null)),
                (a.sets || []).map((n) => h('span', { class: 'ob-nested' }, h('span', { class: 'pv-tag' }, 'set'), this.token('member', n))),
                (a.members || []).length > 6 ? h('span', { class: 'pv-more' }, `+${a.members.length - 6} more`) : null,
              )
            : h('span', { class: 'faint' }, '—'),
        ),
        h('td', { class: 'c-used', dataset: { label: 'Used by' } }, this.usedCell(it)),
        h('td', { class: ['c-prov', isDirect(a) && 'is-empty'], dataset: { label: 'Provenance' } }, h('div', { class: 'pv-badges' }, provBadges(h, a))),
      );
    });
    return h(
      'table',
      { class: 'pv-table ob-table ob-apps' },
      h('caption', { class: 'sr-only' }, 'Applications and application sets'),
      h('colgroup', null, ['name', 'kind', 'proto', 'port', 'members', 'used', 'prov'].map((c) => h('col', { class: `c-${c}` }))),
      h(
        'thead',
        null,
        h(
          'tr',
          null,
          h('th', { scope: 'col', class: 'c-name' }, 'Name'),
          h('th', { scope: 'col' }, 'Kind'),
          h('th', { scope: 'col' }, 'Protocol'),
          h('th', { scope: 'col', title: 'Destination port (source port below when set)' }, 'Port'),
          h('th', { scope: 'col' }, 'Members'),
          h('th', { scope: 'col' }, 'Used by'),
          h('th', { scope: 'col' }, 'Provenance'),
        ),
      ),
      h('tbody', null, rows),
    );
  }

  onTableClick(e) {
    const t = e.target instanceof Element ? e.target : null;
    if (!t) return;
    const book = t.closest('.ob-bookname[data-book]');
    if (book) {
      this.openSel(`book|${book.dataset.book}`, { push: true });
      return;
    }
    const zoneUsed = t.closest('.ob-used[data-zone]');
    if (zoneUsed) {
      this.ctx.navigate('policies', { q: `zone:${qv(zoneUsed.dataset.zone)}` });
      return;
    }
    const v = t.closest('[data-k][data-v]');
    if (v) {
      e.preventDefault();
      this.addFilter(v.dataset.k, v.dataset.v, e.altKey);
      return;
    }
    const tr = t.closest('tr.ob-row[data-i]');
    if (!tr) return;
    if (t.closest('button, a') && !t.closest('.pv-name') && !t.closest('.ob-used')) return;
    const selection = window.getSelection();
    if (selection && String(selection).length && !t.closest('button')) return;
    const it = this.visible[Number(tr.dataset.i)];
    if (it) this.openSel(it.id, { push: true });
  }

  // ---- keyboard --------------------------------------------------------------------------------

  onKey(e) {
    if (this.dead || e.defaultPrevented || e.metaKey || e.ctrlKey || e.altKey) return;
    const t = e.target;
    if (t instanceof Element && t.closest('input, textarea, select, [contenteditable="true"], .layer, .dialog, .menu')) return;
    if (!this.el.isConnected || !this.idx || !this.visible.length) return;
    if (e.key === 'j' || e.key === 'k') {
      e.preventDefault();
      const md = this.isMD() && this.mdPane;
      const cur = this.panelOpen ? this.visible.findIndex((it) => it.id === this.sel) : md ? this.visible.findIndex((it) => it.id === this.mdSel) : this.cursor;
      const next = cur < 0 ? 0 : Math.max(0, Math.min(this.visible.length - 1, cur + (e.key === 'j' ? 1 : -1)));
      if ((this.panelOpen || md) && this.visible[next]) {
        this.openSel(this.visible[next].id, { push: false });
      } else {
        this.cursor = next;
        this.markSelected();
        const tr = this.tableHost.querySelector(`tr.ob-row[data-i="${next}"]`);
        if (tr) {
          const btn = tr.querySelector('.pv-name');
          if (btn) btn.focus({ preventScroll: true });
          tr.scrollIntoView({ block: 'nearest' });
        }
      }
    } else if (e.key === 'Enter' && this.cursor >= 0 && (t === document.body || t === document.getElementById('main'))) {
      e.preventDefault();
      const it = this.visible[this.cursor];
      if (it) this.openSel(it.id, { push: true });
    }
  }

  markSelected() {
    const selId = this.isMD() && this.mdPane ? this.mdSel : this.panelOpen ? this.sel : null;
    for (const tr of this.tableHost.querySelectorAll('tr.ob-row')) {
      const on = selId ? tr.dataset.id === selId : Number(tr.dataset.i) === this.cursor;
      if (on) tr.setAttribute('aria-selected', 'true');
      else tr.removeAttribute('aria-selected');
    }
  }

  // ---- detail panels ---------------------------------------------------------------------------

  tryOpenWanted() {
    if (!this.wantSel || !this.idx) return;
    const want = this.wantSel;
    this.wantSel = null;
    if (!this.openSel(want, { push: false })) {
      this.sel = null;
      this.saveRoute(false);
      if (!/^zone\|/.test(want) || this.section('zones').status === 'ok') this.ctx.ui.toast('That object is not in this scope of the configuration.', 'warn');
    }
  }

  find(id) {
    const [type] = String(id).split('|');
    const tab = type === 'zone' ? 'zones' : type === 'app' ? 'applications' : 'address-books';
    return { tab, item: (this.items[tab] || []).find((it) => it.id === id) || null };
  }

  /** Opens the detail for an id (zone|Z, addr|B|N, set|B|N, book|B, app|N). False when unknown. */
  openSel(id, { push = true, refresh = false } = {}) {
    if (!this.idx) return false;
    let title;
    let content;
    let tabOf;
    if (String(id).startsWith('book|')) {
      const name = id.slice(5);
      const b = this.idx.books.find((x) => x.name === name);
      if (!b) return false;
      tabOf = 'address-books';
      title = `Address book ${name}`;
      content = this.bookDetail(b);
    } else {
      const { tab, item: it } = this.find(id);
      if (!it) return false;
      tabOf = tab;
      if (it.type === 'zone') {
        title = `Zone ${it.z.name}`;
        content = this.zoneDetail(it);
      } else if (it.type === 'app') {
        title = it.a.name;
        content = this.appDetail(it);
      } else {
        title = it.name;
        content = this.entryDetail(it);
      }
    }
    if (tabOf !== this.tab) this.showTab(tabOf, { save: false });
    if (this.isMD() && String(id).startsWith('zone|')) {
      // Master-detail: the zone shows in the pane beside the list.
      if (this.panelOpen) this.ctx.ui.closePanel();
      const was = this.sel;
      this.sel = id;
      this.mdSel = id;
      if (this.mdPane && this.mdPane.isConnected) {
        this.ctx.dom.put(this.mdPane, content);
        this.mdPane.setAttribute('aria-label', title);
        this.mdPane.scrollTop = 0;
      } else {
        this.renderTab();
      }
      this.markSelected();
      if (!refresh && was !== id) this.saveRoute(push);
      return true;
    }
    const token = ++this.panelToken;
    const was = this.sel;
    this.sel = id;
    this.panelOpen = true;
    const opened = this.ctx.ui.panel({ title, content, wide: true, onClose: () => this.onPanelClosed(token) });
    if (!refresh && opened && opened.el) opened.el.scrollTop = 0; // the shell's reset runs while the panel is hidden
    this.markSelected();
    const tr = [...this.tableHost.querySelectorAll('tr.ob-row')].find((x) => x.dataset.id === id);
    if (tr && !refresh) tr.scrollIntoView({ block: 'nearest' });
    if (!refresh && was !== id) this.saveRoute(push);
    return true;
  }

  onPanelClosed(token) {
    if (this.dead || token !== this.panelToken) return;
    this.panelOpen = false;
    if (this.sel) {
      this.sel = null;
      this.saveRoute(false);
    }
    this.markSelected();
  }

  psec(title, kids, cls) {
    return this.h('section', { class: ['panel-section', 'pv-psec', cls] }, this.h('h3', null, title), kids);
  }

  hero(eyebrow, parts, actions) {
    const { h } = this;
    return h('div', { class: 'pv-hero' }, h('p', { class: 'pv-eyebrow' }, eyebrow), h('div', { class: 'pv-where' }, parts), actions && actions.length ? h('div', { class: 'pv-hero-actions' }, actions) : null);
  }

  navBtn(iconName, label, view, params, title) {
    return this.h('button', { class: 'btn sm', type: 'button', title: title || label, on: { click: () => this.ctx.navigate(view, params) } }, this.ctx.dom.icon(iconName), label);
  }

  policyList(use) {
    const { h } = this;
    const pol = this.idx.pol;
    if (!this.idx.polOk) return h('p', { class: 'pv-small muted' }, 'The policies of this scope could not be read, so their use is not known.');
    const items = [...use.direct.map((idx) => ({ idx, set: null })), ...use.via];
    if (!items.length) return h('p', { class: 'pv-small muted' }, 'No policy in this scope names it, directly or through a set.');
    items.sort((a, b) => a.idx - b.idx);
    return h(
      'ul',
      { class: 'ob-uselist' },
      items.map(({ idx, set }) => {
        const r = pol[idx];
        const zl = (l) => ((l || []).length ? l.join(', ') : 'any');
        return h(
          'li',
          { class: r.inactive ? 'is-inactive' : null },
          h('button', { class: 'pv-ord-name', type: 'button', title: `Open ${r.name} in Policies`, on: { click: () => this.ctx.navigate('policies', { q: `name:${qv(r.name)}`, sel: r.id }) } }, r.name),
          h('span', { class: ['pill', ['permit', 'deny', 'reject'].includes(r.action) ? r.action : 'muted'] }, r.action),
          h('span', { class: 'ob-use-z' }, r.kind === 'global' ? 'global ' : '', h('span', { class: 'mono' }, zl(r.from)), h('span', { class: 'arrow' }, ` ${ARROW} `), h('span', { class: 'mono' }, zl(r.to))),
          set ? h('span', { class: 'pv-tag' }, `via set ${set}`) : h('span', { class: 'faint' }, 'direct'),
          r.inactive ? h('span', { class: 'faint' }, 'inactive') : null,
        );
      }),
    );
  }

  zoneDetail(it) {
    const { h } = this;
    const z = it.z;
    const fmt = this.fmt;
    const scopeId = this.ctx.store.scope;
    const root = scopeParts(scopeId).kind === 'root';
    const actions = [
      this.navBtn('policies', 'Policies with this zone', 'policies', { q: `zone:${qv(z.name)}` }),
      this.navBtn('sessions', 'Sessions', 'sessions', { q: `zone:${qv(z.name)}` }, `Live sessions whose policy is from or to ${z.name}`),
      this.navBtn('logs', 'Logs', 'logs', { q: `zone:${qv(z.name)}` }, `Log lines with source or destination zone ${z.name}`),
    ];
    const hero = this.hero(`Security zone${SEP}${scopeTitle(this.snap, scopeId)}`, [
      h('span', { class: 'zone ob-zone-big' }, z.name),
      h('span', { class: 'pv-where-pos' }, `${fmt.plural((z.interfaces || []).length, 'interface')}${SEP}screen ${z.screen || 'none'}`),
      ...provBadges(h, z, { direct: false }),
    ], actions);
    const ifaces = z.interfaces || [];
    const hitRows = [
      h(
        'tr',
        { class: 'ob-hit-zone' },
        h('td', null, h('b', null, 'zone'), h('div', { class: 'pv-hint' }, 'every interface without its own settings')),
        h('td', null, this.svcChips(z.services, 'service', 'svc')),
        h('td', null, this.svcChips(z.protocols, 'proto', 'proto')),
        h('td', null, z.group ? h('span', { class: 'pv-badge b-group' }, `group ${z.group}`) : h('span', { class: 'faint' }, 'direct')),
      ),
      ...ifaces.map((f) => {
        const ownS = (f.services || []).length > 0;
        const ownP = (f.protocols || []).length > 0;
        return h(
          'tr',
          null,
          h('td', null, h('span', { class: 'iface' }, f.name)),
          h('td', null, ownS ? [this.svcChips(f.services, 'service', 'svc'), h('div', { class: 'ob-prec' }, 'interface setting (takes precedence)')] : h('span', { class: 'ob-fromzone' }, 'from the zone')),
          h('td', null, ownP ? [this.svcChips(f.protocols, 'proto', 'proto'), h('div', { class: 'ob-prec' }, 'interface setting (takes precedence)')] : h('span', { class: 'ob-fromzone' }, 'from the zone')),
          h('td', null, f.group ? h('span', { class: 'pv-badge b-group' }, `group ${f.group}`) : h('span', { class: 'faint' }, 'direct')),
        );
      }),
    ];
    const hit = this.psec('Host-inbound traffic', [
      h('p', { class: 'pv-small muted' }, 'What the firewall itself answers on this zone’s interfaces (for example ping, SSH, HTTPS for J-Web, IKE). It does not affect traffic passing through. An interface with its own host-inbound-traffic settings uses those instead of the zone’s.'),
      h(
        'table',
        { class: 'table pv-mini ob-hit' },
        h('thead', null, h('tr', null, h('th', { scope: 'col' }, 'Where'), h('th', { scope: 'col' }, 'System services'), h('th', { scope: 'col' }, 'Protocols'), h('th', { scope: 'col' }, 'Provenance'))),
        h('tbody', null, hitRows),
      ),
      !ifaces.length ? h('p', { class: 'pv-small muted' }, 'No interface is in this zone, so the settings above apply nowhere yet.') : null,
    ]);
    const use = it.use;
    const pairs = this.psec('Policies that name this zone', [
      !this.idx.polOk
        ? h('p', { class: 'pv-small muted' }, 'The policies of this scope could not be read.')
        : use.pairs.length || use.globals.length
          ? h(
              'ul',
              { class: 'ob-pairs' },
              use.pairs.map((p) =>
                h(
                  'li',
                  null,
                  h(
                    'button',
                    { class: 'ob-pair', type: 'button', title: `Show the ${p.from} → ${p.to} policies`, on: { click: () => this.ctx.navigate('policies', { q: `from:${qv(p.from)} to:${qv(p.to)}` }) } },
                    h('span', { class: ['zone', p.from === z.name && 'is-this'] }, p.from),
                    h('span', { class: 'arrow' }, ARROW),
                    h('span', { class: ['zone', p.to === z.name && 'is-this'] }, p.to),
                    h('span', { class: 'ob-pair-n' }, fmt.plural(p.idxs.length, 'policy')),
                  ),
                ),
              ),
              use.globals.length
                ? h('li', null, h('button', { class: 'ob-pair', type: 'button', on: { click: () => this.ctx.navigate('policies', { q: `kind:global zone:${qv(z.name)}` }) } }, h('span', { class: 'pv-sec-name' }, 'Global'), h('span', { class: 'ob-pair-n' }, `${fmt.plural(use.globals.length, 'global policy', 'global policies')} ${use.globals.length === 1 ? 'applies' : 'apply'}`)))
                : null,
            )
          : h('p', { class: 'pv-small muted' }, 'No policy names this zone. Flows from or to it are decided by the global policies that apply, then the default policy.'),
    ]);
    const books = this.idx.books.filter((b) => b.legacy_zone === z.name || (b.attach || []).includes(z.name) || (b.name === 'global' && !b.legacy_zone));
    const bookSec = this.psec(
      'Address books its policies can use',
      books.length
        ? h(
            'ul',
            { class: 'ob-pairs' },
            books.map((b) =>
              h('li', null, h('button', { class: 'ob-pair', type: 'button', on: { click: () => this.openSel(`book|${b.name}`, { push: true }) } }, this.ctx.dom.icon('globe'), h('span', { class: 'mono' }, b.name), h('span', { class: 'ob-pair-n' }, this.bookAttach(b)))),
            ),
          )
        : h('p', { class: 'pv-small muted' }, 'None: no book is attached to this zone and there is no global book.'),
    );
    const cli = [cliBlock(this.ctx, `show configuration ${cliPrefix(scopeId)}security zones security-zone ${cliWord(z.name)}`)];
    if (root) cli.push(cliBlock(this.ctx, `show security zones ${cliWord(z.name)}`));
    return h('div', { class: 'pv-detail' }, hero, z.description ? h('p', { class: 'pv-desc-full' }, z.description) : null, hit, pairs, bookSec, this.psec('See it on the device', cli));
  }

  bookDetail(b) {
    const { h } = this;
    const fmt = this.fmt;
    const scopeId = this.ctx.store.scope;
    const prefix = cliPrefix(scopeId);
    const hero = this.hero(`Address book${SEP}${scopeTitle(this.snap, scopeId)}`, [
      h('span', { class: 'mono ob-big' }, b.name),
      h('span', { class: 'pv-where-pos' }, `${fmt.plural((b.addresses || []).length, 'address', 'addresses')}${SEP}${fmt.plural((b.sets || []).length, 'address set')}`),
      ...provBadges(h, b, { direct: false }),
    ], [
      h('button', { class: 'btn sm', type: 'button', on: { click: () => { this.ctx.ui.closePanel(); this.setText('address-books', `book:${qv(b.name)}`); } } }, this.ctx.dom.icon('filter'), 'Show only this book'),
    ]);
    const attach = this.psec('Where it applies', [
      h('p', null, this.bookAttach(b), '.'),
      h('p', { class: 'pv-small muted' }, 'A zone-pair policy looks a name up in the zone’s legacy address book, then the books attached to the zone, then the book named global. Global policies use the global book. (J-Wicket’s reading of the Junos documentation; listed for verification in Spec 001.)'),
    ]);
    const cli = b.legacy_zone
      ? `show configuration ${prefix}security zones security-zone ${cliWord(b.legacy_zone)} address-book`
      : `show configuration ${prefix}security address-book ${cliWord(b.name)}`;
    return h('div', { class: 'pv-detail' }, hero, attach, this.psec('See it on the device', cliBlock(this.ctx, cli)));
  }

  entryDetail(it) {
    const { h } = this;
    const fmt = this.fmt;
    const b = it.book;
    const e = it.entry;
    const scopeId = this.ctx.store.scope;
    const prefix = cliPrefix(scopeId);
    const isSet = it.type === 'set';
    const where = b.legacy_zone ? `security zones security-zone ${cliWord(b.legacy_zone)} address-book` : `security address-book ${cliWord(b.name)}`;
    const cli = `show configuration ${prefix}${where} ${isSet ? 'address-set' : 'address'} ${cliWord(it.name)}`;
    const actions = [
      this.navBtn('policies', 'Policies using it', 'policies', { q: `addr:${qv(it.name)}` }, `Policies whose source or destination names ${it.name} or resolves to it`),
      !isSet && e.value && /^[\d.:a-f/]+$/i.test(e.value) ? this.navBtn('sessions', 'Sessions', 'sessions', { q: `src:${e.value} OR dst:${e.value}` }, `Live sessions from or to ${e.value}`) : null,
    ].filter(Boolean);
    const hero = this.hero(`${isSet ? 'Address set' : 'Address'}${SEP}${b.name}${SEP}${scopeTitle(this.snap, scopeId)}`, [
      h('span', { class: ['ob-kind', `k-${it.kind}`] }, it.kind),
      !isSet && e.value ? h('span', { class: 'mono ip ob-big' }, e.value) : null,
      h('button', { class: 'ob-bookname', type: 'button', on: { click: () => this.openSel(`book|${b.name}`, { push: true }) } }, this.ctx.dom.icon('globe'), b.name),
      ...provBadges(h, e, { direct: false }),
    ], actions);
    const kids = [hero, e.description ? h('p', { class: 'pv-desc-full' }, e.description) : null];
    if (isSet) {
      const addrByName = new Map((b.addresses || []).map((a) => [a.name, a]));
      const setByName = new Map((b.sets || []).map((s) => [s.name, s]));
      const rows = [];
      const seen = new Set();
      const walk = (s, depth, via) => {
        if (seen.has(s.name) || depth > 8) return;
        seen.add(s.name);
        for (const n of s.addresses || []) {
          const a = addrByName.get(n);
          rows.push(h('tr', null, h('td', { class: 'mono' }, n), h('td', { class: 'muted' }, a ? a.kind : 'not found'), h('td', { class: ['mono', 'ip', !a && 'pv-unres'] }, a ? a.value || '' : 'not in this book'), h('td', { class: 'faint' }, via || 'direct')));
        }
        for (const n of s.sets || []) {
          const nested = setByName.get(n);
          if (nested) walk(nested, depth + 1, `via ${n}`);
          else rows.push(h('tr', null, h('td', { class: 'mono' }, n), h('td', { class: 'muted' }, 'address set'), h('td', { class: 'pv-unres' }, 'not in this book'), h('td', { class: 'faint' }, via || 'direct')));
        }
      };
      walk(e, 0, null);
      kids.push(
        this.psec(`Members, expanded (${fmt.num(rows.length)})`, [
          h('table', { class: 'table pv-mini' }, h('thead', null, h('tr', null, ['Address', 'Kind', 'Value', 'Through'].map((t) => h('th', { scope: 'col' }, t)))), h('tbody', null, rows)),
          (e.sets || []).length ? h('p', { class: 'pv-small muted' }, `Nested sets: ${e.sets.join(', ')}.`) : null,
        ]),
      );
    }
    const containing = (b.sets || []).filter((s) => (s.addresses || []).includes(it.name) || (s.sets || []).includes(it.name));
    kids.push(
      this.psec('Member of', containing.length ? h('ul', { class: 'ob-pairs' }, containing.map((s) => h('li', null, h('button', { class: 'ob-pair', type: 'button', on: { click: () => this.openSel(`set|${b.name}|${s.name}`, { push: false }) } }, h('span', { class: 'pv-tag' }, 'set'), h('span', { class: 'mono' }, s.name))))) : h('p', { class: 'pv-small muted' }, 'No address set in this book contains it.')),
      this.psec(`Used by ${it.usedCount ? fmt.plural(it.usedCount, 'policy') : 'no policy'}`, this.policyList(it.use)),
      this.psec('See it on the device', cliBlock(this.ctx, cli)),
    );
    return h('div', { class: 'pv-detail' }, kids);
  }

  appDetail(it) {
    const { h } = this;
    const fmt = this.fmt;
    const a = it.a;
    const scopeId = this.ctx.store.scope;
    const isSet = a.kind === 'set';
    const actions = [
      this.navBtn('policies', 'Policies using it', 'policies', { q: `app:${qv(a.name)}` }),
      !isSet && /^\d+$/.test(String(a.destination_port || '')) ? this.navBtn('sessions', 'Sessions', 'sessions', { q: `dport:${a.destination_port}${a.protocol && /^(tcp|udp)$/.test(a.protocol) ? ` proto:${a.protocol}` : ''}` }, `Live sessions to port ${a.destination_port}`) : null,
    ].filter(Boolean);
    const hero = this.hero(`${isSet ? 'Application set' : 'Custom application'}${SEP}${scopeTitle(this.snap, scopeId)}`, [
      h('span', { class: ['ob-kind', isSet ? 'k-set' : 'k-app'] }, isSet ? 'set' : 'application'),
      !isSet ? h('span', { class: 'mono ob-big' }, `${a.protocol || '?'}${a.destination_port ? `/${a.destination_port}` : ''}`) : null,
      ...provBadges(h, a, { direct: false }),
    ], actions);
    const kids = [hero, a.description ? h('p', { class: 'pv-desc-full' }, a.description) : null];
    if (!isSet) {
      kids.push(
        this.psec('Definition', [
          h(
            'dl',
            { class: 'kv pv-kv' },
            h('dt', null, 'Protocol'),
            h('dd', { class: 'mono' }, a.protocol || '—'),
            h('dt', null, 'Destination port'),
            h('dd', { class: 'mono' }, a.destination_port || '—'),
            h('dt', null, 'Source port'),
            h('dd', { class: 'mono' }, a.source_port || '—'),
            h('dt', null, 'Terms'),
            h('dd', null, a.terms ? `${fmt.plural(a.terms, 'term')} (not expanded by J-Wicket)` : h('span', { class: 'muted' }, 'none')),
          ),
          a.terms ? h('p', { class: 'pv-small muted' }, 'An application with terms matches if any term matches. Check the terms on the device.') : null,
        ]),
      );
    } else {
      const rows = [];
      const seen = new Set();
      const walk = (s, depth, via) => {
        if (seen.has(s.name) || depth > 8) return;
        seen.add(s.name);
        for (const n of s.members || []) {
          const m = this.idx.appByName.get(n);
          if (m && m.kind === 'application') {
            rows.push(h('tr', null, h('td', { class: 'mono' }, n), h('td', { class: 'mono' }, m.protocol || (m.terms ? `${m.terms} terms` : '—')), h('td', { class: 'mono' }, m.destination_port || '—'), h('td', { class: 'faint' }, via || 'direct')));
          } else if (/^junos-/.test(n)) {
            const known = this.Q && this.Q.PREDEFINED_APPS ? this.Q.PREDEFINED_APPS[n] : null;
            rows.push(
              known
                ? h('tr', null, h('td', { class: 'mono' }, n), h('td', { class: 'mono', title: 'junos-defaults, as J-Wicket knows it' }, known.protocol), h('td', { class: 'mono' }, known.port), h('td', { class: 'faint' }, via || 'direct'))
                : h('tr', null, h('td', { class: 'mono' }, n), h('td', { colspan: '2', class: 'muted' }, 'predefined (junos-defaults); port not read by J-Wicket'), h('td', { class: 'faint' }, via || 'direct')),
            );
          } else {
            rows.push(h('tr', null, h('td', { class: 'mono' }, n), h('td', { colspan: '2', class: 'pv-unres' }, 'not found'), h('td', { class: 'faint' }, via || 'direct')));
          }
        }
        for (const n of s.sets || []) {
          const nested = this.idx.appByName.get(n);
          if (nested && nested.kind === 'set') walk(nested, depth + 1, `via ${n}`);
          else rows.push(h('tr', null, h('td', { class: 'mono' }, n), h('td', { colspan: '2', class: 'pv-unres' }, 'set not found'), h('td', { class: 'faint' }, via || 'direct')));
        }
      };
      walk(a, 0, null);
      kids.push(this.psec(`Members, expanded (${fmt.num(rows.length)})`, h('table', { class: 'table pv-mini' }, h('thead', null, h('tr', null, ['Application', 'Protocol', 'Destination port', 'Through'].map((t) => h('th', { scope: 'col' }, t)))), h('tbody', null, rows))));
      const predefined = (a.members || []).filter((n) => /^junos-/.test(n));
      if (predefined.length) {
        kids.push(h('p', { class: 'pv-small muted' }, 'Predefined applications are defined in junos-defaults. To see one:'), cliBlock(this.ctx, `show configuration groups junos-defaults applications application ${cliWord(predefined[0])}`));
      }
    }
    const containing = this.idx.apps.filter((s) => s.kind === 'set' && ((s.members || []).includes(a.name) || (s.sets || []).includes(a.name)));
    const cli = `show configuration ${cliPrefix(scopeId)}applications ${isSet ? 'application-set' : 'application'} ${cliWord(a.name)}`;
    kids.push(
      this.psec('Member of', containing.length ? h('ul', { class: 'ob-pairs' }, containing.map((s) => h('li', null, h('button', { class: 'ob-pair', type: 'button', on: { click: () => this.openSel(`app|${s.name}`, { push: false }) } }, h('span', { class: 'pv-tag' }, 'set'), h('span', { class: 'mono' }, s.name))))) : h('p', { class: 'pv-small muted' }, 'No application set contains it.')),
      this.psec(`Used by ${it.usedCount ? fmt.plural(it.usedCount, 'policy') : 'no policy'}`, this.policyList(it.use)),
      this.psec('See it on the device', cliBlock(this.ctx, cli)),
    );
    return h('div', { class: 'pv-detail' }, kids);
  }
}
