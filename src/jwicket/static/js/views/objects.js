// views/objects.js: zones, address books and applications of the current scope (UI brief, section 7).
//
// Three tabs over one inventory snapshot, each with the shared query language (query.js parse /
// validate / compile) over keys defined here, a table and a detail panel:
// * Zones: interfaces, host-inbound traffic at zone and interface level ("Interface configuration
//   overrides that of the zone", verified), screen, provenance, the zone pairs that use the zone.
// * Address books: books with their attachment (zones, global, legacy zone book), addresses and
//   sets, set expansion, which policies use each entry (directly or through a set), provenance.
// * Applications: custom applications and sets, members expanded, which policies use them.
// Every panel is device data or an explicit state. Nothing read from the device is stored.
//
// UI-19: what is deactivated (inactive:) is shown as written but not in effect, and is never counted
// as a use: "used by" counts active policies, and set closures run over active objects only. Device
// text goes through ctx.dom.vis() (hidden characters as badges), titles through format.plain(), and a
// CLI command is offered only when no name in it would break a pasted command (format.cliUnsafe).

import {
  cliBlock,
  cliJoin,
  cliPrefix,
  cliWord,
  inventoryErrorFor,
  inventoryState,
  markNodes,
  pairKey,
  provBadges,
  qvDevice,
  scopeParts,
  scopeTitle,
  subLine,
} from './policies.js';
import { controlParts, plain } from '../format.js';

const ICON = 'M12 3.2l7.8 4.4v8.8L12 20.8l-7.8-4.4V7.6z M4.4 7.7L12 12l7.6-4.3 M12 12v8.6';
// A speech bubble, for configuration comments (annotate); the same shape as in policies.js.
const COMMENT_ICON = 'M5 5.5h14v9.5h-8.5L6 19v-4H5z';
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

/** Every comment of an object: the one before it and those inside it (annotate). */
const commentsOf = (o) => [o && o.comment, ...((o && o.part_comments) || []).map((c) => c && c.text)].filter(Boolean);

/** "ftp except" (a deactivated exclusion) -> "ftp". */
const svcName = (s) => String(s).replace(/ except$/, '');

/** The hidden (control or format) characters in these strings, as "U+200B" names. */
function hiddenNames(strings, all = false) {
  const out = [];
  for (const s of strings) {
    for (const p of controlParts(String(s || ''), { all })) if (p.ctl && !out.includes(p.ctl)) out.push(p.ctl);
  }
  return out;
}

/** "used:" values: yes (an active policy uses it), no, and inactive (only deactivated policies name it). */
const usedValues = (r) => (r.usedCount > 0 ? ['yes', 'true'] : ['no', 'false', ...(r.offCount > 0 ? ['inactive'] : [])]);

const FIELDS = {
  zones: {
    name: { aliases: ['zone'], type: 'text', label: 'zone name', get: (r) => r.z.name, values: (rows) => topValues(rows, (r) => r.z.name) },
    iface: { aliases: ['interface', 'if'], type: 'text', label: 'interface in the zone', get: (r) => (r.z.interfaces || []).map((i) => i.name), values: (rows) => topValues(rows, (r) => (r.z.interfaces || []).map((i) => i.name)) },
    service: {
      aliases: ['services', 'system-services', 'svc'],
      type: 'text',
      label: 'host-inbound system service in effect (zone or interface)',
      get: (r) => uniq([...(r.z.services || []), ...(r.z.interfaces || []).flatMap((i) => i.services || [])]),
      values: (rows) => topValues(rows, (r) => [...(r.z.services || []), ...(r.z.interfaces || []).flatMap((i) => i.services || [])]),
    },
    proto: {
      aliases: ['protocol', 'protocols'],
      type: 'text',
      label: 'host-inbound protocol in effect (zone or interface)',
      get: (r) => uniq([...(r.z.protocols || []), ...(r.z.interfaces || []).flatMap((i) => i.protocols || [])]),
      values: (rows) => topValues(rows, (r) => [...(r.z.protocols || []), ...(r.z.interfaces || []).flatMap((i) => i.protocols || [])]),
    },
    except: { aliases: ['excluded', 'svc-except'], type: 'text', label: 'host-inbound service or protocol excluded with except (zone or interface)', get: (r) => r.except, values: (rows) => topValues(rows, (r) => r.except) },
    'inactive-svc': { aliases: [], type: 'text', label: 'deactivated host-inbound service or protocol (not in effect)', get: (r) => r.offSvc, values: (rows) => topValues(rows, (r) => r.offSvc) },
    screen: { aliases: ['ids'], type: 'text', label: 'screen profile in effect', get: (r) => r.z.screen || 'none', values: (rows) => topValues(rows, (r) => r.z.screen || 'none') },
    group: { aliases: ['groups'], type: 'text', label: 'configuration group (zone or interface)', get: (r) => uniq([r.z.group, ...(r.z.groups || []), ...(r.z.interfaces || []).map((i) => i.group)]), values: (rows) => topValues(rows, (r) => [r.z.group, ...(r.z.interfaces || []).map((i) => i.group)]) },
    inactive: { aliases: ['disabled'], type: 'enum', label: 'yes or no (the zone or its scope deactivated)', get: (r) => yesNo(r.z.inactive || r.scopeOff), values: () => ['yes', 'no'] },
    policies: { aliases: ['used'], type: 'int', label: 'number of active policies naming the zone', get: (r) => String(r.policyCount) },
    desc: { aliases: ['description'], type: 'text', contains: true, label: 'description (substring)', get: (r) => r.z.description },
    comment: { aliases: ['comments', 'note', 'annotation'], type: 'text', contains: true, label: 'configuration comment (annotate), substring', get: (r) => r.comments },
  },
  'address-books': {
    name: { aliases: ['address', 'entry'], type: 'text', label: 'address or address-set name', get: (r) => r.name, values: (rows) => topValues(rows, (r) => r.name) },
    book: { aliases: ['address-book'], type: 'text', label: 'address book', get: (r) => r.book.name, values: (rows) => topValues(rows, (r) => r.book.name) },
    kind: { aliases: ['type'], type: 'enum', label: 'prefix, range, dns, wildcard, unknown or set', get: (r) => r.kind, values: (rows) => topValues(rows, (r) => r.kind) },
    addr: { aliases: ['ip', 'value', 'prefix'], type: 'ip', label: 'address value, CIDR-aware (sets: their members in effect)', get: (r) => r.values },
    member: { aliases: ['members', 'contains'], type: 'text', label: 'member of a set in effect (address or nested set)', get: (r) => r.members, values: (rows) => topValues(rows, (r) => r.members) },
    'member-inactive': { aliases: [], type: 'text', label: 'deactivated member of a set, or a member that is itself deactivated', get: (r) => r.membersOff, values: (rows) => topValues(rows, (r) => r.membersOff) },
    zone: { aliases: ['attach', 'attached'], type: 'text', label: 'zone the book is attached to ("global" for the global book)', get: (r) => r.zones, values: (rows) => topValues(rows, (r) => r.zones) },
    used: { aliases: ['in-use'], type: 'enum', label: 'used by an active policy: yes, no, or inactive (named only by deactivated policies)', get: usedValues, values: () => ['yes', 'no', 'inactive'] },
    group: { aliases: ['groups'], type: 'text', label: 'configuration group', get: (r) => uniq([r.entry.group, r.book.group]), values: (rows) => topValues(rows, (r) => [r.entry.group, r.book.group]) },
    inactive: { aliases: ['disabled'], type: 'enum', label: 'yes or no (the entry, its book or its scope deactivated)', get: (r) => yesNo(!r.effective), values: () => ['yes', 'no'] },
    desc: { aliases: ['description'], type: 'text', contains: true, label: 'description (substring)', get: (r) => r.entry.description },
    comment: { aliases: ['comments', 'note', 'annotation'], type: 'text', contains: true, label: 'configuration comment (annotate), substring', get: (r) => r.comments },
  },
  applications: {
    name: { aliases: ['application', 'app'], type: 'text', label: 'application or set name', get: (r) => r.a.name, values: (rows) => topValues(rows, (r) => r.a.name) },
    kind: { aliases: ['type'], type: 'enum', label: 'application or set', get: (r) => r.a.kind, values: () => ['application', 'set'] },
    proto: { aliases: ['protocol'], type: 'text', label: 'protocol (sets: their members in effect)', get: (r) => r.protocols, values: (rows) => topValues(rows, (r) => r.protocols) },
    port: { aliases: ['dport', 'destination-port'], type: 'int', label: 'destination port or range (sets: their members; predefined ones from J-Wicket’s catalog, marked)', get: (r) => [...r.ports, ...r.catalogPorts] },
    sport: { aliases: ['source-port'], type: 'int', label: 'source port', get: (r) => r.a.source_port },
    member: { aliases: ['members', 'contains'], type: 'text', label: 'member of a set in effect (application or nested set)', get: (r) => r.members, values: (rows) => topValues(rows, (r) => r.members) },
    'member-inactive': { aliases: [], type: 'text', label: 'deactivated member of a set, or a member that is itself deactivated', get: (r) => r.membersOff, values: (rows) => topValues(rows, (r) => r.membersOff) },
    used: { aliases: ['in-use'], type: 'enum', label: 'used by an active policy: yes, no, or inactive (named only by deactivated policies)', get: usedValues, values: () => ['yes', 'no', 'inactive'] },
    group: { aliases: ['groups'], type: 'text', label: 'configuration group', get: (r) => r.a.group, values: (rows) => topValues(rows, (r) => r.a.group) },
    inactive: { aliases: ['disabled'], type: 'enum', label: 'yes or no (the application or its scope deactivated)', get: (r) => yesNo(r.a.inactive || r.scopeOff), values: () => ['yes', 'no'] },
    desc: { aliases: ['description'], type: 'text', contains: true, label: 'description (substring)', get: (r) => r.a.description },
    comment: { aliases: ['comments', 'note', 'annotation'], type: 'text', contains: true, label: 'configuration comment (annotate), substring', get: (r) => r.comments },
  },
};

// The applications keys with port matching device-read ports only: a set row the full query keeps
// but this one drops matched through a catalog port, and is marked so (OBJ-47).
const APP_FIELDS_DEVICE = { ...FIELDS.applications, port: { ...FIELDS.applications.port, get: (r) => r.ports } };

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

/**
 * Who uses what. Policies name entries through `resolved` (the server resolves to entries in effect
 * only). Set closures run over objects in effect only (OBJ-45): a deactivated set, a deactivated member
 * statement (not in the set's lists at all) and a member that names a deactivated object add nothing.
 * Each use lists active policies (`direct`, `via`) apart from deactivated ones (`off`), which are not
 * counted (OBJ-44).
 */
function buildIndex(snap) {
  const scope = snap.scope;
  const scopeOff = Boolean(scope.inactive);
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
  // set closures over objects in effect (within a book; within the scope's applications)
  const bookSets = new Map();
  for (const b of books) {
    const addrs = new Map((b.addresses || []).map((a) => [a.name, a]));
    const sets = new Map((b.sets || []).map((s) => [s.name, s]));
    const closure = new Map();
    const close = (name, seen) => {
      if (closure.has(name)) return closure.get(name);
      const out = new Set();
      const s = sets.get(name);
      if (s && !s.inactive && !seen.has(name)) {
        seen.add(name);
        for (const a of s.addresses || []) {
          const e = addrs.get(a);
          if (!e || !e.inactive) out.add(a);
        }
        for (const n of s.sets || []) {
          const ns = sets.get(n);
          if (ns && ns.inactive) continue;
          out.add(n);
          for (const x of close(n, seen)) out.add(x);
        }
      }
      closure.set(name, out);
      return out;
    };
    for (const name of sets.keys()) close(name, new Set());
    bookSets.set(b.name, { addrs, sets, closure });
  }
  const appByName = new Map(apps.map((a) => [a.name, a]));
  const appClosure = new Map();
  const closeApp = (name, seen) => {
    if (appClosure.has(name)) return appClosure.get(name);
    const out = new Set();
    const a = appByName.get(name);
    if (a && a.kind === 'set' && !a.inactive && !seen.has(name)) {
      seen.add(name);
      for (const m of [...(a.members || []), ...(a.sets || [])]) {
        const x = appByName.get(m);
        if (x && x.inactive) continue;
        out.add(m);
        for (const y of closeApp(m, seen)) out.add(y);
      }
    }
    appClosure.set(name, out);
    return out;
  };
  for (const a of apps) closeApp(a.name, new Set());

  /** Splits policy uses into active ones and deactivated ones (not in effect, not counted). */
  const split = (direct, via) => {
    const off = [];
    const d = [];
    const v = [];
    for (const idx of direct) (pol[idx] && pol[idx].inactive ? off.push({ idx, set: null }) : d.push(idx));
    for (const x of via) (pol[x.idx] && pol[x.idx].inactive ? off.push(x) : v.push(x));
    return { direct: d, via: v, off };
  };
  /** {direct:[idx], via:[{idx, set}], off:[{idx, set}]} for an address-book entry. */
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
    return split(direct, via);
  };
  const appUse = (name) => {
    const direct = [...(appDirect.get(name) || [])];
    const via = [];
    for (const [setName, members] of appClosure) {
      if (!members.has(name)) continue;
      for (const idx of appDirect.get(setName) || []) if (!direct.includes(idx) && !via.some((v) => v.idx === idx)) via.push({ idx, set: setName });
    }
    return split(direct, via);
  };
  const zoneNames = zones.map((z) => z.name);
  /** Zone-pair policies naming the zone, active and deactivated apart, and the global policies that apply. */
  const zoneUse = (z) => {
    const pairs = new Map();
    const globals = [];
    let count = 0;
    let off = 0;
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
      if (!pairs.has(key)) pairs.set(key, { from, to, idxs: [], active: 0, off: 0 });
      const p = pairs.get(key);
      p.idxs.push(idx);
      if (r.inactive) {
        p.off += 1;
        off += 1;
      } else {
        p.active += 1;
        count += 1;
      }
    });
    return { pairs: [...pairs.values()], globals, globalsActive: globals.filter((i) => !pol[i].inactive).length, count, off };
  };
  return { scope, scopeOff, pol, polOk, books, apps, zones, zoneNames, bookSets, appByName, appClosure, addrUse, appUse, zoneUse };
}

/** Why a policy is inactive, in a few words (the Policies view gives the full sentence). */
function offReason(r) {
  const why = r.inactive_reason;
  if (why === 'policy') return 'policy deactivated';
  if (why === 'zone-pair') return r.kind === 'global' ? 'global section deactivated' : 'zone pair deactivated';
  if (why === 'policies') return '[security policies] deactivated';
  if (why === 'security') return '[security] deactivated';
  if (why === 'scope') return 'scope deactivated';
  return `reason ${why || 'not given'}`;
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
    this.infoOpen = false;
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

  // ---- device text -----------------------------------------------------------------------------

  /** A name (one line) as nodes, hidden characters shown as badges. */
  v(s) {
    return this.ctx.dom.vis(s, { all: true });
  }

  /** A description or comment as nodes (line breaks kept). */
  vd(s) {
    return this.ctx.dom.vis(s);
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
    // Snapshot and scope warnings: a chip that opens the list, as in Policies (OBJ-54).
    this.infoEl = h('div', { class: 'pv-info ob-info', hidden: true });
    this.infoPanel = h('div', { class: 'pv-infopanel', id: 'ob-infopanel', hidden: true });
    this.qbHost = h('div', { class: 'pv-qb' });
    this.tabNoteEl = h('div', { class: 'ob-tabnote', hidden: true });
    this.tabStateEl = h('div', { class: 'ob-tabstate', hidden: true });
    this.tableHost = h('div', { class: 'pv-tablehost' });
    this.panelEl = h(
      'div',
      { class: 'ob-panel', id: 'ob-panel', role: 'tabpanel' },
      h('div', { class: 'ob-introrow' }, this.introEl, this.infoEl),
      this.infoPanel,
      this.qbHost,
      this.tabNoteEl,
      this.tabStateEl,
      this.tableHost,
    );
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
    const err = inventoryErrorFor(this.ctx);
    if (snap && err) {
      out.push(h('div', { class: 'pv-notice deny', role: 'status' }, icon('alert'), h('span', null, h('b', null, 'The last read failed. '), this.vd(`${err.message} This page still shows the read from ${this.fmt.time(snap.meta && snap.meta.read_at)} UTC.`))));
    }
    if (snap && snap.scope && snap.scope.inactive) {
      out.push(h('div', { class: 'pv-notice reject', role: 'note' }, icon('alert'), h('span', null, h('b', null, this.v(`${scopeTitle(snap, snap.meta.scope)} is deactivated in the configuration. `)), 'Nothing in this scope is in effect.')));
    }
    if (snap && snap.scope && snap.scope.security_present === false && (!snap.config || snap.config.status === 'ok')) {
      const user = (snap.meta && snap.meta.read_as && snap.meta.read_as.user) || 'this user';
      out.push(
        h(
          'div',
          { class: 'pv-notice', role: 'note' },
          icon('info'),
          h('span', null, 'The configuration J-Wicket read has no security section: either nothing is configured, or ', h('span', { class: 'mono' }, this.v(user)), '’s login class cannot view it.'),
        ),
      );
    }
    this.ctx.dom.put(this.noticeEl, ...out);
    this.noticeEl.hidden = !out.length;
  }

  /** Whether the scope's configuration has a security section (B-9; absent in older snapshots: true). */
  securityPresent() {
    return !(this.snap && this.snap.scope && this.snap.scope.security_present === false);
  }

  render() {
    const { h } = this;
    this.loadingEl.hidden = true;
    this.renderSub();
    this.renderNotices();
    const st = inventoryState(this.ctx, this.snap, 'objects', () => this.load(true), {
      deniedHint: 'Your Junos login class does not allow J-Wicket to read the configuration, so no zones, address books or applications are shown.',
    });
    if (st) {
      this.idx = null;
      this.bodyEl.hidden = true;
      this.ctx.dom.put(this.stateEl, h('div', { class: 'pv-statewrap' }, h('p', { class: 'pv-state-what' }, 'The zones, address books and applications of this scope are not shown.'), st));
      this.stateEl.hidden = false;
      if (this.panelOpen) this.ctx.ui.closePanel();
      // Nothing can be opened: drop an object the address asks for, as tryOpenWanted does (POL-UI-07).
      if (this.wantSel || this.sel) {
        this.wantSel = null;
        this.sel = null;
        this.mdSel = null;
        this.saveRoute(false);
      }
      return;
    }
    this.stateEl.hidden = true;
    this.bodyEl.hidden = false;
    this.idx = buildIndex(this.snap);
    this.buildItems();
    this.renderTabs();
    this.renderInfo();
    this.renderTab();
    if (this.panelOpen && this.sel) {
      if (!this.openSel(this.sel, { refresh: true })) this.ctx.ui.closePanel();
    }
    this.tryOpenWanted();
  }

  /** The warnings chip: snapshot and scope warnings, verbatim (OBJ-54). */
  renderInfo() {
    const { h } = this;
    const { icon } = this.ctx.dom;
    const list = this.warnings();
    if (!list.length) this.infoOpen = false;
    this.ctx.dom.put(
      this.infoEl,
      list.length
        ? h(
            'button',
            {
              class: 'pv-infochip is-amber',
              type: 'button',
              title: 'What J-Wicket could not show, or what is not in effect. Select to read them.',
              'aria-expanded': this.infoOpen ? 'true' : 'false',
              'aria-controls': 'ob-infopanel',
              on: { click: () => this.toggleInfo() },
            },
            icon('alert'),
            h('b', null, String(list.length)),
            h('span', null, list.length === 1 ? ' warning' : ' warnings'),
            icon('chevron-down'),
          )
        : null,
    );
    this.infoEl.hidden = !list.length;
    this.renderInfoPanel();
  }

  warnings() {
    const snap = this.snap;
    if (!snap) return [];
    return [...(snap.warnings || []), ...((snap.scope && snap.scope.warnings) || [])];
  }

  toggleInfo() {
    this.infoOpen = !this.infoOpen;
    const chip = this.infoEl.querySelector('.pv-infochip');
    if (chip) chip.setAttribute('aria-expanded', this.infoOpen ? 'true' : 'false');
    this.renderInfoPanel();
  }

  renderInfoPanel() {
    const { h } = this;
    const { icon } = this.ctx.dom;
    const list = this.warnings();
    const node =
      this.infoOpen && list.length
        ? h(
            'div',
            { class: 'pv-warn', role: 'note' },
            h('p', { class: 'pv-warn-hint' }, 'What J-Wicket could not show, or what is not in effect:'),
            h('ul', null, list.map((w) => h('li', null, icon(/^Fixture/.test(w) ? 'info' : 'alert'), h('span', { class: 'dev-text' }, this.vd(w))))),
          )
        : null;
    this.ctx.dom.put(this.infoPanel, node);
    this.infoPanel.hidden = !node;
  }

  buildItems() {
    const x = this.idx;
    const scopeOff = x.scopeOff;
    const zoneItems = x.zones.map((z) => {
      const use = x.zoneUse(z.name);
      const ifaces = z.interfaces || [];
      const except = uniq([...(z.services_except || []), ...(z.protocols_except || []), ...ifaces.flatMap((i) => [...(i.services_except || []), ...(i.protocols_except || [])])]);
      const offSvc = uniq([...(z.inactive_services || []), ...(z.inactive_protocols || []), ...ifaces.flatMap((i) => [...(i.inactive_services || []), ...(i.inactive_protocols || [])])].map(svcName));
      const comments = [...commentsOf(z), ...ifaces.map((i) => i.comment)].filter(Boolean);
      return item({
        type: 'zone',
        id: `zone|${z.name}`,
        z,
        scopeOff,
        policyCount: use.count,
        use,
        except,
        offSvc,
        comments,
        hidden: hiddenNames([z.name, ...ifaces.map((i) => i.name)], true).concat(hiddenNames([z.description, ...comments])),
        _text: [z.name, z.description, z.screen, z.group, ...(z.services || []), ...(z.protocols || []), ...except, ...comments, ...ifaces.flatMap((i) => [i.name, ...(i.services || []), ...(i.protocols || []), i.group])].filter(Boolean).join(' '),
      });
    });
    const entryItems = [];
    for (const b of x.books) {
      const zones = b.legacy_zone ? [b.legacy_zone] : (b.attach || []).length ? b.attach : b.name === 'global' ? ['global'] : [];
      const bs = x.bookSets.get(b.name);
      const addrByName = bs ? bs.addrs : new Map();
      const setByName = bs ? bs.sets : new Map();
      for (const a of b.addresses || []) {
        const use = x.addrUse(b.name, a.name);
        const comments = commentsOf(a);
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
            membersOff: [],
            use,
            usedCount: use.direct.length + use.via.length,
            offCount: use.off.length,
            effective: !a.inactive && !b.inactive && !scopeOff,
            comments,
            hidden: hiddenNames([a.name, a.value], true).concat(hiddenNames([a.description, ...comments])),
            _text: [a.name, a.kind, a.value, a.description, a.group, b.name, ...zones, ...comments].filter(Boolean).join(' '),
          }),
        );
      }
      for (const s of b.sets || []) {
        const closure = bs ? bs.closure.get(s.name) || new Set() : new Set();
        const leafValues = [...closure].map((n) => addrByName.get(n)).filter(Boolean).map((a) => a.value);
        const use = x.addrUse(b.name, s.name);
        const objOff = (n) => Boolean((addrByName.get(n) || setByName.get(n) || {}).inactive);
        const members = [...(s.addresses || []), ...(s.sets || [])];
        const comments = commentsOf(s);
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
            members: members.filter((n) => !objOff(n)),
            membersOff: uniq([...(s.inactive_addresses || []), ...(s.inactive_sets || []), ...members.filter(objOff)]),
            closure,
            use,
            usedCount: use.direct.length + use.via.length,
            offCount: use.off.length,
            effective: !s.inactive && !b.inactive && !scopeOff,
            comments,
            hidden: hiddenNames([s.name, ...members], true).concat(hiddenNames([s.description, ...comments])),
            _text: [s.name, 'set', s.description, s.group, b.name, ...zones, ...members, ...leafValues, ...comments].filter(Boolean).join(' '),
          }),
        );
      }
    }
    const catalog = this.Q && this.Q.PREDEFINED_APPS ? this.Q.PREDEFINED_APPS : {};
    const appItems = x.apps.map((a) => {
      const closure = x.appClosure.get(a.name) || new Set();
      const isSet = a.kind === 'set';
      const leaves = isSet ? [...closure].map((n) => x.appByName.get(n)).filter((m) => m && m.kind === 'application') : [a];
      const predefined = isSet ? [...closure].filter((n) => !x.appByName.has(n) && /^junos-/.test(n)) : [];
      const known = predefined.filter((n) => catalog[n]);
      const use = x.appUse(a.name);
      const objOff = (n) => Boolean((x.appByName.get(n) || {}).inactive);
      const members = [...(a.members || []), ...(a.sets || [])];
      const comments = commentsOf(a);
      return item({
        type: 'app',
        id: `app|${a.name}`,
        a,
        scopeOff,
        closure,
        protocols: uniq(leaves.map((l) => l.protocol)),
        ports: uniq(leaves.map((l) => l.destination_port)),
        // Predefined members' ports from J-Wicket's own table (query.PREDEFINED_SOURCE), not the device.
        catalog: known.map((n) => ({ name: n, protocol: catalog[n].protocol, port: String(catalog[n].port) })),
        catalogPorts: uniq(known.map((n) => String(catalog[n].port))),
        unknownPredefined: predefined.filter((n) => !catalog[n]),
        members: members.filter((n) => !objOff(n)),
        membersOff: uniq([...(a.inactive_applications || []), ...(a.inactive_sets || []), ...members.filter(objOff)]),
        use,
        usedCount: use.direct.length + use.via.length,
        offCount: use.off.length,
        comments,
        hidden: hiddenNames([a.name, ...members], true).concat(hiddenNames([a.description, ...comments])),
        _text: [a.name, a.kind, a.protocol, a.destination_port, a.source_port, a.description, a.group, ...members, ...comments].filter(Boolean).join(' '),
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
      // Address books: the count is the number of books, titled "2 books · 12 entries" (OBJ-59).
      const books = t.id === 'address-books' && this.idx ? this.idx.books.length : null;
      count.textContent = sec.status === 'ok' ? this.fmt.num(books === null ? this.items[t.id].length : books) : sec.status ? '!' : '';
      count.title = sec.status !== 'ok' ? `Not read: ${sec.status}` : books === null ? '' : `${this.fmt.plural(books, 'book')} · ${this.fmt.plural(this.items[t.id].length, 'entry', 'entries')}`;
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
      applications: 'Custom applications and application sets of this scope. Predefined junos-* applications come from junos-defaults, which J-Wicket does not read: their ports, where shown, come from J-Wicket’s own table and are tagged catalog.',
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

  matcher(tab, fields = FIELDS[tab]) {
    const ast = this.asts[tab];
    if (!ast || !this.Q) return () => true;
    const fn = this.Q.compile(ast, fields, {});
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
    const term = `${exclude ? '-' : ''}${key}:${qvDevice(value)}`;
    const has = text.split(/\s+/).includes(term);
    const next = has ? text.split(/\s+/).filter((t) => t !== term).join(' ') : [text.trim(), term].filter(Boolean).join(' ');
    this.setText(this.tab, next);
    this.ctx.ui.announce(has ? `Removed ${key} ${plain(value, { all: true })}` : `${exclude ? 'Excluding' : 'Filtering by'} ${key} ${plain(value, { all: true })}`);
  }

  // ---- tab rendering ---------------------------------------------------------------------------

  /** A note above the table: the functional zone J-Wicket does not display (OBJ-54). */
  renderTabNote() {
    const { h } = this;
    const zonesSec = this.section('zones');
    const notes = [];
    if (this.tab === 'zones' && (zonesSec.unmodeled || []).length) {
      notes.push(
        h(
          'div',
          { class: 'pv-notice', role: 'note' },
          this.ctx.dom.icon('info'),
          h('span', null, (zonesSec.unmodeled || []).includes('functional-zone management') ? 'Functional zone management is configured; J-Wicket does not display it yet.' : ['Zone settings J-Wicket does not display yet: ', this.v(zonesSec.unmodeled.join(', ')), '.']),
        ),
      );
    }
    this.ctx.dom.put(this.tabNoteEl, ...notes);
    this.tabNoteEl.hidden = !notes.length;
  }

  renderTab(announce = false) {
    const { h } = this;
    const tab = this.tab;
    const sec = this.section(tab);
    const bar = this.bars[tab];
    this.renderTabNote();
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
    // A set the query keeps only through a catalog port (J-Wicket's table, not the device) is marked.
    this.viaCatalog = new Set();
    if (tab === 'applications' && this.asts[tab] && /\bport\b|dport|destination-port/i.test(this.texts[tab] || '')) {
      const strict = this.matcher(tab, APP_FIELDS_DEVICE);
      for (const it of shown) if (it.catalogPorts.length && !strict(it)) this.viaCatalog.add(it.id);
    }
    this.terms = this.asts[tab] && this.Q ? this.Q.highlightTerms(this.asts[tab]) : [];
    if (bar) bar.setStatus(this.asts[tab] ? `${this.fmt.num(shown.length)} of ${this.fmt.num(all.length)}` : '');
    const secPresent = this.securityPresent();
    if (!all.length) {
      this.visible = [];
      const books = tab === 'address-books' ? this.idx.books : [];
      let empty;
      if (tab === 'zones') empty = [secPresent ? 'This scope has no security zones' : 'No security zones in what J-Wicket could read', null];
      else if (tab === 'address-books' && books.length) empty = ['No address book entries', `${this.fmt.plural(books.length, 'address book')}, none with an entry. Policies here can name only any, any-ipv4 or any-ipv6.`];
      else if (tab === 'address-books') empty = secPresent ? ['This scope has no address books', 'Policies here can name only any, any-ipv4 or any-ipv6.'] : ['No address books in what J-Wicket could read', null];
      else empty = ['No custom applications or application sets', 'Policies here use predefined junos-* applications only.'];
      this.ctx.dom.put(
        this.tableHost,
        this.ctx.dom.stateCard({ status: 'empty', title: empty[0], message: empty[1], hint: null }),
        books.length ? h('div', { class: 'pv-tablecard ob-tablecard' }, this.booksTable([])) : null,
      );
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
      this.mdPane = h('section', { class: 'ob-md-pane', 'aria-label': pick ? `Zone ${plain(pick.z.name, { all: true })}` : 'Zone' }, pick ? this.zoneDetail(pick) : null);
      this.ctx.dom.put(this.tableHost, h('div', { class: 'ob-md' }, h('div', { class: 'ob-md-list' }, h('div', { class: 'pv-tablecard ob-tablecard' }, table), more), this.mdPane));
    } else {
      this.mdPane = null;
      this.ctx.dom.put(this.tableHost, h('div', { class: 'pv-tablecard ob-tablecard' }, table), more);
    }
    this.markSelected();
    if (announce) this.ctx.ui.announce(`Showing ${shown.length} of ${this.fmt.plural(all.length, TABS.find((t) => t.id === tab).noun, TABS.find((t) => t.id === tab).plural)}.`);
  }

  /** A name with the query terms marked and hidden characters as badges (descriptions: all = false). */
  hl(text, extra, all = true) {
    return this.h('span', { class: ['pv-hl', extra] }, markNodes(this.h, text, this.terms, { all }));
  }

  token(key, value, cls, title) {
    return this.h('span', { class: ['pv-v', cls], dataset: { k: key, v: value }, title: title || `Filter by ${key}:${plain(value, { all: true })} (Alt-click to exclude)` }, markNodes(this.h, value, this.terms));
  }

  /** The title of a host-inbound chip: what all and any-service mean (OBJ-61, verified), else the filter. */
  chipTitle(s, key) {
    if (s === 'all' && key === 'proto') return 'all: every protocol (traffic from all protocols is allowed inbound)';
    if (s === 'all') return 'all: every system service on the Routing Engine';
    if (s === 'any-service') return 'any-service: services on the entire port range';
    return `Filter by ${key}:${plain(s, { all: true })} (Alt-click to exclude)`;
  }

  /**
   * Host-inbound chips for one column (services or protocols) of a zone or an interface: the entries in
   * effect, then "except" and the excluded ones struck through (OBJ-40), then the deactivated ones
   * (OBJ-41) dashed and struck, or "+N deactivated" when `compact`.
   */
  svcChips(o, which, { compact = false } = {}) {
    const { h } = this;
    const key = which === 'services' ? 'service' : 'proto';
    const kind = which === 'services' ? 'svc' : 'proto';
    const tag = which === 'services' ? 'system-services' : 'protocols';
    const list = o[which] || [];
    const except = o[`${which}_except`] || [];
    const off = o[`inactive_${which}`] || [];
    if (o.host_inbound === 'inactive') {
      return h('span', { class: 'ob-hit-off', title: `host-inbound-traffic is deactivated (inactive:): ${plain(off.join(', ')) || 'nothing'} not in effect` }, 'host-inbound-traffic deactivated: none of it is in effect');
    }
    if (!list.length && !except.length && !off.length) return h('span', { class: 'faint' }, 'none');
    const kids = list.map((s) => h('span', { class: ['ob-svc', kind, (s === 'all' || s === 'any-service') && 'wide'], dataset: { k: key, v: s }, title: this.chipTitle(s, key) }, markNodes(h, s, this.terms)));
    if (except.length) {
      const withAll = list.includes('all');
      kids.push(h('span', { class: 'ob-except-w' }, 'except'));
      for (const x of except) {
        kids.push(h('span', { class: ['ob-svc', kind, 'is-except'], dataset: { k: 'except', v: x }, title: `${plain(x, { all: true })} is excluded (${tag} ${plain(x, { all: true })} except)` }, markNodes(h, x, this.terms)));
      }
      if (!withAll) {
        kids.push(
          h(
            'span',
            { class: 'ob-except-note' },
            which === 'services' ? '(Junos accepts except only with all)' : '(Junos accepts except only with all; inferred for protocols)',
          ),
        );
      }
    }
    if (off.length && compact) {
      kids.push(h('span', { class: 'ob-svc-offn', title: `Deactivated (inactive:), not in effect: ${plain(off.join(', '))}` }, `+${off.length} deactivated`));
    } else {
      for (const x of off) {
        const ex = / except$/.test(x);
        const name = svcName(x);
        kids.push(
          h(
            'span',
            { class: ['ob-svc', kind, 'is-off'], dataset: { k: 'inactive-svc', v: name }, title: `Deactivated (inactive: ${tag} ${plain(x, { all: true })}): not in effect` },
            ex ? ['except ', markNodes(h, name, this.terms), ` (deactivated: ${plain(name, { all: true })} is not excluded)`] : markNodes(h, name, this.terms),
          ),
        );
      }
    }
    return h('span', { class: 'ob-chips' }, kids);
  }

  rowAttrs(it, i, extraCls) {
    return { class: ['pv-row', 'ob-row', extraCls], dataset: { i: String(i), id: it.id } };
  }

  /** Row badges shared by the three tables: scope deactivated, comment, hidden characters, settings, parts. */
  rowBadges(o, it) {
    const { h } = this;
    const out = [];
    if (this.idx.scopeOff) out.push(h('span', { class: 'pv-badge b-inactive', title: 'The scope is deactivated in the configuration: nothing in it is in effect' }, 'scope deactivated'));
    const comments = it.comments || [];
    if (comments.length) {
      const text = plain(comments.join('\n'));
      out.push(
        h(
          'span',
          { class: 'pv-badge b-note ob-note', title: text.length > 200 ? `${text.slice(0, 199)}…` : text },
          this.ctx.dom.icon(COMMENT_ICON, { size: 11 }),
          h('span', null, 'note'),
          h('span', { class: 'sr-only' }, ': configuration comment (annotate)'),
        ),
      );
    }
    const hidden = uniq(it.hidden || []);
    if (hidden.length) out.push(h('span', { class: 'pv-badge b-warn', title: `Hidden characters, shown as badges: ${hidden.join(', ')}` }, 'hidden characters'));
    if ((o.unmodeled || []).length) out.push(h('span', { class: 'pv-badge b-warn', title: `J-Wicket does not display: ${plain(o.unmodeled.join(', '))}` }, 'settings not shown'));
    if ((o.inactive_parts || []).length && !o.inactive) out.push(h('span', { class: 'pv-badge b-warn', title: `Deactivated, not in effect: ${plain(o.inactive_parts.join(', '))}` }, 'parts deactivated'));
    return out;
  }

  /** "own: services all except ssh · protocols —" for an interface with its own host-inbound-traffic. */
  ifaceOwn(f) {
    const { h } = this;
    if (f.host_inbound === 'absent' || !f.host_inbound) {
      // Older snapshots carry no host_inbound: own settings are the lists themselves.
      if (f.host_inbound === undefined && ((f.services || []).length || (f.protocols || []).length)) return h('span', { class: 'ob-own' }, 'own: ', this.v([...(f.services || []), ...(f.protocols || [])].join(', ')));
      return h('span', { class: 'ob-inherit faint' }, 'zone settings');
    }
    if (f.host_inbound === 'inactive') return h('span', { class: 'ob-own is-off', title: 'host-inbound-traffic deactivated: none of it is in effect' }, 'own: deactivated');
    const col = (which, label) => {
      const list = f[which] || [];
      const except = f[`${which}_except`] || [];
      const off = f[`inactive_${which}`] || [];
      const present = f[`${which}_present`];
      if (!present && !list.length && !except.length) return [label, ' —'];
      const parts = [label, ' ', list.length ? this.v(list.join(' ')) : '—'];
      if (except.length) parts.push(' except ', this.v(except.join(' ')));
      if (off.length) parts.push(h('span', { class: 'ob-own-off' }, ` +${off.length} deactivated`));
      return parts;
    };
    const nothing = !(f.services || []).length && !(f.protocols || []).length;
    return h(
      'span',
      { class: ['ob-own', nothing && 'is-off'], title: nothing ? 'own host-inbound-traffic with nothing active; whether the zone’s settings still apply is not verified' : 'This interface has its own host-inbound-traffic settings. Interface configuration overrides that of the zone.' },
      'own: ',
      col('services', 'services'),
      SEP,
      col('protocols', 'protocols'),
    );
  }

  /** "4 active + 1 inactive in 3 pairs" (OBJ-44; a deactivated scope reads "0 active + N inactive"). */
  zoneCount(use) {
    const fmt = this.fmt;
    return `${fmt.num(use.count)} active${use.off ? ` + ${fmt.num(use.off)} inactive` : ''} in ${fmt.plural(use.pairs.length, 'pair')}`;
  }

  /** zoneCount() as nodes, the active count in bold. */
  zoneCountNodes(use) {
    const { h } = this;
    const fmt = this.fmt;
    return [h('b', null, fmt.num(use.count)), ' active', use.off ? h('span', { class: 'ob-used-off' }, ` + ${fmt.num(use.off)} inactive`) : null, h('span', null, ` in ${fmt.plural(use.pairs.length, 'pair')}`)];
  }

  zonesTable(page) {
    const { h } = this;
    const rows = page.map((it, i) => {
      const z = it.z;
      const ifaces = z.interfaces || [];
      const badges = [...provBadges(h, z, { direct: !this.rowBadges(z, it).length }), ...this.rowBadges(z, it)];
      return h(
        'tr',
        this.rowAttrs(it, i, (z.inactive || it.scopeOff) && 'is-inactive'),
        h(
          'th',
          { scope: 'row', class: 'c-name' },
          h('button', { class: 'pv-name', type: 'button', 'aria-haspopup': 'dialog', title: `Open zone ${plain(z.name, { all: true })}` }, this.hl(z.name)),
          z.description ? h('div', { class: 'pv-desc', title: plain(z.description) }, this.hl(z.description, null, false)) : null,
        ),
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
                    { class: f.inactive ? 'is-off' : null },
                    this.token('iface', f.name, ['iface', f.inactive && 'is-struck'], f.inactive ? 'Deactivated: this interface is not bound to the zone (not in effect; inferred)' : null),
                    f.inactive ? h('span', { class: 'pv-tag amber', title: 'Deactivated: this interface is not bound to the zone (not in effect; inferred)' }, 'deactivated') : null,
                    f.group ? h('span', { class: 'pv-badge b-group' }, 'group ', this.v(f.group)) : null,
                    f.inactive ? null : this.ifaceOwn(f),
                  ),
                ),
              )
            : h('span', { class: 'faint' }, 'no interfaces'),
        ),
        h('td', { class: ['c-svc', z.host_inbound !== 'inactive' && !(z.services || []).length && !(z.services_except || []).length && !(z.inactive_services || []).length && 'is-empty'], dataset: { label: 'Services' } }, this.svcChips(z, 'services', { compact: true })),
        h('td', { class: ['c-proto', z.host_inbound !== 'inactive' && !(z.protocols || []).length && !(z.protocols_except || []).length && !(z.inactive_protocols || []).length && 'is-empty'], dataset: { label: 'Protocols' } }, this.svcChips(z, 'protocols', { compact: true })),
        h(
          'td',
          { class: ['c-screen', !z.screen && 'is-empty'], dataset: { label: 'Screen' } },
          z.screen ? this.token('screen', z.screen) : h('span', { class: 'faint' }, 'none'),
          (z.inactive_parts || []).some((p) => /^screen /.test(p)) ? h('div', { class: 'pv-hint pv-amber', title: 'The screen statement is deactivated (inactive:): not in effect' }, this.v(`${(z.inactive_parts || []).find((p) => /^screen /.test(p))} deactivated`)) : null,
        ),
        h(
          'td',
          { class: 'c-used', dataset: { label: 'Policies' } },
          this.idx.polOk
            ? h(
                'button',
                { class: 'ob-used', type: 'button', dataset: { zone: z.name }, title: `Show the policies with zone:${plain(z.name, { all: true })} (only active policies are counted)` },
                this.zoneCountNodes(it.use),
                it.use.globals.length ? h('span', { class: 'faint' }, ` + ${it.use.globalsActive} global`) : null,
              )
            : h('span', { class: 'faint' }, '—'),
        ),
        h('td', { class: ['c-prov', isDirect(z) && !this.rowBadges(z, it).length && 'is-empty'], dataset: { label: 'Provenance' } }, h('div', { class: 'pv-badges' }, badges)),
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
          h('th', { scope: 'col', class: 'c-used', title: 'Active policies whose from-zone or to-zone is this zone; deactivated ones are counted apart' }, 'Policies'),
          h('th', { scope: 'col', class: 'c-prov' }, 'Provenance'),
        ),
      ),
      h('tbody', null, rows),
    );
  }

  /** Where a book applies, in words (OBJ-48, OBJ-49). */
  bookAttach(b) {
    const off = b.inactive_attach || [];
    const offText = off.length ? ` (attach zone ${off.join(', ')} ${off.length === 1 ? 'is' : 'are'} deactivated: not in effect)` : '';
    if (b.inactive) {
      const written = [...(b.attach || []), ...off];
      return `deactivated: not used by any zone${written.length ? ` (attach zone ${written.join(', ')} is written but not in effect)` : ''}`;
    }
    if (b.legacy_zone) return `zone-level address book of ${b.legacy_zone} (legacy form)`;
    if ((b.attach || []).length) return `attached to ${b.attach.length === 1 ? 'zone' : 'zones'} ${b.attach.join(', ')}${offText}`;
    if (b.name === 'global') return `global: usable from every zone${offText}`;
    return `not attached to any zone${offText}`;
  }

  /** The "Usable from" cell of an entry: chips, or why none (OBJ-48, OBJ-49). */
  usableFrom(it) {
    const { h } = this;
    const b = it.book;
    if (b.inactive) return h('span', { class: 'faint' }, 'none (book deactivated)');
    if (!it.zones.length && (b.inactive_attach || []).length) return h('span', { class: 'faint' }, 'none (', this.v(b.inactive_attach.join(', ')), ' deactivated)');
    if (!it.zones.length) return h('span', { class: 'faint' }, 'none');
    return h('span', { class: 'ob-chips' }, it.zones.map((z) => (z === 'global' ? h('span', { class: 'zone pv-zone-any' }, 'any zone') : h('span', { class: 'zone' }, this.v(z)))));
  }

  /** The header row of one book in the table: name, where it applies, entry count, description. */
  bookHead(b, shown, total) {
    const { h } = this;
    const fmt = this.fmt;
    return h(
      'tr',
      { class: ['pv-sec', 'ob-book', b.inactive && 'is-off'], dataset: { book: b.name } },
      h(
        'th',
        { colspan: '6', scope: 'colgroup' },
        h(
          'div',
          { class: 'pv-sec-in' },
          h('button', { class: 'ob-bookname', type: 'button', dataset: { book: b.name }, title: `About address book ${plain(b.name, { all: true })}` }, this.ctx.dom.icon('globe'), this.v(b.name)),
          h(
            'span',
            { class: 'pv-sec-sub' },
            this.v(this.bookAttach(b)),
            SEP,
            shown === total ? fmt.plural(total, 'entry', 'entries') : `${shown} of ${fmt.plural(total, 'entry', 'entries')}`,
            b.description ? [SEP, h('span', { class: 'ob-book-desc', title: plain(b.description) }, this.vd(b.description))] : null,
          ),
          ...provBadges(h, b, { direct: false }),
          commentsOf(b).length ? h('span', { class: 'pv-sec-comment', title: `Configuration comment (annotate; not a setting): ${plain(commentsOf(b).join(' | '))}` }, this.ctx.dom.icon(COMMENT_ICON, { size: 13 })) : null,
          (b.unmodeled || []).length ? h('span', { class: 'pv-badge b-warn', title: `J-Wicket does not display: ${plain(b.unmodeled.join(', '))}` }, 'settings not shown') : null,
        ),
      ),
    );
  }

  /** Set members in the table: active first, then deactivated members struck through (OBJ-46, OBJ-51). */
  setMembers(it, addrMax = 5, setMax = 3) {
    const { h } = this;
    const isApp = it.type === 'app';
    const e = isApp ? it.a : it.entry;
    const byName = isApp ? this.idx.appByName : (this.idx.bookSets.get(it.book.name) || {}).addrs || new Map();
    const setsBy = isApp ? this.idx.appByName : (this.idx.bookSets.get(it.book.name) || {}).sets || new Map();
    const objOff = (n, sets) => Boolean(((sets ? setsBy : byName).get(n) || {}).inactive);
    const plainList = isApp ? e.members || [] : e.addresses || [];
    const nested = e.sets || [];
    const offList = isApp ? [...(e.inactive_applications || []), ...(e.inactive_sets || [])] : [...(e.inactive_addresses || []), ...(e.inactive_sets || [])];
    const shownPlain = plainList.slice(0, addrMax);
    const shownSets = nested.slice(0, setMax);
    const kids = [];
    for (const n of shownPlain) {
      const off = objOff(n, false);
      kids.push(off ? h('span', { class: 'ob-member-off', title: `${plain(n, { all: true })} is itself deactivated: skipped (not in effect)` }, markNodes(h, n, this.terms), ' (deactivated)') : this.token('member', n, isApp && /^junos-/.test(n) ? 'is-predef' : null));
    }
    for (const n of shownSets) {
      const off = objOff(n, true);
      kids.push(h('span', { class: 'ob-nested' }, h('span', { class: 'pv-tag' }, 'set'), off ? h('span', { class: 'ob-member-off', title: `${plain(n, { all: true })} is itself deactivated: skipped (not in effect)` }, markNodes(h, n, this.terms), ' (deactivated)') : this.token('member', n)));
    }
    const offShown = offList.slice(0, 3);
    for (const n of offShown) kids.push(h('span', { class: 'ob-member-off is-struck', dataset: { k: 'member-inactive', v: n }, title: `The member statement ${plain(n, { all: true })} is deactivated (inactive:): not in effect` }, markNodes(h, n, this.terms), ' (deactivated member)'));
    const hidden = plainList.length + nested.length + offList.length - shownPlain.length - shownSets.length - offShown.length;
    if (hidden > 0) kids.push(h('button', { class: 'pv-more ob-more-link', type: 'button', dataset: { open: it.id }, title: 'Open to see every member' }, `+${hidden} more`));
    return h('span', { class: 'ob-members' }, kids);
  }

  booksTable(page) {
    const { h } = this;
    const fmt = this.fmt;
    const byBook = new Map();
    page.forEach((it, i) => {
      if (!byBook.has(it.book.name)) byBook.set(it.book.name, []);
      byBook.get(it.book.name).push([it, i]);
    });
    const bodies = [];
    // A header row for every book (an empty one reads "0 entries", OBJ-50); with a query, only the
    // books that hold a match.
    const showAll = !this.asts['address-books'];
    for (const b of this.idx.books) {
      const list = byBook.get(b.name) || [];
      const total = (b.addresses || []).length + (b.sets || []).length;
      if (!list.length && !(showAll && total === 0)) continue;
      const head = this.bookHead(b, list.length, total);
      const rows = list.map(([it, i]) => {
        const e = it.entry;
        const isSet = it.type === 'set';
        let value;
        if (isSet) value = this.setMembers(it);
        else if (it.kind === 'unknown') value = h('span', { class: 'pv-amber', title: 'J-Wicket does not read this form of address' }, 'address form J-Wicket does not read: ', this.v((e.unmodeled || []).join(', ') || 'not reported'));
        else value = h('span', { class: 'ob-value' }, e.value ? this.token('addr', e.value, 'ip') : h('span', { class: 'faint' }, '—'));
        const inEffect = isSet ? [...it.closure].filter((n) => (b.addresses || []).some((a) => a.name === n)).length : 0;
        const badges = this.rowBadges(e, it);
        return h(
          'tr',
          this.rowAttrs(it, i, !it.effective && 'is-inactive'),
          h(
            'th',
            { scope: 'row', class: 'c-name' },
            h('button', { class: 'pv-name', type: 'button', 'aria-haspopup': 'dialog', title: `Open ${plain(it.name, { all: true })}` }, this.hl(it.name)),
            e.description ? h('div', { class: 'pv-desc', title: plain(e.description) }, this.hl(e.description, null, false)) : null,
          ),
          h('td', { class: 'c-kind', dataset: { label: 'Kind' } }, h('span', { class: ['ob-kind', `k-${it.kind}`] }, it.kind)),
          h(
            'td',
            { class: ['c-value', !isSet && !e.value && it.kind !== 'unknown' && 'is-empty'], dataset: { label: isSet ? 'Members' : 'Value' } },
            value,
            isSet ? h('div', { class: 'pv-hint' }, `${fmt.plural(inEffect, 'address', 'addresses')} in effect`) : null,
          ),
          h('td', { class: 'c-used', dataset: { label: 'Used by' } }, this.usedCell(it)),
          h('td', { class: ['c-prov', isDirect(e) && !badges.length && 'is-empty'], dataset: { label: 'Provenance' } }, h('div', { class: 'pv-badges' }, provBadges(h, e, { direct: !badges.length }), badges)),
          h('td', { class: ['c-zones', !it.zones.length && 'is-empty'], dataset: { label: 'Zones' } }, this.usableFrom(it)),
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
          h('th', { scope: 'col', title: 'Active policies naming this entry, directly or through an address set; deactivated ones are counted apart' }, 'Used by'),
          h('th', { scope: 'col' }, 'Provenance'),
          h('th', { scope: 'col', title: 'Zones whose policies can name this entry' }, 'Usable from'),
        ),
      ),
      bodies,
    );
  }

  /** "2 policies (1 via set)" plus a faint "+1 inactive"; "unused (1 inactive policy)"; not in effect (OBJ-44, 45, 49). */
  usedCell(it) {
    const { h } = this;
    if (!this.idx.polOk) return h('span', { class: 'faint' }, '—');
    const o = it.entry || it.a;
    if (o && o.inactive) return h('span', { class: 'ob-unused', title: 'Deactivated in the configuration (inactive:): no policy can use it' }, 'not in effect (deactivated)');
    if (it.book && it.book.inactive) return h('span', { class: 'ob-unused', title: 'Its address book is deactivated (inactive:): no policy can use it' }, 'not in effect (book deactivated)');
    const d = it.use.direct.length;
    const v = it.use.via.length;
    const off = it.use.off.length;
    if (!d && !v) {
      return h(
        'span',
        { class: 'ob-unused', title: off ? 'Only deactivated policies name it, directly or through a set: not in effect' : 'No policy in this scope names it, directly or through a set' },
        off ? `unused (${this.fmt.plural(off, 'inactive policy', 'inactive policies')})` : 'unused',
      );
    }
    return h(
      'button',
      { class: 'ob-used', type: 'button', dataset: { used: it.id }, title: 'Open to see which policies use it (only active policies are counted)' },
      h('b', null, this.fmt.num(d + v)),
      h('span', null, ` ${d + v === 1 ? 'policy' : 'policies'}`),
      v ? h('span', { class: 'faint' }, ` (${v} via set)`) : null,
      off ? h('span', { class: 'faint ob-used-off' }, ` +${off} inactive`) : null,
    );
  }

  /** The Port cell of a set: device-read ports, then "+2 predefined" tagged catalog (OBJ-47). */
  setPorts(it) {
    const { h } = this;
    const Q = this.Q;
    const kids = [];
    kids.push(h('span', { class: 'faint mono' }, it.ports.length ? this.v(it.ports.join(', ')) : '—'));
    if (it.catalog.length) {
      kids.push(
        SEP,
        h('span', { class: 'ob-catalog-n', title: `${it.catalog.map((c) => `${c.name} ${c.protocol}/${c.port}`).join(', ')}` }, `+${it.catalog.length} predefined`),
        ' ',
        h('span', { class: 'pv-tag ob-catalog', title: Q && Q.PREDEFINED_SOURCE ? Q.PREDEFINED_SOURCE : null }, 'catalog'),
      );
    }
    if (it.unknownPredefined.length) kids.push(SEP, h('span', { class: 'muted', title: `Predefined, not in J-Wicket’s table: ${plain(it.unknownPredefined.join(', '))}` }, `${it.unknownPredefined.length} port not read`));
    if (this.viaCatalog && this.viaCatalog.has(it.id)) kids.push(h('div', { class: 'pv-qmark ob-catalog-mark', title: 'Listed because a predefined member’s port in J-Wicket’s own table matches, not a port read from this device' }, 'catalog port'));
    return kids;
  }

  appsTable(page) {
    const { h } = this;
    const fmt = this.fmt;
    const rows = page.map((it, i) => {
      const a = it.a;
      const isSet = a.kind === 'set';
      const badges = this.rowBadges(a, it);
      return h(
        'tr',
        this.rowAttrs(it, i, (a.inactive || it.scopeOff) && 'is-inactive'),
        h(
          'th',
          { scope: 'row', class: 'c-name' },
          h('button', { class: 'pv-name', type: 'button', 'aria-haspopup': 'dialog', title: `Open ${plain(a.name, { all: true })}` }, this.hl(a.name)),
          a.description ? h('div', { class: 'pv-desc', title: plain(a.description) }, this.hl(a.description, null, false)) : null,
        ),
        h('td', { class: 'c-kind', dataset: { label: 'Kind' } }, h('span', { class: ['ob-kind', isSet ? 'k-set' : 'k-app'] }, isSet ? 'set' : 'application')),
        h(
          'td',
          { class: ['c-proto', (isSet ? !it.protocols.length : !a.protocol && !a.terms) && 'is-empty'], dataset: { label: 'Protocol' } },
          isSet ? h('span', { class: 'faint' }, it.protocols.length ? this.v(it.protocols.join(', ')) : '—') : a.protocol ? this.token('proto', a.protocol) : a.terms ? h('span', { class: 'muted' }, `${fmt.plural(a.terms, 'term')}`) : h('span', { class: 'faint' }, '—'),
        ),
        h(
          'td',
          { class: ['c-port', (isSet ? !it.ports.length && !it.catalog.length && !it.unknownPredefined.length : !a.destination_port) && 'is-empty'], dataset: { label: 'Port' } },
          isSet ? this.setPorts(it) : a.destination_port ? this.token('port', a.destination_port) : h('span', { class: 'faint' }, '—'),
          !isSet && a.source_port ? h('div', { class: 'pv-hint' }, 'source ', this.v(a.source_port)) : null,
          !isSet && (a.inactive_parts || []).length ? h('div', { class: 'pv-hint pv-amber', title: 'Deactivated (inactive:): not in effect' }, this.v(`${a.inactive_parts.join(', ')} deactivated`)) : null,
        ),
        h('td', { class: ['c-members', !isSet && 'is-empty'], dataset: { label: 'Members' } }, isSet ? this.setMembers(it, 6, 3) : h('span', { class: 'faint' }, '—')),
        h('td', { class: 'c-used', dataset: { label: 'Used by' } }, this.usedCell(it)),
        h('td', { class: ['c-prov', isDirect(a) && !badges.length && 'is-empty'], dataset: { label: 'Provenance' } }, h('div', { class: 'pv-badges' }, provBadges(h, a, { direct: !badges.length }), badges)),
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
          h('th', { scope: 'col', title: 'Destination port (source port below when set). Sets: ports read from the device, then predefined members from J-Wicket’s own table (catalog).' }, 'Port'),
          h('th', { scope: 'col' }, 'Members'),
          h('th', { scope: 'col', title: 'Active policies naming it, directly or through a set; deactivated ones are counted apart' }, 'Used by'),
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
      this.ctx.navigate('policies', { q: `zone:${qvDevice(zoneUsed.dataset.zone)}` });
      return;
    }
    const more = t.closest('.ob-more-link[data-open]');
    if (more) {
      this.openSel(more.dataset.open, { push: true });
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
        this.mdPane.setAttribute('aria-label', plain(title, { all: true }));
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
    return this.h('button', { class: 'btn sm', type: 'button', title: plain(title || label, { all: true }), on: { click: () => this.ctx.navigate(view, params) } }, this.ctx.dom.icon(iconName), label);
  }

  /** The eyebrow line of a detail: "Address set · global · Root system". */
  eyebrow(...parts) {
    const out = [];
    parts.filter(Boolean).forEach((p, i) => {
      if (i) out.push(SEP);
      out.push(this.v(p));
    });
    return out;
  }

  /** A CLI block, or the "not offered" note when a name would break a pasted command (CRT-14). */
  cli(words, names) {
    return cliBlock(this.ctx, cliJoin(words), 'Copy command', [scopeParts(this.ctx.store.scope).name, ...names].filter((x) => x !== null && x !== undefined));
  }

  /** "show configuration <prefix>" words: null when the scope name is unsafe. */
  showConfig(rest) {
    const prefix = cliPrefix(this.ctx.store.scope);
    return ['show configuration', prefix === null ? null : `${prefix}${rest}`];
  }

  /** The configuration comments of an object, verbatim (OBJ-52): "Configuration comment (annotate): not a setting". */
  commentBlock(o, extra = []) {
    const { h } = this;
    const items = [];
    if (o.comment) items.push(h('li', null, h('span', { class: 'pv-cmt-where' }, 'On it: '), h('span', { class: 'ob-cmt' }, this.vd(o.comment))));
    for (const c of o.part_comments || []) {
      if (!c || !c.text) continue;
      items.push(h('li', null, h('span', { class: 'pv-cmt-where' }, c.before ? ['Inside it, before ', h('span', { class: 'mono' }, this.v(c.before)), ': '] : 'Inside it, at the end: '), h('span', { class: 'ob-cmt' }, this.vd(c.text))));
    }
    for (const [label, text] of extra) if (text) items.push(h('li', null, h('span', { class: 'pv-cmt-where' }, label), h('span', { class: 'ob-cmt' }, this.vd(text))));
    if (!items.length) return null;
    return this.psec('Configuration comment (annotate): not a setting', h('ul', { class: 'pv-cmts ob-cmts' }, items));
  }

  /** Settings J-Wicket does not display yet, with the command to read them (OBJ-53). */
  unmodeledBlock(o, words, names) {
    const { h } = this;
    const list = o.unmodeled || [];
    const parts = o.inactive_parts || [];
    const kids = [];
    if (list.length) {
      kids.push(
        this.psec(
          'Not shown by J-Wicket yet',
          h(
            'div',
            { class: 'pv-callout amber' },
            h('p', null, 'These settings are in the configuration; J-Wicket does not display them yet. Check them on the device:'),
            h('ul', { class: 'pv-bullets' }, list.map((u) => h('li', { class: 'mono' }, this.v(u)))),
            this.cli(words, names),
          ),
        ),
      );
    }
    if (parts.length && !o.inactive) {
      kids.push(
        this.psec(
          'Deactivated parts, not in effect',
          h('div', { class: 'pv-callout reject' }, h('p', null, 'Written in the configuration but deactivated (inactive:), so not in effect:'), h('ul', { class: 'pv-bullets' }, parts.map((p) => h('li', { class: 'mono' }, this.v(p))))),
        ),
      );
    }
    return kids;
  }

  /** Active policies that use it, then deactivated policies that name it, apart (OBJ-44). */
  policyList(use) {
    const { h } = this;
    const pol = this.idx.pol;
    if (!this.idx.polOk) return h('p', { class: 'pv-small muted' }, 'The policies of this scope could not be read, so their use is not known.');
    const items = [...use.direct.map((idx) => ({ idx, set: null })), ...use.via];
    const off = use.off || [];
    const zl = (l) => ((l || []).length ? l.join(', ') : 'any');
    const li = ({ idx, set }) => {
      const r = pol[idx];
      return h(
        'li',
        { class: r.inactive ? 'is-inactive' : null },
        h('button', { class: 'pv-ord-name', type: 'button', title: `Open ${plain(r.name, { all: true })} in Policies`, on: { click: () => this.ctx.navigate('policies', { q: `name:${qvDevice(r.name)}`, sel: r.id }) } }, this.v(r.name)),
        h('span', { class: ['pill', ['permit', 'deny', 'reject'].includes(r.action) ? r.action : 'muted'] }, r.action),
        h('span', { class: 'ob-use-z' }, r.kind === 'global' ? 'global ' : '', h('span', { class: 'mono' }, this.v(zl(r.from))), h('span', { class: 'arrow' }, ` ${ARROW} `), h('span', { class: 'mono' }, this.v(zl(r.to)))),
        set ? h('span', { class: 'pv-tag' }, 'via set ', this.v(set)) : h('span', { class: 'faint' }, 'direct'),
        r.inactive ? h('span', { class: 'faint' }, offReason(r)) : null,
      );
    };
    items.sort((a, b) => a.idx - b.idx);
    const kids = [];
    if (items.length) kids.push(h('ul', { class: 'ob-uselist' }, items.map(li)));
    else kids.push(h('p', { class: 'pv-small muted' }, 'No active policy in this scope names it, directly or through a set.'));
    if (off.length) {
      kids.push(h('p', { class: 'pv-ord-label' }, 'Deactivated policies that name it (not in effect)'), h('ul', { class: 'ob-uselist' }, [...off].sort((a, b) => a.idx - b.idx).map(li)));
    }
    return kids;
  }

  /** Host-inbound cell of an interface for one column, with the per-column fallback (OBJ-43). */
  ifaceHitCell(f, which) {
    const { h } = this;
    const other = which === 'services' ? 'protocols' : 'system services';
    const mine = which === 'services' ? 'system services' : 'protocols';
    if (f.host_inbound === 'inactive') return this.svcChips(f, which);
    const has = (f[which] || []).length || (f[`${which}_except`] || []).length || (f[`inactive_${which}`] || []).length || f[`${which}_present`];
    if (has) return [this.svcChips(f, which), h('div', { class: 'ob-prec' }, 'interface setting (overrides the zone)')];
    if (f.host_inbound === 'active') {
      return h('span', { class: 'ob-fromzone', title: 'Not verified against a Juniper document' }, `from the zone (J-Wicket assumes ${mine} are not overridden when the interface lists only ${other}; not verified)`);
    }
    return h('span', { class: 'ob-fromzone' }, 'from the zone');
  }

  zoneDetail(it) {
    const { h } = this;
    const z = it.z;
    const fmt = this.fmt;
    const scopeId = this.ctx.store.scope;
    const root = scopeParts(scopeId).kind === 'root';
    const actions = [
      this.navBtn('policies', 'Policies with this zone', 'policies', { q: `zone:${qvDevice(z.name)}` }),
      this.navBtn('sessions', 'Sessions', 'sessions', { q: `zone:${qvDevice(z.name)}` }, `Live sessions whose policy is from or to ${z.name}`),
      this.navBtn('logs', 'Logs', 'logs', { q: `zone:${qvDevice(z.name)}` }, `Log lines with source or destination zone ${z.name}`),
    ];
    const ifaces = z.interfaces || [];
    const offIfaces = ifaces.filter((f) => f.inactive).length;
    const hero = this.hero(this.eyebrow('Security zone', scopeTitle(this.snap, scopeId)), [
      h('span', { class: ['zone', 'ob-zone-big', z.inactive && 'is-struck'] }, this.v(z.name)),
      h('span', { class: 'pv-where-pos' }, `${fmt.plural(ifaces.length - offIfaces, 'interface')}${offIfaces ? ` (+${offIfaces} deactivated)` : ''}${SEP}screen `, z.screen ? this.v(z.screen) : 'none'),
      ...provBadges(h, z, { direct: false }),
      ...this.rowBadges(z, it),
    ], actions);
    const notice = z.inactive
      ? h(
          'div',
          { class: 'pv-callout reject', role: 'note' },
          h('p', null, 'Zone ', h('b', { class: 'mono' }, this.v(z.name)), ' is deactivated in the configuration: not in effect. Its interfaces are not bound to it (inferred). Policies that name it are listed below; J-Wicket does not yet mark them (Spec 001 open question 3).'),
        )
      : null;
    const hitProv = (o) => {
      const inh = (o.inherited || []).filter((p) => /^host-inbound-traffic/.test(p));
      const badges = provBadges(h, { group: o.host_inbound_group || null, inherited: inh }, { direct: false });
      return badges.length ? h('div', { class: 'pv-badges' }, badges) : h('span', { class: 'faint' }, 'direct');
    };
    const nothingActive = (o) => o.host_inbound === 'active' && !(o.services || []).length && !(o.protocols || []).length;
    const hitRows = [
      h(
        'tr',
        { class: 'ob-hit-zone' },
        h('td', null, h('b', null, 'zone'), h('div', { class: 'pv-hint' }, 'every interface without its own settings')),
        h('td', null, this.svcChips(z, 'services')),
        h('td', null, this.svcChips(z, 'protocols')),
        h('td', null, hitProv(z)),
      ),
      ...ifaces.map((f) =>
        h(
          'tr',
          { class: f.inactive ? 'is-off' : null },
          h(
            'td',
            null,
            h('span', { class: ['iface', f.inactive && 'is-struck'], title: f.inactive ? 'Deactivated: this interface is not bound to the zone (not in effect; inferred)' : null }, this.v(f.name)),
            f.inactive ? [' ', h('span', { class: 'pv-tag amber', title: 'Deactivated: this interface is not bound to the zone (not in effect; inferred)' }, 'deactivated')] : null,
            f.inactive ? h('div', { class: 'pv-hint' }, 'not in effect') : null,
            nothingActive(f) ? h('div', { class: 'pv-hint pv-amber' }, 'own host-inbound-traffic with nothing active; whether the zone’s settings still apply is not verified') : null,
          ),
          h('td', null, f.inactive ? h('span', { class: 'faint' }, '—') : this.ifaceHitCell(f, 'services')),
          h('td', null, f.inactive ? h('span', { class: 'faint' }, '—') : this.ifaceHitCell(f, 'protocols')),
          h('td', null, f.group ? h('span', { class: 'pv-badge b-group' }, 'group ', this.v(f.group)) : hitProv(f)),
        ),
      ),
    ];
    const hit = this.psec('Host-inbound traffic', [
      h('p', { class: 'pv-small muted' }, 'What the firewall itself answers on this zone’s interfaces (for example ping, SSH, HTTPS for J-Web, IKE). It does not affect traffic passing through. Interface configuration overrides that of the zone.'),
      nothingActive(z) ? h('p', { class: 'pv-small pv-amber' }, 'The zone has its own host-inbound-traffic with nothing active; whether the zone’s settings still apply is not verified.') : null,
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
          ? [
              h('p', { class: 'pv-small muted' }, `${this.zoneCount(use)}; only active policies are counted.`),
              h(
                'ul',
                { class: 'ob-pairs' },
                use.pairs.map((p) =>
                  h(
                    'li',
                    null,
                    h(
                      'button',
                      { class: 'ob-pair', type: 'button', title: `Show the ${plain(p.from, { all: true })} → ${plain(p.to, { all: true })} policies`, on: { click: () => this.ctx.navigate('policies', { q: `from:${qvDevice(p.from)} to:${qvDevice(p.to)}` }) } },
                      h('span', { class: ['zone', p.from === z.name && 'is-this'] }, this.v(p.from)),
                      h('span', { class: 'arrow' }, ARROW),
                      h('span', { class: ['zone', p.to === z.name && 'is-this'] }, this.v(p.to)),
                      h('span', { class: 'ob-pair-n' }, `${fmt.num(p.active)} active${p.off ? ` + ${fmt.num(p.off)} inactive` : ''}`),
                    ),
                  ),
                ),
                use.globals.length
                  ? h(
                      'li',
                      null,
                      h(
                        'button',
                        { class: 'ob-pair', type: 'button', on: { click: () => this.ctx.navigate('policies', { q: `kind:global zone:${qvDevice(z.name)}` }) } },
                        h('span', { class: 'pv-sec-name' }, 'Global'),
                        h('span', { class: 'ob-pair-n' }, `${fmt.plural(use.globalsActive, 'active global policy', 'active global policies')} ${use.globalsActive === 1 ? 'applies' : 'apply'}${use.globals.length > use.globalsActive ? ` (+${use.globals.length - use.globalsActive} inactive)` : ''}`),
                      ),
                    )
                  : null,
              ),
            ]
          : h('p', { class: 'pv-small muted' }, 'No policy names this zone. Flows from or to it are decided by the global policies that apply, then the default policy.'),
    ]);
    const bookSec = this.psec('Address books its policies can use', this.zoneBooks(z));
    const prefixWords = this.showConfig('security zones security-zone');
    const cli = [this.cli([...prefixWords, cliWord(z.name)], [z.name])];
    if (root) cli.push(this.cli(['show security zones', cliWord(z.name)], [z.name]));
    return h(
      'div',
      { class: 'pv-detail' },
      hero,
      notice,
      z.description ? h('p', { class: 'pv-desc-full' }, this.vd(z.description)) : null,
      this.commentBlock(z, ifaces.filter((f) => f.comment && !(z.part_comments || []).some((c) => c.text === f.comment)).map((f) => [['On interface ', h('span', { class: 'mono' }, this.v(f.name)), ': '], f.comment])),
      hit,
      ...this.unmodeledBlock(z, [...prefixWords, cliWord(z.name)], [z.name]),
      pairs,
      bookSec,
      this.psec('See it on the device', cli),
    );
  }

  /**
   * The address books a zone's policies can use, numbered in lookup order (OBJ-57): the zone's legacy
   * book, the books attached to it, then the global book. Attached before global is verified; legacy
   * first is inferred (J-Wicket's reading). Deactivated attach statements and books are listed apart.
   */
  zoneBooks(z) {
    const { h } = this;
    const books = this.idx.books;
    const legacy = books.filter((b) => b.legacy_zone === z.name && !b.inactive);
    const attached = books.filter((b) => !b.legacy_zone && (b.attach || []).includes(z.name) && !b.inactive);
    const global = books.filter((b) => b.name === 'global' && !b.legacy_zone && !b.inactive && !(b.attach || []).includes(z.name));
    const order = [...legacy, ...attached, ...global];
    const offAttach = books.filter((b) => !b.legacy_zone && !b.inactive && (b.inactive_attach || []).includes(z.name));
    const offBook = books.filter((b) => b.inactive && (b.legacy_zone === z.name || (b.attach || []).includes(z.name) || (b.inactive_attach || []).includes(z.name) || (b.name === 'global' && !b.legacy_zone)));
    const bookBtn = (b, n, cls, note) =>
      h(
        'li',
        null,
        h(
          'button',
          { class: ['ob-pair', cls], type: 'button', title: `About address book ${plain(b.name, { all: true })}`, on: { click: () => this.openSel(`book|${b.name}`, { push: true }) } },
          n ? h('span', { class: 'ob-order-n', 'aria-hidden': 'true' }, String(n)) : null,
          this.ctx.dom.icon('globe'),
          h('span', { class: 'mono' }, this.v(b.name)),
          h('span', { class: 'ob-pair-n' }, this.v(note || this.bookAttach(b))),
        ),
      );
    const kids = [];
    if (order.length) {
      kids.push(
        h('p', { class: 'pv-small muted ob-order-cap', title: 'The books attached to the zone come before the global book (verified). The zone’s legacy address book first is J-Wicket’s reading (inferred).' }, 'Names are looked up in this order'),
        h('ol', { class: 'ob-pairs ob-order' }, order.map((b, i) => bookBtn(b, i + 1, null, null))),
      );
    } else {
      kids.push(h('p', { class: 'pv-small muted' }, 'None: no book is attached to this zone and there is no global book in effect.'));
    }
    if (offAttach.length || offBook.length) {
      kids.push(
        h('p', { class: 'pv-ord-label' }, 'Written but not in effect'),
        h(
          'ul',
          { class: 'ob-pairs' },
          offAttach.map((b) => bookBtn(b, 0, 'is-struck', 'attach deactivated, not used')),
          offBook.map((b) => bookBtn(b, 0, 'is-struck', 'book deactivated, not used')),
        ),
      );
    }
    return kids;
  }

  bookDetail(b) {
    const { h } = this;
    const fmt = this.fmt;
    const scopeId = this.ctx.store.scope;
    const hero = this.hero(this.eyebrow('Address book', scopeTitle(this.snap, scopeId)), [
      h('span', { class: ['mono', 'ob-big', b.inactive && 'is-struck'] }, this.v(b.name)),
      h('span', { class: 'pv-where-pos' }, `${fmt.plural((b.addresses || []).length, 'address', 'addresses')}${SEP}${fmt.plural((b.sets || []).length, 'address set')}`),
      ...provBadges(h, b, { direct: false }),
      (b.unmodeled || []).length ? h('span', { class: 'pv-badge b-warn', title: `J-Wicket does not display: ${plain(b.unmodeled.join(', '))}` }, 'settings not shown') : null,
    ], [
      h('button', { class: 'btn sm', type: 'button', on: { click: () => { this.ctx.ui.closePanel(); this.setText('address-books', `book:${qvDevice(b.name)}`); } } }, this.ctx.dom.icon('filter'), 'Show only this book'),
    ]);
    const attachList = [
      ...(b.attach || []).map((z) => h('span', { class: 'zone' }, this.v(z))),
      ...(b.inactive_attach || []).map((z) => h('span', { class: 'zone is-struck', title: 'attach zone deactivated (inactive:): not in effect' }, this.v(z), ' (deactivated)')),
    ];
    const attach = this.psec('Where it applies', [
      h('p', null, this.v(this.bookAttach(b)), '.'),
      attachList.length ? h('p', { class: 'ob-chips' }, h('span', { class: 'muted' }, 'attach zone: '), attachList) : null,
      h('p', { class: 'pv-small muted' }, 'A zone-pair policy looks a name up in the zone’s legacy address book, then the books attached to the zone, then the book named global. Global policies use the global book. (Attached before global is verified; the legacy book first is J-Wicket’s reading, inferred.)'),
    ]);
    const entries = [...(b.addresses || []).map((a) => ({ e: a, id: `addr|${b.name}|${a.name}`, kind: a.kind || 'address', value: a.value })), ...(b.sets || []).map((s) => ({ e: s, id: `set|${b.name}|${s.name}`, kind: 'set', value: null }))];
    const list = this.psec(
      `Entries (${fmt.num(entries.length)})`,
      entries.length
        ? h(
            'ul',
            { class: 'ob-pairs ob-entries' },
            entries.map((x) =>
              h(
                'li',
                null,
                h(
                  'button',
                  { class: ['ob-pair', x.e.inactive && 'is-struck'], type: 'button', title: `Open ${plain(x.e.name, { all: true })}${x.e.inactive ? ' (deactivated)' : ''}`, on: { click: () => this.openSel(x.id, { push: false }) } },
                  h('span', { class: ['ob-kind', `k-${x.kind}`] }, x.kind),
                  h('span', { class: 'mono' }, this.v(x.e.name)),
                  x.value ? h('span', { class: 'ob-pair-n mono' }, this.v(x.value)) : null,
                  x.e.inactive ? h('span', { class: 'ob-pair-n' }, 'deactivated') : null,
                ),
              ),
            ),
          )
        : h('p', { class: 'pv-small muted' }, '0 entries: this book holds no address and no address set.'),
    );
    const words = b.legacy_zone ? [...this.showConfig('security zones security-zone'), cliWord(b.legacy_zone), 'address-book'] : [...this.showConfig('security address-book'), cliWord(b.name)];
    const names = b.legacy_zone ? [b.legacy_zone] : [b.name];
    return h(
      'div',
      { class: 'pv-detail' },
      hero,
      b.inactive ? h('div', { class: 'pv-callout reject', role: 'note' }, h('p', null, 'This address book is deactivated in the configuration: not in effect. Its entries are not used by any policy.')) : null,
      b.description ? h('p', { class: 'pv-desc-full' }, this.vd(b.description)) : null,
      this.commentBlock(b),
      attach,
      ...this.unmodeledBlock(b, words, names),
      list,
      this.psec('See it on the device', this.cli(words, names)),
    );
  }

  /**
   * One "Member of" line (OBJ-45, OBJ-46): the set's name; "deactivated member of <set>" when the member
   * statement is deactivated; "listed in set <set>; skipped because deactivated" when the object itself
   * is deactivated but an active set still lists it.
   */
  memberOfText(s, memberOff, selfOff) {
    const { h } = this;
    const name = h('span', { class: 'mono' }, this.v(s.name));
    if (memberOff) return [h('span', { class: 'ob-pair-n' }, 'deactivated member of '), name];
    if (s.inactive) return [name, h('span', { class: 'ob-pair-n' }, ' (set deactivated)')];
    if (selfOff) return [h('span', { class: 'ob-pair-n' }, 'listed in set '), name, h('span', { class: 'ob-pair-n' }, '; skipped because deactivated')];
    return name;
  }

  /** Sets of the book that list `name` as a member, with the member statement active or deactivated. */
  containingSets(b, name) {
    const out = [];
    for (const s of b.sets || []) {
      if ((s.addresses || []).includes(name) || (s.sets || []).includes(name)) out.push({ s, off: false });
      else if ((s.inactive_addresses || []).includes(name) || (s.inactive_sets || []).includes(name)) out.push({ s, off: true });
    }
    return out;
  }

  entryDetail(it) {
    const { h } = this;
    const fmt = this.fmt;
    const b = it.book;
    const e = it.entry;
    const isSet = it.type === 'set';
    const where = b.legacy_zone ? ['security zones security-zone', b.legacy_zone, 'address-book'] : ['security address-book', b.name];
    const words = [...this.showConfig(where[0]), cliWord(where[1]), ...(where[2] ? [where[2]] : []), isSet ? 'address-set' : 'address', cliWord(it.name)];
    const names = [where[1], it.name];
    // OBJ-58: Sessions only for an address J-Wicket can turn into a CIDR-aware filter.
    const net = !isSet && (it.kind === 'prefix' || it.kind === 'range') && e.value && this.Q && this.Q.parseNet ? this.Q.parseNet(e.value) : null;
    const actions = [
      this.navBtn('policies', 'Policies using it', 'policies', { q: `addr:${qvDevice(it.name)}` }, `Policies whose source or destination names ${it.name} or resolves to it`),
      net ? this.navBtn('sessions', 'Sessions', 'sessions', { q: `src:${e.value} OR dst:${e.value}` }, `Live sessions from or to ${e.value}`) : null,
    ].filter(Boolean);
    const hero = this.hero(this.eyebrow(isSet ? 'Address set' : 'Address', b.name, scopeTitle(this.snap, this.ctx.store.scope)), [
      h('span', { class: ['ob-kind', `k-${it.kind}`] }, it.kind),
      !isSet && e.value ? h('span', { class: 'mono ip ob-big' }, this.v(e.value)) : null,
      h('button', { class: 'ob-bookname', type: 'button', on: { click: () => this.openSel(`book|${b.name}`, { push: true }) } }, this.ctx.dom.icon('globe'), this.v(b.name)),
      ...provBadges(h, e, { direct: false }),
      ...this.rowBadges(e, it),
    ], actions);
    const kids = [hero];
    if (!it.effective) {
      const why = e.inactive ? 'It is deactivated in the configuration (inactive:)' : b.inactive ? 'Its address book is deactivated' : 'Its scope is deactivated';
      kids.push(h('div', { class: 'pv-callout reject', role: 'note' }, h('p', null, `${why}: not in effect. No policy can use it.`)));
    }
    if (it.kind === 'unknown') kids.push(h('p', { class: 'pv-small pv-amber' }, 'address form J-Wicket does not read: ', this.v((e.unmodeled || []).join(', ') || 'not reported')));
    if (e.description) kids.push(h('p', { class: 'pv-desc-full' }, this.vd(e.description)));
    kids.push(this.commentBlock(e));
    if (isSet) kids.push(this.setExpansion(it));
    kids.push(...this.unmodeledBlock(e, words, names));
    const containing = this.containingSets(b, it.name);
    kids.push(
      this.psec(
        'Member of',
        containing.length
          ? h(
              'ul',
              { class: 'ob-pairs' },
              containing.map(({ s, off }) =>
                h(
                  'li',
                  null,
                  h(
                    'button',
                    { class: ['ob-pair', (off || s.inactive) && 'is-struck'], type: 'button', on: { click: () => this.openSel(`set|${b.name}|${s.name}`, { push: false }) } },
                    h('span', { class: 'pv-tag' }, 'set'),
                    this.memberOfText(s, off, e.inactive),
                  ),
                ),
              ),
            )
          : h('p', { class: 'pv-small muted' }, 'No address set in this book contains it.'),
      ),
      this.psec(
        it.effective ? `Used by ${it.usedCount ? fmt.plural(it.usedCount, 'active policy', 'active policies') : 'no active policy'}` : 'Used by',
        it.effective ? this.policyList(it.use) : h('p', { class: 'pv-small muted' }, e.inactive ? 'not in effect (deactivated)' : b.inactive ? 'not in effect (book deactivated)' : 'not in effect (scope deactivated)'),
      ),
      this.psec('See it on the device', this.cli(words, names)),
    );
    return h('div', { class: 'pv-detail' }, kids);
  }

  /** A set's members, expanded through nested sets; rows not in effect are muted (OBJ-46). */
  setExpansion(it) {
    const { h } = this;
    const fmt = this.fmt;
    const b = it.book;
    const e = it.entry;
    const bs = this.idx.bookSets.get(b.name) || { addrs: new Map(), sets: new Map() };
    const rows = [];
    const seen = new Set();
    let inEffect = 0;
    const row = (name, kind, value, through, off, unres) =>
      h(
        'tr',
        { class: off ? 'is-off' : null },
        h('td', { class: ['mono', off && 'is-struck'] }, this.v(name)),
        h('td', { class: 'muted' }, kind),
        h('td', { class: ['mono', 'ip', unres && 'pv-unres'] }, value === null ? '' : this.v(value)),
        h('td', { class: 'faint' }, this.v(through)),
      );
    const walk = (s, depth, via, skipped) => {
      if (seen.has(s.name) || depth > 8) return;
      seen.add(s.name);
      const thru = (dflt) => skipped || via || dflt;
      for (const n of s.addresses || []) {
        const a = bs.addrs.get(n);
        const off = Boolean(skipped) || Boolean(a && a.inactive);
        if (!off && a) inEffect += 1;
        rows.push(row(a && a.inactive ? `${n} (deactivated)` : n, a ? a.kind : 'not found', a ? a.value || '' : 'not in this book', a && a.inactive && !skipped ? 'skipped: deactivated' : thru('direct'), off, !a));
      }
      for (const n of s.inactive_addresses || []) {
        const a = bs.addrs.get(n);
        rows.push(row(`${n} (deactivated member)`, a ? a.kind : 'address', a ? a.value || '' : '', 'skipped: deactivated', true, false));
      }
      for (const n of s.sets || []) {
        const nested = bs.sets.get(n);
        if (nested) walk(nested, depth + 1, `via ${n}`, skipped || (nested.inactive ? `skipped: deactivated set ${n}` : null));
        else rows.push(row(n, 'address set', 'not in this book', thru('direct'), Boolean(skipped), true));
      }
      for (const n of s.inactive_sets || []) rows.push(row(`${n} (deactivated member)`, 'address set', '', 'skipped: deactivated', true, false));
    };
    walk(e, 0, null, e.inactive ? 'skipped: deactivated' : null);
    return this.psec(`Members, expanded (${fmt.plural(inEffect, 'address', 'addresses')} in effect)`, [
      h('table', { class: 'table pv-mini' }, h('thead', null, h('tr', null, ['Address', 'Kind', 'Value', 'Through'].map((t) => h('th', { scope: 'col' }, t)))), h('tbody', null, rows)),
      (e.sets || []).length ? h('p', { class: 'pv-small muted' }, 'Nested sets: ', this.v(e.sets.join(', ')), '.') : null,
    ]);
  }

  appDetail(it) {
    const { h } = this;
    const fmt = this.fmt;
    const a = it.a;
    const isSet = a.kind === 'set';
    const Q = this.Q;
    const actions = [
      this.navBtn('policies', 'Policies using it', 'policies', { q: `app:${qvDevice(a.name)}` }),
      !isSet && /^\d+$/.test(String(a.destination_port || '')) ? this.navBtn('sessions', 'Sessions', 'sessions', { q: `dport:${a.destination_port}${a.protocol && /^(tcp|udp)$/.test(a.protocol) ? ` proto:${a.protocol}` : ''}` }, `Live sessions to port ${a.destination_port}`) : null,
    ].filter(Boolean);
    const hero = this.hero(this.eyebrow(isSet ? 'Application set' : 'Custom application', scopeTitle(this.snap, this.ctx.store.scope)), [
      h('span', { class: ['ob-kind', isSet ? 'k-set' : 'k-app'] }, isSet ? 'set' : 'application'),
      !isSet ? h('span', { class: 'mono ob-big' }, this.v(`${a.protocol || '?'}${a.destination_port ? `/${a.destination_port}` : ''}`)) : null,
      ...provBadges(h, a, { direct: false }),
      ...this.rowBadges(a, it),
    ], actions);
    const words = [...this.showConfig(`applications ${isSet ? 'application-set' : 'application'}`), cliWord(a.name)];
    const kids = [hero];
    if (a.inactive || it.scopeOff) kids.push(h('div', { class: 'pv-callout reject', role: 'note' }, h('p', null, `${a.inactive ? 'It is deactivated in the configuration (inactive:)' : 'Its scope is deactivated'}: not in effect. No policy can use it.`)));
    if (a.description) kids.push(h('p', { class: 'pv-desc-full' }, this.vd(a.description)));
    kids.push(this.commentBlock(a));
    if (!isSet) {
      const leaf = (v) => (v ? this.v(v) : '—');
      kids.push(
        this.psec('Definition', [
          h(
            'dl',
            { class: 'kv pv-kv' },
            h('dt', null, 'Protocol'),
            h('dd', { class: 'mono' }, leaf(a.protocol)),
            h('dt', null, 'Destination port'),
            h('dd', { class: 'mono' }, leaf(a.destination_port)),
            h('dt', null, 'Source port'),
            h('dd', { class: 'mono' }, leaf(a.source_port)),
            h('dt', null, 'Terms'),
            h('dd', null, a.terms ? `${fmt.plural(a.terms, 'term')} (not expanded by J-Wicket)` : h('span', { class: 'muted' }, 'none')),
          ),
          a.terms ? h('p', { class: 'pv-small muted' }, 'An application with terms matches if any term matches. Check the terms on the device.') : null,
        ]),
      );
    } else {
      const rows = [];
      const seen = new Set();
      const row = (name, proto, port, through, off, opts = {}) =>
        h(
          'tr',
          { class: off ? 'is-off' : null },
          h('td', { class: ['mono', off && 'is-struck'] }, this.v(name), opts.catalog ? [' ', h('span', { class: 'pv-tag ob-catalog', title: Q && Q.PREDEFINED_SOURCE ? Q.PREDEFINED_SOURCE : null }, 'catalog')] : null),
          opts.span ? h('td', { colspan: '2', class: opts.cls || 'muted' }, opts.span) : [h('td', { class: 'mono' }, proto), h('td', { class: 'mono' }, port)],
          h('td', { class: 'faint' }, this.v(through)),
        );
      const walk = (s, depth, via, skipped) => {
        if (seen.has(s.name) || depth > 8) return;
        seen.add(s.name);
        const thru = (dflt) => skipped || via || dflt;
        for (const n of s.members || []) {
          const m = this.idx.appByName.get(n);
          if (m && m.kind === 'application') {
            const off = Boolean(skipped) || m.inactive;
            rows.push(row(m.inactive ? `${n} (deactivated)` : n, m.protocol ? this.v(m.protocol) : m.terms ? `${m.terms} terms` : '—', m.destination_port ? this.v(m.destination_port) : '—', m.inactive && !skipped ? 'skipped: deactivated' : thru('direct'), off));
          } else if (/^junos-/.test(n) && !m) {
            const known = Q && Q.PREDEFINED_APPS ? Q.PREDEFINED_APPS[n] : null;
            rows.push(known ? row(n, known.protocol, String(known.port), thru('direct'), Boolean(skipped), { catalog: true }) : row(n, null, null, thru('direct'), Boolean(skipped), { span: 'predefined (junos-defaults): port not read' }));
          } else {
            rows.push(row(n, null, null, thru('direct'), Boolean(skipped), { span: 'not found', cls: 'pv-unres' }));
          }
        }
        for (const n of s.inactive_applications || []) rows.push(row(`${n} (deactivated member)`, null, null, 'skipped: deactivated', true, { span: 'member statement deactivated (inactive:): not in effect' }));
        for (const n of s.sets || []) {
          const nested = this.idx.appByName.get(n);
          if (nested && nested.kind === 'set') walk(nested, depth + 1, `via ${n}`, skipped || (nested.inactive ? `skipped: deactivated set ${n}` : null));
          else rows.push(row(n, null, null, thru('direct'), Boolean(skipped), { span: 'set not found', cls: 'pv-unres' }));
        }
        for (const n of s.inactive_sets || []) rows.push(row(`${n} (deactivated member)`, null, null, 'skipped: deactivated', true, { span: 'member statement deactivated (inactive:): not in effect' }));
      };
      walk(a, 0, null, a.inactive ? 'skipped: deactivated' : null);
      kids.push(
        this.psec(`Members, expanded (${fmt.num(rows.length)})`, [
          h('table', { class: 'table pv-mini' }, h('thead', null, h('tr', null, ['Application', 'Protocol', 'Destination port', 'Through'].map((t) => h('th', { scope: 'col' }, t)))), h('tbody', null, rows)),
          it.catalog.length ? h('p', { class: 'pv-small muted' }, 'Rows tagged catalog: ', Q && Q.PREDEFINED_SOURCE ? Q.PREDEFINED_SOURCE : 'J-Wicket’s own table', '.') : null,
        ]),
      );
      const predefined = (a.members || []).filter((n) => /^junos-/.test(n) && !this.idx.appByName.has(n));
      if (predefined.length) {
        kids.push(h('p', { class: 'pv-small muted' }, 'Predefined applications are defined in junos-defaults. To see one:'), this.cli(['show configuration groups junos-defaults applications application', cliWord(predefined[0])], [predefined[0]]));
      }
    }
    kids.push(...this.unmodeledBlock(a, words, [a.name]));
    const containing = this.idx.apps.filter((s) => s.kind === 'set' && [...(s.members || []), ...(s.sets || []), ...(s.inactive_applications || []), ...(s.inactive_sets || [])].includes(a.name));
    kids.push(
      this.psec(
        'Member of',
        containing.length
          ? h(
              'ul',
              { class: 'ob-pairs' },
              containing.map((s) => {
                const off = [...(s.inactive_applications || []), ...(s.inactive_sets || [])].includes(a.name);
                return h(
                  'li',
                  null,
                  h(
                    'button',
                    { class: ['ob-pair', (off || s.inactive) && 'is-struck'], type: 'button', on: { click: () => this.openSel(`app|${s.name}`, { push: false }) } },
                    h('span', { class: 'pv-tag' }, 'set'),
                    this.memberOfText(s, off, a.inactive),
                  ),
                );
              }),
            )
          : h('p', { class: 'pv-small muted' }, 'No application set contains it.'),
      ),
      this.psec(
        a.inactive ? 'Used by' : `Used by ${it.usedCount ? fmt.plural(it.usedCount, 'active policy', 'active policies') : 'no active policy'}`,
        a.inactive ? h('p', { class: 'pv-small muted' }, 'not in effect (deactivated)') : this.policyList(it.use),
      ),
      this.psec('See it on the device', this.cli(words, [a.name])),
    );
    return h('div', { class: 'pv-detail' }, kids);
  }
}
