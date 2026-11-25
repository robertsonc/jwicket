// views/policies.js: security policies in Junos evaluation order (UI brief, section 7; BRIEF rules 8-10).
//
// What this view shows, from one inventory snapshot of the current scope (root, logical system or
// tenant system):
// * the evaluation order Junos uses: each zone pair's policies top to bottom, then the global
//   policies that apply to the pair, then the default policy. J-Wicket shows the order and gives the
//   exact CLI to test a flow (show security match-policies ...); it never decides which policy a
//   flow matches.
// * a zone-pair matrix, provenance (configuration groups, inherited parts), inactive policies and
//   why, deactivated parts, settings J-Wicket does not model, the exact show-configuration command,
//   central management and warnings.
// * cross-links: live sessions per policy from the last Sessions poll in this tab (never polled
//   here unless the operator asks), "Sessions for this policy", "Logs for this policy".
//
// Filtering uses the shared query language (query.js, FIELDS.policies). One deliberate difference:
// from/to/zone treat a global policy without a zone list as applying to every zone, so a zone-pair
// filter keeps the global policies Junos would check for that pair (evaluation order, not a match).
//
// Strict CSP: DOM through ctx.dom.h()/svg() and textContent only; dynamic sizes through CSSOM custom
// properties. Nothing read from the device is stored in the browser.
//
// Device text is untrusted (UI-19 POL-UI-06, CRT-14): every name, description and comment is shown
// through ctx.dom.vis() (or markNodes(), which builds the same badges through the h it is given), so a
// hidden or reordering character shows as a "U+202E" badge instead of being applied. Titles, labels and
// toasts use format.plain(). A CLI command is never offered for a name with a line break or a C0/C1
// control character (format.cliUnsafe); format characters (bidi, zero-width) are copied exactly.

import { cliUnsafe, controlName, controlParts, countControls, hasControls, plain } from '../format.js';

const ICON = 'M12 3l7.5 3v5.2c0 4.4-3.1 8.2-7.5 9.8-4.4-1.6-7.5-5.4-7.5-9.8V6z M8.8 11.8l2.3 2.3 4.3-4.4';
// A speech bubble, for configuration comments (annotate).
const COMMENT_ICON = 'M5 5.5h14v9.5h-8.5L6 19v-4H5z';
const SEP = ' \u00b7 ';
const ARROW = '\u2192';
const LIST_LIMIT = 4;
const AGE_TICK_MS = 30000;
const SUMMARY_PREF = 'jwicket.policies.summary'; // UI preference only (never device data): "open" or unset
const WIDE_MQ = '(min-width: 1600px)'; // the zone-pair matrix moves beside the table

export const view = {
  id: 'policies',
  title: 'Policies',
  icon: ICON,
  mount(el, ctx) {
    const v = new PoliciesView(el, ctx);
    return { update: (route) => v.update(route), unmount: () => v.destroy() };
  },
};

// ---- shared helpers (objects.js imports these) ------------------------------------------------------

/** A query value, quoted when the query lexer needs it. */
export function qv(v) {
  const s = String(v);
  if (/^[A-Za-z0-9._\-/:*]+$/.test(s) && !/^[-!]/.test(s) && !/^(AND|OR|NOT|and|or|not)$/.test(s)) return s;
  return `"${s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

/**
 * qv() for a device string put into a query: each control or format character becomes the wildcard
 * `*`, as Logs and Sessions do, so the query bar never holds an invisible or reordering character.
 */
export function qvDevice(v) {
  return qv(starControls(v));
}

/** A device string with each control or format character replaced by `*` (the value qvDevice quotes). */
function starControls(v) {
  return controlParts(String(v ?? ''), { all: true }).map((p) => (p.ctl ? '*' : p.text)).join('');
}

export const pairKey = (from, to) => `${from}\u0000${to}`;

export function scopeParts(id) {
  const s = String(id || 'root');
  if (s.startsWith('lsys:')) return { kind: 'lsys', name: s.slice(5) };
  if (s.startsWith('tenant:')) return { kind: 'tenant', name: s.slice(7) };
  return { kind: 'root', name: null };
}

export function scopeTitle(snap, id) {
  const known = snap && snap.meta && (snap.meta.scopes || []).find((s) => s.id === id);
  if (known) return known.label;
  const sp = scopeParts(id);
  if (sp.kind === 'lsys') return `Logical system ${sp.name}`;
  if (sp.kind === 'tenant') return `Tenant system ${sp.name}`;
  return 'Root system';
}

/**
 * Quote a CLI word only when Junos would need it. Null when the word holds a line break or a C0/C1
 * control character (format.cliUnsafe): such a word would break a pasted command, so no command is
 * offered. Format characters (bidi, zero-width) are kept exactly, quoted, so the command names the same
 * object as the device does.
 */
export function cliWord(word) {
  const text = String(word ?? '');
  if (cliUnsafe(text)) return null;
  return /^[A-Za-z0-9._:/-]+$/.test(text) ? text : `"${text.replace(/["\\]/g, '\\$&')}"`;
}

/** "logical-systems LS-A " / "tenants T-1 " / "" for show configuration; null when the name is unsafe. */
export function cliPrefix(scopeId) {
  const sp = scopeParts(scopeId);
  if (sp.kind === 'root') return '';
  const w = cliWord(sp.name);
  if (w === null) return null;
  return sp.kind === 'lsys' ? `logical-systems ${w} ` : `tenants ${w} `;
}

/** The words of a command joined with spaces, or null when any word is null (an unsafe name). */
export function cliJoin(...words) {
  const flat = words.flat();
  return flat.some((w) => w === null || w === undefined) ? null : flat.join(' ').replace(/\s+$/, '');
}

/** "U+000A, U+0085": the characters of `names` that make a command unsafe to paste. */
function unsafeChars(names) {
  const seen = [];
  for (const n of names || []) {
    for (const ch of String(n ?? '')) {
      if (!cliUnsafe(ch)) continue;
      const name = controlName(ch);
      if (!seen.includes(name)) seen.push(name);
    }
  }
  return seen;
}

/** "U+200B, U+202E": the hidden (format) characters a command copies exactly. */
function hiddenChars(text) {
  const seen = [];
  for (const p of controlParts(text)) if (p.ctl && !seen.includes(p.ctl)) seen.push(p.ctl);
  return seen;
}

/**
 * A copyable CLI block; <placeholders> are marked so the operator sees what to replace. Each word is
 * shown through vis(), so a hidden character shows as a badge; the copy holds the exact characters.
 * `text` null (a builder met an unsafe name, CRT-14): no command and no copy button, but a note naming
 * the characters found in `names` (the names the command would have held).
 */
export function cliBlock(ctx, text, label = 'Copy command', names = []) {
  const { h, icon } = ctx.dom;
  if (text === null || text === undefined) {
    const chars = unsafeChars(names);
    return h(
      'div',
      { class: 'cli pv-cli pv-cli-off', role: 'note' },
      h('span', { class: 'pv-prompt', 'aria-hidden': 'true' }, '>'),
      h(
        'span',
        { class: 'pv-cli-refused' },
        `Command not offered: the name contains a line break or control character (shown as ${chars.length ? chars.join(', ') : 'a U+ badge'}) that would break a pasted command.`,
      ),
    );
  }
  const { vis } = ctx.dom;
  const code = h('code', { class: 'pv-cli-code' });
  String(text)
    .split(' ')
    .forEach((word, i) => {
      if (i) code.append(' ');
      code.append(h('span', { class: /^<[^>]+>$/.test(word) ? 'pv-ph' : null }, vis(word, { all: true })));
    });
  const hidden = hiddenChars(text);
  const n = countControls(text);
  const done = hidden.length
    ? `Command copied. The command contains ${n} hidden ${n === 1 ? 'character' : 'characters'} (shown as ${hidden.join(', ')}).`
    : 'Command copied. Paste it into the device CLI.';
  const btn = h(
    'button',
    {
      class: 'btn sm ghost icon',
      type: 'button',
      title: hidden.length ? `Copy (exact characters, including ${hidden.join(', ')})` : 'Copy',
      'aria-label': `${label}: ${plain(text)}`,
      on: { click: () => ctx.ui.copy(text, done) },
    },
    icon('copy'),
  );
  return h('div', { class: 'cli pv-cli' }, h('span', { class: 'pv-prompt', 'aria-hidden': 'true' }, '>'), code, btn);
}

/** A control or format character as a visible badge, built through `h` (the same badge as dom.vis). */
function ctlBadge(h, name) {
  return h('span', { class: 'ctl-badge', title: `A hidden ${name} character is here (shown, not applied)` }, name);
}

/**
 * Device text as nodes built only through `h`: case-insensitive occurrences of `terms` wrapped in
 * <mark class="pv-hit">, and each control or format character shown as a `ctl-badge` span instead of
 * being applied (a badge inside a mark goes inside it). `all` (the default, for names) also badges tab
 * and line feed; descriptions and comments pass `{ all: false }` and keep their line breaks.
 */
export function markNodes(h, text, terms, { all = true } = {}) {
  const s = String(text === null || text === undefined ? '' : text);
  const pieces = (str) => controlParts(str, { all }).map((p) => (p.ctl ? ctlBadge(h, p.ctl) : p.text));
  if (!s) return [s];
  const low = s.toLowerCase();
  const hits = [];
  // Offsets are taken from the lower-cased text; when lower-casing changes the length (a few
  // characters do), the text is shown without marks rather than with marks in the wrong place.
  if (terms && terms.length && low.length === s.length) {
    for (const t of terms) {
      const tl = String(t).toLowerCase();
      if (!tl) continue;
      let i = low.indexOf(tl);
      while (i >= 0 && hits.length < 64) {
        hits.push([i, i + tl.length]);
        i = low.indexOf(tl, i + tl.length);
      }
    }
  }
  if (!hits.length) return hasControls(s, { all }) ? pieces(s) : [s];
  hits.sort((a, b) => a[0] - b[0]);
  const merged = [];
  for (const hit of hits) {
    const last = merged[merged.length - 1];
    if (last && hit[0] <= last[1]) last[1] = Math.max(last[1], hit[1]);
    else merged.push([...hit]);
  }
  const out = [];
  let pos = 0;
  for (const [a, b] of merged) {
    if (a > pos) out.push(...pieces(s.slice(pos, a)));
    out.push(h('mark', { class: 'pv-hit' }, pieces(s.slice(a, b))));
    pos = b;
  }
  if (pos < s.length) out.push(...pieces(s.slice(pos)));
  return out;
}

/** A provenance badge row: configuration group, inherited parts, inactive. */
export function provBadges(h, obj, { direct = true } = {}) {
  const out = [];
  const nodes = (s) => markNodes(h, s, []);
  if (obj.group) out.push(h('span', { class: 'pv-badge b-group', title: `Comes from configuration group ${plain(obj.group)}` }, 'group ', nodes(obj.group)));
  if ((obj.inherited || []).length) {
    out.push(h('span', { class: 'pv-badge b-inherit', title: `Partly inherited: ${plain(obj.inherited.join(', '))}` }, 'inherits ', nodes(obj.inherited.join(', '))));
  }
  if (obj.inactive) out.push(h('span', { class: 'pv-badge b-inactive', title: 'Deactivated in the configuration (inactive:): not in effect' }, 'inactive'));
  if (!out.length && direct) out.push(h('span', { class: 'pv-direct' }, 'direct'));
  return out;
}

/** The HA role of a session row, if any ("active" / "backup"), as the Sessions view reads it. */
export function haRole(r) {
  for (const v of [r.state, r.status]) {
    if (/^\s*(active|backup)\s*$/i.test(String(v || ''))) return String(v).trim().toLowerCase();
  }
  for (const [k, v] of Object.entries(r.extra || {})) {
    if (/state|role|ha|status/i.test(k) && /^\s*(active|backup|stand-?alone|warm)\s*$/i.test(String(v))) return String(v).trim().toLowerCase();
  }
  return null;
}

/**
 * Live session counts per policy name from the last Sessions poll in this tab (memory only), or null
 * when there is none or the scope is not the root system (flow sessions are read for root only).
 * Chassis-cluster backup copies (query.sessionCopies: marked Backup by the device, or inferred from
 * zero counters on the other node) are not counted; `backups` is how many were left out, and `why`
 * says on what basis.
 */
export function liveSessions(ctx) {
  const last = ctx.store.sessionsLast;
  if (!last || ctx.store.scope !== 'root') return null;
  const table = last.sessions || {};
  const meta = last.meta || {};
  const out = {
    status: table.status || 'failed',
    message: table.message || null,
    at: meta.read_at || null,
    filters: meta.device_filters || {},
    truncated: Boolean(table.truncated),
    returned: table.returned,
    counts: new Map(),
    total: 0,
    max: 0,
    backups: 0,
    why: [],
  };
  if (table.status !== 'ok') return out;
  const rows = table.rows || [];
  const copies = ctx.query && ctx.query.sessionCopies ? ctx.query.sessionCopies(rows) : { backups: new Set(), why: new Map() };
  out.backups = copies.backups.size;
  out.why = [...new Set(copies.why.values())];
  for (const r of rows) {
    if (copies.backups.has(r.id)) continue;
    const name = r.policy || '';
    if (!name) continue;
    const n = (out.counts.get(name) || 0) + 1;
    out.counts.set(name, n);
    out.total += 1;
    if (n > out.max) out.max = n;
  }
  return out;
}

/**
 * Edits the top-level AND terms of a query: `drop(item)` removes matching items, `add` appends terms.
 * Returns canonical query text (parse(toQueryString(ast)) round-trips, so meaning is kept).
 */
export function editQuery(query, text, { drop = null, add = [] } = {}) {
  if (!query) return [text, ...add].filter(Boolean).join(' ').trim();
  const p = query.parse(text || '');
  if (p.error) return [String(text || '').trim(), ...add].filter(Boolean).join(' ').trim();
  const items = !p.ast ? [] : p.ast.type === 'and' ? p.ast.items : [p.ast];
  const keep = drop ? items.filter((it) => !drop(it)) : items;
  const parts = keep.map((it) => (it.type === 'or' ? `(${query.toQueryString(it)})` : query.toQueryString(it)));
  return [...parts, ...add].filter(Boolean).join(' ').trim();
}

/** Top-level AND items of a parsed query. */
export function topItems(ast) {
  if (!ast) return [];
  return ast.type === 'and' ? ast.items : [ast];
}

/** The canonical field name of a key, or null (aliases resolved through the fields' own lists). */
export function keyName(fields, key) {
  if (!fields || !key) return null;
  const k = String(key).toLowerCase();
  for (const [name, def] of Object.entries(fields)) {
    if (name === k || (def.aliases || []).includes(k)) return name;
  }
  return null;
}

/**
 * Explicit state for the snapshot as a whole (no data, config not readable, no scope), or null.
 * `deniedHint` replaces the hint of the card shown when the login class may not read the configuration.
 */
export function inventoryState(ctx, snap, what, retry, { deniedHint = null } = {}) {
  const { h, stateCard } = ctx.dom;
  const again = retry ? [h('button', { class: 'btn sm', type: 'button', on: { click: retry } }, 'Read again')] : null;
  if (!snap) {
    const err = inventoryErrorFor(ctx);
    if (err) {
      return stateCard({
        // A named state (the shell's "busy" after waiting out other reads, SL-01) is shown as such.
        status: typeof err.status === 'string' ? err.status : err.status === 0 ? 'offline' : err.status === 404 ? 'unsupported' : 'failed',
        title: err.status === 404 ? 'That scope is not in the configuration' : undefined,
        message: err.message,
        actions: again,
      });
    }
    return null;
  }
  const cfg = snap.config || {};
  if (cfg.status && cfg.status !== 'ok') {
    return stateCard({
      status: cfg.status,
      message: cfg.message,
      hint:
        cfg.status === 'denied'
          ? deniedHint || `The ${what} come from the configuration, which your Junos login class may not read. J-Wicket shows only what your login class allows; ask your Junos administrator if you need this view.`
          : undefined,
      actions: cfg.status === 'failed' ? again : null,
    });
  }
  if (!snap.scope) {
    return stateCard({ status: 'failed', message: 'No inventory came back for this scope.', actions: again });
  }
  return null;
}

/**
 * The last inventory read error when it is about the current scope (OBJ-31: the shell's error names
 * its scope; an error without one is taken as current), else null.
 */
export function inventoryErrorFor(ctx) {
  const err = ctx.store.inventoryError;
  if (!err) return null;
  return err.scope && err.scope !== ctx.store.scope ? null : err;
}

/**
 * The line under the title, built by dom.viewSub (S-4): "branch-fw-01 · Root system · committed
 * config, inheritance expanded · read 09:27:04 UTC · as admin · 2 min ago". When the configuration was
 * not read it says so ("configuration not read (your login class does not allow it) · checked …"),
 * never "committed config". Returns the nodes.
 */
export function subLine(ctx, snap, receivedAt) {
  const { h } = ctx.dom;
  const fmt = ctx.format;
  if (!snap) return ['Reading the configuration\u2026'];
  const meta = snap.meta || {};
  const dev = snap.device && snap.device.status === 'ok' ? snap.device : null;
  const ra = meta.read_as || {};
  const extra = [];
  if (snap.scope && snap.scope.inactive) extra.push(h('span', { class: 'pill reject pv-sub-pill' }, 'deactivated'));
  if (meta.read_at || receivedAt) extra.push(fmt.ago(receivedAt || meta.read_at));
  return ctx.dom.viewSub(null, {
    host: dev && dev.hostname ? dev.hostname : null,
    scope: scopeTitle(snap, meta.scope || ctx.store.scope),
    readAt: meta.read_at,
    user: ra.user || '?',
    backend: ra.backend,
    config: snap.config,
    source: meta.source,
    extra,
  });
}

// ---- policy model --------------------------------------------------------------------------------

function zonesOf(list) {
  return Array.isArray(list) ? list : [];
}

export const globalApplies = (row, from, to) => {
  const f = zonesOf(row.from);
  const t = zonesOf(row.to);
  return (f.length === 0 || f.includes(from)) && (t.length === 0 || t.includes(to));
};

function buildModel(snap) {
  const scope = snap.scope;
  const pol = scope.policies || {};
  const rows = pol.rows || [];
  const pairs = new Map();
  const globals = [];
  const byName = new Map();
  const idById = new Map();
  rows.forEach((row, idx) => {
    idById.set(row.id, idx);
    if (!byName.has(row.name)) byName.set(row.name, []);
    byName.get(row.name).push(idx);
    if (row.kind === 'global') {
      globals.push(idx);
      return;
    }
    const from = zonesOf(row.from)[0] || '?';
    const to = zonesOf(row.to)[0] || '?';
    const key = pairKey(from, to);
    if (!pairs.has(key)) pairs.set(key, { key, from, to, idxs: [] });
    pairs.get(key).idxs.push(idx);
  });
  for (const p of pairs.values()) p.inactive = p.idxs.every((i) => rows[i].inactive_reason === 'zone-pair');
  const zonePanel = scope.zones || {};
  const zones = [];
  const defined = new Set();
  if (zonePanel.status === 'ok') {
    for (const z of zonePanel.rows || []) {
      if (!zones.includes(z.name)) zones.push(z.name);
      defined.add(z.name);
    }
  }
  const addZone = (z) => {
    if (z && z !== '?' && !zones.includes(z)) zones.push(z);
  };
  for (const row of rows) {
    zonesOf(row.from).forEach(addZone);
    zonesOf(row.to).forEach(addZone);
  }
  const counts = { permit: 0, deny: 0, reject: 0, unknown: 0, inactive: 0, zone: 0, global: globals.length };
  for (const r of rows) {
    if (r.kind !== 'global') counts.zone += 1;
    if (r.inactive) counts.inactive += 1;
    else counts[['permit', 'deny', 'reject'].includes(r.action) ? r.action : 'unknown'] += 1;
  }
  return {
    scope,
    pol,
    rows,
    pairs,
    globals,
    byName,
    idById,
    zones,
    defined,
    zonesKnown: zonePanel.status === 'ok',
    stats: new Map((pol.zone_pairs || []).map((p) => [pairKey(p.from, p.to), p])),
    counts,
  };
}

/**
 * FIELDS.policies with from/to/zone reading "applies to": a global policy with no zone list applies
 * to every zone. Same keys and aliases, so the query bar's validation and autocomplete still hold.
 */
function policyFields(query, allZones) {
  const base = query.FIELDS.policies;
  const f = Object.create(base); // free text (the haystack) stays the shared one, via the prototype
  for (const [k, d] of Object.entries(base)) f[k] = d;
  const applies = (list) => (list && list.length ? list : ['any', ...allZones()]);
  f.from = { ...base.from, get: (r) => applies(r.from) };
  f.to = { ...base.to, get: (r) => applies(r.to) };
  f.zone = { ...base.zone, get: (r) => [...applies(r.from), ...applies(r.to)] };
  return f;
}

export const EXAMPLE_SOURCE_PORT = '40000'; // an ordinary client (ephemeral) port; match-policies needs one

const HOST_V4 = /^\d{1,3}(\.\d{1,3}){3}$/;

/**
 * What the match-policies example can take from this policy, without guessing (BRIEF rule 8): a host
 * only when a side resolves to exactly one host address, a port and protocol only when the
 * applications resolve to exactly one port/protocol pair. Otherwise the CLI keeps its <placeholder>
 * and `candidates` lists what the policy names, for the operator to choose from.
 */
export function flowExample(row, Q) {
  const res = row.resolved || {};
  const side = (list) => {
    const leaves = [];
    let any = false;
    let partial = false;
    for (const item of list || []) {
      if (item.kind === 'any') any = true;
      else if (item.kind === 'address' || item.kind === 'set') {
        leaves.push(...(item.leaves || []).map((l) => ({ ...l, via: item.name })));
        if (item.truncated) partial = true;
      } else partial = true;
    }
    let host = null;
    if (!any && !partial && leaves.length === 1 && leaves[0].kind === 'prefix') {
      const v = String(leaves[0].value || '');
      if (/^\d{1,3}(\.\d{1,3}){3}\/32$/.test(v)) host = v.slice(0, -3);
      else if (/^[0-9a-f:]+\/128$/i.test(v)) host = v.slice(0, -4);
      else if (HOST_V4.test(v)) host = v;
    }
    return { host, any, leaves, partial };
  };
  const src = side(res.source);
  const dst = side(res.destination);
  const ports = Q && Q.policyPorts ? Q.policyPorts(row) : { any: false, pairs: [], unknown: [] };
  const uniq = new Map();
  for (const p of ports.pairs) uniq.set(`${p.protocol || '?'}/${p.port}`, p);
  const pairs = [...uniq.values()];
  const single = !ports.any && !ports.unknown.length && pairs.length === 1 && /^\d+$/.test(pairs[0].port) && pairs[0].protocol ? pairs[0] : null;
  // a source port the single application itself names, else an example client port
  let sport = EXAMPLE_SOURCE_PORT;
  let sportNamed = false;
  if (single) {
    for (const ref of res.application || []) {
      for (const l of ref.leaves || []) {
        if (l.name === single.name && /^\d+$/.test(String(l.source_port || ''))) {
          sport = String(l.source_port);
          sportNamed = true;
        }
      }
    }
  }
  return {
    src: src.host,
    dst: dst.host,
    proto: single ? single.protocol : null,
    port: single ? single.port : null,
    sport,
    sportNamed,
    candidates: { src, dst, ports: pairs, anyPort: ports.any, unknownPorts: ports.unknown },
  };
}

/** The match-policies command for a zone pair, or null when a scope or zone name is unsafe (CRT-14). */
function matchPoliciesCli(scopeId, from, to, ex = {}) {
  const sp = scopeParts(scopeId);
  const words = ['show security match-policies'];
  if (sp.kind === 'lsys') words.push('logical-system', cliWord(sp.name));
  if (sp.kind === 'tenant') words.push('tenant', cliWord(sp.name));
  words.push('from-zone', from ? cliWord(from) : '<from-zone>', 'to-zone', to ? cliWord(to) : '<to-zone>');
  words.push('source-ip', ex.src || '<source-ip>', 'destination-ip', ex.dst || '<destination-ip>');
  words.push('source-port', ex.sport || EXAMPLE_SOURCE_PORT, 'destination-port', ex.port || '<destination-port>');
  words.push('protocol', ex.proto ? cliWord(ex.proto) : '<protocol>');
  return cliJoin(words);
}

/** The names a command for this scope and these zones would hold (for the "not offered" note). */
function cliNames(scopeId, ...names) {
  return [scopeParts(scopeId).name, ...names.flat()].filter((x) => x !== null && x !== undefined);
}

function showConfigCli(row, scopeId) {
  const prefix = cliPrefix(row.scope || scopeId);
  if (row.kind === 'global') return cliJoin('show configuration', prefix === null ? null : `${prefix}security policies global policy`, cliWord(row.name));
  const from = zonesOf(row.from)[0];
  const to = zonesOf(row.to)[0];
  return cliJoin(
    'show configuration',
    prefix === null ? null : `${prefix}security policies from-zone`,
    from ? cliWord(from) : '<from-zone>',
    'to-zone',
    to ? cliWord(to) : '<to-zone>',
    'policy',
    cliWord(row.name),
  );
}

function showConfigNames(row, scopeId) {
  return cliNames(row.scope || scopeId, row.name, zonesOf(row.from), zonesOf(row.to));
}

// Why a row is inactive. "policy" and "zone-pair" are the policy's own statement or its zone pair (or
// global block); "policies", "security" and "scope" are the nearest deactivated ancestor of every
// policy in the scope (B-9 ancestor_inactive). That a deactivated ancestor takes its policies out of
// effect is J-Wicket's reading of Junos (inferred, Spec 001 section 7.5): deactivated statements "do
// not take effect when you issue the commit command" is verified, its reach to children is not.
const ANCESTOR_REASONS = ['policies', 'security', 'scope'];

function inactiveText(row, scopeLabel) {
  const why = row.inactive_reason;
  if (why === 'policy') return 'inactive: policy deactivated';
  if (why === 'zone-pair') return row.kind === 'global' ? 'inactive: global section deactivated' : 'inactive: zone pair deactivated';
  if (why === 'policies') return 'inactive: [security policies] deactivated';
  if (why === 'security') return 'inactive: [security] deactivated';
  if (why === 'scope') return `inactive: ${scopeLabel} deactivated`;
  return `inactive: reason ${why === null || why === undefined ? 'not given' : why} (not known to this UI)`;
}

function ancestorSentence(why, scopeLabel) {
  if (why === 'policies') return 'Inactive: [edit security policies] is deactivated, so none of this scope’s policies is in effect.';
  if (why === 'security') return 'Inactive: [edit security] is deactivated, so none of this scope’s policies is in effect.';
  if (why === 'scope') return `Inactive: ${scopeLabel} is deactivated in the configuration; nothing in it is in effect.`;
  return null;
}

/** The sentence for an inactive row; never "Active." for a row marked inactive. */
function inactiveSentence(row, scopeLabel) {
  if (!row.inactive) return null;
  const why = row.inactive_reason;
  if (why === 'policy') return 'Inactive: this policy is deactivated in the configuration (inactive:). Junos skips it.';
  if (why === 'zone-pair') {
    return row.kind === 'global'
      ? 'Inactive: the global policies section is deactivated, so Junos skips this policy.'
      : `Inactive: the zone pair from-zone ${zonesOf(row.from)[0]} to-zone ${zonesOf(row.to)[0]} is deactivated, so Junos skips every policy in it.`;
  }
  return ancestorSentence(why, scopeLabel) || `Inactive: reason ${why === null || why === undefined ? 'not given' : why} (not known to this UI).`;
}

const ANCESTOR_BECAUSE = {
  policies: ' (because [edit security policies] is deactivated)',
  security: ' (because [edit security] is deactivated)',
};

/**
 * The default policy as the UI shows it (POL-UI-02): `{ action, label, tip, badge, cls, group }`.
 * `action` is what decides a flow no policy matched; `badge` is the amber "permit-all deactivated" chip
 * of a deactivated default, else null; `group` is the configuration group, shown only with the
 * configured or deactivated wording. Verified: the YANG default is deny-all, and "If there is no
 * matching policy, the packet is dropped". Inferred: that a deactivated default leaves deny-all in
 * force. The Overview duplicates the `label` strings (POL-SL-01): keep them in step.
 */
export function defaultState(pol, scopeLabel = 'this scope') {
  const p = pol || {};
  const group = p.default_policy_group || null;
  if (p.default_policy) {
    const act = p.default_policy;
    return {
      action: act,
      label: group ? `configured, from group ${group}` : 'configured',
      tip: `The default policy decides when nothing above matched (configured${group ? `, from group ${plain(group)}` : ''})`,
      badge: null,
      cls: act === 'permit-all' ? 'permit' : 'deny',
      group,
    };
  }
  if (p.default_policy_inactive) {
    const act = p.default_policy_inactive;
    const why = p.default_policy_inactive_reason;
    const because = !why || why === 'self' ? '' : ANCESTOR_BECAUSE[why] || (why === 'scope' ? ` (because ${scopeLabel} is deactivated)` : ` (because of a deactivated ${why})`);
    return {
      action: 'deny-all',
      label: `Junos default: the configured default-policy ${act} is deactivated${because}`,
      tip: `default-policy ${act} is written in the configuration but deactivated (inactive:), so it is not in effect; the Junos default, deny-all, decides. (That the default then applies is J-Wicket’s reading: inferred.)`,
      badge: `${act} deactivated`,
      cls: 'deny',
      group,
    };
  }
  return {
    action: 'deny-all',
    label: 'not configured (Junos default: deny-all)',
    tip: 'No default-policy is configured: the Junos default, deny-all, decides when nothing above matched',
    badge: null,
    cls: 'deny',
    group: null,
  };
}

/** The pre-ID default policy state for the unified-policy note: null when neither flag is set. */
function preIdState(pol) {
  if (pol.pre_id_default_policy) return 'configured (contents not shown)';
  if (pol.pre_id_default_policy_inactive) return 'configured but deactivated (not in effect)';
  return null;
}

const ADDRESS_KINDS = { any: 'any address', address: 'address', set: 'address set', unresolved: 'not found' };
const APP_KINDS = {
  any: 'any application',
  application: 'custom application',
  set: 'application set',
  predefined: 'predefined (junos-defaults)',
  'dynamic-defaults': 'the dynamic application’s defaults',
  unresolved: 'not found',
};

const IMPLICIT_TITLE = 'Not in the configuration: Junos adds application junos-defaults (or any) to a unified policy that names a dynamic application and no application.';

/** Split "book:name" (an address inactive_skipped entry) at the first colon. */
function skippedRef(ref) {
  const s = String(ref);
  const i = s.indexOf(':');
  return i < 0 ? { book: null, name: s } : { book: s.slice(0, i), name: s.slice(i + 1) };
}

function bookLabel(book) {
  if (!book) return null;
  if (String(book).startsWith('zone ')) return `zone address book of ${book.slice(5)} (legacy)`;
  return `address book ${book}`;
}

const isIp = (query, s) => Boolean(s) && !/[/\-*]/.test(s) && Boolean(query && query.parseNet && query.parseNet(s));

// ---- the view ------------------------------------------------------------------------------------

class PoliciesView {
  constructor(el, ctx) {
    this.el = el;
    this.ctx = ctx;
    this.h = ctx.dom.h;
    this.fmt = ctx.format;
    this.Q = ctx.query || null;
    this.dead = false;
    this.snap = null;
    this.model = null;
    this.receivedAt = 0;
    this.text = '';
    this.ast = null;
    this.match = () => true;
    this.terms = [];
    this.termsKey = '';
    this.sel = null;
    this.wantSel = null;
    this.wantName = null;
    this.cursor = -1;
    this.visible = [];
    this.panelToken = 0;
    this.panelKind = null;
    this.panelIdx = -1;
    this.panelLive = null;
    this.infoOpen = null;
    this.zonesAll = [];
    this.trs = [];
    this.liveCells = [];
    this.qmarks = [];
    this.markStamps = [];
    this.sections = [];
    this.mxCells = [];
    this.fields = this.Q && this.Q.FIELDS && this.Q.FIELDS.policies ? policyFields(this.Q, () => this.zonesAll) : null;
    this.build();
    const store = ctx.store;
    this.offs = [
      store.on('inventory', (snap) => this.onInventory(snap)),
      store.on('sessions', () => this.onSessions()),
      store.on('scope', () => this.onScope()),
    ];
    this.onKeyBound = (e) => this.onKey(e);
    document.addEventListener('keydown', this.onKeyBound);
    this.ageTimer = setInterval(() => this.renderSub(), AGE_TICK_MS);
    this.mqWide = typeof window.matchMedia === 'function' ? window.matchMedia(WIDE_MQ) : null;
    this.onWide = () => this.placeMatrix();
    if (this.mqWide && this.mqWide.addEventListener) this.mqWide.addEventListener('change', this.onWide);
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

  /** The label of the scope this snapshot is for ("Logical system LS-A"). */
  scopeLabel() {
    return scopeTitle(this.snap, (this.snap && this.snap.meta && this.snap.meta.scope) || this.ctx.store.scope);
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

  refresh() {
    this.refreshBtn.setAttribute('aria-disabled', 'true');
    this.ctx.store.inventory(true).then((snap) => {
      if (this.dead) return;
      this.refreshBtn.removeAttribute('aria-disabled');
      if (snap) this.ctx.ui.toast('Read the configuration again.', 'ok');
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
    if (this.panelKind) this.ctx.ui.closePanel();
    this.snap = null;
    this.model = null;
    this.sel = null;
    this.wantSel = null;
    this.wantName = null;
    this.cursor = -1;
    this.load(false);
  }

  onSessions() {
    if (this.dead || !this.model) return;
    this.renderLiveAll();
  }

  update(route) {
    this.readRoute(route, false);
  }

  destroy() {
    this.dead = true;
    clearInterval(this.ageTimer);
    for (const off of this.offs) off();
    document.removeEventListener('keydown', this.onKeyBound);
    if (this.mqWide && this.mqWide.removeEventListener) this.mqWide.removeEventListener('change', this.onWide);
    if (this.bar) this.bar.destroy();
  }

  readRoute(route, first) {
    const p = route && route.params ? route.params : new URLSearchParams();
    const q = p.get('q') || '';
    const sel = p.get('sel') || null;
    if (first || q !== this.text) {
      this.text = q;
      if (this.bar) this.bar.setValue(q);
      const parsed = this.bar ? this.bar.parsed : this.Q ? this.Q.parse(q, { view: 'policies' }) : { ast: null, error: null };
      this.setAst(parsed.error ? null : parsed.ast, false);
      // A link that names one policy ("#/policies?q=name:allow-web", from a log line or the deny
      // ticker) opens it, with its evaluation order, when the name is used in one place only.
      this.wantName = !sel && !parsed.error ? this.singleName(parsed.ast) : null;
    }
    if (sel !== this.sel && sel) {
      this.wantSel = sel;
      this.tryOpenWanted();
      return;
    }
    // A link that names one policy opens it, even while another one is open (POL-UI-10). The open
    // panel is closed only when no single policy is wanted, or the wanted one is not here.
    if (!sel && this.wantName) {
      const opened = this.tryOpenWanted();
      if (opened !== false) return;
    }
    if (!sel && this.sel && this.panelKind === 'policy') {
      this.sel = null;
      this.ctx.ui.closePanel();
    }
  }

  /** The policy name when a query is exactly one name:<value> term (no wildcard, no alternatives). */
  singleName(ast) {
    if (!ast || ast.type !== 'term' || !ast.key || (ast.op !== ':' && ast.op !== '=') || ast.values.length !== 1) return null;
    const v = ast.values[0];
    if (v.kind === 'regex' || v.text.includes('*') || keyName(this.fields, ast.key) !== 'name') return null;
    return v.text;
  }

  saveRoute(push = false) {
    this.ctx.setParams({ q: this.text || null, sel: this.sel || null }, { replace: !push });
  }

  // ---- frame -----------------------------------------------------------------------------------

  build() {
    const { h } = this;
    const { icon } = this.ctx.dom;
    this.el.classList.add('pv-view');
    this.subEl = h('p', { class: 'view-sub pv-sub' }, 'Reading the security policies\u2026');
    this.refreshBtn = h(
      'button',
      { class: 'btn', type: 'button', title: 'Read the configuration again (r)', on: { click: () => this.refresh() } },
      icon('refresh'),
      h('span', { class: 'pv-hide-sm' }, 'Refresh'),
    );
    const exp = (fmtName) =>
      h('button', { type: 'button', title: `Export this scope as ${fmtName.toUpperCase()} (a fresh device read)`, on: { click: () => this.exportAs(fmtName) } }, fmtName.toUpperCase());
    this.exportSeg = h(
      'div',
      { class: 'seg pv-export', role: 'group', 'aria-label': 'Export the inventory' },
      h('span', { class: 'pv-seg-label' }, icon('download'), h('span', { class: 'pv-hide-sm' }, 'Export')),
      exp('json'),
      exp('csv'),
    );
    this.summaryBtn = h(
      'button',
      { class: 'btn sm ghost pv-ss-toggle', type: 'button', 'aria-controls': 'pv-top', on: { click: () => this.toggleSummary() } },
      h('span', null, 'Summary'),
      icon('chevron-down'),
    );
    this.explainBtn = h(
      'button',
      { class: 'btn', type: 'button', title: 'How Junos picks a policy for a flow, and the command to test one', on: { click: () => this.openExplainer(null, null) } },
      icon('help'),
      h('span', { class: 'pv-hide-sm' }, 'Explain a flow'),
    );
    const head = h(
      'div',
      { class: 'view-head pv-head' },
      h('div', { class: 'pv-titles' }, h('h1', { class: 'view-title' }, 'Policies'), this.subEl),
      h('div', { class: 'view-actions' }, this.explainBtn, this.exportSeg, this.refreshBtn),
    );
    this.noticeEl = h('div', { class: 'pv-notices' });
    this.stateEl = h('div', { class: 'pv-state', hidden: true });
    this.stripEl = h('section', { class: 'pv-sumstrip', 'aria-label': 'Evaluation order and summary' });
    this.cardsEl = h('div', { class: 'pv-cards' });
    this.topEl = h('div', { class: 'pv-top', id: 'pv-top' }, this.cardsEl);
    this.sideEl = h('aside', { class: 'pv-side', hidden: true, 'aria-label': 'Zone pairs' });
    this.applySummaryPref();
    this.qbHost = h('div', { class: 'pv-qb' });
    const QB = this.ctx.QueryBar;
    if (QB && this.Q) {
      this.bar = new QB({
        view: 'policies',
        label: 'Filter policies',
        placeholder: 'Filter policies: addr:10.10.3.4  from:trust  app:junos-https  action:deny  -inactive:yes',
        value: '',
        onChange: (text, parsed) => this.onQuery(text, parsed),
        getContext: () => ({ rows: this.model ? this.model.rows : [], inventory: this.snap }),
      });
      this.qbHost.append(this.bar.el);
    } else {
      this.qbHost.append(
        this.ctx.dom.stateCard({ status: 'failed', compact: true, title: 'The query engine did not load', message: 'Every policy is listed; filtering is not available. Reload the page to try again.' }),
      );
    }
    this.quickEl = h('div', { class: 'pv-quick', role: 'group', 'aria-label': 'Quick filters' });
    this.infoEl = h('div', { class: 'pv-info' });
    this.infoPanel = h('div', { class: 'pv-infopanel', id: 'pv-infopanel', hidden: true });
    this.noteEl = h('p', { class: 'pv-filter-note', hidden: true }, 'Global policies stay listed when they apply to the chosen zones: a global policy without a zone list applies to every zone.');
    this.tableHost = h('div', { class: 'pv-tablehost' });
    this.mainEl = h(
      'div',
      { class: 'pv-main' },
      h('div', { class: 'pv-main-l' }, h('div', { class: 'pv-filter' }, this.qbHost, h('div', { class: 'pv-quickrow' }, this.quickEl, this.infoEl), this.infoPanel, this.noteEl), this.tableHost),
      this.sideEl,
    );
    this.bodyEl = h('div', { class: 'pv-body', hidden: true }, this.stripEl, this.topEl, this.mainEl);
    this.loadingEl = h('div', { class: 'pv-loading' }, this.ctx.dom.skeleton(3), this.ctx.dom.skeleton(5));
    this.el.append(head, this.noticeEl, this.stateEl, this.loadingEl, this.bodyEl);
    this.tableHost.addEventListener('click', (e) => this.onTableClick(e));
  }

  applySummaryPref() {
    let open = false;
    try {
      open = window.localStorage.getItem(SUMMARY_PREF) === 'open';
    } catch (_err) {
      open = false;
    }
    this.setSummary(open);
  }

  /** The compact strip is always shown; "Summary" opens the full cards (evaluation order, matrix). */
  setSummary(open) {
    this.topEl.hidden = !open;
    this.stripEl.classList.toggle('is-open', open);
    this.summaryBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
    this.summaryBtn.title = open ? 'Hide the summary cards (more room for the table)' : 'Show the evaluation order, facts and the zone-pair matrix';
  }

  toggleSummary() {
    const open = this.topEl.hidden;
    try {
      if (open) window.localStorage.setItem(SUMMARY_PREF, 'open');
      else window.localStorage.removeItem(SUMMARY_PREF);
    } catch (_err) {
      // Storage blocked: the choice lasts for this page only.
    }
    this.setSummary(open);
  }

  /** At 1600 px and wider the matrix sits in a sticky card beside the table; narrower, in the cards. */
  placeMatrix() {
    if (!this.mxCard) return;
    const wide = Boolean(this.mqWide && this.mqWide.matches);
    const host = wide ? this.sideEl : this.cardsEl;
    if (this.mxCard.parentNode !== host) host.append(this.mxCard);
    this.sideEl.hidden = !wide;
    this.mainEl.classList.toggle('has-side', wide);
    this.cardsEl.classList.toggle('single', wide);
  }

  renderLoading() {
    this.loadingEl.hidden = false;
    this.bodyEl.hidden = true;
    this.stateEl.hidden = true;
    this.renderSub();
  }

  renderFailed() {
    if (this.snap && this.snap.meta && this.snap.meta.scope === this.ctx.store.scope) {
      // A re-read failed: keep showing the last good read of this scope, and say so.
      this.renderNotices();
      return;
    }
    const st = inventoryState(this.ctx, null, 'security policies', () => this.load(true));
    this.loadingEl.hidden = true;
    this.bodyEl.hidden = true;
    this.ctx.dom.put(this.stateEl, st || this.ctx.dom.stateCard({ status: 'failed', message: 'The inventory could not be read.' }));
    this.stateEl.hidden = false;
    this.renderSub();
  }

  renderSub() {
    if (this.dead) return;
    this.ctx.dom.put(this.subEl, ...subLine(this.ctx, this.snap, this.receivedAt));
  }

  renderNotices() {
    const { h } = this;
    const { icon } = this.ctx.dom;
    const out = [];
    const snap = this.snap;
    const err = inventoryErrorFor(this.ctx);
    if (snap && err) {
      out.push(
        h(
          'div',
          { class: 'pv-notice deny', role: 'status' },
          icon('alert'),
          h('span', null, h('b', null, 'The last read failed. '), this.vd(`${err.message} This page still shows the read from ${this.fmt.time(snap.meta && snap.meta.read_at)} UTC.`)),
        ),
      );
    }
    if (snap && snap.scope && snap.scope.inactive) {
      out.push(
        h(
          'div',
          { class: 'pv-notice reject', role: 'note' },
          icon('alert'),
          h('span', null, h('b', null, this.v(`${scopeTitle(snap, snap.meta.scope)} is deactivated in the configuration. `)), 'Nothing in this scope is in effect; the policies below are what the configuration holds, not what the device enforces.'),
        ),
      );
    }
    // [edit security policies] or [edit security] deactivated (POL-UI-01): every policy of the scope is
    // out of effect. A deactivated scope already has its banner above.
    const why = this.ancestorReason();
    if (why && why !== 'scope') {
      out.push(
        h(
          'div',
          { class: 'pv-notice reject', role: 'note' },
          icon('alert'),
          h('span', null, h('b', null, ancestorSentence(why, this.scopeLabel())), ' ', h('span', { class: 'faint' }, 'What Junos then enforces is J-Wicket’s reading (inferred).')),
        ),
      );
    }
    this.ctx.dom.put(this.noticeEl, ...out);
    this.noticeEl.hidden = !out.length;
  }

  /**
   * The deactivated ancestor of every policy of the scope: `policies.ancestor_inactive` (B-9), or the
   * reason every row shares when that is an ancestor reason. Null otherwise.
   */
  ancestorReason() {
    const pol = this.snap && this.snap.scope && this.snap.scope.policies;
    if (!pol || pol.status !== 'ok') return null;
    if (pol.ancestor_inactive) return pol.ancestor_inactive;
    const rows = pol.rows || [];
    if (!rows.length) return null;
    const first = rows[0].inactive_reason;
    return ANCESTOR_REASONS.includes(first) && rows.every((r) => r.inactive_reason === first) ? first : null;
  }

  // ---- render ----------------------------------------------------------------------------------

  render() {
    const { h } = this;
    const snap = this.snap;
    this.loadingEl.hidden = true;
    this.renderSub();
    this.renderNotices();
    const st = inventoryState(this.ctx, snap, 'security policies', () => this.load(true));
    const pol = snap && snap.scope ? snap.scope.policies || {} : null;
    let state = st;
    if (!state && pol && pol.status !== 'ok') {
      state = this.ctx.dom.stateCard({ status: pol.status, message: pol.message, hint: undefined });
    }
    const usable = !state;
    this.summaryBtn.hidden = !usable;
    this.explainBtn.hidden = !usable;
    this.exportSeg.hidden = !(snap && (!snap.config || snap.config.status === 'ok'));
    if (state) {
      this.model = null;
      this.bodyEl.hidden = true;
      this.ctx.dom.put(this.stateEl, h('div', { class: 'pv-statewrap' }, h('p', { class: 'pv-state-what' }, 'The security policies of this scope are not shown.'), state));
      this.stateEl.hidden = false;
      if (this.panelKind) this.ctx.ui.closePanel();
      // Nothing can be opened: drop a policy the address asks for (as tryOpenWanted does).
      this.wantName = null;
      if (this.wantSel || this.sel) {
        this.wantSel = null;
        this.sel = null;
        this.saveRoute(false);
      }
      return;
    }
    this.stateEl.hidden = true;
    this.bodyEl.hidden = false;
    this.model = buildModel(snap);
    this.zonesAll = this.model.zones;
    this.termsKey = null;
    this.hlKeys = new Array(this.model.rows.length).fill('');
    this.markedIdx = -1;
    this.renderTop();
    this.renderTable();
    this.compile();
    this.applyFilter(false);
    this.renderLiveAll();
    if (this.panelKind === 'policy' && this.sel) {
      const idx = this.model.idById.get(this.sel);
      if (idx === undefined) this.ctx.ui.closePanel();
      else this.openDetail(idx, { refresh: true });
    } else if (this.panelKind === 'explain' && this.explainState) {
      this.openExplainer(this.explainState.from, this.explainState.to, { refresh: true });
    }
    this.tryOpenWanted();
  }

  /**
   * Opens the policy a link asked for (`sel`, or a single `name:` term). Returns true when one opened,
   * false when nothing could be opened, and undefined while the inventory is not loaded yet.
   */
  tryOpenWanted() {
    if (!this.model) return undefined;
    if (!this.wantSel && this.wantName) {
      const idxs = this.model.byName.get(this.wantName) || [];
      this.wantName = null;
      if (idxs.length === 1) this.wantSel = this.model.rows[idxs[0]].id;
    }
    if (!this.wantSel) return false;
    const want = this.wantSel;
    this.wantSel = null;
    const idx = this.model.idById.get(want);
    if (idx === undefined) {
      this.sel = null;
      this.saveRoute(false);
      if (this.panelKind === 'policy') this.ctx.ui.closePanel();
      this.ctx.ui.toast('That policy is not in this scope of the configuration.', 'warn');
      return false;
    }
    this.openDetail(idx, { push: false });
    const tr = this.trs[idx];
    if (tr && !tr.hidden) tr.scrollIntoView({ block: 'nearest' });
    return true;
  }

  // ---- top: evaluation order, facts, matrix ----------------------------------------------------

  renderTop() {
    this.renderStrip();
    this.renderCards();
    this.renderInfo();
  }

  /**
   * The compact summary (one line on desktop): ① zone-pair → ② global → ③ default │ action mix │ live
   * │ groups │ Summary ▾. The steps scroll to their section of the table.
   */
  renderStrip() {
    const { h } = this;
    const fmt = this.fmt;
    const m = this.model;
    const c = m.counts;
    const ds = defaultState(m.pol, this.scopeLabel());
    const arrow = () => h('span', { class: 'pv-ss-arrow', 'aria-hidden': 'true' }, ARROW);
    const step = (n, value, label, target, cls, tip) =>
      h(
        'button',
        { class: ['pv-ss-step', cls], type: 'button', title: tip, on: { click: () => this.scrollToSection(target) } },
        h('span', { class: 'pv-ss-n', 'aria-hidden': 'true' }, String(n)),
        h('b', { class: 'pv-ss-v' }, value),
        label ? h('span', { class: 'pv-ss-l' }, label) : null,
      );
    const flow = h(
      'div',
      { class: 'pv-ss-seg pv-ss-flow', role: 'group', 'aria-label': 'Junos evaluation order: first match wins' },
      step(1, fmt.num(c.zone), 'zone-pair', 'pairs', '', `Checked first: the policies of the flow’s from-zone to to-zone pair, top to bottom (${fmt.plural(m.pairs.size, 'zone pair')})`),
      arrow(),
      step(2, fmt.num(c.global), 'global', 'global', '', c.global ? 'Checked next, in order, for each zone pair they apply to' : 'No global policies are configured'),
      arrow(),
      step(3, ds.action, ds.badge ? ds.badge : '', 'default', ds.cls, `${plain(ds.label)}. ${ds.tip}`),
    );
    const total = Math.max(1, m.rows.length);
    const seg = (cls, v) => (v ? h('i', { class: cls, style: { '--w': `${(v / total) * 100}%` } }) : null);
    const mix = h(
      'div',
      { class: 'pv-ss-seg pv-ss-mix', title: `${fmt.plural(m.rows.length, 'policy')} in this scope` },
      h('div', { class: 'meter pv-meter', 'aria-hidden': 'true' }, seg('permit', c.permit), seg('deny', c.deny), seg('reject', c.reject), seg('inactive', c.inactive), seg('', c.unknown)),
      h(
        'span',
        { class: 'pv-mix' },
        h('span', { class: 'act-permit' }, `${fmt.num(c.permit)} permit`),
        SEP,
        h('span', { class: 'act-deny' }, `${fmt.num(c.deny)} deny`),
        SEP,
        h('span', { class: 'act-reject' }, `${fmt.num(c.reject)} reject`),
        SEP,
        h('span', { class: 'muted' }, `${fmt.num(c.inactive)} inactive`),
        c.unknown ? [SEP, h('span', { class: 'act-unknown' }, `${fmt.num(c.unknown)} no action`)] : null,
      ),
    );
    this.liveStrip = h('div', { class: 'pv-ss-seg pv-ss-live' });
    const groups = m.scope.groups || [];
    const groupSeg = groups.length
      ? h(
          'div',
          { class: 'pv-ss-seg pv-ss-groups' },
          h('span', { class: 'pv-ss-cap' }, groups.length === 1 ? 'group' : 'groups'),
          groups.slice(0, 3).map((g) =>
            h(
              'button',
              { class: 'pv-chipbtn gold', type: 'button', title: `Show the policies with parts from configuration group ${plain(g.name, { all: true })} (${g.policies})`, on: { click: () => this.toggleTerm('group', g.name) } },
              h('span', { class: 'mono' }, this.v(g.name)),
              h('span', { class: 'pv-chipcount' }, fmt.num(g.policies)),
            ),
          ),
          groups.length > 3 ? h('span', { class: 'faint' }, `+${groups.length - 3}`) : null,
        )
      : null;
    this.ctx.dom.put(this.stripEl, flow, mix, this.liveStrip, groupSeg, h('span', { class: 'spacer' }), this.summaryBtn);
  }

  /** The full summary cards (opened with "Summary"): evaluation order and facts, zone-pair matrix. */
  renderCards() {
    const { h } = this;
    const { icon, put } = this.ctx.dom;
    const fmt = this.fmt;
    const m = this.model;
    const pol = m.pol;
    const c = m.counts;
    const step = (n, title, value, sub, cls, target, tip) =>
      h(
        'li',
        { class: 'pv-step-li' },
        h(
          'button',
          { class: ['pv-step', cls], type: 'button', title: tip, on: { click: () => this.scrollToSection(target) } },
          h('span', { class: 'pv-step-n', 'aria-hidden': 'true' }, String(n)),
          h('span', { class: 'pv-step-t' }, title),
          h('b', { class: 'pv-step-v' }, value),
          h('span', { class: 'pv-step-s' }, sub),
        ),
      );
    const ds = defaultState(pol, this.scopeLabel());
    const flow = h(
      'ol',
      { class: 'pv-flow', 'aria-label': 'Junos evaluation order' },
      step(1, 'Zone-pair policies', fmt.num(c.zone), `in ${fmt.plural(m.pairs.size, 'zone pair')}, top to bottom`, '', 'pairs', 'Checked first: the policies of the flow’s from-zone to to-zone pair, in configuration order'),
      step(2, 'Global policies', fmt.num(c.global), c.global ? 'for each pair they apply to' : 'none configured', '', 'global', 'Checked next, in order, when no zone-pair policy matched'),
      step(3, 'Default policy', ds.action, this.v(ds.label), `${ds.cls} is-word`, 'default', `Used when no policy above matched. ${ds.tip}`),
    );
    const explain = h(
      'p',
      { class: 'pv-explain' },
      h('b', null, 'First match wins. '),
      'J-Wicket shows the order Junos checks; it does not decide which policy a flow matches. ',
      h('button', { class: 'link pv-inline-link', type: 'button', on: { click: () => this.openExplainer(null, null) } }, 'Test a flow on the device', icon('arrow-right')),
    );
    this.liveFact = h('dd', { class: 'pv-live-fact' });
    const facts = h(
      'dl',
      { class: 'pv-facts' },
      h('div', { class: 'pv-fact' }, h('dt', null, 'Live sessions'), this.liveFact),
      h('div', { class: 'pv-fact' }, h('dt', null, 'Policy rematch'), h('dd', null, this.rematchFact(pol))),
      pol.pre_id_default_policy || pol.pre_id_default_policy_inactive
        ? h(
            'div',
            { class: 'pv-fact' },
            h('dt', null, 'Pre-ID default policy'),
            h(
              'dd',
              { title: pol.pre_id_default_policy_comment ? `Comment: ${plain(pol.pre_id_default_policy_comment)}` : null },
              pol.pre_id_default_policy
                ? ['configured', h('span', { class: 'faint' }, ' (contents not shown)')]
                : h('span', { class: 'pv-amber' }, 'configured but deactivated (not in effect)'),
            ),
          )
        : null,
      h(
        'div',
        { class: 'pv-fact' },
        h('dt', null, 'Configuration groups'),
        h(
          'dd',
          { class: 'pv-groups' },
          (m.scope.groups || []).length
            ? m.scope.groups.map((g) =>
                h(
                  'button',
                  { class: 'pv-chipbtn gold', type: 'button', title: `Show the policies with parts from group ${plain(g.name, { all: true })}`, on: { click: () => this.toggleTerm('group', g.name) } },
                  h('span', { class: 'mono' }, this.v(g.name)),
                  h('span', { class: 'pv-chipcount' }, fmt.num(g.policies)),
                ),
              )
            : h('span', { class: 'muted' }, 'none'),
        ),
      ),
    );
    const evalCard = h(
      'section',
      { class: 'tile pv-eval', 'aria-label': 'Evaluation order and facts' },
      h('div', { class: 'tile-head' }, h('h2', { class: 'tile-title' }, icon('policies'), 'Evaluation order'), h('span', { class: 'tile-meta' }, this.v(scopeTitle(this.snap, this.ctx.store.scope)))),
      h('div', { class: 'tile-body pv-eval-body' }, flow, explain, facts),
    );
    this.mxCard = h(
      'section',
      { class: 'tile pv-mxcard', 'aria-labelledby': 'pv-mx-title' },
      h('div', { class: 'tile-head' }, h('h2', { class: 'tile-title', id: 'pv-mx-title' }, icon('grid'), 'Zone pairs'), h('span', { class: 'tile-meta' }, 'from ↓  to →')),
      h('div', { class: 'tile-body' }, this.buildMatrix()),
    );
    put(this.cardsEl, evalCard);
    put(this.sideEl);
    this.placeMatrix();
  }

  /**
   * policy-rematch in three states (POL-UI-03, POL-UI-12). The meaning of the "off" state is the
   * contract's wording; the tooltip of "on" cites the YANG text only (J-Wicket shows the setting, not
   * its effect on a given session).
   */
  rematchFact(pol) {
    const { h } = this;
    const note = pol.policy_rematch_comment ? ` Comment: ${plain(pol.policy_rematch_comment)}` : '';
    if (pol.policy_rematch && pol.policy_rematch_extensive) {
      return h('span', { title: `policy-rematch extensive is configured (YANG: "Perform policy extensive rematch").${note}` }, 'on, extensive: a session may stay up if another policy permits it');
    }
    if (pol.policy_rematch) {
      return h('span', { title: `policy-rematch is configured (YANG: "enable policy-rematch"). Juniper Feature Explorer, feature 5004, describes what it re-checks; J-Wicket shows the setting.${note}` }, 'on: changed policies are re-checked');
    }
    if (pol.policy_rematch_inactive) {
      return h('span', { class: 'pv-amber', title: `policy-rematch is written in the configuration but deactivated (inactive:).${note}` }, 'off: configured but deactivated (not in effect)');
    }
    return h('span', { class: 'muted' }, 'off (not configured): sessions of a renamed, deactivated or deleted policy are closed');
  }

  /** Central management and warnings as two chips beside the quick filters; each opens a short panel. */
  renderInfo() {
    const { h } = this;
    const { icon } = this.ctx.dom;
    const mg = this.snap.management || {};
    const warnings = [...(this.snap.warnings || []), ...((this.snap.scope && this.snap.scope.warnings) || [])];
    const chips = [];
    const chip = (key, cls, kids, title) => {
      const on = this.infoOpen === key;
      return h(
        'button',
        { class: ['pv-infochip', cls], type: 'button', title, dataset: { info: key }, 'aria-expanded': on ? 'true' : 'false', 'aria-controls': 'pv-infopanel', on: { click: () => this.toggleInfo(key) } },
        kids,
        icon('chevron-down'),
      );
    };
    if (mg.status !== 'ok') {
      chips.push(chip('managed', 'is-unknown', [icon('broadcast'), h('span', null, 'central management not known')], 'Whether another system manages this device could not be read'));
    } else if (mg.managed) {
      const names = (mg.clients || []).map((c) => c.client);
      chips.push(chip('managed', 'is-gold', [icon('broadcast'), h('span', null, 'managed from '), h('b', { class: 'mono' }, this.v(names.slice(0, 2).join(', '))), names.length > 2 ? h('span', null, ` +${names.length - 2}`) : null], 'Another system also manages this device (outbound-ssh). Select for details.'));
    }
    if (warnings.length) {
      chips.push(chip('warnings', 'is-amber', [icon('alert'), h('b', null, String(warnings.length)), h('span', null, warnings.length === 1 ? ' warning' : ' warnings')], 'What J-Wicket could not show, or what is not in effect. Select to read them.'));
    }
    if (!chips.some((c) => c.dataset.info === this.infoOpen)) this.infoOpen = null;
    this.ctx.dom.put(this.infoEl, chips);
    this.infoEl.hidden = !chips.length;
    this.renderInfoPanel();
  }

  toggleInfo(key) {
    this.infoOpen = this.infoOpen === key ? null : key;
    for (const b of this.infoEl.querySelectorAll('.pv-infochip')) b.setAttribute('aria-expanded', b.dataset.info === this.infoOpen ? 'true' : 'false');
    this.renderInfoPanel();
  }

  renderInfoPanel() {
    const node = this.infoOpen === 'managed' ? this.managedStrip() : this.infoOpen === 'warnings' ? this.warningsBlock() : null;
    this.ctx.dom.put(this.infoPanel, node);
    this.infoPanel.hidden = !node;
  }

  managedStrip() {
    const { h } = this;
    const { icon } = this.ctx.dom;
    const mg = this.snap.management || {};
    if (mg.status === 'ok' && !mg.managed) return null;
    if (mg.status !== 'ok') {
      return h(
        'div',
        { class: 'pv-managed unknown', role: 'note' },
        icon('broadcast'),
        h('span', null, h('b', null, 'Central management: not known. '), h('span', { class: 'muted' }, `It is read from the configuration (${mg.status || 'unknown'}). Another system may also manage this device.`)),
      );
    }
    const services = [...new Set((mg.clients || []).flatMap((c) => c.services || []))];
    return h(
      'div',
      { class: 'pv-managed', role: 'note' },
      icon('broadcast'),
      h(
        'span',
        null,
        h('b', null, 'Also managed from '),
        (mg.clients || []).map((c, i) => [i ? ', ' : null, h('b', { class: 'mono' }, this.v(c.client)), (c.targets || []).length ? h('span', { class: 'mono faint' }, ' ', this.v(c.targets.join(', '))) : null]),
        services.length ? h('span', { class: 'faint' }, ' (', this.v(services.join(', ')), ')') : null,
        h('span', { class: 'muted' }, '. Changes made there may overwrite these policies, and what you see can change without J-Wicket knowing.'),
      ),
    );
  }

  warningsBlock() {
    const { h } = this;
    const { icon } = this.ctx.dom;
    const snap = this.snap;
    const list = [...(snap.warnings || []), ...((snap.scope && snap.scope.warnings) || [])];
    if (!list.length) return null;
    const item = (w) => {
      const mm = /^Policy (\S+) (.*)$/.exec(w);
      const idxs = mm && this.model.byName.get(mm[1]);
      if (idxs && idxs.length) {
        return h(
          'li',
          null,
          icon('alert'),
          h('span', { class: 'dev-text' }, 'Policy ', h('button', { class: 'policy-link', type: 'button', title: `Open policy ${plain(mm[1])}`, on: { click: () => this.openDetail(idxs[0]) } }, this.v(mm[1])), ' ', this.vd(mm[2])),
        );
      }
      return h('li', null, icon(/^Fixture/.test(w) ? 'info' : 'alert'), h('span', { class: 'dev-text' }, this.vd(w)));
    };
    return h(
      'div',
      { class: 'pv-warn', role: 'note' },
      h('p', { class: 'pv-warn-hint' }, 'What J-Wicket could not show, or what is not in effect:'),
      h('ul', null, list.map(item)),
    );
  }

  buildMatrix() {
    const { h } = this;
    const fmt = this.fmt;
    const m = this.model;
    const zones = m.zones;
    this.mxCells = [];
    if (!zones.length) {
      return h('p', { class: 'pv-none' }, 'This scope has no zones and no zone-pair policies.');
    }
    const grid = h('div', { class: 'pv-mx', role: 'grid', 'aria-label': 'Policies per zone pair. Rows: from-zone; columns: to-zone.', style: { '--pv-cols': String(zones.length) } });
    const label = (z, axis) => {
      const unknown = m.zonesKnown && !m.defined.has(z);
      return h('span', { class: ['pv-mx-z', unknown && 'undefined'], title: `${axis} ${plain(z)}${unknown ? ' (not defined as a zone in this scope)' : ''}` }, this.v(z), unknown ? '*' : null);
    };
    grid.append(h('div', { class: 'pv-mx-row', role: 'row' }, h('span', { class: 'pv-mx-corner', role: 'columnheader', 'aria-label': 'from-zone, to-zone' }), zones.map((z) => h('span', { class: 'pv-mx-col', role: 'columnheader' }, label(z, 'to')))));
    zones.forEach((from, r) => {
      const cells = [];
      const row = h('div', { class: 'pv-mx-row', role: 'row' }, h('span', { class: 'pv-mx-rowh', role: 'rowheader' }, label(from, 'from')));
      zones.forEach((to, c) => {
        const st = m.stats.get(pairKey(from, to));
        const globalsHere = m.globals.filter((i) => globalApplies(m.rows[i], from, to) && !m.rows[i].inactive).length;
        const has = st && st.count;
        const pairInactive = has && m.pairs.get(pairKey(from, to)) && m.pairs.get(pairKey(from, to)).inactive;
        const btn = h('button', {
          class: ['pv-mx-cell', has ? 'has' : 'empty', from === to && 'self', pairInactive && 'off'],
          type: 'button',
          role: 'gridcell',
          'aria-pressed': 'false',
          tabindex: r === 0 && c === 0 ? '0' : '-1',
          dataset: { from, to, r: String(r), c: String(c) },
        });
        const liveEl = h('span', { class: 'pv-mx-live', hidden: true });
        if (has) {
          const parts = [];
          for (const a of ['permit', 'deny', 'reject']) if (st[a]) parts.push(h('i', { class: `act-${a}`, title: `${st[a]} ${a}` }, String(st[a])));
          if (st.inactive) parts.push(h('i', { class: 'muted', title: `${st.inactive} inactive` }, `${st.inactive} off`));
          const bar = h('span', { class: 'pv-mx-bar', 'aria-hidden': 'true' });
          for (const [cls, n] of [['permit', st.permit], ['deny', st.deny], ['reject', st.reject], ['inactive', st.inactive]]) {
            if (!n) continue;
            const seg = h('i', { class: cls });
            seg.style.flexGrow = String(n);
            bar.append(seg);
          }
          btn.append(h('b', { class: 'pv-mx-n' }, String(st.count)), h('span', { class: 'pv-mx-mix' }, parts), liveEl, bar);
          const notes = [st.comment, st.trailing_comment].filter(Boolean).map((t) => plain(t)).join(' | ');
          btn.title = `${plain(from)} \u2192 ${plain(to)}: ${fmt.plural(st.count, 'policy')} (${st.permit} permit, ${st.deny} deny, ${st.reject} reject, ${st.inactive} inactive)${pairInactive ? '; the zone pair is deactivated' : ''}. Select to filter.${notes ? ` Comment: ${notes}` : ''}`;
          if (notes) btn.classList.add('has-comment');
        } else {
          btn.append(
            h('span', { class: 'pv-mx-dot', 'aria-hidden': 'true' }, '\u2014'),
            h('span', { class: 'pv-mx-g' }, globalsHere ? `${globalsHere} global` : 'default'),
            liveEl,
          );
          btn.title = `${plain(from)} \u2192 ${plain(to)}: no zone-pair policy, so Junos checks ${globalsHere ? fmt.plural(globalsHere, 'global policy', 'global policies') : 'the global policies (none apply)'} and then the default policy. Select to filter.`;
        }
        btn.setAttribute('aria-label', btn.title);
        btn.addEventListener('click', () => this.togglePair(from, to));
        btn.addEventListener('focus', () => {
          for (const rr of this.mxCells) for (const cell of rr) cell.el.tabIndex = cell.el === btn ? 0 : -1;
        });
        cells.push({ el: btn, from, to, liveEl });
        row.append(btn);
      });
      this.mxCells.push(cells);
      grid.append(row);
    });
    grid.addEventListener('keydown', (e) => this.onMatrixKey(e));
    const undefinedZones = m.zonesKnown ? zones.filter((z) => !m.defined.has(z)) : [];
    this.mxLegendLive = h('span', { hidden: true }, h('i', { class: 'live' }), 'live sessions');
    const legend = h(
      'div',
      { class: 'pv-mx-legend' },
      h('span', null, h('i', { class: 'permit' }), 'permit'),
      h('span', null, h('i', { class: 'deny' }), 'deny'),
      h('span', null, h('i', { class: 'reject' }), 'reject'),
      h('span', null, h('i', { class: 'inactive' }), 'inactive'),
      this.mxLegendLive,
    );
    const notes = [];
    if (undefinedZones.length) notes.push([' * Named in a policy but not defined as a zone in this scope: ', this.v(undefinedZones.join(', ')), '.']);
    if (!m.zonesKnown) notes.push(' Zones could not be read; the zones shown are the ones named in policies.');
    return [
      h('div', { class: 'pv-mx-scroll' }, grid),
      legend,
      h('p', { class: 'pv-mx-note' }, 'Counts include inactive policies. A dashed square has no zone-pair policy: Junos checks the global policies that apply (shown), then the default policy. Select a square to filter the table.', notes),
    ];
  }

  onMatrixKey(e) {
    const t = e.target;
    if (!(t instanceof HTMLElement) || !t.classList.contains('pv-mx-cell')) return;
    const cells = this.mxCells;
    let r = Number(t.dataset.r);
    let c = Number(t.dataset.c);
    const last = cells.length - 1;
    switch (e.key) {
      case 'ArrowRight': c = Math.min(last, c + 1); break;
      case 'ArrowLeft': c = Math.max(0, c - 1); break;
      case 'ArrowDown': r = Math.min(last, r + 1); break;
      case 'ArrowUp': r = Math.max(0, r - 1); break;
      case 'Home': c = 0; if (e.ctrlKey) r = 0; break;
      case 'End': c = last; if (e.ctrlKey) r = last; break;
      default: return;
    }
    e.preventDefault();
    e.stopPropagation();
    const next = cells[r] && cells[r][c];
    if (next) next.el.focus();
  }

  // ---- table -----------------------------------------------------------------------------------

  renderTable() {
    const { h } = this;
    const { icon } = this.ctx.dom;
    const fmt = this.fmt;
    const m = this.model;
    const pol = m.pol;
    this.trs = [];
    this.liveCells = [];
    this.qmarks = [];
    this.markStamps = [];
    this.sections = [];
    const table = h('table', { class: 'pv-table', id: 'pv-table' });
    const cols = ['seq', 'name', 'src', 'dst', 'app', 'act', 'live', 'notes'];
    table.append(
      h('caption', { class: 'sr-only' }, 'Security policies in Junos evaluation order'),
      h('colgroup', null, cols.map((c) => h('col', { class: `c-${c}` }))),
      h(
        'thead',
        null,
        h(
          'tr',
          null,
          h('th', { scope: 'col', class: 'c-seq', title: 'Position in its zone pair (or among the global policies)' }, '#'),
          h('th', { scope: 'col', class: 'c-name' }, 'Policy'),
          h('th', { scope: 'col', class: 'c-src' }, 'Source'),
          h('th', { scope: 'col', class: 'c-dst' }, 'Destination'),
          h('th', { scope: 'col', class: 'c-app' }, 'Application'),
          h('th', { scope: 'col', class: 'c-act' }, 'Action'),
          h('th', { scope: 'col', class: 'c-live', title: 'Live sessions in the last Sessions poll in this tab' }, 'Live'),
          h('th', { scope: 'col', class: 'c-notes' }, 'Notes'),
        ),
      ),
    );
    const ds = defaultState(pol, this.scopeLabel());
    for (const pair of m.pairs.values()) {
      const applying = m.globals.filter((i) => globalApplies(m.rows[i], pair.from, pair.to) && !m.rows[i].inactive).length;
      const countEl = h('span', { class: 'pv-sec-count' });
      const st = m.stats.get(pair.key) || {};
      const head = h(
        'tr',
        { class: 'pv-sec', dataset: { sec: 'pair' } },
        h(
          'th',
          { colspan: String(cols.length), scope: 'colgroup' },
          h(
            'div',
            { class: 'pv-sec-in' },
            h('span', { class: 'pv-sec-pair' }, this.zoneChip(pair.from, 'from'), h('span', { class: 'arrow' }, ARROW), this.zoneChip(pair.to, 'to')),
            this.commentIcon([st.comment, st.trailing_comment], `the zone pair ${plain(pair.from)} → ${plain(pair.to)}`),
            h('span', { class: 'pv-sec-sub' }, 'checked in this order', SEP, countEl),
            pair.inactive ? h('span', { class: 'pill reject' }, 'zone pair deactivated') : null,
            h('span', { class: 'spacer' }),
            h(
              'button',
              {
                class: 'pv-sec-then',
                type: 'button',
                title: `If no policy above matches a ${plain(pair.from)} → ${plain(pair.to)} flow: ${applying ? fmt.plural(applying, 'global policy', 'global policies') : 'no global policy applies'}, then the default policy (${ds.action}: ${plain(ds.label)}). Show the full order.`,
                dataset: { from: pair.from, to: pair.to },
              },
              'no match ',
              h('span', { class: 'arrow' }, ARROW),
              applying ? ` ${applying} global ` : ' ',
              applying ? h('span', { class: 'arrow' }, ARROW) : null,
              h('span', { class: ds.cls === 'permit' ? 'act-permit' : 'act-deny' }, ` ${ds.action}`),
              icon('chevron-right'),
            ),
          ),
        ),
      );
      this.addSection(table, head, pair.idxs, countEl, { kind: 'pair', from: pair.from, to: pair.to });
    }
    if (m.globals.length) {
      const countEl = h('span', { class: 'pv-sec-count' });
      const allOff = m.globals.every((i) => m.rows[i].inactive_reason === 'zone-pair');
      const globalComment = (m.globals.map((i) => m.rows[i].pair_comment).find(Boolean)) || null;
      const head = h(
        'tr',
        { class: 'pv-sec pv-sec-global', dataset: { sec: 'global' } },
        h(
          'th',
          { colspan: String(cols.length), scope: 'colgroup' },
          h(
            'div',
            { class: 'pv-sec-in' },
            h('span', { class: 'pv-sec-pair' }, h('span', { class: 'pv-sec-name' }, 'Global policies')),
            this.commentIcon([globalComment, pol.global_trailing_comment], 'the global section'),
            h('span', { class: 'pv-sec-sub' }, 'checked after the zone-pair policies of each pair they apply to', SEP, countEl),
            allOff ? h('span', { class: 'pill reject' }, 'global section deactivated') : null,
            h('span', { class: 'spacer' }),
            h('span', { class: 'pv-sec-then static', title: `Then the default policy: ${ds.action} (${plain(ds.label)})` }, 'no match ', h('span', { class: 'arrow' }, ARROW), h('span', { class: ds.cls === 'permit' ? 'act-permit' : 'act-deny' }, ` ${ds.action}`)),
          ),
        ),
      );
      this.addSection(table, head, m.globals, countEl, { kind: 'global' });
    }
    this.noMatch = h('tbody', { class: 'pv-nomatch', hidden: true }, h('tr', null, h('td', { colspan: String(cols.length) }, h('div', { class: 'pv-nomatch-in' }))));
    table.append(this.noMatch, this.defaultBody(cols.length));
    this.table = table;
    this.ctx.dom.put(this.tableHost, h('div', { class: 'pv-tablecard' }, table));
  }

  /**
   * A comment icon for a section header (POL-UI-05): its tooltip holds the configuration comments
   * (annotate) on the zone pair or global section, and the one after its last policy. Null when none.
   */
  commentIcon(texts, where) {
    const list = (texts || []).filter(Boolean);
    if (!list.length) return null;
    const tip = `Configuration comment on ${where} (annotate; not a setting): ${list.map((t) => plain(t)).join(' | ')}`;
    return this.h('span', { class: 'pv-sec-comment', title: tip, role: 'img', 'aria-label': tip }, this.ctx.dom.icon(COMMENT_ICON, { size: 13 }));
  }

  addSection(table, head, idxs, countEl, info) {
    const tbody = this.h('tbody', { class: 'pv-group', dataset: { kind: info.kind } }, head);
    for (const idx of idxs) {
      const tr = this.policyRow(idx);
      this.trs[idx] = tr;
      tbody.append(tr);
    }
    table.append(tbody);
    this.sections.push({ tbody, idxs, countEl, ...info });
  }

  defaultBody(span) {
    const { h } = this;
    const pol = this.model.pol;
    const ds = defaultState(pol, this.scopeLabel());
    return h(
      'tbody',
      { class: 'pv-group pv-default', dataset: { kind: 'default' } },
      h(
        'tr',
        { class: 'pv-sec', dataset: { sec: 'default' } },
        h('th', { colspan: String(span), scope: 'colgroup' }, h('div', { class: 'pv-sec-in' }, h('span', { class: 'pv-sec-name' }, 'Default policy'), h('span', { class: 'pv-sec-sub' }, 'applies when no policy above matches'))),
      ),
      h(
        'tr',
        { class: 'pv-row is-default', title: 'Show how Junos reaches the default policy' },
        h('td', { class: 'c-seq' }),
        h(
          'th',
          { scope: 'row', class: 'c-name' },
          h('button', { class: 'pv-name', type: 'button', dataset: { explain: 'default' } }, 'default-policy'),
          pol.default_policy_comment ? h('div', { class: 'pv-comment', title: plain(pol.default_policy_comment) }, this.vd(pol.default_policy_comment)) : null,
        ),
        h('td', { class: 'c-src', dataset: { label: 'Source' } }, h('span', { class: 'muted mono' }, 'any')),
        h('td', { class: 'c-dst', dataset: { label: 'Destination' } }, h('span', { class: 'muted mono' }, 'any')),
        h('td', { class: 'c-app', dataset: { label: 'Application' } }, h('span', { class: 'muted mono' }, 'any')),
        h('td', { class: 'c-act' }, h('span', { class: ['pill', ds.cls] }, ds.action)),
        h('td', { class: 'c-live' }),
        h(
          'td',
          { class: 'c-notes' },
          h(
            'div',
            { class: 'pv-badges' },
            h('span', { class: ['pv-badge', ds.badge ? 'b-warn' : null], title: ds.badge ? ds.tip : `${plain(ds.label)}. ${ds.tip}` }, ds.badge ? ds.badge : this.v(ds.label)),
            ds.badge ? h('span', { class: 'pv-badge', title: ds.tip }, this.v(ds.label)) : null,
            ds.group ? h('span', { class: 'pv-badge b-group', title: `Comes from configuration group ${plain(ds.group)}` }, 'group ', this.v(ds.group)) : null,
          ),
        ),
      ),
    );
  }

  zoneChip(z, axis) {
    const unknown = this.model && this.model.zonesKnown && z && !this.model.defined.has(z);
    return this.h('span', { class: ['zone', unknown && 'pv-zone-undef'], title: unknown ? `${plain(z)}: not defined as a zone in this scope` : `${axis}-zone ${plain(z)}` }, z ? this.v(z) : '?');
  }

  zoneList(list, axis) {
    const zs = zonesOf(list);
    if (!zs.length) return [this.h('span', { class: 'zone pv-zone-any', title: `any ${axis}-zone` }, 'any')];
    return zs.map((z) => this.zoneChip(z, axis));
  }

  /** Whether the row's name, description or comments hold a hidden (control or format) character. */
  hiddenIn(r) {
    const out = [];
    const add = (s, all) => {
      for (const p of controlParts(String(s || ''), { all })) if (p.ctl && !out.includes(p.ctl)) out.push(p.ctl);
    };
    add(r.name, true);
    add(r.description, false);
    add(r.comment, false);
    for (const c of r.part_comments || []) add(c.text, false);
    return out;
  }

  policyRow(idx) {
    const { h } = this;
    const r = this.model.rows[idx];
    const nameBtn = h('button', { class: 'pv-name', type: 'button', 'aria-haspopup': 'dialog', title: `Open ${plain(r.name, { all: true })}` }, h('span', { class: 'pv-hl', dataset: { text: r.name } }, this.v(r.name)));
    const liveCell = h('td', { class: 'c-live', dataset: { label: 'Live' } });
    this.liveCells[idx] = liveCell;
    const qmark = h('span', { class: 'pv-qmark', hidden: true, dataset: { mark: '' } });
    this.qmarks[idx] = qmark;
    return h(
      'tr',
      { class: ['pv-row', r.inactive && 'is-inactive'], dataset: { idx: String(idx) } },
      h('td', { class: 'c-seq' }, String(r.seq)),
      h(
        'th',
        { scope: 'row', class: 'c-name' },
        nameBtn,
        r.kind === 'global' ? h('div', { class: 'pv-gzones' }, this.zoneList(r.from, 'from'), h('span', { class: 'arrow' }, ARROW), this.zoneList(r.to, 'to')) : null,
        r.comment ? h('div', { class: 'pv-comment pv-hl', title: plain(r.comment), dataset: { text: r.comment, all: '0' } }, this.vd(r.comment)) : null,
        r.description ? h('div', { class: 'pv-desc pv-hl', title: plain(r.description), dataset: { text: r.description, all: '0' } }, this.vd(r.description)) : null,
      ),
      h('td', { class: 'c-src', dataset: { label: 'Source' } }, this.addrList(r, 'source')),
      h('td', { class: 'c-dst', dataset: { label: 'Destination' } }, this.addrList(r, 'destination')),
      h('td', { class: 'c-app', dataset: { label: 'Application' } }, this.appList(r), qmark),
      h('td', { class: 'c-act' }, this.actionPill(r.action)),
      liveCell,
      h('td', { class: 'c-notes', dataset: { label: 'Notes' } }, h('div', { class: 'pv-badges' }, this.notes(r))),
    );
  }

  actionPill(action) {
    const cls = ['permit', 'deny', 'reject'].includes(action) ? action : 'muted';
    return this.h('span', { class: ['pill', cls, 'pv-act'] }, action || 'unknown');
  }

  valueToken(key, value, extra) {
    return this.h(
      'span',
      { class: ['pv-v', 'pv-hl', extra], dataset: { k: key, v: value, text: value }, title: `Filter by ${key}:${plain(value, { all: true })} (Alt-click to exclude)` },
      this.v(value),
    );
  }

  /** The amber "deactivated" tag of a reference whose entry (or a member) is written but inactive. */
  skippedTag(res, what) {
    const skipped = res.inactive_skipped || [];
    if (!skipped.length) return null;
    const names = what === 'address' ? skipped.map((x) => skippedRef(x).name) : skipped;
    const title =
      res.kind === 'unresolved'
        ? `Deactivated: ${plain(res.name)} is written in the configuration but inactive, so this policy cannot use it (not in effect).`
        : `Members deactivated (not in effect): ${plain(names.join(', '))}`;
    return this.h('span', { class: 'pv-tag amber', title }, 'deactivated');
  }

  addrList(r, side) {
    const { h } = this;
    const names = (r.match && r.match[side]) || [];
    const resolved = (r.resolved && r.resolved[side]) || [];
    const excluded = r.match && r.match[`${side}_excluded`];
    const key = side === 'source' ? 'src' : 'dst';
    const ul = h('ul', { class: 'pv-names' });
    if (excluded) ul.append(h('li', null, h('span', { class: 'pv-tag bad', title: `${side}-address-excluded: every address except these` }, 'all except')));
    names.slice(0, LIST_LIMIT).forEach((name) => {
      const res = resolved.find((x) => x.name === name) || {};
      const leaves = res.leaves || [];
      let hint = null;
      if (res.kind === 'set') hint = h('span', { class: 'pv-tag', title: `Address set: ${leaves.length}${res.truncated ? '+' : ''} addresses` }, `set ${leaves.length}${res.truncated ? '+' : ''}`);
      else if (res.kind === 'address' && leaves.length === 1 && leaves[0].value && leaves[0].value !== name) hint = h('span', { class: 'pv-hint', title: `${leaves[0].kind || 'address'} ${plain(leaves[0].value)}` }, this.v(leaves[0].value));
      // "not found" only for a real miss; a deactivated entry or member gets the amber tag (POL-UI-08).
      const missing = (res.kind === 'unresolved' && !(res.inactive_skipped || []).length) || (res.unresolved || []).length;
      ul.append(
        h(
          'li',
          null,
          this.valueToken(key, name, name === 'any' && 'is-any'),
          hint,
          this.skippedTag(res, 'address'),
          missing ? h('span', { class: 'pv-tag bad', title: 'No address book visible to this policy defines it' }, 'not found') : null,
        ),
      );
    });
    if (names.length > LIST_LIMIT) ul.append(h('li', { class: 'pv-more' }, `+${names.length - LIST_LIMIT} more`));
    return ul;
  }

  appList(r) {
    const { h } = this;
    const mm = r.match || {};
    const names = mm.application || [];
    const resolved = (r.resolved && r.resolved.application) || [];
    const ul = h('ul', { class: 'pv-names' });
    names.slice(0, LIST_LIMIT).forEach((name) => {
      const res = resolved.find((x) => x.name === name) || {};
      const leaves = res.leaves || [];
      let hint = null;
      if (res.kind === 'set') hint = h('span', { class: 'pv-tag', title: `Application set: ${leaves.length} applications` }, `set ${leaves.length}`);
      else if (res.kind === 'application' && leaves[0] && leaves[0].protocol) {
        hint = h('span', { class: 'pv-hint' }, this.v(`${leaves[0].protocol}${leaves[0].destination_port ? `/${leaves[0].destination_port}` : ''}`));
      } else if (res.kind === 'application' && leaves[0] && leaves[0].terms) hint = h('span', { class: 'pv-hint' }, `${leaves[0].terms} terms`);
      else if (res.kind === 'predefined' && this.Q && this.Q.PREDEFINED_APPS && this.Q.PREDEFINED_APPS[name]) {
        const k = this.Q.PREDEFINED_APPS[name];
        hint = h('span', { class: 'pv-hint', title: 'junos-defaults, as J-Wicket knows it' }, `${k.protocol}/${k.port}`);
      } else if (res.kind === 'dynamic-defaults') {
        hint = h('span', { class: 'pv-hint', title: 'Each dynamic application’s own default ports and protocols' }, 'dynamic app defaults');
      }
      const missing = (res.kind === 'unresolved' && !(res.inactive_skipped || []).length) || (res.unresolved || []).length;
      const unmodeled = leaves.some((l) => (l.unmodeled || []).length);
      ul.append(
        h(
          'li',
          null,
          this.valueToken('app', name, name === 'any' && 'is-any'),
          mm.application_implicit ? h('span', { class: 'pv-tag sky', title: IMPLICIT_TITLE }, 'implicit') : null,
          hint,
          this.skippedTag(res, 'application'),
          missing ? h('span', { class: 'pv-tag bad', title: 'No application or application set with this name is defined' }, 'not found') : null,
          unmodeled ? h('span', { class: 'pv-tag amber', title: 'J-Wicket does not display these application settings yet.' }, 'settings not shown') : null,
        ),
      );
    });
    if (names.length > LIST_LIMIT) ul.append(h('li', { class: 'pv-more' }, `+${names.length - LIST_LIMIT} more`));
    const dyn = mm.dynamic_application || [];
    if (dyn.length) ul.append(h('li', null, h('span', { class: 'pv-tag sky' }, 'dynamic'), h('span', { class: 'pv-hint' }, this.v(dyn.join(', ')))));
    return ul;
  }

  notes(r) {
    const { h } = this;
    const { icon } = this.ctx.dom;
    const out = [];
    const b = (text, cls, title) => h('span', { class: ['pv-badge', cls], title: title || text }, text);
    // Settings that are neither a signal nor provenance: one neutral chip style, told apart by icon.
    const nb = (iconName, text, title) => h('span', { class: 'pv-badge b-note', title: plain(title || text) }, icon(iconName, { size: 11 }), h('span', null, this.v(text)));
    if (r.inactive) out.push(b(inactiveText(r, this.scopeLabel()), 'b-inactive', plain(inactiveSentence(r, this.scopeLabel()))));
    if (r.group) out.push(h('span', { class: 'pv-badge b-group', title: `Comes from configuration group ${plain(r.group)}` }, 'group ', this.v(r.group)));
    if ((r.inherited || []).length) out.push(h('span', { class: 'pv-badge b-inherit', title: `Partly inherited from another group: ${plain(r.inherited.join(', '))}` }, 'inherits ', this.v(r.inherited.join(', '))));
    const comments = [r.comment, ...(r.part_comments || []).map((c) => c.text)].filter(Boolean);
    if (comments.length) out.push(nb(COMMENT_ICON, 'comment', comments.join('\n')));
    const hidden = this.hiddenIn(r);
    if (hidden.length) out.push(b('hidden characters', 'b-warn', `The name, description or comment holds hidden characters, shown as badges: ${hidden.join(', ')}`));
    const log = [r.log && r.log.init ? 'init' : null, r.log && r.log.close ? 'close' : null].filter(Boolean);
    if (log.length) out.push(nb('logs', `log ${log.join('+')}`, `Logs session-${log.join(' and session-')}`));
    if (r.count) out.push(nb('rows', 'count', 'Counts traffic (then count)'));
    if (r.scheduler) out.push(nb('clock', `schedule ${r.scheduler}`, `In effect only while scheduler ${r.scheduler} is active`));
    if ((r.application_services || []).length) out.push(nb('shield', r.application_services.join(', '), `Application services: ${r.application_services.join(', ')}`));
    if (r.tunnel) out.push(nb('lock', `tunnel ${r.tunnel}`, `Permits into IPsec VPN ${r.tunnel}`));
    const mm = r.match || {};
    if ((mm.source_identity || []).length) out.push(nb('user', 'source identity', `source-identity ${mm.source_identity.join(', ')}`));
    if ((mm.url_category || []).length) out.push(nb('globe', 'URL category', `url-category ${mm.url_category.join(', ')}`));
    if ((mm.source_end_user_profile || []).length) out.push(nb('user', 'end-user profile', `source-end-user-profile ${mm.source_end_user_profile.join(', ')}`));
    if ((r.inactive_parts || []).length && !r.inactive) out.push(b('parts deactivated', 'b-warn', `Deactivated, not in effect: ${plain(r.inactive_parts.join(', '))}`));
    if ((r.unmodeled || []).length) out.push(b('settings not shown', 'b-warn', `J-Wicket does not display: ${plain(r.unmodeled.join(', '))}`));
    return out;
  }

  onTableClick(e) {
    const t = e.target instanceof Element ? e.target : null;
    if (!t) return;
    const then = t.closest('.pv-sec-then[data-from]');
    if (then) {
      this.openExplainer(then.dataset.from, then.dataset.to);
      return;
    }
    if (t.closest('[data-explain="default"]') || t.closest('tr.is-default')) {
      this.openExplainer(null, null, { focusDefault: true });
      return;
    }
    const live = t.closest('.pv-live-n');
    if (live) {
      this.goSessions(live.dataset.name);
      return;
    }
    const v = t.closest('.pv-v[data-k]');
    if (v) {
      e.preventDefault();
      this.addFilter(v.dataset.k, v.dataset.v, e.altKey);
      return;
    }
    const tr = t.closest('tr.pv-row[data-idx]');
    if (!tr) return;
    if (t.closest('button, a') && !t.closest('.pv-name')) return;
    const selection = window.getSelection();
    if (selection && String(selection).length && !t.closest('button')) return; // the operator is selecting text
    this.openDetail(Number(tr.dataset.idx));
  }

  // ---- query -----------------------------------------------------------------------------------

  onQuery(text, parsed) {
    this.text = text;
    if (parsed && parsed.error) {
      if (this.bar) this.bar.setPlan(null);
      return; // the bar shows the error; the last good filter stays
    }
    this.setAst(parsed ? parsed.ast : null, true);
    this.saveRoute(false);
  }

  setAst(ast, announce) {
    this.ast = ast || null;
    this.compile();
    if (this.bar && this.Q) this.bar.setPlan(this.ast ? this.Q.plan(this.ast, 'policies') : null);
    if (this.model) this.applyFilter(announce);
  }

  compile() {
    this.matchAny = null;
    this.queryKeys = new Set();
    if (!this.Q || !this.fields) {
      this.match = () => true;
      this.terms = [];
      return;
    }
    const safe = (fn) => (row) => {
      try {
        return fn(row);
      } catch (_err) {
        return false;
      }
    };
    // Three-valued: true, false, or null when the answer depends on what J-Wicket cannot read (an
    // application port it does not know, an address it cannot compare); null rows stay listed, marked.
    const tri = this.Q.compileTri || this.Q.compile;
    this.match = safe(tri(this.ast, this.fields, { inventory: this.snap }));
    const walk = (n) => {
      if (!n) return;
      if (n.type === 'and' || n.type === 'or') n.items.forEach(walk);
      else if (n.type === 'not') walk(n.item);
      else if (n.key) {
        const k = keyName(this.fields, n.key);
        if (k) this.queryKeys.add(k);
      }
    };
    walk(this.ast);
    // A second pass where application "any" covers no port tells which rows matched only through it.
    if (this.queryKeys.has('port') && this.Q.compileTri) this.matchAny = safe(this.Q.compileTri(this.ast, this.fields, { inventory: this.snap, strictAny: true }));
    this.terms = this.ast ? this.Q.highlightTerms(this.ast) : [];
  }

  /** Why a row's answer is unknown for the current query: [{name, why}]. */
  unknownReasons(row) {
    const Q = this.Q;
    const out = [];
    if (!Q) return out;
    if (this.queryKeys.has('port') && Q.policyPorts) out.push(...Q.policyPorts(row).unknown.map((u) => ({ ...u, what: 'port' })));
    const sides = [];
    if (this.queryKeys.has('src')) sides.push('source');
    if (this.queryKeys.has('dst')) sides.push('destination');
    if (this.queryKeys.has('addr')) sides.push('both');
    if (Q.policyAddrUnknown) for (const side of sides) out.push(...Q.policyAddrUnknown(row, side).map((u) => ({ ...u, what: 'address' })));
    const seen = new Set();
    return out.filter((u) => {
      const k = `${u.what}|${u.name}`;
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    });
  }

  applyFilter(announce) {
    const m = this.model;
    if (!m || !this.table) return;
    let shown = 0;
    const order = [];
    const viaAny = [];
    const unknown = [];
    for (const sec of this.sections) {
      let n = 0;
      for (const idx of sec.idxs) {
        const row = m.rows[idx];
        const res = this.match(row);
        const vis = res !== false;
        const tr = this.trs[idx];
        if (tr && tr.hidden === vis) tr.hidden = !vis;
        let mark = null;
        if (vis && res === null) {
          mark = 'unknown';
          unknown.push(idx);
        } else if (vis && this.matchAny && this.matchAny(row) === false) {
          mark = 'any';
          viaAny.push(idx);
        }
        this.setMark(idx, mark);
        if (vis) {
          n += 1;
          order.push(idx);
        }
      }
      if (sec.tbody.hidden !== (n === 0)) sec.tbody.hidden = n === 0;
      sec.countEl.textContent = n === sec.idxs.length ? this.fmt.plural(n, 'policy') : `${n} of ${this.fmt.plural(sec.idxs.length, 'policy')}`;
      shown += n;
    }
    this.visible = order;
    const total = m.rows.length;
    const box = this.noMatch.querySelector('.pv-nomatch-in');
    if (!total) {
      this.ctx.dom.put(box, this.ctx.dom.stateCard({ status: 'empty', title: 'This scope has no security policies', message: 'Every flow between zones is decided by the default policy.', hint: null }));
    } else {
      this.ctx.dom.put(
        box,
        this.ctx.dom.stateCard({
          status: 'empty',
          title: 'No policy matches this query',
          message: this.text,
          hint: 'Free text searches names, descriptions, comments, zones, groups and addresses; addr:, src:, dst: are CIDR-aware. The default policy below still applies.',
          actions: [this.h('button', { class: 'btn sm', type: 'button', on: { click: () => this.setQuery('') } }, 'Clear the query')],
        }),
      );
    }
    this.noMatch.hidden = shown !== 0;
    if (this.bar) this.bar.setStatus(this.ast ? `${this.fmt.num(shown)} of ${this.fmt.num(total)}` : '');
    this.renderResultNote(viaAny, unknown);
    if (this.cursor >= 0 && !order.includes(this.cursor)) this.cursor = -1;
    this.renderPressed();
    this.renderQuick();
    this.highlight();
    this.markSelected();
    if (announce) this.ctx.ui.announce(`Showing ${shown} of ${this.fmt.plural(total, 'policy')}.`);
  }

  /** The "matched only through application any" / "answer unknown" mark in a row's Application cell. */
  setMark(idx, mark) {
    const el = this.qmarks[idx];
    if (!el) return;
    const key = mark || '';
    const stamp = mark ? `${mark}\u0000${this.text}` : '';
    if (el.dataset.mark === key && this.markStamps[idx] === stamp) return;
    el.dataset.mark = key;
    this.markStamps[idx] = stamp;
    el.hidden = !mark;
    if (!mark) {
      el.textContent = '';
      el.removeAttribute('title');
      return;
    }
    if (mark === 'any') {
      el.textContent = 'any port';
      el.title = 'Listed because its application is any, which covers every port';
      return;
    }
    const reasons = this.unknownReasons(this.model.rows[idx]);
    const what = new Set(reasons.map((r) => r.what));
    el.textContent = what.size === 1 && what.has('address') ? 'address ?' : what.size === 1 && what.has('port') ? 'port ?' : 'not known';
    el.title = `Kept: J-Wicket cannot tell whether this policy matches. ${plain(reasons.map((r) => `${r.name}: ${r.why}`).join('; ')) || 'Part of the match is not readable.'}`;
  }

  /** One sentence under the query bar when rows matched through application any or are unknown. */
  renderResultNote(viaAny, unknown) {
    if (!this.bar || !this.bar.setNotice) return;
    const fmt = this.fmt;
    const parts = [];
    if (viaAny.length) parts.push(`${fmt.plural(viaAny.length, 'policy matches', 'policies match')} through application any (every port), marked “any port”.`);
    if (unknown.length) {
      const names = [...new Set(unknown.flatMap((i) => this.unknownReasons(this.model.rows[i]).map((r) => r.name)))];
      parts.push(`${fmt.plural(unknown.length, 'policy is', 'policies are')} kept but not certain: J-Wicket cannot read ${plain(names.slice(0, 4).join(', '), { all: true })}${names.length > 4 ? ', …' : ''} (marked “?”). The device decides: use “Explain a flow”.`);
    }
    this.bar.setNotice(parts.join(' '), unknown.length ? 'warn' : 'info');
  }

  highlight() {
    // Only the rows on screen are re-marked; a hidden row catches up when it is shown again.
    const key = this.terms.join('\u0000');
    this.termsKey = key;
    if (!this.hlKeys) this.hlKeys = [];
    for (const idx of this.visible) {
      if (this.hlKeys[idx] === key) continue;
      this.hlKeys[idx] = key;
      const tr = this.trs[idx];
      if (!tr) continue;
      for (const el of tr.querySelectorAll('.pv-hl')) this.ctx.dom.put(el, ...markNodes(this.h, el.dataset.text, this.terms, { all: el.dataset.all !== '0' }));
    }
  }

  setQuery(text) {
    this.text = text;
    if (this.bar) {
      this.bar.setValue(text);
      this.onQuery(text, this.bar.parsed);
    } else {
      this.onQuery(text, this.Q ? this.Q.parse(text, { view: 'policies' }) : { ast: null, error: null });
    }
  }

  isKey(it, name) {
    return it && it.type === 'term' && it.key && keyName(this.fields, it.key) === name;
  }

  /** The single value of a top-level positive key:value term, or null. */
  termValue(name) {
    const items = topItems(this.ast);
    const it = items.find((x) => this.isKey(x, name) && x.op !== '!=' && x.values.length === 1);
    return it ? it.values[0].text : null;
  }

  togglePair(from, to) {
    const cur = this.termValue('from') === starControls(from) && this.termValue('to') === starControls(to);
    const next = editQuery(this.Q, this.text, {
      drop: (it) => this.isKey(it, 'from') || this.isKey(it, 'to') || this.isKey(it, 'zone'),
      add: cur ? [] : [`from:${qvDevice(from)}`, `to:${qvDevice(to)}`],
    });
    // Measured before the table changes, so this does not force a layout of the filtered table.
    const far = !cur && this.tableHost.getBoundingClientRect().top > window.innerHeight * 0.7;
    this.setQuery(next);
    if (far) this.scrollToSection('pairs');
  }

  toggleTerm(key, value) {
    const term = `${key}:${qvDevice(value)}`;
    const want = starControls(value);
    const has = topItems(this.ast).some((it) => this.isKey(it, key) && it.op !== '!=' && it.values.length === 1 && it.values[0].text === want);
    this.setQuery(editQuery(this.Q, this.text, { drop: (it) => this.isKey(it, key) && it.values.length === 1 && it.values[0].text === want, add: has ? [] : [term] }));
  }

  addFilter(key, value, exclude) {
    const want = starControls(value).toLowerCase();
    const sameValue = (it) => it.values.length === 1 && it.values[0].text.toLowerCase() === want;
    const drop = (it) => (this.isKey(it, key) && sameValue(it)) || (it.type === 'not' && this.isKey(it.item, key) && sameValue(it.item));
    const present = topItems(this.ast).some((it) => (exclude ? it.type === 'not' && this.isKey(it.item, key) && sameValue(it.item) : this.isKey(it, key) && it.op !== '!=' && sameValue(it)));
    this.setQuery(editQuery(this.Q, this.text, { drop, add: present ? [] : [`${exclude ? '-' : ''}${key}:${qvDevice(value)}`] }));
    this.ctx.ui.announce(present ? `Removed ${key} ${plain(value, { all: true })}` : `${exclude ? 'Excluding' : 'Filtering by'} ${key} ${plain(value, { all: true })}`);
  }

  renderPressed() {
    const from = this.termValue('from');
    const to = this.termValue('to');
    for (const row of this.mxCells) for (const cell of row) cell.el.setAttribute('aria-pressed', starControls(cell.from) === from && starControls(cell.to) === to ? 'true' : 'false');
    const zoneFilter = Boolean(from || to || this.termValue('zone'));
    this.noteEl.hidden = !(zoneFilter && this.model && this.model.globals.length);
  }

  renderQuick() {
    const { h } = this;
    const items = topItems(this.ast);
    const hideInactive = items.some(
      (it) => (it.type === 'not' && this.isKey(it.item, 'inactive') && it.item.values.some((v) => /^(yes|true)$/i.test(v.text))) || (this.isKey(it, 'inactive') && it.op !== '!=' && it.values.every((v) => /^(no|false)$/i.test(v.text))),
    );
    const groupsOnly = items.some((it) => this.isKey(it, 'group') && it.op !== '!=' && it.values.length === 1 && it.values[0].text === '*');
    const actionTerm = items.find((it) => this.isKey(it, 'action') && it.op !== '!=');
    const actions = actionTerm ? actionTerm.values.map((v) => v.text.toLowerCase()) : [];
    const toggle = (label, on, title, fn) => h('button', { class: 'pv-qchip', type: 'button', 'aria-pressed': on ? 'true' : 'false', title, on: { click: fn } }, label);
    const actionBtn = (a) =>
      h(
        'button',
        {
          type: 'button',
          class: a ? `pv-qa-${a}` : null,
          'aria-pressed': (a ? actions.length === 1 && actions[0] === a : !actions.length) ? 'true' : 'false',
          on: {
            click: () => this.setQuery(editQuery(this.Q, this.text, { drop: (it) => this.isKey(it, 'action'), add: a ? [`action:${a}`] : [] })),
          },
        },
        a || 'any action',
      );
    this.ctx.dom.put(
      this.quickEl,
      h('div', { class: 'seg pv-qact', role: 'group', 'aria-label': 'Action' }, actionBtn(null), actionBtn('permit'), actionBtn('deny'), actionBtn('reject')),
      toggle('Hide inactive', hideInactive, 'Adds -inactive:yes to the query', () =>
        this.setQuery(
          hideInactive
            ? editQuery(this.Q, this.text, { drop: (it) => (it.type === 'not' && this.isKey(it.item, 'inactive')) || (this.isKey(it, 'inactive') && it.values.every((v) => /^(no|false)$/i.test(v.text))) })
            : editQuery(this.Q, this.text, { add: ['-inactive:yes'] }),
        ),
      ),
      toggle('From configuration groups', groupsOnly, 'Adds group:* to the query: policies with any part from a configuration group', () =>
        this.setQuery(editQuery(this.Q, this.text, { drop: (it) => this.isKey(it, 'group') && it.values.length === 1 && it.values[0].text === '*', add: groupsOnly ? [] : ['group:*'] })),
      ),
      toggle('Not logged', items.some((it) => this.isKey(it, 'log') && it.op !== '!=' && it.values.some((v) => /^(none|no)$/i.test(v.text))), 'Adds log:none: policies that log neither session-init nor session-close', () => {
        const on = items.some((it) => this.isKey(it, 'log') && it.values.some((v) => /^(none|no)$/i.test(v.text)));
        this.setQuery(editQuery(this.Q, this.text, { drop: (it) => this.isKey(it, 'log'), add: on ? [] : ['log:none'] }));
      }),
      h('span', { class: 'spacer' }),
      this.ast
        ? h('button', { class: 'btn sm ghost', type: 'button', on: { click: () => this.setQuery('') } }, this.ctx.dom.icon('close'), 'Clear')
        : null,
    );
  }

  scrollToSection(target) {
    if (!this.table) return;
    let el = null;
    if (target === 'pairs') el = this.sections.find((s) => s.kind === 'pair' && !s.tbody.hidden);
    else if (target === 'global') el = this.sections.find((s) => s.kind === 'global');
    el = el ? el.tbody : target === 'default' ? this.table.querySelector('.pv-default') : null;
    if (!el) el = this.table;
    const reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    el.scrollIntoView({ block: 'start', behavior: reduced ? 'auto' : 'smooth' });
  }

  // ---- live sessions ---------------------------------------------------------------------------

  renderLiveAll() {
    const { h } = this;
    const { icon } = this.ctx.dom;
    const fmt = this.fmt;
    const m = this.model;
    if (!m || !this.table) return;
    const live = liveSessions(this.ctx);
    this.live = live;
    const ok = Boolean(live && live.status === 'ok');
    this.table.classList.toggle('has-live', ok);
    for (const idx of m.rows.keys()) {
      const cell = this.liveCells[idx];
      if (!cell) continue;
      const name = m.rows[idx].name;
      const n = ok ? live.counts.get(name) || 0 : 0;
      if (!ok) {
        cell.replaceChildren();
        continue;
      }
      const shared = (m.byName.get(name) || []).length > 1;
      this.ctx.dom.put(
        cell,
        n
          ? h(
              'button',
              {
                class: 'pv-live-n',
                type: 'button',
                dataset: { name },
                title: `${fmt.plural(n, 'live session')} in the last Sessions poll${shared ? ' (counted by name: the name is used in more than one place)' : ''}. Open them in Sessions.`,
              },
              h('b', null, fmt.compact(n)),
              h('span', { class: 'bar pv-live-bar', 'aria-hidden': 'true' }, h('i', { style: { '--w': `${Math.max(6, (n / Math.max(1, live.max)) * 100)}%` } })),
            )
          : h('span', { class: 'pv-live-0', title: 'No session in the last Sessions poll' }, '0'),
      );
    }
    // matrix: per pair, from names used by exactly one zone pair
    const pairLive = new Map();
    if (ok) {
      for (const [name, n] of live.counts) {
        const idxs = (m.byName.get(name) || []).filter((i) => m.rows[i].kind === 'zone');
        const keys = [...new Set(idxs.map((i) => pairKey(zonesOf(m.rows[i].from)[0], zonesOf(m.rows[i].to)[0])))];
        if (keys.length === 1) pairLive.set(keys[0], (pairLive.get(keys[0]) || 0) + n);
      }
    }
    for (const row of this.mxCells) {
      for (const cell of row) {
        const n = pairLive.get(pairKey(cell.from, cell.to)) || 0;
        cell.liveEl.hidden = !n;
        cell.liveEl.textContent = n ? fmt.compact(n) : '';
        if (n) cell.liveEl.title = `${fmt.plural(n, 'live session')} in the last Sessions poll`;
      }
    }
    if (this.mxLegendLive) this.mxLegendLive.hidden = !ok;
    // compact strip
    if (this.liveStrip) {
      const { put } = this.ctx.dom;
      if (this.ctx.store.scope !== 'root') {
        put(this.liveStrip, h('span', { class: 'faint', title: 'Flow sessions are read for the root system only' }, 'live: root only'));
      } else if (!live) {
        put(this.liveStrip, h('button', { class: 'link pv-inline-link', type: 'button', title: 'Read the session table once (one device read) to count live sessions per policy', on: { click: () => this.readSessionsOnce() } }, icon('sessions'), 'count live'));
      } else if (!ok) {
        put(this.liveStrip, h('span', { class: 'muted', title: plain(live.message || '') }, `live: ${live.status}`));
      } else {
        put(
          this.liveStrip,
          h('b', { class: 'num pv-ss-livenum', title: `${fmt.plural(live.total, 'live session')} in the Sessions poll at ${fmt.time(live.at)} UTC${live.truncated ? ' (partial list)' : ''}${live.backups ? '; backup copies not counted' : ''}` }, fmt.num(live.total)),
          h('span', { class: 'pv-ss-l' }, ' live'),
          live.truncated ? h('span', { class: 'pill reject pv-ss-pill' }, 'partial') : null,
        );
      }
    }
    // summary fact
    if (this.liveFact) {
      if (this.ctx.store.scope !== 'root') {
        this.ctx.dom.put(this.liveFact, h('span', { class: 'muted' }, 'flow sessions are read for the root system only'));
      } else if (!live) {
        this.ctx.dom.put(
          this.liveFact,
          h('span', { class: 'muted' }, 'not read in this tab yet '),
          h('button', { class: 'link pv-inline-link', type: 'button', title: 'Read the session table once (one device read)', on: { click: () => this.readSessionsOnce() } }, icon('sessions'), 'Count now'),
        );
      } else if (!ok) {
        this.ctx.dom.put(this.liveFact, h('span', { class: 'pill muted' }, live.status), ' ', h('span', { class: 'muted' }, live.status === 'refused' ? 'too many sessions to list; counts per policy are not available' : this.vd(live.message || 'the session table could not be read')));
      } else {
        const filters = Object.entries(live.filters || {}).map(([k, v]) => `${k}=${v}`);
        this.ctx.dom.put(
          this.liveFact,
          h('b', { class: 'num pv-live-total' }, fmt.num(live.total)),
          h('span', { class: 'muted' }, ` in the poll at ${fmt.time(live.at)} UTC`),
          filters.length ? h('span', { class: 'pill sky', title: 'The Sessions view asked the device for these sessions only' }, 'device filter ', this.v(filters.join(' '))) : null,
          live.truncated ? h('span', { class: 'pill reject', title: `The device returned more sessions (${live.returned}) than were listed` }, 'partial') : null,
          live.backups
            ? h(
                'span',
                { class: 'faint', title: `Chassis cluster: ${fmt.plural(live.backups, 'backup copy', 'backup copies')} of sessions left out (${live.why.join('; ')})` },
                ' \u00b7 backup copies not counted',
              )
            : null,
        );
      }
    }
    if (this.panelLive && this.panelKind === 'policy' && this.panelIdx >= 0) this.renderPanelLive(this.panelIdx);
  }

  async readSessionsOnce() {
    if (this.readingSessions) return;
    this.readingSessions = true;
    const res = await this.ctx.api.get('/api/sessions', { scope: 'root' });
    this.readingSessions = false;
    if (this.dead) return;
    if (res.ok && res.data) {
      this.ctx.ui.noteFixture(res.data.meta);
      this.ctx.store.setSessionsLast(res.data);
    } else if (res.status === 429) {
      const n = res.retryAfter || 2;
      this.ctx.ui.toast(
        res.reason === 'busy'
          ? `Another read on your session is still running. Try again in ${n} s.`
          : `Sessions were read moments ago for your session (perhaps in another tab). Try again in ${n} s.`,
        'warn',
      );
    } else if (res.status !== 401) {
      this.ctx.ui.toast(plain((res.data && res.data.error) || `The session table could not be read (HTTP ${res.status}).`), 'error');
    }
  }

  goSessions(name) {
    this.ctx.navigate('sessions', { q: `policy:${qvDevice(name)}` });
  }

  goLogs(name) {
    const sp = scopeParts(this.ctx.store.scope);
    const q = `policy:${qvDevice(name)}${sp.kind === 'lsys' ? ` lsys:${qvDevice(sp.name)}` : ''}`;
    this.ctx.navigate('logs', { q });
  }

  // ---- export ----------------------------------------------------------------------------------

  exportAs(fmtName) {
    if (!['json', 'csv'].includes(fmtName)) return;
    // The shell fetches the export and saves it from a Blob, pacing reads and turning a 429 or 401
    // into a message, so an error reply is never saved as the file.
    this.ctx.ui.exportInventory(fmtName, this.ctx.store.scope);
  }

  // ---- keyboard --------------------------------------------------------------------------------

  onKey(e) {
    if (this.dead || e.defaultPrevented || e.metaKey || e.ctrlKey || e.altKey) return;
    const t = e.target;
    if (t instanceof Element && t.closest('input, textarea, select, [contenteditable="true"], .layer, .dialog, .menu')) return;
    if (!this.el.isConnected || !this.model) return;
    if (e.key === 'j' || e.key === 'k') {
      if (!this.visible.length) return;
      e.preventDefault();
      const cur = this.panelKind === 'policy' ? this.visible.indexOf(this.panelIdx) : this.visible.indexOf(this.cursor);
      const nextPos = cur < 0 ? 0 : Math.max(0, Math.min(this.visible.length - 1, cur + (e.key === 'j' ? 1 : -1)));
      const idx = this.visible[nextPos];
      if (this.panelKind === 'policy') {
        this.openDetail(idx, { push: false });
      } else {
        this.cursor = idx;
        this.markSelected();
        const tr = this.trs[idx];
        if (tr) {
          const btn = tr.querySelector('.pv-name');
          if (btn) btn.focus({ preventScroll: true });
          tr.scrollIntoView({ block: 'nearest' });
        }
      }
    } else if (e.key === 'Enter' && this.cursor >= 0 && (t === document.body || t === document.getElementById('main'))) {
      e.preventDefault();
      this.openDetail(this.cursor);
    }
  }

  markSelected() {
    const on = this.panelKind === 'policy' ? this.panelIdx : this.cursor;
    if (on === this.markedIdx) return;
    const prev = this.trs[this.markedIdx];
    if (prev) prev.removeAttribute('aria-selected');
    const next = this.trs[on];
    if (next) next.setAttribute('aria-selected', 'true');
    this.markedIdx = on;
  }

  // ---- detail panel ----------------------------------------------------------------------------

  openDetail(idx, { push = true, refresh = false } = {}) {
    const m = this.model;
    const row = m && m.rows[idx];
    if (!row) return;
    const { h } = this;
    const { icon } = this.ctx.dom;
    const token = ++this.panelToken;
    this.panelKind = 'policy';
    this.panelIdx = idx;
    this.cursor = idx;
    const wasSel = this.sel;
    this.sel = row.id;
    const pos = this.visible.indexOf(idx);
    const nav = (dir) => {
      const list = this.visible;
      const at = list.indexOf(idx);
      const next = list[at + dir];
      return h(
        'button',
        {
          class: 'btn ghost icon sm',
          type: 'button',
          'aria-label': dir < 0 ? 'Previous policy (k)' : 'Next policy (j)',
          title: dir < 0 ? 'Previous policy (k)' : 'Next policy (j)',
          'aria-disabled': next === undefined ? 'true' : null,
          on: { click: () => next !== undefined && this.openDetail(next, { push: false }) },
        },
        icon(dir < 0 ? 'chevron-left' : 'chevron-right'),
      );
    };
    const actions = pos >= 0 ? [h('span', { class: 'pv-panel-pos faint mono' }, `${pos + 1}/${this.visible.length}`), nav(-1), nav(1)] : [];
    const opened = this.ctx.ui.panel({
      title: row.name,
      content: this.detailNode(idx),
      wide: true,
      actions,
      onClose: () => this.onPanelClosed(token),
    });
    // The shell resets the scroll while the panel is still hidden; reset it again once shown.
    if (!refresh && opened && opened.el) opened.el.scrollTop = 0;
    this.markSelected();
    const tr = this.trs[idx];
    if (tr && !tr.hidden && !refresh) tr.scrollIntoView({ block: 'nearest' });
    if (!refresh && wasSel !== row.id) this.saveRoute(push);
  }

  onPanelClosed(token) {
    if (this.dead || token !== this.panelToken) return;
    const wasPolicy = this.panelKind === 'policy';
    this.panelKind = null;
    this.panelIdx = -1;
    this.panelLive = null;
    this.explainState = null;
    if (wasPolicy && this.sel) {
      this.sel = null;
      this.saveRoute(false);
    }
    this.markSelected();
  }

  renderPanelLive(idx) {
    const { h } = this;
    const fmt = this.fmt;
    const m = this.model;
    const row = m.rows[idx];
    const el = this.panelLive;
    if (!el) return;
    const live = this.live;
    if (this.ctx.store.scope !== 'root') {
      this.ctx.dom.put(el, h('span', { class: 'muted' }, 'Flow sessions are read for the root system only.'));
      return;
    }
    if (!live) {
      this.ctx.dom.put(el, h('span', { class: 'muted' }, 'No Sessions poll in this tab yet. '), h('button', { class: 'link pv-inline-link', type: 'button', on: { click: () => this.readSessionsOnce() } }, 'Count live sessions now'));
      return;
    }
    if (live.status !== 'ok') {
      this.ctx.dom.put(el, h('span', { class: 'muted' }, `Live sessions not known: the last Sessions poll was ${live.status}.`));
      return;
    }
    const n = live.counts.get(row.name) || 0;
    const shared = (m.byName.get(row.name) || []).length > 1;
    this.ctx.dom.put(
      el,
      h('span', { class: ['pv-live-dot', n && 'on'], 'aria-hidden': 'true' }),
      h('b', { class: 'num' }, fmt.num(n)),
      ` live ${n === 1 ? 'session uses' : 'sessions use'} this policy`,
      h('span', { class: 'faint' }, ` (Sessions poll at ${fmt.time(live.at)} UTC${shared ? '; counted by name, which is used in more than one place' : ''}${live.truncated ? '; partial list' : ''})`),
    );
  }

  detailNode(idx) {
    const { h } = this;
    const { icon } = this.ctx.dom;
    const m = this.model;
    const row = m.rows[idx];
    const isGlobal = row.kind === 'global';
    const scopeId = row.scope || this.ctx.store.scope;
    const pair = !isGlobal ? m.pairs.get(pairKey(zonesOf(row.from)[0], zonesOf(row.to)[0])) : null;
    const siblings = isGlobal ? m.globals : pair ? pair.idxs : [];
    const pos = siblings.indexOf(idx) + 1;
    this.panelLive = h('p', { class: 'pv-hero-live' });
    const cli = showConfigCli(row, scopeId);
    const hidden = this.hiddenIn(row);

    const hero = h(
      'div',
      { class: 'pv-hero' },
      h('p', { class: 'pv-eyebrow' }, `${isGlobal ? 'Global policy' : 'Zone-pair policy'}${SEP}`, this.v(scopeTitle(this.snap, scopeId))),
      h(
        'div',
        { class: 'pv-where' },
        h('span', { class: 'pv-where-zones' }, this.zoneLinks(row.from, 'from'), h('span', { class: 'arrow' }, ARROW), this.zoneLinks(row.to, 'to')),
        h('span', { class: 'pv-where-pos' }, isGlobal ? `global policy ${pos} of ${siblings.length}` : `policy ${pos} of ${siblings.length} in this zone pair`),
        this.actionPill(row.action),
        row.inactive ? h('span', { class: 'pv-badge b-inactive', title: plain(inactiveSentence(row, this.scopeLabel())) }, inactiveText(row, this.scopeLabel())) : null,
        row.group ? h('span', { class: 'pv-badge b-group' }, 'group ', this.v(row.group)) : null,
        hidden.length ? h('span', { class: 'pv-badge b-warn', title: `Hidden characters, shown as badges: ${hidden.join(', ')}` }, 'hidden characters') : null,
      ),
      row.description ? h('p', { class: 'pv-desc-full' }, this.vd(row.description)) : null,
      this.panelLive,
      h(
        'div',
        { class: 'pv-hero-actions' },
        h('button', { class: 'btn sm', type: 'button', title: `Sessions with policy:${plain(row.name, { all: true })}`, on: { click: () => this.goSessions(row.name) } }, icon('sessions'), 'Sessions for this policy'),
        h('button', { class: 'btn sm', type: 'button', title: `Logs with policy:${plain(row.name, { all: true })}`, on: { click: () => this.goLogs(row.name) } }, icon('logs'), 'Logs for this policy'),
        cli !== null
          ? h('button', { class: 'btn sm ghost', type: 'button', title: 'Copy the show configuration command', on: { click: () => this.copyCli(cli) } }, icon('terminal'), 'Copy CLI')
          : null,
      ),
    );
    this.renderPanelLive(idx);
    return h(
      'div',
      { class: 'pv-detail' },
      hero,
      this.ruleCard(row),
      this.matchSection(row),
      this.commentsSection(row),
      this.resolvedAddrSection(row, 'source', 'Source addresses, resolved'),
      this.resolvedAddrSection(row, 'destination', 'Destination addresses, resolved'),
      this.resolvedAppSection(row, scopeId),
      this.thenSection(row),
      this.provenanceSection(row),
      this.unmodeledSection(row, scopeId),
      this.section('See it on the device', [
        cliBlock(this.ctx, cli, 'Copy command', showConfigNames(row, scopeId)),
        h('p', { class: 'pv-small faint' }, 'The configuration as committed, with this policy’s exact path. Add | display inheritance to see what comes from groups.'),
      ]),
      this.evaluationSection(row, idx, scopeId),
    );
  }

  /** Copies a command; the toast says how many hidden characters it holds, copied exactly. */
  copyCli(text) {
    const hidden = hiddenChars(text);
    const n = countControls(text);
    this.ctx.ui.copy(
      text,
      hidden.length
        ? `Command copied. The command contains ${n} hidden ${n === 1 ? 'character' : 'characters'} (shown as ${hidden.join(', ')}).`
        : 'Command copied. Paste it into the device CLI.',
    );
  }

  section(title, kids, cls) {
    const { h } = this;
    return h('section', { class: ['panel-section', 'pv-psec', cls] }, h('h3', null, title), kids);
  }

  zoneLinks(list, axis) {
    const { h } = this;
    const zs = zonesOf(list);
    if (!zs.length) return [h('span', { class: 'zone pv-zone-any', title: `any ${axis}-zone` }, 'any')];
    return zs.map((z) =>
      h(
        'button',
        { class: 'zone pv-zone-link', type: 'button', title: `Zone ${plain(z, { all: true })} in Objects`, on: { click: () => this.ctx.navigate('objects', { tab: 'zones', q: `name:${qvDevice(z)}`, sel: `zone|${z}` }) } },
        this.v(z),
      ),
    );
  }

  ruleCard(row) {
    const { h } = this;
    const mm = row.match || {};
    const res = row.resolved || {};
    const end = (side, label, zones, axis) => {
      const names = mm[side] || [];
      const resolved = res[side] || [];
      const excluded = mm[`${side}_excluded`];
      const items = names.slice(0, 6).map((n) => {
        const r = resolved.find((x) => x.name === n) || {};
        const leaves = r.leaves || [];
        const off = r.kind === 'unresolved' && (r.inactive_skipped || []).length;
        const value = r.kind === 'address' && leaves.length === 1 ? leaves[0].value : r.kind === 'set' ? `set of ${leaves.length}${r.truncated ? '+' : ''}` : off ? 'deactivated' : r.kind === 'unresolved' ? 'not found' : null;
        return h('li', null, h('span', { class: ['mono', n === 'any' && 'muted'] }, this.v(n)), value && value !== n ? h('span', { class: ['pv-rule-v', r.kind === 'unresolved' && (off ? 'amber' : 'bad')] }, this.v(value)) : null);
      });
      if (names.length > 6) items.push(h('li', { class: 'faint' }, `+${names.length - 6} more`));
      return h(
        'div',
        { class: ['pv-rule-end', side] },
        h('div', { class: 'pv-rule-head' }, h('span', { class: 'pv-rule-label' }, label), h('span', { class: 'pv-rule-zones' }, this.zoneList(zones, axis))),
        excluded ? h('span', { class: 'pv-tag bad' }, 'all except') : null,
        h('ul', { class: 'pv-rule-list' }, items),
      );
    };
    const apps = (mm.application || []).slice(0, 4);
    const action = ['permit', 'deny', 'reject'].includes(row.action) ? row.action : 'unknown';
    const extras = [];
    if (row.log && (row.log.init || row.log.close)) extras.push(`log ${[row.log.init && 'init', row.log.close && 'close'].filter(Boolean).join('+')}`);
    if (row.count) extras.push('count');
    if (row.tunnel) extras.push(`tunnel ${row.tunnel}`);
    if ((row.application_services || []).length) extras.push(row.application_services.join(', '));
    const label = `${(mm.source || []).join(', ') || 'any'} to ${(mm.destination || []).join(', ') || 'any'}, application ${(mm.application || []).join(', ') || 'any'}: ${row.action}`;
    return h(
      'div',
      { class: ['pv-rule', `is-${action}`, row.inactive && 'is-inactive'], role: 'img', 'aria-label': plain(label, { all: true }) },
      end('source', 'Source', row.from, 'from'),
      h(
        'div',
        { class: 'pv-rule-mid' },
        h(
          'div',
          { class: 'pv-rule-apps' },
          apps.map((a) => h('span', { class: 'mono' }, this.v(a))),
          mm.application_implicit ? h('span', { class: 'pv-tag sky', title: IMPLICIT_TITLE }, 'implicit') : null,
          (mm.application || []).length > 4 ? h('span', { class: 'faint' }, `+${mm.application.length - 4}`) : null,
        ),
        h('div', { class: 'pv-rule-line', 'aria-hidden': 'true' }, h('span', { class: 'pv-rule-actwrap' }, h('span', { class: ['pill', action === 'unknown' ? 'muted' : action, 'pv-rule-act'] }, row.action))),
        h('div', { class: 'pv-rule-extra' }, this.v(extras.join(SEP))),
      ),
      end('destination', 'Destination', row.to, 'to'),
    );
  }

  kv(pairs) {
    const { h } = this;
    const dl = h('dl', { class: 'kv pv-kv' });
    for (const [label, value] of pairs) {
      if (value === null || value === undefined) continue;
      dl.append(h('dt', null, label), h('dd', null, value));
    }
    return dl;
  }

  joinOrNone(list, none) {
    const { h } = this;
    return list && list.length ? h('span', { class: 'mono' }, this.v(list.join(', '))) : h('span', { class: 'muted' }, none || 'none');
  }

  matchSection(row) {
    const { h } = this;
    const mm = row.match || {};
    const side = (names, excluded) => (excluded ? h('span', null, h('span', { class: 'pv-tag bad' }, 'all except'), ' ', h('span', { class: 'mono' }, this.v(names.join(', ')))) : this.joinOrNone(names, 'any'));
    const apps = mm.application_implicit
      ? h('span', { title: IMPLICIT_TITLE }, h('span', { class: 'mono' }, this.v((mm.application || []).join(', '))), ' (implicit)')
      : this.joinOrNone(mm.application, 'any');
    return this.section('Match', [
      this.kv([
        ['Source', side(mm.source || [], mm.source_excluded)],
        ['Destination', side(mm.destination || [], mm.destination_excluded)],
        ['Application', apps],
        ['Source identity', (mm.source_identity || []).length ? this.joinOrNone(mm.source_identity) : null],
        ['Dynamic application', (mm.dynamic_application || []).length ? this.joinOrNone(mm.dynamic_application) : null],
        ['URL category', (mm.url_category || []).length ? this.joinOrNone(mm.url_category) : null],
        ['End-user profile', (mm.source_end_user_profile || []).length ? this.joinOrNone(mm.source_end_user_profile) : null],
      ]),
      mm.source_excluded || mm.destination_excluded
        ? h('p', { class: 'pv-small muted' }, 'An excluded address list (source-address-excluded or destination-address-excluded) matches every address except the ones listed.')
        : null,
    ]);
  }

  /**
   * Configuration comments (annotate) on this policy, inside it, and on its zone pair or the global
   * section (POL-UI-05): shown verbatim, delimiters included, line breaks kept.
   */
  commentsSection(row) {
    const { h } = this;
    const items = [];
    const item = (label, text) => items.push(h('li', null, h('span', { class: 'pv-cmt-where' }, label), h('span', { class: 'pv-cmt-text' }, this.vd(text))));
    if (row.comment) item('On this policy: ', row.comment);
    for (const c of row.part_comments || []) {
      if (!c || !c.text) continue;
      if (c.before) item(['Inside it, before ', h('span', { class: 'mono' }, this.v(c.before)), ': '], c.text);
      else item('Inside it, at the end: ', c.text);
    }
    if (row.pair_comment) {
      if (row.kind === 'global') item('On the global section: ', row.pair_comment);
      else item(['On the zone pair ', this.v(zonesOf(row.from)[0] || '?'), ` ${ARROW} `, this.v(zonesOf(row.to)[0] || '?'), ': '], row.pair_comment);
    }
    if (!items.length) return null;
    return this.section('Configuration comments', [h('ul', { class: 'pv-cmts' }, items), h('p', { class: 'pv-small muted' }, 'Written with annotate; not a setting.')]);
  }

  objLink(name, tab, sel, title) {
    return this.h('button', { class: 'pv-objlink', type: 'button', title: plain(title, { all: true }), on: { click: () => this.ctx.navigate('objects', { tab, q: `name:${qvDevice(name)}`, sel }) } }, this.v(name));
  }

  /** "Deactivated: h3 in address book global is written but inactive …" lines, linked to Objects. */
  skippedAddrLines(item) {
    const { h } = this;
    return (item.inactive_skipped || []).map((ref) => {
      const { book, name } = skippedRef(ref);
      return h(
        'p',
        { class: 'pv-skip' },
        'Deactivated: ',
        book ? this.objLink(name, 'address-books', `addr|${book}|${name}`, `Open ${name} in Objects`) : this.v(name),
        ' in address book ',
        this.v(book || '?'),
        ' is written but inactive, so this policy cannot use it (not in effect).',
      );
    });
  }

  resolvedAddrSection(row, side, title) {
    const { h } = this;
    const list = (row.resolved && row.resolved[side]) || [];
    const zones = side === 'source' ? row.from : row.to;
    const blocks = list.map((item) => {
      const leaves = item.leaves || [];
      const single = item.kind === 'address' && leaves.length === 1 && leaves[0].name === item.name;
      const skipped = item.inactive_skipped || [];
      const off = item.kind === 'unresolved' && skipped.length > 0;
      const head = [
        item.kind === 'address' || item.kind === 'set'
          ? this.objLink(item.name, 'address-books', `${item.kind === 'set' ? 'set' : 'addr'}|${item.book || ''}|${item.name}`, `Open ${item.name} in Objects`)
          : h('span', { class: 'pv-res-name' }, this.v(item.name)),
        h('span', { class: ['pv-tag', off ? 'amber' : item.kind === 'unresolved' && 'bad'] }, off ? 'deactivated' : ADDRESS_KINDS[item.kind] || item.kind),
        single ? h('span', { class: 'pv-res-val' }, h('span', { class: 'faint' }, `${leaves[0].kind || 'address'} `), h('span', { class: 'mono ip' }, this.v(leaves[0].value || ''))) : null,
        item.book ? h('span', { class: 'pv-res-book' }, 'from ', this.v(bookLabel(item.book))) : null,
      ];
      const body = [];
      if (item.kind === 'any') body.push(h('p', { class: 'pv-small muted' }, 'Matches every address.'));
      if (off) {
        body.push(...this.skippedAddrLines(item));
      } else if (item.kind === 'unresolved') {
        body.push(h('p', { class: 'pv-unres' }, `Not found: no address book visible ${row.kind === 'global' || !zonesOf(zones).length ? 'to this policy' : 'from zone '}`, row.kind === 'global' || !zonesOf(zones).length ? null : this.v(zonesOf(zones)[0]), ' defines ', this.v(item.name), '.'));
      }
      if (leaves.length && !single) {
        body.push(
          h(
            'table',
            { class: 'table pv-mini' },
            h('thead', null, h('tr', null, h('th', { scope: 'col' }, 'Address'), h('th', { scope: 'col' }, 'Kind'), h('th', { scope: 'col' }, 'Value'))),
            h('tbody', null, leaves.map((l) => h('tr', null, h('td', { class: 'mono' }, this.v(l.name)), h('td', { class: 'muted' }, l.kind || ''), h('td', { class: 'mono ip' }, this.v(l.value || ''))))),
          ),
        );
      }
      if (item.truncated) body.push(h('p', { class: 'pv-small muted' }, `The list stops at ${leaves.length} addresses; the set is larger.`));
      if (!off && skipped.length) {
        body.push(
          h(
            'p',
            { class: 'pv-skip' },
            'Members deactivated (not in effect): ',
            skipped.map((ref, i) => {
              const { book, name } = skippedRef(ref);
              return [i ? ', ' : null, book ? this.objLink(name, 'address-books', `addr|${book}|${name}`, `Open ${name} in Objects`) : this.v(name)];
            }),
          ),
        );
      }
      const unres = (item.unresolved || []).filter((n) => n !== item.name || item.kind !== 'unresolved');
      if (unres.length) body.push(h('p', { class: 'pv-unres' }, 'Members not found: ', this.v(unres.join(', '))));
      return h('div', { class: ['pv-res', item.kind === 'unresolved' && (off ? 'is-off' : 'is-bad')] }, h('div', { class: 'pv-res-head' }, head), body);
    });
    return this.section(title, blocks.length ? blocks : h('p', { class: 'pv-small muted' }, 'No addresses in the match.'));
  }

  resolvedAppSection(row, scopeId) {
    const { h } = this;
    const list = (row.resolved && row.resolved.application) || [];
    const prefix = cliPrefix(scopeId);
    const appLink = (name) => this.objLink(name, 'applications', `app|${name}`, `Open ${name} in Objects`);
    const blocks = list.map((item) => {
      const body = [];
      const skipped = item.inactive_skipped || [];
      const off = item.kind === 'unresolved' && skipped.length > 0;
      if (item.kind === 'any') body.push(h('p', { class: 'pv-small muted' }, 'Matches every application.'));
      if (off) {
        for (const n of skipped) body.push(h('p', { class: 'pv-skip' }, 'Deactivated: application ', appLink(n), ' is inactive (not in effect).'));
      } else if (item.kind === 'unresolved') {
        body.push(h('p', { class: 'pv-unres' }, 'Not found: no application or application set named ', this.v(item.name), ' is defined.'));
      }
      if (item.kind === 'predefined') body.push(this.predefinedLine(item.name));
      if (item.kind === 'dynamic-defaults') body.push(h('p', { class: 'pv-small muted' }, 'Unified policy: each dynamic application’s own default ports and protocols. The port filter keeps this policy and marks it “port ?”.'));
      const leaves = item.leaves || [];
      if (leaves.length && item.kind !== 'predefined') {
        body.push(
          h(
            'table',
            { class: 'table pv-mini' },
            h('thead', null, h('tr', null, ['Application', 'Protocol', 'Destination port', 'Source port'].map((t) => h('th', { scope: 'col' }, t)))),
            h(
              'tbody',
              null,
              leaves.map((l) =>
                l.predefined
                  ? this.predefinedRow(l.name)
                  : h(
                      'tr',
                      null,
                      h(
                        'td',
                        { class: 'mono' },
                        this.v(l.name),
                        (l.unmodeled || []).length
                          ? [' ', h('span', { class: 'pv-tag amber', title: 'J-Wicket does not display these application settings yet.' }, 'settings not shown: ', this.v(l.unmodeled.join(', ')))]
                          : null,
                      ),
                      h('td', { class: 'mono' }, l.protocol ? this.v(l.protocol) : l.terms ? `${l.terms} terms (not expanded)` : '—'),
                      h('td', { class: 'mono' }, l.destination_port ? this.v(l.destination_port) : '—'),
                      h('td', { class: 'mono' }, l.source_port ? this.v(l.source_port) : '—'),
                    ),
              ),
            ),
          ),
        );
        // CRT-06: where an application has settings J-Wicket does not display (an ALG, a timeout), the
        // command to read them on the device. J-Wicket does not interpret what they do.
        for (const l of leaves.filter((x) => !x.predefined && (x.unmodeled || []).length)) {
          body.push(cliBlock(this.ctx, cliJoin('show configuration', prefix === null ? null : `${prefix}applications application`, cliWord(l.name)), 'Copy command', cliNames(scopeId, l.name)));
        }
      }
      if (!off && skipped.length) body.push(h('p', { class: 'pv-skip' }, 'Members deactivated (not in effect): ', skipped.map((n, i) => [i ? ', ' : null, appLink(n)])));
      const unres = (item.unresolved || []).filter((n) => n !== item.name || item.kind !== 'unresolved');
      if (unres.length) body.push(h('p', { class: 'pv-unres' }, 'Members not found: ', this.v(unres.join(', '))));
      const nameEl = item.kind === 'application' || item.kind === 'set' ? appLink(item.name) : h('span', { class: 'pv-res-name' }, this.v(item.name));
      return h(
        'div',
        { class: ['pv-res', item.kind === 'unresolved' && (off ? 'is-off' : 'is-bad')] },
        h('div', { class: 'pv-res-head' }, nameEl, h('span', { class: ['pv-tag', off ? 'amber' : item.kind === 'unresolved' && 'bad'] }, off ? 'deactivated' : APP_KINDS[item.kind] || item.kind)),
        body,
      );
    });
    const mm = row.match || {};
    const intro = mm.application_implicit ? h('p', { class: 'pv-small pv-implicit' }, h('span', { class: 'pv-tag sky' }, 'implicit'), ' ', IMPLICIT_TITLE) : null;
    return this.section('Applications, resolved', [intro, blocks.length ? blocks : h('p', { class: 'pv-small muted' }, 'No applications in the match.')]);
  }

  /** A predefined application: its factory port when J-Wicket knows it, else say the port is not read. */
  predefinedLine(name) {
    const { h } = this;
    const known = this.Q && this.Q.PREDEFINED_APPS ? this.Q.PREDEFINED_APPS[name] : null;
    if (known) {
      return h('p', { class: 'pv-small' }, h('span', { class: 'mono' }, `${known.protocol}/${known.port}`), h('span', { class: 'muted' }, ' — the junos-defaults definition as J-Wicket knows it (the inventory does not read junos-defaults).'));
    }
    return h(
      'div',
      { class: 'pv-small' },
      h('p', { class: 'muted' }, 'Port not read: J-Wicket does not expand junos-defaults, so the port filter keeps this policy and marks it “port ?”. To see the definition:'),
      cliBlock(this.ctx, cliJoin('show configuration groups junos-defaults applications application', cliWord(name)), 'Copy command', [name]),
    );
  }

  predefinedRow(name) {
    const { h } = this;
    const known = this.Q && this.Q.PREDEFINED_APPS ? this.Q.PREDEFINED_APPS[name] : null;
    if (known) {
      // The fourth column is the source port; the provenance note belongs with the name.
      return h(
        'tr',
        null,
        h('td', { class: 'mono' }, this.v(name), h('span', { class: 'faint', title: 'junos-defaults, as J-Wicket knows it' }, ' predefined')),
        h('td', { class: 'mono' }, known.protocol),
        h('td', { class: 'mono' }, known.port),
        h('td', { class: 'faint' }, '—'),
      );
    }
    return h('tr', null, h('td', { class: 'mono' }, this.v(name)), h('td', { colspan: '3', class: 'muted' }, 'predefined (junos-defaults); port not read by J-Wicket'));
  }

  thenSection(row) {
    const { h } = this;
    const log = [row.log && row.log.init ? 'session-init' : null, row.log && row.log.close ? 'session-close' : null].filter(Boolean);
    return this.section('Then', [
      this.kv([
        ['Action', this.actionPill(row.action)],
        ['Log', this.joinOrNone(log, 'no logging')],
        ['Count', row.count ? 'yes' : h('span', { class: 'muted' }, 'no')],
        ['Application services', this.joinOrNone(row.application_services, 'none')],
        ['Tunnel', row.tunnel ? h('span', { class: 'mono' }, 'ipsec-vpn ', this.v(row.tunnel)) : h('span', { class: 'muted' }, 'none')],
        ['Scheduler', row.scheduler ? h('span', { class: 'mono' }, this.v(row.scheduler)) : h('span', { class: 'muted' }, 'none: always in effect while active')],
      ]),
      row.action === 'unknown' ? h('p', { class: 'pv-unres' }, 'No permit, deny or reject action that J-Wicket recognises. Check the policy on the device.') : null,
    ]);
  }

  provenanceSection(row) {
    const { h } = this;
    // Never "Active." for a row marked inactive (POL-UI-01).
    const state = row.inactive ? inactiveSentence(row, this.scopeLabel()) : 'Active.';
    const others = (row.groups || []).filter((g) => g !== row.group);
    const parts = row.inactive_parts || [];
    return this.section('Where it comes from', [
      this.kv([
        ['Configured', row.group ? h('span', null, 'From configuration group ', h('b', { class: 'mono pv-gold' }, this.v(row.group))) : 'Directly in the configuration (no group).'],
        ['Inherited parts', (row.inherited || []).length ? h('span', null, 'Partly inherited from another group: ', h('span', { class: 'mono' }, this.v(row.inherited.join(', ')))) : h('span', { class: 'muted' }, 'none')],
        ['Groups in this policy', (row.groups || []).length ? h('span', { class: 'mono' }, this.v(row.groups.join(', '))) : h('span', { class: 'muted' }, 'none')],
        ['State', h('span', { class: row.inactive ? 'act-reject' : 'act-permit' }, this.v(state))],
      ]),
      parts.length
        ? h(
            'div',
            { class: 'pv-callout reject' },
            h('p', null, h('b', null, 'Deactivated parts, not in effect. '), row.inactive ? 'The policy itself is also inactive.' : 'The policy is active, but Junos ignores these parts of it:'),
            h('ul', { class: 'pv-bullets' }, parts.map((p) => h('li', { class: 'mono' }, this.v(p)))),
            h('p', { class: 'pv-small muted' }, 'The match and action above already leave them out.'),
          )
        : null,
      others.length && row.group ? h('p', { class: 'pv-small muted' }, 'Other groups also contribute settings: ', this.v(others.join(', ')), '.') : null,
      row.group || (row.groups || []).length
        ? h('p', { class: 'pv-small muted' }, 'A change made directly to an object that comes from a group may be overridden by the group, or may override it. J-Wicket shows where each part comes from so that you can decide where a change belongs.')
        : null,
    ]);
  }

  unmodeledSection(row, scopeId) {
    const { h } = this;
    const unmodeled = row.unmodeled || [];
    if (!unmodeled.length) return null;
    return this.section(
      'Settings J-Wicket does not show',
      h(
        'div',
        { class: 'pv-callout amber' },
        h('p', null, 'This policy has settings J-Wicket does not display yet. Check them on the device:'),
        h('ul', { class: 'pv-bullets' }, unmodeled.map((u) => h('li', { class: 'mono' }, this.v(u)))),
        cliBlock(this.ctx, showConfigCli(row, scopeId), 'Copy command', showConfigNames(row, scopeId)),
      ),
    );
  }

  /**
   * The evaluation order for one zone pair, as nodes. `current` marks a policy. Rows with a dynamic
   * application are marked "unified", and a note says that until the application is identified Junos
   * may match a list of candidate policies (verified); listing them in configuration order is J-Wicket's
   * reading of the order Junos considers them (inferred, POL-UI-09). The note decides no match.
   */
  orderNodes(from, to, current) {
    const { h } = this;
    const m = this.model;
    const fmt = this.fmt;
    const pol = m.pol;
    const kids = [];
    let n = 1;
    const isUnified = (r) => ((r.match && r.match.dynamic_application) || []).length > 0;
    const item = (idx) => {
      const r = m.rows[idx];
      const here = idx === current;
      return h(
        'li',
        { class: ['pv-ord', r.inactive && 'skipped', here && 'this'] },
        h('span', { class: 'pv-ord-n', 'aria-hidden': 'true' }, String(n++)),
        h('button', { class: 'pv-ord-name', type: 'button', title: `Open ${plain(r.name, { all: true })}`, on: { click: () => this.openDetail(idx, { push: false }) } }, this.v(r.name)),
        this.actionPill(r.action),
        isUnified(r) ? h('span', { class: 'pv-tag sky', title: `Unified policy: dynamic-application ${plain(r.match.dynamic_application.join(', '))}` }, 'unified') : null,
        r.kind === 'global' ? h('span', { class: 'pv-ord-z' }, this.zoneList(r.from, 'from'), h('span', { class: 'arrow' }, ARROW), this.zoneList(r.to, 'to')) : null,
        r.inactive ? h('span', { class: 'pv-ord-why', title: plain(inactiveSentence(r, this.scopeLabel())) }, 'skipped: inactive') : null,
        here ? h('span', { class: 'pv-ord-here' }, '← this policy') : null,
      );
    };
    const group = (label, idxs, empty) => {
      kids.push(h('p', { class: 'pv-ord-label' }, label));
      if (idxs.length) kids.push(h('ol', { class: 'pv-order' }, idxs.map(item)));
      else kids.push(h('p', { class: 'pv-ord-empty' }, empty));
    };
    const pair = m.pairs.get(pairKey(from, to));
    group(['Zone-pair policies for ', this.v(from), ` ${ARROW} `, this.v(to), ', top to bottom'], pair ? pair.idxs : [], 'No zone-pair policy for this pair.');
    const applying = m.globals.filter((i) => globalApplies(m.rows[i], from, to));
    group(['Then the global policies that apply to ', this.v(from), ` ${ARROW} `, this.v(to)], applying, 'No global policy applies to this pair.');
    const ds = defaultState(pol, this.scopeLabel());
    kids.push(
      h('p', { class: 'pv-ord-label' }, 'Then the default policy'),
      h(
        'ol',
        { class: 'pv-order' },
        h(
          'li',
          { class: ['pv-ord', 'is-default', current === 'default' && 'this'] },
          h('span', { class: 'pv-ord-n', 'aria-hidden': 'true' }, String(n)),
          h('span', { class: 'pv-ord-name static' }, 'default-policy'),
          h('span', { class: ['pill', ds.cls] }, ds.action),
          ds.badge ? h('span', { class: 'pv-tag amber', title: ds.tip }, ds.badge) : null,
          h('span', { class: 'pv-ord-why', title: ds.tip }, this.v(ds.label)),
        ),
      ),
    );
    const unified = [...(pair ? pair.idxs : []), ...applying].some((i) => isUnified(m.rows[i]));
    if (unified) {
      // JUNOS-01 (a deviation from the POL-UI-09 wording): the pre-ID default policy sets only the
      // session timeout and logging before AppID identifies the application; it does not permit or
      // deny (HPE unified policies page; 24.4R2 YANG: then { log, session-timeout }).
      const pre = preIdState(pol);
      let preText;
      if (pol.pre_id_default_policy) {
        preText = `Until then, the pre-ID default policy (${pre}) sets only the session timeout and session logging; it does not permit or deny (verified).`;
      } else if (pol.pre_id_default_policy_inactive) {
        preText = `Until then, a pre-ID default policy would set only the session timeout and session logging, not permit or deny (verified); this one is ${pre}, so J-Wicket reads that the default session timeouts apply and no pre-ID logs are written (inferred).`;
      } else {
        preText = 'Until then, no pre-ID default policy is configured: default session timeouts apply and no pre-ID logs are written (verified).';
      }
      kids.push(
        h(
          'p',
          { class: 'pv-callout sky pv-unified' },
          `This pair has unified policies (dynamic application). Until the application is identified, Junos may match a list of candidate policies, not one (verified); J-Wicket lists them in configuration order, which it reads as the order Junos considers them (inferred). ${preText}`,
        ),
      );
    }
    kids.unshift(
      h(
        'p',
        { class: 'pv-ord-sum' },
        `${fmt.plural((pair ? pair.idxs.length : 0) + applying.length + 1, 'step')} for a flow from `,
        this.v(from),
        ' to ',
        this.v(to),
        '. The first policy whose match fits the flow decides; inactive ones are skipped.',
      ),
    );
    return kids;
  }

  /** What this policy names for each <placeholder> of the match-policies example. */
  exampleCandidates(ex) {
    const { h } = this;
    const c = ex.candidates;
    const rows = [];
    const hostList = (sd) => {
      if (sd.any) return h('span', { class: 'muted' }, 'any address');
      const shown = sd.leaves.slice(0, 4).map((l, i) => [i ? ', ' : null, h('span', { class: 'mono' }, this.v(l.value || l.name)), l.via && l.via !== l.value ? h('span', { class: 'faint' }, ' (', this.v(l.via), ')') : null]);
      return [shown, sd.leaves.length > 4 ? h('span', { class: 'faint' }, `, +${sd.leaves.length - 4} more`) : null, sd.partial ? h('span', { class: 'faint' }, ' (list incomplete)') : null];
    };
    const within = (sd) => (sd.any ? hostList(sd) : [h('span', { class: 'muted' }, sd.leaves.length === 1 ? 'an address in ' : 'an address in one of '), hostList(sd)]);
    if (!ex.src) rows.push(['source-ip', within(c.src)]);
    if (!ex.dst) rows.push(['destination-ip', within(c.dst)]);
    if (!ex.port) {
      const list = c.ports.slice(0, 6).map((p, i) => [i ? ', ' : null, h('span', { class: 'mono' }, this.v(`${p.port}${p.protocol ? `/${p.protocol}` : ''}`)), h('span', { class: 'faint' }, ' (', this.v(p.name), ')')]);
      const extra = [];
      if (c.ports.length > 6) extra.push(h('span', { class: 'faint' }, `, +${c.ports.length - 6} more`));
      if (c.anyPort) extra.push(h('span', { class: 'muted' }, `${c.ports.length ? '; ' : ''}any port (application any)`));
      if (c.unknownPorts.length) extra.push(h('span', { class: 'muted' }, `${c.ports.length || c.anyPort ? '; ' : ''}port not read by J-Wicket: `, this.v(c.unknownPorts.map((u) => u.name).join(', '))));
      rows.push(['destination-port', [list, extra]]);
      const protos = [...new Set(c.ports.map((p) => p.protocol).filter(Boolean))];
      if (protos.length) rows.push(['protocol', [h('span', { class: 'mono' }, this.v(protos.join(', '))), c.anyPort || c.unknownPorts.length ? h('span', { class: 'faint' }, ' (and what the other applications use)') : null]]);
    }
    if (!rows.length) return null;
    return h(
      'dl',
      { class: 'pv-cands', 'aria-label': 'What this policy names for each placeholder' },
      rows.map(([k, v]) => [h('dt', { class: 'mono' }, `<${k}>`), h('dd', null, v)]),
    );
  }

  evaluationSection(row, idx, scopeId) {
    const { h } = this;
    const m = this.model;
    let from = null;
    let to = null;
    if (row.kind === 'zone') {
      from = zonesOf(row.from)[0];
      to = zonesOf(row.to)[0];
    } else {
      from = zonesOf(row.from).length === 1 ? row.from[0] : null;
      to = zonesOf(row.to).length === 1 ? row.to[0] : null;
    }
    const kids = [];
    // POL-UI-01: a row out of effect because an ancestor is deactivated says so first.
    if (row.inactive && ANCESTOR_REASONS.includes(row.inactive_reason)) {
      kids.push(h('p', { class: 'pv-callout reject pv-eval-off' }, this.v(ancestorSentence(row.inactive_reason, this.scopeLabel()))));
    }
    if (from && to) {
      kids.push(...this.orderNodes(from, to, idx));
    } else {
      const zl = (list) => (zonesOf(list).length ? list.join(', ') : 'any');
      kids.push(
        h(
          'p',
          { class: 'pv-small' },
          'This global policy applies to every zone pair whose from-zone is in (',
          this.v(zl(row.from)),
          ') and whose to-zone is in (',
          this.v(zl(row.to)),
          '); “any” means every zone. For each such pair, Junos checks that pair’s zone-pair policies first, then the global policies in this order, then the default policy.',
        ),
        h('p', { class: 'pv-ord-label' }, 'Global policies, in order'),
      );
      let n = 1;
      kids.push(
        h(
          'ol',
          { class: 'pv-order' },
          m.globals.map((i) => {
            const r = m.rows[i];
            return h(
              'li',
              { class: ['pv-ord', r.inactive && 'skipped', i === idx && 'this'] },
              h('span', { class: 'pv-ord-n', 'aria-hidden': 'true' }, String(n++)),
              h('button', { class: 'pv-ord-name', type: 'button', on: { click: () => this.openDetail(i, { push: false }) } }, this.v(r.name)),
              this.actionPill(r.action),
              ((r.match && r.match.dynamic_application) || []).length ? h('span', { class: 'pv-tag sky' }, 'unified') : null,
              h('span', { class: 'pv-ord-z' }, this.zoneList(r.from, 'from'), h('span', { class: 'arrow' }, ARROW), this.zoneList(r.to, 'to')),
              r.inactive ? h('span', { class: 'pv-ord-why' }, 'skipped: inactive') : null,
              i === idx ? h('span', { class: 'pv-ord-here' }, '← this policy') : null,
            );
          }),
        ),
        h('button', { class: 'btn sm', type: 'button', on: { click: () => this.openExplainer(null, null) } }, this.ctx.dom.icon('help'), 'Pick a zone pair to see its full order'),
      );
    }
    const ex = flowExample(row, this.Q);
    kids.push(
      h('p', { class: 'pv-small' }, 'This shows order, not a match result. To test a flow, run on the device:'),
      cliBlock(this.ctx, matchPoliciesCli(scopeId, from, to, ex), 'Copy command', cliNames(scopeId, from, to)),
      this.exampleCandidates(ex),
      h(
        'p',
        { class: 'pv-small muted' },
        'Values are filled in only where this policy names exactly one host, or exactly one port and protocol. ',
        ex.sportNamed ? `Source port ${ex.sport} is the one its application names. ` : `Source port ${ex.sport} is an example client port (Junos needs one). `,
        'Replace each <placeholder> with the flow you want to test.',
      ),
    );
    const sp = scopeParts(scopeId);
    if (sp.kind !== 'root') {
      kids.push(h('p', { class: 'pv-small muted' }, `The ${sp.kind === 'lsys' ? 'logical-system' : 'tenant'} option name can differ between releases; check it with “show security match-policies ?”.`));
    }
    return this.section(from && to ? 'Evaluation order for this zone pair' : 'Evaluation order', kids, 'pv-eval-sec');
  }

  // ---- explainer: how Junos picks a policy -----------------------------------------------------

  openExplainer(from, to, { refresh = false, focusDefault = false } = {}) {
    const m = this.model;
    if (!m) return;
    const { h } = this;
    const { icon } = this.ctx.dom;
    const prev = this.explainState || {};
    const st = refresh ? { ...prev } : { from: from || prev.from || null, to: to || prev.to || null, src: prev.src || '', dst: prev.dst || '', sport: prev.sport || '', port: prev.port || '', proto: prev.proto || '' };
    if (!refresh && from) st.from = from;
    if (!refresh && to) st.to = to;
    if (!st.from && !st.to && m.pairs.size && !focusDefault) {
      const first = m.pairs.values().next().value;
      st.from = first.from;
      st.to = first.to;
    }
    this.explainState = st;
    const scopeId = this.ctx.store.scope;
    // A select drawn like the inputs: native chevron hidden, an inline SVG one on the right.
    const selectWrap = (sel) => h('span', { class: 'pv-ex-selwrap' }, sel, h('span', { class: 'pv-ex-chev', 'aria-hidden': 'true' }, icon('chevron-down')));
    const zoneSelect = (key, label) => {
      const sel = h('select', { class: 'input pv-ex-select', id: `pv-ex-${key}`, on: { change: () => { st[key] = sel.value || null; draw(); } } }, h('option', { value: '' }, 'choose a zone'), m.zones.map((z) => h('option', { value: z }, plain(z, { all: true }))));
      sel.value = st[key] || '';
      return h('div', { class: ['field', 'pv-ex-field', `pv-ex-f-${key}`] }, h('label', { for: `pv-ex-${key}` }, label), selectWrap(sel));
    };
    const textField = (key, label, placeholder, check) => {
      const err = h('span', { class: 'pv-ex-err', hidden: true });
      const input = h('input', {
        class: 'input pv-ex-input',
        id: `pv-ex-${key}`,
        type: 'text',
        inputmode: /port$/.test(key) ? 'numeric' : null,
        autocomplete: 'off',
        spellcheck: 'false',
        placeholder,
        value: st[key] || '',
        on: {
          input: () => {
            st[key] = input.value.trim();
            const bad = st[key] && !check(st[key]);
            err.hidden = !bad;
            err.textContent = bad ? (/port$/.test(key) ? 'a port from 1 to 65535' : 'one IPv4 or IPv6 address') : '';
            input.setAttribute('aria-invalid', bad ? 'true' : 'false');
            draw();
          },
        },
      });
      return h('div', { class: ['field', 'pv-ex-field', `pv-ex-f-${key}`] }, h('label', { for: `pv-ex-${key}` }, label), input, err);
    };
    const isPort = (s) => /^\d{1,5}$/.test(s) && Number(s) >= 1 && Number(s) <= 65535;
    const protoSel = h(
      'select',
      { class: 'input pv-ex-select', id: 'pv-ex-proto', on: { change: () => { st.proto = protoSel.value; draw(); } } },
      h('option', { value: '' }, 'choose'),
      ['tcp', 'udp', 'icmp', 'icmp6', 'gre', 'esp'].map((p) => h('option', { value: p }, p)),
    );
    protoSel.value = st.proto || '';
    const form = h(
      'div',
      { class: 'pv-ex-form' },
      zoneSelect('from', 'From zone'),
      textField('src', 'Source IP', 'e.g. 10.10.3.4', (s) => isIp(this.Q, s)),
      textField('sport', 'Source port', `e.g. ${EXAMPLE_SOURCE_PORT}`, isPort),
      h('div', { class: 'field pv-ex-field pv-ex-f-proto' }, h('label', { for: 'pv-ex-proto' }, 'Protocol'), selectWrap(protoSel)),
      zoneSelect('to', 'To zone'),
      textField('dst', 'Destination IP', 'e.g. 198.51.100.20', (s) => isIp(this.Q, s)),
      textField('port', 'Destination port', 'e.g. 443', isPort),
    );
    const out = h('div', { class: 'pv-ex-out' });
    const draw = () => {
      if (this.dead || !this.model) return;
      const ex = {
        src: isIp(this.Q, st.src) ? st.src : null,
        dst: isIp(this.Q, st.dst) ? st.dst : null,
        port: isPort(st.port || '') ? st.port : null,
        sport: isPort(st.sport || '') ? st.sport : null,
        proto: st.proto || null,
      };
      const kids = [];
      if (st.from && st.to) {
        kids.push(h('div', { class: 'pv-ex-order' }, this.orderNodes(st.from, st.to, focusDefault ? 'default' : -1)));
      } else {
        kids.push(h('p', { class: 'pv-small muted' }, 'Pick a from-zone and a to-zone to see the order Junos checks for that pair.'));
      }
      kids.push(
        h('h4', { class: 'pv-ex-h' }, 'Test the flow on the device'),
        cliBlock(this.ctx, matchPoliciesCli(scopeId, st.from, st.to, ex), 'Copy command', cliNames(scopeId, st.from, st.to)),
        h('p', { class: 'pv-small muted' }, `Junos answers with the policy that matches. Fill in the fields above, or replace each <placeholder> in the command. ${ex.sport ? '' : `An empty source port uses ${EXAMPLE_SOURCE_PORT}, an example client port.`}`),
      );
      const terms = [];
      if (st.from) terms.push(`from:${qvDevice(st.from)}`);
      if (st.to) terms.push(`to:${qvDevice(st.to)}`);
      if (ex.src) terms.push(`src:${ex.src}`);
      if (ex.dst) terms.push(`dst:${ex.dst}`);
      if (terms.length) {
        const q = terms.join(' ');
        kids.push(
          h(
            'div',
            { class: 'pv-ex-filter' },
            h('p', { class: 'pv-small' }, 'Narrow the table to the policies that name these zones and addresses (“any” counts; applications are not checked). This is a filter, not a match result.'),
            h('button', { class: 'btn sm', type: 'button', on: { click: () => this.setQuery(q) } }, icon('filter'), h('span', { class: 'mono' }, this.v(q))),
          ),
        );
      }
      if (focusDefault || !st.from) {
        const ds = defaultState(m.pol, this.scopeLabel());
        const prefix = cliPrefix(scopeId);
        kids.push(
          h('h4', { class: 'pv-ex-h' }, 'The default policy'),
          h(
            'p',
            { class: 'pv-small' },
            h('span', { class: ['pill', ds.cls] }, ds.action),
            ds.badge ? [' ', h('span', { class: 'pv-tag amber', title: ds.tip }, ds.badge)] : null,
            ' ',
            this.v(ds.label),
            '. It decides every flow that no zone-pair or global policy matches.',
          ),
          ds.badge ? h('p', { class: 'pv-small muted' }, ds.tip) : null,
          m.pol.default_policy_comment ? h('p', { class: 'pv-small pv-comment-full' }, 'Comment (annotate; not a setting): ', this.vd(m.pol.default_policy_comment)) : null,
          cliBlock(this.ctx, cliJoin('show configuration', prefix === null ? null : `${prefix}security policies default-policy`), 'Copy command', cliNames(scopeId)),
        );
      }
      const sp = scopeParts(scopeId);
      if (sp.kind !== 'root') {
        kids.push(h('p', { class: 'pv-small muted' }, `The ${sp.kind === 'lsys' ? 'logical-system' : 'tenant'} option name can differ between releases; check it with “show security match-policies ?”.`));
      }
      this.ctx.dom.put(out, ...kids);
    };
    draw();
    const intro = h(
      'div',
      { class: 'pv-ex-intro' },
      h(
        'ol',
        { class: 'pv-ex-steps' },
        h('li', null, h('span', null, h('b', null, 'Zone-pair policies'), ' of the flow’s from-zone to to-zone, top to bottom.')),
        h('li', null, h('span', null, h('b', null, 'Global policies'), ' that apply to the pair, in order.')),
        h('li', null, h('span', null, h('b', null, 'The default policy.'))),
      ),
      h('p', { class: 'pv-small muted' }, 'The first policy whose match fits the flow decides. Inactive policies are skipped. J-Wicket shows this order; it does not decide which policy a flow matches. The device does, with the command below.'),
    );
    const token = ++this.panelToken;
    const wasPolicy = this.panelKind === 'policy';
    this.panelKind = 'explain';
    this.panelIdx = -1;
    this.panelLive = null;
    if (wasPolicy && this.sel) {
      this.sel = null;
      this.saveRoute(false);
    }
    const opened = this.ctx.ui.panel({
      title: 'How Junos picks a policy',
      content: h('div', { class: 'pv-detail pv-explainer' }, intro, this.section('The flow', form), this.section('Evaluation order', out, 'pv-eval-sec')),
      wide: true,
      onClose: () => this.onPanelClosed(token),
    });
    if (!refresh && opened && opened.el) opened.el.scrollTop = 0;
    this.markSelected();
  }
}
