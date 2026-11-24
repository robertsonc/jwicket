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

const ICON = 'M12 3l7.5 3v5.2c0 4.4-3.1 8.2-7.5 9.8-4.4-1.6-7.5-5.4-7.5-9.8V6z M8.8 11.8l2.3 2.3 4.3-4.4';
const SEP = ' \u00b7 ';
const ARROW = '\u2192';
const LIST_LIMIT = 4;
const AGE_TICK_MS = 30000;
const SUMMARY_PREF = 'jwicket.policies.summary'; // UI preference only (never device data)

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

/** Quote a CLI word only when Junos would need it. */
export function cliWord(word) {
  const text = String(word);
  return /^[A-Za-z0-9._:/-]+$/.test(text) ? text : `"${text.replace(/["\\]/g, '\\$&')}"`;
}

/** "logical-systems LS-A " / "tenants T-1 " / "" for show configuration. */
export function cliPrefix(scopeId) {
  const sp = scopeParts(scopeId);
  if (sp.kind === 'lsys') return `logical-systems ${cliWord(sp.name)} `;
  if (sp.kind === 'tenant') return `tenants ${cliWord(sp.name)} `;
  return '';
}

/** A copyable CLI block; <placeholders> are marked so the operator sees what to replace. */
export function cliBlock(ctx, text, label = 'Copy command') {
  const { h, icon } = ctx.dom;
  const code = h('code', { class: 'pv-cli-code' });
  String(text)
    .split(' ')
    .forEach((word, i) => {
      if (i) code.append(' ');
      code.append(h('span', { class: /^<[^>]+>$/.test(word) ? 'pv-ph' : null }, word));
    });
  const btn = h(
    'button',
    {
      class: 'btn sm ghost icon',
      type: 'button',
      title: 'Copy',
      'aria-label': `${label}: ${text}`,
      on: { click: () => ctx.ui.copy(text, 'Command copied. Paste it into the device CLI.') },
    },
    icon('copy'),
  );
  return h('div', { class: 'cli pv-cli' }, h('span', { class: 'pv-prompt', 'aria-hidden': 'true' }, '>'), code, btn);
}

/** Text with case-insensitive occurrences of `terms` wrapped in <mark>. */
export function markNodes(h, text, terms) {
  const s = String(text === null || text === undefined ? '' : text);
  if (!terms || !terms.length || !s) return [s];
  const low = s.toLowerCase();
  const hits = [];
  for (const t of terms) {
    const tl = String(t).toLowerCase();
    if (tl.length < 2) continue;
    let i = low.indexOf(tl);
    while (i >= 0 && hits.length < 64) {
      hits.push([i, i + tl.length]);
      i = low.indexOf(tl, i + tl.length);
    }
  }
  if (!hits.length) return [s];
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
    if (a > pos) out.push(s.slice(pos, a));
    out.push(h('mark', { class: 'pv-hit' }, s.slice(a, b)));
    pos = b;
  }
  if (pos < s.length) out.push(s.slice(pos));
  return out;
}

/** A provenance badge row: configuration group, inherited parts, inactive. */
export function provBadges(h, obj, { direct = true } = {}) {
  const out = [];
  if (obj.group) out.push(h('span', { class: 'pv-badge b-group', title: `Comes from configuration group ${obj.group}` }, `group ${obj.group}`));
  if ((obj.inherited || []).length) {
    out.push(h('span', { class: 'pv-badge b-inherit', title: `Partly inherited: ${obj.inherited.join(', ')}` }, `inherits ${obj.inherited.join(', ')}`));
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
  };
  if (table.status !== 'ok') return out;
  for (const r of table.rows || []) {
    if (haRole(r) === 'backup') {
      out.backups += 1;
      continue;
    }
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

/** Explicit state for the snapshot as a whole (no data, config not readable, no scope), or null. */
export function inventoryState(ctx, snap, what, retry) {
  const { h, stateCard } = ctx.dom;
  const again = retry ? [h('button', { class: 'btn sm', type: 'button', on: { click: retry } }, 'Read again')] : null;
  if (!snap) {
    const err = ctx.store.inventoryError;
    if (err) {
      return stateCard({
        status: err.status === 0 ? 'offline' : err.status === 404 ? 'unsupported' : 'failed',
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
          ? `The ${what} come from the configuration, which your Junos login class may not read. J-Wicket shows only what your login class allows; ask your Junos administrator if you need this view.`
          : undefined,
      actions: cfg.status === 'failed' ? again : null,
    });
  }
  if (!snap.scope) {
    return stateCard({ status: 'failed', message: 'No inventory came back for this scope.', actions: again });
  }
  return null;
}

/** "branch-fw-01 · Root system · committed configuration, inheritance expanded · read 09:27 UTC · as admin" */
export function subLine(ctx, snap, receivedAt) {
  const { h } = ctx.dom;
  const fmt = ctx.format;
  if (!snap) return ['Reading the configuration\u2026'];
  const meta = snap.meta || {};
  const dev = snap.device && snap.device.status === 'ok' ? snap.device : null;
  const src = meta.source || {};
  const ra = meta.read_as || {};
  const scope = scopeTitle(snap, meta.scope || ctx.store.scope);
  const out = [];
  const push = (...kids) => {
    if (out.length) out.push(h('span', { class: 'pv-dot', 'aria-hidden': 'true' }, SEP));
    out.push(...kids);
  };
  if (dev && dev.hostname) push(h('span', { class: 'mono' }, dev.hostname));
  push(h('span', null, scope), snap.scope && snap.scope.inactive ? h('span', { class: 'pill reject pv-sub-pill' }, 'deactivated') : null);
  push(h('span', { title: `${src.database || 'committed'} configuration database; ${src.inheritance ? 'group inheritance expanded' : 'group inheritance not expanded'}` }, `${src.database === 'committed' || !src.database ? 'committed' : src.database} config, ${src.inheritance ? 'inheritance expanded' : 'not expanded'}`));
  push(h('span', { title: fmt.stamp(meta.read_at) }, `read ${fmt.time(meta.read_at)} UTC (${fmt.ago(receivedAt || meta.read_at)})`));
  push(h('span', null, ra.backend === 'lab-token' ? 'lab token: as ' : 'as ', h('span', { class: 'mono' }, ra.user || '?')));
  return out;
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

/** A host or port this policy names unambiguously, to pre-fill the match-policies template. */
function flowExample(row) {
  const res = row.resolved || {};
  const host = (list) => {
    for (const item of list || []) {
      for (const leaf of item.leaves || []) {
        const value = String(leaf.value || '');
        if (leaf.kind === 'prefix' && /^\d{1,3}(\.\d{1,3}){3}\/32$/.test(value)) return value.slice(0, -3);
        if (leaf.kind === 'prefix' && /^[0-9a-f:]+\/128$/i.test(value)) return value.slice(0, -4);
      }
    }
    return null;
  };
  let proto = null;
  let port = null;
  for (const app of res.application || []) {
    for (const leaf of app.leaves || []) {
      if (!leaf.predefined && leaf.protocol && /^\d+$/.test(String(leaf.destination_port || ''))) {
        proto = leaf.protocol;
        port = leaf.destination_port;
        break;
      }
    }
    if (port) break;
  }
  return { src: host(res.source), dst: host(res.destination), proto, port };
}

function matchPoliciesCli(scopeId, from, to, ex = {}) {
  const sp = scopeParts(scopeId);
  const words = ['show security match-policies'];
  if (sp.kind === 'lsys') words.push('logical-system', cliWord(sp.name));
  if (sp.kind === 'tenant') words.push('tenant', cliWord(sp.name));
  words.push('from-zone', from ? cliWord(from) : '<from-zone>', 'to-zone', to ? cliWord(to) : '<to-zone>');
  words.push('source-ip', ex.src || '<source-ip>', 'destination-ip', ex.dst || '<destination-ip>');
  words.push('source-port', ex.sport || '<source-port>', 'destination-port', ex.port || '<destination-port>');
  words.push('protocol', ex.proto || '<protocol>');
  return words.join(' ');
}

function showConfigCli(row, scopeId) {
  const prefix = cliPrefix(row.scope || scopeId);
  if (row.kind === 'global') return `show configuration ${prefix}security policies global policy ${cliWord(row.name)}`;
  const from = zonesOf(row.from)[0] || '<from-zone>';
  const to = zonesOf(row.to)[0] || '<to-zone>';
  return `show configuration ${prefix}security policies from-zone ${cliWord(from)} to-zone ${cliWord(to)} policy ${cliWord(row.name)}`;
}

function inactiveText(row) {
  if (row.inactive_reason === 'policy') return 'inactive: policy deactivated';
  if (row.inactive_reason === 'zone-pair') return row.kind === 'global' ? 'inactive: global section deactivated' : 'inactive: zone pair deactivated';
  return 'inactive';
}

function inactiveSentence(row) {
  if (row.inactive_reason === 'policy') return 'Inactive: this policy is deactivated in the configuration (inactive:). Junos skips it.';
  if (row.inactive_reason === 'zone-pair') {
    return row.kind === 'global'
      ? 'Inactive: the global policies section is deactivated, so Junos skips this policy.'
      : `Inactive: the zone pair from-zone ${zonesOf(row.from)[0]} to-zone ${zonesOf(row.to)[0]} is deactivated, so Junos skips every policy in it.`;
  }
  return null;
}

const ADDRESS_KINDS = { any: 'any address', address: 'address', set: 'address set', unresolved: 'not found' };
const APP_KINDS = {
  any: 'any application',
  application: 'custom application',
  set: 'application set',
  predefined: 'predefined (junos-defaults, not expanded)',
  unresolved: 'not found',
};

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
    this.cursor = -1;
    this.visible = [];
    this.panelToken = 0;
    this.panelKind = null;
    this.panelIdx = -1;
    this.panelLive = null;
    this.warnOpen = false;
    this.zonesAll = [];
    this.trs = [];
    this.liveCells = [];
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
    }
    if (sel !== this.sel) {
      if (sel) {
        this.wantSel = sel;
        this.tryOpenWanted();
      } else if (this.panelKind === 'policy') {
        this.sel = null;
        this.ctx.ui.closePanel();
      }
    }
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
      { class: 'btn ghost', type: 'button', 'aria-controls': 'pv-top', on: { click: () => this.toggleSummary() } },
      icon('grid'),
      h('span', { class: 'pv-hide-sm' }, 'Summary'),
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
      h('div', { class: 'view-actions' }, this.summaryBtn, this.explainBtn, this.exportSeg, this.refreshBtn),
    );
    this.noticeEl = h('div', { class: 'pv-notices' });
    this.stateEl = h('div', { class: 'pv-state', hidden: true });
    this.topEl = h('div', { class: 'pv-top', id: 'pv-top' });
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
    this.noteEl = h('p', { class: 'pv-filter-note', hidden: true }, 'Global policies stay listed when they apply to the chosen zones: a global policy without a zone list applies to every zone.');
    this.tableHost = h('div', { class: 'pv-tablehost' });
    this.bodyEl = h('div', { class: 'pv-body', hidden: true }, this.topEl, h('div', { class: 'pv-filter' }, this.qbHost, this.quickEl, this.noteEl), this.tableHost);
    this.loadingEl = h('div', { class: 'pv-loading' }, this.ctx.dom.skeleton(3), this.ctx.dom.skeleton(5));
    this.el.append(head, this.noticeEl, this.stateEl, this.loadingEl, this.bodyEl);
    this.tableHost.addEventListener('click', (e) => this.onTableClick(e));
  }

  applySummaryPref() {
    let hidden = false;
    try {
      hidden = window.localStorage.getItem(SUMMARY_PREF) === 'hidden';
    } catch (_err) {
      hidden = false;
    }
    this.setSummary(hidden);
  }

  setSummary(hidden) {
    this.topEl.hidden = hidden;
    this.summaryBtn.setAttribute('aria-expanded', hidden ? 'false' : 'true');
    this.summaryBtn.title = hidden ? 'Show the evaluation order and the zone-pair matrix' : 'Hide the evaluation order and the zone-pair matrix (more room for the table)';
  }

  toggleSummary() {
    const hide = !this.topEl.hidden;
    try {
      if (hide) window.localStorage.setItem(SUMMARY_PREF, 'hidden');
      else window.localStorage.removeItem(SUMMARY_PREF);
    } catch (_err) {
      // Storage blocked: the choice lasts for this page only.
    }
    this.setSummary(hide);
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
    const err = this.ctx.store.inventoryError;
    if (snap && err) {
      out.push(
        h(
          'div',
          { class: 'pv-notice deny', role: 'status' },
          icon('alert'),
          h('span', null, h('b', null, 'The last read failed. '), `${err.message} This page still shows the read from ${this.fmt.time(snap.meta && snap.meta.read_at)} UTC.`),
        ),
      );
    }
    if (snap && snap.scope && snap.scope.inactive) {
      out.push(
        h(
          'div',
          { class: 'pv-notice reject', role: 'note' },
          icon('alert'),
          h('span', null, h('b', null, `${scopeTitle(snap, snap.meta.scope)} is deactivated in the configuration. `), 'Nothing in this scope is in effect; the policies below are what the configuration holds, not what the device enforces.'),
        ),
      );
    }
    this.ctx.dom.put(this.noticeEl, ...out);
    this.noticeEl.hidden = !out.length;
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

  tryOpenWanted() {
    if (!this.wantSel || !this.model) return;
    const want = this.wantSel;
    this.wantSel = null;
    const idx = this.model.idById.get(want);
    if (idx === undefined) {
      this.sel = null;
      this.saveRoute(false);
      this.ctx.ui.toast('That policy is not in this scope of the configuration.', 'warn');
      return;
    }
    this.openDetail(idx, { push: false });
    const tr = this.trs[idx];
    if (tr && !tr.hidden) tr.scrollIntoView({ block: 'nearest' });
  }

  // ---- top: evaluation order, facts, matrix ----------------------------------------------------

  renderTop() {
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
    const dp = pol.default_policy;
    const flow = h(
      'ol',
      { class: 'pv-flow', 'aria-label': 'Junos evaluation order' },
      step(1, 'Zone-pair policies', fmt.num(c.zone), `in ${fmt.plural(m.pairs.size, 'zone pair')}, top to bottom`, '', 'pairs', 'Checked first: the policies of the flow’s from-zone to to-zone pair, in configuration order'),
      step(2, 'Global policies', fmt.num(c.global), c.global ? 'for each pair they apply to' : 'none configured', '', 'global', 'Checked next, in order, when no zone-pair policy matched'),
      step(
        3,
        'Default policy',
        dp || 'deny-all',
        dp ? (pol.default_policy_group ? `from group ${pol.default_policy_group}` : 'configured') : 'not configured: Junos default',
        `${dp === 'permit-all' ? 'permit' : 'deny'} is-word`,
        'default',
        'Used when no policy above matched',
      ),
    );
    const explain = h(
      'p',
      { class: 'pv-explain' },
      h('b', null, 'First match wins. '),
      'J-Wicket shows the order Junos checks; it does not decide which policy a flow matches. ',
      h('button', { class: 'link pv-inline-link', type: 'button', on: { click: () => this.openExplainer(null, null) } }, 'Test a flow on the device', icon('arrow-right')),
    );

    // facts
    const total = Math.max(1, m.rows.length);
    const seg = (cls, v) => (v ? h('i', { class: cls, style: { '--w': `${(v / total) * 100}%` } }) : null);
    const meter = h('div', { class: 'meter pv-meter', 'aria-hidden': 'true' }, seg('permit', c.permit), seg('deny', c.deny), seg('reject', c.reject), seg('inactive', c.inactive), seg('', c.unknown));
    const mix = h(
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
    );
    const groups = m.scope.groups || [];
    this.liveFact = h('dd', { class: 'pv-live-fact' });
    const mixRow = h(
      'div',
      { class: 'pv-mixrow' },
      h('div', { class: 'pv-mixrow-l' }, h('span', { class: 'pv-cap' }, fmt.plural(m.rows.length, 'policy')), meter, mix),
    );
    const facts = h(
      'dl',
      { class: 'pv-facts' },
      h('div', { class: 'pv-fact' }, h('dt', null, 'Live sessions'), this.liveFact),
      h(
        'div',
        { class: 'pv-fact' },
        h('dt', null, 'Policy rematch'),
        h('dd', null, pol.policy_rematch ? h('span', { title: 'Existing sessions are re-checked when policies change' }, 'on: re-checked on change') : h('span', { class: 'muted' }, 'off (not configured)')),
      ),
      pol.pre_id_default_policy
        ? h('div', { class: 'pv-fact' }, h('dt', null, 'Pre-ID default policy'), h('dd', null, 'configured', h('span', { class: 'faint' }, '\u00a0(contents not shown)')))
        : null,
      h(
        'div',
        { class: 'pv-fact' },
        h('dt', null, 'Configuration groups'),
        h(
          'dd',
          { class: 'pv-groups' },
          groups.length
            ? groups.map((g) =>
                h(
                  'button',
                  { class: 'pv-chipbtn gold', type: 'button', title: `Show the policies with parts from group ${g.name}`, on: { click: () => this.toggleTerm('group', g.name) } },
                  h('span', { class: 'mono' }, g.name),
                  h('span', { class: 'pv-chipcount' }, fmt.num(g.policies)),
                ),
              )
            : h('span', { class: 'muted' }, 'none'),
        ),
      ),
    );
    const evalCard = h(
      'section',
      { class: 'tile pv-eval', 'aria-label': 'Evaluation order and summary' },
      h('div', { class: 'tile-head' }, h('h2', { class: 'tile-title' }, icon('policies'), 'Evaluation order'), h('span', { class: 'tile-meta' }, scopeTitle(this.snap, this.ctx.store.scope))),
      h('div', { class: 'tile-body pv-eval-body' }, flow, explain, mixRow, facts),
    );
    const matrixCard = h(
      'section',
      { class: 'tile pv-mxcard', 'aria-labelledby': 'pv-mx-title' },
      h('div', { class: 'tile-head' }, h('h2', { class: 'tile-title', id: 'pv-mx-title' }, icon('grid'), 'Zone pairs'), h('span', { class: 'tile-meta' }, 'from \u2193  to \u2192')),
      h('div', { class: 'tile-body' }, this.buildMatrix()),
    );
    const strip = [this.managedStrip(), this.warningsBlock()].filter(Boolean);
    put(this.topEl, h('div', { class: 'pv-cards' }, evalCard, matrixCard), strip.length ? h('div', { class: 'pv-strip' }, strip) : null);
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
        (mg.clients || []).map((c, i) => [i ? ', ' : null, h('b', { class: 'mono' }, c.client), (c.targets || []).length ? h('span', { class: 'mono faint' }, ` ${c.targets.join(', ')}`) : null]),
        services.length ? h('span', { class: 'faint' }, ` (${services.join(', ')})`) : null,
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
          h('span', null, 'Policy ', h('button', { class: 'policy-link', type: 'button', title: `Open policy ${mm[1]}`, on: { click: () => this.openDetail(idxs[0]) } }, mm[1]), ` ${mm[2]}`),
        );
      }
      return h('li', null, icon(/^Fixture/.test(w) ? 'info' : 'alert'), h('span', null, w));
    };
    const det = h(
      'details',
      { class: 'pv-warn' },
      h('summary', null, icon('alert'), `Warnings`, h('span', { class: 'badge amber' }, String(list.length)), h('span', { class: 'pv-warn-hint' }, 'what J-Wicket could not show, or what is not in effect')),
      h('ul', null, list.map(item)),
    );
    det.open = this.warnOpen;
    det.addEventListener('toggle', () => {
      this.warnOpen = det.open;
    });
    return det;
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
      return h('span', { class: ['pv-mx-z', unknown && 'undefined'], title: `${axis} ${z}${unknown ? ' (not defined as a zone in this scope)' : ''}` }, z, unknown ? '*' : null);
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
          btn.title = `${from} \u2192 ${to}: ${fmt.plural(st.count, 'policy')} (${st.permit} permit, ${st.deny} deny, ${st.reject} reject, ${st.inactive} inactive)${pairInactive ? '; the zone pair is deactivated' : ''}. Select to filter.`;
        } else {
          btn.append(
            h('span', { class: 'pv-mx-dot', 'aria-hidden': 'true' }, '\u2014'),
            h('span', { class: 'pv-mx-g' }, globalsHere ? `${globalsHere} global` : 'default'),
            liveEl,
          );
          btn.title = `${from} \u2192 ${to}: no zone-pair policy, so Junos checks ${globalsHere ? fmt.plural(globalsHere, 'global policy', 'global policies') : 'the global policies (none apply)'} and then the default policy. Select to filter.`;
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
    if (undefinedZones.length) notes.push(`* Named in a policy but not defined as a zone in this scope: ${undefinedZones.join(', ')}.`);
    if (!m.zonesKnown) notes.push('Zones could not be read; the zones shown are the ones named in policies.');
    return [
      h('div', { class: 'pv-mx-scroll' }, grid),
      legend,
      h('p', { class: 'pv-mx-note' }, 'Counts include inactive policies. A dashed square has no zone-pair policy: Junos checks the global policies that apply (shown), then the default policy. Select a square to filter the table.', notes.length ? ` ${notes.join(' ')}` : ''),
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
    const defaultText = pol.default_policy || 'deny-all';
    for (const pair of m.pairs.values()) {
      const applying = m.globals.filter((i) => globalApplies(m.rows[i], pair.from, pair.to) && !m.rows[i].inactive).length;
      const countEl = h('span', { class: 'pv-sec-count' });
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
            h('span', { class: 'pv-sec-sub' }, 'checked in this order', SEP, countEl),
            pair.inactive ? h('span', { class: 'pill reject' }, 'zone pair deactivated') : null,
            h('span', { class: 'spacer' }),
            h(
              'button',
              {
                class: 'pv-sec-then',
                type: 'button',
                title: `If no policy above matches a ${pair.from} \u2192 ${pair.to} flow: ${applying ? fmt.plural(applying, 'global policy', 'global policies') : 'no global policy applies'}, then the default policy. Show the full order.`,
                dataset: { from: pair.from, to: pair.to },
              },
              'no match ',
              h('span', { class: 'arrow' }, ARROW),
              applying ? ` ${applying} global ` : ' ',
              applying ? h('span', { class: 'arrow' }, ARROW) : null,
              h('span', { class: defaultText === 'permit-all' ? 'act-permit' : 'act-deny' }, ` ${defaultText}`),
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
            h('span', { class: 'pv-sec-sub' }, 'checked after the zone-pair policies of each pair they apply to', SEP, countEl),
            allOff ? h('span', { class: 'pill reject' }, 'global section deactivated') : null,
            h('span', { class: 'spacer' }),
            h('span', { class: 'pv-sec-then static' }, 'no match ', h('span', { class: 'arrow' }, ARROW), h('span', { class: defaultText === 'permit-all' ? 'act-permit' : 'act-deny' }, ` ${defaultText}`)),
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
    const configured = Boolean(pol.default_policy);
    const action = pol.default_policy || 'deny-all';
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
        h('th', { scope: 'row', class: 'c-name' }, h('button', { class: 'pv-name', type: 'button', dataset: { explain: 'default' } }, 'default-policy')),
        h('td', { class: 'c-src', dataset: { label: 'Source' } }, h('span', { class: 'muted mono' }, 'any')),
        h('td', { class: 'c-dst', dataset: { label: 'Destination' } }, h('span', { class: 'muted mono' }, 'any')),
        h('td', { class: 'c-app', dataset: { label: 'Application' } }, h('span', { class: 'muted mono' }, 'any')),
        h('td', { class: 'c-act' }, h('span', { class: ['pill', action === 'permit-all' ? 'permit' : 'deny'] }, action)),
        h('td', { class: 'c-live' }),
        h(
          'td',
          { class: 'c-notes' },
          h(
            'div',
            { class: 'pv-badges' },
            configured ? null : h('span', { class: 'pv-badge', title: 'No default-policy is configured, so the Junos default applies: deny-all' }, 'not configured (Junos default)'),
            pol.default_policy_group ? h('span', { class: 'pv-badge b-group' }, `group ${pol.default_policy_group}`) : null,
          ),
        ),
      ),
    );
  }

  zoneChip(z, axis) {
    const unknown = this.model && this.model.zonesKnown && z && !this.model.defined.has(z);
    return this.h('span', { class: ['zone', unknown && 'pv-zone-undef'], title: unknown ? `${z}: not defined as a zone in this scope` : `${axis}-zone ${z}` }, z || '?');
  }

  zoneList(list, axis) {
    const zs = zonesOf(list);
    if (!zs.length) return [this.h('span', { class: 'zone pv-zone-any', title: `any ${axis}-zone` }, 'any')];
    return zs.map((z) => this.zoneChip(z, axis));
  }

  policyRow(idx) {
    const { h } = this;
    const r = this.model.rows[idx];
    const nameBtn = h('button', { class: 'pv-name', type: 'button', 'aria-haspopup': 'dialog', title: `Open ${r.name}` }, h('span', { class: 'pv-hl', dataset: { text: r.name } }, r.name));
    const liveCell = h('td', { class: 'c-live', dataset: { label: 'Live' } });
    this.liveCells[idx] = liveCell;
    return h(
      'tr',
      { class: ['pv-row', r.inactive && 'is-inactive'], dataset: { idx: String(idx) } },
      h('td', { class: 'c-seq' }, String(r.seq)),
      h(
        'th',
        { scope: 'row', class: 'c-name' },
        nameBtn,
        r.kind === 'global' ? h('div', { class: 'pv-gzones' }, this.zoneList(r.from, 'from'), h('span', { class: 'arrow' }, ARROW), this.zoneList(r.to, 'to')) : null,
        r.description ? h('div', { class: 'pv-desc', title: r.description }, r.description) : null,
      ),
      h('td', { class: 'c-src', dataset: { label: 'Source' } }, this.addrList(r, 'source')),
      h('td', { class: 'c-dst', dataset: { label: 'Destination' } }, this.addrList(r, 'destination')),
      h('td', { class: 'c-app', dataset: { label: 'Application' } }, this.appList(r)),
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
      { class: ['pv-v', 'pv-hl', extra], dataset: { k: key, v: value, text: value }, title: `Filter by ${key}:${value} (Alt-click to exclude)` },
      value,
    );
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
      if (res.kind === 'set') hint = h('span', { class: 'pv-tag', title: `Address set: ${leaves.length}${res.truncated ? '+' : ''} addresses` }, `set\u2009${leaves.length}${res.truncated ? '+' : ''}`);
      else if (res.kind === 'address' && leaves.length === 1 && leaves[0].value && leaves[0].value !== name) hint = h('span', { class: 'pv-hint', title: `${leaves[0].kind || 'address'} ${leaves[0].value}` }, leaves[0].value);
      const bad = res.kind === 'unresolved' || (res.unresolved || []).length;
      ul.append(h('li', null, this.valueToken(key, name, name === 'any' && 'is-any'), hint, bad ? h('span', { class: 'pv-tag bad', title: 'No address book visible to this policy defines it' }, 'not found') : null));
    });
    if (names.length > LIST_LIMIT) ul.append(h('li', { class: 'pv-more' }, `+${names.length - LIST_LIMIT} more`));
    return ul;
  }

  appList(r) {
    const { h } = this;
    const names = (r.match && r.match.application) || [];
    const resolved = (r.resolved && r.resolved.application) || [];
    const ul = h('ul', { class: 'pv-names' });
    names.slice(0, LIST_LIMIT).forEach((name) => {
      const res = resolved.find((x) => x.name === name) || {};
      const leaves = res.leaves || [];
      let hint = null;
      if (res.kind === 'set') hint = h('span', { class: 'pv-tag', title: `Application set: ${leaves.length} applications` }, `set\u2009${leaves.length}`);
      else if (res.kind === 'application' && leaves[0] && leaves[0].protocol) {
        hint = h('span', { class: 'pv-hint' }, `${leaves[0].protocol}${leaves[0].destination_port ? `/${leaves[0].destination_port}` : ''}`);
      } else if (res.kind === 'application' && leaves[0] && leaves[0].terms) hint = h('span', { class: 'pv-hint' }, `${leaves[0].terms} terms`);
      const bad = res.kind === 'unresolved' || (res.unresolved || []).length;
      ul.append(h('li', null, this.valueToken('app', name, name === 'any' && 'is-any'), hint, bad ? h('span', { class: 'pv-tag bad', title: 'No application or application set with this name is defined' }, 'not found') : null));
    });
    if (names.length > LIST_LIMIT) ul.append(h('li', { class: 'pv-more' }, `+${names.length - LIST_LIMIT} more`));
    const dyn = (r.match && r.match.dynamic_application) || [];
    if (dyn.length) ul.append(h('li', null, h('span', { class: 'pv-tag sky' }, 'dynamic'), h('span', { class: 'pv-hint' }, dyn.join(', '))));
    return ul;
  }

  notes(r) {
    const { h } = this;
    const out = [];
    const b = (text, cls, title) => h('span', { class: ['pv-badge', cls], title: title || text }, text);
    if (r.inactive) out.push(b(inactiveText(r), 'b-inactive', inactiveSentence(r)));
    if (r.group) out.push(b(`group ${r.group}`, 'b-group', `Comes from configuration group ${r.group}`));
    if ((r.inherited || []).length) out.push(b(`inherits ${r.inherited.join(', ')}`, 'b-inherit', `Partly inherited from another group: ${r.inherited.join(', ')}`));
    const log = [r.log && r.log.init ? 'init' : null, r.log && r.log.close ? 'close' : null].filter(Boolean);
    if (log.length) out.push(b(`log ${log.join('+')}`, 'b-log', `Logs session-${log.join(' and session-')}`));
    if (r.count) out.push(b('count', 'b-log', 'Counts traffic (then count)'));
    if (r.scheduler) out.push(b(`schedule ${r.scheduler}`, 'b-sched', `In effect only while scheduler ${r.scheduler} is active`));
    if ((r.application_services || []).length) out.push(b(`services: ${r.application_services.join(', ')}`, 'b-svc', `Application services: ${r.application_services.join(', ')}`));
    if (r.tunnel) out.push(b(`tunnel ${r.tunnel}`, 'b-tunnel', `Permits into IPsec VPN ${r.tunnel}`));
    const mm = r.match || {};
    if ((mm.source_identity || []).length) out.push(b('source identity', 'b-match', `source-identity ${mm.source_identity.join(', ')}`));
    if ((mm.url_category || []).length) out.push(b('URL category', 'b-match', `url-category ${mm.url_category.join(', ')}`));
    if ((mm.source_end_user_profile || []).length) out.push(b('end-user profile', 'b-match', `source-end-user-profile ${mm.source_end_user_profile.join(', ')}`));
    if ((r.inactive_parts || []).length && !r.inactive) out.push(b('parts deactivated', 'b-warn', `Deactivated, not in effect: ${r.inactive_parts.join(', ')}`));
    if ((r.unmodeled || []).length) out.push(b('settings not shown', 'b-warn', `J-Wicket does not display: ${r.unmodeled.join(', ')}`));
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
    if (!this.Q || !this.fields) {
      this.match = () => true;
      this.terms = [];
      return;
    }
    const fn = this.Q.compile(this.ast, this.fields, { inventory: this.snap });
    this.match = (row) => {
      try {
        return fn(row);
      } catch (_err) {
        return false;
      }
    };
    this.terms = this.ast ? this.Q.highlightTerms(this.ast) : [];
  }

  applyFilter(announce) {
    const m = this.model;
    if (!m || !this.table) return;
    let shown = 0;
    const order = [];
    for (const sec of this.sections) {
      let n = 0;
      for (const idx of sec.idxs) {
        const vis = this.match(m.rows[idx]);
        const tr = this.trs[idx];
        if (tr && tr.hidden === vis) tr.hidden = !vis;
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
          hint: 'Policies match on names and on what their address books resolve to (addr:, src:, dst: are CIDR-aware). The default policy below still applies.',
          actions: [this.h('button', { class: 'btn sm', type: 'button', on: { click: () => this.setQuery('') } }, 'Clear the query')],
        }),
      );
    }
    this.noMatch.hidden = shown !== 0;
    if (this.bar) this.bar.setStatus(this.ast ? `${this.fmt.num(shown)} of ${this.fmt.num(total)}` : '');
    if (this.cursor >= 0 && !order.includes(this.cursor)) this.cursor = -1;
    this.renderPressed();
    this.renderQuick();
    this.highlight();
    this.markSelected();
    if (announce) this.ctx.ui.announce(`Showing ${shown} of ${this.fmt.plural(total, 'policy')}.`);
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
      for (const el of tr.querySelectorAll('.pv-hl')) this.ctx.dom.put(el, ...markNodes(this.h, el.dataset.text, this.terms));
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
    const cur = this.termValue('from') === from && this.termValue('to') === to;
    const next = editQuery(this.Q, this.text, {
      drop: (it) => this.isKey(it, 'from') || this.isKey(it, 'to') || this.isKey(it, 'zone'),
      add: cur ? [] : [`from:${qv(from)}`, `to:${qv(to)}`],
    });
    // Measured before the table changes, so this does not force a layout of the filtered table.
    const far = !cur && this.tableHost.getBoundingClientRect().top > window.innerHeight * 0.7;
    this.setQuery(next);
    if (far) this.scrollToSection('pairs');
  }

  toggleTerm(key, value) {
    const term = `${key}:${qv(value)}`;
    const has = topItems(this.ast).some((it) => this.isKey(it, key) && it.op !== '!=' && it.values.length === 1 && it.values[0].text === String(value));
    this.setQuery(editQuery(this.Q, this.text, { drop: (it) => this.isKey(it, key) && it.values.length === 1 && it.values[0].text === String(value), add: has ? [] : [term] }));
  }

  addFilter(key, value, exclude) {
    const sameValue = (it) => it.values.length === 1 && it.values[0].text.toLowerCase() === String(value).toLowerCase();
    const drop = (it) => (this.isKey(it, key) && sameValue(it)) || (it.type === 'not' && this.isKey(it.item, key) && sameValue(it.item));
    const present = topItems(this.ast).some((it) => (exclude ? it.type === 'not' && this.isKey(it.item, key) && sameValue(it.item) : this.isKey(it, key) && it.op !== '!=' && sameValue(it)));
    this.setQuery(editQuery(this.Q, this.text, { drop, add: present ? [] : [`${exclude ? '-' : ''}${key}:${qv(value)}`] }));
    this.ctx.ui.announce(present ? `Removed ${key} ${value}` : `${exclude ? 'Excluding' : 'Filtering by'} ${key} ${value}`);
  }

  renderPressed() {
    const from = this.termValue('from');
    const to = this.termValue('to');
    for (const row of this.mxCells) for (const cell of row) cell.el.setAttribute('aria-pressed', cell.from === from && cell.to === to ? 'true' : 'false');
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
        this.ctx.dom.put(this.liveFact, h('span', { class: 'pill muted' }, live.status), ' ', h('span', { class: 'muted' }, live.status === 'refused' ? 'too many sessions to list; counts per policy are not available' : live.message || 'the session table could not be read'));
      } else {
        const filters = Object.entries(live.filters || {}).map(([k, v]) => `${k}=${v}`);
        this.ctx.dom.put(
          this.liveFact,
          h('b', { class: 'num pv-live-total' }, fmt.num(live.total)),
          h('span', { class: 'muted' }, ` in the poll at ${fmt.time(live.at)} UTC`),
          filters.length ? h('span', { class: 'pill sky', title: 'The Sessions view asked the device for these sessions only' }, `device filter ${filters.join(' ')}`) : null,
          live.truncated ? h('span', { class: 'pill reject', title: `The device returned more sessions (${live.returned}) than were listed` }, 'partial') : null,
          live.backups ? h('span', { class: 'faint', title: 'Chassis cluster: backup copies of sessions are not counted' }, ` \u00b7 ${fmt.plural(live.backups, 'backup copy', 'backup copies')} not counted`) : null,
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
      this.ctx.ui.toast(`The device was read moments ago. Try again in ${res.retryAfter || 2} s.`, 'warn');
    } else if (res.status !== 401) {
      this.ctx.ui.toast((res.data && res.data.error) || `The session table could not be read (HTTP ${res.status}).`, 'error');
    }
  }

  goSessions(name) {
    this.ctx.navigate('sessions', { q: `policy:${qv(name)}` });
  }

  goLogs(name) {
    const sp = scopeParts(this.ctx.store.scope);
    const q = `policy:${qv(name)}${sp.kind === 'lsys' ? ` lsys:${qv(sp.name)}` : ''}`;
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

    const hero = h(
      'div',
      { class: 'pv-hero' },
      h('p', { class: 'pv-eyebrow' }, `${isGlobal ? 'Global policy' : 'Zone-pair policy'}${SEP}${scopeTitle(this.snap, scopeId)}`),
      h(
        'div',
        { class: 'pv-where' },
        h('span', { class: 'pv-where-zones' }, this.zoneLinks(row.from, 'from'), h('span', { class: 'arrow' }, ARROW), this.zoneLinks(row.to, 'to')),
        h('span', { class: 'pv-where-pos' }, isGlobal ? `global policy ${pos} of ${siblings.length}` : `policy ${pos} of ${siblings.length} in this zone pair`),
        this.actionPill(row.action),
        row.inactive ? h('span', { class: 'pv-badge b-inactive' }, inactiveText(row)) : null,
        row.group ? h('span', { class: 'pv-badge b-group' }, `group ${row.group}`) : null,
      ),
      row.description ? h('p', { class: 'pv-desc-full' }, row.description) : null,
      this.panelLive,
      h(
        'div',
        { class: 'pv-hero-actions' },
        h('button', { class: 'btn sm', type: 'button', title: `Sessions with policy:${row.name}`, on: { click: () => this.goSessions(row.name) } }, icon('sessions'), 'Sessions for this policy'),
        h('button', { class: 'btn sm', type: 'button', title: `Logs with policy:${row.name}`, on: { click: () => this.goLogs(row.name) } }, icon('logs'), 'Logs for this policy'),
        h('button', { class: 'btn sm ghost', type: 'button', title: 'Copy the show configuration command', on: { click: () => this.ctx.ui.copy(showConfigCli(row, scopeId), 'Command copied. Paste it into the device CLI.') } }, icon('terminal'), 'Copy CLI'),
      ),
    );
    this.renderPanelLive(idx);
    return h(
      'div',
      { class: 'pv-detail' },
      hero,
      this.ruleCard(row),
      this.matchSection(row),
      this.resolvedAddrSection(row, 'source', 'Source addresses, resolved'),
      this.resolvedAddrSection(row, 'destination', 'Destination addresses, resolved'),
      this.resolvedAppSection(row),
      this.thenSection(row),
      this.provenanceSection(row),
      this.unmodeledSection(row, scopeId),
      this.section('See it on the device', [
        cliBlock(this.ctx, showConfigCli(row, scopeId)),
        h('p', { class: 'pv-small faint' }, 'The configuration as committed, with this policy’s exact path. Add | display inheritance to see what comes from groups.'),
      ]),
      this.evaluationSection(row, idx, scopeId),
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
        { class: 'zone pv-zone-link', type: 'button', title: `Zone ${z} in Objects`, on: { click: () => this.ctx.navigate('objects', { tab: 'zones', q: `name:${qv(z)}`, sel: `zone|${z}` }) } },
        z,
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
        const value = r.kind === 'address' && leaves.length === 1 ? leaves[0].value : r.kind === 'set' ? `set of ${leaves.length}${r.truncated ? '+' : ''}` : r.kind === 'unresolved' ? 'not found' : null;
        return h('li', null, h('span', { class: ['mono', n === 'any' && 'muted'] }, n), value && value !== n ? h('span', { class: ['pv-rule-v', r.kind === 'unresolved' && 'bad'] }, value) : null);
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
    return h(
      'div',
      { class: ['pv-rule', `is-${action}`, row.inactive && 'is-inactive'], role: 'img', 'aria-label': `${(mm.source || []).join(', ') || 'any'} to ${(mm.destination || []).join(', ') || 'any'}, application ${(mm.application || []).join(', ') || 'any'}: ${row.action}` },
      end('source', 'Source', row.from, 'from'),
      h(
        'div',
        { class: 'pv-rule-mid' },
        h('div', { class: 'pv-rule-apps' }, apps.map((a) => h('span', { class: 'mono' }, a)), (mm.application || []).length > 4 ? h('span', { class: 'faint' }, `+${mm.application.length - 4}`) : null),
        h('div', { class: 'pv-rule-line', 'aria-hidden': 'true' }, h('span', { class: 'pv-rule-actwrap' }, h('span', { class: ['pill', action === 'unknown' ? 'muted' : action, 'pv-rule-act'] }, row.action))),
        h('div', { class: 'pv-rule-extra' }, extras.join(SEP)),
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
    return list && list.length ? h('span', { class: 'mono' }, list.join(', ')) : h('span', { class: 'muted' }, none || 'none');
  }

  matchSection(row) {
    const { h } = this;
    const mm = row.match || {};
    const side = (names, excluded) => (excluded ? h('span', null, h('span', { class: 'pv-tag bad' }, 'all except'), ' ', h('span', { class: 'mono' }, names.join(', '))) : this.joinOrNone(names, 'any'));
    return this.section('Match', [
      this.kv([
        ['Source', side(mm.source || [], mm.source_excluded)],
        ['Destination', side(mm.destination || [], mm.destination_excluded)],
        ['Application', this.joinOrNone(mm.application, 'any')],
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

  objLink(name, tab, sel, title) {
    return this.h('button', { class: 'pv-objlink', type: 'button', title, on: { click: () => this.ctx.navigate('objects', { tab, q: `name:${qv(name)}`, sel }) } }, name);
  }

  resolvedAddrSection(row, side, title) {
    const { h } = this;
    const list = (row.resolved && row.resolved[side]) || [];
    const zones = side === 'source' ? row.from : row.to;
    const blocks = list.map((item) => {
      const leaves = item.leaves || [];
      const single = item.kind === 'address' && leaves.length === 1 && leaves[0].name === item.name;
      const head = [
        item.kind === 'address' || item.kind === 'set'
          ? this.objLink(item.name, 'address-books', `${item.kind === 'set' ? 'set' : 'addr'}|${item.book || ''}|${item.name}`, `Open ${item.name} in Objects`)
          : h('span', { class: 'pv-res-name' }, item.name),
        h('span', { class: ['pv-tag', item.kind === 'unresolved' && 'bad'] }, ADDRESS_KINDS[item.kind] || item.kind),
        single ? h('span', { class: 'pv-res-val' }, h('span', { class: 'faint' }, `${leaves[0].kind || 'address'} `), h('span', { class: 'mono ip' }, leaves[0].value || '')) : null,
        item.book ? h('span', { class: 'pv-res-book' }, `from ${bookLabel(item.book)}`) : null,
      ];
      const body = [];
      if (item.kind === 'any') body.push(h('p', { class: 'pv-small muted' }, 'Matches every address.'));
      if (item.kind === 'unresolved') {
        body.push(h('p', { class: 'pv-unres' }, `Not found: no address book visible ${row.kind === 'global' || !zonesOf(zones).length ? 'to this policy' : `from zone ${zonesOf(zones)[0]}`} defines ${item.name}.`));
      }
      if (leaves.length && !single) {
        body.push(
          h(
            'table',
            { class: 'table pv-mini' },
            h('thead', null, h('tr', null, h('th', { scope: 'col' }, 'Address'), h('th', { scope: 'col' }, 'Kind'), h('th', { scope: 'col' }, 'Value'))),
            h('tbody', null, leaves.map((l) => h('tr', null, h('td', { class: 'mono' }, l.name), h('td', { class: 'muted' }, l.kind || ''), h('td', { class: 'mono ip' }, l.value || '')))),
          ),
        );
      }
      if (item.truncated) body.push(h('p', { class: 'pv-small muted' }, `The list stops at ${leaves.length} addresses; the set is larger.`));
      const unres = (item.unresolved || []).filter((n) => n !== item.name || item.kind !== 'unresolved');
      if (unres.length) body.push(h('p', { class: 'pv-unres' }, `Members not found: ${unres.join(', ')}`));
      return h('div', { class: ['pv-res', item.kind === 'unresolved' && 'is-bad'] }, h('div', { class: 'pv-res-head' }, head), body);
    });
    return this.section(title, blocks.length ? blocks : h('p', { class: 'pv-small muted' }, 'No addresses in the match.'));
  }

  resolvedAppSection(row) {
    const { h } = this;
    const list = (row.resolved && row.resolved.application) || [];
    const blocks = list.map((item) => {
      const body = [];
      if (item.kind === 'any') body.push(h('p', { class: 'pv-small muted' }, 'Matches every application.'));
      if (item.kind === 'unresolved') body.push(h('p', { class: 'pv-unres' }, `Not found: no application or application set named ${item.name} is defined.`));
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
                  ? h('tr', null, h('td', { class: 'mono' }, l.name), h('td', { colspan: '3', class: 'muted' }, 'predefined (junos-defaults, not expanded)'))
                  : h(
                      'tr',
                      null,
                      h('td', { class: 'mono' }, l.name),
                      h('td', { class: 'mono' }, l.protocol || (l.terms ? `${l.terms} terms (not expanded)` : '\u2014')),
                      h('td', { class: 'mono' }, l.destination_port || '\u2014'),
                      h('td', { class: 'mono' }, l.source_port || '\u2014'),
                    ),
              ),
            ),
          ),
        );
      }
      const unres = (item.unresolved || []).filter((n) => n !== item.name || item.kind !== 'unresolved');
      if (unres.length) body.push(h('p', { class: 'pv-unres' }, `Members not found: ${unres.join(', ')}`));
      const nameEl =
        item.kind === 'application' || item.kind === 'set'
          ? this.objLink(item.name, 'applications', `app|${item.name}`, `Open ${item.name} in Objects`)
          : h('span', { class: 'pv-res-name' }, item.name);
      return h('div', { class: ['pv-res', item.kind === 'unresolved' && 'is-bad'] }, h('div', { class: 'pv-res-head' }, nameEl, h('span', { class: ['pv-tag', item.kind === 'unresolved' && 'bad'] }, APP_KINDS[item.kind] || item.kind)), body);
    });
    return this.section('Applications, resolved', blocks.length ? blocks : h('p', { class: 'pv-small muted' }, 'No applications in the match.'));
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
        ['Tunnel', row.tunnel ? h('span', { class: 'mono' }, `ipsec-vpn ${row.tunnel}`) : h('span', { class: 'muted' }, 'none')],
        ['Scheduler', row.scheduler ? h('span', { class: 'mono' }, row.scheduler) : h('span', { class: 'muted' }, 'none: always in effect while active')],
      ]),
      row.action === 'unknown' ? h('p', { class: 'pv-unres' }, 'No permit, deny or reject action that J-Wicket recognises. Check the policy on the device.') : null,
    ]);
  }

  provenanceSection(row) {
    const { h } = this;
    const state = inactiveSentence(row) || 'Active.';
    const others = (row.groups || []).filter((g) => g !== row.group);
    const parts = row.inactive_parts || [];
    return this.section('Where it comes from', [
      this.kv([
        ['Configured', row.group ? h('span', null, 'From configuration group ', h('b', { class: 'mono pv-gold' }, row.group)) : 'Directly in the configuration (no group).'],
        ['Inherited parts', (row.inherited || []).length ? h('span', null, 'Partly inherited from another group: ', h('span', { class: 'mono' }, row.inherited.join(', '))) : h('span', { class: 'muted' }, 'none')],
        ['Groups in this policy', (row.groups || []).length ? h('span', { class: 'mono' }, row.groups.join(', ')) : h('span', { class: 'muted' }, 'none')],
        ['State', h('span', { class: row.inactive ? 'act-reject' : 'act-permit' }, state)],
      ]),
      parts.length
        ? h(
            'div',
            { class: 'pv-callout reject' },
            h('p', null, h('b', null, 'Deactivated parts, not in effect. '), row.inactive ? 'The policy itself is also inactive.' : 'The policy is active, but Junos ignores these parts of it:'),
            h('ul', { class: 'pv-bullets' }, parts.map((p) => h('li', { class: 'mono' }, p))),
            h('p', { class: 'pv-small muted' }, 'The match and action above already leave them out.'),
          )
        : null,
      others.length && row.group ? h('p', { class: 'pv-small muted' }, `Other groups also contribute settings: ${others.join(', ')}.`) : null,
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
        h('ul', { class: 'pv-bullets' }, unmodeled.map((u) => h('li', { class: 'mono' }, u))),
        cliBlock(this.ctx, showConfigCli(row, scopeId)),
      ),
    );
  }

  /** The evaluation order for one zone pair, as nodes. `current` marks a policy. */
  orderNodes(from, to, current) {
    const { h } = this;
    const m = this.model;
    const fmt = this.fmt;
    const pol = m.pol;
    const kids = [];
    let n = 1;
    const item = (idx) => {
      const r = m.rows[idx];
      const here = idx === current;
      return h(
        'li',
        { class: ['pv-ord', r.inactive && 'skipped', here && 'this'] },
        h('span', { class: 'pv-ord-n', 'aria-hidden': 'true' }, String(n++)),
        h('button', { class: 'pv-ord-name', type: 'button', title: `Open ${r.name}`, on: { click: () => this.openDetail(idx, { push: false }) } }, r.name),
        this.actionPill(r.action),
        r.kind === 'global' ? h('span', { class: 'pv-ord-z' }, this.zoneList(r.from, 'from'), h('span', { class: 'arrow' }, ARROW), this.zoneList(r.to, 'to')) : null,
        r.inactive ? h('span', { class: 'pv-ord-why' }, 'skipped: inactive') : null,
        here ? h('span', { class: 'pv-ord-here' }, '\u2190 this policy') : null,
      );
    };
    const group = (label, idxs, empty) => {
      kids.push(h('p', { class: 'pv-ord-label' }, label));
      if (idxs.length) kids.push(h('ol', { class: 'pv-order' }, idxs.map(item)));
      else kids.push(h('p', { class: 'pv-ord-empty' }, empty));
    };
    const pair = m.pairs.get(pairKey(from, to));
    group(`Zone-pair policies for ${from} \u2192 ${to}, top to bottom`, pair ? pair.idxs : [], 'No zone-pair policy for this pair.');
    const applying = m.globals.filter((i) => globalApplies(m.rows[i], from, to));
    group(`Then the global policies that apply to ${from} \u2192 ${to}`, applying, 'No global policy applies to this pair.');
    const dp = pol.default_policy;
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
          h('span', { class: ['pill', dp === 'permit-all' ? 'permit' : 'deny'] }, dp || 'deny-all'),
          h('span', { class: 'pv-ord-why' }, dp ? (pol.default_policy_group ? `from group ${pol.default_policy_group}` : 'configured') : 'not configured: Junos default'),
        ),
      ),
    );
    kids.unshift(
      h(
        'p',
        { class: 'pv-ord-sum' },
        `${fmt.plural((pair ? pair.idxs.length : 0) + applying.length + 1, 'step')} for a flow from ${from} to ${to}. The first policy whose match fits the flow decides; inactive ones are skipped.`,
      ),
    );
    return kids;
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
    if (from && to) {
      kids.push(...this.orderNodes(from, to, idx));
    } else {
      const zl = (list) => (zonesOf(list).length ? list.join(', ') : 'any');
      kids.push(
        h(
          'p',
          { class: 'pv-small' },
          `This global policy applies to every zone pair whose from-zone is in (${zl(row.from)}) and whose to-zone is in (${zl(row.to)}); “any” means every zone. For each such pair, Junos checks that pair’s zone-pair policies first, then the global policies in this order, then the default policy.`,
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
              h('button', { class: 'pv-ord-name', type: 'button', on: { click: () => this.openDetail(i, { push: false }) } }, r.name),
              this.actionPill(r.action),
              h('span', { class: 'pv-ord-z' }, this.zoneList(r.from, 'from'), h('span', { class: 'arrow' }, ARROW), this.zoneList(r.to, 'to')),
              r.inactive ? h('span', { class: 'pv-ord-why' }, 'skipped: inactive') : null,
              i === idx ? h('span', { class: 'pv-ord-here' }, '\u2190 this policy') : null,
            );
          }),
        ),
        h('button', { class: 'btn sm', type: 'button', on: { click: () => this.openExplainer(null, null) } }, this.ctx.dom.icon('help'), 'Pick a zone pair to see its full order'),
      );
    }
    kids.push(
      h('p', { class: 'pv-small' }, 'This shows order, not a match result. To test a flow, run on the device:'),
      cliBlock(this.ctx, matchPoliciesCli(scopeId, from, to, flowExample(row))),
      h('p', { class: 'pv-small muted' }, 'Values come from this policy where it names a single host or port. Replace each <placeholder> with the flow you want to test.'),
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
    const zoneSelect = (key, label) => {
      const sel = h('select', { class: 'input pv-ex-select', id: `pv-ex-${key}`, on: { change: () => { st[key] = sel.value || null; draw(); } } }, h('option', { value: '' }, `${label}\u2026`), m.zones.map((z) => h('option', { value: z }, z)));
      sel.value = st[key] || '';
      return h('div', { class: ['field', 'pv-ex-field', `pv-ex-f-${key}`] }, h('label', { for: `pv-ex-${key}` }, label), sel);
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
      h('option', { value: '' }, 'protocol\u2026'),
      ['tcp', 'udp', 'icmp', 'icmp6', 'gre', 'esp'].map((p) => h('option', { value: p }, p)),
    );
    protoSel.value = st.proto || '';
    const form = h(
      'div',
      { class: 'pv-ex-form' },
      zoneSelect('from', 'From zone'),
      textField('src', 'Source IP', '10.10.3.4', (s) => isIp(this.Q, s)),
      textField('sport', 'Source port', '40000', isPort),
      h('div', { class: 'field pv-ex-field pv-ex-f-proto' }, h('label', { for: 'pv-ex-proto' }, 'Protocol'), protoSel),
      zoneSelect('to', 'To zone'),
      textField('dst', 'Destination IP', '198.51.100.20', (s) => isIp(this.Q, s)),
      textField('port', 'Destination port', '443', isPort),
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
        cliBlock(this.ctx, matchPoliciesCli(scopeId, st.from, st.to, ex)),
        h('p', { class: 'pv-small muted' }, 'Junos answers with the policy that matches. Fill in the fields above, or replace each <placeholder> in the command.'),
      );
      const terms = [];
      if (st.from) terms.push(`from:${qv(st.from)}`);
      if (st.to) terms.push(`to:${qv(st.to)}`);
      if (ex.src) terms.push(`src:${ex.src}`);
      if (ex.dst) terms.push(`dst:${ex.dst}`);
      if (terms.length) {
        const q = terms.join(' ');
        kids.push(
          h(
            'div',
            { class: 'pv-ex-filter' },
            h('p', { class: 'pv-small' }, 'Narrow the table to the policies that name these zones and addresses (“any” counts; applications are not checked). This is a filter, not a match result.'),
            h('button', { class: 'btn sm', type: 'button', on: { click: () => this.setQuery(q) } }, icon('filter'), h('span', { class: 'mono' }, q)),
          ),
        );
      }
      if (focusDefault || !st.from) {
        kids.push(
          h('h4', { class: 'pv-ex-h' }, 'The default policy'),
          h(
            'p',
            { class: 'pv-small' },
            m.pol.default_policy
              ? `Configured: ${m.pol.default_policy}${m.pol.default_policy_group ? `, from configuration group ${m.pol.default_policy_group}` : ''}. It decides every flow that no zone-pair or global policy matches.`
              : 'Not configured, so the Junos default applies: deny-all. It decides every flow that no zone-pair or global policy matches.',
          ),
          cliBlock(this.ctx, `show configuration ${cliPrefix(scopeId)}security policies default-policy`),
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
