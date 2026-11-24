// main.js: the J-Wicket v2 shell.
//
// Sign-in, hash routing, the left rail, the top bar (device identity, scope, read-as, managed-from),
// the fixture banner, the command palette, keyboard shortcuts, the right-hand detail panel, toasts,
// the live region, theme/density preferences, and lazy loading of the views, each of which gets a
// `ctx` (see the module contract in the UI brief, section 10).
//
// Rules kept here: no innerHTML or other HTML parsing, no inline styles (CSSOM only), nothing read
// from the device is stored in the browser (localStorage holds UI preferences only), every panel is
// device data or an explicit state.

import * as dom from './dom.js';
import * as format from './format.js';
import * as api from './api.js';
import { Palette } from './widgets/palette.js';

const { h, icon, put, stateCard } = dom;

const VIEWS = [
  { id: 'overview', title: 'Overview', key: 'o', icon: 'overview', sub: 'Device, sessions, denies, warnings' },
  { id: 'policies', title: 'Policies', key: 'p', icon: 'policies', sub: 'Security policies in evaluation order' },
  { id: 'sessions', title: 'Sessions', key: 's', icon: 'sessions', sub: 'Live flow sessions' },
  { id: 'logs', title: 'Logs', key: 'l', icon: 'logs', sub: 'Live syslog tail, highlighted' },
  { id: 'objects', title: 'Objects', key: 'b', icon: 'objects', sub: 'Zones, address books, applications' },
];
const VIEW_BY_ID = new Map(VIEWS.map((v) => [v.id, v]));
const SCOPE_RE = /^(root|lsys:[A-Za-z0-9._-]{1,63}|tenant:[A-Za-z0-9._-]{1,63})$/;
const PREF = { theme: 'jwicket.theme', density: 'jwicket.density', rail: 'jwicket.rail' };
const ANNOUNCE_GAP_MS = 10000;
const IS_MAC = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent || '');
const SEP = ' · ';

const $ = (id) => document.getElementById(id);

// ---- state ---------------------------------------------------------------------------------------

const S = {
  server: null, // GET /api/session while signed out: credential, backend, fixture, version
  session: null, // signed in: user, csrf, backend, credential, fixture, idle_timeout_s, version
  gen: 0, // bumps on every sign-in and sign-out; late results from an older generation are dropped
  scope: 'root',
  inv: new Map(), // scope -> snapshot, this sign-in only, memory only
  invInflight: new Map(),
  invError: null,
  lastInventory: null,
  policyIdx: null,
  policyIdxFor: null,
  sessionsLast: null,
  route: { view: 'overview', params: new URLSearchParams() },
  lastHash: null,
  current: null, // { id, el, handle, offs, live }
  mountSeq: 0,
  viewModules: new Map(),
  engines: null,
  live: new Set(),
  fixture: false,
  recent: [], // query strings visited in this tab (memory only)
  reading: 0,
};

const listeners = { inventory: new Set(), sessions: new Set(), scope: new Set() };

function emit(event, payload) {
  for (const fn of [...listeners[event]]) {
    try {
      fn(payload);
    } catch (err) {
      console.error(err);
    }
  }
}

// ---- preferences (UI only, never device data) -----------------------------------------------------

function prefGet(key) {
  try {
    return window.localStorage.getItem(key);
  } catch (_err) {
    return null;
  }
}

function prefSet(key, value) {
  try {
    if (value === null) window.localStorage.removeItem(key);
    else window.localStorage.setItem(key, value);
  } catch (_err) {
    // Storage blocked: the preference lasts for this page only.
  }
}

function applyPrefs() {
  const root = document.documentElement;
  const theme = prefGet(PREF.theme);
  if (theme === 'light' || theme === 'dark') root.dataset.theme = theme;
  if (prefGet(PREF.density) === 'comfortable') root.dataset.density = 'comfortable';
  const rail = prefGet(PREF.rail);
  if (rail === 'collapsed' || rail === 'expanded') root.dataset.rail = rail;
}

function effectiveTheme() {
  const t = document.documentElement.dataset.theme;
  if (t === 'light' || t === 'dark') return t;
  return window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}

function toggleTheme() {
  const next = effectiveTheme() === 'light' ? 'dark' : 'light';
  document.documentElement.dataset.theme = next;
  prefSet(PREF.theme, next);
  updateThemeButton();
  say(`${next === 'light' ? 'Day' : 'Night'} theme`);
}

function toggleDensity() {
  const root = document.documentElement;
  const comfy = root.dataset.density !== 'comfortable';
  if (comfy) root.dataset.density = 'comfortable';
  else delete root.dataset.density;
  prefSet(PREF.density, comfy ? 'comfortable' : null);
  document.dispatchEvent(new CustomEvent('jwicket:density', { detail: { density: comfy ? 'comfortable' : 'compact' } }));
  renderRailFoot();
  say(comfy ? 'Comfortable rows' : 'Dense rows');
}

function railCollapsed() {
  const root = document.documentElement;
  if (root.dataset.rail === 'collapsed') return true;
  if (root.dataset.rail === 'expanded') return false;
  return window.matchMedia && window.matchMedia('(max-width: 960px)').matches;
}

function toggleRail() {
  const next = railCollapsed() ? 'expanded' : 'collapsed';
  document.documentElement.dataset.rail = next;
  prefSet(PREF.rail, next);
  renderRailFoot();
}

// ---- live region, toasts -------------------------------------------------------------------------

let sayTimer = 0;
function say(text, assertive = false) {
  const region = $(assertive ? 'alert' : 'live');
  if (!region) return;
  region.textContent = '';
  clearTimeout(sayTimer);
  sayTimer = setTimeout(() => {
    region.textContent = String(text);
  }, 40);
}

let lastAnnounce = 0;
let pendingAnnounce = '';
let announceTimer = 0;
/** Polite and throttled: at most one announcement every 10 s; the latest text wins. */
function announce(text) {
  const msg = String(text || '');
  if (!msg) return;
  const wait = lastAnnounce + ANNOUNCE_GAP_MS - Date.now();
  if (wait <= 0) {
    lastAnnounce = Date.now();
    say(msg);
    return;
  }
  pendingAnnounce = msg;
  if (!announceTimer) {
    announceTimer = setTimeout(() => {
      announceTimer = 0;
      if (pendingAnnounce) {
        lastAnnounce = Date.now();
        say(pendingAnnounce);
        pendingAnnounce = '';
      }
    }, wait);
  }
}

const TOAST_ICON = { info: 'info', ok: 'check-circle', warn: 'alert', error: 'alert' };
const recentToasts = new Map();

function toast(message, kind = 'info') {
  const text = String(message || '').trim();
  if (!text) return;
  const k = TOAST_ICON[kind] ? kind : 'info';
  const key = `${k}:${text}`;
  const now = Date.now();
  if ((recentToasts.get(key) || 0) > now - 5000) return;
  recentToasts.set(key, now);
  const box = $('toasts');
  let timer = 0;
  const el = h(
    'div',
    { class: ['toast', k] },
    icon(TOAST_ICON[k]),
    h('div', { class: 'toast-msg' }, text),
    h('button', { class: 'btn ghost sm icon', type: 'button', 'aria-label': 'Dismiss', on: { click: () => dismiss() } }, icon('close')),
  );
  function dismiss() {
    clearTimeout(timer);
    el.classList.add('leaving');
    setTimeout(() => el.remove(), 180);
  }
  el.addEventListener('mouseenter', () => clearTimeout(timer));
  el.addEventListener('mouseleave', () => {
    clearTimeout(timer);
    timer = setTimeout(dismiss, 2500);
  });
  box.append(el);
  while (box.children.length > 4) box.firstElementChild.remove();
  timer = setTimeout(dismiss, k === 'error' ? 9000 : 5000);
  say(text, k === 'error');
}

async function copy(text, label = 'Copied to the clipboard.') {
  const value = String(text === null || text === undefined ? '' : text);
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(value);
      toast(label, 'ok');
      return true;
    }
  } catch (_err) {
    // fall through to the selection-based copy
  }
  const area = h('textarea', { class: 'sr-only', readonly: true, 'aria-hidden': 'true', tabindex: '-1' });
  area.value = value;
  document.body.append(area);
  area.select();
  let ok = false;
  try {
    ok = document.execCommand('copy');
  } catch (_err) {
    ok = false;
  }
  area.remove();
  toast(ok ? label : 'The browser did not allow copying. Select the text and copy it yourself.', ok ? 'ok' : 'warn');
  return ok;
}

function showFixture() {
  if (S.fixture) return;
  S.fixture = true;
  $('fixture-banner').hidden = false;
  positionPanel();
}

function noteFixture(meta) {
  if (meta && meta.fixture === true) showFixture();
}

// ---- right-hand detail panel ---------------------------------------------------------------------

const P = { open: false, onClose: null, opener: null };

function positionPanel() {
  const bar = $('topbar');
  const app = $('app');
  if (!bar || !app || app.hidden) return;
  const r = bar.getBoundingClientRect();
  document.documentElement.style.setProperty('--panel-top', `${Math.max(0, Math.round(r.bottom))}px`);
}

function focusables(root) {
  return [
    ...root.querySelectorAll(
      'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
    ),
  ].filter((el) => el.getClientRects().length > 0);
}

function openPanel({ title = '', content = null, onClose = null, wide = false, actions = null } = {}) {
  const panel = $('panel');
  const active = document.activeElement;
  if (P.open) finishPanelClose(false);
  else P.opener = active && !panel.contains(active) ? active : null;
  P.onClose = typeof onClose === 'function' ? onClose : null;
  $('panel-title').textContent = String(title);
  put($('panel-actions'), ...(actions || []));
  const body = $('panel-body');
  body.replaceChildren();
  if (content) body.append(content);
  panel.classList.toggle('wide', Boolean(wide));
  positionPanel();
  panel.hidden = false;
  // Reset after un-hiding: a scrollTop set on a display:none element is ignored.
  body.scrollTop = 0;
  $('panel-scrim').classList.add('show');
  requestAnimationFrame(() => panel.classList.add('open'));
  P.open = true;
  $('panel-title').focus({ preventScroll: true });
  return {
    el: body,
    close: closePanel,
    setTitle: (t) => {
      $('panel-title').textContent = String(t);
    },
  };
}

function finishPanelClose(restoreFocus) {
  const panel = $('panel');
  panel.classList.remove('open');
  panel.hidden = true;
  $('panel-scrim').classList.remove('show');
  $('panel-body').replaceChildren();
  $('panel-actions').replaceChildren();
  P.open = false;
  const cb = P.onClose;
  P.onClose = null;
  if (restoreFocus) {
    const opener = P.opener;
    P.opener = null;
    if (opener && document.contains(opener) && typeof opener.focus === 'function') opener.focus({ preventScroll: true });
  }
  if (cb) {
    try {
      cb();
    } catch (err) {
      console.error(err);
    }
  }
}

function closePanel() {
  if (P.open) finishPanelClose(true);
}

function wirePanel() {
  const panel = $('panel');
  $('panel-close').append(icon('close'));
  $('panel-close').addEventListener('click', closePanel);
  $('panel-scrim').addEventListener('click', closePanel);
  panel.addEventListener('keydown', (e) => {
    if (e.key !== 'Tab') return;
    const items = focusables(panel);
    if (!items.length) return;
    const first = items[0];
    const last = items[items.length - 1];
    if (e.shiftKey && (document.activeElement === first || document.activeElement === $('panel-title'))) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  });
}

// ---- store ---------------------------------------------------------------------------------------

function publicSession() {
  const s = S.session;
  if (!s) return null;
  return {
    user: s.user,
    backend: s.backend,
    csrf: s.csrf,
    fixture: Boolean(s.fixture),
    credential: s.credential,
    idle_timeout_s: s.idle_timeout_s,
    version: s.version,
  };
}

function setReading(delta) {
  S.reading = Math.max(0, S.reading + delta);
  const dot = document.querySelector('#chip-device .status-dot');
  if (dot && S.reading) dot.className = 'status-dot idle';
  else if (dot) renderDeviceChip();
}

async function readInventory(scope) {
  const gen = S.gen;
  setReading(1);
  let res = await api.get('/api/inventory', { scope });
  // api.get waits out a Retry-After on the next call for the same endpoint.
  if (res.status === 429 && gen === S.gen) res = await api.get('/api/inventory', { scope });
  setReading(-1);
  if (gen !== S.gen) return null;
  if (!res.ok) {
    if (res.status === 401) return null;
    S.invError = { status: res.status, message: res.data.error || `The inventory read failed (HTTP ${res.status}).` };
    if (res.status === 404 && scope !== 'root') {
      toast(`${scope} is not configured on this device. Showing the root system.`, 'warn');
      setScope('root');
    } else {
      toast(S.invError.message, 'error');
    }
    renderTopbar();
    return null;
  }
  S.invError = null;
  S.inv.set(scope, res.data);
  if (scope === S.scope) {
    S.lastInventory = res.data;
    S.policyIdx = null;
    renderTopbar();
    renderRailMeta();
    emit('inventory', res.data);
  }
  return res.data;
}

/** store.inventory(force): the snapshot for the current scope, cached per scope; null on error. */
function inventory(force = false) {
  const scope = S.scope;
  if (!S.session) return Promise.resolve(null);
  if (!force && S.inv.has(scope)) return Promise.resolve(S.inv.get(scope));
  const pending = S.invInflight.get(scope);
  if (pending) return pending;
  const p = readInventory(scope).finally(() => S.invInflight.delete(scope));
  S.invInflight.set(scope, p);
  return p;
}

function policyIndex() {
  const snap = S.lastInventory;
  if (S.policyIdx && S.policyIdxFor === snap) return S.policyIdx;
  const map = new Map();
  const rows = (snap && snap.scope && snap.scope.policies && snap.scope.policies.rows) || [];
  for (const r of rows) {
    if (!r || !r.name) continue;
    const entry = {
      from: [...(r.from || [])],
      to: [...(r.to || [])],
      kind: r.kind,
      seq: r.seq,
      id: r.id,
      scope: r.scope,
      action: r.action,
      inactive: Boolean(r.inactive_reason),
    };
    const prev = map.get(r.name);
    if (!prev) {
      map.set(r.name, entry);
    } else {
      // The same name in several zone pairs: keep every match, and the union of zones.
      if (!prev.all) prev.all = [{ ...prev }];
      prev.all.push(entry);
      prev.ambiguous = true;
      prev.from = [...new Set([...prev.from, ...entry.from])];
      prev.to = [...new Set([...prev.to, ...entry.to])];
    }
  }
  S.policyIdx = map;
  S.policyIdxFor = snap;
  return map;
}

function setSessionsLast(payload) {
  S.sessionsLast = payload || null;
  renderRailMeta();
  emit('sessions', S.sessionsLast);
}

function makeStore(record) {
  return {
    get session() {
      return publicSession();
    },
    get scope() {
      return S.scope;
    },
    inventory,
    get lastInventory() {
      return S.lastInventory;
    },
    get inventoryError() {
      return S.invError;
    },
    policyIndex,
    get sessionsLast() {
      return S.sessionsLast;
    },
    setSessionsLast,
    on(event, fn) {
      if (!listeners[event]) throw new TypeError(`unknown store event: ${event}`);
      listeners[event].add(fn);
      const off = () => listeners[event].delete(fn);
      if (record) record.offs.add(off);
      return off;
    },
  };
}

// ---- live badges ---------------------------------------------------------------------------------

function setLive(viewId, on, record) {
  if (!VIEW_BY_ID.has(viewId)) return;
  if (on) S.live.add(viewId);
  else S.live.delete(viewId);
  if (record) {
    if (on) record.live.add(viewId);
    else record.live.delete(viewId);
  }
  renderRailMeta();
}

// ---- routing -------------------------------------------------------------------------------------

function parseHash(raw) {
  if (!raw || !raw.startsWith('#/')) return null;
  const body = raw.slice(2);
  const qi = body.indexOf('?');
  const path = qi >= 0 ? body.slice(0, qi) : body;
  const query = qi >= 0 ? body.slice(qi + 1) : '';
  const id = path.split('/')[0];
  return { view: VIEW_BY_ID.has(id) ? id : 'overview', params: new URLSearchParams(query) };
}

function toParams(params) {
  if (params instanceof URLSearchParams) return new URLSearchParams(params);
  const sp = new URLSearchParams();
  if (params && typeof params === 'object') {
    for (const [k, v] of Object.entries(params)) {
      if (v === undefined || v === null || v === '') continue;
      if (Array.isArray(v)) v.forEach((x) => sp.append(k, String(x)));
      else sp.set(k, String(v));
    }
  }
  return sp;
}

function withScope(sp) {
  if (!sp.has('scope') && S.scope !== 'root') sp.set('scope', S.scope);
  if (sp.get('scope') === 'root') sp.delete('scope');
  return sp;
}

function hashFor(view, sp) {
  const qs = sp.toString();
  return `#/${view}${qs ? `?${qs}` : ''}`;
}

function routeCopy() {
  return { view: S.route.view, params: new URLSearchParams(S.route.params) };
}

/** ctx.navigate(viewId, params): a new history entry; the current scope is kept. */
function navigate(viewId, params) {
  const id = VIEW_BY_ID.has(viewId) ? viewId : 'overview';
  const sp = withScope(toParams(params));
  const hash = hashFor(id, sp);
  if (hash === location.hash) {
    S.lastHash = null;
    onRoute();
    return;
  }
  location.hash = hash;
}

/** ctx.setParams(params, { replace = true }): change the current view's URL state without remounting. */
function setParams(params, { replace = true } = {}) {
  const sp = withScope(toParams(params));
  const hash = hashFor(S.route.view, sp);
  if (hash === location.hash) return;
  if (replace) history.replaceState(null, '', hash);
  else history.pushState(null, '', hash);
  S.lastHash = hash;
  S.route = { view: S.route.view, params: sp };
  rememberQuery(S.route);
  updateRailLinks();
}

function rememberQuery(route) {
  const q = route.params.get('q');
  if (!q) return;
  const key = `${route.view}|${q}`;
  S.recent = [{ key, view: route.view, q, params: route.params.toString() }, ...S.recent.filter((r) => r.key !== key)].slice(0, 8);
}

function onRoute() {
  if (!S.session) return;
  const raw = location.hash;
  if (raw === S.lastHash) return;
  const parsed = parseHash(raw);
  if (!parsed) {
    if (!raw || raw === '#' || raw === '#/') {
      history.replaceState(null, '', hashFor('overview', withScope(new URLSearchParams())));
      onRoute();
    }
    return; // an in-page anchor (the skip link): not a route
  }
  S.lastHash = raw;
  // The hash is the whole truth about scope: no scope parameter means the root system (withScope()
  // drops scope=root), so Back to an older root entry and navigate(view, { scope: 'root' }) both work.
  const asked = parsed.params.get('scope');
  const scope = asked && SCOPE_RE.test(asked) ? asked : 'root';
  let scopeChanged = false;
  if (scope !== S.scope) {
    S.scope = scope;
    scopeChanged = true;
  }
  const sameView = S.current && S.current.id === parsed.view;
  S.route = parsed;
  rememberQuery(parsed);
  if (scopeChanged) scopeDidChange();
  markRail(parsed.view);
  if (!sameView) {
    mountView(parsed.view);
  } else if (S.current.handle && typeof S.current.handle.update === 'function') {
    try {
      S.current.handle.update(routeCopy());
    } catch (err) {
      console.error(err);
    }
  }
}

// ---- views ---------------------------------------------------------------------------------------

async function loadEngines() {
  if (S.engines) return S.engines;
  const [query, logparse, querybar] = await Promise.allSettled([
    import('./query.js'),
    import('./logparse.js'),
    import('./widgets/querybar.js'),
  ]);
  const ok = (r) => (r.status === 'fulfilled' ? r.value : null);
  for (const [name, r] of [['query.js', query], ['logparse.js', logparse], ['widgets/querybar.js', querybar]]) {
    if (r.status === 'rejected') console.warn(`J-Wicket: ${name} did not load`, r.reason);
  }
  S.engines = {
    query: ok(query),
    logparse: ok(logparse),
    QueryBar: ok(querybar) && typeof ok(querybar).QueryBar === 'function' ? ok(querybar).QueryBar : null,
  };
  return S.engines;
}

function loadView(id) {
  if (!S.viewModules.has(id)) {
    // The id comes from the fixed VIEWS list, never from the URL directly.
    const loader = {
      overview: () => import('./views/overview.js'),
      policies: () => import('./views/policies.js'),
      sessions: () => import('./views/sessions.js'),
      logs: () => import('./views/logs.js'),
      objects: () => import('./views/objects.js'),
    }[id];
    const p = loader().catch((err) => {
      S.viewModules.delete(id);
      throw err;
    });
    S.viewModules.set(id, p);
  }
  return S.viewModules.get(id);
}

function makeCtx(record) {
  const engines = S.engines || {};
  return {
    api: { get: api.get, post: api.post },
    get route() {
      return routeCopy();
    },
    navigate,
    /** The hash navigate(viewId, params) would set: for href attributes, so open-in-new-tab and
        copy-link keep the filters and the scope. */
    href: (viewId, params) => hashFor(VIEW_BY_ID.has(viewId) ? viewId : 'overview', withScope(toParams(params))),
    setParams,
    store: makeStore(record),
    ui: {
      toast,
      panel: openPanel,
      closePanel,
      announce,
      setLive: (viewId, on) => setLive(viewId, Boolean(on), record),
      noteFixture,
      copy,
      toggleDensity,
      exportInventory: (fmt, scope) => exportInventory(fmt, scope || S.scope),
    },
    query: engines.query,
    logparse: engines.logparse,
    QueryBar: engines.QueryBar,
    dom,
    format,
  };
}

function unmountCurrent() {
  const rec = S.current;
  if (!rec) return;
  S.current = null;
  try {
    if (rec.handle && typeof rec.handle.unmount === 'function') rec.handle.unmount();
  } catch (err) {
    console.error(err);
  }
  for (const off of rec.offs) off();
  rec.offs.clear();
  for (const id of rec.live) S.live.delete(id);
  rec.live.clear();
  renderRailMeta();
  closePanel();
}

async function mountView(id) {
  const seq = (S.mountSeq += 1);
  unmountCurrent();
  const meta = VIEW_BY_ID.get(id);
  const el = h('section', { class: 'view', dataset: { view: id }, 'aria-label': meta.title });
  el.append(h('p', { class: 'view-loading' }, `Loading ${meta.title}…`));
  const main = $('main');
  put(main, el);
  main.scrollTop = 0;
  updateTitle();
  let mod;
  try {
    mod = await loadView(id);
  } catch (err) {
    if (seq !== S.mountSeq) return;
    put(el, 
      stateCard({
        status: 'failed',
        title: `The ${meta.title} view did not load`,
        message: String((err && err.message) || err),
        hint: 'Reload the page. If it keeps failing, the J-Wicket build on this device may be incomplete.',
      }),
    );
    return;
  }
  if (seq !== S.mountSeq || !S.session) return;
  const record = { id, el, handle: null, offs: new Set(), live: new Set() };
  el.replaceChildren();
  S.current = record;
  try {
    const view = mod && mod.view;
    if (!view || typeof view.mount !== 'function') throw new TypeError(`views/${id}.js exports no view.mount`);
    record.handle = view.mount(el, makeCtx(record)) || null;
  } catch (err) {
    console.error(err);
    put(el, 
      stateCard({ status: 'failed', title: `The ${meta.title} view failed to start`, message: String((err && err.message) || err) }),
    );
  }
  if (document.activeElement === document.body || !document.activeElement) main.focus({ preventScroll: true });
  say(`${meta.title}`);
}

function updateTitle() {
  const meta = VIEW_BY_ID.get(S.route.view) || VIEWS[0];
  const dev = S.lastInventory && S.lastInventory.device;
  const host = dev && dev.status === 'ok' && dev.hostname ? dev.hostname : null;
  document.title = [meta.title, host, 'J-Wicket'].filter(Boolean).join(SEP);
}

// ---- scope ---------------------------------------------------------------------------------------

function scopeKind(id) {
  if (id.startsWith('lsys:')) return 'lsys';
  if (id.startsWith('tenant:')) return 'tenant';
  return 'root';
}

function scopeLabel(id) {
  const snap = S.lastInventory || S.inv.get('root');
  const known = snap && (snap.meta.scopes || []).find((s) => s.id === id);
  if (known) return known.label;
  if (id === 'root') return 'Root system';
  const [kind, name] = id.split(':');
  return `${kind === 'lsys' ? 'Logical system' : 'Tenant system'} ${name}`;
}

function scopeDidChange() {
  S.lastInventory = S.inv.get(S.scope) || null;
  S.policyIdx = null;
  closeScopeMenu();
  renderTopbar();
  updateRailLinks();
  emit('scope', S.scope);
  if (S.lastInventory) emit('inventory', S.lastInventory);
  inventory();
}

function setScope(id) {
  if (!SCOPE_RE.test(id) || id === S.scope) return;
  S.scope = id;
  const sp = new URLSearchParams(S.route.params);
  if (id === 'root') sp.delete('scope');
  else sp.set('scope', id);
  const hash = hashFor(S.route.view, sp);
  history.replaceState(null, '', hash);
  S.lastHash = hash;
  S.route = { view: S.route.view, params: sp };
  scopeDidChange();
  say(`Scope: ${scopeLabel(id)}`);
  if (S.current && S.current.handle && typeof S.current.handle.update === 'function') {
    try {
      S.current.handle.update(routeCopy());
    } catch (err) {
      console.error(err);
    }
  }
}

// ---- top bar -------------------------------------------------------------------------------------

function logoMark() {
  const { svg } = dom;
  return svg(
    'svg',
    { class: 'logo-mark', viewBox: '0 0 48 48', 'aria-hidden': 'true', focusable: 'false' },
    svg('rect', { class: 'lg-stump', x: 10, y: 15, width: 6, height: 29, rx: 3 }),
    svg('rect', { class: 'lg-stump', x: 21, y: 15, width: 6, height: 29, rx: 3 }),
    svg('rect', { class: 'lg-stump', x: 32, y: 15, width: 6, height: 29, rx: 3 }),
    svg('rect', { class: 'lg-bail', x: 9.5, y: 8.6, width: 15, height: 4.6, rx: 2.3 }),
    svg('rect', { class: 'lg-bail', x: 25, y: 4.4, width: 15, height: 4.6, rx: 2.3, transform: 'rotate(-17 32.5 6.7)' }),
  );
}

function modelName(model) {
  if (!model) return '';
  return String(model).toUpperCase().replace(/^VSRX/, 'vSRX');
}

/** A short HA label for chips: "standalone", "RG0 primary node0", "MNHA". */
function haSummary(ha) {
  if (!ha) return { text: 'HA ?', cls: '' };
  if (ha.status && ha.status !== 'ok') return { text: `HA ${ha.status}`, cls: '' };
  if (ha.mode === 'standalone') return { text: 'standalone', cls: '' };
  if (ha.mode === 'chassis-cluster') {
    const rg0 = (ha.redundancy_groups || []).find((g) => String(g.id) === '0');
    const primary = rg0 && (rg0.nodes || []).find((n) => String(n.status || '').toLowerCase() === 'primary');
    return { text: primary ? `RG0 primary ${primary.name}` : `cluster ${ha.cluster_id || ''}`.trim(), cls: 'cluster' };
  }
  if (ha.mode === 'mnha') return { text: 'MNHA', cls: 'cluster' };
  return { text: 'HA unknown', cls: '' };
}

const TB = {};

function buildTopbar() {
  const bar = $('topbar');
  TB.device = h('button', {
    id: 'chip-device',
    class: 'chip chip-device',
    type: 'button',
    on: { click: openDevicePanel },
  });
  TB.scopeBtn = h('button', {
    id: 'chip-scope',
    class: 'chip chip-scope',
    type: 'button',
    'aria-haspopup': 'listbox',
    'aria-expanded': 'false',
    on: { click: toggleScopeMenu, keydown: onScopeButtonKey },
  });
  TB.scopeWrap = h('div', { class: 'scope-switch' }, TB.scopeBtn);
  TB.readAs = h('span', { id: 'chip-readas', class: 'chip chip-readas' });
  TB.managed = h('button', { id: 'chip-managed', class: 'chip chip-managed', type: 'button', hidden: true, on: { click: openManagedPanel } });
  TB.theme = h('button', { id: 'btn-theme', class: 'btn ghost icon', type: 'button', on: { click: toggleTheme } });
  TB.search = h(
    'button',
    { id: 'btn-palette', class: 'cmdk', type: 'button', 'aria-label': 'Jump to a view, policy, zone or action (Ctrl K)', on: { click: () => palette.open() } },
    icon('search'),
    h('span', { class: 'label' }, 'Jump to\u2026'),
    h('span', { class: 'keys', 'aria-hidden': 'true' }, h('kbd', null, IS_MAC ? '⌘' : 'Ctrl'), h('kbd', null, 'K')),
  );
  TB.signout = h(
    'button',
    { id: 'btn-signout', class: 'btn ghost', type: 'button', title: 'Sign out and close your device session', on: { click: signOut } },
    icon('signout'),
    h('span', { class: 'tb-signout-label' }, 'Sign out'),
  );
  put(bar, 
    h(
      'a',
      { class: 'tb-brand', href: '#/overview', 'aria-label': 'J-Wicket overview', on: { click: (e) => { e.preventDefault(); navigate('overview', {}); } } },
      logoMark(),
      h('span', { class: 'wordmark' }, 'J-Wicket'),
      h('span', { class: 'ro-badge', title: 'This build has no code path that changes the device configuration.' }, icon('lock'), 'READ-ONLY'),
    ),
    h('span', { class: 'tb-divider', 'aria-hidden': 'true' }),
    h('div', { class: 'tb-ctx', role: 'group', 'aria-label': 'What you are looking at' }, TB.device, TB.scopeWrap, TB.readAs, TB.managed),
    h('div', { class: 'tb-actions' }, TB.search, TB.theme, TB.signout),
  );
  renderTopbar();
}

function renderDeviceChip() {
  const chip = TB.device;
  if (!chip) return;
  const snap = S.lastInventory;
  const dev = snap && snap.device;
  if (!snap) {
    const failed = S.invError && !S.reading;
    put(chip, 
      h('span', { class: ['status-dot', failed ? 'bad' : 'idle'] }),
      h('span', { class: 'host' }, failed ? 'device not read' : 'reading device…'),
    );
    chip.title = failed ? S.invError.message : 'Reading the device';
    return;
  }
  const ha = haSummary(snap.ha);
  const configOk = !snap.config || snap.config.status === 'ok';
  const dotCls = S.reading ? 'idle' : dev && dev.status === 'ok' ? (configOk ? '' : 'warn') : 'bad';
  if (dev && dev.status === 'ok') {
    put(chip, 
      h('span', { class: ['status-dot', dotCls] }),
      h('span', { class: 'host' }, dev.hostname || 'unnamed device'),
      dev.model ? h('span', { class: 'dim model shrink first' }, modelName(dev.model)) : null,
      dev.version ? h('span', { class: 'dim ver shrink' }, dev.version) : null,
      h('span', { class: ['ha-badge', ha.cls] }, ha.text),
    );
    chip.title = `${dev.hostname || ''}${SEP}${modelName(dev.model)}${SEP}Junos ${dev.version || '?'}${SEP}${ha.text}. Details: device panel.`;
  } else {
    put(chip, 
      h('span', { class: ['status-dot', 'bad'] }),
      h('span', { class: 'host' }, `device facts ${dev ? dev.status : 'missing'}`),
      h('span', { class: ['ha-badge', ha.cls] }, ha.text),
    );
    chip.title = (dev && dev.message) || 'The device facts could not be read.';
  }
  chip.setAttribute('aria-label', `Device: ${chip.textContent}. Open device details.`);
}

function renderTopbar() {
  if (!TB.device) return;
  renderDeviceChip();
  // scope
  const snap = S.lastInventory;
  const scopes = (snap && snap.meta && snap.meta.scopes) || [];
  const current = scopes.find((s) => s.id === S.scope);
  const kind = scopeKind(S.scope);
  put(TB.scopeBtn, 
    icon(kind === 'root' ? 'server' : kind === 'lsys' ? 'layers' : 'tenant'),
    h('span', { class: 'ellipsis' }, scopeLabel(S.scope)),
    current && current.inactive ? h('span', { class: 'pill reject' }, 'deactivated') : null,
    icon('chevron-down', { class: 'chev' }),
  );
  TB.scopeBtn.setAttribute('aria-label', `Scope: ${scopeLabel(S.scope)}. Change scope.`);
  // read as
  const ra = (snap && snap.meta && snap.meta.read_as) || (S.session ? { user: S.session.user, backend: S.session.backend } : {});
  const lab = ra.backend === 'lab-token';
  TB.readAs.className = `chip chip-readas${lab ? ' amber' : ''}`;
  put(TB.readAs, 
    icon(lab ? 'token' : 'user'),
    lab ? h('span', null, 'lab token: as ') : h('span', { class: 'muted' }, 'as'),
    h('b', { class: 'mono' }, ra.user || '?'),
  );
  TB.readAs.title = lab
    ? `Lab sign-in: every read runs as the daemon's Junos account ${ra.user || ''}, not as you. Your own login class is not applied.`
    : ra.backend === 'fixture'
      ? 'Fixture replay on the development server, not a Junos session.'
      : `Read with your own Junos session as ${ra.user || '?'}: your login class decides what you can see.`;
  // managed from
  const mg = snap && snap.management;
  if (mg && mg.status === 'ok' && mg.managed) {
    const names = (mg.clients || []).map((c) => c.client);
    TB.managed.hidden = false;
    TB.managed.className = 'chip chip-managed gold';
    put(TB.managed, 
      icon('broadcast'),
      h('span', { class: 'muted shrink first' }, 'managed from'),
      h('b', { class: 'mono shrink' }, names[0] || 'outbound SSH'),
      names.length > 1 ? h('span', { class: 'pill gold' }, `+${names.length - 1}`) : null,
    );
    TB.managed.title = 'Another system holds a management connection to this device. Changes made there may overwrite this configuration.';
  } else if (mg && mg.status !== 'ok') {
    TB.managed.hidden = false;
    TB.managed.className = 'chip chip-managed';
    put(TB.managed, icon('broadcast'), h('span', { class: 'muted shrink' }, 'managed from: unknown'));
    TB.managed.title = `Central management is read from the configuration, which could not be read (${mg.status}). Another system may also manage this device.`;
  } else {
    TB.managed.hidden = true;
  }
  updateThemeButton();
  updateTitle();
}

function updateThemeButton() {
  if (!TB.theme) return;
  const next = effectiveTheme() === 'light' ? 'dark' : 'light';
  put(TB.theme, icon(next === 'light' ? 'sun' : 'moon'));
  TB.theme.setAttribute('aria-label', `Switch to the ${next === 'light' ? 'day (light)' : 'night (dark)'} theme (t)`);
  TB.theme.title = `${next === 'light' ? 'Day' : 'Night'} theme (t)`;
}

// scope menu

let scopeMenu = null;

function closeScopeMenu(focusButton = false) {
  if (!scopeMenu) return;
  scopeMenu.remove();
  scopeMenu = null;
  TB.scopeBtn.setAttribute('aria-expanded', 'false');
  document.removeEventListener('mousedown', onDocMouseDown, true);
  if (focusButton) TB.scopeBtn.focus();
}

function onDocMouseDown(e) {
  if (scopeMenu && !scopeMenu.contains(e.target) && !TB.scopeBtn.contains(e.target)) closeScopeMenu();
}

function placeScopeMenu() {
  if (!scopeMenu) return;
  const r = TB.scopeBtn.getBoundingClientRect();
  const width = Math.min(320, window.innerWidth - 16);
  scopeMenu.style.top = `${Math.round(r.bottom + 6)}px`;
  scopeMenu.style.left = `${Math.round(Math.max(8, Math.min(r.left, window.innerWidth - width - 8)))}px`;
  scopeMenu.style.width = `${width}px`;
}

function toggleScopeMenu() {
  if (scopeMenu) closeScopeMenu();
  else openScopeMenu();
}

function onScopeButtonKey(e) {
  if (e.key === 'ArrowDown' && !scopeMenu) {
    e.preventDefault();
    openScopeMenu();
  }
}

function openScopeMenu() {
  const snap = S.lastInventory;
  let scopes = (snap && snap.meta && snap.meta.scopes) || [];
  if (!scopes.length) scopes = [{ id: S.scope, label: scopeLabel(S.scope), policies: null, inactive: false }];
  const options = scopes.map((s, i) => {
    const kind = scopeKind(s.id);
    return h(
      'div',
      {
        role: 'option',
        id: `scope-opt-${i}`,
        tabindex: '-1',
        'aria-selected': s.id === S.scope ? 'true' : 'false',
        dataset: { scope: s.id },
        on: {
          click: () => {
            closeScopeMenu(true);
            setScope(s.id);
          },
        },
      },
      icon(kind === 'root' ? 'server' : kind === 'lsys' ? 'layers' : 'tenant'),
      h('span', { class: 'opt-label' }, s.label),
      s.inactive ? h('span', { class: 'pill reject' }, 'deactivated') : null,
      s.policies !== null && s.policies !== undefined ? h('span', { class: 'opt-meta' }, format.plural(s.policies, 'policy')) : null,
    );
  });
  const note =
    scopes.length < 2
      ? h('p', { class: 'menu-head' }, snap && snap.scope ? 'No logical or tenant systems configured' : 'Scopes are listed once the configuration can be read')
      : null;
  scopeMenu = h(
    'div',
    {
      class: 'menu',
      role: 'listbox',
      'aria-label': 'Scope',
      on: {
        keydown: (e) => {
          const opts = [...scopeMenu.querySelectorAll('[role="option"]')];
          const at = opts.indexOf(document.activeElement);
          if (e.key === 'ArrowDown') {
            e.preventDefault();
            opts[Math.min(opts.length - 1, at + 1)].focus({ preventScroll: true });
          } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            opts[Math.max(0, at - 1)].focus({ preventScroll: true });
          } else if (e.key === 'Home') {
            e.preventDefault();
            opts[0].focus();
          } else if (e.key === 'End') {
            e.preventDefault();
            opts[opts.length - 1].focus();
          } else if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            if (at >= 0) opts[at].click();
          } else if (e.key === 'Escape') {
            e.preventDefault();
            e.stopPropagation();
            closeScopeMenu(true);
          } else if (e.key === 'Tab') {
            closeScopeMenu();
          }
        },
      },
    },
    h('div', { class: 'menu-head' }, 'Scope'),
    options,
    note,
  );
  // Rendered at body level: the chip row clips its overflow (and focus would scroll it).
  scopeMenu.classList.add('menu-fixed');
  document.body.append(scopeMenu);
  placeScopeMenu();
  TB.scopeBtn.setAttribute('aria-expanded', 'true');
  document.addEventListener('mousedown', onDocMouseDown, true);
  const selected = scopeMenu.querySelector('[aria-selected="true"]') || scopeMenu.querySelector('[role="option"]');
  if (selected) selected.focus({ preventScroll: true });
}

// device and management panels (rule 10: what am I looking at, on every screen)

function fact(label, ...value) {
  return [h('dt', null, label), h('dd', null, ...value)];
}

function deviceFacts(snap) {
  const out = [];
  const dev = snap.device || {};
  if (dev.status === 'ok') {
    out.push(...fact('Device', h('span', { class: 'mono strong' }, dev.hostname || '?'), h('span', { class: 'note' }, `${modelName(dev.model) || 'model not reported'}${SEP}Junos ${dev.version || 'not reported'}`)));
    const versions = [...new Set((dev.nodes || []).map((n) => n.version).filter(Boolean))];
    if (versions.length > 1) out.push(...fact('Releases', h('span', { class: 'act-reject' }, `Nodes report different releases: ${versions.join(', ')}`)));
  } else {
    out.push(...fact('Device', stateCard({ status: dev.status || 'failed', message: dev.message, compact: true })));
  }
  const ha = snap.ha || {};
  if (ha.status && ha.status !== 'ok') {
    out.push(...fact('High availability', stateCard({ status: ha.status, message: ha.message, compact: true })));
  } else if (ha.mode === 'chassis-cluster') {
    const nodes = (dev.nodes || []).reduce((m, n) => m.set(n.node, n.hostname), new Map());
    out.push(
      ...fact(
        'High availability',
        h('span', null, `Chassis cluster${ha.cluster_id ? ` ${ha.cluster_id}` : ''}`),
        (ha.redundancy_groups || []).map((g) =>
          h(
            'span',
            { class: 'rg-row' },
            h('span', { class: 'rg-id' }, `RG${g.id}`),
            (g.nodes || []).map((n) =>
              h(
                'span',
                { class: ['rg-node', String(n.status || '').toLowerCase() === 'primary' && 'primary'] },
                `${n.name}${nodes.get(n.name) ? ` (${nodes.get(n.name)})` : ''}`,
                h('span', { class: 'prio' }, `${n.status || '?'} ${n.priority || ''}`.trim()),
              ),
            ),
          ),
        ),
        h('span', { class: 'note' }, ha.local_node ? `This page is served by ${ha.local_node}.` : 'Which node serves this page is not reported.'),
      ),
    );
  } else {
    out.push(...fact('High availability', h('span', null, ha.mode === 'mnha' ? 'Multinode High Availability' : ha.mode === 'standalone' ? 'Standalone' : 'Unknown'), ha.message ? h('span', { class: 'note' }, ha.message) : null));
  }
  const meta = snap.meta || {};
  const scopeInv = snap.scope;
  out.push(
    ...fact(
      'Scope',
      h('span', null, scopeLabel(meta.scope || S.scope)),
      scopeInv && scopeInv.inactive ? h('span', { class: 'act-reject' }, 'Deactivated in the configuration: nothing in this scope is in effect.') : null,
    ),
  );
  const ra = meta.read_as || {};
  out.push(
    ...fact(
      'Read as',
      h('span', { class: 'mono strong' }, ra.user || '?'),
      h(
        'span',
        { class: 'note' },
        ra.backend === 'lab-token'
          ? `Lab sign-in: every read runs as the daemon's Junos account ${ra.user || ''}, not as you.`
          : ra.backend === 'fixture'
            ? 'Fixture replay on the development server, not a Junos session.'
            : 'Your own Junos session: your login class decides what you can see.',
      ),
    ),
  );
  const src = meta.source || {};
  out.push(
    ...fact(
      'Source',
      h('span', null, `${src.database === 'committed' ? 'Committed configuration' : `${src.database || 'Unknown'} configuration`}${SEP}${src.inheritance ? 'inheritance expanded' : 'inheritance not expanded'}`),
      h('span', { class: 'note' }, `Read ${format.stamp(meta.read_at)} (${format.ago(meta.read_at)})`),
      src.groups_annotated ? h('span', { class: 'note' }, 'Each object says which configuration group it came from.') : null,
    ),
  );
  const mg = snap.management || {};
  out.push(...fact('Central management', managementSummary(mg, snap.config || {})));
  if (S.session && S.session.idle_timeout_s) {
    out.push(...fact('J-Wicket session', h('span', null, `Ends after ${Math.round(S.session.idle_timeout_s / 60)} min without activity.`), h('span', { class: 'note' }, 'Nothing read from the device is kept in this browser.')));
  }
  return h('dl', { class: 'facts-grid' }, out);
}

function managementSummary(mg, cfg) {
  if (mg.status !== 'ok') {
    const known = cfg.status && cfg.status !== 'ok';
    return stateCard({
      status: mg.status || 'failed',
      title: 'Not known',
      message: known ? 'It is read from the configuration, which could not be read.' : mg.message,
      hint: 'Another system may also manage this device.',
      compact: true,
    });
  }
  if (!mg.managed) return h('span', { class: 'muted' }, 'No outbound-SSH management client is configured.');
  return h(
    'div',
    null,
    (mg.clients || []).map((c) =>
      h(
        'div',
        { class: 'mg-client' },
        h('span', { class: 'mg-name' }, icon('broadcast'), c.client),
        (c.targets || []).length ? h('span', { class: 'mg-targets' }, c.targets.map((t) => h('span', { class: 'zone' }, t))) : null,
        (c.services || []).length ? h('span', { class: 'mg-targets' }, c.services.map((s) => h('span', { class: 'pill gold' }, s))) : null,
      ),
    ),
    h('p', { class: 'mg-note' }, 'Another system holds a management connection to this device. Changes made there may overwrite this configuration, and what you see here can change without J-Wicket knowing.'),
  );
}

function openDevicePanel() {
  const snap = S.lastInventory;
  const content = snap
    ? h('div', { class: 'panel-section' }, deviceFacts(snap))
    : stateCard(
        S.invError
          ? { status: S.invError.status === 0 ? 'offline' : 'failed', message: S.invError.message }
          : { status: 'loading', message: 'The device is being read.', code: false },
      );
  openPanel({ title: 'What you are looking at', content });
}

function openManagedPanel() {
  const snap = S.lastInventory;
  if (!snap) return;
  openPanel({ title: 'Central management', content: h('div', { class: 'panel-section' }, managementSummary(snap.management || {}, snap.config || {})) });
}

// ---- rail ----------------------------------------------------------------------------------------

const RAIL = {};

function buildRail() {
  const nav = $('rail');
  RAIL.items = new Map();
  const list = h(
    'ul',
    null,
    VIEWS.map((v) => {
      const meta = h('span', { class: 'rail-meta' });
      const link = h(
        'a',
        {
          class: 'rail-item',
          href: hashFor(v.id, withScope(new URLSearchParams())),
          dataset: { view: v.id },
          title: `${v.title}${SEP}g ${v.key}`,
          on: {
            click: (e) => {
              if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0) return;
              e.preventDefault();
              navigate(v.id, {});
            },
          },
        },
        icon(v.icon, { size: 18 }),
        h('span', { class: 'rail-label' }, v.title),
        meta,
        h('span', { class: 'live-dot', 'aria-hidden': 'true' }),
      );
      RAIL.items.set(v.id, { link, meta });
      return h('li', null, link);
    }),
  );
  RAIL.foot = h('div', { class: 'rail-foot' });
  put(nav, h('div', { class: 'rail-section' }, 'Console'), list, RAIL.foot);
  renderRailFoot();
  markRail(S.route.view);
  renderRailMeta();
}

function renderRailFoot() {
  if (!RAIL.foot) return;
  const comfy = document.documentElement.dataset.density === 'comfortable';
  const collapsed = railCollapsed();
  const btn = (label, iconName, onClick, extra = {}) =>
    h('button', { class: 'rail-item', type: 'button', title: label, 'aria-label': label, on: { click: onClick }, ...extra }, icon(iconName), h('span', { class: 'rail-label' }, label));
  const version = (S.session && S.session.version) || (S.server && S.server.version) || '';
  put(RAIL.foot, 
    btn('Keyboard shortcuts', 'keyboard', showKeys),
    btn(comfy ? 'Dense rows' : 'Comfortable rows', 'rows', toggleDensity, { 'aria-pressed': comfy ? 'true' : 'false' }),
    btn(collapsed ? 'Expand the rail' : 'Collapse the rail', 'sidebar', toggleRail),
    h('div', { class: 'rail-ver' }, `J-Wicket ${version}`.trim(), h('br'), 'read-only build'),
  );
}

function markRail(viewId) {
  if (!RAIL.items) return;
  for (const [id, { link }] of RAIL.items) {
    if (id === viewId) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
  }
}

function updateRailLinks() {
  if (!RAIL.items) return;
  for (const [id, { link }] of RAIL.items) link.setAttribute('href', hashFor(id, withScope(new URLSearchParams())));
}

function renderRailMeta() {
  if (!RAIL.items) return;
  const snap = S.lastInventory;
  const pol = snap && snap.scope && snap.scope.policies;
  const counts = {
    policies: pol && pol.status === 'ok' ? format.num((pol.rows || []).length) : '',
    sessions: S.sessionsLast && S.sessionsLast.summary && S.sessionsLast.summary.status === 'ok' ? format.compact(S.sessionsLast.summary.active) : '',
  };
  for (const [id, { link, meta }] of RAIL.items) {
    const live = S.live.has(id);
    link.classList.toggle('is-live', live);
    if (live) {
      put(meta, h('span', { class: 'live-badge' }, h('span', { class: 'dot', 'aria-hidden': 'true' }), 'LIVE'));
    } else {
      put(meta, counts[id] || '');
    }
    const v = VIEW_BY_ID.get(id);
    link.setAttribute('aria-label', `${v.title}${live ? ', live' : ''}${counts[id] ? `, ${counts[id]}` : ''}`);
  }
}

// ---- command palette and shortcuts ---------------------------------------------------------------

function quoteValue(v) {
  const s = String(v);
  return /^[A-Za-z0-9._\-/*]+$/.test(s) ? s : `"${s.replace(/"/g, '\\"')}"`;
}

function dispatch(name, detail) {
  document.dispatchEvent(new CustomEvent(`jwicket:${name}`, { detail }));
}

function refresh() {
  dispatch('refresh');
  if (!S.current || S.current.id !== 'overview') inventory(true);
  toast('Refreshing from the device…', 'info');
}

/** Export the inventory (a fresh device read) as a file. Fetched, then saved from a Blob, so that a
    429 or 401 reply is shown as a message and never saved as the export. */
async function exportInventory(fmt, scope = S.scope) {
  if (fmt !== 'json' && fmt !== 'csv') return false;
  if (!SCOPE_RE.test(scope)) return false;
  const gen = S.gen;
  const label = scopeLabel(scope);
  toast(`Exporting ${label} as ${fmt.toUpperCase()}: a fresh read of the device, not a copy of this page.`, 'info');
  let res = await api.download('/api/export', { scope, format: fmt });
  // api.js waits out the Retry-After before the next call for the same endpoint.
  if (res.status === 429 && gen === S.gen) res = await api.download('/api/export', { scope, format: fmt });
  if (gen !== S.gen) return false;
  if (!res.ok) {
    if (res.status !== 401) toast((res.data && res.data.error) || `The export failed (HTTP ${res.status}).`, 'error');
    return false;
  }
  const url = URL.createObjectURL(res.blob);
  const link = h('a', { href: url, download: res.filename || `jwicket-${scope.replace(/[^A-Za-z0-9._-]/g, '_')}.${fmt}`, class: 'sr-only' });
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30000);
  toast(`Saved ${res.filename || `the ${fmt.toUpperCase()} export`}.`, 'ok');
  return true;
}

function paletteItems() {
  const items = [];
  for (const v of VIEWS) {
    items.push({ group: 'Views', label: `Go to ${v.title}`, detail: v.sub, hint: ['g', v.key], icon: v.icon, keywords: v.id, run: () => navigate(v.id, {}) });
  }
  const anyLive = S.live.size > 0;
  const nextTheme = effectiveTheme() === 'light' ? 'night (dark)' : 'day (light)';
  const comfy = document.documentElement.dataset.density === 'comfortable';
  items.push(
    { group: 'Actions', label: 'Refresh from the device', hint: ['r'], icon: 'refresh', keywords: 'reload read again', run: refresh },
    { group: 'Actions', label: anyLive ? 'Pause or resume live updates' : 'Pause or resume live updates (in Sessions and Logs)', hint: ['Space'], icon: 'pause', keywords: 'live poll stop start', run: () => dispatch('toggle-live') },
    { group: 'Actions', label: `Switch to the ${nextTheme} theme`, hint: ['t'], icon: effectiveTheme() === 'light' ? 'moon' : 'sun', keywords: 'theme dark light colour color', run: toggleTheme },
    { group: 'Actions', label: comfy ? 'Use dense rows' : 'Use comfortable rows', icon: 'rows', keywords: 'density compact spacing', run: toggleDensity },
    { group: 'Actions', label: railCollapsed() ? 'Expand the rail' : 'Collapse the rail', hint: ['['], icon: 'sidebar', keywords: 'sidebar navigation', run: toggleRail },
    { group: 'Actions', label: 'Show keyboard shortcuts', hint: ['?'], icon: 'keyboard', keywords: 'help keys', run: showKeys },
    { group: 'Actions', label: 'What you are looking at (device details)', icon: 'server', keywords: 'device identity ha cluster release read as source', run: openDevicePanel },
    { group: 'Actions', label: 'Copy a link to this view', icon: 'link', keywords: 'share url', run: () => copy(location.href, 'Link copied. It holds the view and its filters, not device data.') },
    { group: 'Actions', label: 'Export the policy inventory as JSON', icon: 'download', keywords: 'download snapshot', run: () => exportInventory('json') },
    { group: 'Actions', label: 'Export the policy inventory as CSV', icon: 'download', keywords: 'download spreadsheet', run: () => exportInventory('csv') },
    { group: 'Actions', label: 'Sign out', icon: 'signout', keywords: 'logout log out exit', run: signOut },
  );
  const snap = S.lastInventory;
  for (const s of (snap && snap.meta && snap.meta.scopes) || []) {
    if (s.id === S.scope) continue;
    const kind = scopeKind(s.id);
    items.push({
      group: 'Scopes',
      label: `Switch scope to ${s.label}`,
      detail: `${format.plural(s.policies, 'policy')}${s.inactive ? `${SEP}deactivated` : ''}`,
      icon: kind === 'root' ? 'server' : kind === 'lsys' ? 'layers' : 'tenant',
      keywords: `${s.id} scope lsys tsys tenant logical`,
      run: () => setScope(s.id),
    });
  }
  for (const r of S.recent) {
    const v = VIEW_BY_ID.get(r.view);
    items.push({
      group: 'Recent filters',
      label: r.q,
      detail: v.title,
      icon: v.icon,
      keywords: v.title,
      boost: 2,
      run: () => navigate(r.view, new URLSearchParams(r.params)),
    });
  }
  const rows = (snap && snap.scope && snap.scope.policies && snap.scope.policies.rows) || [];
  for (const r of rows) {
    const from = (r.from || []).length ? r.from.join(',') : 'any';
    const to = (r.to || []).length ? r.to.join(',') : 'any';
    items.push({
      group: 'Policies',
      label: r.name,
      detail: `${r.kind === 'global' ? 'global ' : ''}${from} → ${to}${SEP}${r.action}${r.inactive_reason ? `${SEP}inactive` : ''}`,
      icon: 'policies',
      keywords: `${from} ${to} ${r.action} ${r.description || ''} ${r.group || ''}`,
      run: () => navigate('policies', { q: `name:${quoteValue(r.name)}`, sel: r.id }),
    });
  }
  const zones = (snap && snap.scope && snap.scope.zones && snap.scope.zones.rows) || [];
  for (const z of zones) {
    const ifaces = (z.interfaces || []).map((i) => i.name);
    items.push({
      group: 'Zones',
      label: z.name,
      detail: ifaces.length ? ifaces.join(' ') : 'no interfaces',
      icon: 'zone',
      keywords: `zone ${ifaces.join(' ')} ${z.description || ''}`,
      run: () => navigate('policies', { q: `zone:${quoteValue(z.name)}` }),
    });
  }
  return items;
}

const palette = new Palette({ getItems: paletteItems });

let keysLayer = null;

function closeKeys() {
  if (!keysLayer) return;
  const opener = keysLayer.opener;
  keysLayer.remove();
  keysLayer = null;
  if (opener && document.contains(opener)) opener.focus({ preventScroll: true });
}

function showKeys() {
  if (keysLayer) return;
  const k = (...keys) => keys.map((x) => h('kbd', null, x));
  const group = (title, rows) =>
    h('section', null, h('h3', null, title), h('dl', null, rows.map(([keys, what]) => [h('dt', null, keys), h('dd', null, what)])));
  const close = h('button', { class: 'btn ghost icon', type: 'button', 'aria-label': 'Close', on: { click: closeKeys } }, icon('close'));
  const dialog = h(
    'div',
    { class: 'dialog keys-dialog', role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': 'keys-title' },
    h('div', { class: 'keys-head' }, h('h2', { id: 'keys-title' }, 'Keyboard shortcuts'), close),
    h(
      'div',
      { class: 'keys-grid' },
      group('Go to', [
        [k('g', 'o'), 'Overview'],
        [k('g', 'p'), 'Policies'],
        [k('g', 's'), 'Sessions'],
        [k('g', 'l'), 'Logs'],
        [k('g', 'b'), 'Objects (zones, address books, applications)'],
        [k(IS_MAC ? '⌘' : 'Ctrl', 'K'), 'Command palette: views, policies, zones, actions'],
      ]),
      group('Anywhere', [
        [k('/'), 'Focus the query bar'],
        [k('Esc'), 'Close the panel, or leave the query bar'],
        [k('r'), 'Refresh from the device'],
        [k('t'), 'Day or night theme'],
        [k('['), 'Collapse or expand the rail'],
        [k('?'), 'This list'],
      ]),
      group('Tables and streams', [
        [k('j'), 'Next row'],
        [k('k'), 'Previous row'],
        [k('↵'), 'Open the detail panel'],
        [k('Space'), 'Pause or resume live updates'],
      ]),
      group('Logs', [
        [k('n'), 'Next match'],
        [k('N'), 'Previous match'],
        [k('f'), 'Follow the newest line'],
      ]),
    ),
    h('div', { class: 'pal-foot' }, h('span', null, 'Click any value in Sessions or Logs to filter by it; Alt-click to exclude it.')),
  );
  keysLayer = h('div', { class: 'layer', on: { mousedown: (e) => { if (e.target === keysLayer) closeKeys(); } } }, dialog);
  keysLayer.opener = document.activeElement;
  dialog.addEventListener('keydown', (e) => {
    if (e.key === 'Tab') {
      e.preventDefault();
      close.focus();
    }
  });
  document.body.append(keysLayer);
  close.focus();
}

function isTyping(el) {
  if (!el || el === document.body) return false;
  if (el.isContentEditable) return true;
  const tag = el.tagName;
  if (tag === 'TEXTAREA' || tag === 'SELECT') return true;
  if (tag === 'INPUT') {
    const type = (el.getAttribute('type') || 'text').toLowerCase();
    return !['button', 'checkbox', 'radio', 'submit', 'reset', 'range', 'color', 'file'].includes(type);
  }
  return false;
}

function activatesOnSpace(el) {
  if (!el || el === document.body) return false;
  const tag = el.tagName;
  if (['BUTTON', 'A', 'SUMMARY', 'INPUT', 'SELECT', 'TEXTAREA', 'LABEL'].includes(tag)) return true;
  const role = el.getAttribute && el.getAttribute('role');
  return ['button', 'checkbox', 'switch', 'menuitem', 'option', 'tab', 'radio', 'link', 'treeitem'].includes(role || '');
}

let pendingG = 0;

function onKeyDown(e) {
  if (!S.session || e.defaultPrevented) return;
  const key = e.key;
  const mod = e.metaKey || e.ctrlKey;
  if (mod && !e.altKey && !e.shiftKey && key.toLowerCase() === 'k') {
    e.preventDefault();
    if (palette.isOpen) palette.close();
    else {
      closeKeys();
      closeScopeMenu();
      palette.open();
    }
    return;
  }
  if (key === 'Escape') {
    if (palette.isOpen) return; // the palette handles its own Escape
    if (keysLayer) {
      e.preventDefault();
      closeKeys();
      return;
    }
    if (scopeMenu) {
      closeScopeMenu(true);
      return;
    }
    if (P.open) {
      e.preventDefault();
      closePanel();
      return;
    }
    dispatch('escape');
    if (isTyping(document.activeElement)) document.activeElement.blur();
    return;
  }
  if (mod || e.altKey || palette.isOpen || keysLayer) return;
  if (isTyping(e.target)) return;
  if (pendingG) {
    clearTimeout(pendingG);
    pendingG = 0;
    const view = VIEWS.find((v) => v.key === key);
    if (view) {
      e.preventDefault();
      navigate(view.id, {});
    }
    return;
  }
  switch (key) {
    case 'g':
      pendingG = setTimeout(() => {
        pendingG = 0;
      }, 1200);
      break;
    case '/':
      e.preventDefault();
      dispatch('focus-query');
      break;
    case '?':
      e.preventDefault();
      showKeys();
      break;
    case ' ':
    case 'Spacebar':
      if (activatesOnSpace(e.target)) return;
      e.preventDefault();
      dispatch('toggle-live');
      break;
    case 'n':
      dispatch('next-match');
      break;
    case 'N':
      dispatch('prev-match');
      break;
    case 'f':
      dispatch('toggle-follow');
      break;
    case 't':
      toggleTheme();
      break;
    case 'r':
      refresh();
      break;
    case '[':
      toggleRail();
      break;
    default:
      break;
  }
}

// ---- sign-in and sign-out ------------------------------------------------------------------------

let loginLockUntil = 0;
let loginTimer = 0;

function showSignInError(message) {
  const box = $('signin-error');
  box.textContent = message;
  box.hidden = false;
}

function showSignIn(message, isError) {
  $('boot').hidden = true;
  $('app').hidden = true;
  $('signin').hidden = false;
  const srv = S.server || {};
  if (srv.fixture) showFixture();
  const token = srv.credential === 'token';
  $('field-username').hidden = token;
  $('field-password').hidden = token;
  $('field-token').hidden = !token;
  $('signin-heading').textContent = token ? 'Sign in with the lab token' : 'Sign in with your Junos account';
  $('signin-copy').textContent = token
    ? 'Lab sign-in with a token. J-Wicket does not store the token in this browser.'
    : 'Junos checks your user name and password and applies your login class. J-Wicket does not store them.';
  const lab = $('signin-lab');
  if (srv.backend === 'lab-token') {
    put(lab, h('strong', null, 'Lab mode. '), "Every read runs as the daemon's Junos account, not as you. Your own login class is not applied.");
    lab.hidden = false;
  } else {
    lab.hidden = true;
  }
  $('signin-notice').hidden = true;
  $('signin-error').hidden = true;
  if (message) {
    if (isError) showSignInError(message);
    else {
      $('signin-notice').textContent = message;
      $('signin-notice').hidden = false;
    }
  }
  $('password').value = '';
  $('token').value = '';
  $('signin-version').textContent = srv.version ? `J-Wicket ${srv.version}` : '';
  const facts = [
    ['lock', 'Read-only: no code path changes the configuration'],
    ['globe', 'Served from the device: nothing loads from the internet'],
    srv.backend === 'lab-token' ? ['token', "Lab mode: reads run as the daemon's account"] : ['user', 'Your login class decides what you see'],
  ];
  put($('signin-facts'), ...facts.map(([ic, text]) => h('li', null, icon(ic), text)));
  document.title = 'Sign in · J-Wicket';
  const first = token ? $('token') : $('username').value ? $('password') : $('username');
  first.focus();
}

function lockLogin(seconds, message) {
  loginLockUntil = Date.now() + seconds * 1000;
  const btn = $('signin-submit');
  const base = message || 'Too many sign-in attempts. Wait and try again.';
  btn.disabled = true;
  clearInterval(loginTimer);
  const tick = () => {
    const left = Math.ceil((loginLockUntil - Date.now()) / 1000);
    if (left <= 0) {
      clearInterval(loginTimer);
      btn.disabled = false;
      btn.textContent = 'Sign in';
      showSignInError(`${base} You can try again now.`);
      return;
    }
    btn.textContent = `Wait ${left} s`;
  };
  showSignInError(`${base} You can try again in ${seconds} s.`);
  tick();
  loginTimer = setInterval(tick, 1000);
}

async function onSignIn(event) {
  event.preventDefault();
  if (Date.now() < loginLockUntil) return;
  const token = S.server && S.server.credential === 'token';
  $('signin-error').hidden = true;
  $('signin-notice').hidden = true;
  const body = token ? { token: $('token').value } : { username: $('username').value.trim(), password: $('password').value };
  if (token ? !body.token : !body.username || !body.password) {
    showSignInError(token ? 'Enter the lab token.' : 'Enter your Junos user name and password.');
    (token ? $('token') : body.username ? $('password') : $('username')).focus();
    return;
  }
  const btn = $('signin-submit');
  btn.disabled = true;
  btn.textContent = 'Signing in…';
  const res = await api.post('/api/login', body);
  body.password = '';
  body.token = '';
  $('password').value = '';
  $('token').value = '';
  btn.textContent = 'Sign in';
  btn.disabled = false;
  if (res.status === 429) {
    lockLogin(res.retryAfter || 30, res.data.error);
    return;
  }
  if (!res.ok || !res.data.authenticated) {
    showSignInError(res.data.error || `Sign-in failed (HTTP ${res.status}).`);
    (token ? $('token') : $('password')).focus();
    return;
  }
  S.session = { ...(S.server || {}), ...res.data };
  enterApp();
}

let signingOut = false;

async function signOut() {
  if (!S.session || signingOut) return;
  signingOut = true;
  try {
    const res = await api.post('/api/logout', {});
    const info = await api.get('/api/session', null, { evenIfHidden: true });
    if (info.ok) S.server = info.data;
    // A 401 means the session had already ended (idle timeout, or signed out in another tab).
    const closed = res.ok || res.status === 401 || (info.ok && info.data.authenticated === false);
    if (closed) leaveApp('You are signed out. Your device session is closed.', false);
    else leaveApp(res.data.error || 'J-Wicket could not confirm the sign-out. Close the browser to be sure.', true);
  } finally {
    signingOut = false;
  }
}

function onUnauthorized(data) {
  if (!S.session) return;
  const detail = data && data.error ? String(data.error) : '';
  const message =
    data && data.signed_out
      ? `Your device session ended${detail ? `: ${detail}` : ''}. Sign in again; J-Wicket keeps no password, so it cannot reconnect for you.`
      : 'Your J-Wicket session has ended (idle too long, or signed out elsewhere). Sign in again.';
  leaveApp(message, true);
}

function enterApp() {
  S.gen += 1;
  api.setCsrf(S.session.csrf);
  $('boot').hidden = true;
  $('signin').hidden = true;
  $('app').hidden = false;
  if (S.session.fixture) showFixture();
  buildTopbar();
  buildRail();
  positionPanel();
  const gen = S.gen;
  loadEngines().then(() => {
    if (gen !== S.gen) return;
    if (!location.hash.startsWith('#/')) history.replaceState(null, '', hashFor('overview', new URLSearchParams()));
    S.lastHash = null;
    onRoute();
    inventory();
  });
  say(`Signed in as ${S.session.user}.`);
}

function leaveApp(message, isError) {
  S.gen += 1;
  unmountCurrent();
  closePanel();
  if (palette.isOpen) palette.close({ restoreFocus: false });
  closeKeys();
  closeScopeMenu();
  S.session = null;
  S.inv.clear();
  S.invInflight.clear();
  S.invError = null;
  S.lastInventory = null;
  S.policyIdx = null;
  S.sessionsLast = null;
  S.live.clear();
  S.recent = [];
  S.scope = 'root';
  S.lastHash = null;
  S.mountSeq += 1;
  for (const set of Object.values(listeners)) set.clear();
  api.reset();
  $('main').replaceChildren();
  $('topbar').replaceChildren();
  $('rail').replaceChildren();
  for (const k of Object.keys(TB)) delete TB[k];
  RAIL.items = null;
  RAIL.foot = null;
  showSignIn(message, isError);
}

// ---- boot ----------------------------------------------------------------------------------------

async function boot() {
  applyPrefs();
  wirePanel();
  $('signin-form').addEventListener('submit', onSignIn);
  $('skip').addEventListener('click', (e) => {
    e.preventDefault();
    const main = $('main');
    if (!$('app').hidden) main.focus();
  });
  document.addEventListener('keydown', onKeyDown);
  window.addEventListener('hashchange', onRoute);
  window.addEventListener('popstate', onRoute);
  window.addEventListener(
    'resize',
    dom.rafBatch(() => {
      positionPanel();
      placeScopeMenu();
    }),
  );
  if (window.matchMedia) {
    const mq = window.matchMedia('(prefers-color-scheme: light)');
    if (mq.addEventListener) mq.addEventListener('change', updateThemeButton);
  }
  api.onUnauthorized(onUnauthorized);
  api.onResponse((data) => noteFixture(data && data.meta));

  const res = await api.get('/api/session', null, { evenIfHidden: true });
  $('boot').hidden = true;
  if (res.status === 0) {
    S.server = {};
    showSignIn(res.data.error, true);
    return;
  }
  S.server = res.data || {};
  if (S.server.fixture) showFixture();
  if (res.ok && res.data.authenticated) {
    S.session = res.data;
    enterApp();
  } else {
    showSignIn();
  }
}

boot();
