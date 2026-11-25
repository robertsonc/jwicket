// main.js: the J-Wicket v2 shell.
//
// Sign-in, hash routing, the left rail, the top bar (device identity, scope, read-as, managed-from),
// the fixture banner, the command palette, keyboard shortcuts, the right-hand detail panel, toasts,
// the live region, theme/density preferences, and lazy loading of the views, each of which gets a
// `ctx` (see the module contract in the UI brief, section 10).
//
// Rules kept here: no innerHTML or other HTML parsing, no inline styles (CSSOM only), nothing read
// from the device is stored in the browser (localStorage holds UI preferences only), every panel is
// device data or an explicit state. Device text is untrusted: it is shown through dom.vis() (a hidden
// or direction-changing character becomes a visible badge) and written with format.plain() into
// titles, aria labels, toasts, announcements and document.title.

import * as dom from './dom.js';
import * as format from './format.js';
import * as api from './api.js';
import { Palette } from './widgets/palette.js';

const { h, icon, put, stateCard, vis } = dom;
const { plain } = format;

const VIEWS = [
  { id: 'overview', title: 'Overview', key: 'o', icon: 'overview', sub: 'Device, sessions, denies, warnings' },
  { id: 'policies', title: 'Policies', key: 'p', icon: 'policies', sub: 'Security policies in evaluation order' },
  { id: 'sessions', title: 'Sessions', key: 's', icon: 'sessions', sub: 'Live flow sessions' },
  { id: 'logs', title: 'Logs', key: 'l', icon: 'logs', sub: 'Live syslog tail, highlighted' },
  { id: 'objects', title: 'Objects', key: 'b', icon: 'objects', sub: 'Zones, address books, applications' },
];
const VIEW_BY_ID = new Map(VIEWS.map((v) => [v.id, v]));
const SCOPE_RE = /^(root|lsys:[A-Za-z0-9._-]{1,63}|tenant:[A-Za-z0-9._-]{1,63})$/;
const PREF = { theme: 'jwicket.theme', scheme: 'jwicket.scheme', density: 'jwicket.density', rail: 'jwicket.rail', announce: 'jwicket.announce' };
// Colour schemes (app.css "colour schemes"); the first is the default and needs no data-scheme.
const SCHEMES = [
  { id: 'hpe', label: 'HPE', detail: 'HPE brand: green accents on slate' },
  { id: 'obsidian', label: 'Obsidian & Phosphor', detail: 'NOC: cyan telemetry, teal healthy, coral critical' },
  { id: 'nordic', label: 'Nordic Steel', detail: 'Colourblind-safe: ice blue allow, magenta deny' },
];
const ANNOUNCE_GAP_MS = 10000;
const IS_MAC = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent || '');
const SEP = ' · ';
// The inventory read waits out other reads of the same session (another tab), within this budget.
const INV_RETRY429 = { attempts: 4, maxWaitMs: 20000 };
const INV_BUSY_RETRY_MS = 30000;
const INV_BUSY_MESSAGE = 'J-Wicket could not read the device because other reads for your session kept it busy. It tries again in 30 s.';
const ENDS_WARN_MS = 5 * 60 * 1000;

const $ = (id) => document.getElementById(id);

/** "HH:MM" in UTC. */
function hhmm(date) {
  return format.time(date).slice(0, 5);
}

/** A duration of whole hours as "8 h", otherwise "90 min". */
function spanText(seconds) {
  const s = Math.max(0, Math.round(Number(seconds) || 0));
  return s % 3600 === 0 ? `${s / 3600} h` : `${Math.round(s / 60)} min`;
}

// ---- state ---------------------------------------------------------------------------------------

const S = {
  server: null, // GET /api/session while signed out: credential, backend, fixture, version
  session: null, // signed in: user, csrf, backend, credential, fixture, idle_timeout_s, version
  gen: 0, // bumps on every sign-in and sign-out; late results from an older generation are dropped
  scope: 'root',
  inv: new Map(), // scope -> snapshot, this sign-in only, memory only
  invInflight: new Map(),
  invError: null, // { scope, status, message }: the last inventory read that failed
  invWaiting: null, // { scope, until, reason }: the inventory read waits out another read of this session
  invRetry: 0, // timer: the automatic re-read after "busy"
  lastInventory: null,
  policyIdx: null,
  policyIdxFor: null,
  sessionsLast: null,
  sessionsSummary: null, // { summary, at }: the latest table-wide summary that read ok
  // Session limits from the last sign-in in this tab (server settings, not device data; memory only),
  // so a sign-in refusal or an ended session can be worded with them.
  lastFacts: null,
  endsTimer: 0,
  checkingSession: false,
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

const listeners = { inventory: new Set(), sessions: new Set(), scope: new Set(), 'inventory-state': new Set() };

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
  applyScheme(prefGet(PREF.scheme));
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

function currentScheme() {
  return document.documentElement.dataset.scheme || SCHEMES[0].id;
}

function applyScheme(id) {
  const root = document.documentElement;
  if (SCHEMES.some((s) => s.id === id) && id !== SCHEMES[0].id) root.dataset.scheme = id;
  else delete root.dataset.scheme;
}

function setScheme(id) {
  const scheme = SCHEMES.find((s) => s.id === id) || SCHEMES[0];
  applyScheme(scheme.id);
  prefSet(PREF.scheme, scheme.id === SCHEMES[0].id ? null : scheme.id);
  if (TB.scheme && TB.scheme.value !== scheme.id) TB.scheme.value = scheme.id;
  say(`${scheme.label} colour scheme`);
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
    region.textContent = plain(text);
  }, 40);
}

let lastAnnounce = 0;
let pendingText = '';
const pendingCounted = new Map(); // key -> { counts, render }
let announceTimer = 0;

function announcementsMuted() {
  return prefGet(PREF.announce) === 'off';
}

function composeAnnouncement() {
  const parts = [];
  if (pendingText) parts.push(pendingText);
  for (const p of pendingCounted.values()) {
    let text = '';
    try {
      text = p.render ? String(p.render({ ...p.counts }) || '') : '';
    } catch (err) {
      console.error(err);
    }
    if (text) parts.push(text);
  }
  pendingText = '';
  pendingCounted.clear();
  // Announcements may carry device names: hidden characters are spoken as "<U+202E>", never applied.
  return plain(parts.join(' '));
}

function flushAnnouncement() {
  clearTimeout(announceTimer);
  announceTimer = 0;
  const text = composeAnnouncement();
  if (!text || announcementsMuted()) return;
  lastAnnounce = Date.now();
  say(text);
}

/** Forget what was queued (a view unmounted: its news must not be spoken in the next view). */
function clearAnnouncements() {
  clearTimeout(announceTimer);
  announceTimer = 0;
  pendingText = '';
  pendingCounted.clear();
}

/**
 * Polite and throttled: at most one announcement every 10 s.
 *   announce('Overview paused.')                      plain text: the latest one wins
 *   announce({ key: 'sessions', counts: { added: 3, ended: 1 },
 *              render: (c) => `${c.added} new sessions, ${c.ended} ended.` })
 * Counted announcements with the same key add up over the window, so what is said is the total since
 * the last announcement, not the last poll's change. Nothing is said while muted (palette action).
 */
function announce(msg) {
  if (announcementsMuted()) return;
  if (msg && typeof msg === 'object') {
    const key = String(msg.key || 'live');
    const entry = pendingCounted.get(key) || { counts: {}, render: null };
    for (const [k, v] of Object.entries(msg.counts || {})) entry.counts[k] = (entry.counts[k] || 0) + (Number(v) || 0);
    if (typeof msg.render === 'function') entry.render = msg.render;
    pendingCounted.set(key, entry);
  } else {
    const text = String(msg || '');
    if (!text) return;
    pendingText = text;
  }
  const wait = lastAnnounce + ANNOUNCE_GAP_MS - Date.now();
  if (wait <= 0) {
    flushAnnouncement();
    return;
  }
  if (!announceTimer) announceTimer = setTimeout(flushAnnouncement, wait);
}

function toggleAnnouncements() {
  const muted = !announcementsMuted();
  if (muted) clearAnnouncements();
  prefSet(PREF.announce, muted ? 'off' : null);
  say(muted ? 'Live announcements muted. Toggle them again from the command palette.' : 'Live announcements on.');
}

const TOAST_ICON = { info: 'info', ok: 'check-circle', warn: 'alert', error: 'alert' };
const recentToasts = new Map();
const pendingConfirms = new Set(); // resolve(false) for each confirm toast still open

/**
 * A short message in the corner. Device names in it are written with format.plain(), so a hidden or
 * direction-changing character reads "<U+202E>" instead of being applied. `ms` overrides how long it
 * stays (5 s, 9 s for errors).
 */
function toast(message, kind = 'info', { ms = 0 } = {}) {
  const text = plain(String(message || '').trim());
  if (!text) return;
  const k = TOAST_ICON[kind] ? kind : 'info';
  const key = `${k}:${text}`;
  const now = Date.now();
  if ((recentToasts.get(key) || 0) > now - 5000) return;
  recentToasts.set(key, now);
  const box = $('toasts');
  if (!box) return;
  let timer = 0;
  const el = h(
    'div',
    { class: ['toast', 'toast-auto', k] },
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
  // Only passing toasts give way; the idle note and an open question stay.
  const auto = [...box.querySelectorAll('.toast-auto')];
  for (const old of auto.slice(0, Math.max(0, auto.length - 4))) old.remove();
  timer = setTimeout(dismiss, ms > 0 ? ms : k === 'error' ? 9000 : 5000);
  say(text, k === 'error');
}

/**
 * A toast that asks: resolves true for `ok`, false for `cancel`, and false when it is cleared (sign-out).
 * It stays until answered.
 */
function confirmToast(message, { ok = 'Save', cancel = 'Cancel', iconName = 'download' } = {}) {
  const text = plain(String(message || ''));
  return new Promise((resolve) => {
    const box = $('toasts');
    if (!box) {
      resolve(false);
      return;
    }
    let done = false;
    const finish = (value) => {
      if (done) return;
      done = true;
      pendingConfirms.delete(finish);
      el.remove();
      resolve(value);
    };
    const yes = h('button', { class: 'btn sm primary', type: 'button', on: { click: () => finish(true) } }, ok);
    const el = h(
      'div',
      { class: ['toast', 'info', 'toast-confirm'], role: 'group', 'aria-label': text },
      icon(iconName),
      h(
        'div',
        { class: 'toast-msg' },
        h('span', null, text),
        h('span', { class: 'toast-actions' }, yes, h('button', { class: 'btn sm', type: 'button', on: { click: () => finish(false) } }, cancel)),
      ),
    );
    el.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        e.stopPropagation();
        finish(false);
      }
    });
    pendingConfirms.add(finish);
    box.append(el);
    yes.focus({ preventScroll: true });
    say(text);
  });
}

/** Sign-out: every toast goes, and the "same toast within 5 s" memory with them (SL-14). */
function clearToasts() {
  for (const finish of [...pendingConfirms]) finish(false);
  pendingConfirms.clear();
  const box = $('toasts');
  if (box) box.replaceChildren();
  recentToasts.clear();
  idleNote = null;
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

const P = { open: false, onClose: null, opener: null, modal: false };

// Phone width: the panel is a full-screen sheet over a scrim, so it is modal (the page behind it is
// inert and Tab stays inside). Wider: a side panel next to the page, not modal, no focus trap.
const NARROW = '(max-width: 640px)';

function narrow() {
  return Boolean(window.matchMedia && window.matchMedia(NARROW).matches);
}

function syncPanelModal() {
  const modal = P.open && narrow();
  P.modal = modal;
  $('panel').setAttribute('aria-modal', modal ? 'true' : 'false');
  $('app').inert = modal;
}

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

const isNodeLike = (v) => Array.isArray(v) || (v !== null && typeof v === 'object' && typeof v.nodeType === 'number');

/**
 * The panel title: a string is device text as often as not ("Zone untrust", a policy name), so it is
 * shown through dom.vis() and labelled with format.plain(); a Node or an Array of nodes and strings is
 * shown as given and labelled with `label` (or its text).
 */
function setPanelTitle(title, label = null) {
  const el = $('panel-title');
  if (isNodeLike(title)) {
    put(el, title);
    const text = label !== null && label !== undefined ? String(label) : el.textContent || '';
    el.setAttribute('aria-label', plain(text, { all: true }));
  } else {
    const text = String(title ?? '');
    put(el, vis(text, { all: true }));
    el.setAttribute('aria-label', plain(text, { all: true }));
  }
}

/**
 * ctx.ui.panel({ title, content, onClose, wide, actions, label }) or ctx.ui.panel(title, content):
 * `title` is a string, a Node or an Array (see setPanelTitle).
 */
function openPanel(opts = {}, second = undefined) {
  const named = isNodeLike(opts) || typeof opts === 'string' || second !== undefined;
  const { title = '', content = null, onClose = null, wide = false, actions = null, label = null } = named ? { title: opts, content: second ?? null } : opts || {};
  const panel = $('panel');
  const active = document.activeElement;
  if (P.open) finishPanelClose(false);
  else P.opener = active && !panel.contains(active) ? active : null;
  P.onClose = typeof onClose === 'function' ? onClose : null;
  setPanelTitle(title, label);
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
  syncPanelModal();
  $('panel-title').focus({ preventScroll: true });
  return {
    el: body,
    close: closePanel,
    setTitle: (t, l = null) => setPanelTitle(t, l),
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
  syncPanelModal();
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
    if (e.key !== 'Tab' || !P.modal) return;
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

/** The inventory read state changed (waiting, busy, failed, cleared): tiles and the chip redraw. */
function inventoryStateChanged() {
  renderTopbar();
  emit('inventory-state', { waiting: inventoryWaiting(), error: S.invError });
}

function setInvWaiting(value) {
  S.invWaiting = value;
  inventoryStateChanged();
}

/** store.inventoryWaiting: { until, reason } while the current scope's read waits, else null. */
function inventoryWaiting() {
  const w = S.invWaiting;
  return w && w.scope === S.scope ? { until: w.until, reason: w.reason } : null;
}

function clearInvRetry() {
  clearTimeout(S.invRetry);
  S.invRetry = 0;
}

/** After "busy": read again by itself in 30 s, unless the operator signed out or moved on. */
function armInvRetry(scope) {
  clearInvRetry();
  const gen = S.gen;
  S.invRetry = setTimeout(() => {
    S.invRetry = 0;
    if (gen === S.gen && S.session && S.scope === scope && !S.inv.has(scope)) inventory(true);
  }, INV_BUSY_RETRY_MS);
}

function scopeNotFoundText(scope) {
  const kind = scopeKind(scope);
  const name = scope.split(':')[1] || scope;
  return `${kind === 'tenant' ? 'Tenant system' : 'Logical system'} ${name} is not in the configuration. Showing the root system.`;
}

async function readInventory(scope) {
  const gen = S.gen;
  setReading(1);
  // Another tab or window of this session may be reading: wait it out (Retry-After), within a budget,
  // and say so, rather than failing. With B-8 the server usually answers such a collision with the
  // other tab's read (meta.reused) instead.
  const res = await api.get('/api/inventory', { scope }, {
    retry429: INV_RETRY429,
    onWait: ({ retryAfter, reason }) => {
      if (gen !== S.gen) return;
      setInvWaiting({ scope, until: Date.now() + Math.max(1, Number(retryAfter) || 1) * 1000, reason });
    },
  });
  setReading(-1);
  if (gen !== S.gen) return null;
  const wasWaiting = Boolean(S.invWaiting);
  S.invWaiting = null;
  if (!res.ok) {
    if (res.status === 401 || res.aborted) {
      inventoryStateChanged();
      return null;
    }
    if (res.status === 429) {
      // The budget ran out: no error toast (nothing failed on the device); try again in 30 s.
      S.invError = { scope, status: 'busy', message: INV_BUSY_MESSAGE };
      armInvRetry(scope);
    } else if (res.status === 404 && scope !== 'root') {
      S.invError = null;
      toast(scopeNotFoundText(scope), 'warn');
      inventoryStateChanged();
      setScope('root');
      return null;
    } else {
      const status = res.internal ? 'internal' : res.status;
      S.invError = { scope, status, message: res.data.error || `The inventory read failed (HTTP ${res.status}).` };
      toast(S.invError.message, 'error');
    }
    inventoryStateChanged();
    return null;
  }
  const hadState = wasWaiting || Boolean(S.invError);
  S.invError = null;
  clearInvRetry();
  if (hadState) inventoryStateChanged();
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

/**
 * Keep the latest table-wide summary that read ok ({ summary, at }), from any /api/sessions reply of
 * this sign-in: a Sessions poll, the Overview's summary-only read, a Policies read. The rail badge
 * shows it.
 */
function noteSessionsSummary(payload) {
  if (!S.session || !payload || typeof payload !== 'object') return;
  const summary = payload.summary;
  if (!summary || summary.status !== 'ok') return;
  const ra = payload.meta && payload.meta.read_as;
  if (ra && typeof ra.user === 'string' && ra.user !== S.session.user) return; // read as someone else
  // On this browser's clock (the device's may differ): now, less the summary's age when the reply was
  // made (a gauge reused by the server can be a few seconds older than the reply).
  const replied = Date.parse((payload.meta && payload.meta.read_at) || '');
  const read = Date.parse(summary.read_at || '');
  const at = Date.now() - (Number.isFinite(replied) && Number.isFinite(read) ? Math.max(0, replied - read) : 0);
  if (S.sessionsSummary && S.sessionsSummary.at > at) return; // an older (reused) read
  S.sessionsSummary = { summary, at };
  renderRailMeta();
}

/**
 * store.setSessionsLast(payload): the last /api/sessions reply, for the next view. A summary-only
 * reply (sessions "not-requested") keeps the last list and updates only the summary.
 */
function setSessionsLast(payload) {
  noteSessionsSummary(payload);
  if (payload && payload.sessions && payload.sessions.status === 'not-requested') return;
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
    /** { scope, status, message } of the last failed read; views compare `scope` with store.scope. */
    get inventoryError() {
      return S.invError;
    },
    /** { until, reason } while the read waits out another read of this session, else null. */
    get inventoryWaiting() {
      return inventoryWaiting();
    },
    policyIndex,
    get sessionsLast() {
      return S.sessionsLast;
    },
    /** { summary, at }: the latest /api/sessions summary that read ok, or null. */
    get sessionsSummary() {
      return S.sessionsSummary;
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
      /** The shared label for a scope id: "Root system", "Logical system LS-A", "Tenant system T-1". */
      scopeLabel: (id) => scopeLabel(id || S.scope),
      setLive: (viewId, on) => setLive(viewId, Boolean(on), record),
      /** Whether live reads are paused for inactivity; window 'jwicket:idle' says when it changes. */
      isIdle: () => Boolean(S.session) && api.isIdle(),
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
  clearAnnouncements();
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
  const host = dev && dev.status === 'ok' && dev.hostname ? plain(dev.hostname, { all: true }) : null;
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

function scopeShort(id) {
  if (id === 'root') return 'Root';
  return id.split(':')[1] || id;
}

/** A non-root scope is visible everywhere: tinted scope chip, a line under the top bar, and the scope
    name before every view title ("LS-A / Policies"), set as a CSS string the stylesheet shows. */
function markScope() {
  const root = document.documentElement;
  const kind = S.session ? scopeKind(S.scope) : 'root';
  if (kind === 'root') {
    delete root.dataset.scopeKind;
    root.style.removeProperty('--scope-crumb');
  } else {
    root.dataset.scopeKind = kind;
    // SCOPE_RE allows only [A-Za-z0-9._-] in the name, so it needs no escaping inside the quotes.
    root.style.setProperty('--scope-crumb', `"${scopeShort(S.scope)}"`);
  }
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

/**
 * A short HA label for chips: "standalone", "RG0 primary node0", "MNHA". "standalone?" when the
 * server says why standalone is not certain (ha.message, for example a fallback filter); `title` then
 * carries that message.
 */
function haSummary(ha) {
  if (!ha) return { text: 'HA ?', cls: '', title: null };
  if (ha.status && ha.status !== 'ok') return { text: `HA ${ha.status}`, cls: '', title: ha.message ? plain(ha.message) : null };
  if (ha.mode === 'standalone') return ha.message ? { text: 'standalone?', cls: '', title: plain(ha.message) } : { text: 'standalone', cls: '', title: null };
  if (ha.mode === 'chassis-cluster') {
    const rg0 = (ha.redundancy_groups || []).find((g) => String(g.id) === '0');
    const primary = rg0 && (rg0.nodes || []).find((n) => String(n.status || '').toLowerCase() === 'primary');
    return { text: primary ? `RG0 primary ${primary.name}` : `cluster ${ha.cluster_id || ''}`.trim(), cls: 'cluster', title: ha.message ? plain(ha.message) : null };
  }
  if (ha.mode === 'mnha') return { text: 'MNHA', cls: 'cluster', title: ha.message ? plain(ha.message) : null };
  return { text: 'HA unknown', cls: '', title: null };
}

/** Management clients split into those in effect and those deactivated (CRT-01). */
function mgClients(mg) {
  const all = (mg && Array.isArray(mg.clients) ? mg.clients : []).filter((c) => c && c.client !== undefined && c.client !== null);
  return { active: all.filter((c) => !c.inactive), off: all.filter((c) => c.inactive) };
}

const offClientTitle = (name) => `outbound-ssh client ${plain(name, { all: true })} is in the configuration but deactivated (inactive:), so it is not in effect.`;

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
  TB.ctx = h('div', { class: 'tb-ctx', role: 'group', 'aria-label': 'Scope, read-as user and central management' }, TB.scopeWrap, TB.readAs, TB.managed);
  TB.theme = h('button', { id: 'btn-theme', class: 'btn ghost icon', type: 'button', on: { click: toggleTheme } });
  TB.scheme = h(
    'select',
    { id: 'sel-scheme', class: 'tb-scheme', title: 'Colour scheme', 'aria-label': 'Colour scheme', on: { change: () => setScheme(TB.scheme.value) } },
    SCHEMES.map((s) => h('option', { value: s.id, title: s.detail }, s.label)),
  );
  TB.scheme.value = currentScheme();
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
    h('div', { class: 'tb-dev' }, TB.device),
    TB.ctx,
    h('div', { class: 'tb-actions' }, TB.search, TB.scheme, TB.theme, TB.signout),
  );
  renderTopbar();
}

function renderDeviceChip() {
  const chip = TB.device;
  if (!chip) return;
  const snap = S.lastInventory;
  const dev = snap && snap.device;
  if (!snap) {
    const waiting = inventoryWaiting();
    const err = S.invError && (!S.invError.scope || S.invError.scope === S.scope) ? S.invError : null;
    let dot = 'idle';
    let text = 'reading device…';
    let title = 'Reading the device';
    if (waiting) {
      const n = Math.max(1, Math.ceil((waiting.until - Date.now()) / 1000));
      dot = 'warn';
      text = 'waiting for another read…';
      title = `Another read for your session is running (another tab or window?). J-Wicket tries again in ${n} s.`;
    } else if (err && err.status === 'busy' && !S.reading) {
      dot = 'warn';
      text = 'busy: reading again in 30 s';
      title = err.message;
    } else if (err && !S.reading) {
      dot = 'bad';
      text = 'device not read';
      title = plain(err.message);
    }
    put(chip, h('span', { class: ['status-dot', dot] }), h('span', { class: 'host' }, text));
    chip.title = title;
    chip.setAttribute('aria-label', `Device: ${text}. Open device details.`);
    return;
  }
  const ha = haSummary(snap.ha);
  const configOk = !snap.config || snap.config.status === 'ok';
  const dotCls = S.reading ? 'idle' : dev && dev.status === 'ok' ? (configOk ? '' : 'warn') : 'bad';
  let label;
  if (dev && dev.status === 'ok') {
    const host = dev.hostname || 'unnamed device';
    put(chip,
      h('span', { class: ['status-dot', dotCls] }),
      h('span', { class: 'host dev-text' }, vis(host, { all: true })),
      dev.model ? h('span', { class: 'dim model shrink first dev-text' }, vis(modelName(dev.model), { all: true })) : null,
      dev.version ? h('span', { class: 'dim ver shrink dev-text' }, vis(dev.version, { all: true })) : null,
      h('span', { class: ['ha-badge', ha.cls], title: ha.title }, vis(ha.text, { all: true })),
    );
    const facts = [plain(host, { all: true }), plain(modelName(dev.model), { all: true }), `Junos ${plain(dev.version || '?', { all: true })}`, plain(ha.text, { all: true })];
    chip.title = `${facts.join(SEP)}.${ha.title ? ` ${ha.title}` : ''} Details: device panel.`;
    label = facts.filter(Boolean).join(' ');
  } else {
    const text = `device facts ${dev ? dev.status : 'missing'}`;
    put(chip,
      h('span', { class: ['status-dot', 'bad'] }),
      h('span', { class: 'host' }, text),
      h('span', { class: ['ha-badge', ha.cls], title: ha.title }, vis(ha.text, { all: true })),
    );
    chip.title = plain((dev && dev.message) || 'The device facts could not be read.');
    label = `${text} ${plain(ha.text, { all: true })}`;
  }
  chip.setAttribute('aria-label', `Device: ${label}. Open device details.`);
}

function renderTopbar() {
  if (!TB.device) return;
  renderDeviceChip();
  // scope
  const snap = S.lastInventory;
  const scopes = (snap && snap.meta && snap.meta.scopes) || [];
  const current = scopes.find((s) => s.id === S.scope);
  const kind = scopeKind(S.scope);
  TB.scopeBtn.className = `chip chip-scope scope-${kind}`;
  const label = scopeLabel(S.scope);
  put(TB.scopeBtn,
    icon(kind === 'root' ? 'server' : kind === 'lsys' ? 'layers' : 'tenant'),
    h('span', { class: 'ellipsis scope-long dev-text' }, vis(label, { all: true })),
    h('span', { class: 'ellipsis scope-short', 'aria-hidden': 'true' }, scopeShort(S.scope)),
    current && current.inactive ? h('span', { class: 'pill reject' }, 'deactivated') : null,
    icon('chevron-down', { class: 'chev' }),
  );
  TB.scopeBtn.setAttribute('aria-label', `Scope: ${plain(label, { all: true })}. Change scope.`);
  markScope();
  // read as
  const ra = (snap && snap.meta && snap.meta.read_as) || (S.session ? { user: S.session.user, backend: S.session.backend } : {});
  const lab = ra.backend === 'lab-token';
  const user = plain(ra.user || '?', { all: true });
  TB.readAs.className = `chip chip-readas${lab ? ' amber' : ''}`;
  put(TB.readAs,
    icon(lab ? 'token' : 'user'),
    lab ? h('span', null, 'lab token: as ') : h('span', { class: 'muted' }, 'as'),
    h('b', { class: 'mono dev-text' }, vis(ra.user || '?', { all: true })),
  );
  TB.readAs.title = lab
    ? `Lab sign-in: every read runs as the daemon's Junos account ${user}, not as you. Your own login class is not applied.`
    : ra.backend === 'fixture'
      ? 'Fixture replay on the development server, not a Junos session.'
      : `Read with your own Junos session as ${user}: your login class decides what you can see.`;
  // managed from: only clients in effect are named and counted (a deactivated client is not)
  const mg = snap && snap.management;
  const cfg = (snap && snap.config) || {};
  const { active } = mgClients(mg);
  if (mg && mg.status === 'ok' && active.length) {
    const names = active.map((c) => String(c.client));
    TB.managed.hidden = false;
    TB.managed.className = 'chip chip-managed is-managed';
    put(TB.managed,
      icon('broadcast'),
      h('span', { class: 'muted shrink first' }, 'managed from'),
      h('b', { class: 'mono shrink dev-text' }, vis(names[0], { all: true })),
      names.length > 1 ? h('span', { class: 'pill' }, `+${names.length - 1}`) : null,
    );
    TB.managed.setAttribute('aria-label', `Managed from ${names.map((n) => plain(n, { all: true })).join(', ')}. Details.`);
    TB.managed.title = 'Another system holds a management connection to this device. Changes made there may overwrite this configuration.';
  } else if (mg && mg.status !== 'ok') {
    TB.managed.hidden = false;
    TB.managed.className = 'chip chip-managed';
    // Like the known variant: "managed from" is the part that hides when the bar is tight, so the
    // chip still reads "(icon) not known" rather than a bare icon. CRT-01: the same words as the panel.
    put(TB.managed, icon('broadcast'), h('span', { class: 'muted shrink first' }, 'managed from:'), h('span', { class: 'shrink' }, 'not known'));
    TB.managed.setAttribute('aria-label', 'Central management: not known. Details.');
    TB.managed.title =
      cfg.status && cfg.status !== 'ok'
        ? `Central management is read from the configuration, which could not be read (${cfg.status}). Another system may also manage this device.`
        : `${plain(mg.message || `Central management was not read (${mg.status}).`)} Another system may also manage this device.`;
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

/** At the scope chip, as wide as the longest label needs (280 to 480 px, never past the window). */
function placeScopeMenu() {
  if (!scopeMenu) return;
  const r = TB.scopeBtn.getBoundingClientRect();
  const maxW = Math.max(0, Math.min(480, window.innerWidth - 16));
  scopeMenu.style.minWidth = `${Math.min(280, maxW)}px`;
  scopeMenu.style.maxWidth = `${maxW}px`;
  scopeMenu.style.width = '';
  scopeMenu.style.top = `${Math.round(r.bottom + 6)}px`;
  // Measured at the left edge, where nothing limits it but max-width; then moved under the chip.
  scopeMenu.style.left = '8px';
  const w = scopeMenu.getBoundingClientRect().width;
  scopeMenu.style.left = `${Math.round(Math.max(8, Math.min(r.left, window.innerWidth - w - 8)))}px`;
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
    const kind = scopeKind(String(s.id));
    // CRT-13: a scope whose name J-Wicket cannot address yet is listed, disabled, with the reason.
    const blocked = s.selectable === false;
    const reason = blocked ? String(s.reason || 'J-Wicket cannot open this scope yet.') : '';
    const full = plain(String(s.label ?? s.id), { all: true });
    return h(
      'div',
      {
        role: 'option',
        class: blocked ? 'opt-blocked' : null,
        id: `scope-opt-${i}`,
        tabindex: '-1',
        title: blocked ? `${full}: ${plain(reason)}` : full,
        'aria-selected': s.id === S.scope ? 'true' : 'false',
        'aria-disabled': blocked ? 'true' : null,
        dataset: { scope: String(s.id) },
        on: {
          click: () => {
            if (blocked) {
              toast(`${full}: ${reason}`, 'warn');
              return;
            }
            closeScopeMenu(true);
            setScope(s.id);
          },
        },
      },
      icon(kind === 'root' ? 'server' : kind === 'lsys' ? 'layers' : 'tenant'),
      h('span', { class: 'opt-label dev-text' }, vis(s.label ?? s.id, { all: true })),
      s.inactive ? h('span', { class: 'pill reject' }, 'deactivated') : null,
      s.policies !== null && s.policies !== undefined ? h('span', { class: 'opt-meta' }, format.plural(s.policies, 'policy')) : null,
      blocked ? h('span', { class: 'opt-reason' }, reason) : null,
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

/**
 * The device's configured time zone (snapshot `clock`, B-12). It says "configured", never "in
 * effect": Junos applies a change to every process only after a reboot (verified). J-Wicket shows
 * times in UTC; Logs can show log times in the configured zone (LG-02).
 */
function timeZoneFact(snap) {
  const cfg = snap.config || {};
  const clock = snap.clock;
  if (cfg.status && cfg.status !== 'ok') return { text: `not known (configuration not read: ${cfg.status})`, note: null };
  if (!clock || typeof clock !== 'object') return { text: 'not known (not reported)', note: null };
  if (clock.status !== 'ok') return { text: `not known (${clock.status})`, note: clock.message || null };
  if (clock.time_zone) return { text: `${clock.time_zone} (configured; Junos applies a change to every process only after a reboot)`, note: null };
  if (clock.deactivated) {
    return {
      // JUNOS-02: "configured" wording only (B-12); that the default then applies is inferred.
      text: `not configured (time-zone ${clock.deactivated} is deactivated); Junos default: UTC`,
      note: `time-zone ${clock.deactivated} is in the configuration but deactivated (inactive:). That the Junos default, UTC, then applies is J-Wicket's reading (inferred); Junos applies a time-zone change to every process only after a reboot.`,
    };
  }
  return { text: 'UTC (no time-zone configured: the Junos default)', note: null };
}

/** The J-Wicket session line (SL-09): the idle limit, and the absolute limit when the server says it. */
function sessionFact() {
  const s = S.session || {};
  const idle = Math.round((Number(s.idle_timeout_s) || 0) / 60);
  if (!idle) return null;
  if (s.ends_by && s.signed_in_at && s.absolute_timeout_s) {
    return `Ends after ${idle} min without activity, and at the latest at ${hhmm(s.ends_by)} UTC (${spanText(s.absolute_timeout_s)} after you signed in at ${hhmm(s.signed_in_at)} UTC).`;
  }
  return `Ends after ${idle} min without activity.`;
}

function deviceFacts(snap) {
  const out = [];
  const dev = snap.device || {};
  if (dev.status === 'ok') {
    out.push(
      ...fact(
        'Device',
        h('span', { class: 'mono strong dev-text' }, vis(dev.hostname || '?', { all: true })),
        h('span', { class: 'note dev-text' }, vis(`${modelName(dev.model) || 'model not reported'}${SEP}Junos ${dev.version || 'not reported'}`, { all: true })),
      ),
    );
    const versions = [...new Set((dev.nodes || []).map((n) => n.version).filter(Boolean))];
    if (versions.length > 1) out.push(...fact('Releases', h('span', { class: 'act-reject dev-text' }, vis(`Nodes report different releases: ${versions.join(', ')}`, { all: true }))));
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
        h('span', { class: 'dev-text' }, vis(`Chassis cluster${ha.cluster_id ? ` ${ha.cluster_id}` : ''}`, { all: true })),
        (ha.redundancy_groups || []).map((g) =>
          h(
            'span',
            { class: 'rg-row' },
            h('span', { class: 'rg-id dev-text' }, vis(`RG${g.id}`, { all: true })),
            (g.nodes || []).map((n) =>
              h(
                'span',
                { class: ['rg-node', 'dev-text', String(n.status || '').toLowerCase() === 'primary' && 'primary'] },
                vis(`${n.name}${nodes.get(n.name) ? ` (${nodes.get(n.name)})` : ''}`, { all: true }),
                h('span', { class: 'prio' }, vis(`${n.status || '?'} ${n.priority || ''}`.trim(), { all: true })),
              ),
            ),
          ),
        ),
        h('span', { class: 'note dev-text' }, ha.local_node ? vis(`This page is served by ${ha.local_node}.`, { all: true }) : 'Which node serves this page is not reported.'),
        ha.message ? h('span', { class: 'note' }, vis(ha.message)) : null,
      ),
    );
  } else {
    const mode = ha.mode === 'mnha' ? 'Multinode High Availability' : ha.mode === 'standalone' ? (ha.message ? 'Standalone (not certain)' : 'Standalone') : 'Unknown';
    out.push(...fact('High availability', h('span', null, mode), ha.message ? h('span', { class: 'note' }, vis(ha.message)) : null));
  }
  const meta = snap.meta || {};
  const scopeInv = snap.scope;
  out.push(
    ...fact(
      'Scope',
      h('span', { class: 'dev-text' }, vis(scopeLabel(meta.scope || S.scope), { all: true })),
      scopeInv && scopeInv.inactive ? h('span', { class: 'act-reject' }, 'Deactivated in the configuration: nothing in this scope is in effect.') : null,
    ),
  );
  const ra = meta.read_as || {};
  out.push(
    ...fact(
      'Read as',
      h('span', { class: 'mono strong dev-text' }, vis(ra.user || '?', { all: true })),
      h(
        'span',
        { class: 'note' },
        ra.backend === 'lab-token'
          ? [`Lab sign-in: every read runs as the daemon's Junos account `, h('span', { class: 'dev-text' }, vis(ra.user || '', { all: true })), ', not as you.']
          : ra.backend === 'fixture'
            ? 'Fixture replay on the development server, not a Junos session.'
            : 'Your own Junos session: your login class decides what you can see.',
      ),
    ),
  );
  const src = meta.source || {};
  const cfg = snap.config || {};
  const configRead = !cfg.status || cfg.status === 'ok';
  out.push(
    ...fact(
      'Source',
      configRead
        ? h('span', null, `${src.database === 'committed' ? 'Committed configuration' : `${src.database || 'Unknown'} configuration`}${SEP}${src.inheritance ? 'inheritance expanded' : 'inheritance not expanded'}`)
        : h('span', null, `Configuration not read (${cfg.status})`),
      h('span', { class: 'note' }, `Read ${format.stamp(meta.read_at)} (${format.ago(meta.read_at)})`),
      configRead && src.groups_annotated ? h('span', { class: 'note' }, 'Each object says which configuration group it came from.') : null,
    ),
  );
  const tz = timeZoneFact(snap);
  out.push(
    ...fact(
      'Time zone',
      h('span', { class: 'dev-text' }, vis(tz.text, { all: true })),
      tz.note ? h('span', { class: 'note' }, vis(tz.note)) : null,
      h('span', { class: 'note' }, 'J-Wicket shows times in UTC; Logs can show log times in the configured device zone.'),
    ),
  );

  const mg = snap.management || {};
  out.push(...fact('Central management', managementSummary(mg, snap.config || {})));
  const line = sessionFact();
  if (line) out.push(...fact('J-Wicket session', h('span', null, line), h('span', { class: 'note' }, 'Nothing read from the device is kept in this browser.')));
  return h('dl', { class: 'facts-grid' }, out);
}

/** One outbound-SSH client: name, targets, services; a deactivated one muted, with a pill. */
function mgClientRow(c) {
  const off = Boolean(c.inactive);
  return h(
    'div',
    { class: ['mg-client', off && 'is-off'] },
    h('span', { class: 'mg-name dev-text' }, icon('broadcast'), vis(c.client, { all: true })),
    off ? h('span', { class: 'pill muted', title: offClientTitle(c.client) }, 'deactivated') : null,
    (c.targets || []).length ? h('span', { class: 'mg-targets' }, c.targets.map((t) => h('span', { class: 'zone dev-text' }, vis(t, { all: true })))) : null,
    (c.services || []).length ? h('span', { class: 'mg-targets' }, c.services.map((s) => h('span', { class: ['pill', off ? 'muted' : 'gold', 'dev-text'] }, vis(s, { all: true })))) : null,
  );
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
  const { active, off } = mgClients(mg);
  if (!active.length && !off.length) return h('span', { class: 'muted' }, 'No outbound-SSH management client is configured.');
  if (!active.length) {
    return h(
      'div',
      null,
      h('p', { class: 'muted dev-text' }, vis(`No active outbound-SSH client. Configured but deactivated: ${off.map((c) => c.client).join(', ')}.`)),
      off.map(mgClientRow),
    );
  }
  return h(
    'div',
    null,
    active.map(mgClientRow),
    off.map(mgClientRow),
    h('p', { class: 'mg-note' }, 'Another system holds a management connection to this device. Changes made there may overwrite this configuration, and what you see here can change without J-Wicket knowing.'),
  );
}

/** The device panel when no snapshot is there yet: the read's state, with "Read again" on errors. */
function inventoryStateCard() {
  const waiting = inventoryWaiting();
  const err = S.invError && (!S.invError.scope || S.invError.scope === S.scope) ? S.invError : null;
  const again = [h('button', { class: 'btn sm', type: 'button', on: { click: () => { closePanel(); inventory(true); } } }, 'Read again')];
  if (waiting) return stateCard({ status: 'waiting' });
  if (!err) return stateCard({ status: 'loading', message: 'The device is being read.', code: false });
  // F7: the message already says when it tries again, so the S-3 hint would repeat it.
  if (err.status === 'busy') return stateCard({ status: 'busy', message: err.message, hint: null, actions: again });
  const status = err.status === 0 ? 'offline' : err.status === 'internal' ? 'internal' : 'failed';
  return stateCard({ status, message: err.message, actions: again });
}

function openDevicePanel() {
  const snap = S.lastInventory;
  const content = snap ? h('div', { class: 'panel-section' }, deviceFacts(snap)) : inventoryStateCard();
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
  const sum = S.sessionsSummary && S.sessionsSummary.summary;
  const counts = {
    policies: pol && pol.status === 'ok' ? format.num((pol.rows || []).length) : '',
    sessions: sum && Number.isFinite(sum.active) ? format.compact(sum.active) : '',
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
    // A 409 (CSV without a configuration read) carries the server's own explanation.
    if (res.status !== 401) toast((res.data && res.data.error) || `The export failed (HTTP ${res.status}).`, 'error');
    return false;
  }
  const filename = res.filename || `jwicket-${scope.replace(/[^A-Za-z0-9._-]/g, '_')}.${fmt}`;
  // Say what is about to be saved before the browser writes it (UI-001-15). The read time is the one
  // the server put in the file name (…-YYYYMMDDTHHMMSSZ…), else the time the reply arrived.
  const stamp = /-\d{8}T(\d{2})(\d{2})(\d{2})Z/.exec(filename);
  const readAt = stamp ? `${stamp[1]}:${stamp[2]}:${stamp[3]}` : format.time(new Date());
  const dev = S.lastInventory && S.lastInventory.device;
  const host = dev && dev.status === 'ok' && dev.hostname ? dev.hostname : 'device';
  const user = (S.session && S.session.user) || '?';
  const save = await confirmToast(`${filename}: ${host}, ${label}, read ${readAt} UTC as ${user}`, { ok: 'Save', cancel: 'Cancel' });
  if (gen !== S.gen) return false;
  if (!save) {
    toast('Export not saved.', 'info');
    return false;
  }
  const url = URL.createObjectURL(res.blob);
  const link = h('a', { href: url, download: filename, class: 'sr-only' });
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30000);
  toast(`Saved ${filename}.`, 'ok');
  return true;
}

const scopeIcon = (id) => {
  const kind = scopeKind(String(id));
  return kind === 'root' ? 'server' : kind === 'lsys' ? 'layers' : 'tenant';
};

/** A section of the current scope's snapshot when it read ok, else null. */
function okSection(snap, key) {
  const s = snap && snap.scope && snap.scope[key];
  return s && s.status === 'ok' ? s : null;
}

/**
 * The palette's items. Every item has a stable `id` (view:logs, action:refresh, scope:<id>,
 * policy:<row id>, zone:<name>, addr:<book>|<name>, app:<name>, filter:<view>|<q>), so the palette
 * can rank what was run recently first, and a `name` to match on (default: the label).
 */
function paletteItems() {
  const items = [];
  for (const v of VIEWS) {
    items.push({ id: `view:${v.id}`, group: 'Views', name: v.title, label: `Go to ${v.title}`, detail: v.sub, hint: ['g', v.key], icon: v.icon, keywords: v.id, run: () => navigate(v.id, {}) });
  }
  const anyLive = S.live.size > 0;
  const nextTheme = effectiveTheme() === 'light' ? 'night (dark)' : 'day (light)';
  const comfy = document.documentElement.dataset.density === 'comfortable';
  const snap = S.lastInventory;
  const cfg = snap && snap.config;
  // CRT-04: no export without a configuration read; say why instead, and open the device panel.
  const exports =
    cfg && cfg.status === 'ok'
      ? [
          { id: 'action:export-json', group: 'Actions', label: 'Export the policy inventory as JSON', icon: 'download', keywords: 'download snapshot', run: () => exportInventory('json') },
          { id: 'action:export-csv', group: 'Actions', label: 'Export the policy inventory as CSV', icon: 'download', keywords: 'download spreadsheet', run: () => exportInventory('csv') },
        ]
      : [
          {
            id: 'action:export-unavailable',
            group: 'Actions',
            label: snap ? `Export not available: the configuration was not read (${(cfg && cfg.status) || 'not reported'})` : 'Export not available: the configuration was not read yet',
            icon: 'download',
            keywords: 'export download snapshot spreadsheet json csv',
            run: openDevicePanel,
          },
        ];
  items.push(
    { id: 'action:refresh', group: 'Actions', label: 'Refresh from the device', hint: ['r'], icon: 'refresh', keywords: 'reload read again', run: refresh },
    { id: 'action:live', group: 'Actions', label: anyLive ? 'Pause or resume live updates' : 'Pause or resume live updates (in Sessions and Logs)', hint: ['Space'], icon: 'pause', keywords: 'live poll stop start', run: () => dispatch('toggle-live') },
    { id: 'action:theme', group: 'Actions', label: `Switch to the ${nextTheme} theme`, hint: ['t'], icon: effectiveTheme() === 'light' ? 'moon' : 'sun', keywords: 'theme dark light colour color', run: toggleTheme },
    ...SCHEMES.filter((s) => s.id !== currentScheme()).map((s) => ({ id: `action:scheme:${s.id}`, group: 'Actions', label: `Use the ${s.label} colour scheme`, detail: s.detail, icon: 'info', keywords: 'theme scheme colour color palette hpe obsidian phosphor nordic steel colourblind colorblind', run: () => setScheme(s.id) })),
    { id: 'action:density', group: 'Actions', label: comfy ? 'Use dense rows' : 'Use comfortable rows', icon: 'rows', keywords: 'density compact spacing', run: toggleDensity },
    { id: 'action:rail', group: 'Actions', label: railCollapsed() ? 'Expand the rail' : 'Collapse the rail', hint: ['['], icon: 'sidebar', keywords: 'sidebar navigation', run: toggleRail },
    { id: 'action:keys', group: 'Actions', label: 'Show keyboard shortcuts', hint: ['?'], icon: 'keyboard', keywords: 'help keys', run: showKeys },
    { id: 'action:device', group: 'Actions', label: 'What you are looking at (device details)', icon: 'server', keywords: 'device identity ha cluster release read as source time zone', run: openDevicePanel },
    { id: 'action:link', group: 'Actions', label: 'Copy a link to this view', icon: 'link', keywords: 'share url', run: () => copy(location.href, 'Link copied. It holds the view and its filters, not device data.') },
    { id: 'action:announce', group: 'Actions', label: announcementsMuted() ? 'Turn live announcements back on' : 'Mute live announcements (screen reader)', icon: 'info', keywords: 'screen reader aria live region speak quiet mute unmute', run: toggleAnnouncements },
    ...exports,
    { id: 'action:signout', group: 'Actions', label: 'Sign out', icon: 'signout', keywords: 'logout log out exit', run: signOut },
  );
  // Common incident filters, so typing "deny" or "commit" finds the logs as well as the policies.
  const filter = (view, q, label, iconName, keywords) => ({ id: `filter:${view}|${q}`, group: 'Filters', label, detail: q, icon: iconName, keywords, run: () => navigate(view, { q }) });
  items.push(
    filter('logs', 'tag:RT_FLOW_SESSION_DENY', 'Logs: session denies', 'logs', 'deny denied blocked drop rt_flow'),
    filter('logs', 'tag:UI_COMMIT*', 'Logs: commits and configuration changes', 'logs', 'commit change config who changed'),
    filter('policies', 'action:deny|reject', 'Policies: deny and reject', 'policies', 'deny denied reject blocked'),
    filter('policies', 'inactive:true', 'Policies: inactive', 'policies', 'inactive deactivated disabled'),
    filter('sessions', 'nat!=none', 'Sessions with NAT', 'sessions', 'nat snat dnat translated'),
  );
  for (const s of (snap && snap.meta && snap.meta.scopes) || []) {
    if (s.id === S.scope) continue;
    const blocked = s.selectable === false;
    items.push({
      id: `scope:${s.id}`,
      group: 'Scopes',
      name: String(s.label ?? s.id),
      label: `Switch scope to ${s.label ?? s.id}`,
      detail: blocked ? 'cannot be opened in J-Wicket yet' : `${format.plural(s.policies, 'policy')}${s.inactive ? `${SEP}deactivated` : ''}`,
      icon: scopeIcon(s.id),
      keywords: `${s.id} scope lsys tsys tenant logical`,
      run: () => (blocked ? toast(`${plain(String(s.label ?? s.id), { all: true })}: ${s.reason || 'J-Wicket cannot open this scope yet.'}`, 'warn') : setScope(s.id)),
    });
  }
  // Queries visited in this tab: shown under Recent when the palette opens empty (recentRank).
  const byId = new Map(items.map((it) => [it.id, it]));
  S.recent.forEach((r, i) => {
    const v = VIEW_BY_ID.get(r.view);
    const id = `filter:${r.view}|${r.q}`;
    const known = byId.get(id);
    if (known) {
      if (!Number.isFinite(known.recentRank)) known.recentRank = i;
      return;
    }
    const item = { id, group: 'Recent filters', label: r.q, detail: v.title, icon: v.icon, keywords: v.title, recentRank: i, run: () => navigate(r.view, new URLSearchParams(r.params)) };
    byId.set(id, item);
    items.push(item);
  });
  const pol = okSection(snap, 'policies');
  for (const r of (pol && pol.rows) || []) {
    const from = (r.from || []).length ? r.from.join(',') : 'any';
    const to = (r.to || []).length ? r.to.join(',') : 'any';
    items.push({
      id: `policy:${r.id}`,
      group: 'Policies',
      label: r.name,
      detail: `${r.kind === 'global' ? 'global ' : ''}${from} → ${to}${SEP}${r.action}${r.inactive_reason ? `${SEP}inactive` : ''}`,
      icon: 'policies',
      keywords: [from, to, r.action, r.description, r.group, r.comment, r.pair_comment].filter(Boolean).join(' '),
      run: () => navigate('policies', { q: `name:${quoteValue(r.name)}`, sel: r.id }),
    });
  }
  const zones = okSection(snap, 'zones');
  for (const z of (zones && zones.rows) || []) {
    const ifaces = (z.interfaces || []).map((i) => i.name);
    items.push({
      id: `zone:${z.name}`,
      group: 'Zones',
      label: z.name,
      detail: ifaces.length ? ifaces.join(' ') : 'no interfaces',
      icon: 'zone',
      keywords: `zone ${ifaces.join(' ')} ${z.description || ''}`,
      run: () => navigate('policies', { q: `zone:${quoteValue(z.name)}` }),
    });
  }
  // SL-11: address-book entries and sets, and applications and application sets; each opens its
  // Objects panel (ids as objects.js builds them: addr|book|name, set|book|name, app|name).
  const books = okSection(snap, 'address_books');
  for (const b of (books && books.rows) || []) {
    for (const a of b.addresses || []) {
      items.push({
        id: `addr:${b.name}|${a.name}`,
        group: 'Addresses',
        label: a.name,
        detail: `${a.value || a.kind || 'address'}${SEP}book ${b.name}`,
        icon: 'globe',
        keywords: ['address', a.kind, a.description, a.comment, b.name].filter(Boolean).join(' '),
        run: () => navigate('objects', { tab: 'address-books', sel: `addr|${b.name}|${a.name}` }),
      });
    }
    for (const s of b.sets || []) {
      const n = (s.addresses || []).length + (s.sets || []).length;
      items.push({
        id: `addr:${b.name}|${s.name}`,
        group: 'Addresses',
        label: s.name,
        detail: `set of ${n}${SEP}book ${b.name}`,
        icon: 'globe',
        keywords: ['address set', s.description, s.comment, b.name, ...(s.addresses || []), ...(s.sets || [])].filter(Boolean).join(' '),
        run: () => navigate('objects', { tab: 'address-books', sel: `set|${b.name}|${s.name}` }),
      });
    }
  }
  const apps = okSection(snap, 'applications');
  for (const a of (apps && apps.rows) || []) {
    const isSet = a.kind === 'set';
    const n = (a.members || []).length + (a.sets || []).length;
    const proto = [a.protocol, a.destination_port].filter((x) => x !== null && x !== undefined && x !== '').join(' ');
    items.push({
      id: `app:${a.name}`,
      group: 'Applications',
      label: a.name,
      detail: isSet ? `set of ${n}` : proto || 'application',
      icon: 'grid',
      keywords: ['application', isSet ? 'set' : '', a.description, a.comment, ...(a.members || []), ...(a.sets || [])].filter(Boolean).join(' '),
      run: () => navigate('objects', { tab: 'applications', sel: `app|${a.name}` }),
    });
  }
  return items;
}

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/;
const IPV6 = /^[0-9A-Fa-f:]*:[0-9A-Fa-f:]*:[0-9A-Fa-f:.]*(?:\/(\d{1,3}))?$/;

function addressOf(text) {
  const m4 = IPV4.exec(text);
  if (m4) {
    if (m4.slice(1, 5).some((o) => Number(o) > 255)) return null;
    if (m4[5] !== undefined && Number(m4[5]) > 32) return null;
    return { value: text, cidr: m4[5] !== undefined };
  }
  const m6 = IPV6.exec(text);
  if (m6 && text.length <= 49 && !/:::/.test(text)) {
    if (m6[1] !== undefined && Number(m6[1]) > 128) return null;
    return { value: text, cidr: m6[1] !== undefined };
  }
  return null;
}

/** What the palette offers for a pasted address, CIDR, port or session id (computed as you type). */
function lookupItems(text) {
  const q = String(text || '').trim();
  if (!q || q.startsWith('>') || q.length > 49 || /\s/.test(q)) return [];
  const items = [];
  const addr = addressOf(q);
  if (addr) {
    const v = addr.value;
    const either = `src:${v} or dst:${v}`;
    items.push(
      { id: `lookup:1|${q}`, group: 'Look up', label: `Sessions with ${v} as source or destination`, detail: either, icon: 'sessions', run: () => navigate('sessions', { q: either }) },
      { id: `lookup:2|${q}`, group: 'Look up', label: `Sessions from ${v}`, detail: `src:${v} (filtered on the device)`, icon: 'sessions', run: () => navigate('sessions', { q: `src:${v}` }) },
      { id: `lookup:3|${q}`, group: 'Look up', label: `Logs with ${v}`, detail: addr.cidr ? either : v, icon: 'logs', run: () => navigate('logs', { q: addr.cidr ? either : v }) },
      { id: `lookup:4|${q}`, group: 'Look up', label: `Policies that match ${v}`, detail: `addr:${v}`, icon: 'policies', run: () => navigate('policies', { q: `addr:${v}` }) },
    );
    return items;
  }
  if (/^\d{1,12}$/.test(q)) {
    const n = Number(q);
    if (n >= 1 && n <= 65535) {
      items.push(
        { id: `lookup:5|${q}`, group: 'Look up', label: `Sessions to port ${n}`, detail: `dport:${n} (filtered on the device)`, icon: 'sessions', run: () => navigate('sessions', { q: `dport:${n}` }) },
        { id: `lookup:6|${q}`, group: 'Look up', label: `Logs with destination port ${n}`, detail: `dport:${n}`, icon: 'logs', run: () => navigate('logs', { q: `dport:${n}` }) },
      );
    }
    items.push(
      { id: `lookup:7|${q}`, group: 'Look up', label: `Session ${q}`, detail: `id:${q}`, icon: 'sessions', run: () => navigate('sessions', { q: `id:${q}` }) },
      { id: `lookup:8|${q}`, group: 'Look up', label: `Logs for session ${q}`, detail: `session:${q}`, icon: 'logs', run: () => navigate('logs', { q: `session:${q}` }) },
    );
  }
  return items;
}

const palette = new Palette({
  getItems: paletteItems,
  getLookups: lookupItems,
  placeholder: 'Search views, policies, zones, addresses and actions, or paste an address, port or session id…',
});

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
        [k(IS_MAC ? '⌘' : 'Ctrl', 'K'), 'Command palette: views, policies, zones, actions, or paste an address, port or session id'],
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

/**
 * The sign-in screen, with a notice or an error. `user` prefills the user name field (the departing
 * user, so signing in again is quick); it lives only in that field.
 */
function showSignIn(message, isError, user = '') {
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
  if (user && !token) $('username').value = String(user);
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
    showSignInError(res.status === 503 ? signInUnavailableText(res.data) : res.data.error || `Sign-in failed (HTTP ${res.status}).`);
    (token ? $('token') : $('password')).focus();
    return;
  }
  S.session = { ...(S.server || {}), ...res.data };
  enterApp();
}

/**
 * SL-07: a 503 at sign-in. At the session cap the server gives counts and bounds (B-7): the latest
 * time a slot must free (the absolute limit cannot be extended), and when one would free if its user
 * stays inactive. The absolute limit itself is known only from an earlier sign-in in this tab.
 */
function signInUnavailableText(data) {
  const d = data || {};
  if (d.reason === 'session-limit') {
    const max = d.sessions && Number.isFinite(Number(d.sessions.max)) ? Number(d.sessions.max) : null;
    const absolute = S.lastFacts && Number(S.lastFacts.absolute_timeout_s);
    const freeBy = Number(d.slot_free_by_s);
    const mayFree = Number(d.slot_may_free_in_s);
    let text = max !== null ? `All ${max} J-Wicket sessions on this device are in use.` : 'All J-Wicket sessions on this device are in use.';
    if (d.slot_free_by) {
      text += ` One ends by ${hhmm(d.slot_free_by)} UTC at the latest${absolute ? ` (sessions last at most ${spanText(absolute)})` : ''}`;
      if (Number.isFinite(mayFree) && mayFree > 0 && (!Number.isFinite(freeBy) || mayFree < freeBy)) {
        text += `, or in about ${Math.max(1, Math.ceil(mayFree / 60))} min if its user stays inactive`;
      }
      text += '.';
    }
    return `${text} Ask a colleague to sign out, or try again later.`;
  }
  const base = String(d.error || 'Sign-in is not available right now.').trim();
  return `${base} J-Wicket cannot tell when the device's management service will answer; try again in a minute.`;
}

let signingOut = false;

async function signOut() {
  if (!S.session || signingOut) return;
  signingOut = true;
  try {
    let res = await api.post('/api/logout', {});
    if (res.status === 403) {
      // CRT-05: another tab of this browser signed in since (a new session, a new CSRF token). Take
      // the browser's current token and try once more; the token itself is never shown.
      const fresh = await api.get('/api/session', null, { evenIfHidden: true, foreground: true });
      if (fresh.ok && fresh.data.authenticated && fresh.data.csrf) {
        api.setCsrf(fresh.data.csrf);
        res = await api.post('/api/logout', {});
      } else if (fresh.ok && fresh.data.authenticated === false) {
        res = { ok: true, status: 200, data: {} };
      }
    }
    const info = await api.get('/api/session', null, { evenIfHidden: true });
    if (info.ok) S.server = info.data;
    // A 401 means the session had already ended (idle timeout, or signed out in another tab).
    const closed = res.ok || res.status === 401 || (info.ok && info.data.authenticated === false);
    if (closed) announceSignedOut();
    if (closed) leaveApp('You are signed out. Your device session is closed.', false);
    else leaveApp(res.status === 403 ? 'J-Wicket could not confirm the sign-out. Close the browser to be sure.' : res.data.error || 'J-Wicket could not confirm the sign-out. Close the browser to be sure.', true);
  } finally {
    signingOut = false;
  }
}

/**
 * SL-06: why the session ended, from the server's reason (401 body, the keep-alive, or the `ended`
 * of GET /api/session after a reload). `facts` are the session limits when known (this tab's sign-in);
 * after a reload they are not, and the wording leaves them out.
 */
function endedText(reason, { at = null, user = '', facts = null, detail = '', signedOut = false, hadSession = false } = {}) {
  const f = facts || {};
  switch (reason) {
    case 'replaced': {
      const when = at ? ` at ${hhmm(at)} UTC` : '';
      const who = user ? plain(user, { all: true }) : 'the same Junos user';
      const max = Number(f.max_sessions_per_user);
      const keeps = Number.isFinite(max) && max > 0 ? `at most ${max} sessions per Junos user` : 'only a few sessions per Junos user';
      return `You were signed out${when}: ${who} signed in again in another browser or on another computer, and J-Wicket keeps ${keeps} (the oldest closes). Signing in again here closes the oldest of the others.`;
    }
    case 'idle': {
      const n = Math.round((Number(f.idle_timeout_s) || 0) / 60);
      return n
        ? `You were signed out after ${n} min without activity. J-Wicket keeps no password, so sign in again.`
        : 'You were signed out after a time without activity. J-Wicket keeps no password, so sign in again.';
    }
    case 'absolute': {
      const s = Number(f.absolute_timeout_s);
      return s > 0 ? `You were signed out: a J-Wicket session lasts at most ${spanText(s)}.` : 'You were signed out: a J-Wicket session has a fixed maximum length, and this one reached it.';
    }
    case 'signed-out':
      return 'You signed out in another tab or window.';
    case 'session-lost':
      return `Your device session ended${signedOut && detail ? `: ${plain(detail)}` : ''}. Sign in again; J-Wicket keeps no password, so it cannot reconnect for you.`;
    case 'none':
      // A 401 with no session cookie. Signing out clears the cookie for the whole browser, so a tab
      // that had a session also lands here when the operator signed out in another tab (F2).
      return hadSession
        ? 'This browser no longer has a J-Wicket session: you may have signed out in another tab or window, or J-Wicket restarted. Sign in again.'
        : 'J-Wicket has no session for this browser (it may have restarted). Sign in again.';
    default:
      return 'Your J-Wicket session has ended: it was idle too long, you signed out in another tab, the same user signed in again elsewhere, or J-Wicket restarted. Sign in again.';
  }
}

function onUnauthorized(data) {
  if (!S.session) return;
  const d = data || {};
  const reason = typeof d.reason === 'string' ? d.reason : d.signed_out ? 'session-lost' : 'unknown';
  const user = S.session.user || '';
  const message = endedText(reason, { at: d.at || null, user, facts: S.session, detail: d.error ? String(d.error) : '', signedOut: Boolean(d.signed_out), hadSession: true });
  leaveApp(message, true, { user });
}

// F2: signing out clears the cookie for every tab of this browser, so the other tabs are told at once
// and say why (SL-06 'signed-out'), instead of finding out from a 401 that carries no reason. Only
// same-origin pages of this browser profile can post on the channel; the message carries nothing.
const SIGNOUT_CHANNEL = 'jwicket-signout';
let signoutChannel = null;

function openSignoutChannel() {
  if (typeof BroadcastChannel !== 'function' || signoutChannel) return;
  try {
    signoutChannel = new BroadcastChannel(SIGNOUT_CHANNEL);
  } catch (_err) {
    signoutChannel = null;
    return;
  }
  signoutChannel.onmessage = (ev) => {
    if (!ev || !ev.data || ev.data.type !== 'signed-out' || !S.session || signingOut) return;
    const user = S.session.user || '';
    leaveApp(endedText('signed-out'), true, { user });
  };
}

function announceSignedOut() {
  try {
    if (signoutChannel) signoutChannel.postMessage({ type: 'signed-out' });
  } catch (_err) {
    // Another tab then learns it from its next request.
  }
}

/**
 * CRT-05: a reply was read as another user than this tab's, so this browser signed in again (another
 * tab or window). Ask the server who this browser is now and follow it.
 */
async function recheckSession() {
  if (!S.session || S.checkingSession) return;
  S.checkingSession = true;
  const gen = S.gen;
  try {
    const res = await api.get('/api/session', null, { evenIfHidden: true });
    if (gen !== S.gen || !S.session || !res.ok) return;
    const d = res.data || {};
    if (d.authenticated === false) {
      const ended = d.ended && typeof d.ended === 'object' ? d.ended : {};
      const user = S.session.user || '';
      leaveApp(endedText(ended.reason || 'unknown', { at: ended.at || null, user, facts: S.session }), true, { user });
    } else if (d.authenticated && d.user !== S.session.user) {
      switchUser(d);
    } else if (d.authenticated) {
      // The same user in a newer session of this browser: take its token and limits.
      S.session = { ...S.session, ...d };
      if (d.csrf) api.setCsrf(d.csrf);
      armEndsWarning();
    }
  } finally {
    S.checkingSession = false;
  }
}

/** This tab now follows the browser's new session: nothing read as the old user is kept. */
function switchUser(data) {
  const old = S.session ? S.session.user : '';
  resetApp();
  S.session = { ...(S.server || {}), ...data };
  enterApp();
  toast(`This browser is now signed in as ${data.user} (a sign-in in another tab or window). This tab now reads as ${data.user}; nothing read as ${old} is kept.`, 'warn', { ms: 20000 });
}

function onApiResponse(data, path) {
  noteFixture(data && data.meta);
  if (!S.session || !data || typeof data !== 'object') return;
  const ra = data.meta && data.meta.read_as;
  if (ra && typeof ra.user === 'string' && ra.user !== S.session.user) {
    recheckSession();
    return;
  }
  if (path === '/api/sessions') noteSessionsSummary(data);
}

/** SL-09: one warning 5 min before the absolute limit ends the session. */
function armEndsWarning() {
  clearTimeout(S.endsTimer);
  S.endsTimer = 0;
  const s = S.session;
  const end = s && s.ends_by ? Date.parse(s.ends_by) : NaN;
  if (!Number.isFinite(end)) return;
  const gen = S.gen;
  const warn = () => {
    S.endsTimer = 0;
    if (gen !== S.gen || !S.session) return;
    const h = S.session.absolute_timeout_s ? ` (${spanText(S.session.absolute_timeout_s)} limit)` : '';
    toast(`Your J-Wicket session ends at ${hhmm(end)} UTC${h}. Sign in again then; J-Wicket keeps no password.`, 'warn', { ms: 30000 });
  };
  const wait = end - ENDS_WARN_MS - Date.now();
  if (end <= Date.now()) return;
  if (wait <= 0) warn();
  else S.endsTimer = setTimeout(warn, Math.min(wait, 2 ** 31 - 1));
}

// ---- idle pause ----------------------------------------------------------------------------------

let idleNote = null;

/** Reads pause well before the server's idle timeout, so the timeout can end an unattended session. */
function idleLimitMs(session) {
  const timeout = Number(session && session.idle_timeout_s) || 900;
  return Math.max(60, timeout - 300) * 1000;
}

function onIdleChange(idle) {
  if (idleNote) {
    idleNote.remove();
    idleNote = null;
  }
  const on = Boolean(idle && S.session);
  document.documentElement.classList.toggle('is-idle', on);
  // SL-08: views show the pause in their own LIVE pills.
  window.dispatchEvent(new CustomEvent('jwicket:idle', { detail: { idle: on } }));
  if (!on) {
    if (!idle && S.session) say('Live reads resumed.');
    return;
  }
  const limit = idleLimitMs(S.session);
  const mins = Math.round(limit / 60000);
  const ends = Math.round((Number(S.session.idle_timeout_s) || 900) / 60);
  // The server counts idle time from the last request that reported activity (B-4); that is at or
  // just after the last input, hence "about".
  const endsAt = Date.now() - limit + ends * 60000;
  idleNote = h(
    'div',
    { class: 'toast warn idle-note', role: 'status' },
    icon('pause'),
    h(
      'div',
      { class: 'toast-msg' },
      h('b', null, 'Paused: no activity. '),
      `No key or pointer input for ${mins} min, so live reads have stopped. They resume when you move the pointer or press a key. Your session ends ${ends} min after your last activity (about ${hhmm(endsAt)} UTC) unless you come back.`,
    ),
    h('button', { class: 'btn sm', type: 'button', on: { click: () => api.noteActivity() } }, 'Resume'),
  );
  $('toasts').append(idleNote);
  say('Live reads paused: no activity.', true);
}

function watchActivity() {
  const note = () => api.noteActivity();
  for (const type of ['keydown', 'pointerdown', 'pointermove', 'wheel', 'touchstart']) {
    document.addEventListener(type, note, { capture: true, passive: true });
  }
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') api.noteActivity();
  });
}

function enterApp() {
  S.gen += 1;
  api.setCsrf(S.session.csrf);
  api.noteActivity();
  api.setIdleLimit(idleLimitMs(S.session));
  const s = S.session;
  S.lastFacts = { idle_timeout_s: s.idle_timeout_s, absolute_timeout_s: s.absolute_timeout_s, max_sessions_per_user: s.max_sessions_per_user };
  armEndsWarning();
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

/** Forget everything of this sign-in (device data, views, timers, toasts); the page stays. */
function resetApp() {
  S.gen += 1;
  unmountCurrent();
  closePanel();
  if (palette.isOpen) palette.close({ restoreFocus: false });
  palette.clearRecent();
  closeKeys();
  closeScopeMenu();
  clearToasts();
  clearInvRetry();
  clearTimeout(S.endsTimer);
  S.endsTimer = 0;
  S.session = null;
  S.inv.clear();
  S.invInflight.clear();
  S.invError = null;
  S.invWaiting = null;
  S.lastInventory = null;
  S.policyIdx = null;
  S.sessionsLast = null;
  S.sessionsSummary = null;
  S.live.clear();
  S.recent = [];
  S.scope = 'root';
  document.documentElement.classList.remove('is-idle');
  markScope();
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
}

function leaveApp(message, isError, { user = '' } = {}) {
  resetApp();
  showSignIn(message, isError, user);
}

// ---- boot ----------------------------------------------------------------------------------------

async function boot() {
  applyPrefs();
  wirePanel();
  openSignoutChannel();
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
      if (P.open) syncPanelModal();
    }),
  );
  if (window.matchMedia) {
    const mq = window.matchMedia('(prefers-color-scheme: light)');
    if (mq.addEventListener) mq.addEventListener('change', updateThemeButton);
  }
  api.onUnauthorized(onUnauthorized);
  api.onResponse(onApiResponse);
  api.onIdle(onIdleChange);
  watchActivity();

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
  } else if (res.ok && res.data.ended && typeof res.data.ended === 'object') {
    // SL-06: after a reload, say why this browser's session ended (as a notice, not an error).
    const ended = res.data.ended;
    showSignIn(endedText(String(ended.reason || 'unknown'), { at: ended.at || null, facts: S.lastFacts }), false);
  } else {
    showSignIn();
  }
}

boot();
