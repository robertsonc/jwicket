// J-Wicket browser UI: Spec 001, a scoped, read-only security policy inventory.
//
// Rules this file keeps (see the build brief and src/jwicket/web/http.py):
// * Strict CSP with Trusted Types: no innerHTML, outerHTML, insertAdjacentHTML or document.write.
//   Every node is built with createElement and textContent; no inline style attributes (CSSOM only).
// * No sample data, ever: a panel shows device data or an explicit state (denied, unsupported,
//   failed, session-lost) with the server's operator-safe message.
// * Nothing read from the device is stored in the browser. localStorage holds the theme only.
// * No automatic polling. The device is read on sign-in, on scope change and on Refresh.
// * Explain, don't guess: the UI shows Junos evaluation order and the CLI to test a flow; it does
//   not reimplement the policy matcher.

const THEME_KEY = 'jwicket.theme';
const READ_GAP_MS = 2000; // the server refuses a re-read within 2 s (HTTP 429)
const AGE_TICK_MS = 30000;
const LIST_LIMIT = 6; // names shown per table cell before "+N more"
const ARROW = '\u2192';
const SEP = ' \u00b7 ';

const STATE_TITLES = {
  denied: 'Your Junos login class does not allow this',
  unsupported: 'This device does not support or has not enabled this',
  failed: 'The device could not complete this read',
  'session-lost': 'Your device session ended',
  rejected: 'Junos refused the sign-in',
  unavailable: 'J-Wicket could not reach the device management service',
};
const STATE_HINTS = {
  denied: 'J-Wicket shows only what your Junos login class may read. If you need this view, ask your Junos administrator about your login class.',
  unsupported: 'This is a property of the device or its configuration, not a J-Wicket error.',
  failed: 'Press Refresh to try again. If it keeps failing, check the J-Wicket log on the device.',
  'session-lost': 'Sign in again. J-Wicket keeps no password, so it cannot reconnect for you.',
};

// ---- state ---------------------------------------------------------------------------------------

const S = {
  server: null, // GET /api/session answer while signed out: credential, backend, fixture, version
  session: null, // the signed-in session: user, csrf, backend, idle_timeout_s, ...
  scope: 'root',
  snap: null, // the last good snapshot
  receivedAt: 0, // browser time the snapshot arrived (age is measured from here, not the server clock)
  lastReadAt: 0,
  reading: false,
  retryTimer: 0,
  model: null,
  filters: defaultFilters(),
  tab: 'policies',
  warningsOpen: false,
  opener: null,
};

function defaultFilters() {
  return { q: '', from: '', to: '', action: '', inactive: true, groupsOnly: false };
}

// ---- DOM helpers ---------------------------------------------------------------------------------

const byId = (id) => document.getElementById(id);

/** Build an element. opts: class, text, on:{event:fn}, dataset, hidden, plus plain attributes. */
function h(tag, opts, ...kids) {
  const node = document.createElement(tag);
  if (opts) {
    for (const [key, value] of Object.entries(opts)) {
      if (value === undefined || value === null || value === false) continue;
      if (key === 'class') node.className = Array.isArray(value) ? value.filter(Boolean).join(' ') : value;
      else if (key === 'text') node.textContent = String(value);
      else if (key === 'on') for (const [ev, fn] of Object.entries(value)) node.addEventListener(ev, fn);
      else if (key === 'dataset') Object.assign(node.dataset, value);
      else if (key === 'hidden') node.hidden = true;
      else if (/^on/i.test(key) || key === 'style' || key === 'srcdoc') throw new Error(`refused attribute ${key}`);
      else node.setAttribute(key, value === true ? '' : String(value));
    }
  }
  appendKids(node, kids);
  return node;
}

function appendKids(node, kids) {
  for (const kid of kids.flat(Infinity)) {
    if (kid === null || kid === undefined || kid === false || kid === '') continue;
    node.append(kid instanceof Node ? kid : String(kid));
  }
  return node;
}

const line = (...kids) => h('div', { class: 'line' }, ...kids);
const mute = (text, cls) => h('span', { class: ['mute', cls], text });
const data = (text) => h('span', { class: 'data', text });

let liveTimer = 0;
function announce(text) {
  const live = byId('live');
  if (!live) return;
  clearTimeout(liveTimer);
  live.textContent = '';
  liveTimer = setTimeout(() => {
    live.textContent = text;
  }, 60);
}

function setStatus(text, kind) {
  const node = byId('status');
  node.textContent = text || '';
  node.className = 'status' + (kind ? ` is-${kind}` : '');
}

const reducedMotion = () => window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

// ---- formatting ----------------------------------------------------------------------------------

const plural = (n, one, many) => `${Number(n).toLocaleString('en')} ${n === 1 ? one : many || `${one}s`}`;
const pairKey = (from, to) => `${from}\u0000${to}`;
const norm = (text) => String(text || '').toLowerCase().replace(/[.\s]+$/, '').trim();

function utcClock(iso) {
  const when = new Date(iso);
  return Number.isNaN(when.getTime()) ? String(iso || 'unknown time') : when.toISOString().slice(11, 19);
}

function ageText() {
  const secs = Math.max(0, Math.round((Date.now() - S.receivedAt) / 1000));
  if (secs < 45) return 'just now';
  const mins = Math.round(secs / 60);
  if (mins < 60) return `${mins} min ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours} h ${mins % 60} min ago`;
  return `${Math.floor(hours / 24)} d ago`;
}

function updateAge() {
  const node = byId('read-age');
  if (node && S.snap) node.textContent = ageText();
}

function scopeParts(scopeId) {
  if (scopeId.startsWith('lsys:')) return { kind: 'lsys', name: scopeId.slice(5) };
  if (scopeId.startsWith('tenant:')) return { kind: 'tenant', name: scopeId.slice(7) };
  return { kind: 'root', name: null };
}

function scopeLabel(scopeId) {
  const known = S.snap && (S.snap.meta.scopes || []).find((s) => s.id === scopeId);
  if (known) return known.label;
  const parts = scopeParts(scopeId);
  if (parts.kind === 'lsys') return `logical system ${parts.name}`;
  if (parts.kind === 'tenant') return `tenant system ${parts.name}`;
  return 'root system';
}

/** Quote a CLI word only when Junos would need it. */
function cliWord(word) {
  const text = String(word);
  return /^[A-Za-z0-9._:/-]+$/.test(text) ? text : `"${text.replace(/["\\]/g, '\\$&')}"`;
}

function showConfigCli(row) {
  const sp = scopeParts(row.scope || S.scope);
  const prefix =
    sp.kind === 'lsys' ? `logical-systems ${cliWord(sp.name)} ` : sp.kind === 'tenant' ? `tenants ${cliWord(sp.name)} ` : '';
  if (row.kind === 'global') return `show configuration ${prefix}security policies global policy ${cliWord(row.name)}`;
  return (
    `show configuration ${prefix}security policies from-zone ${cliWord(row.from[0] || '?')} ` +
    `to-zone ${cliWord(row.to[0] || '?')} policy ${cliWord(row.name)}`
  );
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

function matchPoliciesCli(scopeId, from, to, row) {
  const sp = scopeParts(scopeId);
  const ex = row ? flowExample(row) : {};
  const words = ['show security match-policies'];
  if (sp.kind === 'lsys') words.push('logical-system', cliWord(sp.name));
  if (sp.kind === 'tenant') words.push('tenant', cliWord(sp.name));
  words.push('from-zone', from ? cliWord(from) : '<from-zone>', 'to-zone', to ? cliWord(to) : '<to-zone>');
  words.push('source-ip', ex.src || '<source-ip>', 'destination-ip', ex.dst || '<destination-ip>');
  words.push('source-port', '<source-port>', 'destination-port', ex.port || '<destination-port>');
  words.push('protocol', ex.proto || '<protocol>');
  return words.join(' ');
}

// ---- theme ---------------------------------------------------------------------------------------

const lightQuery = window.matchMedia ? window.matchMedia('(prefers-color-scheme: light)') : null;

function storedTheme() {
  try {
    const value = window.localStorage.getItem(THEME_KEY);
    return value === 'light' || value === 'dark' ? value : null;
  } catch (_err) {
    return null; // storage blocked or unavailable: follow the system preference
  }
}

function saveTheme(value) {
  try {
    window.localStorage.setItem(THEME_KEY, value);
  } catch (_err) {
    // Storage blocked: the choice lasts until the page is reloaded.
  }
}

const effectiveTheme = () => storedTheme() || (lightQuery && lightQuery.matches ? 'light' : 'dark');

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  const btn = byId('theme');
  const next = theme === 'light' ? 'dark' : 'light';
  btn.textContent = next === 'light' ? 'Light theme' : 'Dark theme';
  btn.setAttribute('aria-label', `Switch to ${next} theme`);
}

// ---- API -----------------------------------------------------------------------------------------

async function api(method, path, body) {
  const headers = { Accept: 'application/json' };
  const init = { method, headers, credentials: 'same-origin', cache: 'no-store', redirect: 'error' };
  if (method !== 'GET') {
    headers['Content-Type'] = 'application/json';
    if (S.session && S.session.csrf) headers['X-CSRF-Token'] = S.session.csrf;
    init.body = JSON.stringify(body || {});
  }
  let res;
  try {
    res = await fetch(path, init);
  } catch (_err) {
    return {
      ok: false,
      status: 0,
      body: {
        error:
          'J-Wicket did not answer. Check that it is running on the device and, if you reach it through an SSH tunnel, that the tunnel is open.',
      },
      retryAfter: 0,
    };
  }
  let payload = {};
  try {
    const parsed = await res.json();
    if (parsed && typeof parsed === 'object') payload = parsed;
  } catch (_err) {
    payload = {};
  }
  const retry = parseInt(res.headers.get('Retry-After') || '', 10);
  return { ok: res.ok, status: res.status, body: payload, retryAfter: Number.isFinite(retry) && retry > 0 ? retry : 0 };
}

// ---- views ---------------------------------------------------------------------------------------

function showView(name) {
  for (const view of ['boot', 'signin', 'app']) byId(`view-${view}`).hidden = view !== name;
  byId('signed-tools').hidden = name !== 'app';
  byId('signout').hidden = name !== 'app';
}

function setFixture(on) {
  byId('fixture-banner').hidden = !on;
}

/** Remove everything read from the device from the page (sign-out, session loss). */
function clearAppData() {
  const dlg = byId('detail');
  if (dlg.open) dlg.close();
  clearTimeout(S.retryTimer);
  S.snap = null;
  S.model = null;
  S.filters = defaultFilters();
  S.scope = 'root';
  S.tab = 'policies';
  byId('device-title').textContent = '';
  for (const id of ['facts', 'warnings', 'inventory-state', 'panel-policies', 'panel-zones', 'panel-books', 'panel-apps']) {
    byId(id).replaceChildren();
  }
  for (const id of ['count-policies', 'count-zones', 'count-books', 'count-apps']) byId(id).textContent = '';
  byId('inventory').hidden = true;
}

// ---- sign-in -------------------------------------------------------------------------------------

let loginLockUntil = 0;
let loginTimer = 0;

function showSignIn(message, isError) {
  clearAppData();
  showView('signin');
  const srv = S.server || {};
  setFixture(Boolean(srv.fixture));
  const token = srv.credential === 'token';
  byId('field-username').hidden = token;
  byId('field-password').hidden = token;
  byId('field-token').hidden = !token;
  byId('signin-copy').textContent = token
    ? 'Lab sign-in with a token. J-Wicket does not store the token in this browser.'
    : 'Junos checks your user name and password and applies your login class. J-Wicket does not store them.';
  const lab = byId('signin-lab');
  if (srv.backend === 'lab-token') {
    lab.replaceChildren(
      h('strong', { text: 'Lab mode. ' }),
      "Every read runs as the daemon's Junos account, not as you. Your own login class is not applied.",
    );
    lab.hidden = false;
  } else {
    lab.hidden = true;
  }
  const notice = byId('signin-notice');
  const error = byId('signin-error');
  notice.hidden = true;
  error.hidden = true;
  if (message) {
    const box = isError ? error : notice;
    box.textContent = message;
    box.hidden = false;
  }
  byId('password').value = '';
  byId('token').value = '';
  setStatus('');
  document.title = 'Sign in · J-Wicket';
  const first = token ? byId('token') : byId('username').value ? byId('password') : byId('username');
  first.focus();
}

function showSignInError(message) {
  const error = byId('signin-error');
  error.textContent = message;
  error.hidden = false;
}

function lockLogin(seconds, message) {
  loginLockUntil = Date.now() + seconds * 1000;
  const btn = byId('signin-submit');
  const base = message || 'Too many sign-in attempts. Wait and try again.';
  showSignInError(`${base} You can try again in ${seconds} s.`);
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
  tick();
  loginTimer = setInterval(tick, 1000);
}

async function onSignIn(event) {
  event.preventDefault();
  if (Date.now() < loginLockUntil) return;
  const token = S.server && S.server.credential === 'token';
  byId('signin-error').hidden = true;
  byId('signin-notice').hidden = true;
  const body = token
    ? { token: byId('token').value }
    : { username: byId('username').value.trim(), password: byId('password').value };
  if (token ? !body.token : !body.username || !body.password) {
    showSignInError(token ? 'Enter the lab token.' : 'Enter your Junos user name and password.');
    (token ? byId('token') : body.username ? byId('password') : byId('username')).focus();
    return;
  }
  const btn = byId('signin-submit');
  btn.disabled = true;
  btn.textContent = 'Signing in…';
  const res = await api('POST', '/api/login', body);
  body.password = '';
  body.token = '';
  byId('password').value = '';
  byId('token').value = '';
  btn.textContent = 'Sign in';
  btn.disabled = false;
  if (res.status === 429) {
    lockLogin(res.retryAfter || 30, res.body.error);
    return;
  }
  if (!res.ok || !res.body.authenticated) {
    showSignInError(res.body.error || `Sign-in failed (HTTP ${res.status}).`);
    (token ? byId('token') : byId('password')).focus();
    return;
  }
  S.session = { ...(S.server || {}), ...res.body };
  const again = await api('GET', '/api/session');
  if (again.ok && again.body.authenticated) S.session = again.body;
  enterApp();
}

async function signOut() {
  const btn = byId('signout');
  btn.disabled = true;
  const res = await api('POST', '/api/logout', {});
  btn.disabled = false;
  S.session = null;
  if (res.ok) {
    showSignIn('You are signed out. Your device session is closed.', false);
  } else {
    showSignIn(res.body.error || 'J-Wicket could not confirm the sign-out. Close the browser to be sure.', true);
  }
}

function sessionLost(message) {
  S.session = null;
  showSignIn(message || 'Sign in again.', true);
}

// ---- the read path -------------------------------------------------------------------------------

function enterApp() {
  showView('app');
  setFixture(Boolean(S.session.fixture));
  const idle = Number(S.session.idle_timeout_s || 0);
  byId('foot-idle').textContent = idle ? `Your J-Wicket session ends after ${Math.round(idle / 60)} min without activity.` : '';
  byId('foot-version').textContent = S.session.version ? `J-Wicket ${S.session.version}` : '';
  byId('device-title').textContent = 'Reading the device…';
  byId('inventory').hidden = true;
  updateExportLinks();
  read({});
}

function setBusy(busy) {
  const btn = byId('refresh');
  btn.disabled = busy;
  btn.textContent = busy ? 'Reading…' : 'Refresh';
  byId('main').setAttribute('aria-busy', busy ? 'true' : 'false');
  const select = byId('scope-select');
  if (select) select.disabled = busy || !(S.snap && (S.snap.meta.scopes || []).length);
}

async function read(opts) {
  if (S.reading || !S.session) return;
  clearTimeout(S.retryTimer);
  const gap = READ_GAP_MS - (Date.now() - S.lastReadAt);
  if (gap > 0) {
    setStatus(`Waiting ${Math.ceil(gap / 1000)} s: J-Wicket reads the device at most once every 2 seconds.`);
    S.retryTimer = setTimeout(() => read(opts), gap);
    return;
  }
  const scope = S.scope;
  S.reading = true;
  setBusy(true);
  setStatus(`Reading ${scopeLabel(scope)} from the device…`);
  S.lastReadAt = Date.now();
  const res = await api('GET', `/api/inventory?scope=${encodeURIComponent(scope)}`);
  S.reading = false;
  setBusy(false);

  if (res.status === 401) {
    sessionLost(res.body.error);
    return;
  }
  if (res.status === 429) {
    const wait = res.retryAfter || 2;
    const msg = res.body.error || 'Reading too often.';
    if (!opts.retried) {
      setStatus(`${msg} Trying again in ${wait} s.`, 'warn');
      S.retryTimer = setTimeout(() => read({ ...opts, retried: true }), wait * 1000);
    } else {
      setStatus(`${msg} Wait ${wait} s, then press Refresh.`, 'warn');
    }
    return;
  }
  if (!res.ok) {
    readProblem(scope, res);
    return;
  }
  S.snap = res.body;
  S.receivedAt = Date.now();
  render();
  const meta = S.snap.meta || {};
  const count = S.snap.scope && S.snap.scope.policies ? (S.snap.scope.policies.rows || []).length : 0;
  setStatus(`Read ${utcClock(meta.read_at)} UTC`);
  announce(
    S.snap.config && S.snap.config.status === 'ok'
      ? `Read ${plural(count, 'policy', 'policies')} in ${scopeLabel(meta.scope || scope)}.`
      : 'Read finished. The security configuration could not be shown; see the message on the page.',
  );
}

/** A read failed. Keep showing the last good snapshot only if it is for the same scope. */
function readProblem(scope, res) {
  const msg = res.body.error || `HTTP ${res.status}`;
  setStatus(`Read failed: ${msg}`, 'error');
  announce(`Read failed: ${msg}`);
  let title;
  let text;
  if (res.status === 404 && Array.isArray(res.body.scopes)) {
    title = 'That scope is not in the configuration';
    text = `${scopeLabel(scope)} was not found in the committed configuration. Choose another scope.`;
    if (S.snap) S.snap.meta.scopes = res.body.scopes;
  } else if (res.status === 0) {
    title = 'J-Wicket did not answer';
    text = msg;
  } else {
    title = 'The read did not complete';
    text = msg;
  }
  if (S.snap) {
    S.scope = S.snap.meta.scope || 'root';
    render();
    text += ` The page still shows the read from ${utcClock(S.snap.meta.read_at)} UTC of ${scopeLabel(S.scope)}.`;
  } else {
    byId('device-title').textContent = 'Device not read';
    byId('facts').replaceChildren(fact('Read as', line(data((S.session && S.session.user) || '?'))));
  }
  byId('inventory-state').prepend(
    h(
      'div',
      { class: 'state-card is-failed', role: 'alert' },
      h('span', { class: 'state-code', text: res.status ? `HTTP ${res.status}` : 'no answer' }),
      h('h3', { text: title }),
      h('p', { text }),
    ),
  );
}

function updateExportLinks() {
  const scope = (S.snap && S.snap.meta.scope) || S.scope;
  for (const fmt of ['json', 'csv']) {
    byId(`export-${fmt}`).setAttribute('href', `/api/export?scope=${encodeURIComponent(scope)}&format=${fmt}`);
  }
}

let exportTimer = 0;

function onExportClick(event) {
  const link = event.currentTarget;
  if (S.reading) {
    event.preventDefault();
    setStatus('A read is in progress. Export again when it finishes.', 'warn');
    return;
  }
  const gap = READ_GAP_MS - (Date.now() - S.lastReadAt);
  if (gap > 0) {
    // Export is a fresh device read; the server would answer 429 and the browser would show it.
    event.preventDefault();
    setStatus(`Export reads the device again; starting in ${Math.ceil(gap / 1000)} s.`);
    const href = link.href;
    clearTimeout(exportTimer);
    exportTimer = setTimeout(() => {
      S.lastReadAt = Date.now();
      setStatus('Export started. The file is a new read of the device, not a copy of this page.');
      window.location.assign(href);
    }, gap);
    return;
  }
  S.lastReadAt = Date.now();
  setStatus('Export started. The file is a new read of the device, not a copy of this page.');
}

// ---- render: shell -------------------------------------------------------------------------------

function render() {
  const snap = S.snap;
  const meta = snap.meta || {};
  S.scope = meta.scope || S.scope;
  setFixture(Boolean(meta.fixture) || Boolean(S.session && S.session.fixture));
  renderBanner(snap);
  renderWarnings(snap);
  updateExportLinks();
  const state = byId('inventory-state');
  state.replaceChildren();
  const cfg = snap.config || {};
  const dev = snap.device || {};
  const host = dev.status === 'ok' && dev.hostname ? dev.hostname : 'device';
  document.title = `${host} · ${scopeLabel(S.scope)} · J-Wicket`;
  if (cfg.status !== 'ok') {
    byId('inventory').hidden = true;
    state.append(stateCard(cfg.status, cfg.message, 'The security configuration of this device is not shown.'));
    return;
  }
  if (!snap.scope) {
    byId('inventory').hidden = true;
    state.append(stateCard('failed', 'No inventory came back for this scope.', 'Nothing to show for this scope.'));
    return;
  }
  byId('inventory').hidden = false;
  renderPolicies(snap.scope);
  renderZones(snap.scope);
  renderBooks(snap.scope);
  renderApps(snap.scope);
  selectTab(S.tab, false);
}

function stateCard(status, message, what) {
  const st = status || 'failed';
  const title = STATE_TITLES[st] || 'This could not be read';
  return h(
    'div',
    { class: ['state-card', `is-${st}`] },
    h('span', { class: 'state-code', text: `status: ${st}` }),
    h('h3', { text: title }),
    what ? h('p', { text: what }) : null,
    message && norm(message) !== norm(title) ? h('p', { text: message }) : null,
    STATE_HINTS[st] ? h('p', { class: 'mute small', text: STATE_HINTS[st] }) : null,
  );
}

function stateInline(status, message) {
  const title = STATE_TITLES[status] || 'Not readable';
  const extra = message && norm(message) !== norm(title) ? `: ${message}` : '';
  return h('span', { class: 'state-inline' }, h('span', { class: 'state-code', text: status || 'failed' }), ' ', `${title}${extra}`);
}

function fact(label, content, cls) {
  return h('div', { class: ['fact', cls] }, h('dt', { text: label }), h('dd', null, content));
}

// ---- render: scope banner ------------------------------------------------------------------------

function renderBanner(snap) {
  const meta = snap.meta || {};
  const dev = snap.device || {};
  byId('device-title').textContent =
    dev.status === 'ok' ? dev.hostname || 'Device without a host name' : 'Device not identified';
  byId('facts').replaceChildren(
    fact('Device', deviceFact(dev)),
    fact('High availability', haFact(snap.ha || {}, dev)),
    fact('Scope', scopeFact(meta, snap.scope)),
    fact('Read as', readAsFact(meta)),
    fact('Source', sourceFact(meta)),
    fact('Central management', mgmtFact(snap.management || {}, snap.config || {}), 'wide'),
  );
}

function deviceFact(dev) {
  if (dev.status !== 'ok') return stateInline(dev.status, dev.message);
  const out = [
    line(h('span', { class: 'data nowrap', text: dev.model || 'model not reported' }), SEP, h('span', { class: 'nowrap' }, 'Junos ', data(dev.version || 'not reported'))),
  ];
  const versions = [...new Set((dev.nodes || []).map((n) => n.version).filter(Boolean))];
  if (versions.length > 1) out.push(line(h('span', { class: 'warn-line', text: `Nodes report different releases: ${versions.join(', ')}` })));
  return out;
}

function haFact(ha, dev) {
  const nodes = dev.status === 'ok' && Array.isArray(dev.nodes) ? dev.nodes : [];
  const withHost = (name) => {
    const node = nodes.find((n) => n.node === name);
    return node && node.hostname ? `${name} (${node.hostname})` : name;
  };
  const out = [];
  if (ha.status && ha.status !== 'ok') {
    out.push(line(stateInline(ha.status, ha.message)));
  } else if (ha.mode === 'standalone') {
    out.push(line('Standalone'));
  } else if (ha.mode === 'chassis-cluster') {
    const groups = ha.redundancy_groups || [];
    const primary = (group) => {
      const p = (group.nodes || []).find((n) => String(n.status || '').toLowerCase() === 'primary');
      return p ? withHost(p.name) : 'none reported';
    };
    const rg0 = groups.find((g) => String(g.id) === '0');
    out.push(line(`Chassis cluster${ha.cluster_id ? ` ${ha.cluster_id}` : ''}`, SEP, 'RG0 primary: ', h('strong', { class: 'data', text: rg0 ? primary(rg0) : 'not reported' })));
    const others = groups.filter((g) => String(g.id) !== '0');
    if (others.length) out.push(line(mute(others.map((g) => `RG${g.id} primary: ${primary(g)}`).join(SEP), 'small')));
    out.push(
      line(mute(ha.local_node ? `This page is served by ${withHost(ha.local_node)}.` : 'Which node serves this page is not reported.', 'small')),
    );
  } else if (ha.mode === 'mnha') {
    out.push(line('Multinode High Availability'));
    if (ha.message) out.push(line(mute(ha.message, 'small')));
  } else {
    out.push(line('Unknown'));
    if (ha.message) out.push(line(mute(ha.message, 'small')));
  }
  if (nodes.length) {
    out.push(
      h(
        'div',
        { class: 'ha-nodes small' },
        nodes.map((n) => h('span', null, mute(`${n.node || 'node'} `), data(n.hostname || '?'))),
      ),
    );
  }
  return out;
}

function scopeFact(meta, scopeInv) {
  const scopes = meta.scopes || [];
  const select = h('select', { id: 'scope-select' });
  if (!scopes.length) {
    const label = scopeLabel(meta.scope || S.scope);
    select.append(h('option', { value: meta.scope || S.scope, text: label.charAt(0).toUpperCase() + label.slice(1) }));
    select.disabled = true;
  }
  for (const s of scopes) {
    const label = `${s.label}${SEP}${plural(s.policies, 'policy', 'policies')}${s.inactive ? `${SEP}deactivated` : ''}`;
    select.append(h('option', { value: s.id, text: label }));
  }
  select.value = meta.scope || S.scope;
  select.addEventListener('change', () => {
    S.scope = select.value;
    S.filters = defaultFilters();
    read({});
  });
  const out = [h('label', { for: 'scope-select', class: 'sr-only', text: 'Scope' }), select];
  if (scopeInv && scopeInv.inactive) {
    out.push(line(h('span', { class: 'warn-line', text: 'Deactivated in the configuration: nothing in this scope is in effect.' })));
  }
  if (!scopes.length && meta.scope) out.push(line(mute('Other scopes are listed once the configuration can be read.', 'small')));
  return out;
}

function readAsFact(meta) {
  const ra = meta.read_as || {};
  const user = ra.user || '?';
  const out = [line(h('strong', { class: 'data', text: user }))];
  if (ra.backend === 'lab-token') {
    out.push(
      h(
        'div',
        { class: 'lab-warning small' },
        h('strong', { text: 'Lab sign-in. ' }),
        `Every read runs as the daemon's Junos account ${user}, not as you.`,
      ),
    );
  } else if (ra.backend === 'netconf') {
    out.push(line(mute('Your own Junos session: your login class decides what you can see.', 'small')));
  } else if (ra.backend === 'fixture') {
    out.push(line(mute('Fixture replay on the development server, not a Junos session.', 'small')));
  } else if (ra.backend) {
    out.push(line(mute(`Sign-in backend: ${ra.backend}`, 'small')));
  }
  return out;
}

function sourceFact(meta) {
  const src = meta.source || {};
  const database = src.database === 'committed' ? 'Committed configuration' : `${src.database || 'Unknown'} configuration`;
  const inherit = src.inheritance ? 'inheritance expanded' : 'inheritance not expanded';
  const time = h('time', { datetime: meta.read_at || '', title: meta.read_at || '' }, `${utcClock(meta.read_at)} UTC`);
  return [
    line(`${database}${SEP}${inherit}${SEP}read `, time, ' (', h('span', { id: 'read-age', text: ageText() }), ')'),
    src.groups_annotated ? line(mute('Each object says which configuration group it came from.', 'small')) : null,
  ];
}

function mgmtFact(mg, cfg) {
  if (mg.status !== 'ok' && cfg.status && cfg.status !== 'ok') {
    // Central management is read from the configuration; it is unknown when that read failed.
    return [
      line(h('span', { class: 'state-inline' }, h('span', { class: 'state-code', text: 'unknown' }), ' Not known: it is read from the configuration, which could not be read.')),
      line(mute('Another system may also manage this device.', 'small')),
    ];
  }
  if (mg.status !== 'ok') {
    return [line(stateInline(mg.status, mg.message)), line(mute('Another system may also manage this device.', 'small'))];
  }
  if (!mg.managed) return line(mute('None configured (no outbound-SSH management client).'));
  const clients = (mg.clients || [])
    .map((c) => `${c.client}${(c.targets || []).length ? ` (${c.targets.join(', ')})` : ''}`)
    .join('; ');
  const services = [...new Set((mg.clients || []).flatMap((c) => c.services || []))];
  return [
    h('div', { class: 'mgmt' }, h('span', { class: 'mgmt-chip' }, h('b', { text: 'Also managed from: ' }), clients || 'an outbound-SSH client')),
    line(
      mute(
        `Another system holds a management connection to this device${services.length ? ` (${services.join(', ')})` : ''}. ` +
          'Changes made there may overwrite this configuration, and what you see here can change without J-Wicket knowing.',
        'small',
      ),
    ),
  ];
}

function renderWarnings(snap) {
  const list = [...(snap.warnings || []), ...((snap.scope && snap.scope.warnings) || [])];
  const box = byId('warnings');
  box.replaceChildren();
  if (!list.length) return;
  const details = h(
    'details',
    { class: 'warnings' },
    h('summary', null, `Warnings (${list.length})`),
    h('ul', null, list.map((w) => h('li', { text: w }))),
  );
  details.open = S.warningsOpen;
  details.addEventListener('toggle', () => {
    S.warningsOpen = details.open;
  });
  box.append(details);
}

// ---- policies: model -----------------------------------------------------------------------------

function searchText(row) {
  const m = row.match || {};
  const bits = [
    row.name, row.description, row.scheduler, row.group, row.tunnel, row.action,
    ...(row.groups || []), ...(row.application_services || []),
    ...(m.source || []), ...(m.destination || []), ...(m.application || []),
    ...(m.source_identity || []), ...(m.dynamic_application || []), ...(m.url_category || []),
    ...(m.source_end_user_profile || []),
  ];
  const res = row.resolved || {};
  for (const side of ['source', 'destination']) {
    for (const item of res[side] || []) {
      bits.push(item.name, item.book, ...(item.unresolved || []));
      for (const leaf of item.leaves || []) bits.push(leaf.name, leaf.value);
    }
  }
  for (const item of res.application || []) {
    bits.push(item.name, ...(item.unresolved || []));
    for (const leaf of item.leaves || []) bits.push(leaf.name, leaf.protocol, leaf.destination_port);
  }
  return bits.filter((b) => b !== null && b !== undefined && b !== '').join('\n').toLowerCase();
}

function buildModel(scope) {
  const pol = scope.policies || {};
  const rows = pol.rows || [];
  const pairs = new Map();
  const globals = [];
  rows.forEach((row, idx) => {
    row.from = row.from || [];
    row.to = row.to || [];
    if (row.kind === 'global') {
      globals.push(idx);
      return;
    }
    const from = row.from[0] || '?';
    const to = row.to[0] || '?';
    const key = pairKey(from, to);
    if (!pairs.has(key)) pairs.set(key, { from, to, rows: [] });
    pairs.get(key).rows.push(idx);
  });
  const zones = [];
  const defined = new Set();
  const zonePanel = scope.zones || {};
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
    row.from.forEach(addZone);
    row.to.forEach(addZone);
  }
  return {
    scope,
    rows,
    search: rows.map(searchText),
    pairs: [...pairs.values()],
    globals,
    zones,
    defined,
    zonesKnown: zonePanel.status === 'ok',
    stats: new Map((pol.zone_pairs || []).map((p) => [pairKey(p.from, p.to), p])),
    sections: [],
    cells: [],
  };
}

const globalApplies = (row, from, to) =>
  (row.from.length === 0 || row.from.includes(from)) && (row.to.length === 0 || row.to.includes(to));

function rowVisible(idx, f, model) {
  const row = model.rows[idx];
  if (!f.inactive && row.inactive) return false;
  if (f.groupsOnly && !(row.group || (row.groups || []).length || (row.inherited || []).length)) return false;
  if (f.action && row.action !== f.action) return false;
  const global = row.kind === 'global';
  if (f.from && !(global ? row.from.length === 0 || row.from.includes(f.from) : row.from.includes(f.from))) return false;
  if (f.to && !(global ? row.to.length === 0 || row.to.includes(f.to) : row.to.includes(f.to))) return false;
  if (f.q) {
    const hay = model.search[idx];
    for (const term of f.q.toLowerCase().split(/\s+/)) if (term && !hay.includes(term)) return false;
  }
  return true;
}

// ---- policies: render ----------------------------------------------------------------------------

function renderPolicies(scope) {
  const panel = byId('panel-policies');
  panel.replaceChildren();
  const pol = scope.policies || {};
  byId('count-policies').textContent = pol.status === 'ok' ? String((pol.rows || []).length) : '';
  if (pol.status !== 'ok') {
    S.model = null;
    panel.append(h('h2', { text: 'Security policies' }), stateCard(pol.status, pol.message, 'The security policies of this scope are not shown.'));
    return;
  }
  const model = buildModel(scope);
  S.model = model;
  panel.append(
    h(
      'div',
      { class: 'overview' },
      h(
        'div',
        { class: 'matrix-wrap' },
        h('h2', { id: 'matrix-title', text: 'Zone pairs' }),
        h('p', {
          class: 'sub',
          text: 'Rows are the source zone (from), columns the destination zone (to). Select a square to show only that pair below. An empty square has no zone-pair policy, so Junos checks the global policies and then the default policy.',
        }),
        buildMatrix(model),
      ),
      buildSummary(scope),
    ),
    h('h2', { id: 'policy-title', class: 'policy-title', text: 'Policies in evaluation order' }),
    h('p', {
      class: 'sub',
      text: 'For a flow from one zone to another, Junos checks that pair’s policies top to bottom, then the global policies, then the default policy. The first match decides. J-Wicket shows the order; it does not decide which policy a flow matches.',
    }),
    buildFilters(model),
    h('p', { id: 'filter-note', class: 'filter-note', hidden: true }),
    h('div', { class: 'scroll', tabindex: '0', role: 'region', 'aria-labelledby': 'policy-title' }, buildPolicyTable(scope, model)),
  );
  applyPolicyFilters(false);
}

function buildMatrix(model) {
  const zones = model.zones;
  if (!zones.length) return h('p', { class: 'none', text: 'This scope has no zones and no zone-pair policies.' });
  const table = h('table', { class: 'matrix', 'aria-describedby': 'matrix-axis' });
  table.append(h('caption', { class: 'sr-only', text: 'Policy count per zone pair' }));
  const head = h('tr', null, h('td', { class: 'corner', text: `from \u2193 to ${ARROW}` }));
  for (const z of zones) head.append(h('th', { scope: 'col' }, h('span', { class: 'sr-only', text: 'to ' }), zoneLabel(z, model)));
  table.append(h('thead', null, head));
  const body = h('tbody');
  model.cells = [];
  zones.forEach((from, r) => {
    const tr = h('tr', null, h('th', { scope: 'row' }, h('span', { class: 'sr-only', text: 'from ' }), zoneLabel(from, model)));
    const rowCells = [];
    zones.forEach((to, c) => {
      const btn = cellButton(model, from, to, r, c);
      rowCells.push(btn);
      tr.append(h('td', null, btn));
    });
    model.cells.push(rowCells);
    body.append(tr);
  });
  table.append(body);
  table.addEventListener('keydown', onMatrixKey);
  const undefinedZones = model.zonesKnown ? zones.filter((z) => !model.defined.has(z)) : [];
  return h(
    'div',
    null,
    h('div', { class: 'scroll', tabindex: '-1' }, table),
    h(
      'p',
      { class: 'axis', id: 'matrix-axis' },
      'Counts include inactive policies; the coloured bar shows permit, deny, reject and inactive.',
      undefinedZones.length ? ` * Named in a policy but not defined as a zone in this scope: ${undefinedZones.join(', ')}.` : '',
      !model.zonesKnown ? ' Zones could not be read; the zones shown are the ones named in policies.' : '',
    ),
  );
}

function zoneLabel(zone, model) {
  const unknown = model.zonesKnown && !model.defined.has(zone);
  return h('span', { class: unknown ? 'undefined-zone' : null, title: unknown ? 'not defined as a zone in this scope' : null }, zone + (unknown ? ' *' : ''));
}

function cellButton(model, from, to, r, c) {
  const st = model.stats.get(pairKey(from, to));
  const btn = h('button', {
    type: 'button',
    class: ['cell', st && st.count ? 'has' : 'none'],
    'aria-pressed': 'false',
    tabindex: r === 0 && c === 0 ? '0' : '-1',
    dataset: { from, to, r: String(r), c: String(c) },
  });
  btn.append(h('span', { class: 'sr-only', text: `from ${from} to ${to}: ` }));
  if (st && st.count) {
    btn.append(h('span', { class: 'cell-n' }, String(st.count), h('small', { text: st.count === 1 ? 'policy' : 'policies' })));
    const mix = h('span', { class: 'cell-mix' });
    const parts = [];
    for (const action of ['permit', 'deny', 'reject']) if (st[action]) parts.push(h('span', { class: `m-${action}`, text: `${st[action]} ${action}` }));
    if (st.inactive) parts.push(h('span', { text: `${st.inactive} inactive` }));
    parts.forEach((p, i) => {
      if (i) mix.append(SEP);
      mix.append(p);
    });
    btn.append(mix);
    const bar = h('span', { class: 'mixbar', 'aria-hidden': 'true' });
    for (const [cls, n] of [['permit', st.permit], ['deny', st.deny], ['reject', st.reject], ['inactive', st.inactive]]) {
      if (!n) continue;
      const seg = h('span', { class: `b-${cls}` });
      seg.style.flexGrow = String(n); // CSSOM is allowed by the CSP; style attributes are not
      bar.append(seg);
    }
    btn.append(bar);
  } else {
    btn.append(h('span', { class: 'cell-empty', text: `no policy ${ARROW} global, then default` }));
  }
  btn.addEventListener('click', () => togglePair(from, to));
  btn.addEventListener('focus', () => {
    for (const row of model.cells) for (const cell of row) cell.tabIndex = cell === btn ? 0 : -1;
  });
  return btn;
}

function onMatrixKey(event) {
  const target = event.target;
  if (!(target instanceof HTMLElement) || !target.classList.contains('cell')) return;
  const cells = S.model ? S.model.cells : [];
  let r = Number(target.dataset.r);
  let c = Number(target.dataset.c);
  const last = cells.length - 1;
  switch (event.key) {
    case 'ArrowRight': c = Math.min(last, c + 1); break;
    case 'ArrowLeft': c = Math.max(0, c - 1); break;
    case 'ArrowDown': r = Math.min(last, r + 1); break;
    case 'ArrowUp': r = Math.max(0, r - 1); break;
    case 'Home': c = 0; if (event.ctrlKey) r = 0; break;
    case 'End': c = last; if (event.ctrlKey) r = last; break;
    default: return;
  }
  event.preventDefault();
  const next = cells[r] && cells[r][c];
  if (next) next.focus();
}

function togglePair(from, to) {
  const f = S.filters;
  if (f.from === from && f.to === to) {
    f.from = '';
    f.to = '';
  } else {
    f.from = from;
    f.to = to;
  }
  syncFilterControls();
  applyPolicyFilters(true);
  const title = byId('policy-title');
  if (title && f.from) {
    const rect = title.getBoundingClientRect();
    if (rect.top > window.innerHeight * 0.75 || rect.top < 0) {
      title.scrollIntoView({ block: 'start', behavior: reducedMotion() ? 'auto' : 'smooth' });
    }
  }
}

function buildSummary(scope) {
  const pol = scope.policies;
  const rows = [];
  const item = (label, ...value) => h('div', { class: 'row' }, h('dt', { text: label }), h('dd', null, ...value));
  rows.push(item('Global policies', h('span', { class: 'big', text: `Global policies: ${pol.global_count || 0}` }), h('div', { class: 'mute small', text: 'Checked after the zone-pair policies.' })));
  if (pol.default_policy) {
    rows.push(
      item(
        'Default policy',
        h('span', { class: 'big', text: `Default policy: ${pol.default_policy}` }),
        h('div', { class: 'mute small', text: pol.default_policy_group ? `From configuration group ${pol.default_policy_group}.` : 'Used when no policy above matches.' }),
      ),
    );
  } else {
    rows.push(item('Default policy', h('span', { class: 'big', text: 'Default policy: not configured' }), h('div', { class: 'mute small', text: '(Junos default: deny-all)' })));
  }
  rows.push(item('Policy rematch', pol.policy_rematch ? 'On: existing sessions are re-checked when policies change.' : 'Off (not configured).'));
  if (pol.pre_id_default_policy) rows.push(item('Pre-ID default policy', 'Configured. J-Wicket shows that it exists, not its contents.'));
  const groups = scope.groups || [];
  rows.push(
    item(
      'Configuration groups in policies',
      groups.length
        ? h('ul', { class: 'names' }, groups.map((g) => h('li', null, g.name, h('span', { class: 'k', text: plural(g.policies, 'policy', 'policies') }))))
        : mute('No policy comes from a configuration group.'),
    ),
  );
  return h('aside', { class: 'summary', 'aria-label': 'Policy summary' }, h('dl', null, rows));
}

function buildFilters(model) {
  const zoneOptions = (id, label) => {
    const select = h('select', { id }, h('option', { value: '', text: 'Any zone' }));
    for (const z of model.zones) select.append(h('option', { value: z, text: z }));
    return h('div', { class: 'f' }, h('label', { for: id, text: label }), select);
  };
  const actions = ['permit', 'deny', 'reject'];
  if (model.rows.some((r) => r.action === 'unknown')) actions.push('unknown');
  const actionSelect = h('select', { id: 'pf-action' }, h('option', { value: '', text: 'Any action' }), actions.map((a) => h('option', { value: a, text: a })));
  const search = h('input', {
    id: 'pf-q', type: 'search', autocomplete: 'off', spellcheck: 'false',
    placeholder: 'name, address, 10.20.0.10, application', 'aria-describedby': 'pf-q-help',
  });
  const inactive = h('input', { id: 'pf-inactive', type: 'checkbox' });
  const groups = h('input', { id: 'pf-groups', type: 'checkbox' });
  const box = h(
    'div',
    { class: 'filters', role: 'search', 'aria-label': 'Filter policies' },
    h('div', { class: 'f f-search' }, h('label', { for: 'pf-q', text: 'Search policies' }), search, h('span', { id: 'pf-q-help', class: 'sr-only', text: 'Matches names, descriptions, address and application names, and the addresses they resolve to.' })),
    zoneOptions('pf-from', 'From zone'),
    zoneOptions('pf-to', 'To zone'),
    h('div', { class: 'f' }, h('label', { for: 'pf-action', text: 'Action' }), actionSelect),
    h('label', { class: 'check' }, inactive, 'Show inactive'),
    h('label', { class: 'check' }, groups, 'Only from configuration groups'),
    h('button', { id: 'pf-clear', type: 'button', class: 'btn small', text: 'Clear filters' }),
    h('span', { id: 'pf-count', class: 'filter-count' }),
  );
  let debounce = 0;
  search.addEventListener('input', () => {
    clearTimeout(debounce);
    debounce = setTimeout(() => {
      S.filters.q = search.value.trim();
      applyPolicyFilters(true);
    }, 120);
  });
  // Handlers read S.filters at event time: "Clear filters" replaces the object.
  box.querySelector('#pf-from').addEventListener('change', (e) => { S.filters.from = e.target.value; applyPolicyFilters(true); });
  box.querySelector('#pf-to').addEventListener('change', (e) => { S.filters.to = e.target.value; applyPolicyFilters(true); });
  actionSelect.addEventListener('change', () => { S.filters.action = actionSelect.value; applyPolicyFilters(true); });
  inactive.addEventListener('change', () => { S.filters.inactive = inactive.checked; applyPolicyFilters(true); });
  groups.addEventListener('change', () => { S.filters.groupsOnly = groups.checked; applyPolicyFilters(true); });
  box.querySelector('#pf-clear').addEventListener('click', () => {
    S.filters = defaultFilters();
    syncFilterControls();
    applyPolicyFilters(true);
    search.focus();
  });
  queueMicrotask(syncFilterControls);
  return box;
}

function syncFilterControls() {
  const f = S.filters;
  const set = (id, prop, value) => {
    const node = byId(id);
    if (node) node[prop] = value;
  };
  set('pf-q', 'value', f.q);
  set('pf-from', 'value', f.from);
  set('pf-to', 'value', f.to);
  set('pf-action', 'value', f.action);
  set('pf-inactive', 'checked', f.inactive);
  set('pf-groups', 'checked', f.groupsOnly);
}

function buildPolicyTable(scope, model) {
  const table = h('table', { class: 'tbl policies', id: 'policy-table' });
  table.append(
    h('caption', { class: 'sr-only', text: 'Security policies in evaluation order' }),
    h('colgroup', null, ['num', 'name', 'src', 'dst', 'app', 'act', 'notes'].map((c) => h('col', { class: `c-${c}` }))),
    h(
      'thead',
      null,
      h('tr', null, ['#', 'Name', 'Source', 'Destination', 'Application', 'Action', 'Notes'].map((t, i) => h('th', { scope: 'col', class: i === 0 ? 'num' : null, text: t }))),
    ),
  );
  model.sections = [];
  for (const pair of model.pairs) {
    const allPairInactive = pair.rows.every((i) => model.rows[i].inactive_reason === 'zone-pair');
    const head = h(
      'tr',
      { class: 'section' },
      h(
        'th',
        { colspan: '7', scope: 'colgroup' },
        h(
          'span',
          { class: 'sec-label' },
          `${pair.from} ${ARROW} ${pair.to}`,
          h('span', { class: 'sec-sub', text: `${SEP}checked in this order${SEP}${plural(pair.rows.length, 'policy', 'policies')}` }),
          allPairInactive ? h('span', { class: 'sec-flag', text: 'zone pair deactivated' }) : null,
        ),
      ),
    );
    model.sections.push(sectionBody(head, pair.rows, model, table));
  }
  if (model.globals.length) {
    const head = h(
      'tr',
      { class: 'section' },
      h('th', { colspan: '7', scope: 'colgroup' }, h('span', { class: 'sec-label' }, 'Global policies', h('span', { class: 'sec-sub', text: `${SEP}checked after zone-pair policies${SEP}${plural(model.globals.length, 'policy', 'policies')}` }))),
    );
    model.sections.push(sectionBody(head, model.globals, model, table));
  }
  model.noMatch = h(
    'tbody',
    { hidden: true },
    h('tr', { class: 'no-match' }, h('td', { colspan: '7', id: 'no-match-text', text: 'No policy matches these filters.' })),
  );
  table.append(model.noMatch);
  table.append(defaultBody(scope.policies));
  table.addEventListener('click', (event) => {
    const tr = event.target instanceof Element ? event.target.closest('tr.prow[data-idx]') : null;
    if (!tr) return;
    if (event.target.closest('button') && !event.target.closest('button.pname')) return;
    const selection = window.getSelection();
    if (selection && String(selection).length && !event.target.closest('button')) return; // the operator is selecting text
    const btn = tr.querySelector('button.pname');
    openDetail(Number(tr.dataset.idx), btn);
  });
  return table;
}

function sectionBody(head, indices, model, table) {
  const tbody = h('tbody', null, head);
  const items = indices.map((idx) => {
    const tr = policyRow(model.rows[idx], idx);
    tbody.append(tr);
    return { idx, tr };
  });
  table.append(tbody);
  return { tbody, items };
}

function policyRow(row, idx) {
  const nameCell = h(
    'th',
    { scope: 'row' },
    h('button', { type: 'button', class: 'linkish pname', 'aria-haspopup': 'dialog', text: row.name }),
    row.kind === 'global' ? h('div', { class: 'pzones', text: `zones: ${zoneList(row.from)} ${ARROW} ${zoneList(row.to)}` }) : null,
    row.description ? h('div', { class: 'pdesc', text: row.description }) : null,
  );
  return h(
    'tr',
    { class: ['prow', row.inactive && 'is-inactive'], dataset: { idx: String(idx) } },
    h('td', { class: 'num', text: String(row.seq) }),
    nameCell,
    h('td', null, addressCell(row, 'source')),
    h('td', null, addressCell(row, 'destination')),
    h('td', null, appCell(row)),
    h('td', null, pill(row.action)),
    h('td', null, notes(row)),
  );
}

const zoneList = (zones) => (zones && zones.length ? zones.join(', ') : 'any');

function pill(action, text) {
  const cls = ['permit', 'deny', 'reject'].includes(action) ? action : 'unknown';
  return h('span', { class: ['pill', cls], text: text || action || 'unknown' });
}

function limited(list, render) {
  const out = list.slice(0, LIST_LIMIT).map(render);
  if (list.length > LIST_LIMIT) out.push(h('li', { class: 'mute', text: `+${list.length - LIST_LIMIT} more` }));
  return out;
}

function addressCell(row, side) {
  const names = (row.match && row.match[side]) || [];
  const resolved = (row.resolved && row.resolved[side]) || [];
  const excluded = row.match && row.match[`${side}_excluded`];
  const ul = h('ul', { class: 'names' });
  if (excluded) ul.append(h('li', null, h('span', { class: 'neg', text: 'all except' })));
  appendKids(
    ul,
    limited(names, (name) => {
      const res = resolved.find((r) => r.name === name) || {};
      const leaves = (res.leaves || []).length;
      return h(
        'li',
        null,
        name,
        res.kind === 'set' ? h('span', { class: 'k', text: `set of ${leaves}${res.truncated ? '+' : ''}` }) : null,
        res.kind === 'unresolved' || (res.unresolved || []).length ? h('span', { class: 'bad', text: 'unresolved' }) : null,
      );
    }),
  );
  return ul;
}

function appCell(row) {
  const names = (row.match && row.match.application) || [];
  const resolved = (row.resolved && row.resolved.application) || [];
  const ul = h('ul', { class: 'names' });
  appendKids(
    ul,
    limited(names, (name) => {
      const res = resolved.find((r) => r.name === name) || {};
      return h(
        'li',
        null,
        name,
        res.kind === 'set' ? h('span', { class: 'k', text: `set of ${(res.leaves || []).length}` }) : null,
        res.kind === 'unresolved' || (res.unresolved || []).length ? h('span', { class: 'bad', text: 'unresolved' }) : null,
      );
    }),
  );
  const dyn = (row.match && row.match.dynamic_application) || [];
  if (dyn.length) ul.append(h('li', null, h('span', { class: 'k', text: 'dynamic: ' }), dyn.join(', ')));
  return ul;
}

function inactiveText(row) {
  if (row.inactive_reason === 'policy') return 'inactive (policy deactivated)';
  if (row.inactive_reason === 'zone-pair') return row.kind === 'global' ? 'inactive (global section deactivated)' : 'inactive (zone pair deactivated)';
  return 'inactive';
}

function notes(row) {
  const out = [];
  const badge = (text, cls, title) => h('span', { class: ['badge', cls], text, title: title || text });
  if (row.inactive) out.push(badge(inactiveText(row), 'b-inactive'));
  if (row.group) out.push(badge(`from group ${row.group}`, 'b-group'));
  if ((row.inherited || []).length) out.push(badge(`partly inherited (${row.inherited.join(', ')})`, 'b-group'));
  const log = [row.log && row.log.init ? 'init' : null, row.log && row.log.close ? 'close' : null].filter(Boolean);
  if (log.length) out.push(badge(`log ${log.join(', ')}`));
  if (row.count) out.push(badge('count'));
  if (row.scheduler) out.push(badge(`scheduler ${row.scheduler}`));
  if ((row.application_services || []).length) out.push(badge(`application services: ${row.application_services.join(', ')}`, 'b-svc'));
  if (row.tunnel) out.push(badge(`tunnel ${row.tunnel}`));
  const m = row.match || {};
  if ((m.source_identity || []).length) out.push(badge('source identity'));
  if ((m.url_category || []).length) out.push(badge('URL category'));
  if ((m.source_end_user_profile || []).length) out.push(badge('end-user profile'));
  if ((row.unmodeled || []).length) out.push(badge('has settings not shown', 'b-warn', `Not shown: ${row.unmodeled.join(', ')}`));
  return h('div', { class: 'badges' }, out);
}

function defaultBody(pol) {
  const configured = Boolean(pol.default_policy);
  const action = pol.default_policy || 'deny-all';
  const notesCell = h(
    'div',
    { class: 'badges' },
    configured ? null : h('span', { class: 'badge', text: 'not configured (Junos default: deny-all)' }),
    pol.default_policy_group ? h('span', { class: 'badge b-group', text: `from group ${pol.default_policy_group}` }) : null,
  );
  return h(
    'tbody',
    null,
    h(
      'tr',
      { class: 'section' },
      h('th', { colspan: '7', scope: 'colgroup' }, h('span', { class: 'sec-label' }, 'Default policy', h('span', { class: 'sec-sub', text: `${SEP}applies when no policy above matches` }))),
    ),
    h(
      'tr',
      { class: 'prow is-default' },
      h('td', { class: 'num', text: '' }),
      h('th', { scope: 'row' }, h('span', { class: 'pname', text: 'default-policy' })),
      h('td', { class: 'd', text: 'any' }),
      h('td', { class: 'd', text: 'any' }),
      h('td', { class: 'd', text: 'any' }),
      h('td', null, pill(action === 'permit-all' ? 'permit' : 'deny', action)),
      h('td', null, notesCell),
    ),
  );
}

function applyPolicyFilters(announceIt) {
  const model = S.model;
  if (!model || !model.sections) return;
  const f = S.filters;
  let shown = 0;
  for (const sec of model.sections) {
    let visible = 0;
    for (const item of sec.items) {
      const vis = rowVisible(item.idx, f, model);
      item.tr.hidden = !vis;
      if (vis) visible += 1;
    }
    sec.tbody.hidden = visible === 0;
    shown += visible;
  }
  const total = model.rows.length;
  if (model.noMatch) {
    model.noMatch.hidden = shown !== 0;
    byId('no-match-text').textContent = total
      ? 'No policy matches these filters.'
      : 'This scope has no security policies. Every flow between zones is decided by the default policy.';
  }
  const count = byId('pf-count');
  if (count) count.textContent = `${shown.toLocaleString('en')} of ${plural(total, 'policy', 'policies')}`;
  const note = byId('filter-note');
  if (note) {
    const zoneFilter = f.from || f.to;
    note.hidden = !(zoneFilter && model.globals.length);
    note.textContent = 'Global policies stay listed when they apply to the chosen zones (an empty zone list means any zone).';
  }
  for (const row of model.cells || []) {
    for (const cell of row) cell.setAttribute('aria-pressed', cell.dataset.from === f.from && cell.dataset.to === f.to ? 'true' : 'false');
  }
  if (announceIt) {
    const pair = f.from && f.to ? ` for ${f.from} ${ARROW} ${f.to}` : '';
    announce(`Showing ${shown} of ${plural(total, 'policy', 'policies')}${pair}.`);
  }
}

// ---- policy detail dialog ------------------------------------------------------------------------

function openDetail(idx, opener) {
  const model = S.model;
  const row = model && model.rows[idx];
  if (!row) return;
  S.opener = opener || document.activeElement;
  const dlg = byId('detail');
  const sheet = byId('detail-sheet');
  sheet.replaceChildren(...detailContent(row, idx, model));
  if (!dlg.open) dlg.showModal();
  sheet.scrollTop = 0;
  byId('detail-close').focus();
}

function closeDetail() {
  const dlg = byId('detail');
  if (dlg.open) dlg.close();
}

function detailContent(row, idx, model) {
  const isGlobal = row.kind === 'global';
  const siblings = isGlobal ? model.globals : (model.pairs.find((p) => p.from === row.from[0] && p.to === row.to[0]) || { rows: [] }).rows;
  const where = isGlobal
    ? `Global policy ${row.seq} of ${siblings.length}${SEP}zones ${zoneList(row.from)} ${ARROW} ${zoneList(row.to)}`
    : `${row.from[0]} ${ARROW} ${row.to[0]}${SEP}policy ${row.seq} of ${siblings.length} in this zone pair`;
  const head = h(
    'div',
    { class: 'sheet-head' },
    h(
      'div',
      { class: 't' },
      h('p', { class: 'eyebrow', text: `${isGlobal ? 'Global policy' : 'Zone-pair policy'}${SEP}${scopeLabel(row.scope || S.scope)}` }),
      h('h2', { id: 'detail-title', text: row.name }),
      h('p', { class: 'where' }, where, ' ', pill(row.action), row.inactive ? h('span', { class: 'badge b-inactive', text: inactiveText(row) }) : null),
    ),
    h('button', { id: 'detail-close', type: 'button', class: 'btn', text: 'Close', on: { click: closeDetail } }),
  );
  return [
    head,
    matchSection(row),
    resolvedAddressSection(row, 'source', 'Source addresses, resolved'),
    resolvedAddressSection(row, 'destination', 'Destination addresses, resolved'),
    resolvedAppSection(row),
    thenSection(row),
    provenanceSection(row),
    deviceCliSection(row),
    evaluationSection(row, idx, model),
  ];
}

function kv(pairs) {
  const dl = h('dl', { class: 'kv' });
  for (const [label, value] of pairs) {
    if (value === null || value === undefined) continue;
    dl.append(h('dt', { text: label }), h('dd', null, value));
  }
  return dl;
}

const joinOrNone = (list, none) => (list && list.length ? h('span', { class: 'data', text: list.join(', ') }) : mute(none || 'none'));

function matchSection(row) {
  const m = row.match || {};
  const side = (names, excluded) =>
    excluded
      ? h('span', null, h('span', { class: 'warn-line', text: 'All addresses except: ' }), data(names.join(', ')))
      : joinOrNone(names, 'any');
  return h(
    'section',
    null,
    h('h3', { text: 'Match' }),
    kv([
      ['Source', side(m.source || [], m.source_excluded)],
      ['Destination', side(m.destination || [], m.destination_excluded)],
      ['Application', joinOrNone(m.application, 'any')],
      ['Source identity', (m.source_identity || []).length ? joinOrNone(m.source_identity) : null],
      ['Dynamic application', (m.dynamic_application || []).length ? joinOrNone(m.dynamic_application) : null],
      ['URL category', (m.url_category || []).length ? joinOrNone(m.url_category) : null],
      ['End-user profile', (m.source_end_user_profile || []).length ? joinOrNone(m.source_end_user_profile) : null],
      ['Description', row.description ? h('span', { text: row.description }) : null],
    ]),
    m.source_excluded || m.destination_excluded
      ? h('p', { class: 'mute small', text: 'An excluded address list (source-address-excluded or destination-address-excluded) matches every address except the ones listed.' })
      : null,
  );
}

function bookLabel(book) {
  if (!book) return null;
  if (book.startsWith('zone ')) return `zone address book of ${book.slice(5)} (legacy)`;
  return `address book ${book}`;
}

const ADDRESS_KINDS = { any: 'any address', address: 'address', set: 'address set', unresolved: 'not found' };
const APP_KINDS = {
  any: 'any application',
  application: 'custom application',
  set: 'application set',
  predefined: 'predefined (junos-defaults, not expanded)',
  unresolved: 'not found',
};

function resolvedAddressSection(row, side, title) {
  const list = (row.resolved && row.resolved[side]) || [];
  const zones = side === 'source' ? row.from : row.to;
  const blocks = list.map((item) => {
    const headBits = [
      h('span', { class: 'nm', text: item.name }),
      h('span', { class: 'k', text: ADDRESS_KINDS[item.kind] || item.kind }),
      item.book ? h('span', { class: 'k', text: `from ${bookLabel(item.book)}` }) : null,
    ];
    const body = [];
    if (item.kind === 'any') body.push(mute('Matches every address.', 'small'));
    if (item.kind === 'unresolved') {
      body.push(
        h('p', {
          class: 'unres',
          text: `Not found: no address book visible ${row.kind === 'global' || !zones.length ? 'to this policy' : `from zone ${zones[0]}`} defines ${item.name}.`,
        }),
      );
    }
    const leaves = item.leaves || [];
    if (leaves.length) {
      body.push(
        h(
          'table',
          { class: 'tbl' },
          h('thead', null, h('tr', null, ['Address', 'Kind', 'Value'].map((t) => h('th', { scope: 'col', text: t })))),
          h('tbody', null, leaves.map((l) => h('tr', null, h('td', { class: 'd', text: l.name }), h('td', { text: l.kind || '' }), h('td', { class: 'd', text: l.value || '' })))),
        ),
      );
    }
    if (item.truncated) body.push(mute(`The list stops at ${leaves.length} addresses; the set is larger.`, 'small'));
    const unres = (item.unresolved || []).filter((n) => n !== item.name || item.kind !== 'unresolved');
    if (unres.length) body.push(h('p', { class: 'unres', text: `Members not found: ${unres.join(', ')}` }));
    return h('div', { class: 'res' }, h('div', { class: 'res-head' }, headBits), body);
  });
  return h('section', null, h('h3', { text: title }), blocks.length ? blocks : mute('No addresses in the match.'));
}

function resolvedAppSection(row) {
  const list = (row.resolved && row.resolved.application) || [];
  const blocks = list.map((item) => {
    const body = [];
    if (item.kind === 'any') body.push(mute('Matches every application.', 'small'));
    if (item.kind === 'unresolved') body.push(h('p', { class: 'unres', text: `Not found: no application or application set named ${item.name} is defined.` }));
    const leaves = item.leaves || [];
    if (leaves.length) {
      body.push(
        h(
          'table',
          { class: 'tbl' },
          h('thead', null, h('tr', null, ['Application', 'Protocol', 'Destination port', 'Source port'].map((t) => h('th', { scope: 'col', text: t })))),
          h(
            'tbody',
            null,
            leaves.map((l) =>
              l.predefined
                ? h('tr', null, h('td', { class: 'd', text: l.name }), h('td', { colspan: '3', class: 'mute', text: 'predefined (junos-defaults, not expanded)' }))
                : h(
                    'tr',
                    null,
                    h('td', { class: 'd', text: l.name }),
                    h('td', { class: 'd', text: l.protocol || (l.terms ? `${l.terms} terms (not expanded)` : '—') }),
                    h('td', { class: 'd', text: l.destination_port || '—' }),
                    h('td', { class: 'd', text: l.source_port || '—' }),
                  ),
            ),
          ),
        ),
      );
    }
    const unres = (item.unresolved || []).filter((n) => n !== item.name || item.kind !== 'unresolved');
    if (unres.length) body.push(h('p', { class: 'unres', text: `Members not found: ${unres.join(', ')}` }));
    return h(
      'div',
      { class: 'res' },
      h('div', { class: 'res-head' }, h('span', { class: 'nm', text: item.name }), h('span', { class: 'k', text: APP_KINDS[item.kind] || item.kind })),
      body,
    );
  });
  return h('section', null, h('h3', { text: 'Applications, resolved' }), blocks.length ? blocks : mute('No applications in the match.'));
}

function thenSection(row) {
  const log = [row.log && row.log.init ? 'session-init' : null, row.log && row.log.close ? 'session-close' : null].filter(Boolean);
  return h(
    'section',
    null,
    h('h3', { text: 'Then' }),
    kv([
      ['Action', pill(row.action)],
      ['Log', joinOrNone(log, 'no logging')],
      ['Count', row.count ? 'yes' : mute('no')],
      ['Application services', joinOrNone(row.application_services, 'none')],
      ['Tunnel', row.tunnel ? data(`ipsec-vpn ${row.tunnel}`) : mute('none')],
      ['Scheduler', row.scheduler ? data(row.scheduler) : mute('none: always in effect while active')],
    ]),
  );
}

function provenanceSection(row) {
  let state;
  if (row.inactive_reason === 'policy') state = 'Inactive: this policy is deactivated in the configuration (inactive:). Junos skips it.';
  else if (row.inactive_reason === 'zone-pair') {
    state =
      row.kind === 'global'
        ? 'Inactive: the global policies section is deactivated, so Junos skips this policy.'
        : `Inactive: the zone pair from-zone ${row.from[0]} to-zone ${row.to[0]} is deactivated, so Junos skips every policy in it.`;
  } else state = 'Active.';
  const others = (row.groups || []).filter((g) => g !== row.group);
  return h(
    'section',
    null,
    h('h3', { text: 'Where it comes from' }),
    kv([
      ['Configured', row.group ? h('span', null, 'From configuration group ', data(row.group)) : 'Directly in the configuration (no group).'],
      ['Inherited parts', (row.inherited || []).length ? h('span', null, 'Partly inherited from another group: ', data(row.inherited.join(', '))) : mute('none')],
      ['Groups in this policy', (row.groups || []).length ? data(row.groups.join(', ')) : mute('none')],
      ['State', h('span', { class: row.inactive ? 'warn-line' : null, text: state })],
    ]),
    others.length && row.group
      ? h('p', { class: 'mute small', text: `Other groups also contribute settings: ${others.join(', ')}.` })
      : null,
    row.group || (row.groups || []).length
      ? h('p', { class: 'mute small', text: 'A change made directly to an object that comes from a group may be overridden by the group, or may override it. J-Wicket shows where each part comes from so that you can decide where a change belongs.' })
      : null,
  );
}

function cliBlock(text) {
  const code = h('code');
  text.split(' ').forEach((word, i) => {
    if (i) code.append(' ');
    code.append(h('span', { class: 'w', text: word }));
  });
  const kids = [code];
  if (navigator.clipboard && window.isSecureContext) {
    const btn = h('button', { type: 'button', class: 'btn small', text: 'Copy', 'aria-label': `Copy command: ${text}` });
    btn.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(text);
        btn.textContent = 'Copied';
        announce('Command copied.');
      } catch (_err) {
        btn.textContent = 'Copy failed';
      }
      setTimeout(() => {
        btn.textContent = 'Copy';
      }, 1600);
    });
    kids.push(btn);
  }
  return h('div', { class: 'cli' }, kids);
}

function deviceCliSection(row) {
  const unmodeled = row.unmodeled || [];
  if (unmodeled.length) {
    return h(
      'section',
      null,
      h('h3', { text: 'Settings J-Wicket does not show' }),
      h(
        'div',
        { class: 'unmodeled' },
        h('p', { text: 'J-Wicket does not display these settings yet. Check them on the device:' }),
        h('ul', null, unmodeled.map((u) => h('li', { text: u }))),
        cliBlock(showConfigCli(row)),
      ),
    );
  }
  return h('section', null, h('h3', { text: 'See it on the device' }), cliBlock(showConfigCli(row)));
}

function orderItem(model, idx, currentIdx) {
  const row = model.rows[idx];
  return h(
    'li',
    { class: [row.inactive && 'skipped', idx === currentIdx && 'this'] },
    h('span', { class: 'nm', text: row.name }),
    mute(` ${row.action}`, 'small'),
    row.kind === 'global' ? mute(` (zones ${zoneList(row.from)} ${ARROW} ${zoneList(row.to)})`, 'small') : null,
    row.inactive ? h('span', { class: 'why', text: ' skipped: inactive' }) : null,
    idx === currentIdx ? h('span', { class: 'here', text: '\u2190 this policy' }) : null,
  );
}

function evaluationSection(row, idx, model) {
  const pol = model.scope.policies || {};
  const defaultText = pol.default_policy ? `default-policy ${pol.default_policy}` : 'default policy not configured: Junos default deny-all';
  let from = null;
  let to = null;
  if (row.kind === 'zone') {
    from = row.from[0];
    to = row.to[0];
  } else {
    from = row.from.length === 1 ? row.from[0] : null;
    to = row.to.length === 1 ? row.to[0] : null;
  }
  const kids = [h('h3', { text: 'Evaluation order for this zone pair' })];
  let n = 1;
  if (from && to) {
    const pair = model.pairs.find((p) => p.from === from && p.to === to);
    const zoneRows = pair ? pair.rows : [];
    kids.push(h('p', { class: 'order-label', text: `Zone-pair policies for ${from} ${ARROW} ${to}, top to bottom` }));
    if (zoneRows.length) {
      kids.push(h('ol', { class: 'order', start: String(n) }, zoneRows.map((i) => orderItem(model, i, idx))));
      n += zoneRows.length;
    } else {
      kids.push(h('p', { class: 'mute small', text: 'No zone-pair policy for this pair.' }));
    }
    const applying = model.globals.filter((i) => globalApplies(model.rows[i], from, to));
    kids.push(h('p', { class: 'order-label', text: `Then the global policies that apply to ${from} ${ARROW} ${to}` }));
    if (applying.length) {
      kids.push(h('ol', { class: 'order', start: String(n) }, applying.map((i) => orderItem(model, i, idx))));
      n += applying.length;
    } else {
      kids.push(h('p', { class: 'mute small', text: 'No global policy applies to this pair.' }));
    }
  } else {
    kids.push(
      h('p', {
        class: 'small',
        text: `This global policy applies to every zone pair whose from-zone is in (${zoneList(row.from)}) and whose to-zone is in (${zoneList(row.to)}); “any” means every zone. For each such pair, Junos checks that pair’s zone-pair policies first, then the global policies below in this order, then the default policy.`,
      }),
      h('p', { class: 'order-label', text: 'Global policies, in order' }),
      h('ol', { class: 'order', start: String(n) }, model.globals.map((i) => orderItem(model, i, idx))),
    );
    n += model.globals.length;
  }
  kids.push(
    h('p', { class: 'order-label', text: 'Then the default policy' }),
    h('ol', { class: 'order', start: String(n) }, h('li', null, h('span', { class: 'nm', text: defaultText }))),
    h('p', { class: 'small', text: 'This shows order, not a match result. To test a flow, run on the device:' }),
    cliBlock(matchPoliciesCli(row.scope || S.scope, from, to, row)),
    h('p', { class: 'mute small', text: 'Values come from this policy where it names a single host or port. Replace each <placeholder> with the flow you want to test.' }),
  );
  const sp = scopeParts(row.scope || S.scope);
  if (sp.kind !== 'root') {
    kids.push(h('p', { class: 'mute small', text: `The ${sp.kind === 'lsys' ? 'logical-system' : 'tenant'} option name can differ between releases; check it with “show security match-policies ?”.` }));
  }
  return h('section', null, kids);
}

// ---- other tabs ----------------------------------------------------------------------------------

/** A text filter over a set of rows; hides non-matching rows and keeps a count. */
function textFilter(id, label, placeholder, items, nouns, onApply) {
  const [one, many] = nouns;
  const input = h('input', { id, type: 'search', autocomplete: 'off', spellcheck: 'false', placeholder });
  const count = h('span', { class: 'filter-count' });
  const apply = () => {
    const terms = input.value.trim().toLowerCase().split(/\s+/).filter(Boolean);
    let shown = 0;
    for (const item of items) {
      const vis = terms.every((t) => item.text.includes(t));
      item.node.hidden = !vis;
      if (vis) shown += 1;
    }
    count.textContent = `${shown.toLocaleString('en')} of ${plural(items.length, one, many)}`;
    if (onApply) onApply();
    return shown;
  };
  let debounce = 0;
  input.addEventListener('input', () => {
    clearTimeout(debounce);
    debounce = setTimeout(() => {
      const shown = apply();
      announce(`Showing ${shown} of ${plural(items.length, one, many)}.`);
    }, 120);
  });
  const box = h('div', { class: 'filters', role: 'search', 'aria-label': label }, h('div', { class: 'f f-search' }, h('label', { for: id, text: label }), input), count);
  apply();
  return box;
}

const lower = (...bits) => bits.flat(Infinity).filter((b) => b !== null && b !== undefined).join('\n').toLowerCase();

function provenance(obj) {
  const out = [];
  if (obj.group) out.push(h('span', { class: 'badge b-group', text: `from group ${obj.group}` }));
  if (obj.inactive) out.push(h('span', { class: 'badge b-inactive', text: 'inactive' }));
  if (!out.length) out.push(mute('direct', 'small'));
  return h('div', { class: 'badges' }, out);
}

const chips = (list, none) => (list && list.length ? list.map((s) => h('span', { class: 'chip', text: s })) : mute(none || 'none', 'small'));

function panelIntro(panel, title, sub) {
  panel.append(h('h2', { text: title }), h('p', { class: 'sub', text: sub }));
}

function renderZones(scope) {
  const panel = byId('panel-zones');
  panel.replaceChildren();
  const z = scope.zones || {};
  panelIntro(panel, 'Zones', 'The interfaces in each zone, and what each zone and interface may open on the firewall itself (host-inbound system services and protocols).');
  byId('count-zones').textContent = z.status === 'ok' ? String((z.rows || []).length) : '';
  if (z.status !== 'ok') {
    panel.append(stateCard(z.status, z.message, 'The zones of this scope are not shown.'));
    return;
  }
  const rows = z.rows || [];
  if (!rows.length) {
    panel.append(h('p', { class: 'none', text: 'This scope has no security zones.' }));
    return;
  }
  const items = rows.map((zone) => {
    const ifaces = zone.interfaces || [];
    const tr = h(
      'tr',
      { class: zone.inactive ? 'prow is-inactive' : null },
      h('th', { scope: 'row' }, h('span', { class: 'pname', text: zone.name }), zone.description ? h('div', { class: 'pdesc', text: zone.description }) : null),
      h(
        'td',
        null,
        ifaces.length
          ? h(
              'ul',
              { class: 'ifc' },
              ifaces.map((i) =>
                h(
                  'li',
                  null,
                  h('span', { class: 'ifn', text: i.name }),
                  i.group ? h('span', { class: 'badge b-group', text: `from group ${i.group}` }) : null,
                  (i.services || []).length || (i.protocols || []).length
                    ? h(
                        'div',
                        { class: 'ifs' },
                        (i.services || []).length ? `interface services: ${i.services.join(', ')}` : '',
                        (i.services || []).length && (i.protocols || []).length ? SEP : '',
                        (i.protocols || []).length ? `interface protocols: ${i.protocols.join(', ')}` : '',
                      )
                    : null,
                ),
              ),
            )
          : mute('no interfaces', 'small'),
      ),
      h('td', null, chips(zone.services)),
      h('td', null, chips(zone.protocols)),
      h('td', { class: 'd', text: zone.screen || '' }, zone.screen ? null : mute('none', 'small')),
      h('td', null, provenance(zone)),
    );
    return {
      node: tr,
      text: lower(zone.name, zone.description, zone.screen, zone.group, zone.services, zone.protocols, ifaces.map((i) => [i.name, i.services, i.protocols, i.group])),
    };
  });
  const table = h(
    'table',
    { class: 'tbl entries' },
    h('caption', { class: 'sr-only', text: 'Security zones' }),
    h(
      'thead',
      null,
      h('tr', null, ['Zone', 'Interfaces', 'Host-inbound services (zone)', 'Host-inbound protocols (zone)', 'Screen', 'Provenance'].map((t) => h('th', { scope: 'col', text: t }))),
    ),
    h('tbody', null, items.map((i) => i.node)),
  );
  panel.append(
    textFilter('zf-q', 'Filter zones', 'zone, interface, service, screen', items, ['zone', 'zones']),
    h('div', { class: 'scroll', tabindex: '0', role: 'region', 'aria-label': 'Zones table' }, table),
    h('p', { class: 'axis', text: 'Interface lines list host-inbound settings configured on that interface; zone columns list the settings configured for the whole zone.' }),
  );
}

function renderBooks(scope) {
  const panel = byId('panel-books');
  panel.replaceChildren();
  const b = scope.address_books || {};
  panelIntro(panel, 'Address books', 'Each address book, the zones it is attached to, its addresses and its address sets.');
  if (b.status !== 'ok') {
    byId('count-books').textContent = '';
    panel.append(stateCard(b.status, b.message, 'The address books of this scope are not shown.'));
    return;
  }
  const books = b.rows || [];
  byId('count-books').textContent = String(books.length);
  if (!books.length) {
    panel.append(h('p', { class: 'none', text: 'This scope has no address books.' }));
    return;
  }
  const items = [];
  const sections = [];
  for (const book of books) {
    const bookItems = [];
    const addrRows = (book.addresses || []).map((a) => {
      const tr = h(
        'tr',
        { class: a.inactive ? 'prow is-inactive' : null },
        h('th', { scope: 'row', class: 'd', text: a.name }),
        h('td', { text: a.kind }),
        h('td', { class: 'd', text: a.value || '' }),
        h('td', null, provenance(a)),
        h('td', { text: a.description || '' }),
      );
      const item = { node: tr, text: lower(book.name, a.name, a.kind, a.value, a.description, a.group) };
      bookItems.push(item);
      return tr;
    });
    const setRows = (book.sets || []).map((s) => {
      const tr = h(
        'tr',
        { class: s.inactive ? 'prow is-inactive' : null },
        h('th', { scope: 'row', class: 'd', text: s.name }),
        h('td', null, chips(s.addresses)),
        h('td', null, chips(s.sets)),
        h('td', null, provenance(s)),
        h('td', { text: s.description || '' }),
      );
      const item = { node: tr, text: lower(book.name, s.name, s.addresses, s.sets, s.description, s.group) };
      bookItems.push(item);
      return tr;
    });
    const attach = book.legacy_zone
      ? `Zone-level address book of zone ${book.legacy_zone} (legacy form).`
      : (book.attach || []).length
        ? `Attached to zone${book.attach.length === 1 ? '' : 's'} ${book.attach.join(', ')}.`
        : book.name === 'global'
          ? 'Global address book: not attached to a zone, usable from every zone.'
          : 'Not attached to any zone.';
    const addrTable = h(
      'tbody',
      null,
      addrRows,
    );
    const addrSection = addrRows.length
      ? h(
          'div',
          null,
          h('h4', { text: plural(addrRows.length, 'address', 'addresses') }),
          h(
            'div',
            { class: 'scroll', tabindex: '0', role: 'region', 'aria-label': `Addresses in ${book.name}` },
            h('table', { class: 'tbl entries' }, h('thead', null, h('tr', null, ['Address', 'Kind', 'Value', 'Provenance', 'Description'].map((t) => h('th', { scope: 'col', text: t })))), addrTable),
          ),
        )
      : h('p', { class: 'none', text: 'No addresses.' });
    const setSection = setRows.length
      ? h(
          'div',
          null,
          h('h4', { text: plural(setRows.length, 'address set') }),
          h(
            'div',
            { class: 'scroll', tabindex: '0', role: 'region', 'aria-label': `Address sets in ${book.name}` },
            h('table', { class: 'tbl entries' }, h('thead', null, h('tr', null, ['Set', 'Addresses', 'Nested sets', 'Provenance', 'Description'].map((t) => h('th', { scope: 'col', text: t })))), h('tbody', null, setRows)),
          ),
        )
      : null;
    const section = h(
      'section',
      { class: 'book', 'aria-label': `Address book ${book.name}` },
      h('h3', { text: book.name }),
      h('div', { class: 'book-meta' }, h('span', { text: attach }), book.group || book.inactive ? provenance(book) : null),
      addrSection,
      setSection,
    );
    sections.push({ section, items: bookItems, addrSection, setSection });
    items.push(...bookItems);
  }
  const refreshSections = () => {
    for (const s of sections) s.section.hidden = s.items.length > 0 && s.items.every((i) => i.node.hidden);
  };
  panel.append(
    textFilter('bf-q', 'Filter address books', 'name, 10.20.0.10, set, book', items, ['entry', 'entries'], refreshSections),
    ...sections.map((s) => s.section),
  );
}

function renderApps(scope) {
  const panel = byId('panel-apps');
  panel.replaceChildren();
  const a = scope.applications || {};
  panelIntro(panel, 'Applications', 'Custom applications and application sets defined in this scope. Predefined junos-* applications come from junos-defaults and are not expanded here.');
  if (a.status !== 'ok') {
    byId('count-apps').textContent = '';
    panel.append(stateCard(a.status, a.message, 'The applications of this scope are not shown.'));
    return;
  }
  const rows = a.rows || [];
  byId('count-apps').textContent = String(rows.length);
  if (!rows.length) {
    panel.append(h('p', { class: 'none', text: 'No custom applications or application sets. Policies here use predefined applications only.' }));
    return;
  }
  const items = rows.map((app) => {
    const isSet = app.kind === 'set';
    const tr = h(
      'tr',
      { class: app.inactive ? 'prow is-inactive' : null },
      h('th', { scope: 'row', class: 'd', text: app.name }),
      h('td', { text: isSet ? 'application set' : 'application' }),
      h('td', { class: 'd', text: isSet ? '' : app.protocol || (app.terms ? 'see terms' : '') }),
      h('td', { class: 'd', text: isSet ? '' : app.destination_port || '' }),
      h('td', { class: 'd', text: isSet ? '' : app.source_port || '' }),
      h('td', { class: 'd', text: !isSet && app.terms ? `${app.terms} (not expanded)` : '' }),
      h('td', null, isSet ? [chips(app.members, 'no applications'), (app.sets || []).length ? h('div', { class: 'small' }, mute('nested sets: '), chips(app.sets)) : null] : null),
      h('td', null, provenance(app)),
      h('td', { text: app.description || '' }),
    );
    return { node: tr, text: lower(app.name, app.kind, app.protocol, app.destination_port, app.source_port, app.members, app.sets, app.description, app.group) };
  });
  const table = h(
    'table',
    { class: 'tbl entries' },
    h('caption', { class: 'sr-only', text: 'Applications and application sets' }),
    h(
      'thead',
      null,
      h('tr', null, ['Name', 'Kind', 'Protocol', 'Destination port', 'Source port', 'Terms', 'Members', 'Provenance', 'Description'].map((t) => h('th', { scope: 'col', text: t }))),
    ),
    h('tbody', null, items.map((i) => i.node)),
  );
  panel.append(
    textFilter('af-q', 'Filter applications', 'name, protocol, port, member', items, ['application', 'applications']),
    h('div', { class: 'scroll', tabindex: '0', role: 'region', 'aria-label': 'Applications table' }, table),
  );
}

// ---- tabs ----------------------------------------------------------------------------------------

const TABS = ['policies', 'zones', 'books', 'apps'];

function selectTab(name, focus) {
  const chosen = TABS.includes(name) ? name : 'policies';
  S.tab = chosen;
  for (const t of TABS) {
    const tab = byId(`tab-${t}`);
    const on = t === chosen;
    tab.setAttribute('aria-selected', on ? 'true' : 'false');
    tab.tabIndex = on ? 0 : -1;
    byId(`panel-${t}`).hidden = !on;
  }
  if (focus) byId(`tab-${chosen}`).focus();
}

function onTabKey(event) {
  const idx = TABS.indexOf(S.tab);
  let next = null;
  if (event.key === 'ArrowRight') next = TABS[(idx + 1) % TABS.length];
  else if (event.key === 'ArrowLeft') next = TABS[(idx - 1 + TABS.length) % TABS.length];
  else if (event.key === 'Home') next = TABS[0];
  else if (event.key === 'End') next = TABS[TABS.length - 1];
  if (next) {
    event.preventDefault();
    selectTab(next, true);
  }
}

// ---- boot ----------------------------------------------------------------------------------------

function wire() {
  document.body.append(h('div', { id: 'live', class: 'sr-only', 'aria-live': 'polite', 'aria-atomic': 'true' }));
  applyTheme(effectiveTheme());
  if (lightQuery) {
    const follow = () => {
      if (!storedTheme()) applyTheme(effectiveTheme());
    };
    if (lightQuery.addEventListener) lightQuery.addEventListener('change', follow);
  }
  byId('theme').addEventListener('click', () => {
    const next = effectiveTheme() === 'light' ? 'dark' : 'light';
    saveTheme(next);
    applyTheme(next);
    announce(`${next === 'light' ? 'Light' : 'Dark'} theme.`);
  });
  byId('signin-form').addEventListener('submit', onSignIn);
  byId('refresh').addEventListener('click', () => read({}));
  byId('signout').addEventListener('click', signOut);
  byId('export-json').addEventListener('click', onExportClick);
  byId('export-csv').addEventListener('click', onExportClick);
  for (const t of TABS) byId(`tab-${t}`).addEventListener('click', () => selectTab(t, false));
  document.querySelector('.tabs').addEventListener('keydown', onTabKey);
  const dlg = byId('detail');
  dlg.addEventListener('click', (event) => {
    if (event.target === dlg) closeDetail(); // a click on the backdrop
  });
  dlg.addEventListener('close', () => {
    byId('detail-sheet').replaceChildren();
    const opener = S.opener;
    S.opener = null;
    if (opener && document.contains(opener)) opener.focus();
  });
  setInterval(updateAge, AGE_TICK_MS);
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) updateAge();
  });
}

async function boot() {
  wire();
  const res = await api('GET', '/api/session');
  if (!res.ok) {
    const view = byId('view-boot');
    view.replaceChildren(
      h('div', { class: 'state-card is-failed', role: 'alert' }, h('span', { class: 'state-code', text: res.status ? `HTTP ${res.status}` : 'no answer' }), h('h3', { text: 'J-Wicket could not start' }), h('p', { text: res.body.error || 'The session check failed.' })),
      h('button', { type: 'button', class: 'btn', text: 'Try again', on: { click: () => window.location.reload() } }),
    );
    return;
  }
  S.server = {
    credential: res.body.credential,
    backend: res.body.backend,
    fixture: res.body.fixture,
    version: res.body.version,
  };
  byId('foot-version').textContent = res.body.version ? `J-Wicket ${res.body.version}` : '';
  if (res.body.authenticated) {
    S.session = res.body;
    enterApp();
  } else {
    showSignIn();
  }
}

boot();
