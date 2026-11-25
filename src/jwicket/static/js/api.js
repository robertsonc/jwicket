// api.js: the one fetch wrapper for the J-Wicket API.
//
// * Every call resolves (never throws) to
//     { ok, status, data, retryAfter, reason, waited, internal, aborted?, blob?, filename? }
//   `reason` is the body's machine-readable reason (429 "rate"/"busy", 401 "idle"/"replaced", ...) or
//   null; `waited` is the time spent in retry429 waits; `internal` marks a J-Wicket fault (5xx other
//   than 503), whose missing or generic text is replaced by messages.INTERNAL_ERROR.
// * POST adds Content-Type: application/json and X-CSRF-Token.
// * 401 is reported to the shell (back to sign-in with the server's reason) and still resolves.
// * 429 honours Retry-After: the call resolves with retryAfter seconds, and later calls for the same
//   endpoint wait until then instead of hammering the device. With opts.retry429 the call waits and
//   sends again itself, within a budget (attempts, maxWaitMs), telling opts.onWait at each wait.
// * While the tab is hidden, GETs wait for it to be visible again, so live polling stops and resumes
//   on its own (Junos logs every read; nobody is watching a hidden tab).
// * Idle pause: after setIdleLimit(ms) with no keyboard, pointer or touch input, GETs wait for the
//   next input in the same way, so a console left open on a shared workstation stops polling and
//   the server's idle timeout can end the session. onIdle(fn) tells the shell, which says so.
// * Background marker: a GET is foreground only when the operator did something (noteActivity) since
//   the last foreground request, or when the caller says so (opts.foreground). This is decided when the
//   call is made, before any wait. Every other GET carries X-JWicket-Background: 1, and the server
//   leaves its idle clock alone for it, so timer-driven polls never keep a session alive. A POST never
//   carries the header. When the operator was active but no foreground request went out within 60 s,
//   a keep-alive (GET /api/session) reports the activity, at most once a minute.
// * Network errors resolve { ok: false, status: 0 }. A GET whose connection was refused or closed
//   quickly (within 5 s) is tried once more after 1.5 s; a POST is never retried.
// * download() fetches a file (the inventory export) so that only a 200 body becomes a file.
//
// URLs are built only from a fixed /api/ path and URLSearchParams-encoded values.

const PATH = /^\/api\/[a-z][a-z/]*$/;
const TIMEOUT_MS = 30000;
const NETWORK_ERROR =
  'J-Wicket did not answer. Check that it is running on the device and, if you reach it through an SSH tunnel, that the tunnel is open.';
const NETWORK_ERROR_TWICE =
  'J-Wicket did not answer twice in a row. It may be busy (too many open connections) or not running; through an SSH tunnel, check the tunnel.';
// "<status>" is replaced by the HTTP status.
const INTERNAL_ERROR =
  'J-Wicket hit an internal error (HTTP <status>). This is a J-Wicket fault, not a device failure; the J-Wicket log on the device has the details.';

// The server refuses a re-read of these endpoints within a short gap (HTTP 429). Pacing requests here
// keeps normal use (views remounting, a refresh right after a poll) from ever hitting that limit.
const MIN_GAP_MS = { '/api/inventory': 2100, '/api/export': 2100, '/api/sessions': 1600, '/api/logs': 1600 };

const KEEPALIVE_MS = 60000;
const NET_RETRY_MS = 1500;
const NET_QUICK_FAIL_MS = 5000;
const RETRY429_DEFAULTS = { attempts: 4, maxWaitMs: 20000 };

let csrf = '';
let unauthorizedHandler = null;
let responseHook = null;
const notBefore = new Map();
const lastSent = new Map();
// Bumped by reset() (sign-out, a new sign-in): a call still waiting in sendOnce or between 429
// retries when it changes is not sent, so a read queued for the old session never goes out with no
// session (F3).
let generation = 0;

// ---- activity (idle pause, the background marker and the keep-alive) --------------------------------

let lastInput = Date.now();
// Operator input is counted; a foreground request reports every input counted so far. The page load
// counts as input, so the first GET is foreground.
let inputSeq = 1;
let reportedSeq = 0;
let pendingSince = Date.now(); // when the oldest input not yet reported happened (0: none)
let keepTimer = 0;
let lastKeepAlive = -Infinity;
let idleLimitMs = 0; // 0: never pause
let idleNow = false;
let idleTimer = 0;
let idleHook = null;
const idleWaiters = new Set();

function setIdle(on) {
  if (idleNow === on) return;
  idleNow = on;
  if (!on) {
    for (const resolve of [...idleWaiters]) resolve();
    idleWaiters.clear();
  }
  if (idleHook) {
    try {
      idleHook(on);
    } catch (_err) {
      // A display hook must never break a read.
    }
  }
}

function armIdle() {
  clearTimeout(idleTimer);
  if (!idleLimitMs) return;
  const wait = lastInput + idleLimitMs - Date.now();
  if (wait <= 0) setIdle(true);
  else idleTimer = setTimeout(armIdle, Math.min(wait + 50, 60000));
}

/** A foreground request is going out: the server's idle clock now knows about every input so far. */
function reportInput() {
  reportedSeq = inputSeq;
  pendingSince = 0;
}

function armKeepAlive() {
  if (keepTimer) return;
  keepTimer = setTimeout(keepAliveTick, KEEPALIVE_MS);
}

function keepAliveTick() {
  keepTimer = 0;
  if (inputSeq <= reportedSeq || !pendingSince) return; // a foreground request already reported it
  const due = Math.max(pendingSince + KEEPALIVE_MS, lastKeepAlive + KEEPALIVE_MS);
  const now = Date.now();
  if (due > now) {
    keepTimer = setTimeout(keepAliveTick, due - now);
    return;
  }
  // Signed out, hidden or idle: no keep-alive (the next input arms it again).
  if (!csrf || hidden() || idleNow) return;
  lastKeepAlive = now;
  get('/api/session', null, { foreground: true }).then((res) => {
    const d = res && res.data;
    if (res && res.ok && d && d.authenticated === false && unauthorizedHandler) {
      const ended = d.ended && typeof d.ended === 'object' ? d.ended : {};
      try {
        unauthorizedHandler({ reason: ended.reason || 'unknown', at: ended.at || null }, '/api/session');
      } catch (_err) {
        // The shell's handler must never break the keep-alive.
      }
    }
  });
}

/** The operator did something (key, pointer, touch): live reads resume and the idle clock restarts. */
export function noteActivity() {
  const now = Date.now();
  inputSeq += 1;
  if (!pendingSince) pendingSince = now;
  armKeepAlive();
  // pointermove fires constantly; only re-arm the idle timer when it matters.
  if (now - lastInput < 1000 && !idleNow) {
    lastInput = now;
    return;
  }
  lastInput = now;
  setIdle(false);
  armIdle();
}

/** Pause GETs after ms without input (0 turns the pause off). */
export function setIdleLimit(ms) {
  idleLimitMs = Math.max(0, Number(ms) || 0);
  if (!idleLimitMs) setIdle(false);
  armIdle();
}

/** fn(true) when reads pause for inactivity, fn(false) when they resume. */
export function onIdle(fn) {
  idleHook = typeof fn === 'function' ? fn : null;
}

export function isIdle() {
  return idleNow;
}

function whenActive(signal) {
  if (!idleNow) return Promise.resolve();
  return new Promise((resolve) => {
    const done = () => {
      idleWaiters.delete(done);
      resolve();
    };
    idleWaiters.add(done);
    if (signal) signal.addEventListener('abort', done, { once: true });
  });
}

export function setCsrf(token) {
  csrf = typeof token === 'string' ? token : '';
}

/**
 * fn(data, path) is called for every 401 outside /api/session and /api/login, with the 401 body
 * ({error, reason, at?}). The keep-alive also calls it, as fn({reason, at}, '/api/session'), when the
 * server says the session has ended.
 */
export function onUnauthorized(fn) {
  unauthorizedHandler = typeof fn === 'function' ? fn : null;
}

/** fn(data, path) sees every parsed JSON response (the shell watches meta.fixture). */
export function onResponse(fn) {
  responseHook = typeof fn === 'function' ? fn : null;
}

export function buildUrl(path, params) {
  if (!PATH.test(path)) throw new TypeError(`not an API path: ${path}`);
  if (!params) return path;
  let sp;
  if (params instanceof URLSearchParams) {
    sp = new URLSearchParams(params);
  } else {
    sp = new URLSearchParams();
    for (const [key, value] of Object.entries(params)) {
      if (value === undefined || value === null || value === '') continue;
      sp.set(key, String(value));
    }
  }
  const qs = sp.toString();
  return qs ? `${path}?${qs}` : path;
}

// The server rate-limits per endpoint (and per log source); back-off is tracked the same way.
function bucket(path, params) {
  let source = '';
  if (params instanceof URLSearchParams) source = params.get('source') || '';
  else if (params && params.source) source = String(params.source);
  return source ? `${path}|${source}` : path;
}

function sleep(ms, signal) {
  return new Promise((resolve) => {
    if (signal && signal.aborted) {
      resolve();
      return;
    }
    const timer = setTimeout(resolve, Math.max(0, ms));
    if (signal) {
      signal.addEventListener(
        'abort',
        () => {
          clearTimeout(timer);
          resolve();
        },
        { once: true },
      );
    }
  });
}

function hidden() {
  return typeof document !== 'undefined' && document.visibilityState === 'hidden';
}

function whenVisible(signal) {
  if (!hidden()) return Promise.resolve();
  return new Promise((resolve) => {
    const done = () => {
      if (hidden() && !(signal && signal.aborted)) return;
      document.removeEventListener('visibilitychange', done);
      resolve();
    };
    document.addEventListener('visibilitychange', done);
    if (signal) signal.addEventListener('abort', done, { once: true });
  });
}

// Only a plain file name from Content-Disposition; anything else falls back to the caller's name.
function filenameOf(res) {
  const cd = res.headers.get('Content-Disposition') || '';
  const m = /filename="([A-Za-z0-9._-]{1,120})"/.exec(cd);
  return m ? m[1] : '';
}

function retryAfterOf(res, data) {
  const header = parseInt(res.headers.get('Retry-After') || '', 10);
  if (Number.isFinite(header) && header > 0) return header;
  const body = data && Number(data.retry_after_s);
  return Number.isFinite(body) && body > 0 ? body : 0;
}

function retryPolicy(opt) {
  if (!opt) return null;
  const o = opt === true ? {} : opt;
  const attempts = Number.isFinite(Number(o.attempts)) && Number(o.attempts) >= 1 ? Math.floor(Number(o.attempts)) : RETRY429_DEFAULTS.attempts;
  const maxWaitMs = Number.isFinite(Number(o.maxWaitMs)) && Number(o.maxWaitMs) >= 0 ? Number(o.maxWaitMs) : RETRY429_DEFAULTS.maxWaitMs;
  return { attempts, maxWaitMs };
}

const ABORTED = () => ({ ok: false, status: 0, data: {}, retryAfter: 0, aborted: true });

/** Adds the fields every result carries. */
function finish(res, waited) {
  const data = res.data && typeof res.data === 'object' ? res.data : {};
  return { ...res, data, reason: typeof data.reason === 'string' ? data.reason : null, waited, internal: Boolean(res.internal) };
}

/** One request: waits (hidden, idle, Retry-After, pacing), sends (a quick network failure of a GET is tried again once), reads. */
async function sendOnce(method, path, url, key, body, opts, background, gen) {
  const signal = opts.signal || null;
  const gone = () => (signal && signal.aborted) || gen !== generation;
  if (method === 'GET' && !opts.evenIfHidden) {
    // Hidden and idle can alternate (a tab hidden, shown, then left alone): wait until neither holds.
    while ((hidden() || idleNow) && !gone()) {
      await whenVisible(signal);
      await whenActive(signal);
    }
  }
  // Wait out a Retry-After, then the endpoint's minimum gap. Concurrent callers queue behind each other.
  for (;;) {
    const gap = MIN_GAP_MS[path] || 0;
    const due = Math.max(notBefore.get(key) || 0, gap ? (lastSent.get(key) || 0) + gap : 0);
    const wait = due - Date.now();
    if (wait <= 0) break;
    await sleep(wait, signal);
    if (gone()) break;
  }
  if (gone()) return ABORTED();
  if (MIN_GAP_MS[path]) lastSent.set(key, Date.now());

  const headers = { Accept: 'application/json' };
  if (background) headers['X-JWicket-Background'] = '1';
  const init = { method, headers, credentials: 'same-origin', cache: 'no-store', redirect: 'error' };
  if (method !== 'GET') {
    headers['Content-Type'] = 'application/json';
    if (csrf) headers['X-CSRF-Token'] = csrf;
    init.body = JSON.stringify(body || {});
  }

  let res = null;
  let timer = 0;
  let onAbort = null;
  const release = () => {
    clearTimeout(timer);
    if (signal && onAbort) signal.removeEventListener('abort', onAbort);
  };
  for (let attempt = 1; ; attempt += 1) {
    const ctl = new AbortController();
    let timedOut = false;
    onAbort = () => ctl.abort();
    if (signal) signal.addEventListener('abort', onAbort, { once: true });
    timer = setTimeout(() => {
      timedOut = true;
      ctl.abort();
    }, opts.timeoutMs || TIMEOUT_MS);
    init.signal = ctl.signal;
    const sentAt = Date.now();
    try {
      res = await fetch(url, init);
      break;
    } catch (_err) {
      release();
      if (signal && signal.aborted) return ABORTED();
      // A refused or closed connection fails at once; a timeout or a slow failure is not retried.
      const quick = !timedOut && Date.now() - sentAt < NET_QUICK_FAIL_MS;
      if (method === 'GET' && attempt === 1 && quick) {
        await sleep(NET_RETRY_MS, signal);
        if (gone()) return ABORTED();
        continue;
      }
      return { ok: false, status: 0, data: { error: attempt > 1 ? NETWORK_ERROR_TWICE : NETWORK_ERROR }, retryAfter: 0 };
    }
  }
  if (opts.raw && res.ok) {
    // A download (export): the body is the file, not JSON for the caller to read.
    let blob = null;
    try {
      blob = await res.blob();
    } catch (_err) {
      blob = null;
    } finally {
      release();
    }
    if (!blob) return { ok: false, status: 0, data: { error: NETWORK_ERROR }, retryAfter: 0 };
    return { ok: true, status: res.status, data: {}, retryAfter: 0, blob, filename: filenameOf(res) };
  }
  let data = {};
  try {
    const parsed = await res.json();
    if (parsed && typeof parsed === 'object') data = parsed;
  } catch (_err) {
    data = {};
  } finally {
    release();
  }

  let retryAfter = 0;
  if (res.status === 429) retryAfter = retryAfterOf(res, data) || 2;
  else if (res.status === 503) retryAfter = retryAfterOf(res, data);
  if (res.status === 429) notBefore.set(key, Date.now() + retryAfter * 1000);
  if (responseHook) {
    try {
      responseHook(data, path);
    } catch (_err) {
      // A display hook must never break a read.
    }
  }
  if (res.status === 401 && path !== '/api/session' && path !== '/api/login' && unauthorizedHandler) {
    unauthorizedHandler(data, path);
  }
  // A J-Wicket fault (5xx other than 503, which says when to try again): never blamed on the device.
  const internal = res.status >= 500 && res.status !== 503;
  if (internal && (typeof data.error !== 'string' || !data.error.trim() || data.error.trim().toLowerCase() === 'internal error')) {
    data = { ...data, error: INTERNAL_ERROR.replace('<status>', String(res.status)) };
  }
  return { ok: res.ok, status: res.status, data, retryAfter, internal };
}

async function request(method, path, params, body, opts = {}) {
  const o = opts || {};
  const url = buildUrl(path, params);
  const key = bucket(path, params);
  // Foreground or background is decided now, before any wait: input made while this call waits
  // (Retry-After, pacing, a hidden tab) is reported by the next call.
  let background = false;
  if (method !== 'GET' || o.foreground === true || inputSeq > reportedSeq) reportInput();
  else background = true;

  const retry = retryPolicy(o.retry429);
  const gen = generation;
  let waited = 0;
  for (let attempt = 1; ; attempt += 1) {
    const res = await sendOnce(method, path, url, key, body, o, background, gen);
    if (res.status !== 429 || !retry || res.aborted) return finish(res, waited);
    if (attempt >= retry.attempts || waited + res.retryAfter * 1000 > retry.maxWaitMs) return finish(res, waited);
    if (typeof o.onWait === 'function') {
      try {
        o.onWait({ retryAfter: res.retryAfter, reason: typeof res.data.reason === 'string' ? res.data.reason : null, attempt });
      } catch (_err) {
        // A display hook must never break a read.
      }
    }
    const t0 = Date.now();
    await sleep((notBefore.get(key) || 0) - Date.now(), o.signal || null);
    waited += Date.now() - t0;
    if ((o.signal && o.signal.aborted) || gen !== generation) return finish(ABORTED(), waited);
  }
}

/** get('/api/sessions', { dport: 443 }, { signal, foreground, retry429, onWait }) */
export function get(path, params, opts) {
  return request('GET', path, params, null, opts);
}

/** download('/api/export', { scope, format }) -> { ok, status, blob, filename, data, retryAfter, ... }.
    Errors (401, 429, ...) come back as JSON in data, so an error body is never saved as the file. */
export function download(path, params, opts) {
  return request('GET', path, params, null, { ...(opts || {}), raw: true });
}

/** post('/api/logout', {}) */
export function post(path, body, opts) {
  return request('POST', path, null, body, opts);
}

/** Sign-out or a new sign-in: forget the token, back-off state and the keep-alive. */
export function reset() {
  generation += 1;
  csrf = '';
  notBefore.clear();
  lastSent.clear();
  clearTimeout(keepTimer);
  keepTimer = 0;
  lastKeepAlive = -Infinity;
  pendingSince = 0;
  reportedSeq = inputSeq;
  setIdleLimit(0);
}

export const messages = { NETWORK_ERROR, NETWORK_ERROR_TWICE, INTERNAL_ERROR };
