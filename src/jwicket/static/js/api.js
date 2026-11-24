// api.js: the one fetch wrapper for the J-Wicket API.
//
// * Every call resolves (never throws) to { ok, status, data, retryAfter }.
// * POST adds Content-Type: application/json and X-CSRF-Token.
// * 401 is reported to the shell (back to sign-in with the server's message) and still resolves.
// * 429 honours Retry-After: the call resolves with retryAfter seconds, and later calls for the same
//   endpoint wait until then instead of hammering the device.
// * While the tab is hidden, GETs wait for it to be visible again, so live polling stops and resumes
//   on its own (Junos logs every read; nobody is watching a hidden tab).
// * Network errors resolve { ok: false, status: 0 }.
// * download() fetches a file (the inventory export) so that only a 200 body becomes a file.
//
// URLs are built only from a fixed /api/ path and URLSearchParams-encoded values.

const PATH = /^\/api\/[a-z][a-z/]*$/;
const TIMEOUT_MS = 30000;
const NETWORK_ERROR =
  'J-Wicket did not answer. Check that it is running on the device and, if you reach it through an SSH tunnel, that the tunnel is open.';

// The server refuses a re-read of these endpoints within a short gap (HTTP 429). Pacing requests here
// keeps normal use (views remounting, a refresh right after a poll) from ever hitting that limit.
const MIN_GAP_MS = { '/api/inventory': 2100, '/api/export': 2100, '/api/sessions': 1600, '/api/logs': 1600 };

let csrf = '';
let unauthorizedHandler = null;
let responseHook = null;
const notBefore = new Map();
const lastSent = new Map();

export function setCsrf(token) {
  csrf = typeof token === 'string' ? token : '';
}

/** fn(data, path) is called for every 401 outside /api/session and /api/login. */
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
    const timer = setTimeout(resolve, ms);
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

async function request(method, path, params, body, opts = {}) {
  const url = buildUrl(path, params);
  const signal = opts.signal || null;
  const key = bucket(path, params);

  if (method === 'GET' && !opts.evenIfHidden) await whenVisible(signal);
  // Wait out a Retry-After, then the endpoint's minimum gap. Concurrent callers queue behind each other.
  for (;;) {
    const gap = MIN_GAP_MS[path] || 0;
    const due = Math.max(notBefore.get(key) || 0, gap ? (lastSent.get(key) || 0) + gap : 0);
    const wait = due - Date.now();
    if (wait <= 0) break;
    await sleep(wait, signal);
    if (signal && signal.aborted) break;
  }
  if (signal && signal.aborted) return { ok: false, status: 0, data: {}, retryAfter: 0, aborted: true };
  if (MIN_GAP_MS[path]) lastSent.set(key, Date.now());

  const headers = { Accept: 'application/json' };
  const init = { method, headers, credentials: 'same-origin', cache: 'no-store', redirect: 'error' };
  if (method !== 'GET') {
    headers['Content-Type'] = 'application/json';
    if (csrf) headers['X-CSRF-Token'] = csrf;
    init.body = JSON.stringify(body || {});
  }
  const ctl = new AbortController();
  const onAbort = () => ctl.abort();
  if (signal) signal.addEventListener('abort', onAbort, { once: true });
  const timer = setTimeout(() => ctl.abort(), opts.timeoutMs || TIMEOUT_MS);
  init.signal = ctl.signal;

  let res;
  try {
    res = await fetch(url, init);
  } catch (_err) {
    clearTimeout(timer);
    if (signal) signal.removeEventListener('abort', onAbort);
    if (signal && signal.aborted) return { ok: false, status: 0, data: {}, retryAfter: 0, aborted: true };
    return { ok: false, status: 0, data: { error: NETWORK_ERROR }, retryAfter: 0 };
  }
  if (opts.raw && res.ok) {
    // A download (export): the body is the file, not JSON for the caller to read.
    let blob = null;
    try {
      blob = await res.blob();
    } catch (_err) {
      blob = null;
    } finally {
      clearTimeout(timer);
      if (signal) signal.removeEventListener('abort', onAbort);
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
    clearTimeout(timer);
    if (signal) signal.removeEventListener('abort', onAbort);
  }

  const retryAfter = res.status === 429 ? retryAfterOf(res, data) || 2 : 0;
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
  return { ok: res.ok, status: res.status, data, retryAfter };
}

/** get('/api/sessions', { dport: 443 }, { signal }) */
export function get(path, params, opts) {
  return request('GET', path, params, null, opts);
}

/** download('/api/export', { scope, format }) -> { ok, status, blob, filename, data, retryAfter }.
    Errors (401, 429, ...) come back as JSON in data, so an error body is never saved as the file. */
export function download(path, params, opts) {
  return request('GET', path, params, null, { ...(opts || {}), raw: true });
}

/** post('/api/logout', {}) */
export function post(path, body, opts) {
  return request('POST', path, null, body, opts);
}

/** Seconds until the endpoint may be read again (0 when it may be read now). */
export function backoff(path, params) {
  const wait = (notBefore.get(bucket(path, params)) || 0) - Date.now();
  return wait > 0 ? Math.ceil(wait / 1000) : 0;
}

export function reset() {
  csrf = '';
  notBefore.clear();
  lastSent.clear();
}

export const messages = { NETWORK_ERROR };
