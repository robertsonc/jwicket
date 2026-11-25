// Unit tests for src/jwicket/static/js/api.js (S-12): pacing, Retry-After, the background marker and
// keep-alive, retry429, 401, 5xx and network errors. fetch is stubbed; timers and Date are mocked.
// Each test imports a fresh copy of the module (a distinct URL), so module state never leaks.
// Run: node --test tests/js/*.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';

const START = Date.UTC(2026, 10, 24, 8, 0, 0);
let instance = 0;

function reply(status, body = {}, headers = {}) {
  const lower = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), String(v)]));
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (k) => lower[String(k).toLowerCase()] ?? null },
    json: async () => body,
    blob: async () => ({ size: 1 }),
  };
}

/** A fresh api.js with mocked timers and a fetch that answers from `answer(call, index)`. */
async function setup(t, answer = () => reply(200, { ok: true })) {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: START });
  const calls = [];
  globalThis.fetch = (url, init) => {
    const call = { url, method: init.method, headers: { ...init.headers }, at: Date.now(), signal: init.signal };
    calls.push(call);
    return Promise.resolve().then(() => answer(call, calls.length - 1));
  };
  instance += 1;
  const api = await import(`../../src/jwicket/static/js/api.js?instance=${instance}`);
  t.after(() => {
    api.reset();
    delete globalThis.fetch;
    delete globalThis.document;
  });
  return { api, calls };
}

async function flush(turns = 6) {
  for (let i = 0; i < turns; i += 1) await new Promise((resolve) => setImmediate(resolve));
}

/** Moves mocked time forward in small steps, letting promise chains run in between. */
async function advance(t, ms, step = 100) {
  await flush();
  for (let done = 0; done < ms; done += step) {
    t.mock.timers.tick(Math.min(step, ms - done));
    await flush();
  }
}

const bg = (call) => call.headers['X-JWicket-Background'] === '1';

test('a 429 sets notBefore for that endpoint and source; others are not held', async (t) => {
  const { api, calls } = await setup(t, (c, i) => (i === 0 ? reply(429, { error: 'Reading too often.', reason: 'rate', retry_after_s: 5, interval_s: 1.5 }, { 'Retry-After': '5' }) : reply(200, {})));
  const first = await api.get('/api/logs', { source: 'file:messages' });
  assert.equal(first.status, 429);
  assert.equal(first.retryAfter, 5);
  assert.equal(first.reason, 'rate');
  assert.equal(first.waited, 0);
  assert.equal(first.internal, false);
  const again = api.get('/api/logs', { source: 'file:messages' });
  const other = api.get('/api/logs', { source: 'traffic-log' });
  await advance(t, 6000);
  await Promise.all([again, other]);
  const at = (src) => calls.filter((c) => c.url.includes(encodeURIComponent(src))).map((c) => c.at - START);
  assert.deepEqual(at('file:messages').length, 2);
  assert.ok(at('file:messages')[1] >= 5000, `re-read waited out Retry-After: ${at('file:messages')}`);
  assert.ok(at('traffic-log')[0] < 1000, 'another source is not held');
});

test('MIN_GAP_MS paces re-reads of the rate-limited endpoints', async (t) => {
  const { api, calls } = await setup(t);
  const a = api.get('/api/sessions', { dport: 443 });
  const b = api.get('/api/sessions', { dport: 443 });
  const c = api.get('/api/session');
  const d = api.get('/api/session');
  await advance(t, 2000);
  await Promise.all([a, b, c, d]);
  const times = (p) => calls.filter((x) => x.url.startsWith(p)).map((x) => x.at - START);
  const s = times('/api/sessions?');
  assert.ok(s[1] - s[0] >= 1600, `sessions paced: ${s}`);
  const plain = calls.filter((x) => x.url === '/api/session').map((x) => x.at - START);
  assert.ok(plain[1] - plain[0] < 200, 'unpaced endpoints are not held');
});

test('background marker: a GET is foreground only after new input (decided on entry, before any wait)', async (t) => {
  const { api, calls } = await setup(t, (c, i) => (c.url.startsWith('/api/logs') && i === 3 ? reply(429, { reason: 'rate' }, { 'Retry-After': '5' }) : reply(200, {})));
  await api.get('/api/session');
  assert.equal(bg(calls[0]), false, 'the page load counts as input');
  await advance(t, 10000);
  await api.get('/api/sessions');
  assert.equal(bg(calls[1]), true, 'a poll 10 s after input, with no new input, is background');
  api.noteActivity();
  await api.get('/api/inventory', { scope: 'root' });
  assert.equal(bg(calls[2]), false, 'the first GET after input is foreground');
  // A 429 with Retry-After 5 on /api/logs, then input: the next GET waits 5 s and is still foreground.
  await advance(t, 3000);
  await api.get('/api/logs', { source: 'file:messages' });
  assert.equal(calls[3].url.startsWith('/api/logs'), true);
  assert.equal(bg(calls[3]), true);
  api.noteActivity();
  const waitedOne = api.get('/api/logs', { source: 'file:messages' });
  const pollDuringWait = api.get('/api/logs', { source: 'file:messages' });
  await advance(t, 9000);
  await Promise.all([waitedOne, pollDuringWait]);
  assert.ok(calls[4].at - calls[3].at >= 5000);
  assert.equal(bg(calls[4]), false, 'foreground although it waited 5 s');
  assert.equal(bg(calls[5]), true, 'a poll made during that wait is background');
  // A caller can say a GET is foreground; a POST never carries the marker.
  await api.get('/api/session', null, { foreground: true });
  assert.equal(bg(calls[6]), false);
  await api.post('/api/logout', {});
  assert.equal(calls[7].method, 'POST');
  assert.equal(calls[7].headers['X-JWicket-Background'], undefined);
});

test('keep-alive: once after unreported input, not while hidden or idle, stopped by reset()', async (t) => {
  const { api, calls } = await setup(t, () => reply(200, { authenticated: true }));
  api.setCsrf('csrf-token');
  await api.get('/api/inventory'); // reports the page-load input
  const sessionCalls = () => calls.filter((c) => c.url === '/api/session');

  api.noteActivity();
  await advance(t, 59000, 500);
  assert.equal(sessionCalls().length, 0, 'not before 60 s');
  await advance(t, 2000, 500);
  assert.equal(sessionCalls().length, 1, 'one keep-alive');
  assert.equal(bg(sessionCalls()[0]), false, 'the keep-alive is foreground');
  await advance(t, 180000, 1000);
  assert.equal(sessionCalls().length, 1, 'no new input, no new keep-alive');

  // Input reported by a foreground request within 60 s: no keep-alive.
  api.noteActivity();
  await advance(t, 1000);
  await api.get('/api/inventory');
  await advance(t, 70000, 1000);
  assert.equal(sessionCalls().length, 1);

  // Hidden tab: no keep-alive.
  globalThis.document = { visibilityState: 'hidden', addEventListener() {}, removeEventListener() {} };
  api.noteActivity();
  await advance(t, 70000, 1000);
  assert.equal(sessionCalls().length, 1, 'not while hidden');
  delete globalThis.document;

  // Idle: no keep-alive.
  api.setIdleLimit(10000);
  api.noteActivity();
  await advance(t, 70000, 1000);
  assert.equal(api.isIdle(), true);
  assert.equal(sessionCalls().length, 1, 'not while idle');
  api.setIdleLimit(0);

  // Activity again: at most once a minute.
  api.noteActivity();
  await advance(t, 61000, 1000);
  assert.equal(sessionCalls().length, 2);

  // reset() (sign-out) stops it.
  api.noteActivity();
  api.reset();
  await advance(t, 70000, 1000);
  assert.equal(sessionCalls().length, 2, 'reset() stops the keep-alive');
});

test('keep-alive: a reply that says the session ended calls the 401 handler with its reason', async (t) => {
  let ended = { reason: 'idle', at: '2026-11-24T08:00:30Z' };
  const { api } = await setup(t, (c) => (c.url === '/api/session' ? reply(200, { authenticated: false, ...(ended ? { ended } : {}) }) : reply(200, {})));
  const seen = [];
  api.onUnauthorized((data, path) => seen.push([data, path]));
  api.setCsrf('csrf-token');
  await api.get('/api/inventory');
  api.noteActivity();
  await advance(t, 61000, 1000);
  assert.deepEqual(seen, [[{ reason: 'idle', at: '2026-11-24T08:00:30Z' }, '/api/session']]);
  ended = null;
  api.noteActivity();
  await advance(t, 61000, 1000);
  assert.deepEqual(seen[1], [{ reason: 'unknown', at: null }, '/api/session']);
});

test('retry429: 429, 429, 200 resolves ok; onWait sees each wait', async (t) => {
  const { api, calls } = await setup(t, (c, i) => (i < 2 ? reply(429, { error: 'Another read for your session is still running. Try again shortly.', reason: 'busy', retry_after_s: 2 }, { 'Retry-After': '2' }) : reply(200, { ok: 1 })));
  const waits = [];
  const p = api.get('/api/inventory', { scope: 'root' }, { retry429: true, onWait: (w) => waits.push(w) });
  await advance(t, 6000);
  const res = await p;
  assert.equal(res.ok, true);
  assert.equal(res.status, 200);
  assert.equal(calls.length, 3);
  assert.ok(res.waited >= 4000 && res.waited <= 5000, `waited ${res.waited}`);
  assert.deepEqual(waits, [{ retryAfter: 2, reason: 'busy', attempt: 1 }, { retryAfter: 2, reason: 'busy', attempt: 2 }]);
  assert.equal(res.reason, null);
});

test('retry429: four 429s resolve the last 429 within maxWaitMs; the wait budget and attempts bound it', async (t) => {
  const { api, calls } = await setup(t, () => reply(429, { reason: 'busy' }, { 'Retry-After': '2' }));
  const p = api.get('/api/inventory', null, { retry429: true });
  await advance(t, 30000, 500);
  const res = await p;
  assert.equal(res.status, 429);
  assert.equal(res.reason, 'busy');
  assert.equal(calls.length, 4, 'attempts default to 4 sends');
  assert.ok(res.waited <= 20000, `waited ${res.waited}`);
  assert.ok(res.waited >= 6000);

  const before = calls.length;
  const capped = api.get('/api/logs', { source: 'x' }, { retry429: { attempts: 2 } });
  await advance(t, 30000, 500);
  assert.equal((await capped).status, 429);
  assert.equal(calls.length - before, 2, 'attempts: 2');
});

test('retry429: a wait past maxWaitMs is not started; an abort resolves aborted', async (t) => {
  const { api, calls } = await setup(t, () => reply(429, { reason: 'rate', retry_after_s: 15 }, { 'Retry-After': '15' }));
  const p = api.get('/api/inventory', null, { retry429: { attempts: 4, maxWaitMs: 20000 } });
  await advance(t, 40000, 500);
  const res = await p;
  assert.equal(res.status, 429);
  assert.equal(calls.length, 2, '15 s + 15 s would pass 20 s');
  assert.ok(res.waited >= 15000 && res.waited <= 20000, `waited ${res.waited}`);

  const ctl = new AbortController();
  const q = api.get('/api/sessions', null, { retry429: true, signal: ctl.signal });
  await advance(t, 1000);
  ctl.abort();
  await advance(t, 200);
  const aborted = await q;
  assert.equal(aborted.aborted, true);
  assert.equal(aborted.ok, false);
  assert.equal(aborted.status, 0);
});

test('without retry429 a 429 resolves at once', async (t) => {
  const { api, calls } = await setup(t, () => reply(429, { reason: 'rate' }));
  const res = await api.get('/api/sessions');
  assert.equal(res.status, 429);
  assert.equal(res.retryAfter, 2, 'Retry-After defaults to 2 s');
  assert.equal(calls.length, 1);
});

test('the 401 handler is called once, never for /api/session or /api/login', async (t) => {
  const { api } = await setup(t, () => reply(401, { error: 'Your session ended after 15 min without activity.', reason: 'idle', at: '2026-11-24T08:00:00Z' }));
  const seen = [];
  api.onUnauthorized((data, path) => seen.push([data.reason, path]));
  const res = await api.get('/api/inventory', { scope: 'root' });
  assert.equal(res.status, 401);
  assert.equal(res.reason, 'idle');
  await api.get('/api/session');
  await api.post('/api/login', { user: 'a', password: 'b' });
  assert.deepEqual(seen, [['idle', '/api/inventory']]);
});

test('5xx other than 503 is internal, with the J-Wicket fault text; 503 carries retryAfter', async (t) => {
  const answers = [
    reply(500, { error: 'internal error' }),
    reply(502, {}),
    reply(500, { error: 'Something specific.' }),
    reply(503, { error: 'Too many people are signed in.', reason: 'session-limit' }, { 'Retry-After': '7' }),
    reply(503, { error: 'x', retry_after_s: 9 }),
  ];
  const { api } = await setup(t, (c, i) => answers[i]);
  const r500 = await api.get('/api/inventory');
  assert.equal(r500.internal, true);
  assert.equal(r500.data.error, 'J-Wicket hit an internal error (HTTP 500). This is a J-Wicket fault, not a device failure; the J-Wicket log on the device has the details.');
  assert.equal(r500.data.error, api.messages.INTERNAL_ERROR.replace('<status>', '500'));
  const r502 = await api.get('/api/session');
  assert.equal(r502.internal, true);
  assert.match(r502.data.error, /\(HTTP 502\)/);
  const kept = await api.get('/api/session');
  assert.equal(kept.data.error, 'Something specific.');
  const r503 = await api.get('/api/session');
  assert.equal(r503.internal, false);
  assert.equal(r503.retryAfter, 7);
  assert.equal(r503.reason, 'session-limit');
  assert.equal((await api.get('/api/session')).retryAfter, 9, 'the body when there is no header');
});

test('network errors: a quick GET failure is retried once after 1.5 s; twice gives the new text', async (t) => {
  let plan = [];
  const { api, calls } = await setup(t, () => {
    const next = plan.shift();
    if (next === 'refuse') throw new TypeError('fetch failed');
    if (next === 'slow') return new Promise((_, reject) => setTimeout(() => reject(new TypeError('fetch failed')), 6000));
    return reply(200, { ok: 1 });
  });
  plan = ['refuse', 'ok'];
  let p = api.get('/api/session');
  await advance(t, 3000);
  let res = await p;
  assert.equal(res.ok, true);
  assert.equal(calls.length, 2);
  assert.ok(calls[1].at - calls[0].at >= 1500);

  plan = ['refuse', 'refuse'];
  p = api.get('/api/session');
  await advance(t, 3000);
  res = await p;
  assert.equal(res.status, 0);
  assert.equal(res.ok, false);
  assert.equal(res.data.error, api.messages.NETWORK_ERROR_TWICE);
  assert.equal(res.data.error, 'J-Wicket did not answer twice in a row. It may be busy (too many open connections) or not running; through an SSH tunnel, check the tunnel.');
  assert.equal(calls.length, 4);

  plan = ['refuse'];
  p = api.post('/api/logout', {});
  await advance(t, 3000);
  res = await p;
  assert.equal(calls.length, 5, 'a POST is never retried');
  assert.equal(res.data.error, api.messages.NETWORK_ERROR);

  plan = ['slow'];
  p = api.get('/api/session');
  await advance(t, 9000);
  res = await p;
  assert.equal(calls.length, 6, 'a slow failure is not retried');
  assert.equal(res.data.error, api.messages.NETWORK_ERROR);
});

test('every result carries reason, waited and internal; backoff() is gone', async (t) => {
  const { api } = await setup(t, () => reply(200, { meta: {} }));
  const res = await api.get('/api/session');
  assert.deepEqual([res.ok, res.status, res.retryAfter, res.reason, res.waited, res.internal], [true, 200, 0, null, 0, false]);
  assert.equal(api.backoff, undefined);
  assert.throws(() => api.buildUrl('/etc/passwd'), /not an API path/);
});

test('reset() (sign-out) cancels calls still waiting: they are never sent (F3)', async (t) => {
  const { api, calls } = await setup(t, (c, i) => (c.url.includes('logs') && i === 1 ? reply(429, { reason: 'rate', retry_after_s: 3 }, { 'Retry-After': '3' }) : reply(200, {})));
  // The Overview's summary read, then its list read paced behind it in the same /api/sessions bucket.
  const summary = await api.get('/api/sessions', { scope: 'root', rows: 'none' });
  assert.equal(summary.status, 200);
  const list = api.get('/api/sessions', { scope: 'root' });
  // A read between 429 retries.
  const logs = api.get('/api/logs', { source: 'buffer' }, { retry429: true });
  await advance(t, 300);
  assert.equal(calls.filter((c) => c.url.includes('logs')).length, 1, 'the logs read got its 429');
  api.reset();
  await advance(t, 5000);
  const [l, g] = await Promise.all([list, logs]);
  assert.equal(l.aborted, true);
  assert.equal(g.aborted, true);
  assert.equal(calls.filter((c) => c.url.includes('/api/sessions')).length, 1, 'the paced list read was not sent');
  assert.equal(calls.filter((c) => c.url.includes('logs')).length, 1, 'the 429 retry was not sent');
  // A call made after the reset goes out as usual.
  const after = await api.get('/api/session');
  assert.equal(after.status, 200);
});
