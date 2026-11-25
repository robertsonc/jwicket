// Unit tests for src/jwicket/static/js/dom.js: state cards (S-3), the subtitle (S-4) and visible
// device text (S-2). A minimal fake document stands in for the browser. Run: node --test tests/js/*.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import * as dom from '../../src/jwicket/static/js/dom.js';

// ---- a minimal DOM: enough for h(), svg() and text nodes ------------------------------------------

class FakeNode {
  constructor(nodeType) {
    this.nodeType = nodeType;
    this.childNodes = [];
  }
  get textContent() {
    return this.nodeType === 3 ? this.data : this.childNodes.map((c) => c.textContent).join('');
  }
  set textContent(v) {
    if (this.nodeType === 3) this.data = String(v);
    else this.childNodes = [makeText(String(v))];
  }
  append(...nodes) {
    for (const n of nodes) this.childNodes.push(typeof n === 'string' ? makeText(n) : n);
  }
  replaceChildren(...nodes) {
    this.childNodes = [];
    this.append(...nodes);
  }
}

class FakeElement extends FakeNode {
  constructor(tag, ns) {
    super(1);
    this.tagName = tag;
    this.namespaceURI = ns || 'http://www.w3.org/1999/xhtml';
    this.attributes = new Map();
    this.dataset = {};
    this.style = { setProperty: (k, v) => { this.style[k] = v; } };
    this.listeners = [];
  }
  setAttribute(k, v) {
    this.attributes.set(k, String(v));
  }
  getAttribute(k) {
    return this.attributes.has(k) ? this.attributes.get(k) : null;
  }
  addEventListener(type, fn) {
    this.listeners.push([type, fn]);
  }
  get className() {
    return this.getAttribute('class') || '';
  }
  /** Every descendant element (depth first). */
  all() {
    return this.childNodes.flatMap((c) => (c instanceof FakeElement ? [c, ...c.all()] : []));
  }
}

function makeText(data) {
  const t = new FakeNode(3);
  t.data = data;
  return t;
}

globalThis.document = {
  createElement: (tag) => new FakeElement(tag),
  createElementNS: (ns, tag) => new FakeElement(tag, ns),
  createTextNode: (data) => makeText(String(data)),
};

const ch = (cp) => String.fromCodePoint(cp);
const RLO = ch(0x202e);
const ZWSP = ch(0x200b);
const textOf = (nodes) => nodes.map((n) => (typeof n === 'string' ? n : n.textContent)).join('');

// ---- state cards ---------------------------------------------------------------------------------

test('STATE_TITLES covers every status a view can show', () => {
  for (const s of ['count-unknown', 'filter-rejected', 'refused', 'denied', 'unsupported', 'failed', 'session-lost', 'waiting', 'busy', 'internal', 'offline']) {
    assert.equal(typeof dom.STATE_TITLES[s], 'string', s);
    assert.ok(dom.STATE_TITLES[s].length > 5, s);
  }
  assert.equal(dom.STATE_TITLES['count-unknown'], 'Not listed: how many sessions match is not known');
  assert.equal(dom.STATE_TITLES['filter-rejected'], 'The device did not accept this filter');
  assert.equal(dom.STATE_TITLES.waiting, 'Waiting for another read');
  assert.equal(dom.STATE_TITLES.busy, 'Other reads for your session kept J-Wicket busy');
  assert.equal(dom.STATE_TITLES.internal, 'J-Wicket could not complete this request');
  assert.equal(dom.STATE_HINTS['count-unknown'], 'J-Wicket lists sessions only when it knows the count is small enough; nothing failed on the device.');
  assert.equal(dom.STATE_HINTS['filter-rejected'], 'Remove the device filters, or filter in the browser instead.');
  assert.equal(dom.STATE_HINTS.waiting, 'Another read for your session is running (another tab or window of this session?). J-Wicket tries again by itself.');
  assert.equal(dom.STATE_HINTS.busy, 'J-Wicket tries again in 30 s, or read again now.');
  assert.equal(dom.STATE_HINTS.internal, 'This is a J-Wicket fault, not a device failure. Refresh to try again; the J-Wicket log on the device has the details.');
  assert.deepEqual(dom.STATE_CODES, { 'count-unknown': 'count unknown', 'filter-rejected': 'filter rejected', waiting: 'waiting', busy: 'busy', internal: 'internal' });
  for (const name of ['help', 'filter', 'clock', 'alert']) assert.ok(dom.ICONS[name], name);
});

test('stateCard: role="alert" only for failed and internal; the code chip uses STATE_CODES', () => {
  const card = (status, extra = {}) => dom.stateCard({ status, ...extra });
  for (const s of ['failed', 'internal']) assert.equal(card(s).getAttribute('role'), 'alert', s);
  for (const s of ['count-unknown', 'filter-rejected', 'waiting', 'busy', 'denied', 'unsupported', 'refused', 'offline', 'session-lost']) {
    const c = card(s);
    assert.equal(c.getAttribute('role'), null, s);
    assert.equal(c.dataset.state, s);
  }
  const code = (c) => c.all().find((e) => e.className === 'state-code');
  assert.equal(code(card('count-unknown')).textContent, 'count unknown');
  assert.equal(code(card('filter-rejected')).textContent, 'filter rejected');
  assert.equal(code(card('denied')).textContent, 'denied');
  const title = card('filter-rejected', { title: `The device did not accept the filter app=a${RLO}b` });
  assert.equal(title.textContent.includes(RLO), false, 'device text in a title is badged, not applied');
  assert.ok(title.all().some((e) => e.className === 'ctl-badge' && e.textContent === 'U+202E'));
});

// ---- the subtitle --------------------------------------------------------------------------------

const BASE = { host: 'branch-fw-01', scope: 'Root system', readAt: '2026-11-24T07:44:22Z', user: 'admin', backend: 'netconf' };
const texts = (o) => dom.subParts(o).map((p) => p.text);

test('subParts: configuration read, committed source', () => {
  assert.deepEqual(texts({ ...BASE, config: { status: 'ok' }, source: { database: 'committed', inheritance: true } }),
    ['branch-fw-01', 'Root system', 'committed config, inheritance expanded', 'read 07:44:22 UTC', 'as admin']);
  assert.deepEqual(texts({ ...BASE, config: { status: 'ok' }, source: { database: 'committed', inheritance: false } }),
    ['branch-fw-01', 'Root system', 'committed config', 'read 07:44:22 UTC', 'as admin']);
  // No config and no source (Sessions, Logs): as before.
  assert.deepEqual(texts(BASE), ['branch-fw-01', 'Root system', 'read 07:44:22 UTC', 'as admin']);
  const parts = dom.subParts({ ...BASE, config: { status: 'ok' }, source: { database: 'committed', inheritance: true } });
  assert.equal(parts[0].mono, true);
  assert.equal(parts[4].mono, true);
  assert.equal(parts[4].head, 'as ');
  assert.equal(parts[3].title, '2026-11-24 07:44:22 UTC');
});

test('subParts: configuration denied or failed reads "configuration not read" and "checked"', () => {
  const denied = { status: 'denied', message: 'Your Junos login class does not allow this.' };
  assert.deepEqual(texts({ ...BASE, user: 'auditor', config: denied, source: { database: 'committed', inheritance: true } }),
    ['branch-fw-01', 'Root system', 'configuration not read (your login class does not allow it)', 'checked 07:44:22 UTC', 'as auditor']);
  const part = dom.subParts({ ...BASE, config: denied })[2];
  assert.equal(part.muted, true);
  assert.equal(part.title, 'Your Junos login class does not allow this.');
  assert.deepEqual(texts({ ...BASE, config: { status: 'failed', message: 'The device could not complete the request.' } }),
    ['branch-fw-01', 'Root system', 'configuration read failed', 'checked 07:44:22 UTC', 'as admin']);
  assert.equal(texts({ ...BASE, config: { status: 'unsupported' } })[2], 'configuration read not supported');
  assert.equal(texts({ ...BASE, config: { status: 'session-lost' } })[2], 'configuration not read (session-lost)');
});

test('subParts: lab token and extras', () => {
  assert.deepEqual(texts({ ...BASE, backend: 'lab-token' }), ['branch-fw-01', 'Root system', 'read 07:44:22 UTC', 'lab token: as admin']);
  assert.equal(dom.subParts({ ...BASE, backend: 'lab-token' })[3].head, 'lab token: as ');
  assert.deepEqual(texts({ host: null, scope: 'Tenant system T-1', extra: ['12 policies', null, ''] }), ['Tenant system T-1', '12 policies']);
  assert.deepEqual(dom.subParts({}), []);
});

test('viewSub renders the parts with separators, the user name mono, device text badged', () => {
  const el = document.createElement('p');
  const nodes = dom.viewSub(el, { ...BASE, user: `ad${RLO}min`, config: { status: 'denied', message: `no${ZWSP}` }, extra: ['3 rows'] });
  assert.equal(el.childNodes.length, nodes.length);
  const text = el.textContent;
  assert.ok(text.startsWith('branch-fw-01 · Root system · configuration not read (your login class does not allow it) · checked 07:44:22 UTC · as ad'), text);
  assert.equal(text.includes(RLO), false);
  assert.ok(text.endsWith(' · 3 rows'));
  const muted = el.all().find((e) => e.className === 'muted');
  assert.equal(muted.getAttribute('title'), 'no<U+200B>');
  const mono = el.all().filter((e) => e.className === 'mono').map((e) => e.textContent);
  assert.deepEqual(mono, ['branch-fw-01', 'adU+202Emin']);
  assert.equal(el.all().filter((e) => e.className === 'sub-sep').length, 5);
});

// ---- visible device text -------------------------------------------------------------------------

test('vis: fast path, badges for controls, marks merged, badges inside marks', () => {
  assert.deepEqual(dom.vis('plain'), ['plain']);
  assert.deepEqual(dom.vis(null), ['']);
  assert.deepEqual(dom.vis('a\tb'), ['a\tb']);
  const out = dom.vis(`web${ZWSP}proxy`);
  assert.equal(out.length, 3);
  assert.equal(out[0], 'web');
  assert.equal(out[1].className, 'ctl-badge');
  assert.equal(out[1].textContent, 'U+200B');
  assert.equal(out[1].getAttribute('title'), 'A hidden U+200B character is here (shown, not applied)');
  assert.equal(out[2], 'proxy');
  assert.equal(dom.vis('a\tb', { all: true })[1].textContent, 'U+0009');

  const marked = dom.vis(`x${RLO}yzzy`, { marks: [[4, 6], [0, 2], [1, 3]] });
  // [0,2) and [1,3) merge to [0,3); [4,6) stays apart.
  assert.equal(marked.length, 3);
  assert.equal(marked[0].tagName, 'mark');
  assert.equal(marked[0].className, 'hit');
  assert.equal(marked[0].textContent, 'xU+202Ey');
  assert.ok(marked[0].all().some((e) => e.className === 'ctl-badge'));
  assert.equal(marked[1], 'z');
  assert.equal(marked[2].textContent, 'zy');
  assert.equal(textOf(dom.vis('abc', { marks: [[1, 99]], markClass: 'pv-hit' })), 'abc');
  assert.equal(dom.vis('abc', { marks: [[1, 99]], markClass: 'pv-hit' })[1].className, 'pv-hit');
  assert.deepEqual(dom.vis('abc', { marks: [[2, 2], [5, 9], ['x', 1]] }), ['abc'], 'empty and invalid marks are dropped');
  const emoji = `a${ch(0x1f600)}b`;
  assert.equal(textOf(dom.vis(emoji, { marks: [[2, 4]] })), emoji, 'a mark never cuts a surrogate pair');
});

test('visSvg: tspan badges for SVG text', () => {
  assert.deepEqual(dom.visSvg('ge-0/0/0.0'), ['ge-0/0/0.0']);
  const out = dom.visSvg(`ge${RLO}0`);
  assert.equal(out[1].tagName, 'tspan');
  assert.equal(out[1].namespaceURI, dom.SVG_NS);
  assert.equal(out[1].className, 'ctl-badge');
  assert.equal(out[1].textContent, 'U+202E');
  assert.equal(textOf(out), 'geU+202E0');
});

test('VirtualList is gone (Sessions and Logs have their own row windows)', () => {
  assert.equal(dom.VirtualList, undefined);
});
