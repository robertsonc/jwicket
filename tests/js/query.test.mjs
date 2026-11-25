// Unit tests for src/jwicket/static/js/query.js. Run: node --test tests/js/
// Rows and inventory below are synthetic, shaped like the /api/sessions and /api/inventory replies.
import test from 'node:test';
import assert from 'node:assert/strict';
import * as q from '../../src/jwicket/static/js/query.js';
import * as lp from '../../src/jwicket/static/js/logparse.js';

const wingIn = (src, sport, dst, dport, proto, iface, bytes, packets) => ({ direction: 'In', src, sport, dst, dport, proto, iface, bytes, packets, tunnel: null });
function session(id, policy, a, b, extra = {}) {
  const nat = { source: b.dst !== a.src || b.dport !== a.sport, destination: b.src !== a.dst || b.sport !== a.dport };
  return { id: String(id), session_id: String(id), location: null, status: 'Normal', state: 'Valid', policy, policy_index: '5', timeout: 1700, configured_timeout: 1800, start_time: '0', duration: 60, application: null, in: a, out: b, nat, extra: {}, ...extra };
}

const ROWS = [
  session(1, 'allow-web', wingIn('10.10.0.11', 40001, '198.51.100.20', 443, 'tcp', 'ge-0/0/1.0', 2_000_000, 1500), wingIn('198.51.100.20', 443, '203.0.113.2', 50001, 'tcp', 'ge-0/0/0.0', 30_000_000, 21000), { duration: 400 }),
  session(2, 'baseline-dns', wingIn('10.10.0.12', 40002, '198.51.100.53', 53, 'udp', 'ge-0/0/1.0', 80, 1), wingIn('198.51.100.53', 53, '203.0.113.2', 50002, 'udp', 'ge-0/0/0.0', 200, 1), { duration: 2 }),
  session(3, 'publish-web', wingIn('198.51.100.130', 51000, '203.0.113.11', 443, 'tcp', 'ge-0/0/0.0', 9000, 30), wingIn('10.20.0.11', 443, '198.51.100.130', 51000, 'tcp', 'ge-0/0/2.0', 400_000, 300), { duration: 30 }),
  session(4, 'admin-to-dmz', wingIn('10.10.0.20', 45145, '10.20.0.50', 22, 'tcp', 'ge-0/0/1.0', 182040, 260), wingIn('10.20.0.50', 22, '10.10.0.20', 45145, 'tcp', 'ge-0/0/2.0', 2274816, 3250), { duration: 712 }),
  session(5, 'allow-web', wingIn('2001:db8:10::5', 40005, '2001:db8:ff::80', 80, 'tcp', 'ge-0/0/1.0', 1000, 10), wingIn('2001:db8:ff::80', 80, '2001:db8:10::5', 40005, 'tcp', 'ge-0/0/0.0', 4000, 12), { duration: 5 }),
];

const POLICY = (name, from, to, extra = {}) => ({
  id: `root|zone|${from}>${to}|${name}`, scope: 'root', kind: 'zone', seq: 1, from: [from], to: [to], name, description: null,
  match: { source: ['any'], destination: ['any'], application: ['any'] }, action: 'permit', application_services: [], tunnel: null,
  log: { init: false, close: false }, count: false, scheduler: null, inactive: false, inactive_reason: null, group: null, inherited: [], groups: [],
  unmodeled: [], resolved: { source: [{ name: 'any', kind: 'any', leaves: [] }], destination: [{ name: 'any', kind: 'any', leaves: [] }], application: [{ name: 'any', kind: 'any', leaves: [] }] },
  ...extra,
});

const INVENTORY = {
  meta: { fixture: true },
  scope: {
    id: 'root',
    policies: {
      status: 'ok',
      rows: [
        POLICY('baseline-dns', 'trust', 'untrust', {
          group: 'corp-baseline', groups: ['corp-baseline'], match: { source: ['corp-lan'], destination: ['any'], application: ['junos-dns-udp'] },
          resolved: { source: [{ name: 'corp-lan', kind: 'address', leaves: [{ name: 'corp-lan', kind: 'prefix', value: '10.10.0.0/16' }] }], destination: [{ name: 'any', kind: 'any', leaves: [] }], application: [{ name: 'junos-dns-udp', kind: 'predefined', leaves: [] }] },
        }),
        POLICY('allow-web', 'trust', 'untrust', {
          seq: 2, count: true, log: { init: false, close: true }, match: { source: ['corp-lan'], destination: ['any'], application: ['web-apps'] },
          resolved: { source: [{ name: 'corp-lan', kind: 'address', leaves: [{ name: 'corp-lan', kind: 'prefix', value: '10.10.0.0/16' }] }], destination: [{ name: 'any', kind: 'any', leaves: [] }], application: [{ name: 'web-apps', kind: 'set', leaves: [{ name: 'junos-https', predefined: true }, { name: 'tcp-8443', protocol: 'tcp', destination_port: '8443' }] }] },
        }),
        POLICY('admin-to-dmz', 'trust', 'dmz', {
          log: { init: true, close: true }, match: { source: ['corp-lan'], destination: ['dmz-jump'], application: ['junos-ssh'] },
          resolved: { source: [{ name: 'corp-lan', kind: 'address', leaves: [{ name: 'corp-lan', kind: 'prefix', value: '10.10.0.0/16' }] }], destination: [{ name: 'dmz-jump', kind: 'address', leaves: [{ name: 'dmz-jump', kind: 'prefix', value: '10.20.0.50/32' }] }], application: [{ name: 'junos-ssh', kind: 'predefined', leaves: [] }] },
        }),
        POLICY('publish-web', 'untrust', 'dmz', {
          match: { source: ['any'], destination: ['web-servers'], application: ['junos-https'] },
          resolved: { source: [{ name: 'any', kind: 'any', leaves: [] }], destination: [{ name: 'web-servers', kind: 'set', leaves: [{ name: 'web-1', kind: 'prefix', value: '10.20.0.11/32' }, { name: 'web-dns', kind: 'dns', value: 'www.example.net' }] }], application: [{ name: 'junos-https', kind: 'predefined', leaves: [] }] },
        }),
        POLICY('block-telnet', 'trust', 'untrust', { action: 'deny', inactive: true, inactive_reason: 'policy' }),
        POLICY('global-printers', 'trust', 'dmz', {
          kind: 'global', group: 'corp-baseline', match: { source: ['branch-printers'], destination: ['any'], application: ['junos-ipp'] },
          resolved: { source: [{ name: 'branch-printers', kind: 'address', leaves: [{ name: 'branch-printers', kind: 'range', value: '10.10.40.10-10.10.40.19' }] }], destination: [{ name: 'any', kind: 'any', leaves: [] }], application: [{ name: 'junos-ipp', kind: 'predefined', leaves: [] }] },
        }),
        POLICY('global-blocklist', 'x', 'y', { kind: 'global', from: [], to: [], action: 'deny' }),
      ],
    },
    zones: { status: 'ok', rows: [{ name: 'trust', interfaces: [{ name: 'ge-0/0/1.0' }] }, { name: 'untrust', interfaces: [{ name: 'ge-0/0/0.0' }] }, { name: 'dmz', interfaces: [{ name: 'ge-0/0/2.0' }] }] },
    address_books: { status: 'ok', rows: [{ name: 'global', addresses: [{ name: 'corp-lan' }, { name: 'dmz-jump' }], sets: [{ name: 'web-servers' }] }] },
    applications: { status: 'ok', rows: [{ name: 'tcp-8443' }, { name: 'web-apps' }] },
    groups: [{ name: 'corp-baseline' }],
  },
};

function ok(text, view) {
  const r = q.parse(text, view ? { view } : undefined);
  assert.equal(r.error, null, `${text}: ${r.error && r.error.message}`);
  return r.ast;
}
function ids(text, view = 'sessions', rows = ROWS, ctx = { inventory: INVENTORY }) {
  const ast = ok(text, view);
  const f = q.compile(ast, q.FIELDS[view], ctx);
  return rows.filter(f).map((r) => r.session_id ?? r.name);
}

// --- grammar --------------------------------------------------------------------------------------

test('empty and blank queries parse to null', () => {
  assert.deepEqual(q.parse(''), { ast: null, error: null });
  assert.deepEqual(q.parse('   '), { ast: null, error: null });
  assert.deepEqual(q.parse(null), { ast: null, error: null });
});

test('terms: key:value, key=value, comparisons, bare values', () => {
  const t = ok('dport:443');
  assert.equal(t.type, 'term');
  assert.equal(t.key, 'dport');
  assert.equal(t.op, ':');
  assert.deepEqual(t.values.map((v) => v.text), ['443']);
  for (const op of ['=', '!=', '>=', '<=', '>', '<', '~']) {
    const a = ok(`bytes${op}1M`);
    assert.equal(a.op, op);
    assert.equal(a.values[0].text, '1M');
  }
  const free = ok('allow-web');
  assert.equal(free.key, null);
  assert.equal(free.values[0].text, 'allow-web');
});

test('J-Web spacing around comparison operators', () => {
  const a = ok('source-address = 10.0.0.1 AND destination-port >= 1024');
  assert.equal(a.type, 'and');
  assert.deepEqual(a.items.map((i) => [i.key, i.op, i.values[0].text]), [['source-address', '=', '10.0.0.1'], ['destination-port', '>=', '1024']]);
});

test('juxtaposition is AND; AND binds tighter than OR', () => {
  const a = ok('a b OR c d');
  assert.equal(a.type, 'or');
  assert.equal(a.items.length, 2);
  assert.equal(a.items[0].type, 'and');
  assert.equal(a.items[1].type, 'and');
  assert.equal(q.toQueryString(a), 'a b OR c d');
  for (const s of ['a AND b', 'a and b', 'a && b', 'a&&b']) assert.equal(ok(s).type, 'and', s);
  for (const s of ['a OR b', 'a or b', 'a || b', 'a | b']) assert.equal(ok(s).type, 'or', s);
});

test('NOT, not, -, ! negate; parentheses group; nesting', () => {
  for (const s of ['NOT a', 'not a', '-a', '!a', '! a']) {
    const n = ok(s);
    assert.equal(n.type, 'not', s);
    assert.equal(n.item.values[0].text, 'a');
  }
  const g = ok('-(a OR b) c');
  assert.equal(g.type, 'and');
  assert.equal(g.items[0].type, 'not');
  assert.equal(g.items[0].item.type, 'or');
  const deep = ok('((a OR (b c)) -d) OR NOT (e)');
  assert.equal(deep.type, 'or');
  assert.equal(q.toQueryString(deep), '(a OR b c) -d OR -e');
  assert.equal(ok('NOT NOT a').item.type, 'not');
});

test('mixed-case words are text, not keywords', () => {
  const a = ok('And Or Not');
  assert.equal(a.type, 'and');
  assert.deepEqual(a.items.map((i) => i.values[0].text), ['And', 'Or', 'Not']);
});

test('quoted strings, escapes, alternatives, regex literals', () => {
  const qd = ok('reason:"TCP FIN"');
  assert.equal(qd.values[0].kind, 'quoted');
  assert.equal(qd.values[0].text, 'TCP FIN');
  assert.equal(ok("'single quoted'").values[0].text, 'single quoted');
  assert.equal(ok('"say \\"hi\\""').values[0].text, 'say "hi"');
  const alt = ok('app:junos-http|"junos https"|/ssh/i');
  assert.deepEqual(alt.values.map((v) => v.kind), ['word', 'quoted', 'regex']);
  assert.equal(alt.values[2].flags, 'i');
  const re = ok('tag:/RT_FLOW_SESSION_(CREATE|CLOSE)/');
  assert.equal(re.values[0].kind, 'regex');
  assert.equal(re.values[0].text, 'RT_FLOW_SESSION_(CREATE|CLOSE)');
  const spaced = ok('/session closed/ x');
  assert.equal(spaced.items[0].values[0].text, 'session closed');
  // A leading slash without a closing one is just a word.
  assert.equal(ok('/kernel:').values[0].kind, 'word');
});

test('addresses, URLs and times are never read as key:value', () => {
  for (const s of ['fe80::1', '2001:db8::/32', '12:30:01', '00:11:22:33:44:55', 'http://example.com/x', '10.0.0.0/8']) {
    const a = ok(s);
    assert.equal(a.key, null, s);
    assert.equal(a.values[0].text, s);
  }
});

test('with a view, an unknown key with no value is text ("UI_COMMIT:")', () => {
  const a = ok('UI_COMMIT: tcp_timer_keep:', 'logs');
  assert.deepEqual(a.items.map((i) => [i.key, i.values[0].text]), [[null, 'UI_COMMIT:'], [null, 'tcp_timer_keep:']]);
});

// --- errors ---------------------------------------------------------------------------------------

test('errors carry the position and an operator-friendly message', () => {
  const cases = [
    ['"unclosed', 0, /Unclosed quote/],
    ['dport:443 "x', 10, /Unclosed quote/],
    ['(dport:443', 0, /Missing '\)'/],
    ['dport:443)', 9, /Unexpected '\)'/],
    ['AND a', 0, /before AND/],
    ['a OR', 4, /after OR/],
    ['a AND', 5, /after AND/],
    ['src:', 4, /value after 'src:'/],
    ['src: 10.0.0.1', 4, /no space/],
    ['a - b', 2, /right before the term/],
    ['()', 0, /Empty parentheses/],
    ['!=443', 0, /needs a key/],
    ['app:a|', 5, /another value/],
    ['zone:(trust)', 5, /zone:a\|b/],
    ['NOT', 3, /after NOT/],
  ];
  for (const [text, pos, re] of cases) {
    const r = q.parse(text);
    assert.equal(r.ast, null, text);
    assert.ok(r.error, text);
    assert.equal(r.error.pos, pos, `${text}: ${r.error.message}`);
    assert.match(r.error.message, re, text);
  }
});

test('view validation: unknown keys (with a suggestion) and bad typed values', () => {
  const cases = [
    ['form:trust', 'sessions', 0, /Unknown key 'form'.*'from'/],
    ['dport:443 colour:red', 'sessions', 10, /Unknown key 'colour'/],
    ['dport:abc', 'sessions', 6, /whole number/],
    ['bytes>1X', 'sessions', 6, /size like/],
    ['dur>5x', 'sessions', 4, /duration like/],
    ['src:300.1.1.1', 'sessions', 4, /not an IP address/],
    ['src>10.0.0.1', 'sessions', 4, /prefix/],
    ['policy>abc', 'sessions', 7, /compares numbers/],
    ['tag:/(/', 'logs', 4, /Invalid regular expression/],
    ['sev>=loud', 'logs', 5, /Unknown value/],
    ['time>=yesterday', 'logs', 6, /time like/],
    ['dport>1024-2048', 'sessions', 6, /one number/],
  ];
  for (const [text, view, pos, re] of cases) {
    const r = q.parse(text, { view });
    assert.ok(r.error, text);
    assert.equal(r.error.pos, pos, `${text}: ${r.error.message}`);
    assert.match(r.error.message, re, text);
  }
  assert.equal(q.parse('dport:443', { view: 'sessions' }).error, null);
  assert.equal(q.parse('SRC:10.0.0.1', { view: 'sessions' }).error, null, 'keys are case-insensitive');
});

test('validate() reports the same errors for an already parsed tree', () => {
  const ast = ok('colour:red');
  const err = q.validate(ast, q.FIELDS.sessions);
  assert.equal(err.pos, 0);
  assert.match(err.message, /Unknown key/);
  assert.equal(q.validate(ok('dport:22'), q.FIELDS.sessions), null);
});

// --- printing, scanning, highlighting ---------------------------------------------------------------

test('toQueryString is canonical and round-trips', () => {
  const queries = [
    'dport:443 bytes>1M', 'src:10.10.0.0/16 -app:junos-dns-udp', '(a OR b) c', 'NOT (a b)', 'reason:"TCP FIN"',
    'tag:/RT_FLOW_(CREATE|CLOSE)/i', 'app:a|b|"c d"', 'x OR y OR z', '-(dport:53 OR dport:123)', 'src = 10.0.0.1 AND dport >= 22',
  ];
  for (const s of queries) {
    const once = q.toQueryString(ok(s));
    const twice = q.toQueryString(ok(once));
    assert.equal(twice, once, s);
    const a = q.compile(ok(s), q.FIELDS.sessions, { inventory: INVENTORY });
    const b = q.compile(ok(once), q.FIELDS.sessions, { inventory: INVENTORY });
    assert.deepEqual(ROWS.map(a), ROWS.map(b), s);
  }
  assert.equal(q.toQueryString(null), '');
  assert.equal(q.toQueryString(ok('"AND"')), '"AND"');
});

test('scan() is lossless and types every part, even after an error', () => {
  const queries = ['src:10.0.0.0/8 -app:dns|ntp "x y" (a OR b) /re/i dport >= 1', 'policy:"allow web" AND', 'dport:443 "open', '  spaced   out  ', ''];
  for (const s of queries) assert.equal(q.scan(s).map((t) => t.v).join(''), s, s);
  const types = q.scan('src:1.2.3.4 -x OR "y" /z/').map((t) => t.t);
  assert.deepEqual(types, ['key', 'op', 'val', 'ws', 'not', 'word', 'ws', 'kw', 'ws', 'str', 'ws', 're']);
  const err = q.scan('a "open');
  assert.equal(err[err.length - 1].t, 'err');
  assert.equal(err[err.length - 1].v, '"open');
});

test('highlightTerms returns positive values only', () => {
  assert.deepEqual(q.highlightTerms(ok('allow-web dport:443 -deny policy!=x bytes>1M "TCP FIN" /re/ pub*web src:10.0.0.0/8')).sort(), ['443', 'TCP FIN', 'allow-web', 'pub'].sort());
  assert.deepEqual(q.highlightTerms(null), []);
});

// --- typed matching --------------------------------------------------------------------------------

test('parseNet: addresses, prefixes, ranges, wildcards, IPv6', () => {
  assert.deepEqual(q.parseNet('10.10.0.0/16'), { v: 4, lo: 168427520, hi: 168493055 });
  assert.deepEqual(q.parseNet('10.10.3.4/16'), q.parseNet('10.10.0.0/16'), 'host bits are ignored');
  assert.deepEqual(q.parseNet('10.10.*'), q.parseNet('10.10.0.0/16'));
  assert.deepEqual(q.parseNet('10.*.*.*'), q.parseNet('10.0.0.0/8'));
  assert.equal(q.parseNet('10.10.40.10-10.10.40.19').hi - q.parseNet('10.10.40.10-10.10.40.19').lo, 9);
  assert.equal(q.parseNet('2001:db8::/32').v, 6);
  assert.equal(q.parseNet('::ffff:10.0.0.1').lo, 0xffff0a000001n);
  assert.equal(q.parseNet('[2001:db8::1]').lo, q.parseNet('2001:db8::1').lo);
  for (const bad of ['300.1.1.1', '10.0.0.0/33', '1.2.3', 'abc', '10.*.1.1', '2001:db8::1::2', '', '1:2:3']) assert.equal(q.parseNet(bad), null, bad);
});

test('CIDR-aware address matching (IPv4 and IPv6)', () => {
  assert.deepEqual(ids('src:10.10.0.0/16'), ['1', '2', '4']);
  assert.deepEqual(ids('src:10.10.0.11'), ['1']);
  assert.deepEqual(ids('src:10.10.*'), ['1', '2', '4']);
  assert.deepEqual(ids('src:10.10.0.10-10.10.0.12'), ['1', '2']);
  assert.deepEqual(ids('src!=10.0.0.0/8'), ['3', '5']);
  assert.deepEqual(ids('src:2001:db8::/32'), ['5']);
  assert.deepEqual(ids('dst:2001:db8:ff::80'), ['5']);
  assert.deepEqual(ids('natsrc:203.0.113.2'), ['1', '2']);
  assert.deepEqual(ids('natdst:10.20.0.0/24'), ['3']);
  // Free text that is an address matches whole addresses only (10.10.0.1 is not inside 10.10.0.11).
  assert.deepEqual(ids('10.10.0.1'), []);
  assert.deepEqual(ids('10.10.0.0/16'), ['1', '2', '4'], 'free-text prefix: any address in the row');
});

test('sizes, durations and integer comparisons', () => {
  // Decimal like Junos counters and format.bytes(); KiB/MiB/GiB are 1024-based when named.
  assert.equal(q.parseSize('1500'), 1500);
  assert.equal(q.parseSize('64k'), 64000);
  assert.equal(q.parseSize('1M'), 1000000);
  assert.equal(q.parseSize('1.5MB'), 1500000);
  assert.equal(q.parseSize('2G'), 2000000000);
  assert.equal(q.parseSize('10KiB'), 10240);
  assert.equal(q.parseSize('1MiB'), 1048576);
  assert.equal(q.parseSize('1Gi'), 1073741824);
  assert.equal(q.parseSize('1X'), null);
  assert.equal(q.parseSize('1iB'), null);
  // A session of 1,040,000 bytes reads "1.0 MB" in Sessions, so bytes>1M must keep it.
  const mb = [session(9, 'allow-web', wingIn('10.10.0.9', 40009, '198.51.100.20', 443, 'tcp', 'ge-0/0/1.0', 40_000, 10), wingIn('198.51.100.20', 443, '203.0.113.2', 50009, 'tcp', 'ge-0/0/0.0', 1_000_000, 700))];
  assert.deepEqual(ids('bytes>1M', 'sessions', mb), ['9']);
  assert.deepEqual(ids('bytes>1MiB', 'sessions', mb), []);
  assert.equal(q.parseDuration('30'), 30);
  assert.equal(q.parseDuration('5m'), 300);
  assert.equal(q.parseDuration('1h30m'), 5400);
  assert.equal(q.parseDuration('2d'), 172800);
  assert.equal(q.parseDuration('250ms'), 0.25);
  assert.equal(q.parseDuration('5x'), null);
  assert.deepEqual(ids('bytes>1M'), ['1', '4']);
  assert.deepEqual(ids('bytes<=1k'), ['2']);
  assert.deepEqual(ids('dur>5m'), ['1', '4']);
  assert.deepEqual(ids('dur<10s'), ['2', '5']);
  assert.deepEqual(ids('dport>=443 dport<=1024'), ['1', '3']);
  assert.deepEqual(ids('dport>443'), []);
  assert.deepEqual(ids('dport<53'), ['4']);
  assert.deepEqual(ids('dport:20-60'), ['2', '4']);
  assert.deepEqual(ids('pkts>1000'), ['1', '4']);
  assert.deepEqual(ids('rate>1k', 'sessions', ROWS.map((r, i) => ({ ...r, rate: i * 1000 }))), ['3', '4', '5']);
});

test('text, enum, wildcard, regex and protocol matching', () => {
  assert.deepEqual(ids('policy:allow-web'), ['1', '5']);
  assert.deepEqual(ids('policy:ALLOW-WEB'), ['1', '5'], 'case-insensitive');
  assert.deepEqual(ids('policy:allow-*'), ['1', '5']);
  assert.deepEqual(ids('policy:*web'), ['1', '3', '5']);
  assert.deepEqual(ids('policy~^pub'), ['3']);
  assert.deepEqual(ids('policy:/^(admin|publish)-/'), ['3', '4']);
  assert.deepEqual(ids('proto:udp'), ['2']);
  assert.deepEqual(ids('proto:17'), ['2']);
  assert.deepEqual(ids('proto:tcp|udp'), ['1', '2', '3', '4', '5']);
  assert.deepEqual(ids('iface:ge-0/0/2.0'), ['3', '4']);
  assert.deepEqual(ids('egress:ge-0/0/2.0'), ['3', '4']);
  assert.deepEqual(ids('nat:dst'), ['3']);
  assert.deepEqual(ids('nat:src'), ['1', '2']);
  assert.deepEqual(ids('nat:none'), ['4', '5']);
  assert.deepEqual(ids('id:4'), ['4']);
  assert.deepEqual(ids('state:valid'), ['1', '2', '3', '4', '5']);
  assert.deepEqual(ids('-policy:allow-web -dport:22'), ['2', '3']);
  assert.deepEqual(ids('NOT (policy:allow-web OR dport:22)'), ['2', '3']);
  assert.deepEqual(ids('dport:443 OR dport:22'), ['1', '3', '4']);
});

test('zones for sessions come from the policy -> zone map (inventory or policyIndex)', () => {
  assert.deepEqual(ids('zone:dmz'), ['3', '4']);
  assert.deepEqual(ids('from:trust to:untrust'), ['1', '2', '5']);
  const idx = new Map([['allow-web', { from: ['inside'], to: ['outside'] }]]);
  assert.deepEqual(ids('from:inside', 'sessions', ROWS, { policyIndex: idx }), ['1', '5']);
  assert.deepEqual(ids('zone:dmz', 'sessions', ROWS, {}), [], 'no inventory: zones unknown, nothing matches');
});

test('free text searches the whole row, case-insensitively', () => {
  assert.deepEqual(ids('ALLOW'), ['1', '5']);
  assert.deepEqual(ids('"ge-0/0/2.0"'), ['3', '4']);
  assert.deepEqual(ids('allow publish'), []);
  assert.deepEqual(ids('allow OR publish'), ['1', '3', '5']);
});

test('compile never throws and treats unknown keys as text', () => {
  const f = q.compile(ok('colour:red'), q.FIELDS.sessions);
  assert.equal(ROWS.some(f), false);
  assert.equal(q.compile(null, q.FIELDS.sessions)(ROWS[0]), true);
  assert.equal(q.compile(ok('dport:abc'), q.FIELDS.sessions)(ROWS[0]), false);
  assert.equal(q.compile(ok('dport:443'), 'sessions')(ROWS[0]), true, 'a view name works as fields');
});

test('policies: names, CIDR-aware resolved addresses, ports, flags', () => {
  const P = INVENTORY.scope.policies.rows;
  const names = (s) => ids(s, 'policies', P, {});
  assert.deepEqual(names('action:deny'), ['block-telnet', 'global-blocklist']);
  assert.deepEqual(names('src:corp-lan'), ['baseline-dns', 'allow-web', 'admin-to-dmz']);
  assert.deepEqual(names('src:10.10.40.15 -src:any'), ['baseline-dns', 'allow-web', 'admin-to-dmz', 'global-printers']);
  // publish-web stays: its web-servers set holds a DNS name, which an address cannot be compared with
  assert.deepEqual(names('addr:10.20.0.50 -dst:any'), ['admin-to-dmz', 'publish-web']);
  // application any covers every port, and a port J-Wicket cannot read keeps the policy (see below)
  assert.deepEqual(names('port:8443'), ['allow-web', 'block-telnet', 'global-printers', 'global-blocklist']);
  assert.deepEqual(names('port:22 -app:any'), ['admin-to-dmz', 'global-printers']);
  assert.deepEqual(names('port:443 -app:any'), ['allow-web', 'publish-web', 'global-printers']);
  assert.deepEqual(names('inactive:yes'), ['block-telnet']);
  assert.deepEqual(names('log:init'), ['admin-to-dmz']);
  assert.deepEqual(names('log:none'), ['baseline-dns', 'publish-web', 'block-telnet', 'global-printers', 'global-blocklist']);
  assert.deepEqual(names('count:yes'), ['allow-web']);
  assert.deepEqual(names('kind:global'), ['global-printers', 'global-blocklist']);
  assert.deepEqual(names('from:any'), ['global-blocklist']);
  assert.deepEqual(names('group:corp-baseline'), ['baseline-dns', 'global-printers']);
  assert.deepEqual(names('app:junos-https'), ['allow-web', 'publish-web']);
  assert.deepEqual(names('zone:dmz action:permit'), ['admin-to-dmz', 'publish-web', 'global-printers']);
});

test('policies: application any matches every port, unknown ports are kept and reported', () => {
  const P = INVENTORY.scope.policies.rows;
  const tri = (s) => {
    const f = q.compileTri(ok(s, 'policies'), q.FIELDS.policies, {});
    return P.map((r) => [r.name, f(r)]).filter(([, v]) => v !== false).map(([n, v]) => (v === null ? `${n}?` : n));
  };
  // "what handles a flow to port 3389": the permit-all style rules are not hidden
  assert.deepEqual(tri('port=3389'), ['block-telnet', 'global-printers?', 'global-blocklist']);
  assert.deepEqual(tri('port:3389 action:deny'), ['block-telnet', 'global-blocklist']);
  // port and port!= agree: any never fails "=", always fails "!="; unknown stays unknown both ways
  assert.deepEqual(tri('port!=3389'), ['baseline-dns', 'allow-web', 'admin-to-dmz', 'publish-web', 'global-printers?']);
  assert.deepEqual(tri('-port:443'), ['baseline-dns', 'admin-to-dmz', 'global-printers?']);
  assert.deepEqual(tri('port>=8000'), ['allow-web', 'block-telnet', 'global-printers?', 'global-blocklist']);
  assert.deepEqual(tri('port:443'), ['allow-web', 'publish-web', 'block-telnet', 'global-printers?', 'global-blocklist']);
  // strictAny: the view's second pass, to say how many rows matched only through application any
  const strict = q.compileTri(ok('port:3389', 'policies'), q.FIELDS.policies, { strictAny: true });
  assert.deepEqual(P.filter((r) => strict(r) !== false).map((r) => r.name), ['global-printers']);
  // compile() keeps unknown rows
  assert.deepEqual(ids('port:3389', 'policies', P, {}), ['block-telnet', 'global-printers', 'global-blocklist']);
  const ports = q.policyPorts(P.find((r) => r.name === 'allow-web'));
  assert.deepEqual(ports.pairs.map((x) => `${x.port}/${x.protocol} ${x.name}`), ['443/tcp junos-https', '8443/tcp tcp-8443']);
  assert.equal(ports.any, false);
  assert.deepEqual(q.policyPorts(P.find((r) => r.name === 'global-printers')).unknown.map((x) => x.name), ['junos-ipp']);
  const named = { resolved: { application: [{ name: 'web', kind: 'application', leaves: [{ name: 'web', protocol: 'tcp', destination_port: 'https' }] }, { name: 'ping', kind: 'application', leaves: [{ name: 'ping', protocol: 'icmp' }] }, { name: 'odd', kind: 'application', leaves: [{ name: 'odd', protocol: 'tcp', destination_port: 'kerberos-sec' }] }] } };
  assert.deepEqual(q.policyPorts(named).pairs.map((x) => x.port), ['443']);
  assert.deepEqual(q.policyPorts(named).unknown.map((x) => x.name), ['odd']);
});

test('policies: an address cannot be compared with a DNS name; wildcards match prefixes as in Sessions', () => {
  const P = INVENTORY.scope.policies.rows;
  const tri = (s) => {
    const f = q.compileTri(ok(s, 'policies'), q.FIELDS.policies, {});
    return P.map((r) => [r.name, f(r)]).filter(([, v]) => v !== false).map(([n, v]) => (v === null ? `${n}?` : n));
  };
  // web-servers holds a DNS name: an address query cannot rule it out
  assert.deepEqual(tri('dst:10.20.0.99 -dst:any'), ['publish-web?']);
  assert.deepEqual(tri('dst:10.20.0.11 -dst:any'), ['publish-web']);
  assert.deepEqual(tri('dst:web-servers'), ['publish-web'], 'names are known: no unknown');
  // 10.10.0.1* holds 10.10.0.1, 10.10.0.10-19 and 10.10.0.100-199: inside corp-lan (10.10.0.0/16)
  assert.deepEqual(tri('src:10.10.0.1* -src:any'), ['baseline-dns', 'allow-web', 'admin-to-dmz']);
  // branch-printers is 10.10.40.10-10.10.40.19
  assert.deepEqual(tri('src:10.10.40.1* -src:corp-lan -src:any'), ['global-printers']);
  assert.deepEqual(tri('src:10.10.40.2* -src:corp-lan -src:any'), []);
  // the same wildcard over single addresses in Sessions
  assert.deepEqual(ids('src:10.10.0.1*'), ['1', '2']);
  assert.deepEqual(ids('src:10.10.0.2*'), ['4']);
});

test('wildcards and regular expressions stay fast on long text', () => {
  const g = q.globMatcher('x*x*x*x*y', false);
  const line = 'x'.repeat(400);
  const t0 = Date.now();
  for (let i = 0; i < 2000; i++) assert.equal(g(line), false);
  assert.ok(Date.now() - t0 < 500, 'linear-time wildcard');
  assert.equal(q.globMatcher('RT_FLOW*CLOSE*443', false)('rt_flow_session_close ... 10.20.0.11/443'), true);
  assert.equal(q.globMatcher('ab*cd', true)('abXcd'), true);
  assert.equal(q.globMatcher('ab*cd', true)('abcdX'), false);
  assert.equal(q.globMatcher('a*a', true)('a'), false, 'prefix and suffix cannot overlap');
  assert.equal(q.globMatcher('*', true)(''), true);
  const lines = Array.from({ length: 50 }, (_, i) => ({ line: `${'a'.repeat(577)} ${i}`, fields: {} }));
  const f = q.compile(ok('a*a*a*a*q', 'logs'), q.FIELDS.logs, {});
  const t1 = Date.now();
  assert.deepEqual(lines.filter(f), []);
  assert.ok(Date.now() - t1 < 500, 'no backtracking on 577-character lines');
  assert.ok(q.REGEX_INPUT_MAX >= 1024);
});

test('filterTimed stops at the budget and says so', () => {
  let t = 0;
  const clock = () => t;
  const rows = Array.from({ length: 1000 }, (_, i) => i);
  const res = q.filterTimed(rows, (r) => { t += 1; return r % 2 === 0; }, 200, clock);
  assert.equal(res.complete, false);
  assert.ok(res.checked < 1000 && res.checked >= 200);
  const all = q.filterTimed(rows, (r) => r < 3, 200, () => 0);
  assert.deepEqual(all.rows, [0, 1, 2]);
  assert.equal(all.complete, true);
  assert.equal(all.checked, 1000);
});

test('logs fields over parsed lines: severity order, NAT, time and age', () => {
  const lines = [
    '<14>1 2026-11-24T07:40:00.000Z fw RT_FLOW - RT_FLOW_SESSION_CLOSE [junos@2636.1.1.1.2.129 reason="TCP FIN" source-address="10.10.0.12" source-port="1255" destination-address="198.51.100.20" destination-port="443" nat-source-address="203.0.113.2" nat-source-port="46702" nat-destination-address="198.51.100.20" nat-destination-port="443" protocol-id="6" policy-name="allow-web" source-zone-name="trust" destination-zone-name="untrust" session-id="9001" bytes-from-client="2000" bytes-from-server="3000000" elapsed-time="400"]',
    '<11>1 2026-11-24T07:45:00.000Z fw RT_LOG - RT_SCREEN_TCP [attack-name="SYN flood" source-address="198.51.100.7" source-zone-name="untrust"]',
    'Nov 24 07:50:00 fw mgd[1]: UI_COMMIT_COMPLETED: commit complete',
    'Nov 24 07:55:00 fw RT_FLOW: RT_FLOW_SESSION_DENY: session denied 198.51.100.66/10239->203.0.113.2/22 0x0 junos-ssh 6(0) deny-inbound untrust trust UNKNOWN UNKNOWN N/A(N/A) ge-0/0/0.0 No policy deny',
  ];
  const now = Date.parse('2026-11-24T08:00:00Z');
  const rows = lines.map((l) => lp.parse(l, { now }));
  const m = (s) => {
    const f = q.compile(ok(s, 'logs'), q.FIELDS.logs, { now });
    return rows.map((r, i) => (f(r) ? i : -1)).filter((i) => i >= 0);
  };
  assert.deepEqual(m('sev>=warning'), [1, 2]);
  assert.deepEqual(m('sev:error'), [1]);
  assert.deepEqual(m('sev<=info'), [0, 3]);
  assert.deepEqual(m('nat:src'), [0]);
  assert.deepEqual(m('nat:none'), []);
  assert.deepEqual(m('family:deny'), [3]);
  assert.deepEqual(m('family:close OR family:screen'), [0, 1]);
  assert.deepEqual(m('time>=2026-11-24T07:45 time<2026-11-24T07:55'), [1, 2]);
  assert.deepEqual(m('time:07:50'), [2]);
  assert.deepEqual(m('age<12m'), [2, 3]);
  assert.deepEqual(m('bytes>1M dur>5m'), [0]);
  assert.deepEqual(m('zone:untrust'), [0, 1, 3]);
  assert.deepEqual(m('from:untrust to:trust dport:22 proto:tcp'), [3]);
  assert.deepEqual(m('session:9001'), [0]);
  assert.deepEqual(m('reason:"policy deny"'), [3]);
  assert.deepEqual(m('msg:"commit complete"'), [2]);
  assert.deepEqual(m('src:198.51.100.0/24'), [1, 3]);
  assert.deepEqual(m('198.51.100.20'), [0]);
  assert.deepEqual(m('ip:203.0.113.2'), [3]);
});

// --- planner --------------------------------------------------------------------------------------

test('sessions pushdown: positive top-level AND-ed ":"/"=" terms on device keys', () => {
  // app: only an application-protocol type of the RPC's application enumeration goes to the device (S-7), lower-cased.
  const p = q.plan(ok('dport:443 src=10.10.0.0/16 proto:TCP app:HTTPS iface:ge-0/0/1.0 sport:40001 dst:198.51.100.20 policy:allow-web bytes>1M'), 'sessions');
  assert.deepEqual(p.device, { dport: '443', src: '10.10.0.0/16', proto: 'tcp', app: 'https', iface: 'ge-0/0/1.0', sport: '40001', dst: '198.51.100.20' });
  assert.equal(q.toQueryString(p.browser), 'policy:allow-web bytes>1M');
  assert.deepEqual(p.explain.map((e) => e.where), ['device', 'device', 'device', 'device', 'device', 'device', 'device', 'browser', 'browser']);
  assert.equal(q.explainText(q.plan(ok('dport:443 policy:allow-web bytes>1M'), 'sessions')), 'Device filtered: dport:443 · Browser filtered: policy:allow-web, bytes>1M');
});

test('sessions pushdown keeps negations, ORs, alternatives, wildcards, ranges and bad values in the browser', () => {
  const cases = ['-dport:443', 'dport!=443', 'dport:443 OR dport:80', 'dport:443|80', 'src:10.10.*', 'dport:1-1024', 'dport>1024',
    'iface:GE-0/0/1.0', 'app:"two words"', 'app:/re/', 'NOT (dport:22)', 'src:10.0.0.1-10.0.0.9', 'app:junos-https', 'dport:0'];
  for (const s of cases) {
    const p = q.plan(ok(s), 'sessions');
    assert.deepEqual(p.device, {}, s);
    assert.ok(p.browser, s);
    assert.ok(p.explain.every((e) => e.where === 'browser'), s);
  }
  const dup = q.plan(ok('dport:443 dport:80'), 'sessions');
  assert.deepEqual(dup.device, { dport: '443' }, 'one value per device parameter');
  assert.equal(q.toQueryString(dup.browser), 'dport:80');
  const all = q.plan(ok('dport:443 (src:10.0.0.0/8)'), 'sessions');
  assert.equal(all.browser, null);
  assert.deepEqual(all.device, { dport: '443', src: '10.0.0.0/8' });
  assert.deepEqual(q.plan(null, 'sessions'), { view: 'sessions', source: null, device: {}, browser: null, explain: [] });
});

test('explain items carry the source span of each top-level term', () => {
  const text = 'dport:443  (a OR b) -c';
  const p = q.plan(ok(text), 'sessions');
  assert.deepEqual(p.explain.map((e) => text.slice(e.pos, e.end)), ['dport:443', '(a OR b)', '-c']);
});

test('logs file pushdown: contains / exclude, at most 4 terms of 120 characters', () => {
  const p = q.plan(ok('denied "session closed" -ssh -"UI_NETCONF_CMD" policy:allow-web 10.10.0.20 tag:/X/'), 'logs');
  assert.equal(p.source, 'file');
  assert.deepEqual(p.terms.contains, ['denied', 'session closed', '10.10.0.20', 'allow-web']);
  assert.deepEqual(p.terms.exclude, ['ssh', 'UI_NETCONF_CMD']);
  assert.equal(p.device.contains, 'denied\nsession closed\n10.10.0.20\nallow-web');
  assert.equal(p.device.exclude, 'ssh\nUI_NETCONF_CMD');
  // Exact free text leaves the browser; address and field hints are re-checked in the browser.
  assert.equal(q.toQueryString(p.browser), 'policy:allow-web 10.10.0.20 tag:/X/');
  const refine = p.explain.filter((e) => e.refine).map((e) => e.text);
  assert.deepEqual(refine, ['policy:allow-web', '10.10.0.20']);
  const five = q.plan(ok('a b c d e -f -g -h -i -j'), 'logs:file');
  assert.deepEqual(five.terms.contains, ['a', 'b', 'c', 'd']);
  assert.deepEqual(five.terms.exclude, ['f', 'g', 'h', 'i']);
  assert.equal(q.toQueryString(five.browser), 'e -j');
  const long = 'x'.repeat(121);
  const lp1 = q.plan(ok(`${long} ok`), 'logs');
  assert.deepEqual(lp1.terms.contains, ['ok']);
  assert.equal(q.toQueryString(lp1.browser), long);
  for (const s of ['a OR b', 'a|b', 'den*', '/re/', '-10.0.0.1', 'proto:tcp', 'family:deny', 'src:10.0.0.0/8', 'policy:allow-*', 'NOT (a b)']) {
    const p2 = q.plan(ok(s), 'logs');
    assert.equal(p2.device.contains, undefined, s);
    assert.equal(p2.device.exclude, undefined, s);
  }
});

test('logs report pushdown: the J-Web expression syntax', () => {
  const ex = (s) => q.plan(ok(s), 'logs:report').expression;
  assert.equal(ex('src:192.0.3.2/24 (session:785 OR session:786)'), 'source-address=192.0.3.2/24 && (session-id=785 || session-id=786)');
  assert.equal(ex('policy:allow-web -dport:53'), 'policy-name=allow-web && destination-port!=53');
  assert.equal(ex('dport>=1024 sport<=1023'), 'destination-port>=1024 && source-port<=1023');
  assert.equal(ex('dport>1023'), 'destination-port>=1024');
  assert.equal(ex('dport<1024'), 'destination-port<=1023');
  assert.equal(ex('NOT dport>=1024'), 'destination-port<=1023');
  assert.equal(ex('proto:tcp'), 'protocol-id=6');
  assert.equal(ex('proto:udp|17'), 'protocol-id=17 || protocol-id=17');
  assert.equal(ex('zone:dmz'), 'source-zone-name=dmz || destination-zone-name=dmz');
  assert.equal(ex('zone!=dmz'), 'source-zone-name!=dmz && destination-zone-name!=dmz');
  assert.equal(ex('from:untrust to:trust user:admin app:HTTP reason:CLI'), 'source-zone-name=untrust && destination-zone-name=trust && username=admin && application=HTTP && reason=CLI');
  assert.equal(ex('-(policy:a OR policy:b)'), 'policy-name!=a && policy-name!=b');
  assert.equal(ex('-(policy:a OR policy:b) dport:22'), '(policy-name!=a && policy-name!=b) && destination-port=22');
  assert.equal(ex('app:a|b'), 'application=a || application=b');
  assert.equal(ex('-app:a|b'), 'application!=a && application!=b');
  assert.equal(ex('-app:a|b src:10.0.0.1'), '(application!=a && application!=b) && source-address=10.0.0.1');
  assert.equal(ex('policy:a OR dport:22'), 'policy-name=a || destination-port=22');
  // Not expressible: regex, wildcards, values with spaces, keys the report lacks, free text.
  for (const s of ['tag:/RT/', 'policy:allow-*', 'reason:"TCP FIN"', 'family:deny', 'denied', 'bytes>1M', 'src:10.10.*', 'policy~x', 'dport<0']) {
    const p = q.plan(ok(s), 'logs:report');
    assert.equal(p.expression, undefined, s);
    assert.ok(p.browser, s);
  }
  const mixed = q.plan(ok('family:deny src:10.0.0.0/8 denied dport:22'), 'logs:report');
  assert.equal(mixed.expression, 'source-address=10.0.0.0/8 && destination-port=22');
  assert.equal(mixed.device.expression, mixed.expression);
  assert.equal(q.toQueryString(mixed.browser), 'family:deny denied');
  assert.match(mixed.expression, /^[A-Za-z0-9_.:/=!<>&|() -]+$/);
});

test('logs report pushdown falls back to the largest AND-prefix within 256 bytes', () => {
  const terms = Array.from({ length: 12 }, (_, i) => `src:10.${i}.0.0/16|10.${i}.1.0/24`);
  const p = q.plan(ok(`${terms.join(' ')} denied`), 'logs:report');
  const expr = p.expression;
  assert.ok(Buffer.byteLength(expr) <= 256, `${Buffer.byteLength(expr)} bytes`);
  const pushed = p.explain.filter((e) => e.where === 'device').map((e) => e.text);
  assert.deepEqual(pushed, terms.slice(0, pushed.length), 'a prefix of the AND-ed terms');
  // The next term would not have fitted.
  const next = `(source-address=10.${pushed.length}.0.0/16 || source-address=10.${pushed.length}.1.0/24)`;
  assert.ok(Buffer.byteLength(`${expr} && ${next}`) > 256);
  assert.equal(q.toQueryString(p.browser), [...terms.slice(pushed.length), 'denied'].join(' '));
  // Exactly at the limit is allowed.
  const value = 'a'.repeat(256 - 'policy-name='.length);
  assert.equal(q.plan(ok(`policy:${value}`), 'logs:report').expression.length, 256);
  assert.equal(q.plan(ok(`policy:${value}a`), 'logs:report').expression, undefined);
});

test('time terms set report start/stop and the buffer "since", and stay in the browser', () => {
  const r = q.plan(ok('time>=2026-11-24T07:50 time<=2026-11-24T07:55 policy:x'), 'logs:report');
  assert.equal(r.device.start, '2026-11-24T07:50:00');
  assert.equal(r.device.stop, '2026-11-24T07:55:59');
  assert.equal(r.device.expression, 'policy-name=x');
  assert.equal(q.toQueryString(r.browser), 'time>=2026-11-24T07:50 time<=2026-11-24T07:55');
  const b = q.plan(ok('time>=2026-11-24T07:50:00Z family:deny'), 'logs', { source: 'buffer' });
  assert.equal(b.source, 'buffer');
  assert.deepEqual(b.device, { since: '2026-11-24.07:49:59' });
  assert.equal(q.toQueryString(b.browser), 'time>=2026-11-24T07:50:00Z family:deny');
});

test('policies have no device filtering', () => {
  const p = q.plan(ok('action:deny zone:dmz'), 'policies');
  assert.deepEqual(p.device, {});
  assert.ok(p.explain.every((e) => e.where === 'browser'));
});

// --- autocomplete ---------------------------------------------------------------------------------

test('suggest: keys, aliases, operators, values, examples, keywords', () => {
  const ctx = { view: 'sessions', rows: ROWS, inventory: INVENTORY };
  const labels = (s, at = s.length, c = ctx) => q.suggest(s, at, c).map((x) => x.insert);
  assert.deepEqual(labels(''), q.examples('sessions'));
  assert.ok(labels('dp').includes('dport:'));
  assert.ok(labels('pol').includes('policy:'), 'alias prefix offers the key');
  assert.deepEqual(labels('dport').slice(0, 3), ['dport:', 'dport>=', 'dport<=']);
  const pv = q.suggest('policy:al', 9, ctx);
  assert.equal(pv[0].insert, 'policy:allow-web');
  assert.equal(pv[0].from, 0);
  assert.equal(pv[0].to, 9);
  assert.ok(labels('zone:').includes('zone:dmz'));
  assert.ok(labels('iface:ge-0/0/2').includes('iface:ge-0/0/2.0'));
  assert.ok(labels('app:junos-http|').includes('app:junos-http|tcp-8443'), 'alternatives keep the earlier values');
  assert.ok(labels('admin').includes('policy:admin-to-dmz'), 'free text offers matching values');
  assert.ok(labels('dport:443 O').includes('OR'));
  const neg = q.suggest('dport:22 -pol', 13, ctx);
  assert.equal(neg[0].from, 10, 'the "-" stays in place');
  assert.deepEqual(q.suggest('colour:', 7, ctx), []);
  const mid = q.suggest('policy:al dport:22', 9, ctx)[0];
  assert.equal(mid.to, 9);
  const ex = q.suggest('bytes>', 6, ctx);
  assert.equal(ex[0].insert, 'bytes>1M');
  const logs = q.suggest('fam', 3, { view: 'logs' }).map((x) => x.insert);
  assert.ok(logs.includes('family:'));
  assert.ok(q.suggest('family:d', 8, { view: 'logs' }).map((x) => x.insert).includes('family:deny'));
  assert.ok(q.suggest('sev:w', 5, { view: 'logs' }).map((x) => x.insert).includes('sev:warning'));
  assert.deepEqual(q.suggest('x', 1, { view: 'nope' }), []);
  // After a space nothing is offered until asked for (ArrowDown sets `all`).
  assert.deepEqual(q.suggest('dport:443 ', 10, ctx), []);
  const all = q.suggest('dport:443 ', 10, { ...ctx, all: true });
  assert.ok(all.length >= 10 && all.every((x) => x.kind === 'key' && x.from === 10));
});

test('FIELDS cover each view with typed keys and getters', () => {
  const types = new Set(['ip', 'int', 'size', 'duration', 'text', 'enum', 'time']);
  for (const view of ['sessions', 'logs', 'policies']) {
    const f = q.FIELDS[view];
    assert.ok(Object.keys(f).length > 10, view);
    for (const [k, d] of Object.entries(f)) {
      assert.ok(types.has(d.type), `${view}.${k}`);
      assert.equal(typeof d.get, 'function', `${view}.${k}`);
      assert.ok(Array.isArray(d.aliases), `${view}.${k}`);
    }
  }
  for (const k of ['src', 'dst', 'sport', 'dport', 'proto', 'app', 'iface', 'policy', 'zone', 'from', 'to', 'nat', 'bytes', 'pkts', 'rate', 'dur', 'timeout', 'state', 'id', 'node']) assert.ok(q.FIELDS.sessions[k], `sessions.${k}`);
  for (const k of ['tag', 'daemon', 'host', 'sev', 'src', 'dst', 'sport', 'dport', 'proto', 'policy', 'zone', 'from', 'to', 'app', 'reason', 'user', 'iface', 'session']) assert.ok(q.FIELDS.logs[k], `logs.${k}`);
  for (const k of ['name', 'from', 'to', 'zone', 'src', 'dst', 'app', 'action', 'group', 'inactive', 'addr', 'log', 'count']) assert.ok(q.FIELDS.policies[k], `policies.${k}`);
  assert.ok(q.parse('event:X', { view: 'logs' }).ast, 'tag alias "event"');
  assert.ok(q.describe('sessions').find((d) => d.key === 'dport').device);
});

// --- UI-19 SHARED: session planner, cluster copies, policy keys, regex refusal (S-6 to S-11) ---------

test('sessions planner: the 14 protocol keywords, icmpv6, and numbers 0..255 go to the device', () => {
  assert.deepEqual([...q.SESSION_PROTOCOLS], ['ah', 'egp', 'esp', 'gre', 'icmp', 'icmp6', 'igmp', 'ipip', 'ospf', 'pim', 'rsvp', 'sctp', 'tcp', 'udp']);
  assert.ok(Object.isFrozen(q.SESSION_PROTOCOLS));
  for (const p of q.SESSION_PROTOCOLS) {
    assert.deepEqual(q.plan(ok(`proto:${p}`, 'sessions'), 'sessions').device, { proto: p }, p);
    assert.deepEqual(q.plan(ok(`proto:${p.toUpperCase()}`, 'sessions'), 'sessions').device, { proto: p }, p.toUpperCase());
  }
  assert.deepEqual(q.plan(ok('proto:ICMPV6', 'sessions'), 'sessions').device, { proto: 'icmp6' });
  assert.deepEqual(q.plan(ok('proto:17', 'sessions'), 'sessions').device, { proto: '17' });
  assert.deepEqual(q.plan(ok('proto:255', 'sessions'), 'sessions').device, { proto: '255' });
  assert.deepEqual(q.plan(ok('proto:017', 'sessions'), 'sessions').device, { proto: '17' }, 'normalised');
  for (const s of ['proto:256', 'proto:foo', 'proto:1000']) {
    const p = q.plan(ok(s), 'sessions');
    assert.deepEqual(p.device, {}, s);
    assert.equal(p.explain[0].where, 'browser', s);
  }
  assert.deepEqual(q.FIELDS.sessions.proto.values([]).slice().sort(), [...q.SESSION_PROTOCOLS].sort());
});

test('sessions planner: app only for application-protocol types, ports 1..65535', () => {
  assert.equal(q.SESSION_APPS.length, 24);
  assert.ok(Object.isFrozen(q.SESSION_APPS));
  for (const a of ['dns', 'ftp', 'ignore', 'mgcp-ca', 'mgcp-ua', 'ms-rpc', 'pptp', 'sun-rpc', 'q931', 'ras', 'realaudio', 'rsh', 'rtsp', 'sccp', 'sip', 'sqlnet-v2', 'talk', 'tftp', 'http', 'https', 'smtp', 'imap', 'ssh', 'telnet']) {
    assert.ok(q.SESSION_APPS.includes(a), a);
  }
  assert.deepEqual(q.plan(ok('app:https'), 'sessions').device, { app: 'https' });
  assert.deepEqual(q.plan(ok('app:DNS'), 'sessions').device, { app: 'dns' }, 'sent lower-case');
  for (const s of ['app:junos-https', 'app:HTTP2', 'app:junos-dns-udp', 'dport:0', 'sport:0', 'dport:65536', 'dport:00000']) {
    const p = q.plan(ok(s), 'sessions');
    assert.deepEqual(p.device, {}, s);
    assert.equal(p.explain[0].where, 'browser', s);
  }
  assert.deepEqual(q.plan(ok('dport:1 sport:65535'), 'sessions').device, { dport: '1', sport: '65535' });
  // JUNOS-03: the sources call these application protocol types, not ALG types.
  assert.equal(q.FIELDS.sessions.app.label, 'application (device filter: application protocol types such as https, ftp, dns, the RPC\u2019s own list; other names filter in the browser)');
});

test('protoNames: IANA numbers for egp and rsvp; ipip has none', () => {
  assert.ok(q.protoNames('rsvp').includes('46'));
  assert.ok(q.protoNames('8').includes('egp'));
  assert.deepEqual(q.protoNames('egp'), ['egp', '8']);
  assert.deepEqual(q.protoNames('46'), ['rsvp', '46']);
  assert.deepEqual(q.protoNames('ipip'), ['ipip']);
  assert.deepEqual(q.protoNames('4'), ['4']);
  assert.deepEqual(q.protoNames('TCP'), ['tcp', '6']);
  assert.deepEqual(q.protoNames('icmpv6'), ['icmpv6', '58', 'icmp6']);
  assert.deepEqual(q.protoNames(''), []);
  assert.deepEqual(q.protoNames(null), []);
});

test('plan browserOnly: listed keys stay in the browser, and the explain sentence says why', () => {
  const p = q.plan(ok('app:https dport:443 policy:allow-web'), 'sessions', { browserOnly: ['app'] });
  assert.deepEqual(p.device, { dport: '443' });
  assert.equal(q.toQueryString(p.browser), 'app:https policy:allow-web');
  assert.deepEqual(p.explain.map((e) => e.where), ['browser', 'device', 'browser']);
  assert.equal(p.explain[0].note, 'app:https is kept in the browser: the device did not accept it as a filter');
  assert.equal(p.explain[2].note, undefined, 'only terms the device would have taken');
  assert.equal(q.explainText(p), 'Device filtered: dport:443 · Browser filtered: app:https, policy:allow-web · app:https is kept in the browser: the device did not accept it as a filter');
  // Aliases name the same key; several keys at once.
  const all = q.plan(ok('application:dns src:10.0.0.0/8 dport:53'), 'sessions', { browserOnly: ['application', 'src', 'dport'] });
  assert.deepEqual(all.device, {});
  assert.equal(all.explain.filter((e) => e.note).length, 3);
  // Without browserOnly, unchanged.
  assert.deepEqual(q.plan(ok('app:https'), 'sessions').device, { app: 'https' });
});

const node0 = (id, extra = {}) => ({ id: `node0:${id}`, session_id: String(id), location: 'node0', state: null, status: null, extra: {}, in: { bytes: 100, packets: 2 }, out: { bytes: 900, packets: 3 }, ...extra });
const node1 = (id, extra = {}) => ({ ...node0(id, extra), id: `node1:${id}`, location: 'node1', in: { bytes: 0, packets: 0 }, out: { bytes: 0, packets: 0 }, ...extra });

test('sessionRole: state, status, then role-like extra keys', () => {
  assert.equal(q.sessionRole({ state: 'Backup' }), 'backup');
  assert.equal(q.sessionRole({ status: ' Active ' }), 'active');
  assert.equal(q.sessionRole({ state: 'Valid', extra: { 'ha-state': 'Stand-alone' } }), 'standalone');
  assert.equal(q.sessionRole({ extra: { role: 'warm' } }), 'warm');
  assert.equal(q.sessionRole({ state: 'Valid', status: 'Normal', extra: { 'session-flag': '0x40' } }), null);
  assert.equal(q.sessionRole({ extra: { colour: 'backup' } }), null, 'only state, role, ha or status keys');
  assert.equal(q.sessionRole(null), null);
});

test('sessionCopies: the device marks Backup, or zero counters beside traffic (inferred)', () => {
  // A pair without roles: node1 has zero counters.
  let c = q.sessionCopies([node0(1), node1(1)]);
  assert.deepEqual([...c.backups], ['node1:1']);
  assert.equal(c.why.get('node1:1'), 'inferred: the same session on another node, with zero counters');
  assert.equal(c.groups, 1);
  // A pair with roles: the device decides, counters do not.
  c = q.sessionCopies([node0(2, { state: 'Active' }), { ...node1(2), state: 'Backup', in: { bytes: 5, packets: 1 } }]);
  assert.deepEqual([...c.backups], ['node1:2']);
  assert.equal(c.why.get('node1:2'), 'the device marks this copy Backup');
  // A role on one row of the group: no inference for that group.
  c = q.sessionCopies([node0(3, { state: 'Active' }), node1(3)]);
  assert.deepEqual([...c.backups], []);
  // Both zero, or both with traffic: nothing inferred.
  c = q.sessionCopies([node1(4), { ...node1(4), id: 'node0:4', location: 'node0' }]);
  assert.equal(c.backups.size, 0);
  c = q.sessionCopies([node0(5), { ...node0(5), id: 'node1:5', location: 'node1' }]);
  assert.equal(c.backups.size, 0);
  assert.equal(c.groups, 1);
  // A single node (no location): never inferred.
  const solo = (id, bytes) => ({ id: String(id), session_id: '9', location: null, extra: {}, in: { bytes, packets: bytes ? 1 : 0 }, out: { bytes: 0, packets: 0 } });
  c = q.sessionCopies([solo(1, 100), solo(2, 0)]);
  assert.equal(c.backups.size, 0);
  assert.equal(c.groups, 0);
  // Three rows of one id: every zero row beside one with traffic.
  c = q.sessionCopies([node0(6), node1(6), { ...node1(6), id: 'node2:6', location: 'node2' }]);
  assert.deepEqual([...c.backups].sort(), ['node1:6', 'node2:6']);
  assert.equal(c.groups, 1);
  // Counters as strings, nulls and missing wings.
  c = q.sessionCopies([{ ...node0(7), in: { bytes: '10', packets: null }, out: null }, { ...node1(7), in: null, out: null }]);
  assert.deepEqual([...c.backups], ['node1:7']);
  assert.deepEqual(q.sessionCopies(null), { backups: new Set(), why: new Map(), groups: 0 });
});

test('policies: comment, dynapp, url, identity and profile keys; comments in free text', () => {
  const rows = [
    POLICY('web-proxy', 'trust', 'untrust', { comment: '/* CHG-42 proxy */', part_comments: [{ before: 'then', text: '# temporary' }], pair_comment: null,
      match: { source: ['any'], destination: ['any'], application: ['any'], dynamic_application: ['junos:HTTP'], url_category: ['Enhanced_News'], source_identity: ['role-a'], source_end_user_profile: ['eup-1'] } }),
    POLICY('plain', 'trust', 'dmz', { pair_comment: '/* pair CHG-7 */' }),
    POLICY('quiet', 'trust', 'dmz', { inactive: true, inactive_reason: 'zone-pair' }),
    POLICY('lsys-off', 'trust', 'dmz', { inactive: true, inactive_reason: 'scope' }),
  ];
  const names = (s) => ids(s, 'policies', rows, {});
  assert.deepEqual(names('comment:CHG'), ['web-proxy', 'plain']);
  assert.deepEqual(names('note:temporary'), ['web-proxy']);
  assert.deepEqual(names('annotation:"pair chg"'), ['plain']);
  assert.deepEqual(names('dynapp:junos:HTTP'), ['web-proxy']);
  assert.deepEqual(names('l7:junos*'), ['web-proxy']);
  assert.deepEqual(names('url-category:enhanced_news'), ['web-proxy']);
  assert.deepEqual(names('identity:role-a'), ['web-proxy']);
  assert.deepEqual(names('user:role-a'), ['web-proxy']);
  assert.deepEqual(names('profile:eup-1'), ['web-proxy']);
  assert.deepEqual(names('CHG-42'), ['web-proxy'], 'free text searches comments');
  assert.deepEqual(names('Enhanced_News'), ['web-proxy'], 'free text searches the four lists');
  assert.deepEqual(names('desc:CHG'), [], 'desc stays the description statement only');
  assert.deepEqual(names('inactive:zone-pair'), ['quiet']);
  assert.deepEqual(names('inactive:scope'), ['lsys-off']);
  assert.deepEqual(names('inactive:yes'), ['quiet', 'lsys-off']);
  assert.deepEqual(q.FIELDS.policies.inactive.values(), ['yes', 'no', 'policy', 'zone-pair', 'policies', 'security', 'scope']);
  assert.equal(q.FIELDS.policies.inactive.label, 'yes, no, or why: policy, zone-pair, policies, security, scope');
  assert.equal(q.FIELDS.policies.comment.label, 'configuration comment (annotate), substring');
  for (const k of ['comment', 'dynapp', 'url', 'identity', 'profile']) assert.equal(q.FIELDS.policies[k].type, 'text', k);
  assert.ok(q.examples('policies').includes('comment:CHG'));
});

test('policies: deactivated references read "deactivated", not "not found"', () => {
  const DEACT = 'deactivated in the configuration (not in effect)';
  const row = {
    resolved: {
      application: [
        { name: 'tcp-8443', kind: 'unresolved', leaves: [], unresolved: ['tcp-8443'], inactive_skipped: ['tcp-8443'] },
        { name: 'web-apps', kind: 'set', leaves: [{ name: 'junos-https', predefined: true }], unresolved: ['gone'], inactive_skipped: ['old-app'] },
        { name: 'missing', kind: 'unresolved', leaves: [], unresolved: [], inactive_skipped: [] },
      ],
      source: [
        { name: 'corp-lan', kind: 'unresolved', leaves: [], unresolved: ['corp-lan'], inactive_skipped: ['global:corp-lan'] },
        { name: 'branch-set', kind: 'set', leaves: [{ name: 'h1', kind: 'prefix', value: '10.0.0.1/32' }], unresolved: ['nowhere'], inactive_skipped: ['global:h2'] },
      ],
      destination: [{ name: 'lost', kind: 'unresolved', leaves: [], unresolved: ['lost'], inactive_skipped: [] }],
    },
  };
  const ports = q.policyPorts(row).unknown.map((u) => `${u.name}: ${u.why}`);
  assert.deepEqual(ports, [`tcp-8443: ${DEACT}`, 'gone: not found in the configuration', `old-app: ${DEACT}`, 'missing: not found in the configuration']);
  const src = q.policyAddrUnknown(row, 'source').map((u) => `${u.name}: ${u.why}`);
  assert.deepEqual(src, [`corp-lan: ${DEACT}`, 'nowhere: not found in an address book', `h2: ${DEACT}`]);
  assert.deepEqual(q.policyAddrUnknown(row, 'destination').map((u) => u.why), ['not found in an address book']);
  // An older reply listed a deactivated member in unresolved too: it is reported once, as deactivated.
  const old = { resolved: { source: [{ name: 's', kind: 'set', leaves: [], unresolved: ['h3'], inactive_skipped: ['global:h3'] }] } };
  assert.deepEqual(q.policyAddrUnknown(old, 'source'), [{ name: 'h3', why: DEACT }]);
});

test('PREDEFINED_SOURCE says where the catalog comes from', () => {
  assert.equal(q.PREDEFINED_SOURCE, 'J-Wicket’s own table of junos-defaults applications (protocol and destination port), not read from this device and not checked against a Juniper document');
  assert.equal(q.PREDEFINED_APPS['junos-https'].port, '443');
});

test('regexRisk refuses nested, back-to-back and back-referenced repeats', () => {
  const refused = { '(a+)+$': '(a+)+', '(\\w+\\s?)+$': '(\\w+\\s?)+', '(.+)+=': '(.+)+', '.*.*=.*zzz': '.*.*', '(\\d+)*x': '(\\d+)*', '(.*a){12}': '(.*a){12}' };
  for (const [src, piece] of Object.entries(refused)) {
    const r = q.regexRisk(src);
    assert.ok(r, src);
    assert.equal(r.piece, piece, src);
    assert.equal(src.slice(r.at, r.at + r.length), piece);
    assert.equal(r.message, `This pattern can take seconds on one long line: '${piece}' ${r.why}. Write it without nested or back-to-back repeats (for example a+ instead of (a+)+).`);
  }
  assert.equal(q.regexRisk('(a+)+$').why, 'repeats a repeat');
  assert.equal(q.regexRisk('.*.*=.*zzz').why, 'has two repeats in a row that can match the same text');
  assert.equal(q.regexRisk('((a)\\2)+').why, 'repeats a back-reference');
  for (const src of ['\\w*\\w+', '.+\\S*', 'a*a?a*', '(?:x|.*)\\d+', '[a-c]+[c-f]+']) assert.ok(q.regexRisk(src), src);
  // S-9 listed /.*=.*zzz/ as accepted, but it is cubic on a line of '=' (2.4 s on 2048 of them): two
  // repeats around one character both can match. It is refused now; =.*zzz finds the same lines.
  for (const src of ['RT_FLOW_SESSION_(CLOSE|DENY)', '10\\.10\\.\\d+\\.\\d+', '=.*zzz', '[^=]*=.*zzz', '^Nov 24', '\\s*\\S+', 'a*b*', '(ab){3}', 'x{', '', '(?<n>a)\\k<n>', '[']) {
    assert.equal(q.regexRisk(src), null, src);
  }
});

test('regexRisk fails closed and reads modifier groups, whatever this engine compiles (SEC-1)', () => {
  // Chromium compiles (?i:...) groups; node 22 does not, so the shape check is tested directly.
  for (const [src, piece] of [['(a+)+$|(?i:x)', '(a+)+'], ['(?i:(a+)+)$', '(a+)+'], ['(?-i:a)(a|a)+$', '(a|a)+'], ['(.*)*zzz9|(?i:y)', '(.*)*'], ['(?i-m:.*.*)', '.*.*']]) {
    const r = q.regexShapeRisk(src);
    assert.ok(r, src);
    assert.equal(r.piece, piece, src);
  }
  for (const src of ['(?i:close)', '(?-i:RT_FLOW)_SESSION', '(?ims-:x)y']) assert.equal(q.regexShapeRisk(src), null, src);
  // Syntax the check does not read is refused, not waved through.
  const unread = q.regexShapeRisk('(?z:x)');
  assert.equal(unread.why, 'cannot be checked');
  assert.match(unread.message, /^J-Wicket cannot check this pattern for slow repeats, so it does not run it/);
  // The validity probe uses the flags the pattern runs with: '.' matches a line break only with s.
  assert.equal(q.regexRisk('(.|\\n)+$', 'i'), null);
  assert.equal(q.regexRisk('(.|\\n)+$', 'is').why, 'repeats a choice whose branches can match the same text');
  // Node 22 does not compile (?s:...) (the pattern is invalid, so null); Node 24 does, and then the
  // check must refuse it. Either way it never runs.
  const sGroup = q.regexRisk('(?s:.|\\n)+', '');
  assert.ok(sGroup === null || sGroup.why === 'repeats a choice whose branches can match the same text', JSON.stringify(sGroup));
  assert.ok(q.regexShapeRisk('(?s:.|\\n)+', { dotAll: false }), 'a (?s:) group turns dotAll on');
});

test('regexRisk refuses ambiguous choices, shared separators, wide ranges and long optional runs (SEC-2)', () => {
  const refused = {
    '(a|a)+$': ['(a|a)+', 'repeats a choice whose branches can match the same text'],
    '(\\w|\\d)+$': ['(\\w|\\d)+', 'repeats a choice whose branches can match the same text'],
    '(a|aa)+$': ['(a|aa)+', 'repeats a choice whose branches can match the same text'],
    '.*a.*a.*zzz': ['.*a.*', 'has two repeats that can both match what is between them'],
    '\\w*a\\w*b': ['\\w*a\\w*', 'has two repeats that can both match what is between them'],
    '.+=.+=.+=zzz': ['.+=.+', 'has two repeats that can both match what is between them'],
    '.*=.*zzz': ['.*=.*', 'has two repeats that can both match what is between them'],
    '.*\\d\\d.*zzz': ['.*\\d\\d.*', 'has two repeats that can both match what is between them'],
    '.*==.*zzz': ['.*==.*', 'has two repeats that can both match what is between them'],
    'a{0,2000}a{0,2000}zzz': ['a{0,2000}a{0,2000}', 'has two repeats in a row that can match the same text'],
    '(a?){24}a{24}': ['(a?){24}', 'repeats a repeat'],
    '(\\s?\\s)+$': ['(\\s?\\s)+', 'repeats a repeat'],
    '(a{1,3}a)+$': ['(a{1,3}a)+', 'repeats a repeat'],
    '(\\w+)\\1!': ['\\w+)\\1', 'has two repeats in a row that can match the same text'],
  };
  for (const [src, [piece, why]] of Object.entries(refused)) {
    const r = q.regexRisk(src, 'i');
    assert.ok(r, src);
    assert.equal(r.piece, piece, src);
    assert.equal(r.why, why, src);
  }
  const run = q.regexRisk(`${'a?'.repeat(20)}${'a'.repeat(20)}`, 'i');
  assert.equal(run.why, 'can split the same text in too many ways');
  assert.equal(q.regexRisk(`${'(a|a)'.repeat(18)}z`, 'i').why, 'can split the same text in too many ways');
  assert.match(q.regexRisk('.*=.*zzz', 'i').message, /Drop a leading or trailing \.\*/);
  assert.match(q.regexRisk('(a|aa)+$', 'i').message, /Write the branches so that they start differently/);
  // Kept: deterministic choices and separators, and two different plain characters between repeats.
  for (const src of ['(\\d{1,3}\\.){3}\\d{1,3}', '([0-9a-f]{1,4}:){7}[0-9a-f]{1,4}', '(TCP|UDP|ICMP) .{0,20}', 'src=\\S+ dst=\\S+', '.*error.*', 'RT_FLOW.*CLOSE', '(\\w+)=(\\S+)', '(foo|bar)+', '(a|b)'.repeat(200), '(.|\\n)+$', '^\\w{3} +\\d+ \\d\\d:\\d\\d', '\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}']) {
    assert.equal(q.regexRisk(src, 'i'), null, src);
  }
  // The check itself stays quick on a long pattern.
  const t0 = performance.now();
  q.regexRisk('(?:x|y|z|w)+'.repeat(60), 'i');
  q.regexRisk('[a-z]'.repeat(400), 'i');
  assert.ok(performance.now() - t0 < 500);
});

test('regexRisk: escapes it cannot read exactly, deep nesting and long patterns are refused, quickly (recheck residuals)', () => {
  const slow = (fn) => {
    const t0 = performance.now();
    const r = fn();
    return { r, ms: performance.now() - t0 };
  };
  // Under the u flag, \u{..} is the character it names: these are the same choice twice.
  for (const src of ['(=|\\u{3d})+$', '( |\\u{20})+$', '(\\s|\\u{20})+$', '(\\d|\\u{30})+$']) {
    const r = q.regexRisk(src, 'u');
    assert.ok(r, src);
    assert.equal(r.why, 'repeats a choice whose branches can match the same text', src);
  }
  assert.equal(q.regexRisk('.*\\u{3d}.*zzz', 'u').why, 'has two repeats that can both match what is between them');
  assert.equal(q.regexRisk('\\u{61}*\\u{61}*zzz', 'u').why, 'has two repeats in a row that can match the same text');
  // The same character written two ways counts once between two repeats.
  assert.ok(q.regexRisk('.*=\\x3d.*zzz', 'i'));
  // Without the u flag the engine reads \u{1,3} and \p{1,9} as a letter and a quantifier: refused.
  for (const src of ['(?:\\u{1,3})+$', '\\p{1,9}x', '\\P{2}']) {
    const r = q.regexRisk(src, 'i');
    assert.equal(r && r.why, 'cannot be checked', src);
    assert.match(r.message, /without the u flag/, src);
  }
  // Legacy octal: \075 is '='.
  const oct = q.regexRisk('.*\\075.*zzz', 'i');
  assert.equal(oct && oct.why, 'cannot be checked');
  assert.match(oct.message, /octal escape/);
  // Astral characters are compared whole, with or without u.
  for (const f of ['', 'u']) assert.ok(q.regexRisk('(\u{1F600}|\u{1F600})+$', f), `astral, flags '${f}'`);
  // Kept under u: property classes and named characters that do not overlap.
  for (const src of ['\\p{L}+-\\d+', 'id=\\u{3d}?\\d+', '^\\u{41}BC']) assert.equal(q.regexRisk(src, 'u'), null, src);
  // Deep nesting is refused at once; at the limit it is checked quickly.
  const deep = `${'(?:'.repeat(200)}ab${'){1,2}'.repeat(200)}`; // 1,802 characters
  const d = slow(() => q.regexRisk(deep, 'i'));
  assert.equal(d.r && d.r.why, 'cannot be checked');
  assert.match(d.r.message, /nested more than 16 deep/);
  assert.ok(d.ms < 50, `deep pattern took ${d.ms} ms`);
  const atLimit = `${'(?:'.repeat(16)}ab${'){1,2}'.repeat(16)}`;
  const l = slow(() => q.regexShapeRisk(atLimit));
  assert.ok(l.ms < 50, `16-deep pattern took ${l.ms} ms`);
  // A long pattern: checked quickly up to the cap, refused above it.
  const wideP = slow(() => q.regexRisk('(?:ab|cd){1,2}x'.repeat(130), 'i'));
  assert.ok(wideP.ms < 200, `wide pattern took ${wideP.ms} ms`);
  const long = q.regexRisk('x'.repeat(2049), 'i');
  assert.equal(long && long.why, 'cannot be checked');
  assert.match(long.message, /longer than 2048 characters/);
});

test('regexRisk: refused patterns are inline errors; accepted ones stay fast on long lines', () => {
  const bad = q.parse('/.*.*=zzz/', { view: 'logs' });
  assert.equal(bad.ast, null);
  assert.match(bad.error.message, /^This pattern can take seconds on one long line: '\.\*\.\*' has two repeats in a row/);
  assert.equal(bad.error.pos, 0);
  const keyed = q.parse('msg:/(a+)+$/', { view: 'logs' });
  assert.match(keyed.error.message, /^msg: This pattern can take seconds/);
  assert.match(q.parse('msg~"(x+)+y"', { view: 'logs' }).error.message, /^msg: This pattern can take seconds.*repeats a repeat/);
  assert.match(q.parse('/(/', { view: 'logs' }).error.message, /^Invalid regular expression/);
  assert.doesNotThrow(() => q.compile(q.parse('/(a+)+$/').ast, q.FIELDS.logs, {}), 'compile never throws');
  // '=' runs (banners), digit runs and spaces as well as the S-14 lines; /.*=.*zzz/ is refused now
  // (see above), and /=.*zzz/ is what it finds.
  const texts = ['a'.repeat(2047) + '!', 'y'.repeat(2048), '='.repeat(2048), '1'.repeat(2048), ' '.repeat(2048)];
  for (const src of ['RT_FLOW_SESSION_(CLOSE|DENY)', '10\\.10\\.\\d+\\.\\d+', '=.*zzz', '^Nov 24', '.*error.*', '(\\d{1,3}\\.){3}\\d{1,3}']) {
    const r = q.parse(`/${src}/`, { view: 'logs' });
    assert.equal(r.error, null, src);
    const f = q.compile(r.ast, q.FIELDS.logs, {});
    for (const line of texts) {
      const t0 = performance.now();
      f({ line, fields: {} });
      assert.ok(performance.now() - t0 < 50, `${src} took ${performance.now() - t0} ms`);
    }
  }
});

test('logs reason: the 28 documented close reasons are offered', () => {
  const labels = q.suggest('reason:', 7, { view: 'logs' }).map((x) => x.label);
  assert.ok(labels.includes('TCP CLIENT RST'), labels.join(', '));
  assert.ok(q.suggest('reason:', 7, { view: 'logs' }).some((x) => x.insert === 'reason:"TCP CLIENT RST"'));
  const values = q.FIELDS.logs.reason.values([]);
  for (const r of lp.CLOSE_REASONS) assert.ok(values.includes(r.text), r.text);
  assert.equal(q.FIELDS.logs.reason.label, 'close or deny reason ("TCP FIN", "TCP CLIENT RST")');
  assert.ok(q.examples('logs').includes('reason:*RST'));
  const close = lp.parse('Jan 12 13:53:44 fw RT_FLOW: RT_FLOW_SESSION_CLOSE: session closed TCP CLIENT RST: 30.0.0.2/46488->50.0.0.2/23 junos-telnet 30.0.0.2/46488->50.0.0.2/23 None None None None 6 p1 green red 240003072 2(100) 1(60) 2 UNKNOWN UNKNOWN N/A(N/A) ge-11/0/0.0 UNKNOWN');
  assert.equal(q.compile(ok('reason:*RST', 'logs'), q.FIELDS.logs, {})(close), true);
});
