// Unit tests for src/jwicket/static/js/format.js: control and format characters (S-1) and the device
// time zone (S-13). Run: node --test tests/js/*.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import * as f from '../../src/jwicket/static/js/format.js';

const ch = (cp) => String.fromCodePoint(cp);
const ZWSP = ch(0x200b);
const NEL = ch(0x85);
const RLO = ch(0x202e);
const LRI = ch(0x2066);
const BOM = ch(0xfeff);
const SHY = ch(0xad);
const ALM = ch(0x61c);
const EMOJI = ch(0x1f600);

test('controlParts splits hidden and direction-changing characters, in order', () => {
  for (const c of [ZWSP, NEL, RLO, LRI, BOM, SHY, ALM]) {
    const name = `U+${c.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}`;
    assert.deepEqual(f.controlParts(`a${c}b`), [{ text: 'a' }, { ctl: name, ch: c }, { text: 'b' }], name);
    assert.equal(f.hasControls(`a${c}b`), true, name);
  }
  assert.deepEqual(f.controlParts(`web${ZWSP}proxy${RLO}`), [{ text: 'web' }, { ctl: 'U+200B', ch: ZWSP }, { text: 'proxy' }, { ctl: 'U+202E', ch: RLO }]);
  assert.deepEqual(f.controlParts(`${RLO}${RLO}`).map((p) => p.ctl), ['U+202E', 'U+202E']);
});

test('controlParts keeps tab and line feed unless `all`, handles "" and never splits an emoji', () => {
  assert.deepEqual(f.controlParts(''), []);
  assert.deepEqual(f.controlParts(null), []);
  assert.deepEqual(f.controlParts('plain name'), [{ text: 'plain name' }]);
  assert.deepEqual(f.controlParts('a\tb\nc'), [{ text: 'a\tb\nc' }]);
  assert.equal(f.hasControls('a\tb\nc'), false);
  assert.deepEqual(f.controlParts('a\tb\nc', { all: true }), [
    { text: 'a' }, { ctl: 'U+0009', ch: '\t' }, { text: 'b' }, { ctl: 'U+000A', ch: '\n' }, { text: 'c' },
  ]);
  assert.equal(f.hasControls('a\nb', { all: true }), true);
  // An astral character is two UTF-16 units; neither is in the class, so it stays whole.
  assert.deepEqual(f.controlParts(`${EMOJI}${ZWSP}${EMOJI}`), [{ text: EMOJI }, { ctl: 'U+200B', ch: ZWSP }, { text: EMOJI }]);
  assert.equal(f.controlParts(`x${EMOJI}`).length, 1);
});

test('plain writes each control as <U+XXXX>; the parts round-trip to the input', () => {
  const s = `a${RLO}b${ZWSP}c\td${NEL}`;
  assert.equal(f.plain(s), 'a<U+202E>b<U+200B>c\td<U+0085>');
  assert.equal(f.plain(s, { all: true }), 'a<U+202E>b<U+200B>c<U+0009>d<U+0085>');
  assert.equal(f.plain('nothing hidden'), 'nothing hidden');
  assert.equal(f.plain(undefined), '');
  for (const all of [false, true]) {
    const parts = f.controlParts(s, { all });
    assert.equal(parts.map((p) => (p.ctl ? p.ch : p.text)).join(''), s);
    assert.equal(parts.map((p) => (p.ctl ? `<${p.ctl}>` : p.text)).join(''), f.plain(s, { all }));
  }
  assert.equal(f.controlName(SHY), 'U+00AD');
  assert.equal(f.countControls(`${ZWSP}${ZWSP}\t\n${RLO}`), 3);
  assert.equal(f.countControls('plain'), 0);
  assert.ok(f.CONTROL_RE.test(BOM));
  assert.ok(!f.CONTROL_RE.test('\t'));
  assert.equal(typeof f.CONTROL_CLASS, 'string');
});

test('cliUnsafe: line breaks and C0/C1 controls are never pasted; format characters are', () => {
  for (const s of ['a\nb', 'a\rb', 'a\tb', `a${NEL}b`, `a${ch(0x2028)}b`, `a${ch(0x2029)}b`, `a${ch(0)}b`, `a${ch(0x7f)}b`]) {
    assert.equal(f.cliUnsafe(s), true, JSON.stringify(s));
  }
  for (const s of [`web${ZWSP}proxy`, `a${RLO}b`, `a${LRI}b`, 'allow-web', '']) assert.equal(f.cliUnsafe(s), false, JSON.stringify(s));
});

test('deviceZone: convertible only for an IANA name the browser knows, configured and read', () => {
  assert.deepEqual(f.deviceZone({ status: 'ok', time_zone: 'Europe/Paris', configured: true, deactivated: null, source: 'configuration' }),
    { zone: 'Europe/Paris', label: 'Europe/Paris', convertible: true });
  assert.deepEqual(f.deviceZone({ status: 'ok', time_zone: null, configured: false, deactivated: null }), { zone: null, label: 'UTC (Junos default)', convertible: false });
  assert.deepEqual(f.deviceZone({ status: 'ok', time_zone: 'PDT', configured: true }), { zone: 'PDT', label: 'PDT (not convertible here)', convertible: false });
  // The sign convention of Junos GMT+n is not known: never converted, even when Intl would accept it.
  for (const z of ['GMT+8', 'GMT-3', 'Etc/GMT+8', 'UTC+2']) assert.equal(f.deviceZone({ status: 'ok', time_zone: z, configured: true }).convertible, false, z);
  assert.deepEqual(f.deviceZone({ status: 'denied', message: 'Your Junos login class does not allow this.' }),
    { zone: null, label: 'not known (configuration not read: denied)', convertible: false });
  assert.equal(f.deviceZone({ status: 'unsupported', message: 'x' }).label, 'not known (configuration not read: unsupported)');
  assert.equal(f.deviceZone(null).convertible, false);
  assert.equal(f.deviceZone(undefined).zone, null);
  const off = f.deviceZone({ status: 'ok', time_zone: null, configured: false, deactivated: 'Asia/Tokyo' });
  assert.equal(off.convertible, false);
  assert.match(off.label, /^UTC \(Junos default/);
  assert.match(off.label, /inferred/);
  assert.equal(f.deviceZone({ status: 'ok', time_zone: `Europe/Paris${RLO}`, configured: true }).label, 'Europe/Paris<U+202E> (not convertible here)');
});

test('naiveToUtc: a wall time in the zone to real UTC, DST-aware', () => {
  const iso = (ms) => new Date(ms).toISOString();
  assert.equal(iso(f.naiveToUtc(Date.UTC(2026, 6, 1, 12, 0, 0), 'Europe/Paris')), '2026-07-01T10:00:00.000Z');
  assert.equal(iso(f.naiveToUtc(Date.UTC(2026, 11, 1, 12, 0, 0), 'Europe/Paris')), '2026-12-01T11:00:00.000Z');
  assert.equal(iso(f.naiveToUtc(Date.UTC(2026, 11, 1, 12, 0, 0, 250), 'Europe/Paris')), '2026-12-01T11:00:00.250Z');
  assert.equal(iso(f.naiveToUtc(Date.UTC(2026, 6, 1, 12, 0, 0), 'UTC')), '2026-07-01T12:00:00.000Z');
  // 02:30 does not exist on 2026-03-29 in Paris: forward by the change. 02:30 on 2026-10-25 happens
  // twice: the first occurrence (summer time).
  assert.equal(iso(f.naiveToUtc(Date.UTC(2026, 2, 29, 2, 30), 'Europe/Paris')), '2026-03-29T01:30:00.000Z');
  assert.equal(iso(f.naiveToUtc(Date.UTC(2026, 9, 25, 2, 30), 'Europe/Paris')), '2026-10-25T00:30:00.000Z');
  assert.equal(iso(f.naiveToUtc(Date.UTC(2026, 10, 1, 1, 30), 'America/Los_Angeles')), '2026-11-01T08:30:00.000Z');
  for (const z of ['PDT', 'GMT+8', null, '', '+08:00']) assert.equal(f.naiveToUtc(Date.UTC(2026, 6, 1), z), null, String(z));
  assert.equal(f.naiveToUtc(Number.NaN, 'Europe/Paris'), null);
});
