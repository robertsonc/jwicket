// Tests for views/policies.js helpers against the UI-19 contract: CRT-14 (no CLI command for a name with
// a line break or control character) and POL-UI-06 (markNodes is badge-aware and builds nodes only
// through the `h` it is given, so it runs without a DOM). Owned by SHARED (tests/js/**); the helpers are
// POLICIES_OBJECTS'. Run: node --test tests/js/*.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import * as pol from '../../src/jwicket/static/js/views/policies.js';

const ch = (cp) => String.fromCodePoint(cp);
const LS = ch(0x2028);
const ZWSP = ch(0x200b);
const RLO = ch(0x202e);

/** A stand-in for dom.h that records what it builds; there is no document in this test. */
function fakeH(tag, attrs, ...children) {
  const isAttrs = attrs && typeof attrs === 'object' && !Array.isArray(attrs) && !attrs.fake;
  const kids = (isAttrs ? children : [attrs, ...children]).flat(Infinity).filter((c) => c !== null && c !== undefined && c !== false);
  return { fake: true, tag, attrs: isAttrs ? attrs : {}, children: kids };
}
const classOf = (n) => {
  const c = n && n.attrs ? n.attrs.class : '';
  return Array.isArray(c) ? c.filter(Boolean).join(' ') : String(c || '');
};
const walk = (nodes) => nodes.flatMap((n) => (n && n.fake ? [n, ...walk(n.children)] : []));
const textOf = (nodes) => nodes.map((n) => (n && n.fake ? textOf(n.children) : String(n))).join('');

test('cliWord: no command for a word with a line break or control character (CRT-14)', () => {
  assert.equal(pol.cliWord('a\nb'), null);
  assert.equal(pol.cliWord(`a${LS}b`), null);
  assert.equal(pol.cliWord('a\tb'), null);
  assert.equal(pol.cliWord(`a${ch(0x85)}b`), null);
  // Format characters are copied exactly (quoted), so the command names the same object.
  const quoted = pol.cliWord(`web${ZWSP}proxy`);
  assert.notEqual(quoted, null);
  assert.ok(quoted.startsWith('"') && quoted.endsWith('"'), quoted);
  assert.ok(quoted.includes(ZWSP));
  assert.equal(pol.cliWord('allow-web'), 'allow-web');
  assert.equal(pol.cliWord('two words'), '"two words"');
});

test('markNodes marks terms and badges controls, only through the given h (POL-UI-06)', () => {
  const out = pol.markNodes(fakeH, `x${RLO}y`, ['x']);
  assert.ok(Array.isArray(out));
  const nodes = walk(out);
  assert.ok(nodes.some((n) => n.tag === 'mark'), 'a mark node');
  const badge = nodes.find((n) => classOf(n).split(/\s+/).includes('ctl-badge'));
  assert.ok(badge, 'a ctl-badge node');
  assert.equal(textOf([badge]), 'U+202E');
  assert.equal(textOf(out).includes(RLO), false, 'the control is shown, not applied');
  // No term, no control: the text as it is.
  assert.equal(textOf(pol.markNodes(fakeH, 'allow-web', [])), 'allow-web');
});
