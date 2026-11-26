// Unit tests for src/jwicket/static/js/regexvm.js. Run: node --test tests/js/ (and again with
// node --js-regexp-modifiers --test tests/js/regexvm.test.mjs, so that the (?i:...) cases run too).
//
// 1. Differential: compileUserRegex(p, f).test(s) must equal new RegExp(p, f).test(s) for every
//    pattern both accept: seeded random patterns over a small alphabet and every supported
//    construct, and hand-written edge cases (Annex B, case folding, astral, \p, m and s, empty loops).
// 2. Every pattern of the adversarial hunt that froze the old heuristic: refused, or fast.
// 3. Linear time: the worst shapes found grow about linearly from 512 to 2048 characters.
// 4. Unsupported constructs are refused with the right `why`.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { compileUserRegex, RegexUnsupported, MAX_STATES, MAX_CLASS_ATOMS, MAX_PROPERTY_ESCAPES, REGEX_SOURCE_MAX, MAX_DEPTH, MAX_SUBJECT, ENGINE_QUIRKS, cacheUse } from '../../src/jwicket/static/js/regexvm.js';

const HAS_MODIFIER = /\(\?[ims]*-?[ims]*:/;
// A modifier group that names i: refused where the engine applies such a group's i wrongly
// (ENGINE_QUIRKS.caseModifierGroups) when it changes i; one that leaves i as it is still runs.
const NAMES_I = /\(\?[ms]*-?[ms]*i[ims-]*:/;
const MODIFIERS = (() => {
  try {
    new RegExp('(?i:a)'); // eslint-disable-line no-new
    return true;
  } catch (_e) {
    return false;
  }
})();

function native(p, f) {
  try {
    return new RegExp(p, f);
  } catch (_e) {
    return null;
  }
}

function ours(p, f) {
  try {
    return compileUserRegex(p, f);
  } catch (e) {
    if (e instanceof RegexUnsupported) return null;
    throw e;
  }
}

const show = (s) => JSON.stringify(s).replace(/[\u0080-\uffff]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);

/** Compares ours with the native engine on every string; returns how many pairs were compared. */
function same(p, f, strings, { mustAccept = false } = {}) {
  const re = native(p, f);
  if (!re) return 0;
  const m = ours(p, f);
  if (!m) {
    if (mustAccept) assert.fail(`refused /${show(p)}/${f}`);
    return 0;
  }
  for (const s of strings) {
    let want;
    try {
      want = re.test(s);
    } catch (e) {
      // V8 gives up on a few huge counts (RangeError: Maximum call stack size exceeded): no answer to compare
      if (e instanceof RangeError) {
        m.test(s);
        continue;
      }
      throw e;
    }
    assert.equal(m.test(s), want, `/${show(p)}/${f} on ${show(s)}: native ${want}`);
  }
  return strings.length;
}

// --- 1a. random differential ------------------------------------------------------------------------

function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// Characters the strings are made of: ASCII, case-folding traps, line terminators, astral, halves.
const ALPHABET = ['a', 'b', 'A', 'B', 'k', 'K', '\u212a', 's', 'S', '\u017f', '\u03c3', '\u03c2', '\u03a3', '\u00b5', '\u03bc', '\u039c', 'i', 'I', '\u0130', '\u0131', '\u00df', '\u1e9e', 'x', '0', '7', '_', '-', ' ', '\n', '\r', '\u2028', '\t', '\\', 'c', '{', '}', '<', '>', '\u00e9', '\u00c9', '\u{1F600}', '\u{1F64F}', '\ud83d', '\ude00', '\u{10400}', '\u{10428}', '\u0000', '\u0001', '\u0008', '\u0011', '\u00ff', '\u0414', '\u3041', '\u4e00', '\u03b1', '\u0390', '\u1fd3'];

const LITERALS = ['a', 'b', 'A', 'k', 'K', '\u212a', 's', '\u017f', '\u03c3', '\u03c2', '\u03a3', '\u00b5', '\u03bc', 'i', '\u0130', '\u0131', '\u00df', 'x', '0', '_', '-', ' ', '\u00e9', '\u{1F600}', '\u3041', '\u03b1', '\\.', '\\-', '\\/', '\\\\', '\\n', '\\r', '\\t', '\\x41', '\\x6b', '\\u212a', '\\u017f', '\\u03c3', '\\ud83d\\ude00', '\\ud83d', '\\ude00', '\\cJ', '\\ck', '\\0', '\\f', '\\v'];
const LITERALS_U = ['\\u{1F600}', '\\u{0000006b}', '\\u{212A}', '\\u{10400}', '\\u{d83d}\\u{de00}', '\\ud83d\\u{de00}'];
const LITERALS_ANNEX_B = ['\\c', '\\c1', '\\c_', '\\8', '\\9', '\\1', '\\2', '\\12', '\\18', '\\377', '\\400', '\\08', '\\01', '\\k', '\\p', '\\P', '\\x4', '\\xg', '\\u12', '\\u{41}', '\\q', '\\e', '\\a', '{', '}', ']', 'a{,2}', 'x{1', '\\\u00e9', '\\\u{1F600}', '\\_'];
const ESCAPES = ['.', '\\d', '\\D', '\\w', '\\W', '\\s', '\\S'];
const ESCAPES_U = ['\\p{L}', '\\P{L}', '\\p{Lu}', '\\p{Ll}', '\\p{Script=Greek}', '\\p{sc=Hira}', '\\p{Nd}', '\\P{Any}', '\\p{ASCII}'];
const CLASSES = ['[ab]', '[^ab]', '[a-c]', '[^k]', '[k]', '[K]', '[\\w-]', '[\\b]', '[]', '[^]', '[\\s\\S]', '[\\0-\\x7f]', '[A-Z]', '[\\]]', '[\u03b1-\u03c9]', '[\u0390-\u03a2]', '[\u1f00-\u1fff]', '[\u{1F600}-\u{1F64F}]', '[\u{1F600}]', '[^\u{1F600}]', '[\\ud83d\\ude00]', '[^\\ud83d]', '[\\cJ]', '[s]', '[^s]', '[\\W]', '[^\\W]', '[^\\w]', '[\u017f]', '[\u212a]', '[\\x00-\\uffff]', '[^\\x00-\\uffff]', '[a-z\\d]', '[\\u03c3]'];
const CLASSES_U = ['[\\u{1F600}-\\u{1F64F}]', '[\\p{L}]', '[^\\p{L}]', '[\\p{Lu}\\d]', '[\\-a]', '[^\\P{Ll}]', '[\\u{10400}]'];
const CLASSES_ANNEX_B = ['[\\d-z]', '[\\c1]', '[\\c_]', '[\\c]', '[\\c*]', '[\\377]', '[\\8]', '[\\1]', '[\\k]', '[\\p]', '[\\x4]', '[\\u12]', '[a-\\d]', '[\\w-\\d]', '[\\-]'];
const ASSERTIONS = ['^', '$', '\\b', '\\B'];
const QUANTS = ['', '', '', '*', '+', '?', '{0}', '{1}', '{2}', '{0,2}', '{1,3}', '{2,}', '{0,}', '{001}', '{0,0}', '*?', '+?', '??', '{1,2}?', '{3}'];

// The native engine backtracks: a repeated group that holds an unbounded repeat ((a*)*, (x+y)+)
// can take seconds even on 12 characters. Such groups get only ? and {0,1}, so the reference stays
// fast; the matcher under test is linear either way.
const UNBOUNDED = /[*+]|\{\d+,\}/;
const SAFE_QUANTS = ['', '', '', '?', '{0,1}', '{1}', '??'];
const quantsFor = (term) => (term.startsWith('(') && UNBOUNDED.test(term) ? SAFE_QUANTS : QUANTS);

function genPattern(rng, unicode, depth = 0) {
  const pick = (arr) => arr[Math.floor(rng() * arr.length)];
  const atom = () => {
    const r = rng();
    if (r < 0.32) return pick(LITERALS);
    if (r < 0.37) return unicode ? pick(LITERALS_U) : pick(LITERALS_ANNEX_B);
    if (r < 0.5) return pick(ESCAPES);
    if (r < 0.54 && unicode) return pick(ESCAPES_U);
    if (r < 0.66) return pick(CLASSES);
    if (r < 0.7) return unicode ? pick(CLASSES_U) : pick(CLASSES_ANNEX_B);
    if (r < 0.77) return pick(ASSERTIONS);
    if (depth >= 3) return pick(LITERALS);
    const body = genPattern(rng, unicode, depth + 1);
    const g = rng();
    if (g < 0.4) return `(?:${body})`;
    if (g < 0.6) return `(${body})`;
    if (g < 0.7) return `(?<n${Math.floor(rng() * 1e6)}>${body})`;
    return `(?:${body}|${genPattern(rng, unicode, depth + 1)})`;
  };
  const alts = [];
  const nAlts = rng() < 0.75 ? 1 : 2 + Math.floor(rng() * 2);
  for (let a = 0; a < nAlts; a += 1) {
    let s = '';
    const nTerms = Math.floor(rng() * 4) + (rng() < 0.1 ? 0 : 1);
    for (let t = 0; t < nTerms; t += 1) {
      const at = atom();
      const isAssertion = ASSERTIONS.includes(at);
      s += at + (isAssertion ? '' : pick(quantsFor(at)));
    }
    alts.push(s);
  }
  return alts.join('|');
}

function genString(rng) {
  const n = Math.floor(rng() * 13);
  let s = '';
  for (let k = 0; k < n; k += 1) s += ALPHABET[Math.floor(rng() * ALPHABET.length)];
  return s;
}

test('random patterns agree with the native engine on random strings', () => {
  const rng = mulberry32(0x5eed2611);
  const FLAGS = ['', 'i', 'm', 's', 'u', 'iu', 'im', 'is', 'mu', 'su', 'imsu', 'ims', 'iu', 'u'];
  let compared = 0;
  let patterns = 0;
  let refused = 0;
  for (let k = 0; k < 6000; k += 1) {
    const f = FLAGS[Math.floor(rng() * FLAGS.length)];
    const p = genPattern(rng, f.includes('u'));
    const re = native(p, f);
    if (!re) continue;
    patterns += 1;
    if (!ours(p, f)) {
      refused += 1;
      continue;
    }
    const strings = [];
    for (let j = 0; j < 24; j += 1) strings.push(genString(rng));
    compared += same(p, f, strings);
  }
  // The generator makes no lookaround and no back-reference except \1 \2 \12 \18 with groups, and
  // \k with named groups; nearly everything else must be accepted.
  assert.ok(patterns > 3000, `only ${patterns} valid patterns`);
  assert.ok(refused / patterns < 0.12, `refused ${refused} of ${patterns}`);
  assert.ok(compared > 60000, `compared ${compared}`);
});

// --- 1b. hand-written edge cases --------------------------------------------------------------------

const S = (...xs) => xs;
const EDGE = [
  // Annex B escapes outside classes
  ['\\c', '', S('\\c', 'c', '\\', '\\C', 'x')],
  ['\\c+', '', S('\\c', '\\cc', '\\', 'cc')],
  ['(?:\\c|\\\\c)+$', 'i', S('\\c\\c', '\\C', '\\c!')],
  ['\\cJ', '', S('\n', 'J', '\\cJ')],
  ['\\cj', '', S('\n', 'j')],
  ['\\c1', '', S('\\c1', '\u0011', 'c1')],
  ['\\c_', '', S('\\c_', '\u001f')],
  ['\\c\u00e7', '', S('\\c\u00e7', '\u0007')],
  ['^\\c$', '', S('\\c', 'c')],
  ['\\k', '', S('k', '\\k', 'K')],
  ['\\k<a>', '', S('k<a>', 'k', '<a>')],
  ['\\k<(?:a+)+b>', 'i', S('k<aab>', 'k<b>', 'k<ab')],
  ['\\8', '', S('8', '\\8', '\u0008')],
  ['\\9\\8', '', S('98', '89')],
  ['\\1', '', S('\u0001', '1', '\\1')],
  ['\\1(a)', '', S('aa', 'a')],
  ['(a)\\2', '', S('a\u0002', 'a2')],
  ['\\12', '', S('\n', '\u0001' + '2', '12')],
  ['\\18', '', S('\u00018', '18')],
  ['\\377', '', S('\u00ff', '\u001f' + '7')],
  ['\\400', '', S('\u0020' + '0', '\u0100')],
  ['\\777', '', S('?7', '\u01ff')],
  ['\\08', '', S('\u00008', '\u0008')],
  ['\\01', '', S('\u0001', '\u00001')],
  ['\\0', '', S('\u0000', '0')],
  ['\\x4', '', S('x4', '\u0004')],
  ['\\x41', '', S('A', 'x41')],
  ['\\xg', '', S('xg')],
  ['\\u12', '', S('u12', '\u0012')],
  ['\\u{41}', '', S('u'.repeat(41), 'u'.repeat(40), 'A')],
  ['\\u{2,3}', '', S('uu', 'u')],
  ['\\p{L}', '', S('p{L}', 'pL', 'a')],
  ['\\P', '', S('P', 'p')],
  ['\\q\\e\\/\\-', '', S('qe/-')],
  ['\\\u00e9', '', S('\u00e9')],
  ['\\\u{1F600}', '', S('\u{1F600}', '\ud83d')],
  ['a{', '', S('a{', 'a')],
  ['a{1', '', S('a{1')],
  ['a{,2}', '', S('a{,2}', 'aa')],
  ['a{1,x}', '', S('a{1,x}')],
  ['{', '', S('{')],
  ['}', '', S('}')],
  [']', '', S(']')],
  ['x{2}{', '', S('xx{')],
  ['\\{1}', '', S('{1}', '{')],
  // quantifier numbers
  ['a{0000000000000000000000100}', '', S('a'.repeat(100), 'a'.repeat(99))],
  ['^a{0001,0003}$', '', S('a', 'aaa', 'aaaa', '')],
  ['(?:a|){99999999999999999999999}b', '', S('b', 'ab', 'x')],
  ['(?:){2147483648}', '', S('', 'x')],
  ['(?:ab){2147483647}', '', S('ab', '')],
  ['(?:ab){2147483648,}', '', S('abab')],
  ['b|(?:ab){99999999999}', '', S('b', 'ab')],
  ['^a{0,99999999999999}$', '', S('', 'a', 'aaaa', 'b')],
  ['^(?:a|b){0,2147483647}$', '', S('abab', 'abc')],
  ['^(?:\\b){3}a', '', S('a', ' a')],
  ['(?:^){5}a', 'm', S('a', 'x\na', 'xa')],
  // classes and their escapes
  ['[\\d-z]', '', S('-', 'z', '5', 'y')],
  ['[a-\\d]', '', S('-', 'a', '3', 'b')],
  ['[\\c1]', '', S('\u0011', 'c', '1', '\\')],
  ['[\\c]', '', S('\\', 'c', ']')],
  ['[\\c]]', '', S('\\]', 'c]', ']')],
  ['[\\c*]', '', S('*', '\\', 'c', '\n')],
  ['[\\cz]', '', S('\u001a', 'z')],
  ['[\\377]', '', S('\u00ff', '3')],
  ['[\\8]', '', S('8', '\\')],
  ['[\\1]', '', S('\u0001', '1')],
  ['[\\k]', '', S('k', '\\')],
  ['[\\b]', '', S('\u0008', 'b')],
  ['[]]', '', S(']', '[]]')],
  ['[^]]', '', S('a]', ']')],
  ['[]', '', S('', 'a')],
  ['[^]', '', S('', 'a', '\n')],
  ['[^]', 'u', S('\u{1F600}', '\ud83d')],
  ['[[]', '', S('[')],
  ['[\\]]', '', S(']')],
  ['[\\-]', 'u', S('-')],
  ['[a\\-z]', '', S('-', 'b')],
  ['[\\u{41}]', '', S('u', '{', '4', '}', 'A')],
  ['[\\u{41}]', 'u', S('A', 'u')],
  // case folding
  ['k', 'i', S('k', 'K', '\u212a')],
  ['k', 'iu', S('k', 'K', '\u212a')],
  ['\u212a', 'i', S('k', 'K', '\u212a')],
  ['\u212a', 'iu', S('k', 'K', '\u212a')],
  ['[k]', 'iu', S('\u212a', 'K')],
  ['[^k]', 'iu', S('\u212a', 'K', 'k', 'j')],
  ['[^k]', 'i', S('\u212a', 'K')],
  ['^(?:(?-i:[^k])|k)+!$', 'iu', S('\u212a\u212a!', 'ab!')],
  ['s', 'i', S('s', 'S', '\u017f')],
  ['s', 'iu', S('s', 'S', '\u017f')],
  ['\u017f', 'i', S('s', 'S', '\u017f')],
  ['\u017f', 'iu', S('s', 'S', '\u017f')],
  ['\\w', 'iu', S('\u017f', '\u212a', 'a')],
  ['\\W', 'iu', S('\u017f', '\u212a', '!')],
  ['\\W', 'i', S('\u017f', '\u212a')],
  ['[\\W]', 'iu', S('\u017f', '!')],
  ['[^\\W]', 'iu', S('\u017f', 'a', '!')],
  ['(?:\\W|\u017f)+$', 'u', S('\u017f\u017fa', '\u017f!')],
  ['\u03c3', 'i', S('\u03c3', '\u03c2', '\u03a3')],
  ['\u03c2', 'i', S('\u03c3', '\u03c2', '\u03a3')],
  ['\u03c3', 'iu', S('\u03c3', '\u03c2', '\u03a3')],
  ['\u03a3\u03c3\u03c2', 'i', S('\u03c3\u03c3\u03c3', '\u03c2\u03a3\u03c3')],
  ['\u00b5', 'i', S('\u00b5', '\u03bc', '\u039c')],
  ['\u03bc', 'i', S('\u00b5', '\u03bc', '\u039c')],
  ['\u00b5', 'iu', S('\u00b5', '\u03bc', '\u039c')],
  ['.*\u00b5\u03bc.*!', 'i', S('\u03bc\u03bc!', '\u00b5\u00b5')],
  ['\u0130', 'i', S('i', 'I', '\u0130', '\u0131')],
  ['\u0130', 'iu', S('i', 'I', '\u0130', '\u0131', 'i\u0307')],
  ['\u0131', 'i', S('i', 'I', '\u0131')],
  ['\u0131', 'iu', S('i', 'I', '\u0131')],
  ['i', 'iu', S('\u0130', '\u0131', 'I')],
  ['\u00df', 'i', S('\u1e9e', 'ss', 'SS')],
  ['\u00df', 'iu', S('\u1e9e', 'ss')],
  ['\u1e9e', 'i', S('\u00df')],
  ['\u00c5', 'i', S('\u212b', '\u00e5')],
  ['\u212b', 'iu', S('\u00c5', '\u00e5')],
  ['\u03a9', 'iu', S('\u2126', '\u03c9')],
  ['\u03b8', 'i', S('\u03d1', '\u0398', '\u03f4')],
  ['\u03b8', 'iu', S('\u03d1', '\u0398', '\u03f4')],
  ['\u01c5', 'i', S('\u01c4', '\u01c6')],
  ['\u01c5', 'iu', S('\u01c4', '\u01c6')],
  ['\u1fd3', 'i', S('\u0390')],
  ['\u1fd3', 'iu', S('\u0390')],
  ['[\u0390-\u03a2]', 'i', S('\u03b1', '\u0391', '\u1fd3')],
  ['[\u0390-\u03a2]*[\u03af-\u03c2]*!', 'i', S('\u03b1\u03b1!', '\u03c2!')],
  ['^(?:[\u0390-\u03a2]|[\u03af-\u03c2])+!', 'i', S('\u03b1\u03b1!', '\u03b1\u03b1')],
  ['[\u03b1-\u03c9]', 'i', S('\u0391', '\u03a9', '\u03c2', '\u00b5')],
  ['[\u03b1-\u03c9]', 'iu', S('\u0391', '\u2126', '\u00b5')],
  ['\\s*[\u167f-\u1681]*!', 'i', S('\u1680!', '\u1680')],
  ['\u{10400}', 'iu', S('\u{10428}', '\u{10400}')],
  ['\u{10400}', 'i', S('\u{10428}', '\u{10400}', '\ud801')],
  ['[\u{10400}]', 'iu', S('\u{10428}')],
  ['\u0345', 'iu', S('\u03b9', '\u0399', '\u1fbe')],
  ['\u0345', 'i', S('\u03b9', '\u0399', '\u1fbe')],
  ['\u1fbe', 'i', S('\u03b9', '\u0399', '\u0345')],
  ['(?:k|\u212a|s|\u017f|\u03c3|\u03c2|\u00b5|\u0130|\u0131)+$', 'i', S('kK\u212asS\u017f', '\u03a3\u039c', 'Ii')],
  ['(?:k|\u212a|s|\u017f|\u03c3|\u03c2|\u00b5|\u0130|\u0131)+$', 'iu', S('kK\u212asS\u017f', '\u03a3\u039c', 'Ii')],
  // \b and \B
  ['a\\b', 'iu', S('a\u017f', 'a\u212a', 'a!', 'a')],
  ['a\\b', 'i', S('a\u017f', 'a\u212a')],
  ['a\\B', 'iu', S('a\u017f', 'a!')],
  ['\\b', '', S('', ' ', 'a')],
  ['\\B', '', S('', ' ', 'a', 'ab')],
  ['^\\B$', '', S('')],
  ['\\bfoo\\b', 'i', S('a foo b', 'afoo', 'FOO')],
  ['\\b\u017f', 'iu', S('\u017f', ' \u017f', 'a\u017f')],
  ['\u{1F600}\\b', 'u', S('\u{1F600}a', '\u{1F600}')],
  // astral, with and without u
  ['^\u{1F600}$', '', S('\u{1F600}', '\ud83d')],
  ['^\u{1F600}$', 'u', S('\u{1F600}', '\ud83d')],
  ['^.$', '', S('\u{1F600}', 'a')],
  ['^.$', 'u', S('\u{1F600}', 'a', '\ud83d')],
  ['^..$', 'u', S('\u{1F600}', '\ud83d\ud83d')],
  ['\u{1F600}*', 'u', S('\u{1F600}\u{1F600}', '\ude00')],
  ['^\u{1F600}+$', '', S('\u{1F600}\ude00', '\u{1F600}\u{1F600}')],
  ['^\u{1F600}+$', 'u', S('\u{1F600}\ude00', '\u{1F600}\u{1F600}')],
  ['\\ude00', 'u', S('\u{1F600}', '\ude00', 'a\ude00')],
  ['\\ude00', '', S('\u{1F600}')],
  ['\\ud83d', 'u', S('\u{1F600}', '\ud83d', '\ud83da')],
  ['^\\ud83d\\ude00$', 'u', S('\u{1F600}')],
  ['^\\ud83d\\u{de00}$', 'u', S('\u{1F600}', '\ud83d\ude00')],
  ['^\\u{d83d}\\ude00$', 'u', S('\u{1F600}')],
  ['^\\u{0000000000001F600}$', 'u', S('\u{1F600}')],
  ['^[\u{1F600}-\u{1F64F}]$', 'u', S('\u{1F600}', '\u{1F620}', '\ud83d')],
  ['^[\u{1F600}]$', '', S('\ud83d', '\ude00', '\u{1F600}')],
  ['^[^\u{1F600}]$', 'u', S('\u{1F601}', '\u{1F600}', 'a')],
  ['[^\\0-\\uffff]', 'u', S('\u{1F600}', 'a', '\ud83d')],
  ['^(?:\u{1F600}|.)*$', 'i', S('\u{1F600}\n', '\u{1F600}\u{1F600}')],
  ['\ud83d', 'u', S('\u{1F600}', '\ud83d')],
  ['\ud83d\\ude00', 'u', S('\u{1F600}')],
  ['\\ud83d\ude00', 'u', S('\u{1F600}')],
  ['\ude00', 'u', S('\u{1F600}', 'x\ude00')],
  // \p{...}
  ['^\\p{L}+$', 'u', S('abc\u0414', 'ab1')],
  ['^\\P{L}+$', 'iu', S('12', 'a')],
  ['\\p{Lu}', 'iu', S('a', '\u017f', '1')],
  ['\\p{Ll}', 'iu', S('A', '\u212a', '1')],
  ['\\P{Lu}', 'iu', S('a', 'A')],
  ['[^\\p{Lu}]', 'iu', S('a', 'A')],
  ['^(?:\\p{Script=Cyrillic}|\\p{L})+$', 'u', S('\u0414\u0414!', '\u0414a')],
  ['\\p{sc=Hira}*\\p{sc=Hira}*!', 'iu', S('\u3041\u3041!', '\u3041')],
  ['\\p{So}', 'u', S('\u{1F600}', 'a')],
  // m and s
  ['^b', 'm', S('a\nb', 'a\rb', 'a\u2028b', 'a\u2029b', 'a\u0085b', 'ab')],
  ['a$', 'm', S('a\nb', 'a\rb', 'a\u2028b', 'ab')],
  ['^b', '', S('a\nb')],
  ['a.b', '', S('a\nb', 'a\rb', 'a\u2028b', 'axb', 'a\u0085b')],
  ['a.b', 's', S('a\nb', 'a\rb', 'a\u2028b')],
  ['^$', 'm', S('', '\n', 'a\n', 'a')],
  ['$^', 'm', S('a\n\nb', 'a\nb')],
  ['^.*$', '', S('a\nb')],
  ['^\\n$', 'm', S('\n')],
  // empty branches and nested empty loops
  ['', '', S('', 'a')],
  ['|', '', S('', 'a')],
  ['a|', '', S('', 'b')],
  ['(?:)*', '', S('')],
  ['(?:)+a', '', S('a', '')],
  ['(?:a*)*b', '', S('aab', 'aa', 'b')],
  ['(?:a*)+$', '', S('aa', '')],
  ['(?:a?)*?b', '', S('aab', 'c')],
  ['(?:(?:a*)*)*c', '', S('aaac', 'aaa')],
  ['^(?:a*|b)*$', '', S('ab', 'abba', 'abc')],
  ['^(?:(?:|a)a)+$', 'i', S('aaa', 'aaa!')],
  ['(?:(?:|a)(?:|a))+$', 'i', S('aaa', 'aa!')],
  ['(?:a(?:|))+$', 'i', S('aaa', 'aa!')],
  ['^(?:\\b|a)*$', '', S('aaa', '')],
  ['^(?:$)*a', '', S('a')],
  ['^(?:^)+a', '', S('a')],
  ['(?:^|a)+b', '', S('b', 'ab', 'xb')],
  ['^(?:a|b?)+c$', '', S('ababc', 'abx')],
  ['^(?:x?\u{1F600}?)+$', 'u', S('x\u{1F600}x\u{1F600}', 'x\u{1F600}!')],
  // named groups (captures do not matter)
  ['(?<a>x)(?<b>y)z', '', S('xyz', 'xz')],
  ['(?<\u{1d49c}>.)', 'u', S('a')],
  ['(?<\\u{1d49c}>.)', '', S('a')],
  ['(?<a>.)\\x41', '', S('aA')],
];

// Refused on purpose: V8 merges these case-insensitive branches wrongly without u (see regexvm.js).
const MAY_REFUSE = ['(?:k|\u212a|s|\u017f|\u03c3|\u03c2|\u00b5|\u0130|\u0131)+$'];

test('hand-written edge cases agree with the native engine', () => {
  let compared = 0;
  for (const [p, f, strings] of EDGE) {
    if (!MODIFIERS && HAS_MODIFIER.test(p.replace(/\(\?:/g, ''))) continue; // needs --js-regexp-modifiers
    assert.ok(native(p, f), `the test case /${show(p)}/${f} must be a valid pattern`);
    const refusedOk = /\\1\(a\)|\(a\)\\2|\\k<a>\(/.test(p) || MAY_REFUSE.includes(p) || (ENGINE_QUIRKS.caseModifierGroups && NAMES_I.test(p));
    compared += same(p, f, strings, { mustAccept: !refusedOk });
  }
  assert.ok(compared > 400);
});

// Node 22's --js-regexp-modifiers (V8 12.4) is not a reliable reference: it drops the flag inside
// some alternations ((?i:xa|b) does not match 'xA', (?i:k|x) does not match 'K'). Patterns with
// modifier groups are therefore checked against an oracle built at the same time: the same structure
// with every atom replaced by the explicit class of the test characters it matches under the flags
// in effect (asked of the engine one atom at a time, with plain flags), and ^ $ \b \B written as
// lookarounds over explicit classes. The oracle runs with no flag but u, natively.

const UNIVERSE = (unicode) => {
  const set = new Set();
  for (const x of ALPHABET) for (const c of unicode ? [...x] : x.split('')) set.add(c.codePointAt(0));
  if (unicode) set.add(0x1f600); // a lone lead and a lone trail next to each other
  return [...set].sort((a, b) => a - b);
};
const UNIV = { true: UNIVERSE(true), false: UNIVERSE(false) };
const ORACLE_CACHE = new Map();
function classOf(text, eff, unicode, word = false) {
  const flags = (eff.i ? 'i' : '') + (eff.s && !word ? 's' : '') + (unicode ? 'u' : '');
  const key = `${word}/${flags}/${text}`;
  let cls = ORACLE_CACHE.get(key);
  if (cls !== undefined) return cls;
  const re = word ? new RegExp('\\b', flags) : new RegExp(`^(?:${text})$`, flags);
  const members = UNIV[unicode].filter((c) => re.test(String.fromCodePoint(c)));
  cls = `[${members.map((c) => (unicode ? `\\u{${c.toString(16)}}` : `\\u${c.toString(16).padStart(4, '0')}`)).join('')}]`;
  ORACLE_CACHE.set(key, cls);
  return cls;
}

// One-character atoms only (a quantifier then repeats the same thing in both).
const SINGLE = (unicode) => [
  ...LITERALS.filter((x) => unicode || (x !== '\u{1F600}' && x !== '\\ud83d\\ude00')),
  ...(unicode ? LITERALS_U.filter((x) => !x.includes('}\\u') && !x.includes('d\\u{')) : LITERALS_ANNEX_B.filter((x) => ['\\8', '\\9', '\\377', '\\01', '\\k', '\\p', '\\q', '\\e', '{', '}', ']', '\\_'].includes(x))),
  ...ESCAPES,
  ...(unicode ? ESCAPES_U : []),
  ...CLASSES,
  ...(unicode ? CLASSES_U : CLASSES_ANNEX_B),
].filter((x) => native(`^(?:${x})$`, unicode ? 'u' : ''));
const SINGLES = { true: SINGLE(true), false: SINGLE(false) };
const MODIFIER_OPENS = ['(?i:', '(?-i:', '(?m:', '(?-m:', '(?s:', '(?-s:', '(?ims:', '(?i-ms:', '(?-ims:', '(?sm-i:', '(?i-s:', '(?-is:'];
const NOT_LT = '[^\\n\\r\\u2028\\u2029]';

// V8 tries a lookaround-only match in the middle of a surrogate pair even with u ((?!x) matches at
// index 2 of 'a\u{10428}'), which the spec never does; the leading [^]*? keeps every start on a
// code point boundary.
const oracle = (o, unicode) => native(`^[^]*?(?:${o})`, unicode ? 'u' : '');

function genPair(rng, unicode, eff, depth = 0) {
  const pick = (arr) => arr[Math.floor(rng() * arr.length)];
  const term = () => {
    const r = rng();
    if (r < 0.6) {
      const x = pick(SINGLES[unicode]);
      // in a group of its own, so that \0 then 7 does not read as the octal escape \07
      return [`(?:${x})`, classOf(x, eff, unicode), true];
    }
    if (r < 0.72) {
      const x = pick(ASSERTIONS);
      if (x === '^') return [x, eff.m ? `(?<!${NOT_LT})` : '(?<![^])', false];
      if (x === '$') return [x, eff.m ? `(?!${NOT_LT})` : '(?![^])', false];
      const w = classOf('', eff, unicode, true);
      return [x, x === '\\b' ? `(?:(?<=${w})(?!${w})|(?<!${w})(?=${w}))` : `(?:(?<=${w})(?=${w})|(?<!${w})(?!${w}))`, false];
    }
    if (depth >= 3) {
      const x = pick(LITERALS.slice(0, 20));
      return [x, classOf(x, eff, unicode), true];
    }
    const g = rng();
    if (g < 0.55) {
      const open = pick(MODIFIER_OPENS);
      const inner = { ...eff };
      const [add, remove = ''] = open.slice(2, -1).split('-');
      for (const f of add) inner[f] = true;
      for (const f of remove) inner[f] = false;
      const [bp, bo] = genPair(rng, unicode, inner, depth + 1);
      return [`${open}${bp})`, `(?:${bo})`, true];
    }
    const [bp, bo] = genPair(rng, unicode, eff, depth + 1);
    if (g < 0.75) return [`(?:${bp})`, `(?:${bo})`, true];
    if (g < 0.9) return [`(${bp})`, `(?:${bo})`, true];
    const [cp, co] = genPair(rng, unicode, eff, depth + 1);
    return [`(?:${bp}|${cp})`, `(?:${bo}|${co})`, true];
  };
  const ps = [];
  const os = [];
  const nAlts = rng() < 0.7 ? 1 : 2 + Math.floor(rng() * 2);
  for (let a = 0; a < nAlts; a += 1) {
    let p = '';
    let o = '';
    const nTerms = Math.floor(rng() * 4) + 1;
    for (let t = 0; t < nTerms; t += 1) {
      const [tp, to, quantifiable] = term();
      const q = quantifiable ? pick(quantsFor(tp)) : '';
      p += tp + q;
      o += (quantifiable && !to.startsWith('(') ? `(?:${to})` : to) + q;
    }
    ps.push(p);
    os.push(o);
  }
  return [ps.join('|'), os.join('|')];
}

test('the oracle used for modifier groups agrees with the engine where no modifier is used', () => {
  // the same construction with every group a plain group: oracle and engine must agree
  const rng = mulberry32(0x0dd5eed);
  let n = 0;
  for (let k = 0; k < 1500; k += 1) {
    const f = ['', 'i', 'm', 's', 'u', 'iu', 'imsu', 'ms'][k % 8];
    const unicode = f.includes('u');
    const eff = { i: f.includes('i'), m: f.includes('m'), s: f.includes('s') };
    let [p, o] = genPair(rng, unicode, eff);
    if (/\(\?-?[ims]/.test(p)) continue;
    const re = native(p, f);
    const ro = oracle(o, unicode);
    if (!re || !ro) continue;
    for (let j = 0; j < 12; j += 1) {
      const s = genString(rng);
      assert.equal(ro.test(s), re.test(s), `oracle ${show(o)} for /${show(p)}/${f} on ${show(s)}`);
      n += 1;
    }
    p = o = null;
  }
  assert.ok(n > 3000, `compared ${n}`);
});

test('modifier groups apply their flags to the atoms inside', { skip: !MODIFIERS && 'run with node --js-regexp-modifiers' }, () => {
  // spec answers, written out (Node 22 gets some of them wrong)
  const cases = [
    ['(?i:a)b', '', { Ab: true, AB: false, ab: true }],
    ['(?-i:a)b', 'i', { aB: true, AB: false, Ab: false }],
    ['(?i:x(a)|b)', '', { xA: true, XA: true, B: true, c: false }],
    ['(?i:xa|b)', '', { xA: true }],
    ['(?i:k|x)', '', { K: true, '\u212a': false }],
    ['(?i:k|x)', 'u', { K: true, '\u212a': true }],
    ['(?-i:k)', 'iu', { '\u212a': false, K: false, k: true }],
    ['(?i:\u03a3|})', '', { '\u03c3': true, '\u03c2': true }],
    ['(?i:\\w)', 'u', { '\u017f': true, '\u212a': true }],
    ['(?i:\\b)\u017f', 'u', { 'a\u017f': false, '\u017f': true }],
    ['^\u017f(?i:\\b)', 'u', { '\u017f': true, '\u017fa': false }],
    ['^a(?-i:\\b)', 'iu', { 'a\u017f': true, aa: false }],
    ['(?m:^b)', '', { 'a\nb': true, ab: false }],
    ['(?-m:^b)', 'm', { 'a\nb': false, b: true }],
    ['(?m:a$)', '', { 'a\nb': true }],
    ['(?s:a.b)', '', { 'a\nb': true }],
    ['(?-s:a.b)', 's', { 'a\nb': false, axb: true }],
    ['(?ims:^A.b$)', '', { 'x\na\nB\ny': true }],
    ['(?i-s:a.)', 's', { 'A\n': false, Ax: true }],
    ['(?i:(?-i:a)b)', '', { aB: true, AB: false }],
  ];
  for (const [p, f, want] of cases) {
    if (ENGINE_QUIRKS.caseModifierGroups && NAMES_I.test(p)) {
      // every case-changing case here changes i (none is (?i:...) under i): refused on this engine
      assert.equal(why(p, f), 'unreadable', `/${p}/${f}`);
      continue;
    }
    const m = compileUserRegex(p, f);
    for (const [s, v] of Object.entries(want)) assert.equal(m.test(s), v, `/${p}/${f} on ${show(s)}`);
  }
  const rng = mulberry32(0x30d1f1e5);
  let n = 0;
  for (let k = 0; k < 4000; k += 1) {
    const f = ['', 'i', 'm', 's', 'u', 'iu', 'imsu', 'ms', 'is', 'mu'][k % 10];
    const unicode = f.includes('u');
    const [p, o] = genPair(rng, unicode, { i: f.includes('i'), m: f.includes('m'), s: f.includes('s') });
    if (!native(p, f)) continue;
    const m = ours(p, f);
    if (!m) continue;
    const ro = oracle(o, unicode);
    for (let j = 0; j < 16; j += 1) {
      const s = genString(rng);
      assert.equal(m.test(s), ro.test(s), `/${show(p)}/${f} on ${show(s)} (oracle ${show(o)})`);
      n += 1;
    }
  }
  // where groups that change i are refused, fewer random patterns run
  assert.ok(n > (ENGINE_QUIRKS.caseModifierGroups ? 15000 : 30000), `compared ${n}`);
});

test('case folding of literals and classes matches the engine on every BMP code unit', () => {
  const units = [];
  for (let c = 0; c < 0x10000; c += 1) units.push(String.fromCharCode(c));
  const lits = ['k', 'K', '\u212a', 's', '\u017f', '\u03c3', '\u03c2', '\u00b5', '\u03bc', 'i', '\u0130', '\u0131', '\u00df', '\u1e9e', '\u00c5', '\u03b8', '\u0345', '\u1fd3', '\u01c5', 'a', '\u4e00', '\u0414', '\u10a0', '\u13a0', '\uab70'];
  for (const f of ['i', 'iu']) {
    for (const l of lits) {
      const m = compileUserRegex(`^${l}$`, f);
      const re = new RegExp(`^${l}$`, f);
      for (const s of units) if (m.test(s) !== re.test(s)) assert.fail(`/${show(l)}/${f} on ${show(s)}`);
    }
    for (const cls of ['[^k]', '\\w', '\\W', '[a-z]', '[\u0390-\u03a2]', '[^\u03c3]', '.']) {
      const pc = `^${cls}$`;
      const mc = compileUserRegex(pc, f);
      const rc = new RegExp(pc, f);
      for (const s of units) if (mc.test(s) !== rc.test(s)) assert.fail(`${show(pc)}/${f} on ${show(s)}`);
    }
    // all of them at once. The reference is the union of the literals one by one: V8 12.4 merges
    // k|K|\u212a under i (without u) and then misses the Kelvin sign that /\u212a/i matches
    // (likewise s|S|\u017f); J-Wicket follows each literal, as the engine does for one literal.
    const p = `^(?:${lits.join('|')})$`;
    if (f === 'i' && ENGINE_QUIRKS.mergesFoldedBranches) {
      assert.equal(why(p, f), 'unreadable'); // this engine merges these branches wrongly without u: refused
      continue;
    }
    const m = compileUserRegex(p, f);
    const each = lits.map((l) => new RegExp(`^${l}$`, f));
    for (const s of units) if (m.test(s) !== each.some((re) => re.test(s))) assert.fail(`${show(p)}/${f} on ${show(s)}`);
  }
  // astral literals under iu: every code point of plane 1
  for (const l of ['\u{10400}', '\u{10428}', '\u{1E900}', '\u{16E40}']) {
    const m = compileUserRegex(`^${l}$`, 'iu');
    const re = new RegExp(`^${l}$`, 'iu');
    for (let c = 0x10000; c < 0x20000; c += 1) {
      const s = String.fromCodePoint(c);
      if (m.test(s) !== re.test(s)) assert.fail(`/${show(l)}/iu on U+${c.toString(16)}`);
    }
  }
});

// --- 2. the adversarial hunt ------------------------------------------------------------------------

const cjk = (n, base = 0x4e00) => Array.from({ length: n }, (_, k) => String.fromCharCode(base + k));
const nest = (levels, body, q) => {
  let s = body;
  for (let k = 0; k < levels; k += 1) s = `(?:${s})${q}`;
  return s;
};
const reps100 = [
  ...[...'abcdefghijklmnopqrstuvwxyz0123456789'].map((c) => `${c}*`),
  ...[...' !"#%&\',-/:;<=>@_`~'].map((c) => `${c}*`),
  ...[...'$()*+.?[\\]^{|}'].map((c) => `\\${c}*`),
  '\\0*',
  ...[...'ABCDEFGHIKLNOPQRSTUVWXYZ'].map((c) => `\\c${c}*`),
  ...['1b', '1c', '1d', '1e', '1f', '7f'].map((h) => `\\x${h}*`),
].join('');
const E = '\u{1F600}';
const A = (n) => 'a'.repeat(n);

// [pattern, flags, slow input] for each of the 97 findings in rxhunt/hunt-findings.json, in order.
// Findings whose cost was the old check itself get a 2048-character line of the pattern's characters.
const HUNT = [
  ['(?:\\c|\\\\c)+$', 'i', '\\c'.repeat(27) + '!'],
  ['^(?:\u{1F600}|.)*$', 'i', E.repeat(27) + '\n'],
  ['^(?:\u{1F600}|\u{1F600})+$', 'u', E.repeat(27) + '!'],
  ['^(?:[\u{1F600}-\u{1F64F}]|.)+!$', 'u', E.repeat(26)],
  ['^(?:\\p{Script=Cyrillic}|\\p{L})+$', 'u', '\u0414'.repeat(25) + '!'],
  ['^(?:[^a-z]|[A-Z])+$', '', 'A'.repeat(27) + 'a'],
  ['^(?:(?-i:[^k])|k)+!$', 'iu', '\u212a'.repeat(26)],
  ['.*\u03c3\u03c2.*$', 'i', '\u03c3'.repeat(2047) + '\n'],
  ['.*\\cI\\t.*$', '', '\t'.repeat(2047) + '\n'],
  ['.*=\\u{0000003d}.*$', 'u', '='.repeat(2047) + '\n'],
  ['^(?:[\\377]|.)+!$', 'i', '\u00ff'.repeat(28)],
  ['(a{1,0000000000000000000000100})+$', 'i', A(28) + '!'],
  ['.*ab.*$', 'i', 'ab'.repeat(1023) + '\n'],
  [`(?:${cjk(1022).join('|')})`, 'i', cjk(1022).join('') + cjk(1022).join('').slice(0, 1026)],
  [`(?:${cjk(1018).join('')})*(?:${cjk(1018, 0x5800).join('')})*`, 'i', cjk(1018).join('') + cjk(1030, 0x5800).join('')],
  ['(?:(?:|a)a)+$', 'i', A(37) + '!'],
  ['(?:(?:a|b?)a)+$', 'i', A(37) + '!'],
  ['(?:(?:a|(?=a))a)+$', 'i', A(37) + '!'],
  ['(?:(?:|a)(?:|a))+$', 'i', A(19) + '!'],
  ['(?:(?:ab){1,2})+$', 'i', 'ab'.repeat(36) + '!'],
  ['(?:(?:ab)?ab)+$', 'i', 'ab'.repeat(36) + '!'],
  ['.*(?=.*x)', 'i', A(2048)],
  ['.*(?<=x.*)', 'i', A(2048)],
  ['(a*)(?=\\1)(?=\\1)(?=\\1)(?=\\1)b', 'i', A(2048)],
  ['(a+){0,99999999999999999999999}$', 'i', A(26) + '!'],
  ['(?:a?a?a?a?a?a?a?a?a?a?)(?:a?a?a?a?a?a?a?a?a?a?)(?:a?a?a?a?)$', 'i', A(63) + '!'],
  ['.*ab.*!', 'i', 'ab'.repeat(1024)],
  ['.*s\u017f.*!', 'iu', 's'.repeat(2048)],
  ['\\p{sc=Hira}*\\p{sc=Hira}*!', 'iu', '\u3041'.repeat(2048)],
  [cjk(1024).map((c) => `${c}*`).join(''), 'i', cjk(1024).join('').repeat(2)],
  [`(?:${cjk(1022).join('|')})`, 'i', cjk(2048, 0x5000).join('')],
  [`(?:${cjk(1020).map((c) => `${c}?`).join('')}x)+`, 'i', cjk(1020).join('').repeat(2).slice(0, 2048)],
  ['\\w*.{0,3}.{0,3}.{0,3}.{0,3}.{0,3}!', 'i', A(2048)],
  ['\\w*\\w{1000}!', 'i', A(2048)],
  ['\\w{0,1000000000000000000000}\\w{0,1000000000000000000000}!', 'i', A(2048)],
  ['(?:a{0000000000000000000000000000001,})+!', 'i', A(30)],
  ['.*\u00b5\u03bc.*!', 'i', '\u03bc'.repeat(2048)],
  ['.*\\xx.*!', 'i', 'x'.repeat(2048)],
  ['.*[^\\0-\u4fff\u5001-\uffff].*!', 'i', '\u5000'.repeat(2048)],
  ['\\w*(?=\\w*!)', 'i', A(2048)],
  ['.*ab.*c', 'i', 'ab'.repeat(1024)],
  ['^.*ab.*ab.*c', 'i', 'ab'.repeat(1024)],
  [cjk(1024).map((c) => `${c}*`).join(''), 'i', cjk(2048).join('')],
  [`(?:${cjk(1020).join('|')})+`, 'i', cjk(1020).join('').repeat(2).slice(0, 2048)],
  [`(?:${cjk(1000).map((c) => `${c}?`).join('')}z)+`, 'i', cjk(1000).join('').repeat(3).slice(0, 2048)],
  ['(?:\u{1F600}{1,4})+$', 'u', E.repeat(28) + '!'],
  ['\u{1F600}*\u{1F600}*\u{1F600}*!', 'u', E.repeat(500)],
  ['(?:\\W|\u017f)+$', 'u', '\u017f'.repeat(25) + 'a'],
  ['(?:|y){1000000}z', 'i', 'x'.repeat(2048)],
  ['a?a?ba?a?c'.repeat(13) + 'd', 'i', 'abac'.repeat(13) + '!'],
  ['(?:a|a|a|a|a|a)?'.repeat(10) + 'b', 'i', A(10) + '!'],
  [Array(511).fill('.*a').join('|'), 'i', '!'.repeat(2048)],
  ['(?:'.repeat(15) + 'x' + '^'.repeat(1932) + '){2}'.repeat(15), 'i', 'x'.repeat(2048)],
  ['\\S*(?:=\\s*)\\S*!', 'i', '='.repeat(2048)],
  ['\\w*(?:a|-+)\\w*!', 'i', A(2048)],
  ['^\\S*(?:=\\s*)\\S*(?:=\\s*)\\S*!', 'i', '='.repeat(2048)],
  ['\u{1F600}*\u{1F600}*\u{1F600}*!', 'u', E.repeat(600)],
  ['.*\u{1F600}.*!', 'u', E.repeat(1024)],
  ['(?:a|a|a|a|a|a|a|a|a|a)?'.repeat(6) + '!', 'i', A(2048)],
  [nest(15, `y${'[]?'.repeat(647)}z`, '{2}'), 'i', 'y'.repeat(2048)],
  [nest(15, `y${'a{0}'.repeat(485)}z`, '{2}'), 'i', 'yz'.repeat(1024)],
  [reps100 + '.'.repeat(2048 - reps100.length), '', 'abc!'.repeat(512)],
  ['(?:\u{1F600}|\u{1F600})+$', 'u', E.repeat(25) + '!'],
  ['^(?:x?\u{1F600}?)+$', 'u', ('x' + E).repeat(24) + '!'],
  ['(?:[\u{1F600}]|[\u{1F600}])+$', 'u', E.repeat(25) + '!'],
  [`[${'\\p{C}'.repeat(203)}][${'\\p{L}'.repeat(203)}]`, 'u', '\u0001a'.repeat(1024)],
  ['(?:(?!a?a?a?a?a?a?a?a?a?a?b).)*!', 'i', A(2048)],
  ['(?:(?!a{1000}b).)*!', 'i', A(2048)],
  ['(.*)\u03b1\u03b2\\1!', 'i', '\u03b1\u03b2'.repeat(1024)],
  ['(?:|a)'.repeat(18) + '!', 'i', A(2048)],
  ['(?:(?=a)|a)'.repeat(17) + '!', 'i', A(2048)],
  ['.*(?:b|a)a.*!', 'i', A(2048)],
  ['\\w*(?:-|_)_\\w*!', 'i', '_'.repeat(2048)],
  ['.*a(?:b|a){1,3}.*!', 'i', A(2048)],
  ['.*,\\d+,.*!', 'i', ',1'.repeat(1024)],
  ['.*a-+a.*!', 'i', 'a-'.repeat(1024)],
  ['\u{1F600}+[^\\uDE00]*!', 'u', E.repeat(1024)],
  ['[\u{1F600}]*.*!', 'u', E.repeat(1024)],
  ['[^\\0-\uffff]*.*!', 'u', E.repeat(1024)],
  ['[^x]*X[^x]*!', '', 'X'.repeat(2048)],
  [(() => {
    let s = '';
    for (let k = 0; s.length < 2046; k += 1) s += `[${String.fromCharCode(0x4e00 + k)}${String.fromCharCode(0x4e01 + k)}]${String.fromCharCode(0x4e01 + k)}`;
    return s.slice(0, s.lastIndexOf('['));
  })(), 'i', cjk(2048).join('')],
  [`(?:${cjk(1018).join('')})(?:${cjk(1017, 0x5200).join('')}\u51f9)`, 'i', cjk(1018).join('') + cjk(1030, 0x5200).join('')],
  ['\\w*\u{1F600}?\\w*!', 'u', A(2048)],
  ['^(?:\u{1F600}|\\p{So})+$', 'u', E.repeat(26) + 'a'],
  ['^(?:\u{1F600}?\u{1F600})+$', 'u', E.repeat(40) + 'x'],
  ['\\k<(?:a+)+b>', 'i', 'k<' + A(26)],
  ['\\k<.*.*.*>', 'i', 'k<' + A(2046)],
  ['(?:[a-z](?:-?|_?))+$', 'i', 'abcdefghijklmnopqrstuvwxyz!'],
  ['(?:a(?:|))+$', 'i', A(26) + '!'],
  [nest(16, Array(635).fill('[]').join('|'), '{1,2}'), 'i', 'x'.repeat(2048)],
  [nest(15, Array(648).fill('[]').join('|'), '{2}'), 'i', 'x'.repeat(2048)],
  [`(?:${'()'.repeat(1000)}\\w)*!`, 'i', A(2048)],
  [`(?:${'()'.repeat(70)}\\w)*!`, 'i', A(2048)],
  ['[\u0390-\u03a2]*[\u03af-\u03c2]*!', 'i', '\u03b1'.repeat(2048)],
  ['^(?:[\u0390-\u03a2]|[\u03af-\u03c2])+!', 'i', '\u03b1'.repeat(26)],
  ['\\s*[\u167f-\u1681]*!', 'i', '\u1680'.repeat(2048)],
  ['^(?:\\s|[\u167f-\u1681])+!', 'i', '\u1680'.repeat(26)],
];

test('every pattern of the adversarial hunt is refused or tests its slow input fast', () => {
  assert.equal(HUNT.length, 97);
  let accepted = 0;
  const slow = [];
  for (const [p, f, input] of HUNT) {
    if (!MODIFIERS && HAS_MODIFIER.test(p.replace(/\(\?:/g, ''))) {
      accepted += 1; // needs --js-regexp-modifiers (checked when run with it)
      continue;
    }
    assert.ok(native(p, f), `hunt pattern must be valid: ${show(p.slice(0, 60))}`);
    const t0 = performance.now();
    let m;
    try {
      m = compileUserRegex(p, f);
    } catch (e) {
      assert.ok(e instanceof RegexUnsupported, String(e));
      assert.ok(performance.now() - t0 < 50, `refusing ${show(p.slice(0, 40))} took too long`);
      continue;
    }
    accepted += 1;
    m.test(input);
    const t1 = performance.now();
    m.test(input);
    const t2 = performance.now();
    // first call includes compile and every first native atom answer; the second is the steady line
    if (t1 - t0 > 50 * 2 || t2 - t1 > 50) slow.push(`${show(p.slice(0, 50))}/${f}: compile+first ${(t1 - t0).toFixed(1)} ms, again ${(t2 - t1).toFixed(1)} ms`);
  }
  assert.deepEqual(slow, []);
  assert.ok(accepted >= 60, `accepted only ${accepted}`);
});

test('hunt patterns that run give the native answer on short inputs', () => {
  for (const [p, f] of HUNT) {
    if (p.length > 200 || (!MODIFIERS && HAS_MODIFIER.test(p.replace(/\(\?:/g, '')))) continue;
    // a million iterations that may each take y: the native engine itself backtracks for hours on
    // 'xy', so it is no reference here (the pattern is the same as z: see round 4 below)
    if (/\{\d{6,}\}/.test(p)) continue;
    const m = ours(p, f);
    if (!m) continue;
    // short versions of the slow inputs, safe for the native engine
    const shortInputs = ['', 'a', 'aa!', 'ab!', '\\c\\c', '\u{1F600}\u{1F600}!', '\u212ak!', '\u03c3\u03c2', '\t\t', '==', '\u00ff!', 'k<ab>', 'abc', '_-_', ',1,!', 'a-a!', 'X!', '\u0414a', '\u017fs!', '\u1680!', '\u03b1!', 'xy', 'z'];
    for (const s of shortInputs) assert.equal(m.test(s), new RegExp(p, f).test(s), `/${show(p)}/${f} on ${show(s)}`);
  }
});

// --- 3. linear time ---------------------------------------------------------------------------------

function timeLine(m, s, runs = 5) {
  m.test(s); // warm the atom caches
  const ts = [];
  for (let k = 0; k < runs; k += 1) {
    const t = performance.now();
    m.test(s);
    ts.push(performance.now() - t);
  }
  ts.sort((x, y) => x - y);
  return ts[Math.floor(runs / 2)];
}

// The shapes that keep the most states alive at every position, each as large as MAX_STATES allows.
function largest(make) {
  let lo = 1;
  let hi = MAX_STATES;
  while (lo < hi) {
    const mid = Math.ceil((lo + hi) / 2);
    let ok = true;
    try {
      compileUserRegex(make(mid), 'u');
    } catch (_e) {
      ok = false;
    }
    if (ok) lo = mid;
    else hi = mid - 1;
  }
  return make(lo);
}
// A part at the start that can match empty is dropped (round 4: R{0,n}S is S), so the shapes whose
// body can match empty start with [^!], which every character of their lines matches.
const WORST = [
  [largest((n) => `[^!](?:.?){${n}}!`), '', (n) => 'a'.repeat(n)],
  [largest((n) => `[^!](?:a?){${n}}!`), 'i', (n) => 'A'.repeat(n)],
  [largest((n) => `(?:\\b|.){${n}}!`), '', (n) => 'a b '.repeat(n / 4)],
  [largest((n) => `(?:\\b|\\B|.){${n}}!`), 'iu', (n) => 'a\u017f b'.repeat(n / 4)],
  [largest((n) => `[^!](?:.*){${n}}!`), '', (n) => 'a'.repeat(n)],
  [largest((n) => `[^!](?:[^!]?){${n}}!`), 'u', (n) => '\u{1F600}'.repeat(n / 2)],
  [largest((n) => `[^!](?:${'a|'.repeat(n)}a)*!`), 'i', (n) => 'a'.repeat(n)],
  [largest((n) => `(?:\\w|\\s|\\d|.|\\W){${n}}!`), 'm', (n) => 'a1 -'.repeat(n / 4)],
  [largest((n) => `[^!](?:^|$|\\B|a?){${n}}!`), 'm', (n) => 'a\na\n'.repeat(n / 4)],
];

test('test time grows linearly with the line, and the worst line stays fast', () => {
  const report = [];
  for (const [p, f, mk] of WORST) {
    const m = compileUserRegex(p, f);
    assert.ok(m.states <= MAX_STATES);
    const t512 = timeLine(m, mk(512));
    const t1024 = timeLine(m, mk(1024));
    const t2048 = timeLine(m, mk(2048));
    report.push(`${p.slice(0, 24)} ${m.states} states: ${t512.toFixed(1)} / ${t1024.toFixed(1)} / ${t2048.toFixed(1)} ms`);
    // linear: four times the line costs about four times as much (generous for timer noise)
    assert.ok(t2048 <= t512 * 4 * 2 + 2, `not linear: ${report.at(-1)}`);
    // the worst line: about 25 ms on the reference machine; the bound here leaves room for a loaded CI host
    assert.ok(t2048 < 120, `too slow: ${report.at(-1)}`);
  }
  if (process.env.REGEXVM_REPORT) console.log(report.join('\n'));
});

test('a line of distinct characters against the most native atoms stays fast', () => {
  // MAX_CLASS_ATOMS heavy classes, all alive at every position, on 2048 distinct code points
  const classes = Array.from({ length: MAX_CLASS_ATOMS }, (_, k) => (k < MAX_PROPERTY_ESCAPES ? `[\\p{L}${String.fromCodePoint(0x4e00 + k)}]${k ? '?' : ''}` : `[^\\s\\d${String.fromCodePoint(0x4e00 + k)}]?`));
  const p = `${classes.join('')}!`;
  const m = compileUserRegex(p, 'iu');
  const s = Array.from({ length: 2048 }, (_, k) => String.fromCodePoint(0x3400 + k * 7)).join('');
  const t0 = performance.now();
  m.test(s);
  const first = performance.now() - t0;
  const again = timeLine(m, s, 3);
  if (process.env.REGEXVM_REPORT) console.log(`native atoms: first line ${first.toFixed(1)} ms, again ${again.toFixed(1)} ms`);
  assert.ok(first < 250, `first line ${first.toFixed(1)} ms`);
  assert.ok(again < 60, `again ${again.toFixed(1)} ms`);
});

// A line of 2047 BMP code units never seen before (line k of a run), without '~'.
function freshLine(k, base = 0x100) {
  let s = '';
  for (let j = 0; j < 2047; j += 1) {
    let c = base + ((k * 2047 + j) % 0xf000);
    if (c >= 0xd800 && c < 0xe000) c += 0x800;
    s += String.fromCharCode(c);
  }
  return s;
}

test('a run of lines of never-seen characters against the most native atoms stays fast on every line', () => {
  // Each native atom asks the engine once per character it has not seen. The answers used to be kept
  // in one Map per atom, and the MAX_CLASS_ATOMS Maps grew (and rehashed) together inside one test():
  // about 30 ms per line, over 60 ms on the 17th. They are kept in typed blocks of 256 now.
  // the first class is not optional: a part at the start that can match empty is dropped (round 4)
  const p = `(?:${Array.from({ length: MAX_CLASS_ATOMS }, (_, j) => `[^\\x${(0x41 + j).toString(16)}]${j ? '?' : ''}`).join('')})~`;
  const m = compileUserRegex(p, '');
  const re = new RegExp(p);
  const times = [];
  for (let k = 0; k < 33; k += 1) {
    const line = freshLine(k);
    const t0 = performance.now();
    const got = m.test(line);
    times.push(performance.now() - t0);
    assert.equal(got, false, `line ${k}`);
  }
  assert.equal(m.test('x~'), re.test('x~'));
  const sorted = [...times].sort((a, b) => a - b);
  const median = sorted[sorted.length >> 1];
  if (process.env.REGEXVM_REPORT) console.log(`fresh lines: median ${median.toFixed(1)} ms, worst ${sorted.at(-1).toFixed(1)} ms`);
  assert.ok(median < 20, `median line ${median.toFixed(1)} ms`);
  assert.ok(sorted.at(-1) < 60, `worst line ${sorted.at(-1).toFixed(1)} ms (line ${times.indexOf(sorted.at(-1))})`);
});

test('the per-character caches of all patterns together stay within their budget', () => {
  // Many patterns of MAX_CLASS_ATOMS different classes, each fed tens of thousands of different
  // characters: the caches used to keep up to 512 x 65535 answers (about 0.9 GB in Node 22).
  const { budget } = cacheUse();
  let most = 0;
  let emptied = false;
  let last = cacheUse().bytes;
  for (const flags of ['', 'u']) {
    const pats = [];
    for (let k = 0; k < 6; k += 1) {
      const atoms = Array.from({ length: MAX_CLASS_ATOMS }, (_, j) => `[^\\x${(0x41 + j).toString(16)}${String.fromCharCode(0x61 + k)}${j}]${j ? '?' : ''}`);
      pats.push(compileUserRegex(`(?:${atoms.join('')})~`, flags));
    }
    for (let k = 0; k < 24; k += 1) {
      const line = flags ? Array.from({ length: 1023 }, (_, j) => String.fromCodePoint(0x20000 + k * 1023 + j)).join('') : freshLine(k);
      for (const m of pats) {
        assert.equal(m.test(line), false);
        const use = cacheUse();
        if (use.bytes < last) emptied = true;
        last = use.bytes;
        most = Math.max(most, use.bytes);
        assert.ok(use.bytes <= budget, `${use.bytes} bytes cached, budget ${budget}`);
      }
    }
    for (const m of pats) {
      assert.equal(m.test('z~'), true);
      assert.equal(m.test('\u{20000}~'), true);
    }
  }
  assert.ok(emptied, 'the budget was reached and the caches emptied');
  assert.ok(most > budget / 2, `${most} bytes at most`);
});

// --- 4. refusals ------------------------------------------------------------------------------------

function why(p, f = '') {
  try {
    compileUserRegex(p, f);
  } catch (e) {
    if (e instanceof RegexUnsupported) {
      assert.equal(e.name, 'RegexUnsupported');
      assert.equal(typeof e.message, 'string');
      assert.ok(Number.isInteger(e.at) && e.at >= 0 && e.at <= p.length, `offset ${e.at}`);
      return e.why;
    }
    throw e;
  }
  return null;
}

test('lookaround and back-references are refused with a plain message', () => {
  for (const [p, f] of [['(?=a)', ''], ['a(?!b)', ''], ['(?<=a)b', ''], ['(?<!a)b', 'u'], ['(?=a)*b', ''], ['x|(?:(?=y))', 'i']]) assert.equal(why(p, f), 'lookaround', p);
  for (const [p, f] of [['(a)\\1', ''], ['\\1(a)', ''], ['(a)\\1', 'u'], ['(?<n>a)\\k<n>', ''], ['(?<n>a)\\k<n>', 'u'], ['\\k<n>(?<n>a)', ''], ['(a)(b)(c)(d)(e)(f)(g)(h)\\8', ''], ['((((((((((a))))))))))\\10', ''], ['(.*)\u03b1\u03b2\\1!', 'i']]) {
    assert.equal(why(p, f), 'backreference', p);
  }
  try {
    compileUserRegex('ab(?=c)', '');
    assert.fail('not refused');
  } catch (e) {
    assert.equal(e.at, 2);
    assert.match(e.message, /lookahead or lookbehind/);
    assert.match(e.message, /Write the pattern without/);
  }
  try {
    compileUserRegex('(a)x\\1', '');
    assert.fail('not refused');
  } catch (e) {
    assert.equal(e.at, 4);
    assert.match(e.message, /back-references/);
  }
});

test('the engine quirks are probed on the engine that runs the module', () => {
  assert.equal(ENGINE_QUIRKS.mergesFoldedBranches, !new RegExp('^(?:k|K|\u212a)$', 'i').test('\u212a') || !new RegExp('^(?:s|S|\u017f)$', 'i').test('\u017f') || !new RegExp('^(?:xk|xK|x\u212a)$', 'i').test('x\u212a'));
  assert.equal(ENGINE_QUIRKS.notWordBoundaryInsidePairs, new RegExp('\\B', 'u').test('a\u{1F600}a'));
  // the spec answers of caseModifierGroupsDiffer's probes, which V8 12.4 or 13.6 gets wrong
  const probes = [
    ['(?i:\\u039c)', '', '\u00b5', true],
    ['(?-i:\\u039c)', 'i', '\u00b5', false],
    ['(?i:x)\\w', 'u', 'x\u212a', false],
    ['(?-i:x)\\W', 'iu', 'xk', false],
    ['(?i:x)?k', '', 'xK', false],
    ['(?i:ab)|ac|AD', '', 'Ac', false],
  ];
  assert.equal(ENGINE_QUIRKS.caseModifierGroups, MODIFIERS && probes.some(([p, f, str, spec]) => new RegExp(p, f).test(str) !== spec));
  // V8 12.4 (Node 22, with --js-regexp-modifiers) and 13.6 (Node 24) have all three quirks; Chrome 158 has none.
  assert.ok(Object.isFrozen(ENGINE_QUIRKS));
});

// The round-2 findings on modifier groups: [pattern, flags, line, spec answer]. V8 12.4 and 13.6
// answer differently for a one-byte line (all Latin-1) than for the same characters stored two-byte,
// leak a group's i into a later \w, \W or literal, merge branches with different case flags, and
// even answer differently after other patterns ran. Chrome 158 gives the spec answer every time.
const CASE_GROUPS = [
  ['(?i:\u03bcs)', '', 'took 5\u00b5s', true],
  ['latency (?i:\\u039c)s', '', 'latency \u00b5s', true],
  ['(?i:\\u0178)', '', '\u00ff', true],
  ['(?i:[\\u0370-\\u03ff])', '', '\u00b5', true],
  ['(?i:[\\u0100-\\u024f])', '', '\u00ff', true],
  ['(?i:\\u212a)', 'u', 'k', true],
  ['(?i:\\u017f)', 'u', 'S', true],
  ['x(?i:\\u017f)', 'u', 'xs', true],
  ['(?i:\\u1e9e)', 'u', 'stra\u00dfe', true],
  ['(?i:\\u212b)', 'u', '\u00e5', true],
  ['(?-i:\\u039c)', 'i', '\u00b5', false],
  ['(?-i:\\u03bc)', 'i', '\u00b5', false],
  ['(?-i:\\u0178)', 'i', '\u00ff', false],
  ['(?-i:\\u{39c})', 'iu', '\u00b5', false],
  ['(?-i:\\u{178})', 'iu', '\u00ff', false],
  ['(?i:deny)|drop|DISCARD', '', 'Drop', false],
  ['(?i:ab)|ac|AD', '', 'Ac', false],
  ['(?i:ab)|ac|AD', '', 'ad', false],
  ['ab|(?i:ac)|ad', '', 'Ad', false],
  ['(?i:ab|ac)|ad', '', 'AD', false],
  ['Aa|(?i:ab)|(?i:ac)', '', 'aa', false],
  ['(?i:xa|xb)|xc', '', 'XA', true],
  ['(?i:xa|xb)|xc', '', 'Xc', false],
  ['(?i:x)\\w', 'u', 'x\u212a', false],
  ['(?i:x)|\\w', 'u', '\u212a', false],
  ['(?i:x)[^\\W]', 'u', 'x\u017f', false],
  ['(?-i:ID)\\W', 'iu', 'IDs', false],
  ['(?-i:ID)\\W', 'iu', 'IDk', false],
  ['(?-i:x)[^\\W]', 'iu', 'xk', true],
  ['(?-i:x)|\\W', 'iu', 'k', false],
  ['(?i:x)?k', '', 'xK', false],
  ['(?i:x)+k', '', 'xK', false],
  ['(?-i:x)?k', 'i', 'K', true],
  ['(?-i:[a-z]+)', 'i', 'Q', false],
  ['(?-i:[b]+)', 'i', 'B', false],
  ['^(?-i:[a-z]*)$', 'i', 'Q', false],
  ['(?-i:i{1,3})', 'iu', 'IS', false],
  ['(?i-s:k^\u0130|\\x41(?:a|)*)', 'm', '\udc00\u03c2\ude00\u0000\u00e9\u0000\u{10428}\u00c9\u{10428}k\u0000iI\n.a\u00c9', true],
];

test('groups that change i are refused only where the engine applies them wrongly (round 2)', { skip: !MODIFIERS && 'run with node --js-regexp-modifiers' }, () => {
  for (const [p, f, line, spec] of CASE_GROUPS) {
    if (ENGINE_QUIRKS.caseModifierGroups) {
      assert.equal(why(p, f), 'unreadable', `/${show(p)}/${f}`);
      continue;
    }
    // the spec answer, on the line as written and on the same characters stored two-byte
    const m = compileUserRegex(p, f);
    assert.equal(m.test(line), spec, `/${show(p)}/${f} on ${show(line)}`);
    assert.equal(new RegExp(p, f).test(line), spec, `native /${show(p)}/${f} on ${show(line)}`);
    assert.equal(m.test(`${line}\u0100`), new RegExp(p, f).test(`${line}\u0100`), `/${show(p)}/${f} on ${show(line)} + U+0100`);
  }
  if (ENGINE_QUIRKS.caseModifierGroups) {
    let e = null;
    try {
      compileUserRegex('x(?-i:ID)\\W', 'iu');
    } catch (err) {
      e = err;
    }
    assert.equal(e.at, 1);
    assert.equal(e.length, 5);
    assert.equal(e.message, "This browser does not apply the i of a group such as '(?-i:' (at character 2) the way the standard does, so J-Wicket does not run it here. Put the i flag on the whole pattern or leave it off, and write the letters whose case matters as classes such as [Dd]rop.");
  }
  // Groups that leave i as it is, or change only m and s, run everywhere and give the native
  // answer on one-byte and two-byte lines alike (fuzzed: 0 differences in 1.6 million tests).
  const keep = [
    ['(?i:\u03bcs)', 'i', ['took 5\u00b5s', 'x']],
    ['(?-i:\\u039c)', '', ['\u00b5', '\u039c']],
    ['(?i:x)\\w', 'iu', ['x\u212a', 'xk', 'x!']],
    ['(?-i:ID)\\W', 'u', ['IDs', 'ID!', 'IDk']],
    ['(?i:deny)|drop|DISCARD', 'i', ['Drop', 'dEnY', 'discard']],
    ['(?i-s:a.)', 'is', ['A\n', 'Ax']],
    ['(?s:a.b)|(?m:^c$)', '', ['a\nb', 'x\nc\ny', 'c']],
    ['(?-s:a.)(?-m:^b)', 'ms', ['a\nb', 'axb', 'ax\nb']],
    ['(?ms:^\u00b5.$)', 'i', ['\u039c\n', 'x\n\u00b5\n']],
  ];
  for (const [p, f, lines] of keep) same(p, f, [...lines, ...lines.map((l) => `${l}\u0100`)], { mustAccept: true });
});

test('two case-insensitive branches run in every engine and give the native answer', () => {
  // V8 never rewrites a disjunction of two branches, so these run even where the engine merges
  // three or more; they were refused before. Smart case adds i to /stra\u00dfe|stra\u1e9ee/
  // (\u1e9e is no capital A-Z), so an operator met this with a message that blamed the browser.
  const cases = [
    ['stra\u00dfe|stra\u1e9ee', { 'stra\u00dfe': true, 'STRA\u00dfE': true, 'stra\u1e9ee': true, strasse: false, 'Stra\u00dfe': true }],
    ['k|K', { k: true, K: true, '\u212a': false }],
    ['k|\u212a', { k: true, K: true, '\u212a': true }],
    ['s|\u017f', { s: true, S: true, '\u017f': true }],
    ['\u00df|\u1e9e', { '\u00df': true, '\u1e9e': true, ss: false }],
    ['\u00c5|\u00e5', { '\u00c5': true, '\u00e5': true, '\u212b': false }],
    ['\u03a9|\u03c9', { '\u03a9': true, '\u03c9': true, '\u2126': false }],
    ['ka|Kb', { KA: true, kb: true, '\u212aa': false }],
    ['\u0390|\u1fd3', { '\u0390': true, '\u1fd3': true }],
    ['(?:\u212a|k)x', { kx: true, '\u212ax': true, KX: true }],
    ['x(?:\u00df|\u1e9e)', { 'x\u00df': true, 'X\u1e9e': true }],
    ['k\u212a|x', { 'k\u212a': true, 'K\u212a': true, X: true, kk: false }], // without u, \u212a matches only itself
    ['[k]|K|\u212a', { k: true, '\u212a': true }], // only two branches are literals: never merged
    ['^(?:k|\\w|\u212a)$', { k: true, '\u212a': true, '!': false }],
  ];
  for (const [p, expect] of cases) {
    const re = new RegExp(p, 'i');
    const m = compileUserRegex(p, 'i');
    for (const [s, spec] of Object.entries(expect)) {
      assert.equal(m.test(s), spec, `/${show(p)}/i on ${show(s)}`);
      assert.equal(re.test(s), spec, `native /${show(p)}/i on ${show(s)}`);
    }
  }
});

test('three or more case-insensitive literal branches are refused only where the engine merges them wrongly', () => {
  // /^(?:k|K|\u212a)$/i.test('\u212a') is false in V8 12.4 and 13.6, true by the spec and in Chrome 158
  const three = [
    ['k|K|\u212a', '\u212a'],
    ['^(?:s|S|\u017f)$', '\u017f'],
    ['kk|kK|k\u212a', 'k\u212a'],
    ['xk|xK|x\u212a', 'x\u212a'],
    ['stra\u00dfe|strasse|stra\u1e9ee', 'stra\u1e9ee'],
  ];
  for (const [p, s] of three) {
    if (ENGINE_QUIRKS.mergesFoldedBranches) {
      assert.equal(why(p, 'i'), 'unreadable', p);
    } else {
      assert.equal(compileUserRegex(p, 'i').test(s), true, p);
      assert.equal(new RegExp(p, 'i').test(s), true, `native ${p}`);
    }
    assert.equal(why(p, 'iu'), null, p);
    assert.equal(why(p, ''), null, p);
  }
  for (const p of ['kafka|kibana|kube', 'k|x|s', '[kK\u212a]', 'a|b|c|\u00e9']) assert.equal(why(p, 'i'), null, p);
  if (ENGINE_QUIRKS.mergesFoldedBranches) {
    const e = (() => {
      try {
        compileUserRegex('k|K|\u212a', 'i');
      } catch (err) {
        return err;
      }
      return null;
    })();
    assert.match(e.message, /^This browser does not match three or more case-insensitive branches such as k\|K\|\\u212a/);
    assert.match(e.message, /Write the characters as one class, for example \[kK\\u212a\], or add the u flag\.$/);
    assert.doesNotMatch(e.message, /Chromium/);
  }
});

test('\\B that can match on its own is refused with u only where the engine splits surrogate pairs', () => {
  // V8 12.4 and 13.6 try the middle of a surrogate pair with u, where \B holds:
  // /\B/u.test('a\u{1F600}a') is true there, false by the spec and in Chrome 158.
  const strings = ['a\u{1F600}a', '\u{1F600}', 'a', '', 'ab', '\u{1F600}\u{1F600}', 'a!'];
  for (const p of ['\\B', '(?:x|\\B)', 'x*\\B', 'x?\\B', '(?:\\B)+', '\\B\\B', 'a|\\B', '\\B|^a']) {
    for (const f of ['u', 'iu', 'mu']) {
      if (ENGINE_QUIRKS.notWordBoundaryInsidePairs) {
        assert.equal(why(p, f), 'unreadable', p);
      } else {
        same(p, f, strings, { mustAccept: true });
      }
    }
    assert.equal(why(p, ''), null, p);
  }
  // the spec's answers, which the matcher gives wherever it runs these
  if (!ENGINE_QUIRKS.notWordBoundaryInsidePairs) {
    assert.equal(compileUserRegex('\\B', 'u').test('a\u{1F600}a'), false);
    assert.equal(compileUserRegex('\\B', 'u').test('\u{1F600}'), true);
  }
  for (const p of ['\\Bx', 'x\\B', '\\B|', '\\b', '^\\B$']) assert.equal(why(p, 'u'), null, p);
  assert.equal(compileUserRegex('x\\B', 'u').test('x\u{1F600}'), new RegExp('x\\B', 'u').test('x\u{1F600}'));
  if (ENGINE_QUIRKS.notWordBoundaryInsidePairs) {
    try {
      compileUserRegex('\\B', 'u');
      assert.fail('not refused');
    } catch (e) {
      assert.match(e.message, /^With the u flag, this browser lets \\B match in the middle of a character/);
      assert.doesNotMatch(e.message, /Chromium/);
    }
  }
});

test('a huge count on a body that can match empty gives the spec answer, also where the engine gives none', () => {
  // The body may take every iteration empty, so the count does not matter: the matcher answers as
  // the spec does. V8 (12.4, 13.6, Chrome 158) overflows its stack compiling such counts in the
  // billions and throws a RangeError from test() instead of answering; smaller counts agree.
  for (const [p, s, spec] of [['(?:a?){2147483648}x', 'x', true], ['(?:a|){1073741824,}', 'b', true], ['(?:a?){2147483647}x', 'y', false], ['(?:a?){100000,}x', 'x', true], ['(?:a|){100000,}', 'b', true]]) {
    assert.equal(compileUserRegex(p, '').test(s), spec, p);
    let n;
    try {
      n = new RegExp(p).test(s);
    } catch (e) {
      assert.ok(e instanceof RangeError, `${p}: ${e}`);
      continue;
    }
    assert.equal(n, spec, `native ${p}`);
  }
});

test('a count that no line can reach, and a body that only asserts, need no copies (round 2)', () => {
  // These were refused as too large although the native answer is plain. a{2147483647} needs more
  // code units than any V8 string holds (MAX_SUBJECT, String::kMaxLength), and (?:\b){n} with
  // n >= 1 tests the same position n times.
  const cases = [
    ['a{2147483647}|b', '', { b: true, a: false, aa: false }],
    ['x{2147483647,2147483647}|y', '', { y: true, x: false }],
    ['^x{99999999999999}', '', { x: false, '': false }],
    ['a{536870889}|b', '', { b: true, a: false }], // MAX_SUBJECT + 1
    ['(?:\\b){2147483647}x', '', { x: true, ' x': true, ax: false }],
    ['(?:^){2147483648}x', '', { x: true, yx: false }],
    ['(?:\\b|^){1000}x', 'm', { x: true, 'a\nx': true, ax: false }],
    ['a(?:\\b|$){3,}', '', { a: true, ab: false, 'a b': true }],
    ['a(?:\\B){0,9}b', '', { ab: true, 'a b': false }], // none is enough: matches empty
    ['(?:\\B){2}a', '', { ' a': false, ba: true }],
    ['(?:(?:\\b){0}){7}a', '', { a: true }],
    ['a{0,2147483646}b', '', { b: true, aab: true }], // an optional count no line can use up: a*
  ];
  for (const [p, f, want] of cases) {
    const m = compileUserRegex(p, f);
    for (const [str, spec] of Object.entries(want)) {
      assert.equal(m.test(str), spec, `/${show(p)}/${f} on ${show(str)}`);
      let n;
      try {
        n = new RegExp(p, f).test(str);
      } catch (e) {
        assert.ok(e instanceof RangeError, `${p}: ${e}`); // V8 gives up on some huge counts
        continue;
      }
      assert.equal(n, spec, `native /${show(p)}/${f} on ${show(str)}`);
    }
  }
  // The bound holds in this engine: no string is longer than MAX_SUBJECT (V8 checks the length
  // before it allocates), and test() refuses a longer one rather than answer differently.
  assert.throws(() => 'a'.repeat(MAX_SUBJECT + 1), RangeError);
});

test('the flags and the length are refused before the engine reads the source (round 2)', () => {
  // new RegExp of a megabyte of (?:a|b) under iu took about 100 ms before the length check refused
  // it, and 12 KB of wide classes under iv about 55 ms before the v flag was refused.
  const timed = (p, f) => {
    const t0 = performance.now();
    const w = why(p, f);
    return [w, performance.now() - t0];
  };
  for (const [p, f, code] of [
    ['(?:a|b)'.repeat(150000) + 'x', 'iu', 'too-large'],
    ['(?:a|c)'.repeat(72000) + 'x', 'iu', 'too-large'],
    ['(?<n>a)'.repeat(150000), '', 'too-large'],
    [Array.from({ length: 4000 }, (_, r) => `[${String.fromCharCode(0x100 + (r % 3))}-\u{10FFFF}]`).join(''), 'iv', 'flags'],
    ['[\u0100-\u{10FFFF}]'.repeat(10), 'iv', 'flags'],
    ['a'.repeat(1 << 20), 'g', 'flags'],
    ['\\p{L}'.repeat(100000), 'u', 'too-large'],
  ]) {
    const [w, ms] = timed(p, f);
    assert.equal(w, code, `${p.length} characters /${f}`);
    assert.ok(ms < 10, `${p.length} characters /${f} refused after ${ms.toFixed(1)} ms`);
  }
  // an unknown flag is still the engine's own error, and an invalid pattern within the limits too
  let nativeMessage = null;
  try {
    new RegExp('a', 'x'); // eslint-disable-line no-new
  } catch (e) {
    nativeMessage = e.message;
  }
  assert.throws(() => compileUserRegex('a'.repeat(5000), 'x'), (e) => e instanceof SyntaxError && e.message === nativeMessage);
  assert.throws(() => compileUserRegex('(', 'v'), (e) => e instanceof RegexUnsupported && e.why === 'flags');
  assert.throws(() => compileUserRegex('(', 'uv'), SyntaxError);
  assert.throws(() => compileUserRegex('(', 'u'), SyntaxError);
});

test('atoms in a part that can never run cost nothing per line (round 2)', () => {
  // (?:...){0} and parts that can never match hold atoms that no NFA state uses: they are left out
  // of the folding table and get no native matcher. Before, ~1580 literals in a {0} put 25 chunks
  // in the folding table of a line's first never-seen characters (a 57 ms first line, cold).
  const Native = globalThis.RegExp;
  let made = 0;
  globalThis.RegExp = class extends Native {
    constructor(...args) {
      super(...args);
      made += 1;
    }
  };
  let m;
  try {
    const lits = Array.from({ length: 1500 }, (_, k) => String.fromCharCode(0x4e00 + k)).join('');
    for (const p of [`(?:${lits}){0}x`, `(?:${lits}|[a-z]\\d\\w){0}x`, `(?:${lits.slice(0, 400)}){2147483647}|x`]) {
      made = 0;
      m = compileUserRegex(p, 'i');
      // new RegExp('', 'i'), new RegExp(p, 'i') and the folding table of 'x': all, one chunk, its branches
      assert.ok(made <= 5, `${made} RegExps for a pattern of ${p.length} characters`);
      assert.equal(m.test('X'), true);
      assert.equal(m.test('\u4e00'), false);
    }
  } finally {
    globalThis.RegExp = Native;
  }
  assert.equal(m.test('x'), true);
});

test('what Annex B reads as characters is not a back-reference', () => {
  for (const p of ['\\1', '\\8', '(a)\\2', '(a)\\8', '\\12(a)', '\\k', '\\k<n>', '[\\1]', '(a)[\\1]']) assert.equal(why(p), null, p);
});

test('too large patterns, flags and syntax errors', () => {
  assert.equal(why('\\x61'.repeat(REGEX_SOURCE_MAX / 4)), null);
  assert.equal(why('\\x61'.repeat(REGEX_SOURCE_MAX / 4) + 'a'), 'too-large');
  assert.equal(why('a'.repeat(MAX_STATES)), 'too-large');
  assert.equal(why(`a{${MAX_STATES}}`), 'too-large');
  assert.equal(why(`a{${MAX_STATES - 2}}`), null);
  assert.equal(why('(?:a{100}){100}'), 'too-large');
  assert.equal(why('(?:(?:(?:a{20}){20}){20}){20}'), 'too-large');
  assert.equal(why('(?:|y){1000000,}z'), null); // a body that matches empty needs no mandatory copies
  assert.equal(why('(?:|y){1000000}z'), null); // nor optional ones at the start: the same as z (round 4)
  assert.equal(why('x(?:|y){1000000}z'), 'too-large'); // but up to a million optional ones inside are too many
  assert.equal(why('(?:ab){99999999999}|b'), null); // can never match: no state needed
  assert.equal(why('a{99999999999}|b'), null); // needs more code units than any line test() reads
  assert.equal(why(`a{${MAX_SUBJECT}}`), 'too-large'); // a line this long can exist: it is expanded
  assert.equal(why(`a{${MAX_SUBJECT + 1}}`), null);
  assert.equal(why('(?:\\b){5000}'), null); // one copy of a body that only asserts is the same as 5000
  assert.equal(why(`x(?:a?){${MAX_STATES}}y`), 'too-large');
  assert.equal(why('(?:'.repeat(MAX_DEPTH) + 'a' + ')'.repeat(MAX_DEPTH)), null);
  assert.equal(why('(?:'.repeat(MAX_DEPTH + 1) + 'a' + ')'.repeat(MAX_DEPTH + 1)), 'too-large');
  const many = Array.from({ length: MAX_CLASS_ATOMS + 1 }, (_, k) => `[a${String.fromCharCode(0x4e00 + k)}]`).join('');
  assert.equal(why(many), 'too-large');
  assert.equal(why(many.slice(many.indexOf(']') + 1)), null);
  assert.equal(why('\\p{L}'.repeat(MAX_PROPERTY_ESCAPES), 'u'), null);
  assert.equal(why('\\p{L}'.repeat(MAX_PROPERTY_ESCAPES + 1), 'u'), 'too-large');
  assert.equal(why('\\p{L}'.repeat(MAX_PROPERTY_ESCAPES + 1), ''), null); // without u: the letter p
  assert.equal(why('a', 'v'), 'flags');
  assert.equal(why('a', 'g'), 'flags');
  assert.equal(why('a', 'y'), 'flags');
  assert.equal(why('a', 'dimsu'), null);
  // invalid patterns: the engine's own SyntaxError, unchanged
  for (const [p, f] of [['(', ''], ['a**', ''], ['[b-a]', ''], ['\\u{110000}', 'u'], ['\\c', 'u'], ['a{2,1}', ''], ['(?<a>.)(?<a>.)', ''], ['a', 'gg']]) {
    let nativeMessage = null;
    try {
      new RegExp(p, f); // eslint-disable-line no-new
    } catch (e) {
      nativeMessage = e.message;
    }
    if (nativeMessage === null) continue; // an engine that accepts it (duplicate names in newer engines)
    assert.throws(() => compileUserRegex(p, f), (e) => e instanceof SyntaxError && e.message === nativeMessage);
  }
});

test('the matcher keeps no state between calls and accepts any string', () => {
  const m = compileUserRegex('b+', '');
  assert.equal(m.source, 'b+');
  assert.equal(m.flags, '');
  assert.equal(m.test('abb'), true);
  assert.equal(m.test('abb'), true);
  assert.equal(m.test('a'), false);
  assert.equal(m.test(12), false);
  assert.equal(compileUserRegex('1', '').test(12), true);
  assert.equal(compileUserRegex('^$', '').test(''), true);
  const long = 'x'.repeat(100000) + 'b';
  assert.equal(m.test(long), true);
});

/** The refusal of a pattern, or null. */
function refusal(p, f = '') {
  try {
    compileUserRegex(p, f);
  } catch (e) {
    if (e instanceof RegexUnsupported) return e;
    throw e;
  }
  return null;
}

test('parts that can never take part in a match do not count against the limits (round 3)', () => {
  // The state budget and the class count were charged as each part was read, before an enclosing
  // {0} or a part beside one that can never match dropped it: patterns that are the same as x or b
  // were refused as too large.
  const classes = Array.from({ length: MAX_CLASS_ATOMS + 1 }, (_, k) => `[a${k}]`).join('');
  const cases = [
    ['(?:a{1000}){0}x', '', ['x', 'ax', 'a', '']],
    ['(?:[0-9]{1,1000}){0}deny', '', ['deny', '1deny', 'den']],
    ['a{600000000}b{1000}|x', '', ['x', 'b', 'ab']],
    [`(?:${classes}){0}x`, '', ['x', 'a0x', 'a']],
    [`a{600000000}${classes}|x`, 'i', ['X', 'a0']],
    ['(?:a{1000}){0}b', '', ['b', 'ab', 'x']],
    ['b(?:x{800}){0}', '', ['b', 'x']],
    ['y|(?:x{800}){0,0}', '', ['y', '']],
    ['(?:x{60000}){10000}|y', '', ['y', 'xx', 'ayz']],
    ['(?:x{60000}){10000}|y', 'u', ['y', 'xx']],
    ['(?:x{60000}){10000}|y', 'i', ['Y', 'xx']],
    ['(?:x{769}){700000}|y', '', ['y', 'x']],
    ['(?:(?:x{1000}){1000}){1000}|y', '', ['y', 'x']],
    ['x{300000000}x{300000000}|y', '', ['y', 'xx']], // each fits a line, the two together do not
    ['(?:x{1000})[]|y', '', ['y', 'x']], // [] matches no character
    ['[]{1000}|[]*y', 'u', ['y', '']],
    ['(?:\\d|\\w|\\s|[a-z]){0}\\bx', 'iu', ['x', 'ax', ' x']],
  ];
  for (const [p, f, strings] of cases) assert.equal(same(p, f, strings, { mustAccept: true }), strings.length, p.slice(0, 40));
  // they cost what what is left costs
  assert.ok(compileUserRegex('(?:a{1000}){0}x', '').states <= 3);
  assert.ok(compileUserRegex(`(?:${classes}){0}x`, '').natives.length === 0);
  // a part that is left is still charged, and the refusal names it
  for (const [p, piece] of [
    ['(?:a{1000}){2}x', 'a{1000}'],
    ['b(?:x{800}){1}', 'x{800}'],
    ['(?:a{1000}){0}b{1000}', 'b{1000}'],
    ['y(?:x{70000})?z', 'x{70000}'],
  ]) {
    const e = refusal(p);
    assert.equal(e && e.why, 'too-large', p);
    assert.ok(p.slice(e.at).startsWith(piece), `${p}: refused at ${e.at}`);
    assert.match(e.message, /^This pattern is too large for J-Wicket's matcher: '.*' at character \d+ expands to more than 768 parts\./);
  }
  const e = refusal(`(?:[a]){0}${classes}`);
  assert.equal(e && e.why, 'too-large');
  assert.equal(e.at, `(?:[a]){0}${classes}`.lastIndexOf('['), 'the class that is one too many');
});

test('a loop repeated {n,m} is folded into one loop (round 3)', () => {
  // (?:a*){256} expanded 256 copies of a* and was refused; it is a*, and (R{a,}){n,m} is R{na,}.
  const strings = ['', 'a', 'aab', 'b', 'x', 'aaaaab', 'ab'.repeat(5), ' \t x', 'aaaaaaaaaaaaaaaaaaaab'];
  for (const p of ['(?:a*){256}b', '(?:a*){255}', '(?:a*){256}', '(?:\\s*){300}x', '(?:a*){0,300}b', '(?:a*){5,}b', '(?:a+){300}', '(?:a+){0,300}b', '(?:a{2,}){3}b', '(?:(?:ab)+){4,9}', '(?:(?:ab){0,}){2}$', '(?:a+|b){3}', '(?:\\b\\w+){3}', '(?:a+){1,2}?b', '(?:(?:a*)*){400}b']) {
    assert.equal(same(p, '', strings, { mustAccept: true }), strings.length, p);
    assert.equal(same(p, 'i', strings.map((s) => s.toUpperCase()), { mustAccept: true }), strings.length, `${p} /i`);
  }
  assert.ok(compileUserRegex('(?:a*){256}b', '').states <= 4);
  assert.equal(why('(?:a+){300}'), null);
  assert.equal(compileUserRegex('(?:a+){300}', '').test('a'.repeat(299)), false);
  assert.equal(compileUserRegex('(?:a+){300}', '').test('a'.repeat(300)), true);
  // a body that is not a loop is still expanded
  assert.equal(why('x(?:a?){400}b'), 'too-large');
});

test('a disjunction that is dropped is not checked for the engine merging folded branches (round 3)', () => {
  // checkAlternativeFolding built its folding tables for a disjunction inside {0} too: tens of ms per
  // pattern for nothing, and a refusal where the engine has the quirk.
  assert.equal(why('(?:k|K|\u212a){0}x', 'i'), null);
  assert.equal(compileUserRegex('(?:k|K|\u212a){0}x', 'i').test('X'), true);
  assert.equal(compileUserRegex('(?:k|K|\u212a){0}x', 'i').test('k'), false);
  assert.equal(why('(?:k|K|\u212a)x', 'i'), ENGINE_QUIRKS.mergesFoldedBranches ? 'unreadable' : null);
  // the engine merges only branches made of literals alone, which can always match; a branch that
  // can never match is not one of them, here or there
  for (const p of ['\\u212ax{600000000}|k|K', 'kx{600000000}|K|\\u212a', 'k[]|K|\\u212a', '(?:kx{600000000}|kx{600000000}|K|\\u212a)']) {
    assert.equal(same(p, 'i', ['k', 'K', '\u212a', 'kx'], { mustAccept: true }), 4, p);
  }
  const letters = Array.from({ length: 190 }, (_, k) => String.fromCharCode(0x3b1 + (k % 17), 0x430 + (k % 31))).join('');
  const p = `(?:(?:x|y|${letters})(?:x|y|${letters})){0}a~`;
  const t0 = performance.now();
  for (let k = 0; k < 20; k += 1) compileUserRegex(`${p}${'~'.repeat(k)}`, 'i');
  const ms = (performance.now() - t0) / 20;
  assert.ok(ms < 5, `compiling a dropped disjunction of ${letters.length} letters took ${ms.toFixed(1)} ms`);
});

test('where the native engine gives no answer in time, the matcher gives the spec answer (round 3)', () => {
  // (?:\p{Emoji}|[\s\S]+)*\u212a{2} /iu backtracks exponentially in V8 (107 s, then false, on this
  // kind of line); it is not run natively here. The loop can match empty, so the answer is that of \u212a{2}.
  const s = `${'\u{1F600}x\ud83d\u{10400}k_'.repeat(30)}aKK\u00e9${'\u{1F64F} b'.repeat(10)}`;
  const t0 = performance.now();
  assert.equal(compileUserRegex('(?:\\p{Emoji}|[\\s\\S]+)*\\u212a{2}', 'iu').test(s), true);
  assert.equal(compileUserRegex('(?:\\p{Emoji}|[\\s\\S]+)*\\u212a{2}', 'iu').test(s.replace('KK', 'K')), /\u212a{2}/iu.test(s.replace('KK', 'K')));
  assert.equal(/\u212a{2}/iu.test(s), true);
  assert.ok(performance.now() - t0 < 200);
});

test('a part at either end that cannot change the answer costs nothing (round 4)', () => {
  // test() only asks whether some substring matches: R{0,n}S answers like S, S R{0,n} like S,
  // S R{m,n} like S R{m}, and a branch that can match empty matches every line. These were expanded
  // and refused as too large, though the pattern they answer like needs a few states.
  const lines = ['x'.repeat(1000) + ' deny drop ' + 'a'.repeat(1000), 'nothing here', 'a'.repeat(2048), 'deny', '', 'xa', 'x a', 'XK', '1deny', 'dro\np'];
  const cases = [
    ['a{0,1000}x', '', 'x'],
    ['\\d{0,400}deny', '', 'deny'],
    ['.{0,2047}drop', '', 'drop'],
    ['.{0,2047}drop', 's', 'drop'],
    ['deny.{0,800}', '', 'deny'],
    ['x(?:[a-z]?){300}', '', 'x'],
    ['x\\w{1,1000}', '', 'x\\w'],
    ['x\\w{1,1000}', 'iu', 'x\\w'],
    ['x.{1,800}', 's', 'x.'],
    ['deny|\\w{0,1000}', '', ''],
    ['\\s{0,800}', '', ''],
    ['(?:a{0,900}|b)x', '', 'x'],
    ['x(?:ya{0,900}|b)', '', 'x(?:y|b)'],
    ['(?:a{0,900}y|b)x', '', '(?:y|b)x'],
    ['x(?:a{2,900}|b{1,900})', '', 'x(?:aa|b)'],
    ['x(?:ab{0,90}){3}', '', 'x(?:ab{0,90}){2}a'],
    ['(?:b{0,90}a){3}x', '', 'a(?:b{0,90}a){2}x'],
    ['^\\w{0,1000}x', '', '^\\w{0,1000}x'], // an assertion before it: not dropped
  ];
  for (const [p, f, small] of cases) {
    const re = new RegExp(p, f);
    const t0 = performance.now();
    let m;
    try {
      m = compileUserRegex(p, f);
    } catch (e) {
      if (p.startsWith('^')) continue; // ^\w{0,1000}x needs its states: refused as before
      throw e;
    }
    const s = compileUserRegex(small, f);
    for (const line of lines) {
      assert.equal(m.test(line), re.test(line), `/${show(p)}/${f} on ${show(line.slice(0, 30))}`);
      assert.equal(m.test(line), s.test(line), `/${show(p)}/${f} answers like /${small}/`);
    }
    assert.ok(m.states <= s.states, `/${p}/ has ${m.states} states, /${small}/ ${s.states}`);
    assert.ok(performance.now() - t0 < 50);
  }
  assert.equal(why('^\\w{0,1000}x'), 'too-large');
  assert.equal(why('x\\w{0,1000}y'), 'too-large'); // in the middle every copy counts
  // the hunt's (?:|y){1000000}z, on which the native engine backtracks for hours on 'xy', is z
  const z = compileUserRegex('(?:|y){1000000}z', 'i');
  for (const line of ['xy', 'z', 'yZ', '', 'y'.repeat(2048)]) assert.equal(z.test(line), /z/i.test(line), show(line.slice(0, 9)));
});

test('a part at either end is kept when the engine could see a quirk through it (round 4)', () => {
  // dropping a part that can match empty must not hide the engine quirks the matcher refuses
  assert.equal(why('a{0,900}\\B', 'u'), ENGINE_QUIRKS.notWordBoundaryInsidePairs ? 'unreadable' : null);
  assert.equal(why('\\Ba{0,900}', 'u'), ENGINE_QUIRKS.notWordBoundaryInsidePairs ? 'unreadable' : null);
  assert.equal(why('(?:k|K|K){1,900}', 'i'), ENGINE_QUIRKS.mergesFoldedBranches ? 'unreadable' : null);
  assert.equal(why('(?:k|K|K){0,900}x', 'i'), null); // can always be skipped: the engine's answer is that of x
  assert.equal(compileUserRegex('(?:k|K|K){0,900}x', 'i').test('X'), true);
});

test('the first line in a fresh tab is not slowed by the engine recompiling the matcher (round 4)', () => {
  // A line that brings a new kind of character every 100 positions (a line terminator, an astral or
  // lone surrogate, a folding letter) made the engine deoptimize the loop over 700 live states
  // several times in one test(): 75 ms for the first line in a fresh process, 12 ms warm. The answers
  // that depend on the character are now worked out before that loop (classify), so it stays optimized.
  const child = `
import { compileUserRegex } from ${JSON.stringify(new URL('../../src/jwicket/static/js/regexvm.js', import.meta.url).href)};
const [p, f] = process.argv.slice(1);
const ev = ['\\n', '\\u00e9', '\\u4e00', '\\u{1F600}', ' ', 'K', '\\u212a', '1', '\\u2028', '\\ud800', '\\u017f', '_', '\\u0100', '\\uffff', '\\r', '\\u00df', '\\u{10000}', '\\t', '\\u0130', '\\u00b5'];
const arr = [...'a'.repeat(2047)];
ev.forEach((c, k) => { const at = 200 + k * 100; if (at < 2040) arr.splice(at, c.length, ...c); });
const line = arr.join('').slice(0, 2047) + '~';
const m = compileUserRegex(p, f);
const t = performance.now();
const r = m.test(line);
console.log(JSON.stringify({ ms: performance.now() - t, r, states: m.states }));
`;
  const P = '(?:\\b|\\B|^|$|.|\\d|k|é|\\s|\\w|\\W|\\D|\\S|[a-z]){27}!';
  for (const f of ['imsu', 'im']) {
    const runs = [];
    for (let k = 0; k < 5; k += 1) runs.push(JSON.parse(execFileSync(process.execPath, ['--input-type=module', '-e', child, P, f], { encoding: 'utf8' })));
    assert.ok(runs.every((x) => x.r === false && x.states > 700));
    const ms = runs.map((x) => x.ms).sort((a, b) => a - b);
    if (process.env.REGEXVM_REPORT) console.log(`fresh first line /${f}: ${ms.map((x) => x.toFixed(1)).join(' ')} ms`);
    assert.ok(ms[2] < 50, `first line in a fresh process /${f}: median ${ms[2].toFixed(1)} ms (${ms.map((x) => x.toFixed(1)).join(', ')})`);
  }
});
