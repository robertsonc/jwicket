// J-Wicket's own matcher for the regular expressions operators type into a filter.
//
// A native RegExp backtracks: a pattern such as (a+)+$ or .*=.*=.*! takes seconds on one long line and
// freezes the tab. compileUserRegex() reads the pattern itself and runs it in a Thompson NFA, simulated
// as a Pike VM (all threads advance one character at a time, each NFA state at most once per
// position). Testing one line therefore costs at most (line length + 1) x (NFA states) steps, whatever
// the pattern: nothing backtracks, so nothing is exponential or polynomial.
//
// What the browser still decides. Which characters one atom matches (a literal, a class, an escape
// such as \d \w \s \p{...}, or '.') is decided by the browser's own engine, so case folding under i and
// iu, Unicode properties, dotAll and Annex B class quirks are exactly the browser's: each such atom is
// compiled to a native RegExp ^(?:atom)$ with the flags in effect at that point (modifier groups
// included) and tested on one code unit (without u) or one code point (with u). Two shortcuts give the
// same answers faster: a literal without i matches exactly its own character, and literals under i are
// grouped by case-folding class (see foldClasses: two literals that match the same character match
// each other, so the first literal that matches a character names its class, and the engine is asked
// once per character which one that is). \b and \B ask the engine whether each neighbouring
// character is a word character (a native \b tested on that one character, with the i and u flags in
// effect), so \b under iu counts the long s and the Kelvin sign as the engine does. The VM handles
// the structure: concatenation, alternation, groups, quantifiers and the assertions ^ $ \b \B.
//
// What it refuses (RegexUnsupported, with a `why` code, a plain message and the offset `at`):
// lookahead and lookbehind ('lookaround'), back-references, numbered or named ('backreference'), the
// v, g and y flags ('flags'), a pattern longer than REGEX_SOURCE_MAX, one that needs more than
// MAX_STATES NFA states, more than MAX_CLASS_ATOMS different classes or escapes, more than
// MAX_PROPERTY_ESCAPES \p{...}, or groups nested more than MAX_DEPTH deep ('too-large'), and
// anything the parser does not read exactly ('unreadable'): it fails closed. 'unreadable' also
// covers the three places where V8 12.4 and 13.6 depart from the spec and from the atom-by-atom
// answer, but only when the engine that runs the page has them (ENGINE_QUIRKS, probed when the
// module loads; Chrome 158 has none): see checkAlternativeFolding, emptyOnlyThroughNotWordBoundary
// and caseModifierGroupsDiffer (a group such as (?i:...) or (?-i:...) that changes i). The flags and
// the length are checked first; an invalid pattern within them is then given to new RegExp(), so
// its syntax error is the browser's own.
//
// Why the boolean answer equals the native one. Without lookaround and back-references a match
// depends only on positions, never on captures, so a match exists exactly when the NFA accepts some
// substring. The spec rejects a loop iteration that consumes nothing once the minimum count is met;
// such an iteration starts and ends at the same position, so removing it from any accepting path
// leaves an accepting path: the NFA, which simply never revisits a state at one position, accepts the
// same strings. Mandatory iterations are expanded as copies and may match empty, as in the spec.
// Quantifier numbers are read as V8 reads them: any number of digits, saturating at 2^31 - 1, which
// V8 treats as unbounded. A count so large that it could only matter on a line longer than test()
// reads (MAX_SUBJECT, the longest string V8 holds) is folded: x{n,m} with m - n at least that large
// is x{n,}, and a part whose minimum length exceeds it can never match. A body that only asserts,
// such as (?:\b){n}, is the same as one copy of it, and a body that is itself an unbounded loop
// R{a,} repeated {n,m} is R{na,} ((?:a*){300} is a*). Parts that can never take part in a match
// (repeated {0} times, beside a part that can never match, or holding the empty class []) are
// dropped before the limits are checked, so they cost nothing (see checkLimits). So are the parts
// at either end of the pattern that cannot change whether some substring matches: R{0,n}S is S,
// S R{m,n} is S R{m}, and a branch that can match empty matches every line (see keepStart).
//
// Two places where there is no native answer to equal. V8 (12.4, 13.6 and Chrome 158) overflows its
// stack compiling a count in the billions on a body that can match empty, such as
// (?:a?){2147483648}x, and its test() throws a RangeError. The matcher takes every such iteration
// empty and gives the spec's answer (true on 'x' here), as the engine does for smaller counts such as
// {100000,}. And a pattern that backtracks exponentially in the native engine may give no answer in
// any time that matters: (?:\p{Emoji}|[\s\S]+)*\u212a{2} with iu on a 232-code-unit line that holds
// 'KK' ran for 107 s in V8 12.4 and then returned false (the spec says true: the loop can match empty
// and \u212a{2} under iu matches KK; /\u212a{2}/iu.test() of the line is true), and ran for more than
// 11 minutes on a second try and in Chrome 158. The matcher gives the spec's answer, true, in about a millisecond. Where the native
// test() does answer, the two agree.

export const REGEX_SOURCE_MAX = 2048;

// The most NFA states one pattern may have. One line costs at most (length + 1) x MAX_STATES state
// visits, and a visit costs about 8 to 16 ns in Node 22 on the reference machine (a shared 2.1 GHz
// Xeon vCPU whose speed varies by about two times from run to run). The worst shapes found, which
// keep nearly every state alive at every position ([^!](?:.?){255}!, (?:\b|\B|.){153}!,
// [^!](?:^|$|\B|a?){85}!, a 384-way alternation in a loop), took 10 to 27 ms on a 2048-character line
// at 768 states, and 14 to 30 ms at 1024; tests/js/regexvm.test.mjs ('linear time') keeps them in view.
// A second term does not depend on the states: each native atom (at most MAX_CLASS_ATOMS) asks the
// engine once for each character it has not seen yet, so a line of 2048 never-seen characters adds
// up to MAX_CLASS_ATOMS x 2048 native tests (about 100 ns each, with the cache tables below): 4 to
// 12 ms per line on the reference machine for 32 atoms ('never-seen characters' in the tests).
export const MAX_STATES = 768;

// The most different classes and escapes ([a-z], \d, \w, '.', \p{L}, ... counted once per text and
// flags; \b and \B count as one per flag set). Each is a native RegExp tested once per distinct
// character it meets: this bounds the native work on a line of distinct characters.
export const MAX_CLASS_ATOMS = 32;

// Groups nested deeper than this are refused: the parser and the compiler recurse once per level.
export const MAX_DEPTH = 128;

// The most property escapes (\p{...}, \P{...}) with the u flag. The engine itself takes a quarter of a
// millisecond to read each one (V8 12.4: 110 ms for new RegExp of 406 of them), so this is checked
// before the pattern is given to new RegExp.
export const MAX_PROPERTY_ESCAPES = 16;

/**
 * Two places where the engine that runs this module departs from the spec, probed once when it
 * loads (see checkAlternativeFolding and emptyOnlyThroughNotWordBoundary). V8 12.4 and 13.6 (Node 22
 * and 24) have both; Chrome 158 has neither. Patterns that could see a quirk the engine has are
 * refused, so that the matcher's answer is still the engine's.
 */
export const ENGINE_QUIRKS = Object.freeze({
  mergesFoldedBranches: !(/^(?:k|K|\u212a)$/i.test('\u212a') && /^(?:s|S|\u017f)$/i.test('\u017f') && /^(?:xk|xK|x\u212a)$/i.test('x\u212a')),
  notWordBoundaryInsidePairs: /\B/u.test('a\u{1F600}a'),
  caseModifierGroups: caseModifierGroupsDiffer(),
});

/**
 * Whether the engine reads modifier groups (?i:...) and (?-i:...) but does not apply their i as the
 * spec does (see Parser.group). Each probe is a spec answer that V8 12.4 or 13.6 gets wrong: the i of
 * a group dropped for a one-byte subject string, kept inside (?-i:...) for one, leaking into a later
 * \w or \W or past a quantified group, or shared between branches with different case flags.
 * The strings are written in the source, so they are one-byte where the engine stores them so.
 */
function caseModifierGroupsDiffer() {
  try {
    new RegExp('(?i:a)'); // eslint-disable-line no-new -- an engine without modifier groups has nothing to differ
  } catch (_e) {
    return false;
  }
  return (
    !new RegExp('(?i:\\u039c)').test('\u00b5') ||
    new RegExp('(?-i:\\u039c)', 'i').test('\u00b5') ||
    new RegExp('(?i:x)\\w', 'u').test('x\u212a') ||
    new RegExp('(?-i:x)\\W', 'iu').test('xk') ||
    new RegExp('(?i:x)?k').test('xK') ||
    new RegExp('(?i:ab)|ac|AD').test('Ac')
  );
}

const COUNT_INFINITY = 2147483647; // V8's RegExpTree::kInfinity: a {n,m} number saturates here

/**
 * The longest line test() reads, in code units: V8's String::kMaxLength on 64-bit machines, so no
 * line in Chrome (or Node) is longer. test() throws a RangeError for a longer string (an engine with
 * longer strings, such as Firefox or Safari, could hold one), and counts are folded with this bound:
 * a part that needs more code units than this can never match a line test() reads.
 */
export const MAX_SUBJECT = 2 ** 29 - 24;

/** Thrown for a pattern J-Wicket does not run. `why`: one of the codes above; `at`: offset in the source. */
export class RegexUnsupported extends Error {
  constructor(why, message, at = 0, length = 1) {
    super(message);
    this.name = 'RegexUnsupported';
    this.why = why;
    this.at = at;
    this.length = length;
  }
}

// --- parse ------------------------------------------------------------------------------------------

// Node kinds and VM opcodes.
const N_ATOM = 1;
const N_ASSERT = 2;
const N_SEQ = 3;
const N_ALT = 4;
const N_REP = 5;
const N_EMPTY = 6;
const N_FAIL = 7;

const OP_CHAR = 0;
const OP_SPLIT = 1; // out2 < 0: a plain jump
const OP_BOL = 2;
const OP_EOL = 3;
const OP_BOL_M = 4;
const OP_EOL_M = 5;
const OP_WORDB = 6;
const OP_NWORDB = 7;
const OP_MATCH = 8;
const OP_FAIL = 9;
const OP_FOLD = 10; // a character state whose atom is a literal under i (set in makeTester)
const OP_NATIVE = 11; // a character state whose atom is a native class or escape

// Atom kinds.
const A_EXACT = 0; // a literal without i: one code point
const A_FOLD = 1; // a literal under i: its folding class (see foldClasses)
const A_NATIVE = 2; // a class, escape or '.', or the word test of \b: a native RegExp

const EMPTY = { t: N_EMPTY, min: 0, pure: true, zw: true, size: 0 };

const isDigit = (c) => c >= 0x30 && c <= 0x39;
const hexVal = (c) => (c >= 0x30 && c <= 0x39 ? c - 0x30 : c >= 0x41 && c <= 0x46 ? c - 0x37 : c >= 0x61 && c <= 0x66 ? c - 0x57 : -1);
const isLead = (c) => c >= 0xd800 && c <= 0xdbff;
const isTrail = (c) => c >= 0xdc00 && c <= 0xdfff;
const SYNTAX_CHARS = '^$\\.*+?()[]{}|/';

/** V8's ScanForCaptures: the number of capturing groups in the whole pattern, and whether any is named. */
function scanCaptures(src) {
  let count = 0;
  let named = false;
  for (let i = 0; i < src.length; ) {
    const c = src[i++];
    if (c === '\\') i += 1;
    else if (c === '[') {
      while (i < src.length) {
        const d = src[i++];
        if (d === '\\') i += 1;
        else if (d === ']') break;
      }
    } else if (c === '(') {
      if (src[i] === '?') {
        if (src[i + 1] !== '<' || src[i + 2] === '=' || src[i + 2] === '!') continue;
        named = true;
      }
      count += 1;
    }
  }
  return { count, named };
}

const cpText = (c, unicode) => (unicode ? `\\u{${c.toString(16)}}` : `\\u${c.toString(16).padStart(4, '0')}`);

class Parser {
  constructor(src, unicode, base) {
    this.src = src;
    this.u = unicode;
    this.i = 0;
    const scan = scanCaptures(src);
    this.captures = scan.count;
    this.named = scan.named;
    this.base = base; // { i, m, s } from the flags
    this.atoms = []; // { kind, key, code?, text?, flags? }
    this.atomIndex = new Map();
    this.foldChecks = []; // { codes, at }: see checkAlternativeFolding
  }

  refuse(why, at, length, message) {
    throw new RegexUnsupported(why, message, at, length);
  }

  unreadable(at) {
    const piece = this.src.slice(at, at + 12);
    this.refuse('unreadable', at, Math.max(piece.length, 1), `J-Wicket does not read '${piece}' at character ${at + 1} of this pattern, so it does not run it. Write it with plain characters, classes, groups and the quantifiers * + ? {n,m}.`);
  }

  atom(kind, key, extra) {
    let id = this.atomIndex.get(key);
    if (id !== undefined) return id;
    id = this.atoms.length;
    this.atoms.push({ kind, key, ...extra });
    this.atomIndex.set(key, id);
    return id;
  }

  literal(code, fl, at) {
    const id = fl.i ? this.atom(A_FOLD, `F${code}`, { code }) : this.atom(A_EXACT, `L${code}`, { code });
    return { t: N_ATOM, a: id, at, min: 1, pure: false, size: 1 };
  }

  native(text, fl, at) {
    // '.' depends on s only; every other class or escape on i (and u, which is the same for the whole pattern).
    const flags = (text === '.' ? (fl.s ? 's' : '') : fl.i ? 'i' : '') + (this.u ? 'u' : '');
    const id = this.atom(A_NATIVE, `N${flags}/${text}`, { text, flags, word: false });
    return { t: N_ATOM, a: id, at, min: 1, pure: false, size: 1 };
  }

  assertion(op, fl, at) {
    let a = -1;
    if (op === OP_WORDB || op === OP_NWORDB) {
      const flags = (fl.i ? 'i' : '') + (this.u ? 'u' : '');
      a = this.atom(A_NATIVE, `W${flags}`, { text: '\\b', flags, word: true });
    }
    if (op === OP_BOL && fl.m) op = OP_BOL_M;
    if (op === OP_EOL && fl.m) op = OP_EOL_M;
    return { t: N_ASSERT, op, a, at, min: 0, pure: false, zw: true, size: 1 };
  }

  parse() {
    const node = this.disjunction(this.base, 0);
    if (this.i !== this.src.length) this.unreadable(this.i);
    return node;
  }

  disjunction(fl, depth) {
    const at = this.i;
    const alts = [this.alternative(fl, depth)];
    while (this.src[this.i] === '|') {
      this.i += 1;
      alts.push(this.alternative(fl, depth));
    }
    if (alts.length > 2 && !this.u && fl.i && ENGINE_QUIRKS.mergesFoldedBranches) {
      // the literals each branch starts with (see checkAlternativeFolding)
      const codes = [];
      const nodes = [];
      let branches = 0;
      for (const alt of alts) {
        const items = alt.t === N_SEQ ? alt.items : [alt];
        let k = 0;
        for (; k < items.length && items[k].t === N_ATOM && this.atoms[items[k].a].kind === A_FOLD; k += 1) {
          codes.push(this.atoms[items[k].a].code);
          nodes.push(items[k]);
        }
        if (k > 0) branches += 1;
      }
      // `nodes`: whether the disjunction is still part of the pattern once parts that can never
      // match are dropped (see liveParts); a dropped one is not checked.
      if (branches > 2) this.foldChecks.push({ codes: [...new Set(codes)], nodes, at });
    }
    return alts.length === 1 ? alts[0] : mkAlt(alts);
  }

  alternative(fl, depth) {
    const items = [];
    const src = this.src;
    while (this.i < src.length && src[this.i] !== '|' && src[this.i] !== ')') {
      const at = this.i;
      const term = this.term(fl, depth);
      let node = term.node;
      if (term.quantifiable) {
        const q = this.quantifier();
        if (q) node = this.repeat(node, q.min, q.max, at);
      }
      items.push(node);
    }
    return mkSeq(items);
  }

  /** V8's ParseIntervalQuantifier at this.i ('{'): { min, max, end } or null when it is not one. */
  interval(i) {
    const src = this.src;
    let j = i + 1;
    if (!isDigit(src.charCodeAt(j))) return null;
    const num = () => {
      let v = 0;
      while (isDigit(src.charCodeAt(j))) {
        const d = src.charCodeAt(j) - 0x30;
        if (v > (COUNT_INFINITY - d) / 10) {
          while (isDigit(src.charCodeAt(j))) j += 1;
          return COUNT_INFINITY;
        }
        v = v * 10 + d;
        j += 1;
      }
      return v;
    };
    const min = num();
    let max;
    if (src[j] === '}') {
      max = min;
      j += 1;
    } else if (src[j] === ',') {
      j += 1;
      if (src[j] === '}') {
        max = COUNT_INFINITY;
        j += 1;
      } else {
        if (!isDigit(src.charCodeAt(j))) return null;
        max = num();
        if (src[j] !== '}') return null;
        j += 1;
      }
    } else {
      return null;
    }
    return { min, max, end: j };
  }

  quantifier() {
    const src = this.src;
    const c = src[this.i];
    let min;
    let max;
    if (c === '*') [min, max] = [0, Infinity];
    else if (c === '+') [min, max] = [1, Infinity];
    else if (c === '?') [min, max] = [0, 1];
    else if (c === '{') {
      const q = this.interval(this.i);
      if (!q) {
        if (this.u) this.unreadable(this.i);
        return null; // without u, a '{' that is not a quantifier is a literal (the next term)
      }
      if (q.max < q.min) this.unreadable(this.i);
      min = q.min;
      max = q.max === COUNT_INFINITY ? Infinity : q.max;
      this.i = q.end - 1;
    } else return null;
    this.i += 1;
    if (src[this.i] === '?') this.i += 1; // lazy: the same strings match
    return { min, max };
  }

  repeat(body, min, max, at) {
    // Repeated {0} times: nothing, whatever the body (it costs neither states nor atoms).
    if (max === 0) return EMPTY;
    if (body.t === N_FAIL) return min === 0 ? EMPTY : body;
    // A body that never consumes anything (only assertions and empty parts, such as (?:\b|^)) tests
    // the same position on every iteration: one iteration is the same as n, and none matches empty.
    if (body.zw) return min === 0 ? EMPTY : body;
    // A body that matches empty without any assertion can take its mandatory iterations empty.
    if (body.pure) min = 0;
    // Optional iterations that consume nothing are never needed, and each other one consumes at
    // least one code unit: more of them than a line test() reads has code units is the same as
    // unbounded, and mandatory ones that need more code units than that can never match.
    if (max !== Infinity && max - min >= MAX_SUBJECT) max = Infinity;
    if (min > 0 && body.min > 0 && min * body.min > MAX_SUBJECT) return FAIL();
    if (body.size === 0) return EMPTY; // nothing to repeat but empty matches
    if (body.t === N_REP && body.hi === Infinity) {
      // A body that is itself an unbounded loop R{a,}: k copies of it are R{ka,}, so {n,m} of it
      // (m >= 1) is R{na,} for n >= 1, and for n = 0 one optional copy (the body itself when a = 0,
      // which is how a body that matches empty arrives here: (?:a*){256} is a*).
      if (min > 0) return this.repeat(body.body, min * body.lo, Infinity, at);
      if (body.lo === 0) return body;
      max = 1;
    }
    // The size is worked out here but only checked once the whole pattern is read (see
    // checkLimits), so that a part that is later dropped, such as (?:a{1000}){0} or a part next to
    // one that can never match, is not counted. It saturates at MAX_STATES, which is already too many.
    return mkRep(body, min, max, at);
  }

  tooLarge(at) {
    const piece = this.src.slice(at, at + 24);
    this.refuse('too-large', at, Math.max(piece.length, 1), `This pattern is too large for J-Wicket's matcher: '${piece}' at character ${at + 1} expands to more than ${MAX_STATES} parts. Use smaller {n,m} counts, fewer repeated groups or fewer branches.`);
  }

  term(fl, depth) {
    const src = this.src;
    const at = this.i;
    const c = src[at];
    switch (c) {
      case '^':
        this.i += 1;
        return { node: this.assertion(OP_BOL, fl, at), quantifiable: false };
      case '$':
        this.i += 1;
        return { node: this.assertion(OP_EOL, fl, at), quantifiable: false };
      case '(':
        return { node: this.group(fl, depth), quantifiable: true };
      case '.':
        this.i += 1;
        return { node: this.native('.', fl, at), quantifiable: true };
      case '[': {
        const end = this.classEnd(at);
        this.i = end;
        // [] matches no character (with any flags): a part that holds one can never match
        if (end === at + 2) return { node: FAIL(), quantifiable: true };
        return { node: this.native(src.slice(at, end), fl, at), quantifiable: true };
      }
      case '\\':
        return this.escape(fl);
      case '*':
      case '+':
      case '?':
        return this.unreadable(at);
      case '{':
        if (this.u || this.interval(at)) return this.unreadable(at);
        this.i += 1;
        return { node: this.literal(0x7b, fl, at), quantifiable: true };
      case '}':
      case ']':
        if (this.u) return this.unreadable(at);
        break;
      default:
        break;
    }
    let code = src.charCodeAt(at);
    this.i += 1;
    if (this.u && isLead(code) && this.i < src.length && isTrail(src.charCodeAt(this.i))) {
      code = (code - 0xd800) * 0x400 + (src.charCodeAt(this.i) - 0xdc00) + 0x10000;
      this.i += 1;
    }
    return { node: this.literal(code, fl, at), quantifiable: true };
  }

  /** The end (exclusive) of the class that starts at i, read as V8 reads it. */
  classEnd(i) {
    const src = this.src;
    let j = i + 1;
    if (src[j] === '^') j += 1;
    while (j < src.length) {
      const c = src[j];
      if (c === '\\') j += 2;
      else if (c === ']') return j + 1;
      else j += 1;
    }
    return this.unreadable(i);
  }

  group(fl, depth) {
    const src = this.src;
    const at = this.i;
    if (depth + 1 > MAX_DEPTH) {
      this.refuse('too-large', at, 1, `This pattern nests groups more than ${MAX_DEPTH} deep (at character ${at + 1}), so J-Wicket does not run it. Use fewer nested groups.`);
    }
    let inner = fl;
    if (src[at + 1] === '?') {
      const k = src[at + 2];
      if (k === ':') {
        this.i = at + 3;
      } else if (k === '=' || k === '!' || (k === '<' && (src[at + 3] === '=' || src[at + 3] === '!'))) {
        const piece = src.slice(at, k === '<' ? at + 4 : at + 3);
        this.refuse('lookaround', at, piece.length, `J-Wicket does not run lookahead or lookbehind such as '${piece}' (at character ${at + 1}). Write the pattern without (?=, (?!, (?<= and (?<!, for example as two separate terms.`);
      } else if (k === '<') {
        const gt = src.indexOf('>', at + 3);
        if (gt < 0) this.unreadable(at);
        this.i = gt + 1;
      } else if (k === 'i' || k === 'm' || k === 's' || k === '-') {
        let j = at + 2;
        const add = new Set();
        const remove = new Set();
        let set = add;
        for (; j < src.length && src[j] !== ':'; j += 1) {
          const f = src[j];
          if (f === '-' && set === add) set = remove;
          else if ((f === 'i' || f === 'm' || f === 's') && !add.has(f) && !remove.has(f)) set.add(f);
          else this.unreadable(at);
        }
        if (src[j] !== ':' || (add.size === 0 && remove.size === 0)) this.unreadable(at);
        inner = { ...fl };
        for (const f of add) inner[f] = true;
        for (const f of remove) inner[f] = false;
        if (inner.i !== fl.i && ENGINE_QUIRKS.caseModifierGroups) {
          // V8 12.4 and 13.6 apply such a group's i to some characters and not others, depending on
          // how the line is stored and on what else the pattern holds (see caseModifierGroupsDiffer);
          // a group that leaves i as it is (or only changes m and s) is read as the spec says.
          const piece = src.slice(at, j + 1);
          this.refuse('unreadable', at, piece.length, `This browser does not apply the i of a group such as '${piece}' (at character ${at + 1}) the way the standard does, so J-Wicket does not run it here. Put the i flag on the whole pattern or leave it off, and write the letters whose case matters as classes such as [Dd]rop.`);
        }
        this.i = j + 1;
      } else {
        this.unreadable(at);
      }
    } else {
      this.i = at + 1;
    }
    const body = this.disjunction(inner, depth + 1);
    if (src[this.i] !== ')') this.unreadable(this.i < src.length ? this.i : at);
    this.i += 1;
    return body;
  }

  backref(at, length) {
    const piece = this.src.slice(at, at + length);
    this.refuse('backreference', at, length, `J-Wicket does not run back-references such as '${piece}' (at character ${at + 1}). Write the repeated text out instead of \\1 or \\k<name>.`);
  }

  /** V8's ParseOctalLiteral from i: up to three octal digits with a value below 256. */
  octal(i) {
    const src = this.src;
    let v = src.charCodeAt(i) - 0x30;
    let j = i + 1;
    const o = (k) => src.charCodeAt(k) >= 0x30 && src.charCodeAt(k) <= 0x37;
    if (o(j)) {
      v = v * 8 + (src.charCodeAt(j) - 0x30);
      j += 1;
      if (v < 32 && o(j)) {
        v = v * 8 + (src.charCodeAt(j) - 0x30);
        j += 1;
      }
    }
    return { v, end: j };
  }

  /** \u escapes as V8's ParseUnicodeEscape reads them; j is the index after 'u'. { v, end } or null. */
  unicodeEscape(j) {
    const src = this.src;
    if (this.u && src[j] === '{') {
      let k = j + 1;
      let v = 0;
      if (hexVal(src.charCodeAt(k)) < 0) return null;
      while (hexVal(src.charCodeAt(k)) >= 0) {
        v = v * 16 + hexVal(src.charCodeAt(k));
        if (v > 0x10ffff) return null;
        k += 1;
      }
      if (src[k] !== '}') return null;
      return { v, end: k + 1 };
    }
    const hex4 = (k) => {
      let v = 0;
      for (let n = 0; n < 4; n += 1) {
        const h = hexVal(src.charCodeAt(k + n));
        if (h < 0) return -1;
        v = v * 16 + h;
      }
      return v;
    };
    const v = hex4(j);
    if (v < 0) return null;
    if (this.u && isLead(v) && src[j + 4] === '\\' && src[j + 5] === 'u') {
      const t = hex4(j + 6);
      if (t >= 0 && isTrail(t)) return { v: (v - 0xd800) * 0x400 + (t - 0xdc00) + 0x10000, end: j + 10 };
    }
    return { v, end: j + 4 };
  }

  escape(fl) {
    const src = this.src;
    const at = this.i;
    const d = src[at + 1];
    if (d === undefined) return this.unreadable(at);
    const lit = (code, end) => {
      this.i = end;
      return { node: this.literal(code, fl, at), quantifiable: true };
    };
    if (d === 'b' || d === 'B') {
      this.i = at + 2;
      return { node: this.assertion(d === 'b' ? OP_WORDB : OP_NWORDB, fl, at), quantifiable: false };
    }
    if (d >= '1' && d <= '9') {
      if (this.u) return this.backref(at, 2);
      // V8's ParseBackReferenceIndex: all the digits, a back-reference when at most the group count.
      let j = at + 1;
      let v = 0;
      let over = false;
      while (isDigit(src.charCodeAt(j))) {
        v = v * 10 + (src.charCodeAt(j) - 0x30);
        if (v > 65536) over = true;
        j += 1;
      }
      if (!over && v <= this.captures) return this.backref(at, j - at);
      if (d === '8' || d === '9') return lit(d.charCodeAt(0), at + 2);
      const o = this.octal(at + 1);
      return lit(o.v, o.end);
    }
    if (d === '0') {
      if (!isDigit(src.charCodeAt(at + 2))) return lit(0, at + 2);
      if (this.u) return this.unreadable(at);
      const o = this.octal(at + 1);
      return lit(o.v, o.end);
    }
    switch (d) {
      case 'd':
      case 'D':
      case 's':
      case 'S':
      case 'w':
      case 'W':
        this.i = at + 2;
        return { node: this.native(src.slice(at, at + 2), fl, at), quantifiable: true };
      case 'p':
      case 'P': {
        if (!this.u) return lit(d.charCodeAt(0), at + 2);
        if (src[at + 2] !== '{') return this.unreadable(at);
        const close = src.indexOf('}', at + 3);
        if (close < 0) return this.unreadable(at);
        const text = src.slice(at, close + 1);
        if (!/^\\[pP]\{[A-Za-z0-9_=]+\}$/.test(text)) return this.unreadable(at);
        this.i = close + 1;
        return { node: this.native(text, fl, at), quantifiable: true };
      }
      case 'k':
        if (this.u || this.named) {
          const gt = src.indexOf('>', at);
          return this.backref(at, gt > at ? gt + 1 - at : 2);
        }
        return lit(0x6b, at + 2);
      case 'c': {
        const l = src.charCodeAt(at + 2);
        if ((l >= 0x41 && l <= 0x5a) || (l >= 0x61 && l <= 0x7a)) return lit(l & 0x1f, at + 3);
        if (this.u) return this.unreadable(at);
        return lit(0x5c, at + 1); // a backslash; the 'c' is read as the next term
      }
      case 'f':
        return lit(0x0c, at + 2);
      case 'n':
        return lit(0x0a, at + 2);
      case 'r':
        return lit(0x0d, at + 2);
      case 't':
        return lit(0x09, at + 2);
      case 'v':
        return lit(0x0b, at + 2);
      case 'x': {
        const h1 = hexVal(src.charCodeAt(at + 2));
        const h2 = hexVal(src.charCodeAt(at + 3));
        if (h1 >= 0 && h2 >= 0) return lit(h1 * 16 + h2, at + 4);
        if (this.u) return this.unreadable(at);
        return lit(0x78, at + 2);
      }
      case 'u': {
        const e = this.unicodeEscape(at + 2);
        if (e) return lit(e.v, e.end);
        if (this.u) return this.unreadable(at);
        return lit(0x75, at + 2);
      }
      default:
        break;
    }
    if (this.u) {
      if (!SYNTAX_CHARS.includes(d)) return this.unreadable(at);
      return lit(d.charCodeAt(0), at + 2);
    }
    // Annex B identity escape: the code unit itself (\c and \k are handled above).
    return lit(src.charCodeAt(at + 1), at + 2);
  }
}

const FAIL = () => ({ t: N_FAIL, min: Infinity, pure: false, zw: true, size: 1 });

function mkSeq(items) {
  const flat = [];
  for (const it of items) {
    if (it.t === N_EMPTY) continue;
    if (it.t === N_SEQ) flat.push(...it.items);
    else flat.push(it);
  }
  if (flat.length === 0) return EMPTY;
  if (flat.length === 1) return flat[0];
  let min = 0;
  let pure = true;
  let zw = true;
  let size = 0;
  for (const it of flat) {
    if (it.t === N_FAIL) return FAIL();
    min += it.min;
    pure = pure && it.pure;
    zw = zw && it.zw === true;
    size += it.size;
  }
  // parts that together need more code units than a line test() reads can never match
  if (min > MAX_SUBJECT) return FAIL();
  return { t: N_SEQ, items: flat, min, pure, zw, size: Math.min(size, MAX_STATES) };
}

function mkAlt(alts) {
  const live = alts.filter((a) => a.t !== N_FAIL);
  if (live.length === 0) return FAIL();
  if (live.length === 1) return live[0];
  let min = Infinity;
  let pure = false;
  let zw = true;
  let size = live.length - 1;
  for (const a of live) {
    min = Math.min(min, a.min);
    pure = pure || a.pure;
    zw = zw && a.zw === true;
    size += a.size;
  }
  return { t: N_ALT, alts: live, min, pure, zw, size: Math.min(size, MAX_STATES) };
}

/** A repetition of body {lo,hi} as repeat() leaves it (body neither empty, nor only asserting, nor never matching). */
function mkRep(body, lo, hi, at) {
  const size = Math.min(lo * body.size + (hi === Infinity ? body.size + 1 : (hi - lo) * (body.size + 1)), MAX_STATES);
  return { t: N_REP, body, lo, hi, at, min: lo * body.min, pure: lo === 0 || body.pure, zw: false, size };
}

/**
 * test() only asks whether some substring matches, so a part at the edge of the pattern needs only
 * what can change that answer. Two rewrites, each proved on positions (without lookaround and
 * back-references a part matches from position p to q whatever lies outside):
 *
 * keepStart(T) matches from p to some q exactly when T matches from p to some q (the end does not
 * matter). A part that can match empty without an assertion (node.pure: a{0,n}, x?, \w*) matches
 * from p to p, so it is EMPTY; R{m,n} with m >= 1 matches from p exactly when R{m} does (its first m
 * iterations match), and only the last of those m copies is at the end; a disjunction keeps the
 * start of each branch; a sequence keeps the start of its last part.
 *
 * keepEnd(T) is the mirror: T matches from some p to q exactly when keepEnd(T) does.
 *
 * So S R{0,n} is S, S R{m,n} is S R{m}, R{0,n} S is S, and a pattern with a branch that can match
 * empty, such as deny|\w{0,1000}, matches every line: deny.{0,800} costs what deny costs and
 * \d{0,400}deny what deny costs. Leaves (atoms and assertions) are kept as they are, so the
 * parts that are left are the parts checkLimits sees.
 */
function keepStart(node) {
  if (node.pure) return EMPTY;
  if (node.t === N_SEQ) {
    const items = node.items.slice();
    const last = keepStart(items[items.length - 1]);
    if (last === items[items.length - 1]) return node;
    items[items.length - 1] = last;
    return mkSeq(items);
  }
  if (node.t === N_ALT) return mkAlt(node.alts.map(keepStart));
  if (node.t === N_REP) {
    const tail = keepStart(node.body);
    if (tail === node.body && node.hi === node.lo) return node;
    if (tail === node.body) return mkRep(node.body, node.lo, node.lo, node.at);
    return mkSeq([node.lo > 1 ? mkRep(node.body, node.lo - 1, node.lo - 1, node.at) : EMPTY, tail]);
  }
  return node;
}

function keepEnd(node) {
  if (node.pure) return EMPTY;
  if (node.t === N_SEQ) {
    const items = node.items.slice();
    const first = keepEnd(items[0]);
    if (first === items[0]) return node;
    items[0] = first;
    return mkSeq(items);
  }
  if (node.t === N_ALT) return mkAlt(node.alts.map(keepEnd));
  if (node.t === N_REP) {
    const head = keepEnd(node.body);
    if (head === node.body && node.hi === node.lo) return node;
    if (head === node.body) return mkRep(node.body, node.lo, node.lo, node.at);
    return mkSeq([head, node.lo > 1 ? mkRep(node.body, node.lo - 1, node.lo - 1, node.at) : EMPTY]);
  }
  return node;
}

/** Where to point a too-large refusal: the innermost quantified part that is too large on its own. */
function tooLargeAt(node, at) {
  const here = node.t === N_REP ? node.at : at;
  const kids = node.t === N_SEQ ? node.items : node.t === N_ALT ? node.alts : node.t === N_REP ? [node.body] : [];
  for (const k of kids) if (k.size >= MAX_STATES) return tooLargeAt(k, here);
  return here;
}

/**
 * The limits are checked on what is left of the pattern once the parts that can never take part in a
 * match are dropped (a part repeated {0} times, one beside a part that can never match, a branch that
 * can never match): such parts get no NFA state and no native matcher, so (?:a{1000}){0}x is the
 * same as x and costs what x costs. Refuses a pattern that needs more than MAX_STATES states or more
 * than MAX_CLASS_ATOMS different classes and escapes, keeps only the case-folding checks of the
 * disjunctions that are left (see checkAlternativeFolding), and returns the keys of the native atoms.
 */
function checkLimits(parser, root) {
  if (root.size + 1 > MAX_STATES) parser.tooLarge(tooLargeAt(root, 0));
  const live = new Set();
  const natives = new Set();
  const walk = (node) => {
    if (node.t === N_ATOM || node.t === N_ASSERT) {
      live.add(node);
      if (node.a >= 0 && parser.atoms[node.a].kind === A_NATIVE && !natives.has(node.a)) {
        natives.add(node.a);
        if (natives.size > MAX_CLASS_ATOMS) {
          parser.refuse('too-large', node.at, 1, `This pattern has more than ${MAX_CLASS_ATOMS} different classes and escapes (such as [a-z], \\d, \\w or .), so J-Wicket does not run it. Use fewer different classes.`);
        }
      }
    } else if (node.t === N_SEQ) node.items.forEach(walk);
    else if (node.t === N_ALT) node.alts.forEach(walk);
    else if (node.t === N_REP) walk(node.body);
  };
  walk(root);
  parser.foldChecks = parser.foldChecks.filter((c) => c.nodes.some((n) => live.has(n)));
  return [...natives].map((a) => parser.atoms[a].key);
}

// --- compile ----------------------------------------------------------------------------------------

function compileProgram(root) {
  const op = [];
  const out1 = [];
  const out2 = [];
  const arg = [];
  const emit = (o, a, x, y) => {
    op.push(o);
    arg.push(a);
    out1.push(x);
    out2.push(y);
    return op.length - 1;
  };
  const match = emit(OP_MATCH, -1, -1, -1);
  const comp = (node, next) => {
    switch (node.t) {
      case N_ATOM:
        return emit(OP_CHAR, node.a, next, -1);
      case N_ASSERT:
        return emit(node.op, node.a, next, -1);
      case N_EMPTY:
        return next;
      case N_FAIL:
        return emit(OP_FAIL, -1, -1, -1);
      case N_SEQ: {
        let cur = next;
        for (let k = node.items.length - 1; k >= 0; k -= 1) cur = comp(node.items[k], cur);
        return cur;
      }
      case N_ALT: {
        const entries = node.alts.map((a) => comp(a, next));
        let cur = entries[entries.length - 1];
        for (let k = entries.length - 2; k >= 0; k -= 1) cur = emit(OP_SPLIT, -1, entries[k], cur);
        return cur;
      }
      case N_REP: {
        const { body, lo: min, hi: max } = node;
        let cur = next;
        if (max === Infinity) {
          const loop = emit(OP_SPLIT, -1, -1, next);
          out1[loop] = comp(body, loop);
          cur = loop;
        } else {
          for (let k = 0; k < max - min; k += 1) cur = emit(OP_SPLIT, -1, comp(body, cur), next);
        }
        for (let k = 0; k < min; k += 1) cur = comp(body, cur);
        return cur;
      }
      default:
        throw new Error('regexvm: unknown node');
    }
  };
  const start = comp(root, match);
  return {
    start,
    op: Int8Array.from(op),
    arg: Int32Array.from(arg),
    out1: Int32Array.from(out1),
    out2: Int32Array.from(out2),
  };
}

// --- atoms ------------------------------------------------------------------------------------------

// Answers per character, kept by every native atom matcher and by the folding classes of each pattern.
// A table holds the code units below 256 in a fixed array, the rest of the BMP in blocks of 256
// allocated as they are first needed, and astral code points in a small Map that is emptied when it
// reaches ASTRAL_MAX entries (so no table ever rehashes a large Map inside one test()). Every block
// and astral entry is charged to one budget shared by all tables: when CACHE_BUDGET is spent, every
// table that holds anything is emptied at once. The memory of all the caches together therefore
// stays near CACHE_BUDGET (plus 256 values per table), however many patterns and characters an
// operator's session meets; an emptied table asks the engine again.
const ASTRAL_MAX = 4096;
const CACHE_BUDGET = 8 << 20; // bytes, approximately
const BLOCK_COST = 512; // one block of 256 values, with its header (Int16 blocks are charged twice)
const ASTRAL_COST = 64; // one Map entry
const liveTables = [];
let cacheSpent = 0;

function newTable(Kind) {
  return { Kind, small: new Kind(256), bmp: null, astral: null, live: false };
}

function emptyAllTables() {
  for (const t of liveTables) {
    t.bmp = null;
    t.astral = null;
    t.live = false;
  }
  liveTables.length = 0;
  cacheSpent = 0;
}

/** The value kept for code point c, or 0 when there is none. */
function tableGet(t, c) {
  if (c < 256) return t.small[c];
  if (c < 0x10000) {
    const b = t.bmp === null ? undefined : t.bmp[c >>> 8];
    return b === undefined ? 0 : b[c & 255];
  }
  if (t.astral === null) return 0;
  return t.astral.get(c) ?? 0;
}

/** Keeps value v (not 0) for code point c. */
function tableSet(t, c, v) {
  if (c < 256) {
    t.small[c] = v;
    return;
  }
  let cost = 0;
  if (c < 0x10000) {
    if (t.bmp === null) t.bmp = new Array(256);
    let b = t.bmp[c >>> 8];
    if (b === undefined) {
      b = new t.Kind(256);
      t.bmp[c >>> 8] = b;
      cost = BLOCK_COST * t.Kind.BYTES_PER_ELEMENT;
    }
    b[c & 255] = v;
  } else {
    if (t.astral === null) t.astral = new Map();
    else if (t.astral.size >= ASTRAL_MAX) t.astral.clear();
    t.astral.set(c, v);
    cost = ASTRAL_COST;
  }
  if (cost === 0) return;
  if (!t.live) {
    t.live = true;
    liveTables.push(t);
  }
  cacheSpent += cost;
  if (cacheSpent > CACHE_BUDGET) emptyAllTables();
}

/** For tests: the approximate bytes held by all per-character caches, and how many tables hold any. */
export function cacheUse() {
  return { bytes: cacheSpent, tables: liveTables.length, budget: CACHE_BUDGET };
}

// Native atom matchers are shared between patterns (an operator edits one pattern a keystroke at a
// time), keyed by text and flags; each keeps its answer per character (1: no, 2: yes).
const NATIVE_CACHE = new Map();
const NATIVE_CACHE_MAX = 512;

function nativeMatcher(atom) {
  const key = `${atom.word ? 'W' : 'N'}${atom.flags}/${atom.text}`;
  let m = NATIVE_CACHE.get(key);
  if (m) return m;
  const re = atom.word ? new RegExp('\\b', atom.flags) : new RegExp(`^(?:${atom.text})$`, atom.flags);
  m = { re, table: newTable(Int8Array) };
  if (NATIVE_CACHE.size >= NATIVE_CACHE_MAX) NATIVE_CACHE.clear();
  NATIVE_CACHE.set(key, m);
  return m;
}

function nativeTest(m, c) {
  const v = tableGet(m.table, c);
  if (v !== 0) return v === 2;
  const r = m.re.test(String.fromCodePoint(c));
  tableSet(m.table, c, r ? 2 : 1);
  return r;
}

/**
 * Literals under i. Two literals that match the same character match each other (both fold to that
 * character's case-folding class), so a character's class among the pattern's literals can be named
 * by the first literal that matches it: classOf(c) is that literal's index, or -1, and literal k
 * matches c exactly when classOf(c) === classOf(literal k). The answers come from native RegExps with
 * the pattern's i (and u) flags: per FOLD_CHUNK literals, an alternation ^(?:(l1)|(l2)|...)$ whose
 * first matching branch names the literal (each branch is that literal's own ^(?:lit)$), behind
 * native classes of the same literals ([...], one for all and one per chunk) that only skip literals
 * that cannot match: a class under i matches a character exactly when one of its members does.
 * (Each branch is a capture group: V8 merges plain alternatives such as k|K|\u212a under i into
 * one, and then no longer matches the Kelvin sign, which /\u212a/i alone does.)
 */
const FOLD_CHUNK = 64;
function foldClasses(codes, unicode) {
  const flags = unicode ? 'iu' : 'i';
  const text = (list) => list.map((c) => cpText(c, unicode));
  const all = new RegExp(`^[${text(codes).join('')}]$`, flags);
  const chunks = [];
  for (let j = 0; j < codes.length; j += FOLD_CHUNK) {
    const part = text(codes.slice(j, j + FOLD_CHUNK));
    chunks.push({
      start: j,
      any: new RegExp(`^[${part.join('')}]$`, flags),
      which: new RegExp(`^(?:${part.map((t) => `(${t})`).join('|')})$`, flags),
    });
  }
  const table = newTable(Int16Array); // classOf(c) + 2, at most MAX_STATES + 1
  const classOf = (c) => {
    const kept = tableGet(table, c);
    if (kept !== 0) return kept - 2;
    let v = -1;
    const s = String.fromCodePoint(c);
    if (all.test(s)) {
      for (const ch of chunks) {
        if (!ch.any.test(s)) continue;
        const m = ch.which.exec(s);
        if (!m) continue;
        for (let k = 1; k < m.length; k += 1) {
          if (m[k] !== undefined) {
            v = ch.start + k - 1;
            break;
          }
        }
        break;
      }
    }
    tableSet(table, c, v + 2);
    return v;
  };
  return { classOf, own: codes.map((c) => classOf(c)) };
}

// --- run --------------------------------------------------------------------------------------------

const isLineTerminator = (c) => c === 0x0a || c === 0x0d || c === 0x2028 || c === 0x2029;

// The hot loop below runs once per live state and position, so it must stay in optimized code: it
// reads only typed arrays and small integers, and every answer that depends on the character (the
// native atoms, \b's word test, the folding class) is worked out first, once per position, by
// classify(). A line that brings a kind of character the engine has not met yet (a line terminator,
// an astral or lone surrogate, a new cache block) then deoptimizes classify(), which does little work
// per position, and not the loop over hundreds of states (round 4: a fresh tab took 75 ms for one
// such line, against 12 ms warm). Both are plain functions shared by every pattern.

/** Fills the per-position answers of the line in vm.units[0..n) (row n stays empty: no character there). */
function classify(vm, n) {
  const K = vm.natives.length;
  const u = vm.units;
  if (K > 0) {
    const need = (n + 1) * K;
    if (vm.hits.length < need) vm.hits = new Uint8Array(need);
    const hits = vm.hits;
    for (let k = 0; k < K; k += 1) {
      const m = vm.natives[k];
      let r = k;
      for (let pos = 0; pos < n; pos += 1, r += K) hits[r] = nativeTest(m, u[pos]) ? 1 : 0;
      hits[r] = 0;
    }
  }
  if (vm.classOf !== null) {
    if (vm.cids.length < n + 1) vm.cids = new Int32Array(n + 1);
    const cids = vm.cids;
    const classOf = vm.classOf;
    for (let pos = 0; pos < n; pos += 1) cids[pos] = classOf(u[pos]);
    cids[n] = -3; // no literal's class
  }
}

/** The Pike VM over vm.units[0..n): whether the program matches some substring. */
function run(vm, n) {
  const Q = vm.prog;
  const start = vm.start;
  const K = vm.natives.length;
  const u = vm.units;
  const hits = vm.hits;
  const cids = vm.cids;
  let markCur = vm.markCur;
  let markNext = vm.markNext;
  let cur = vm.cur;
  let next = vm.next;
  if (vm.gen > 0x3fffffff - n) {
    markCur.fill(0);
    markNext.fill(0);
    vm.gen = 0;
  }
  let g = vm.gen + 1;
  let found = false;
  markCur[start] = g;
  cur[0] = start;
  let sp = 1;
  for (let pos = 0; ; pos += 1) {
    // Expand every state of this position; character states that match u[pos] put their
    // successor on the next position's stack.
    const mk = markCur;
    const mn = markNext;
    const st = cur;
    const nx = next;
    const gn = g + 1;
    const c = pos < n ? u[pos] : -1;
    const row = pos * K;
    let np = 0;
    while (sp > 0) {
      const x = st[--sp];
      const r = x << 2;
      const o = Q[r];
      if (o === OP_SPLIT) {
        const y = Q[r + 3];
        if (mk[y] !== g) {
          mk[y] = g;
          st[sp++] = y;
        }
        const z = Q[r + 2];
        if (mk[z] !== g) {
          mk[z] = g;
          st[sp++] = z;
        }
        continue;
      }
      if (o === OP_CHAR) {
        if (c !== Q[r + 1]) continue; // c is -1 past the end
      } else if (o === OP_NATIVE) {
        if (hits[row + Q[r + 1]] === 0) continue; // row n is all 0
      } else if (o === OP_FOLD) {
        if (cids[pos] !== Q[r + 1]) continue; // cids[n] is no class
      } else {
        // the match state, a dead end, or an assertion: on success, its successor at this position
        if (o === OP_MATCH) {
          found = true;
          break;
        }
        if (o === OP_FAIL) continue;
        if (o === OP_BOL) {
          if (pos !== 0) continue;
        } else if (o === OP_EOL) {
          if (pos !== n) continue;
        } else if (o === OP_BOL_M) {
          if (pos !== 0 && !isLineTerminator(u[pos - 1])) continue;
        } else if (o === OP_EOL_M) {
          if (pos !== n && !isLineTerminator(c)) continue;
        } else {
          // OP_WORDB / OP_NWORDB: is exactly one neighbour a word character?
          const w = Q[r + 1];
          const before = pos > 0 ? hits[row - K + w] : 0;
          if ((before !== hits[row + w]) !== (o === OP_WORDB)) continue;
        }
        const y = Q[r + 2];
        if (mk[y] !== g) {
          mk[y] = g;
          st[sp++] = y;
        }
        continue;
      }
      const y = Q[r + 2];
      if (mn[y] !== gn) {
        mn[y] = gn;
        nx[np++] = y;
      }
    }
    if (found || pos >= n) break;
    // An unanchored search: a match may also start at the next position.
    if (mn[start] !== gn) {
      mn[start] = gn;
      nx[np++] = start;
    }
    g = gn;
    markCur = mn;
    markNext = mk;
    cur = nx;
    next = st;
    sp = np;
  }
  vm.gen = g + 1; // marks of g + 1 may be on markNext: start past them
  vm.markCur = markCur;
  vm.markNext = markNext;
  vm.cur = cur;
  vm.next = next;
  return found;
}

function makeTester(prog, atoms, unicode) {
  const S = prog.op.length;
  // One record of four numbers per state: opcode, argument, out1, out2 (records are read together).
  const P = new Int32Array(S * 4);
  for (let x = 0; x < S; x += 1) {
    P[x * 4] = prog.op[x];
    P[x * 4 + 1] = prog.arg[x];
    P[x * 4 + 2] = prog.out1[x];
    P[x * 4 + 3] = prog.out2[x];
  }
  // Only the atoms the program uses: those of a part that can never match or that is repeated
  // {0} times (such as (?:...){0}) cost neither native tests nor a place in the folding table.
  const used = new Uint8Array(atoms.length);
  for (let x = 0; x < S; x += 1) {
    const o = prog.op[x];
    if (o === OP_CHAR || o === OP_WORDB || o === OP_NWORDB) used[prog.arg[x]] = 1;
  }
  // The argument of each state: a literal's code point (OP_CHAR), its folding class (OP_FOLD), or
  // the native atom's column in the per-position answers (OP_NATIVE, and \b \B).
  const argOf = new Int32Array(atoms.length);
  const natives = [];
  const foldCodes = [];
  const foldIds = [];
  atoms.forEach((a, k) => {
    if (!used[k]) return;
    if (a.kind === A_EXACT) argOf[k] = a.code;
    else if (a.kind === A_FOLD) {
      foldIds.push(k);
      foldCodes.push(a.code);
    } else {
      argOf[k] = natives.length;
      natives.push(nativeMatcher(a));
    }
  });
  let classOf = null;
  if (foldCodes.length) {
    const fc = foldClasses(foldCodes, unicode);
    classOf = fc.classOf;
    foldIds.forEach((k, j) => {
      if (fc.own[j] < 0) throw new RegexUnsupported('unreadable', 'J-Wicket could not read how this browser folds the case of a character in this pattern, so it does not run it. Remove the i flag or write the character as a class such as [Kk].', 0, 1);
      argOf[k] = fc.own[j];
    });
  }
  for (let x = 0; x < S; x += 1) {
    const r = x * 4;
    const o = P[r];
    if (o !== OP_CHAR && o !== OP_WORDB && o !== OP_NWORDB) continue;
    const a = P[r + 1];
    if (o === OP_CHAR && atoms[a].kind === A_FOLD) P[r] = OP_FOLD;
    else if (o === OP_CHAR && atoms[a].kind === A_NATIVE) P[r] = OP_NATIVE;
    P[r + 1] = argOf[a];
  }
  const vm = {
    prog: P,
    start: prog.start,
    natives,
    classOf,
    units: new Int32Array(64),
    hits: new Uint8Array(natives.length ? 64 * natives.length : 0),
    cids: new Int32Array(classOf ? 64 : 0),
    // Two mark arrays, for the position being expanded and the next one; a state is marked with
    // the position's generation when it is put on that position's stack, so it is expanded once.
    markCur: new Int32Array(S),
    markNext: new Int32Array(S),
    cur: new Int32Array(S),
    next: new Int32Array(S),
    gen: 0,
  };

  return function test(input) {
    const str = String(input);
    if (str.length > MAX_SUBJECT) throw new RangeError(`J-Wicket's matcher reads lines of at most ${MAX_SUBJECT} characters.`);
    if (vm.units.length < str.length) vm.units = new Int32Array(str.length);
    const u = vm.units;
    let n = 0;
    for (let j = 0; j < str.length; j += 1) {
      let c = str.charCodeAt(j);
      if (unicode && c >= 0xd800 && c <= 0xdbff && j + 1 < str.length) {
        const t = str.charCodeAt(j + 1);
        if (t >= 0xdc00 && t <= 0xdfff) {
          c = (c - 0xd800) * 0x400 + (t - 0xdc00) + 0x10000;
          j += 1;
        }
      }
      u[n++] = c;
    }
    classify(vm, n);
    return run(vm, n);
  };
}

/**
 * V8 12.4 and 13.6 (Node 22 and 24, and the Chromium releases built on them) rewrite a disjunction
 * of more than two branches under i: runs of three or more branches made only of literal characters
 * that start with the same letter by Unicode case folding become one shared prefix, and without u
 * that prefix is then matched with the non-u folding of its first branch. k|K|\u212a then no longer
 * matches the Kelvin sign, which /\u212a/i alone matches (likewise s|S|\u017f, xk|xK|x\u212a). Two
 * branches are never rewritten, and Chrome 158 matches all of them as the spec does. ENGINE_QUIRKS
 * tells which engine runs the page; only where it has the quirk is a disjunction refused, and only
 * one with three or more branches, at least three of them starting with literals, whose leading
 * literals fold into different classes with and without u (the classes are asked of the engine, as
 * for any literal under i). This is wider than the rewrite itself, on purpose.
 */
function checkAlternativeFolding(parser) {
  for (const { codes, at } of parser.foldChecks) {
    // ASCII letters fold the same way with and without u ({a, A}); only a non-ASCII one can differ
    if (codes.length < 2 || codes.every((c) => c < 0x80)) continue;
    const plain = foldClasses(codes, false).own;
    const unicode = foldClasses(codes, true).own;
    if (plain.some((v, k) => v !== unicode[k])) {
      throw new RegexUnsupported('unreadable', `This browser does not match three or more case-insensitive branches such as k|K|\\u212a (the Kelvin sign) the way it matches each character alone, and this pattern has such branches (at character ${at + 1}), so J-Wicket does not run it. Write the characters as one class, for example [kK\\u212a], or add the u flag.`, at, 1);
    }
  }
}

/**
 * Whether the match state can be reached without consuming anything only by passing a \B. V8 12.4
 * and 13.6 also try the position between the two halves of a surrogate pair when the u flag is set,
 * where \B holds (both halves are non-word characters) and any other assertion or character fails:
 * /\B/u.test('a\u{1F600}a') is true there, false by the spec, which only tries code point
 * boundaries. Chrome 158 follows the spec. Where ENGINE_QUIRKS says the engine has the quirk,
 * patterns that could see the difference are refused.
 */
function emptyOnlyThroughNotWordBoundary(prog) {
  const reach = (passB) => {
    const seen = new Uint8Array(prog.op.length);
    const stack = [prog.start];
    seen[prog.start] = 1;
    while (stack.length) {
      const x = stack.pop();
      const o = prog.op[x];
      if (o === OP_MATCH) return true;
      const outs = o === OP_SPLIT ? [prog.out1[x], prog.out2[x]] : o === OP_NWORDB && passB ? [prog.out1[x]] : [];
      for (const y of outs) {
        if (!seen[y]) {
          seen[y] = 1;
          stack.push(y);
        }
      }
    }
    return false;
  };
  return reach(true) && !reach(false);
}

// --- entry point ------------------------------------------------------------------------------------

/**
 * A matcher for a user pattern: { test(str) -> boolean, source, flags }. test() gives the same answer
 * as new RegExp(source, flags).test(str) on a fresh RegExp, in time linear in the length of str
 * (and the spec's answer where that native test() throws instead of answering: see the top of this file).
 * Throws the native SyntaxError for an invalid pattern and RegexUnsupported for one J-Wicket does not
 * run (see the top of this file).
 */
export function compileUserRegex(source, flags = '') {
  const src = String(source ?? '');
  const fl = String(flags ?? '');
  // The flags, the length and the property escapes are checked before new RegExp, which reads the
  // whole source first: about 100 ms per megabyte, more with v, and a quarter of a millisecond per
  // property escape. new RegExp('', fl) still gives the browser's own error for a flag it does not know.
  new RegExp('', fl); // eslint-disable-line no-new -- the browser's own syntax error for the flags
  for (const f of fl) {
    if (f === 'v') throw new RegexUnsupported('flags', 'J-Wicket does not run regular expressions with the v flag. Use the u flag instead.', 0, 0);
    if (!'dimsu'.includes(f)) throw new RegexUnsupported('flags', `The ${f} flag does not apply to a filter. Remove it.`, 0, 0);
  }
  if (src.length > REGEX_SOURCE_MAX) {
    throw new RegexUnsupported('too-large', `This pattern is longer than ${REGEX_SOURCE_MAX} characters, so J-Wicket does not run it. Write a shorter pattern.`, REGEX_SOURCE_MAX, src.length - REGEX_SOURCE_MAX);
  }
  if (fl.includes('u')) {
    let count = 0;
    for (let i = 0; i < src.length; i += 1) {
      if (src[i] !== '\\') continue;
      if ((src[i + 1] === 'p' || src[i + 1] === 'P') && src[i + 2] === '{' && (count += 1) > MAX_PROPERTY_ESCAPES) {
        throw new RegexUnsupported('too-large', `This pattern has more than ${MAX_PROPERTY_ESCAPES} property escapes such as \\p{L}, so J-Wicket does not run it. Use fewer, for example one class [\\p{L}\\p{N}] instead of repeating them.`, i, 3);
      }
      i += 1;
    }
  }
  new RegExp(src, fl); // eslint-disable-line no-new -- the browser's own syntax error, as is
  const unicode = fl.includes('u');
  const parser = new Parser(src, unicode, { i: fl.includes('i'), m: fl.includes('m'), s: fl.includes('s') });
  const root = keepEnd(keepStart(parser.parse()));
  const natives = checkLimits(parser, root);
  checkAlternativeFolding(parser);
  const prog = compileProgram(root);
  if (unicode && ENGINE_QUIRKS.notWordBoundaryInsidePairs && emptyOnlyThroughNotWordBoundary(prog)) {
    const at = Math.max(src.indexOf('\\B'), 0);
    throw new RegexUnsupported('unreadable', `With the u flag, this browser lets \\B match in the middle of a character such as an emoji, where the standard does not, and this pattern can match through \\B alone (at character ${at + 1}). J-Wicket does not run it: add a character to match next to \\B, or drop the u flag.`, at, 2);
  }
  const test = makeTester(prog, parser.atoms, unicode);
  return { test, source: src, flags: fl, states: prog.op.length, natives };
}
