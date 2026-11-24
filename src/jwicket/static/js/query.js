// J-Wicket query language, shared by Policies, Sessions and Logs. Pure logic: no DOM, nothing runs at
// import time. A superset of J-Web 24.4's filter box (= != >= <= AND, nested AND/OR):
//
//   expr   := or
//   or     := and ( ("OR" | "or" | "||" | "|") and )*
//   and    := unary ( ("AND" | "and" | "&&")? unary )*      juxtaposition is AND
//   unary  := ("NOT" | "not" | "-" | "!") unary | atom
//   atom   := "(" expr ")" | term
//   term   := key op value | key ":" value | value          a bare value is free text
//   op     := "=" | "!=" | ">=" | "<=" | ">" | "<" | "~"      "~" is a regular expression (browser only)
//   value  := word | "quoted" | 'quoted' | /regex/flags | v1|v2|v3   ("|" inside a value: any of)
//
// Values are typed by the key: addresses are CIDR-aware (src:10.10.0.0/16, 10.10.*), sizes take k/M/G
// (bytes>1M, decimal like Junos counters; KiB/MiB for 1024-based), durations take s/m/h/d (dur>5m),
// words take * wildcards (matched in linear time), text matches are case-insensitive. plan() splits a
// query into what the device can filter (sessions RPC parameters, log substring terms, the on-box
// report expression) and what the browser filters.
//
// Policies are matched three-valued (compileTri): application "any" covers every port, and a term
// J-Wicket cannot decide (a predefined application port it does not know, an address compared with a
// DNS name) is unknown, so the view keeps the policy and says why instead of hiding it.

// --- errors -----------------------------------------------------------------------------------------

class QueryError extends Error {
  constructor(message, pos, end) {
    super(message);
    this.pos = pos;
    this.end = end === undefined ? pos + 1 : end;
  }
}

const isSpace = (c) => c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === '\f' || c === '\v' || c === '\u00a0';
const KEY_RE = /[A-Za-z_][A-Za-z0-9_.-]*/y;
const OP_RE = /!=|>=|<=|=|>|<|~|:/y;
const KEYWORDS = { AND: 'and', and: 'and', OR: 'or', or: 'or', NOT: 'not', not: 'not' };
const REGEX_FLAGS = /^[gimsuy]*$/;

// --- IP addresses -----------------------------------------------------------------------------------

function parseV4(s) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return null;
  let n = 0;
  for (let i = 1; i <= 4; i++) {
    const o = Number(m[i]);
    if (o > 255) return null;
    n = n * 256 + o;
  }
  return n;
}

function parseV6(input) {
  let s = input;
  const pct = s.indexOf('%');
  if (pct >= 0) s = s.slice(0, pct);
  if (!s.includes(':') || !/^[0-9A-Fa-f:.]+$/.test(s)) return null;
  let tailV4 = null;
  const lastColon = s.lastIndexOf(':');
  if (s.indexOf('.', lastColon) > 0) {
    tailV4 = parseV4(s.slice(lastColon + 1));
    if (tailV4 === null) return null;
    s = `${s.slice(0, lastColon + 1)}0:0`;
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const part = (x) => (x === '' ? [] : x.split(':'));
  const head = part(halves[0]);
  const tail = halves.length === 2 ? part(halves[1]) : [];
  if (![...head, ...tail].every((g) => /^[0-9A-Fa-f]{1,4}$/.test(g))) return null;
  const missing = 8 - head.length - tail.length;
  if (halves.length === 2 ? missing < 1 : missing !== 0) return null;
  const groups = [...head, ...Array(halves.length === 2 ? missing : 0).fill('0'), ...tail];
  let n = 0n;
  for (const g of groups) n = (n << 16n) | BigInt(parseInt(g, 16));
  if (tailV4 !== null) n = (n & ~0xffffffffn) | BigInt(tailV4);
  return n;
}

/** An address, prefix, range or trailing wildcard as {v, lo, hi}; null when it is not one. */
export function parseNet(text) {
  if (text === null || text === undefined) return null;
  let s = String(text).trim();
  if (!s) return null;
  if (s[0] === '[' && s.endsWith(']')) s = s.slice(1, -1);
  const slash = s.indexOf('/');
  if (slash > 0) {
    const addr = s.slice(0, slash);
    const lenText = s.slice(slash + 1);
    if (!/^\d{1,3}$/.test(lenText)) return null;
    const len = Number(lenText);
    const a4 = parseV4(addr);
    if (a4 !== null) {
      if (len > 32) return null;
      const size = 2 ** (32 - len);
      const lo = Math.floor(a4 / size) * size;
      return { v: 4, lo, hi: lo + size - 1 };
    }
    const a6 = parseV6(addr);
    if (a6 === null || len > 128) return null;
    const size = 1n << BigInt(128 - len);
    const lo = (a6 / size) * size;
    return { v: 6, lo, hi: lo + size - 1n };
  }
  const dash = s.indexOf('-');
  if (dash > 0) {
    const a = parseNet(s.slice(0, dash));
    const b = parseNet(s.slice(dash + 1));
    if (a && b && a.v === b.v && a.lo <= b.hi) return { v: a.v, lo: a.lo, hi: b.hi };
    return null;
  }
  if (s.includes('*')) {
    const parts = s.split('.');
    if (parts.length < 2 || parts.length > 4) return null;
    let fixed = 0;
    while (fixed < parts.length && /^\d{1,3}$/.test(parts[fixed])) fixed += 1;
    if (fixed === 0 || !parts.slice(fixed).every((p) => p === '*')) return null;
    const octets = parts.slice(0, fixed).map(Number);
    if (octets.some((o) => o > 255)) return null;
    while (octets.length < 4) octets.push(0);
    const len = fixed * 8;
    return parseNet(`${octets.join('.')}/${len}`);
  }
  const a4 = parseV4(s);
  if (a4 !== null) return { v: 4, lo: a4, hi: a4 };
  const a6 = parseV6(s);
  if (a6 !== null) return { v: 6, lo: a6, hi: a6 };
  return null;
}

function overlaps(a, b) {
  return a.v === b.v && a.lo <= b.hi && b.lo <= a.hi;
}

const NET_CACHE = new Map();
function netOf(s) {
  const key = String(s);
  let v = NET_CACHE.get(key);
  if (v === undefined) {
    if (NET_CACHE.size > 20000) NET_CACHE.clear();
    v = parseNet(key);
    NET_CACHE.set(key, v);
  }
  return v;
}

/** True for words that are addresses, times or MAC addresses (so "fe80::1" is never read as key:value). */
function isLiteralWord(w) {
  if (!w) return false;
  if (/^\d{1,2}:\d{2}(:\d{2})?$/.test(w)) return true;
  if (/^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$/.test(w)) return true;
  return netOf(w) !== null;
}

// --- sizes, durations, times --------------------------------------------------------------------------

// Decimal, as network counters, Junos and format.bytes() count (1 kB = 1000 B); KiB/MiB/GiB/TiB are
// 1024-based when asked for by name.
const SIZE_UNITS = { '': 1, k: 1e3, m: 1e6, g: 1e9, t: 1e12 };
const SIZE_UNITS_BINARY = { k: 1024, m: 1024 ** 2, g: 1024 ** 3, t: 1024 ** 4 };

/** "1500", "64k", "1.5M", "2GB" (decimal), "10KiB", "1MiB" (1024-based) -> bytes; null when not a size. */
export function parseSize(text) {
  const m = /^(\d+(?:\.\d+)?)\s*(?:([kmgt])(i)?)?(b)?$/i.exec(String(text).trim());
  if (!m) return null;
  const unit = (m[2] || '').toLowerCase();
  const factor = unit && m[3] ? SIZE_UNITS_BINARY[unit] : SIZE_UNITS[unit];
  return Math.round(Number(m[1]) * factor);
}

const DUR_UNITS = { ms: 0.001, s: 1, m: 60, min: 60, h: 3600, d: 86400, w: 604800 };

/** "30", "30s", "5m", "1h30m", "2d" -> seconds; null when not a duration. */
export function parseDuration(text) {
  const s = String(text).trim().toLowerCase();
  if (!s) return null;
  if (/^\d+(\.\d+)?$/.test(s)) return Number(s);
  const re = /(\d+(?:\.\d+)?)(ms|min|s|m|h|d|w)/y;
  let total = 0;
  let pos = 0;
  while (pos < s.length) {
    re.lastIndex = pos;
    const m = re.exec(s);
    if (!m) return null;
    total += Number(m[1]) * DUR_UNITS[m[2]];
    pos = re.lastIndex;
  }
  return total;
}

/** A point in time as an inclusive [lo, hi] ms range at the precision written; null when not a time. */
export function parseTime(text, now = Date.now()) {
  const s = String(text).trim();
  let m;
  if ((m = /^(\d{4})-(\d\d)-(\d\d)$/.exec(s))) {
    const lo = Date.UTC(+m[1], +m[2] - 1, +m[3]);
    return Number.isFinite(lo) ? { lo, hi: lo + 86400000 - 1 } : null;
  }
  if ((m = /^(\d{4}-\d\d-\d\d)[T .](\d\d:\d\d)(:\d\d)?(\.\d{1,3})?(Z|[+-]\d\d:?\d\d)?$/.exec(s))) {
    let zone = m[5] || 'Z';
    if (/^[+-]\d{4}$/.test(zone)) zone = `${zone.slice(0, 3)}:${zone.slice(3)}`;
    const lo = Date.parse(`${m[1]}T${m[2]}${m[3] || ':00'}${m[4] || ''}${zone}`);
    if (!Number.isFinite(lo)) return null;
    const span = m[4] ? 1 : m[3] ? 1000 : 60000;
    return { lo, hi: lo + span - 1 };
  }
  if ((m = /^(\d\d):(\d\d)(?::(\d\d))?$/.exec(s))) {
    const d = new Date(now);
    const lo = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate(), +m[1], +m[2], m[3] ? +m[3] : 0);
    return { lo, hi: lo + (m[3] ? 999 : 59999) };
  }
  if (/^\d{10}$/.test(s)) return { lo: Number(s) * 1000, hi: Number(s) * 1000 + 999 };
  if (/^\d{13}$/.test(s)) return { lo: Number(s), hi: Number(s) };
  return null;
}

// --- lexer ------------------------------------------------------------------------------------------

function findRegexEnd(text, i) {
  const n = text.length;
  let j = i + 1;
  let inClass = false;
  while (j < n) {
    const ch = text[j];
    if (ch === '\\') {
      j += 2;
      continue;
    }
    if (ch === '[') inClass = true;
    else if (ch === ']') inClass = false;
    else if (ch === '/' && !inClass && j > i + 1) {
      let k = j + 1;
      while (k < n && /[a-z]/.test(text[k])) k += 1;
      if (k === n || isSpace(text[k]) || text[k] === ')' || text[k] === '|') {
        return { end: k, source: text.slice(i + 1, j), flags: text.slice(j + 1, k) };
      }
    }
    j += 1;
  }
  return null;
}

function readQuoted(text, i) {
  const q = text[i];
  let j = i + 1;
  let buf = '';
  while (j < text.length) {
    const ch = text[j];
    if (ch === '\\' && j + 1 < text.length) {
      buf += text[j + 1];
      j += 2;
      continue;
    }
    if (ch === q) return { kind: 'quoted', text: buf, pos: i, end: j + 1 };
    buf += ch;
    j += 1;
  }
  throw new QueryError(`Unclosed quote: add a closing ${q}`, i, text.length);
}

function bareEnd(text, i) {
  let j = i;
  while (j < text.length) {
    const ch = text[j];
    if (isSpace(ch) || ch === '(' || ch === ')' || ch === '|' || ch === '"') break;
    if (ch === '&' && text[j + 1] === '&') break;
    j += 1;
  }
  return j;
}

/** One value, or several joined by "|" (any of). */
function readValues(text, i, pipes) {
  const values = [];
  let j = i;
  for (;;) {
    const ch = text[j];
    let v;
    if (ch === '"' || ch === "'") {
      v = readQuoted(text, j);
    } else if (ch === '/' && findRegexEnd(text, j)) {
      const r = findRegexEnd(text, j);
      if (!REGEX_FLAGS.test(r.flags)) throw new QueryError(`Unknown regular expression flag in /${r.source}/${r.flags}`, j, r.end);
      v = { kind: 'regex', text: r.source, flags: r.flags, pos: j, end: r.end };
    } else {
      const e = bareEnd(text, j);
      if (e === j) return { values, end: j };
      v = { kind: 'word', text: text.slice(j, e), pos: j, end: e };
    }
    values.push(v);
    j = v.end;
    if (text[j] === '|' && text[j + 1] !== '|') {
      const nx = text[j + 1];
      if (nx === undefined || isSpace(nx) || nx === ')') {
        throw new QueryError("Expected another value after '|'", j, j + 1);
      }
      pipes.push(j);
      j += 1;
      continue;
    }
    return { values, end: j };
  }
}

/**
 * Splits a query into tokens: lp, rp, and, or, not, term. `keyOk(key)` (optional) says whether a key
 * exists in the view: an unknown key with nothing after it ("SNMP_TRAP:") is then read as free text.
 * `sink` receives tokens as they are read, so a caller can highlight what came before an error.
 */
function lex(text, keyOk, sink) {
  const toks = sink || [];
  const n = text.length;
  let i = 0;
  while (i < n) {
    const c = text[i];
    if (isSpace(c)) {
      i += 1;
      continue;
    }
    if (c === '(') { toks.push({ t: 'lp', pos: i, end: i + 1 }); i += 1; continue; }
    if (c === ')') { toks.push({ t: 'rp', pos: i, end: i + 1 }); i += 1; continue; }
    if (c === '&' && text[i + 1] === '&') { toks.push({ t: 'and', v: '&&', pos: i, end: i + 2 }); i += 2; continue; }
    if (c === '|') {
      const len = text[i + 1] === '|' ? 2 : 1;
      toks.push({ t: 'or', v: text.slice(i, i + len), pos: i, end: i + len });
      i += len;
      continue;
    }
    if (c === '!') {
      if (text[i + 1] === '=') throw new QueryError("'!=' needs a key before it, like dport!=443", i, i + 2);
      toks.push({ t: 'not', v: '!', pos: i, end: i + 1 });
      i += 1;
      continue;
    }
    if (c === '-') {
      const d = text[i + 1];
      if (d === undefined || isSpace(d) || d === ')') {
        throw new QueryError("Put '-' right before the term to exclude, like -app:junos-dns-udp", i, i + 1);
      }
      toks.push({ t: 'not', v: '-', pos: i, end: i + 1 });
      i += 1;
      continue;
    }
    const we = bareEnd(text, i);
    const w = text.slice(i, we);
    if (KEYWORDS[w]) {
      toks.push({ t: KEYWORDS[w], v: w, pos: i, end: we });
      i = we;
      continue;
    }
    const tok = readTerm(text, i, keyOk);
    toks.push(tok);
    i = tok.end;
  }
  return toks;
}

function readTerm(text, i, keyOk) {
  const n = text.length;
  const c = text[i];
  const pipes = [];
  if (c !== '"' && c !== "'" && c !== '/') {
    KEY_RE.lastIndex = i;
    const km = KEY_RE.exec(text);
    const word = text.slice(i, bareEnd(text, i));
    if (km && !KEYWORDS[km[0]] && !isLiteralWord(word)) {
      const key = km[0];
      const keyEnd = i + key.length;
      let opPos = keyEnd;
      OP_RE.lastIndex = keyEnd;
      let om = OP_RE.exec(text);
      if (!om) {
        // J-Web style "source-address = 10.0.0.1": spaces around comparison operators.
        let k = keyEnd;
        while (k < n && isSpace(text[k])) k += 1;
        if (k > keyEnd) {
          OP_RE.lastIndex = k;
          const om2 = OP_RE.exec(text);
          if (om2 && om2[0] !== ':') {
            om = om2;
            opPos = k;
          }
        }
      }
      // "fe80::1" and URLs ("scheme" followed by "://") are values, not key:value.
      if (om && !(om[0] === ':' && (text[opPos + 1] === ':' || text.startsWith('//', opPos + 1)))) {
        const op = om[0];
        const opEnd = opPos + op.length;
        let vpos = opEnd;
        if (opPos > keyEnd) while (vpos < n && isSpace(text[vpos])) vpos += 1;
        const known = keyOk ? keyOk(key) : true;
        const atEnd = vpos >= n || isSpace(text[vpos]) || text[vpos] === ')';
        if (!known && atEnd) {
          // "UI_COMMIT:" or "FIN:" copied from a log line: plain text, not a key.
          return { t: 'term', key: null, op: null, values: [{ kind: 'word', text: word, pos: i, end: i + word.length }], pos: i, end: i + word.length, pipes };
        }
        if (atEnd) {
          const hint = opPos === keyEnd && op === ':' && isSpace(text[vpos] || '') && vpos < n ? ` (no space after '${key}:')` : '';
          throw new QueryError(`Expected a value after '${key}${op}'${hint}`, opEnd, opEnd + 1);
        }
        if (text[vpos] === '(') {
          throw new QueryError(`Expected a value after '${key}${op}'; for several values write ${key}${op}a|b`, vpos, vpos + 1);
        }
        const { values, end } = readValues(text, vpos, pipes);
        if (!values.length) throw new QueryError(`Expected a value after '${key}${op}'`, vpos, vpos + 1);
        return { t: 'term', key, keyPos: i, keyEnd, op, opPos, opEnd, values, pos: i, end, pipes };
      }
    }
  }
  const { values, end } = readValues(text, i, pipes);
  if (!values.length) {
    // A lone character the grammar has no use for (for example "&").
    return { t: 'term', key: null, op: null, values: [{ kind: 'word', text: text[i], pos: i, end: i + 1 }], pos: i, end: i + 1, pipes };
  }
  return { t: 'term', key: null, op: null, values, pos: i, end, pipes };
}

// --- parser -----------------------------------------------------------------------------------------

function parseTokens(toks, text) {
  let k = 0;
  const peek = () => toks[k];
  const startsUnary = (t) => t && (t.t === 'term' || t.t === 'lp' || t.t === 'not');
  const where = () => (peek() ? peek().pos : text.length);

  function parseOr() {
    const first = parseAnd();
    const items = [first];
    while (peek() && peek().t === 'or') {
      const op = toks[k++];
      if (!startsUnary(peek())) throw new QueryError(`Expected a term after ${op.v}`, where(), where() + 1);
      items.push(parseAnd());
    }
    if (items.length === 1) return first;
    const flat = [];
    for (const it of items) if (it.type === 'or' && !it.group) flat.push(...it.items); else flat.push(it);
    return { type: 'or', items: flat, pos: items[0].pos, end: items[items.length - 1].end };
  }

  function parseAnd() {
    const items = [parseUnary()];
    for (;;) {
      const t = peek();
      if (!t) break;
      if (t.t === 'and') {
        k += 1;
        if (!startsUnary(peek())) throw new QueryError(`Expected a term after ${t.v}`, where(), where() + 1);
        items.push(parseUnary());
        continue;
      }
      if (startsUnary(t)) {
        items.push(parseUnary());
        continue;
      }
      break;
    }
    if (items.length === 1) return items[0];
    const flat = [];
    for (const it of items) if (it.type === 'and') flat.push(...it.items); else flat.push(it);
    return { type: 'and', items: flat, pos: items[0].pos, end: items[items.length - 1].end };
  }

  function parseUnary() {
    const t = peek();
    if (t && t.t === 'not') {
      k += 1;
      if (!startsUnary(peek())) throw new QueryError(`Expected a term after ${t.v === '-' || t.v === '!' ? `'${t.v}'` : t.v}`, where(), where() + 1);
      const item = parseUnary();
      return { type: 'not', item, pos: t.pos, end: item.end };
    }
    return parseAtom();
  }

  function parseAtom() {
    const t = peek();
    if (!t) throw new QueryError('Expected a term', text.length, text.length + 1);
    if (t.t === 'lp') {
      k += 1;
      if (peek() && peek().t === 'rp') throw new QueryError('Empty parentheses', t.pos, peek().end);
      if (!peek()) throw new QueryError("Missing ')' to close this '('", t.pos, t.end);
      const e = parseOr();
      const r = peek();
      if (!r || r.t !== 'rp') throw new QueryError("Missing ')' to close this '('", t.pos, t.end);
      k += 1;
      e.group = true;
      e.gpos = t.pos;
      e.gend = r.end;
      return e;
    }
    if (t.t === 'term') {
      k += 1;
      const node = { type: 'term', key: t.key ? t.key.toLowerCase() : null, op: t.op, values: t.values, pos: t.pos, end: t.end };
      if (t.key) {
        node.rawKey = t.key;
        node.keyPos = t.keyPos;
        node.opPos = t.opPos;
      }
      return node;
    }
    if (t.t === 'rp') throw new QueryError("Unexpected ')': there is no '(' to close", t.pos, t.end);
    throw new QueryError(`Expected a term before ${t.v}`, t.pos, t.end);
  }

  const ast = parseOr();
  if (k < toks.length) {
    const t = toks[k];
    if (t.t === 'rp') throw new QueryError("Unexpected ')': there is no '(' to close", t.pos, t.end);
    throw new QueryError('Unexpected text', t.pos, t.end);
  }
  return ast;
}

function viewOf(view) {
  const v = String(view || '').toLowerCase();
  const [base, src] = v.split(/[:\-/]/);
  return { base: base === 'log' ? 'logs' : base, source: src || null };
}

function fieldsFor(opts) {
  if (!opts) return null;
  if (opts.fields) return opts.fields;
  if (opts.view) return FIELDS[viewOf(opts.view).base] || null;
  return null;
}

/**
 * Parses a query. With `{view}` (or `{fields}`), keys and values are checked against that view.
 * Never throws: returns `{ast, error}`; `error` is `{pos, end, message}` with character offsets.
 */
export function parse(text, opts) {
  const s = String(text ?? '');
  const fields = fieldsFor(opts);
  try {
    const toks = lex(s, fields ? (k) => Boolean(resolveKey(fields, k)) : null);
    if (!toks.length) return { ast: null, error: null };
    const ast = parseTokens(toks, s);
    if (fields) {
      const err = validate(ast, fields);
      if (err) return { ast: null, error: err };
    }
    return { ast, error: null };
  } catch (e) {
    if (e instanceof QueryError) return { ast: null, error: { pos: e.pos, end: e.end, message: e.message } };
    return { ast: null, error: { pos: 0, end: s.length, message: 'This query could not be read' } };
  }
}

/**
 * Lossless highlight spans for a query, `[{t, v}]` with t in: ws, key, op, val, word, str, re, pipe,
 * kw, not, paren, err. Text after a syntax error is one "err" span.
 */
export function scan(text, opts) {
  const s = String(text ?? '');
  const fields = fieldsFor(opts);
  const toks = [];
  let errPos = null;
  try {
    lex(s, fields ? (k) => Boolean(resolveKey(fields, k)) : null, toks);
  } catch (e) {
    errPos = e instanceof QueryError ? e.pos : 0;
  }
  const out = [];
  let pos = 0;
  const emit = (t, end) => {
    if (end > pos) {
      out.push({ t, v: s.slice(pos, end) });
      pos = end;
    }
  };
  const value = (v, free) => {
    emit('ws', v.pos);
    emit(v.kind === 'quoted' ? 'str' : v.kind === 'regex' ? 're' : free ? 'word' : 'val', v.end);
  };
  for (const t of toks) {
    if (errPos !== null && t.pos >= errPos) break;
    emit('ws', t.pos);
    if (t.t === 'lp' || t.t === 'rp') emit('paren', t.end);
    else if (t.t === 'and' || t.t === 'or') emit('kw', t.end);
    else if (t.t === 'not') emit(t.v === '-' || t.v === '!' ? 'not' : 'kw', t.end);
    else {
      if (t.key) {
        emit('key', t.keyEnd);
        emit('ws', t.opPos);
        emit('op', t.opEnd);
      }
      let pi = 0;
      for (const v of t.values) {
        while (pi < t.pipes.length && t.pipes[pi] < v.pos) {
          emit('ws', t.pipes[pi]);
          emit('pipe', t.pipes[pi] + 1);
          pi += 1;
        }
        value(v, !t.key);
      }
    }
  }
  if (errPos !== null) {
    emit('ws', Math.max(pos, Math.min(errPos, s.length)));
    emit('err', s.length);
  }
  emit('ws', s.length);
  return out;
}

// --- fields -----------------------------------------------------------------------------------------

const HAYSTACK = Symbol('haystack');
const ALIASES = new WeakMap();

function resolveKey(fields, key) {
  if (!fields || !key) return null;
  let map = ALIASES.get(fields);
  if (!map) {
    map = new Map();
    for (const [name, def] of Object.entries(fields)) {
      map.set(name, name);
      for (const a of def.aliases || []) if (!map.has(a)) map.set(a, name);
    }
    ALIASES.set(fields, map);
  }
  const name = map.get(String(key).toLowerCase());
  return name ? { name, def: fields[name] } : null;
}

const PROTO_NUM = { icmp: 1, igmp: 2, tcp: 6, udp: 17, gre: 47, esp: 50, ah: 51, icmp6: 58, icmpv6: 58, ospf: 89, pim: 103, sctp: 132 };
const NUM_PROTO = { 1: 'icmp', 2: 'igmp', 6: 'tcp', 17: 'udp', 47: 'gre', 50: 'esp', 51: 'ah', 58: 'icmp6', 89: 'ospf', 103: 'pim', 132: 'sctp' };

function protoNames(p) {
  if (p === null || p === undefined || p === '') return [];
  const s = String(p).trim().toLowerCase();
  if (/^\d+$/.test(s)) return NUM_PROTO[s] ? [NUM_PROTO[s], s] : [s];
  const n = PROTO_NUM[s];
  return n ? [s, String(n), ...(s === 'icmpv6' ? ['icmp6'] : [])] : [s];
}

const SEV = { emergency: 0, emerg: 0, alert: 1, critical: 2, crit: 2, error: 3, err: 3, warning: 4, warn: 4, notice: 5, info: 6, informational: 6, debug: 7 };
const SEV_NAMES = ['emergency', 'alert', 'critical', 'error', 'warning', 'notice', 'info', 'debug'];

const nz = (v) => (v === null || v === undefined || v === '' ? null : v);
const isPlaceholder = (v) => v === null || v === undefined || /^(?:N\/A|NA|None|NONE|UNKNOWN|-|)$/.test(String(v).trim());

function topValues(rows, get, limit = 40) {
  const counts = new Map();
  if (!Array.isArray(rows)) return [];
  const n = Math.min(rows.length, 5000);
  for (let i = 0; i < n; i++) {
    let vs;
    try {
      vs = get(rows[i]);
    } catch (_e) {
      continue;
    }
    for (const v of Array.isArray(vs) ? vs : [vs]) {
      if (v === null || v === undefined || v === '' || isPlaceholder(v)) continue;
      const k = String(v);
      counts.set(k, (counts.get(k) || 0) + 1);
    }
  }
  return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, limit).map(([v]) => v);
}

function scopeOf(inv) {
  return inv && inv.scope ? inv.scope : null;
}
function invRows(inv, part) {
  const s = scopeOf(inv);
  const p = s && s[part];
  return p && Array.isArray(p.rows) ? p.rows : [];
}
const invZones = (inv) => invRows(inv, 'zones').map((z) => z.name).filter(Boolean);
const invPolicies = (inv) => [...new Set(invRows(inv, 'policies').map((p) => p.name).filter(Boolean))];
const invIfaces = (inv) => invRows(inv, 'zones').flatMap((z) => (z.interfaces || []).map((i) => i.name)).filter(Boolean);
function invApps(inv) {
  const out = new Set(invRows(inv, 'applications').map((a) => a.name));
  for (const p of invRows(inv, 'policies')) for (const a of (p.match && p.match.application) || []) out.add(a);
  out.delete('any');
  return [...out].filter(Boolean);
}
function invAddresses(inv) {
  const out = new Set();
  for (const b of invRows(inv, 'address_books')) {
    for (const a of b.addresses || []) out.add(a.name);
    for (const s of b.sets || []) out.add(s.name);
  }
  return [...out].filter(Boolean);
}
const merge = (...lists) => [...new Set(lists.flat().filter((x) => x !== null && x !== undefined && x !== ''))];

const ZONE_INDEX = new WeakMap();
/** {from:[], to:[]} for a policy name, from ctx.policyIndex (Map) or ctx.inventory. */
function policyZones(name, ctx) {
  if (!name || !ctx) return null;
  const idx = ctx.policyIndex;
  if (idx && typeof idx.get === 'function') {
    const hit = idx.get(name);
    if (hit) return hit;
  }
  const inv = ctx.inventory;
  if (!inv || typeof inv !== 'object') return null;
  let map = ZONE_INDEX.get(inv);
  if (!map) {
    map = new Map();
    for (const p of invRows(inv, 'policies')) if (!map.has(p.name)) map.set(p.name, { from: p.from || [], to: p.to || [] });
    ZONE_INDEX.set(inv, map);
  }
  return map.get(name) || null;
}

const wing = (row, side) => (row && row[side]) || {};
const sum = (a, b) => (a === null || a === undefined ? b ?? null : b === null || b === undefined ? a : Number(a) + Number(b));

function sessionZones(row, ctx, side) {
  const direct = side === 'from' ? row.from_zone ?? row.zone_from : row.to_zone ?? row.zone_to;
  if (direct) return [direct];
  const z = policyZones(row.policy, ctx);
  return z ? z[side] || [] : [];
}

// Predefined Junos applications (junos-defaults) whose protocol and destination port J-Wicket knows.
// The inventory does not expand junos-defaults, so any other predefined application has a port that
// is not known here: the policy filter keeps such a policy and marks it instead of guessing.
export const PREDEFINED_APPS = Object.freeze({
  'junos-http': { protocol: 'tcp', port: '80' },
  'junos-https': { protocol: 'tcp', port: '443' },
  'junos-ssh': { protocol: 'tcp', port: '22' },
  'junos-telnet': { protocol: 'tcp', port: '23' },
  'junos-ftp': { protocol: 'tcp', port: '21' },
  'junos-smtp': { protocol: 'tcp', port: '25' },
  'junos-dns-udp': { protocol: 'udp', port: '53' },
  'junos-dns-tcp': { protocol: 'tcp', port: '53' },
  'junos-ntp': { protocol: 'udp', port: '123' },
  'junos-pop3': { protocol: 'tcp', port: '110' },
  'junos-imap': { protocol: 'tcp', port: '143' },
  'junos-imaps': { protocol: 'tcp', port: '993' },
  'junos-ldap': { protocol: 'tcp', port: '389' },
  'junos-syslog': { protocol: 'udp', port: '514' },
  'junos-bgp': { protocol: 'tcp', port: '179' },
  'junos-tftp': { protocol: 'udp', port: '69' },
  'junos-ms-sql': { protocol: 'tcp', port: '1433' },
});

// Port keywords Junos accepts in "destination-port", for the common IANA services.
const NAMED_PORTS = {
  ftp: '21', ssh: '22', telnet: '23', smtp: '25', domain: '53', tftp: '69', http: '80', pop3: '110',
  ntp: '123', imap: '143', snmp: '161', snmptrap: '162', bgp: '179', ldap: '389', https: '443', syslog: '514',
};
const PORTS_CACHE = new WeakMap();

const PORTLESS = new Set(['icmp', 'icmp6', 'icmpv6', 'gre', 'esp', 'ah', 'ospf', 'pim', 'igmp', 'vrrp', '1', '2', '47', '50', '51', '58', '89', '103', '112']);

/**
 * What a policy's applications say about destination ports, for the "port:" filter and the
 * match-policies example: `{ any, pairs: [{name, protocol, port}], unknown: [{name, why}] }`. "any"
 * (application any) covers every port; `unknown` lists applications whose port J-Wicket cannot read
 * (predefined applications it does not know, applications with terms or without a port, names it
 * could not resolve). Portless protocols (ICMP, GRE, ...) add nothing.
 */
export function policyPorts(row) {
  if (row && typeof row === 'object') {
    const hit = PORTS_CACHE.get(row);
    if (hit) return hit;
  }
  const out = { any: false, pairs: [], unknown: [] };
  const leaf = (l) => {
    if (!l || !l.name) return;
    if (l.predefined) {
      const p = PREDEFINED_APPS[l.name];
      if (p) out.pairs.push({ name: l.name, protocol: p.protocol, port: p.port, predefined: true });
      else out.unknown.push({ name: l.name, why: 'predefined application whose port J-Wicket does not read' });
      return;
    }
    const proto = l.protocol ? String(l.protocol).toLowerCase() : null;
    if (l.destination_port !== null && l.destination_port !== undefined && l.destination_port !== '') {
      const raw = String(l.destination_port).trim().toLowerCase();
      const port = /^\d+(-\d+)?$/.test(raw) ? raw : NAMED_PORTS[raw] || null;
      if (port) out.pairs.push({ name: l.name, protocol: proto, port });
      else out.unknown.push({ name: l.name, why: `destination port ${raw}, a name J-Wicket does not translate` });
    } else if (proto && PORTLESS.has(proto)) {
      // no ports to compare
    } else {
      out.unknown.push({ name: l.name, why: l.terms ? 'application with terms (not expanded)' : 'application without a destination port' });
    }
  };
  for (const ref of (row && row.resolved && row.resolved.application) || []) {
    if (ref.kind === 'any') out.any = true;
    else if (ref.kind === 'predefined') leaf({ name: ref.name, predefined: true });
    else if (ref.kind === 'dynamic-defaults') out.unknown.push({ name: ref.name, why: 'the dynamic application’s own default ports' });
    else if (ref.kind === 'unresolved') out.unknown.push({ name: ref.name, why: 'not found in the configuration' });
    else (ref.leaves || []).forEach(leaf);
    for (const n of ref.unresolved || []) if (n !== ref.name) out.unknown.push({ name: n, why: 'not found in the configuration' });
  }
  if (row && typeof row === 'object') PORTS_CACHE.set(row, out);
  return out;
}

const PORT_ANY = '0-65535';

function policyAddr(row, side) {
  const m = row.match || {};
  const r = row.resolved || {};
  const sides = side === 'both' ? ['source', 'destination'] : [side];
  const out = [];
  for (const sd of sides) {
    for (const n of m[sd] || []) out.push(n);
    for (const ref of r[sd] || []) {
      if (ref.kind === 'any') out.push('any');
      for (const leaf of ref.leaves || []) {
        if (leaf.value) out.push(leaf.value);
        if (leaf.name) out.push(leaf.name);
      }
    }
  }
  return out;
}

/**
 * Address-book entries of a policy side that an address cannot be compared with: DNS names, wildcard
 * addresses, sets cut short, names not found. `[{name, why}]`.
 */
export function policyAddrUnknown(row, side) {
  const out = [];
  const sides = side === 'both' ? ['source', 'destination'] : [side];
  for (const sd of sides) {
    for (const ref of (row && row.resolved && row.resolved[sd]) || []) {
      if (ref.kind === 'unresolved') out.push({ name: ref.name, why: 'not found in an address book' });
      if (ref.truncated) out.push({ name: ref.name, why: 'address set longer than J-Wicket lists' });
      for (const n of ref.unresolved || []) if (n !== ref.name) out.push({ name: n, why: 'not found in an address book' });
      for (const l of ref.leaves || []) {
        if (l.kind === 'dns') out.push({ name: l.name, why: `DNS name ${l.value || ''}`.trim() });
        else if (l.kind === 'wildcard') out.push({ name: l.name, why: `wildcard address ${l.value || ''}`.trim() });
        else if (!l.value) out.push({ name: l.name, why: 'no address value' });
      }
    }
  }
  return out;
}

/** For src/dst/addr in Policies: an address (or IPv4 wildcard) query cannot be decided on such entries. */
function addrUnknown(side) {
  return (row, ctx, node) => {
    if (!node || !node.values.some((v) => v.kind === 'word' && (parseNet(v.text) || ipv4Glob(v.text)))) return false;
    return policyAddrUnknown(row, side).length > 0;
  };
}

const FIELD_FN = (obj, text) => {
  Object.defineProperty(obj, HAYSTACK, { value: text, enumerable: false });
  return obj;
};

function sessionText(row) {
  const a = wing(row, 'in');
  const b = wing(row, 'out');
  const parts = [row.session_id, row.id, row.policy, row.application, row.state, row.status, row.location,
    a.src, a.sport, a.dst, a.dport, a.proto, a.iface, b.src, b.sport, b.dst, b.dport, b.iface];
  if (row.extra) for (const v of Object.values(row.extra)) parts.push(v);
  return parts.filter((x) => x !== null && x !== undefined).join(' ');
}

function logField(row, ...keys) {
  const f = (row && row.fields) || {};
  for (const k of keys) {
    const v = f[k];
    if (v !== undefined && v !== null && v !== '' && !isPlaceholder(v)) return v;
  }
  return null;
}

function logNat(row) {
  const f = (row && row.fields) || {};
  if (f['nat-source-address'] === undefined && f['nat-destination-address'] === undefined) return [];
  const host = (v) => (v ? String(v).split('/')[0] : v);
  const out = [];
  const sn = !isPlaceholder(f['nat-source-address']) && (host(f['nat-source-address']) !== host(f['source-address'])
    || (f['nat-source-port'] !== undefined && String(f['nat-source-port']) !== String(f['source-port'])));
  const dn = !isPlaceholder(f['nat-destination-address']) && (host(f['nat-destination-address']) !== host(f['destination-address'])
    || (f['nat-destination-port'] !== undefined && String(f['nat-destination-port']) !== String(f['destination-port'])));
  if (sn) out.push('src', 'snat', 'source');
  if (dn) out.push('dst', 'dnat', 'destination');
  if (sn && dn) out.push('both');
  if (sn || dn) out.push('yes', 'any');
  else out.push('none', 'no');
  return out;
}

/**
 * Query keys per view over the API row shapes. Each entry: {aliases, type, get(row, ctx), values?(rows,
 * inventory), label, device?: true (sessions RPC parameter), report?: report-expression key(s),
 * verbatim?: true (the value appears verbatim in the log line, so a substring hint is safe)}.
 */
export const FIELDS = {
  sessions: FIELD_FN({
    src: { aliases: ['source', 'srcip', 'sip', 'source-address', 'source-prefix'], type: 'ip', device: true, label: 'client address (CIDR-aware)', get: (r) => wing(r, 'in').src, values: (rows) => topValues(rows, (r) => wing(r, 'in').src) },
    dst: { aliases: ['destination', 'dstip', 'dip', 'destination-address', 'destination-prefix'], type: 'ip', device: true, label: 'destination address as the client sent it', get: (r) => wing(r, 'in').dst, values: (rows) => topValues(rows, (r) => wing(r, 'in').dst) },
    sport: { aliases: ['srcport', 'source-port'], type: 'int', device: true, label: 'client port', get: (r) => wing(r, 'in').sport },
    dport: { aliases: ['port', 'dstport', 'destination-port'], type: 'int', device: true, label: 'destination port', get: (r) => wing(r, 'in').dport, values: (rows) => topValues(rows, (r) => wing(r, 'in').dport) },
    proto: { aliases: ['protocol'], type: 'enum', device: true, label: 'protocol (tcp, udp, icmp or a number)', get: (r) => protoNames(wing(r, 'in').proto), values: (rows) => merge(topValues(rows, (r) => wing(r, 'in').proto), ['tcp', 'udp', 'icmp']) },
    app: { aliases: ['application'], type: 'text', device: true, label: 'application', get: (r) => r.application, values: (rows, inv) => merge(topValues(rows, (r) => r.application), invApps(inv)) },
    iface: { aliases: ['interface', 'if'], type: 'text', device: true, label: 'ingress or egress interface', get: (r) => [wing(r, 'in').iface, wing(r, 'out').iface], values: (rows, inv) => merge(topValues(rows, (r) => [wing(r, 'in').iface, wing(r, 'out').iface]), invIfaces(inv)) },
    ingress: { aliases: ['in', 'iniface'], type: 'text', label: 'ingress interface', get: (r) => wing(r, 'in').iface, values: (rows) => topValues(rows, (r) => wing(r, 'in').iface) },
    egress: { aliases: ['out', 'outiface'], type: 'text', label: 'egress interface', get: (r) => wing(r, 'out').iface, values: (rows) => topValues(rows, (r) => wing(r, 'out').iface) },
    policy: { aliases: ['pol', 'policy-name'], type: 'text', label: 'security policy', get: (r) => r.policy, values: (rows, inv) => merge(topValues(rows, (r) => r.policy), invPolicies(inv)) },
    zone: { aliases: [], type: 'text', label: 'from- or to-zone (from the policy)', get: (r, c) => [...sessionZones(r, c, 'from'), ...sessionZones(r, c, 'to')], values: (rows, inv) => invZones(inv) },
    from: { aliases: ['from-zone', 'fromzone', 'source-zone'], type: 'text', label: 'from-zone (from the policy)', get: (r, c) => sessionZones(r, c, 'from'), values: (rows, inv) => invZones(inv) },
    to: { aliases: ['to-zone', 'tozone', 'destination-zone'], type: 'text', label: 'to-zone (from the policy)', get: (r, c) => sessionZones(r, c, 'to'), values: (rows, inv) => invZones(inv) },
    nat: { aliases: [], type: 'enum', label: 'NAT: src, dst, both, none', get: (r) => {
      const n = r.nat || {};
      const out = [];
      if (n.source) out.push('src', 'snat', 'source');
      if (n.destination) out.push('dst', 'dnat', 'destination');
      if (n.source && n.destination) out.push('both');
      out.push(n.source || n.destination ? 'yes' : 'none');
      if (!n.source && !n.destination) out.push('no');
      return out;
    }, values: () => ['src', 'dst', 'both', 'none'] },
    natsrc: { aliases: ['xsrc', 'snat'], type: 'ip', label: 'translated source address', get: (r) => ((r.nat || {}).source ? wing(r, 'out').dst : null) },
    natdst: { aliases: ['xdst', 'dnat'], type: 'ip', label: 'translated destination address', get: (r) => ((r.nat || {}).destination ? wing(r, 'out').src : null) },
    bytes: { aliases: ['size', 'volume'], type: 'size', label: 'bytes, both directions (k, M, G are 1000-based like Junos; KiB, MiB 1024)', get: (r) => sum(wing(r, 'in').bytes, wing(r, 'out').bytes) },
    pkts: { aliases: ['packets'], type: 'int', label: 'packets, both directions', get: (r) => sum(wing(r, 'in').packets, wing(r, 'out').packets) },
    rate: { aliases: ['bps', 'throughput'], type: 'size', label: 'live rate in bytes/s (from poll deltas)', get: (r) => nz(r.rate) },
    dur: { aliases: ['duration', 'age'], type: 'duration', label: 'session age (s, m, h)', get: (r) => r.duration },
    timeout: { aliases: ['ttl', 'remaining'], type: 'duration', label: 'timeout remaining', get: (r) => r.timeout },
    state: { aliases: ['status'], type: 'enum', label: 'session state or status', get: (r) => merge([r.state, r.status, r.extra && r.extra.state, r.extra && r.extra['session-flag']]), values: (rows) => topValues(rows, (r) => [r.state, r.status]) },
    id: { aliases: ['session', 'sid', 'session-id'], type: 'int', label: 'session id', get: (r) => r.session_id ?? r.id },
    node: { aliases: ['location', 'spu'], type: 'text', label: 'cluster node or SPU', get: (r) => (r.location ? [r.location, ...String(r.location).split(/[\s/]+/)] : []), values: (rows) => topValues(rows, (r) => r.location) },
  }, sessionText),

  logs: FIELD_FN({
    tag: { aliases: ['event', 'msgid', 'event-id'], type: 'text', label: 'message tag (RT_FLOW_SESSION_DENY)', verbatim: true, get: (r) => r.tag, values: (rows) => topValues(rows, (r) => r.tag) },
    family: { aliases: ['fam', 'kind'], type: 'enum', label: 'event family (create, close, deny, screen, idp, vpn, commit, auth, snmp, chassis, other)', get: (r) => r.family, values: () => ['create', 'close', 'deny', 'screen', 'idp', 'vpn', 'commit', 'auth', 'snmp', 'chassis', 'other'] },
    daemon: { aliases: ['process', 'proc', 'program', 'app-name'], type: 'text', label: 'process', verbatim: true, get: (r) => r.daemon, values: (rows) => topValues(rows, (r) => r.daemon) },
    host: { aliases: ['hostname', 'device'], type: 'text', label: 'host name in the line', verbatim: true, get: (r) => r.host, values: (rows) => topValues(rows, (r) => r.host) },
    sev: { aliases: ['severity', 'level'], type: 'enum', label: 'severity; sev>=warning means warning or worse', rank: (v) => {
      const s = String(v).toLowerCase();
      const n = /^\d$/.test(s) ? Number(s) : SEV[s];
      return n === undefined ? null : 7 - n;
    }, get: (r) => (Number.isInteger(r.severity) ? [SEV_NAMES[r.severity], String(r.severity)] : []), values: () => SEV_NAMES },
    src: { aliases: ['source', 'source-address', 'srcip', 'sip'], type: 'ip', report: 'source-address', verbatim: true, label: 'source address (CIDR-aware)', get: (r) => logField(r, 'source-address'), values: (rows) => topValues(rows, (r) => logField(r, 'source-address')) },
    dst: { aliases: ['destination', 'destination-address', 'dstip', 'dip'], type: 'ip', report: 'destination-address', verbatim: true, label: 'destination address (CIDR-aware)', get: (r) => logField(r, 'destination-address'), values: (rows) => topValues(rows, (r) => logField(r, 'destination-address')) },
    ip: { aliases: ['addr', 'address', 'host-ip'], type: 'ip', report: ['source-address', 'destination-address'], verbatim: true, label: 'source or destination address', get: (r) => [logField(r, 'source-address'), logField(r, 'destination-address')] },
    sport: { aliases: ['source-port', 'srcport'], type: 'int', report: 'source-port', verbatim: true, label: 'source port', get: (r) => logField(r, 'source-port') },
    dport: { aliases: ['destination-port', 'port', 'dstport'], type: 'int', report: 'destination-port', verbatim: true, label: 'destination port', get: (r) => logField(r, 'destination-port'), values: (rows) => topValues(rows, (r) => logField(r, 'destination-port')) },
    proto: { aliases: ['protocol', 'protocol-id'], type: 'enum', report: 'protocol-id', label: 'protocol (tcp, udp or a number)', get: (r) => protoNames(logField(r, 'protocol-id', 'protocol-name', 'protocol')), values: () => ['tcp', 'udp', 'icmp'] },
    policy: { aliases: ['policy-name', 'pol'], type: 'text', report: 'policy-name', verbatim: true, label: 'policy name', get: (r) => logField(r, 'policy-name'), values: (rows, inv) => merge(topValues(rows, (r) => logField(r, 'policy-name')), invPolicies(inv)) },
    zone: { aliases: [], type: 'text', report: ['source-zone-name', 'destination-zone-name'], verbatim: true, label: 'source or destination zone', get: (r) => [logField(r, 'source-zone-name'), logField(r, 'destination-zone-name')], values: (rows, inv) => merge(invZones(inv), topValues(rows, (r) => [logField(r, 'source-zone-name'), logField(r, 'destination-zone-name')])) },
    from: { aliases: ['source-zone', 'source-zone-name', 'from-zone'], type: 'text', report: 'source-zone-name', verbatim: true, label: 'source zone', get: (r) => logField(r, 'source-zone-name'), values: (rows, inv) => invZones(inv) },
    to: { aliases: ['destination-zone', 'destination-zone-name', 'to-zone'], type: 'text', report: 'destination-zone-name', verbatim: true, label: 'destination zone', get: (r) => logField(r, 'destination-zone-name'), values: (rows, inv) => invZones(inv) },
    app: { aliases: ['application'], type: 'text', report: 'application', verbatim: true, label: 'application (layer 7)', get: (r) => logField(r, 'application', 'application-name'), values: (rows) => topValues(rows, (r) => logField(r, 'application', 'application-name')) },
    service: { aliases: ['service-name', 'svc'], type: 'text', verbatim: true, label: 'service (junos-https)', get: (r) => logField(r, 'service-name'), values: (rows, inv) => merge(topValues(rows, (r) => logField(r, 'service-name')), invApps(inv)) },
    nested: { aliases: ['nested-application'], type: 'text', verbatim: true, label: 'nested application', get: (r) => logField(r, 'nested-application') },
    reason: { aliases: ['close-reason'], type: 'text', report: 'reason', verbatim: true, label: 'close or deny reason ("TCP FIN")', get: (r) => logField(r, 'reason'), values: (rows) => topValues(rows, (r) => logField(r, 'reason')) },
    user: { aliases: ['username'], type: 'text', report: 'username', verbatim: true, label: 'user name', get: (r) => logField(r, 'username'), values: (rows) => topValues(rows, (r) => logField(r, 'username')) },
    iface: { aliases: ['interface', 'packet-incoming-interface', 'interface-name'], type: 'text', verbatim: true, label: 'interface', get: (r) => [logField(r, 'packet-incoming-interface'), logField(r, 'interface-name'), logField(r, 'source-interface-name'), logField(r, 'destination-interface-name')], values: (rows, inv) => merge(invIfaces(inv), topValues(rows, (r) => logField(r, 'packet-incoming-interface', 'interface-name'))) },
    session: { aliases: ['sid', 'session-id', 'id'], type: 'int', report: 'session-id', verbatim: true, label: 'session id', get: (r) => logField(r, 'session-id', 'session-id-32') },
    nat: { aliases: [], type: 'enum', label: 'NAT applied: src, dst, both, none', get: logNat, values: () => ['src', 'dst', 'both', 'none'] },
    natsrc: { aliases: ['nat-source-address', 'xsrc'], type: 'ip', verbatim: true, label: 'translated source address', get: (r) => logField(r, 'nat-source-address') },
    natdst: { aliases: ['nat-destination-address', 'xdst'], type: 'ip', verbatim: true, label: 'translated destination address', get: (r) => logField(r, 'nat-destination-address') },
    bytes: { aliases: ['size', 'volume'], type: 'size', label: 'bytes, both directions (session close)', get: (r) => {
      const a = logField(r, 'bytes-from-client');
      const b = logField(r, 'bytes-from-server');
      return a === null && b === null ? null : Number(a || 0) + Number(b || 0);
    } },
    dur: { aliases: ['elapsed', 'elapsed-time', 'duration'], type: 'duration', label: 'session duration (session close)', get: (r) => logField(r, 'elapsed-time') },
    lsys: { aliases: ['logical-system', 'logical-system-name'], type: 'text', verbatim: true, label: 'logical system', get: (r) => logField(r, 'logical-system-name') },
    time: { aliases: ['ts', 'timestamp'], type: 'time', label: 'time (2026-11-24T07:40, 07:40, UTC)', get: (r) => r.time },
    age: { aliases: ['ago', 'last'], type: 'duration', label: 'how long ago (age<10m)', get: (r, c) => (Number.isFinite(r.time) ? ((c && c.now) || Date.now()) / 1000 - r.time / 1000 : null) },
    msg: { aliases: ['message', 'text'], type: 'text', contains: true, label: 'message text (substring)', get: (r) => r.message ?? r.line },
  }, (r) => r.line ?? r.message ?? ''),

  policies: FIELD_FN({
    name: { aliases: ['policy', 'pol'], type: 'text', label: 'policy name', get: (r) => r.name, values: (rows, inv) => merge(invPolicies(inv), topValues(rows, (r) => r.name)) },
    from: { aliases: ['from-zone', 'fromzone'], type: 'text', label: 'from-zone ("any" for global policies without one)', get: (r) => (r.from && r.from.length ? r.from : ['any']), values: (rows, inv) => merge(invZones(inv), ['any']) },
    to: { aliases: ['to-zone', 'tozone'], type: 'text', label: 'to-zone', get: (r) => (r.to && r.to.length ? r.to : ['any']), values: (rows, inv) => merge(invZones(inv), ['any']) },
    zone: { aliases: [], type: 'text', label: 'from- or to-zone', get: (r) => [...(r.from && r.from.length ? r.from : ['any']), ...(r.to && r.to.length ? r.to : ['any'])], values: (rows, inv) => invZones(inv) },
    src: { aliases: ['source', 'source-address'], type: 'ip', label: 'source address name, or an address inside it (CIDR-aware)', get: (r) => policyAddr(r, 'source'), unknown: addrUnknown('source'), values: (rows, inv) => merge(invAddresses(inv), ['any']) },
    dst: { aliases: ['destination', 'destination-address'], type: 'ip', label: 'destination address name, or an address inside it', get: (r) => policyAddr(r, 'destination'), unknown: addrUnknown('destination'), values: (rows, inv) => merge(invAddresses(inv), ['any']) },
    addr: { aliases: ['address', 'ip'], type: 'ip', label: 'source or destination (resolved, CIDR-aware)', get: (r) => policyAddr(r, 'both'), unknown: addrUnknown('both'), values: (rows, inv) => invAddresses(inv) },
    app: { aliases: ['application'], type: 'text', label: 'application or set (and its members)', get: (r) => {
      const out = [...((r.match && r.match.application) || [])];
      for (const ref of (r.resolved && r.resolved.application) || []) for (const l of ref.leaves || []) if (l.name) out.push(l.name);
      return out;
    }, values: (rows, inv) => invApps(inv) },
    // "application any" covers every port (port:3389 keeps a permit-all; port!=3389 drops it). A port
    // J-Wicket cannot read (an unknown predefined application, terms) leaves the answer unknown: the
    // policy stays listed, and compileTri() reports it as unknown so the view can mark it.
    port: { aliases: ['dport', 'destination-port'], type: 'int', label: 'destination port of the applications ("any" covers every port)', get: (r, c) => {
      const p = policyPorts(r);
      const out = p.pairs.map((x) => x.port);
      if (p.any && !(c && c.strictAny)) out.push(PORT_ANY);
      return out;
    }, unknown: (r) => policyPorts(r).unknown.length > 0 },
    action: { aliases: ['then'], type: 'enum', label: 'permit, deny or reject', get: (r) => r.action, values: () => ['permit', 'deny', 'reject'] },
    group: { aliases: ['groups', 'apply-group'], type: 'text', label: 'configuration group', get: (r) => merge([r.group], r.groups || []), values: (rows, inv) => merge(((scopeOf(inv) || {}).groups || []).map((g) => g.name), topValues(rows, (r) => r.group)) },
    inactive: { aliases: ['disabled'], type: 'enum', label: 'yes or no', get: (r) => (r.inactive ? ['yes', 'true', r.inactive_reason || 'policy'] : ['no', 'false']), values: () => ['yes', 'no'] },
    log: { aliases: ['logging'], type: 'enum', label: 'init, close, yes or none', get: (r) => {
      const l = r.log || {};
      const out = [];
      if (l.init) out.push('init');
      if (l.close) out.push('close');
      out.push(l.init || l.close ? 'yes' : 'none');
      if (!l.init && !l.close) out.push('no');
      return out;
    }, values: () => ['init', 'close', 'yes', 'none'] },
    count: { aliases: ['counting'], type: 'enum', label: 'yes or no', get: (r) => (r.count ? ['yes', 'true'] : ['no', 'false']), values: () => ['yes', 'no'] },
    kind: { aliases: ['type'], type: 'enum', label: 'zone or global', get: (r) => r.kind, values: () => ['zone', 'global'] },
    seq: { aliases: ['order', 'position'], type: 'int', label: 'position in its zone pair', get: (r) => r.seq },
    desc: { aliases: ['description'], type: 'text', contains: true, label: 'description (substring)', get: (r) => r.description },
  }, (r) => [r.name, r.description, ...(r.from || []), ...(r.to || []), r.action, r.group, ...(r.groups || []),
    ...((r.match && r.match.source) || []), ...((r.match && r.match.destination) || []), ...((r.match && r.match.application) || []),
    ...policyAddr(r, 'both'), r.scheduler, ...(r.application_services || [])].filter(Boolean).join(' ')),
};

const EXAMPLES = {
  sessions: ['dport:443 bytes>1M', 'src:10.10.0.0/16 -app:junos-dns-udp', 'policy:allow-web dur>5m', 'nat:dst zone:dmz', 'proto:udp | proto:icmp'],
  logs: ['family:deny', 'tag:RT_FLOW_SESSION_CLOSE reason:"TCP FIN"', 'src:10.10.0.0/16 -dport:53', 'policy:allow-web bytes>1M', 'sev>=warning age<15m'],
  policies: ['action:deny', 'addr:10.10.3.4', 'zone:dmz log:none', 'port:443 -inactive:yes', 'group:corp-baseline'],
};

// --- validation and compilation ------------------------------------------------------------------------


function hasWildcard(v) {
  return v.kind === 'word' && v.text.includes('*');
}

/**
 * A case-insensitive "*" wildcard matcher that runs in linear time (no backtracking RegExp, so a
 * pattern such as a*a*a*a*q cannot freeze the tab): the literal pieces are found left to right with
 * indexOf, and an anchored pattern also checks its first piece as a prefix and its last as a suffix.
 * The returned function takes the text to test; pass `lowered` when it is already lower case.
 */
export function globMatcher(pattern, anchored) {
  const parts = String(pattern).toLowerCase().split('*');
  const first = parts[0];
  const last = parts[parts.length - 1];
  const single = parts.length === 1;
  return (input, lowered) => {
    const s = lowered ? String(input) : String(input).toLowerCase();
    let pos = 0;
    let limit = s.length;
    let from = 0;
    let to = parts.length;
    if (anchored) {
      if (single) return s === first;
      if (s.length < first.length + last.length || !s.startsWith(first) || !s.endsWith(last)) return false;
      pos = first.length;
      limit = s.length - last.length;
      from = 1;
      to = parts.length - 1;
    }
    for (let i = from; i < to; i++) {
      const p = parts[i];
      if (!p) continue;
      const at = s.indexOf(p, pos);
      if (at < 0 || at + p.length > limit) return false;
      pos = at + p.length;
    }
    return true;
  };
}

/**
 * An IPv4 wildcard ("10.10.0.1*", "10.*.0.1", "192.168.1*") as a test on an address range: true when
 * some address in [lo, hi], written in dotted decimal, matches the wildcard text. A single address is
 * then matched exactly as Sessions matches its addresses, and a policy's prefix or range matches when
 * it holds such an address. Null when the text is not an IPv4 wildcard.
 */
const GLOB4_CACHE = new Map();
export function ipv4Glob(text) {
  const pat = String(text);
  if (!pat.includes('*') || !/^[0-9.*]+$/.test(pat) || pat.length > 40) return null;
  if (GLOB4_CACHE.has(pat)) return GLOB4_CACHE.get(pat);
  if (GLOB4_CACHE.size > 200) GLOB4_CACHE.clear();
  const made = makeIpv4Glob(pat);
  GLOB4_CACHE.set(pat, made);
  return made;
}

function makeIpv4Glob(pat) {
  const n = pat.length;
  const close = (set) => {
    for (const p of set) if (pat[p] === '*') set.add(p + 1); // a Set visits what is added while iterating
    return set;
  };
  const feed = (states, str) => {
    let cur = states;
    for (const ch of str) {
      const next = new Set();
      for (const p of cur) {
        if (p >= n) continue;
        if (pat[p] === '*') next.add(p);
        else if (pat[p] === ch) next.add(p + 1);
      }
      cur = close(next);
      if (!cur.size) break;
    }
    return cur;
  };
  const key = (level, states) => `${level}|${[...states].sort((a, b) => a - b).join(',')}`;
  const memo = new Map();
  // Whether any address completes the pattern from these states with `level` octets already read.
  const any = (level, states) => {
    if (level === 4) return states.has(n);
    const k = key(level, states);
    if (memo.has(k)) return memo.get(k);
    let ok = false;
    for (let v = 0; v < 256 && !ok; v++) {
      const next = feed(states, level < 3 ? `${v}.` : String(v));
      if (next.size && any(level + 1, next)) ok = true;
    }
    memo.set(k, ok);
    return ok;
  };
  const within = (lo, hi, level, states, base) => {
    if (level === 4) return states.has(n);
    const size = 256 ** (3 - level);
    const vlo = Math.floor((lo - base) / size);
    const vhi = Math.floor((hi - base) / size);
    for (let v = vlo; v <= vhi; v++) {
      const next = feed(states, level < 3 ? `${v}.` : String(v));
      if (!next.size) continue;
      const b = base + v * size;
      const full = lo <= b && hi >= b + size - 1;
      if (full ? any(level + 1, next) : within(Math.max(lo, b), Math.min(hi, b + size - 1), level + 1, next, b)) return true;
    }
    return false;
  };
  const start = close(new Set([0]));
  if (!any(0, start)) return null; // "1*1*1*1*1*1" and the like: no IPv4 address can match
  return (lo, hi) => within(Number(lo), Number(hi), 0, start, 0);
}

// Regular expressions are user input: the text they run over is capped, so one term cannot take
// seconds per row on long log lines (the views time-box a whole refilter as well).
export const REGEX_INPUT_MAX = 2048;
const capped = (s) => (s.length > REGEX_INPUT_MAX ? s.slice(0, REGEX_INPUT_MAX) : s);

function userRegex(v) {
  let flags = v.flags || '';
  // Smart case: case-insensitive unless the pattern has capitals or flags were given.
  if (!flags && !/[A-Z]/.test(v.text.replace(/\\[A-Z]/g, ''))) flags = 'i';
  flags = flags.replace(/[gy]/g, '');
  return new RegExp(v.text, flags);
}

function parseIntValue(text) {
  const s = String(text).trim();
  let m;
  if ((m = /^(-?\d+)$/.exec(s))) return { lo: Number(m[1]), hi: Number(m[1]) };
  if ((m = /^(\d+)-(\d+)$/.exec(s)) && Number(m[1]) <= Number(m[2])) return { lo: Number(m[1]), hi: Number(m[2]) };
  return null;
}

/** A matcher for one alternative of a typed term: (item) => boolean. Throws a message on bad values. */
function valueMatcher(def, v, op, ctx) {
  const type = def.type;
  if (op === '~' || v.kind === 'regex') {
    let re;
    try {
      re = userRegex(v.kind === 'regex' ? v : { text: v.text, flags: '' });
    } catch (e) {
      throw new Error(`Invalid regular expression: ${String(e.message || e).replace(/^Invalid regular expression: /, '')}`);
    }
    if (op !== '~' && op !== ':' && op !== '=' && op !== '!=') throw new Error(`'${op}' cannot compare with a regular expression`);
    return (item) => re.test(capped(String(item)));
  }
  const text = v.text;
  if (type === 'ip') {
    if (op !== ':' && op !== '=' && op !== '!=') throw new Error(`Addresses take ':' or '=' with a prefix (10.0.0.0/8), not '${op}'`);
    const net = parseNet(text);
    if (net) {
      return (item) => {
        const s = String(item);
        if (s === 'any') return true;
        const n = netOf(s);
        return n ? overlaps(n, net) : false;
      };
    }
    if (/^[\d.]+\/?\d*$/.test(text) && /\d/.test(text)) throw new Error(`'${text}' is not an IP address or prefix`);
    if (hasWildcard(v)) {
      // "10.10.0.1*": an address matches by its text (as in Sessions); a prefix or range matches when
      // it holds such an address (as in Policies); names match the wildcard as text.
      const g4 = ipv4Glob(text);
      const name = globMatcher(text, true);
      return (item) => {
        const s = String(item);
        if (g4) {
          if (s === 'any') return true;
          const n = netOf(s);
          if (n && n.v === 4) return g4(n.lo, n.hi);
        }
        return name(s);
      };
    }
    const low = text.toLowerCase();
    return (item) => String(item).toLowerCase() === low;
  }
  if (type === 'int') {
    const r = parseIntValue(text);
    if (!r) throw new Error(`Expected a whole number${op === ':' || op === '=' ? ' or a range like 1024-2048' : ''}, not '${text}'`);
    if (r.lo !== r.hi && op !== ':' && op !== '=' && op !== '!=') throw new Error(`'${op}' compares with one number, not a range`);
    return rangeMatcher(op, r.lo, r.hi, (item) => {
      const it = parseIntValue(item);
      return it;
    });
  }
  if (type === 'size' || type === 'duration') {
    const n = type === 'size' ? parseSize(text) : parseDuration(text);
    if (n === null) throw new Error(type === 'size' ? `Expected a size like 1500, 64k, 1M or 2G, not '${text}'` : `Expected a duration like 30s, 5m or 2h, not '${text}'`);
    return rangeMatcher(op, n, n, (item) => (item === null || item === undefined || item === '' || Number.isNaN(Number(item)) ? null : { lo: Number(item), hi: Number(item) }));
  }
  if (type === 'time') {
    const t = parseTime(text, ctx && ctx.now);
    if (!t) throw new Error(`Expected a time like 2026-11-24T07:40 or 07:40 (UTC), not '${text}'`);
    return rangeMatcher(op, t.lo, t.hi, (item) => (Number.isFinite(Number(item)) && item !== null ? { lo: Number(item), hi: Number(item) } : null));
  }
  // text and enum
  if (op !== ':' && op !== '=' && op !== '!=') {
    if (def.rank) {
      const target = def.rank(text);
      if (target === null) throw new Error(`Unknown value '${text}'`);
      return rangeMatcher(op, target, target, (item) => {
        const r = def.rank(item);
        return r === null ? null : { lo: r, hi: r };
      });
    }
    throw new Error(`'${op}' compares numbers, sizes, durations or times; use ':' or '~' here`);
  }
  if (def.rank && def.rank(text) === null) throw new Error(`Unknown value '${text}'`);
  if (hasWildcard(v)) {
    const g = globMatcher(text, !def.contains);
    return (item) => g(item);
  }
  const low = text.toLowerCase();
  if (def.contains) return (item) => String(item).toLowerCase().includes(low);
  if (def.type === 'enum' && def.rank) {
    const target = def.rank(text);
    return (item) => def.rank(item) === target;
  }
  return (item) => String(item).toLowerCase() === low;
}

function rangeMatcher(op, lo, hi, toRange) {
  return (item) => {
    const r = toRange(item);
    if (!r) return false;
    switch (op) {
      case '>': return r.hi > hi;
      case '>=': return r.hi >= lo;
      case '<': return r.lo < lo;
      case '<=': return r.lo <= hi;
      default: return r.lo <= hi && lo <= r.hi;
    }
  };
}

function valueError(v, message) {
  return { pos: v.pos, end: v.end, message };
}

/** Checks keys and typed values against a view's fields. Returns the first error, or null. */
export function validate(ast, fields, ctx) {
  let err = null;
  const walk = (node) => {
    if (err || !node) return;
    if (node.type === 'and' || node.type === 'or') node.items.forEach(walk);
    else if (node.type === 'not') walk(node.item);
    else if (node.type === 'term') {
      if (node.key) {
        const hit = resolveKey(fields, node.key);
        if (!hit) {
          const names = Object.keys(fields);
          const near = names.map((n) => [n, editDistance(node.key, n)]).sort((a, b) => a[1] - b[1])[0];
          const hint = near && near[1] <= 2 ? ` Did you mean '${near[0]}'?` : ` Keys: ${names.slice(0, 12).join(', ')}${names.length > 12 ? ', ...' : ''}`;
          err = { pos: node.keyPos ?? node.pos, end: (node.keyPos ?? node.pos) + node.rawKey.length, message: `Unknown key '${node.rawKey}'.${hint}` };
          return;
        }
        for (const v of node.values) {
          try {
            valueMatcher(hit.def, v, node.op, ctx);
          } catch (e) {
            err = valueError(v, `${hit.name}: ${e.message}`);
            return;
          }
        }
      } else {
        for (const v of node.values) {
          if (v.kind === 'regex') {
            try {
              userRegex(v);
            } catch (e) {
              err = valueError(v, `Invalid regular expression: ${String(e.message || e).replace(/^Invalid regular expression: /, '')}`);
              return;
            }
          }
        }
      }
    }
  };
  walk(ast);
  return err;
}

function editDistance(a, b) {
  const m = a.length;
  const n = b.length;
  const d = Array.from({ length: m + 1 }, (_, i) => [i, ...Array(n).fill(0)]);
  for (let j = 1; j <= n; j++) d[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
  }
  return d[m][n];
}

const HAY_CACHE = new WeakMap();
function haystackOf(row, fields) {
  if (row === null || typeof row !== 'object') return { text: String(row ?? '').toLowerCase(), raw: String(row ?? '') };
  let h = HAY_CACHE.get(row);
  if (!h || h.fields !== fields) {
    const fn = fields && fields[HAYSTACK];
    const raw = fn ? String(fn(row) ?? '') : JSON.stringify(row);
    h = { fields, raw, text: raw.toLowerCase(), ips: null };
    HAY_CACHE.set(row, h);
  }
  return h;
}

const IP_IN_TEXT = /(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d])|(?<![\w:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![\w:])/g;

function ipsOf(h) {
  if (!h.ips) {
    h.ips = [];
    for (const m of h.raw.matchAll(IP_IN_TEXT)) {
      const n = netOf(m[0]);
      if (n) h.ips.push(n);
    }
  }
  return h.ips;
}

function freeMatcher(v, fields) {
  if (v.kind === 'regex') {
    const re = userRegex(v);
    return (row) => re.test(capped(haystackOf(row, fields).raw));
  }
  if (v.kind === 'word') {
    const net = /[.:]/.test(v.text) ? parseNet(v.text) : null;
    if (net) {
      return (row) => ipsOf(haystackOf(row, fields)).some((n) => overlaps(n, net));
    }
    if (hasWildcard(v)) {
      const g = globMatcher(v.text, false);
      return (row) => g(haystackOf(row, fields).text, true);
    }
  }
  const low = v.text.toLowerCase();
  return (row) => haystackOf(row, fields).text.includes(low);
}

function asItems(v) {
  if (v === null || v === undefined) return [];
  if (Array.isArray(v)) return v.filter((x) => x !== null && x !== undefined && x !== '');
  return v === '' ? [] : [v];
}

function buildTerm(node, fields, ctx, tri) {
  if (!node.key) {
    const ms = node.values.map((v) => freeMatcher(v, fields));
    return (row) => ms.some((m) => m(row));
  }
  const hit = resolveKey(fields, node.key);
  if (!hit) {
    const raw = `${node.rawKey || node.key}${node.op}${node.values.map((v) => v.text).join('|')}`.toLowerCase();
    return (row) => haystackOf(row, fields).text.includes(raw);
  }
  let ms;
  try {
    ms = node.values.map((v) => valueMatcher(hit.def, v, node.op === '!=' ? '=' : node.op, ctx));
  } catch (_e) {
    return () => false;
  }
  const get = hit.def.get;
  const any = (row) => {
    let items;
    try {
      items = asItems(get(row, ctx));
    } catch (_e) {
      return false;
    }
    for (const it of items) for (const m of ms) if (m(it)) return true;
    return false;
  };
  const unknown = tri && typeof hit.def.unknown === 'function' ? hit.def.unknown : null;
  if (unknown) {
    // A known value decides; otherwise a value J-Wicket cannot read leaves the term unknown (null).
    const positive = node.op !== '!=';
    return (row) => {
      if (any(row)) return positive;
      let unk = false;
      try {
        unk = Boolean(unknown(row, ctx, node));
      } catch (_e) {
        unk = false;
      }
      return unk ? null : !positive;
    };
  }
  return node.op === '!=' ? (row) => !any(row) : any;
}

function build(node, fields, ctx, tri) {
  switch (node.type) {
    case 'and': {
      const fs = node.items.map((n) => build(n, fields, ctx, tri));
      if (tri) {
        // Three-valued (Kleene): false wins, then unknown.
        return (row) => {
          let out = true;
          for (const f of fs) {
            const r = f(row);
            if (r === false) return false;
            if (r === null) out = null;
          }
          return out;
        };
      }
      return (row) => {
        for (const f of fs) if (!f(row)) return false;
        return true;
      };
    }
    case 'or': {
      const fs = node.items.map((n) => build(n, fields, ctx, tri));
      if (tri) {
        return (row) => {
          let out = false;
          for (const f of fs) {
            const r = f(row);
            if (r === true) return true;
            if (r === null) out = null;
          }
          return out;
        };
      }
      return (row) => {
        for (const f of fs) if (f(row)) return true;
        return false;
      };
    }
    case 'not': {
      const f = build(node.item, fields, ctx, tri);
      if (tri) {
        return (row) => {
          const r = f(row);
          return r === null ? null : !r;
        };
      }
      return (row) => !f(row);
    }
    default:
      return buildTerm(node, fields, ctx, tri);
  }
}

const TRI_FIELDS = new WeakMap();
function hasUnknown(fields) {
  if (!fields || typeof fields !== 'object') return false;
  let v = TRI_FIELDS.get(fields);
  if (v === undefined) {
    v = Object.values(fields).some((d) => d && typeof d.unknown === 'function');
    TRI_FIELDS.set(fields, v);
  }
  return v;
}

/**
 * A row predicate for an AST. `fields` is FIELDS.<view> (or a view name); `ctx` may carry `now` (ms),
 * `policyIndex` (Map name -> {from, to}) or `inventory` (for Sessions zone keys). Never throws. A row
 * whose answer is unknown (see compileTri) is kept.
 */
export function compile(ast, fields, ctx = {}) {
  if (!ast) return () => true;
  const fs = (typeof fields === 'string' ? FIELDS[viewOf(fields).base] : fields) || {};
  const c = { ...ctx, now: ctx.now ?? Date.now() };
  if (!hasUnknown(fs)) return build(ast, fs, c, false);
  const f = build(ast, fs, c, true);
  return (row) => f(row) !== false;
}

/**
 * Like compile(), but three-valued: the predicate returns true, false, or null when the answer depends
 * on something J-Wicket cannot read (for Policies: an application port it does not know, an address
 * it cannot compare). NOT of unknown is unknown; AND/OR follow Kleene logic. Views keep null rows and
 * say why.
 */
export function compileTri(ast, fields, ctx = {}) {
  if (!ast) return () => true;
  const fs = (typeof fields === 'string' ? FIELDS[viewOf(fields).base] : fields) || {};
  const c = { ...ctx, now: ctx.now ?? Date.now() };
  return build(ast, fs, c, hasUnknown(fs));
}

const clockNow = () => (typeof performance !== 'undefined' && performance.now ? performance.now() : Date.now());

/**
 * Filters `rows` with `pred` within a time budget (checked every 64 rows), so a slow pattern cannot
 * freeze the tab on a large window. Returns `{rows, complete, checked, ms}`; when `complete` is false
 * only the first `checked` rows were tested and the view should say the query is too slow for this
 * many rows (QueryBar.setNotice). `clock` is for tests.
 */
export function filterTimed(rows, pred, budgetMs = 200, clock = clockNow) {
  const list = Array.isArray(rows) ? rows : [];
  const out = [];
  const t0 = clock();
  let i = 0;
  for (; i < list.length; i++) {
    if ((i & 63) === 0 && i && clock() - t0 > budgetMs) break;
    let keep = false;
    try {
      keep = pred(list[i]);
    } catch (_e) {
      keep = false;
    }
    if (keep) out.push(list[i]);
  }
  return { rows: out, complete: i >= list.length, checked: i, ms: clock() - t0 };
}

// --- printing -----------------------------------------------------------------------------------------

function fmtValue(v) {
  if (v.kind === 'regex') return `/${v.text}/${v.flags || ''}`;
  if (v.kind === 'quoted' || !v.text || /[\s()"'|]/.test(v.text) || /^[-!]/.test(v.text) || KEYWORDS[v.text]) {
    return `"${v.text.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
  }
  return v.text;
}

function str(node, parent) {
  switch (node.type) {
    case 'term': {
      const body = node.values.map(fmtValue).join('|');
      return node.key ? `${node.rawKey || node.key}${node.op}${body}` : body;
    }
    case 'not': {
      const inner = node.item;
      if (inner.type === 'term') return `-${str(inner, 'not')}`;
      return `NOT (${str(inner, null)})`;
    }
    case 'and': {
      const s = node.items.map((n) => str(n, 'and')).join(' ');
      return parent === 'not' ? `(${s})` : s;
    }
    case 'or': {
      const s = node.items.map((n) => str(n, 'or')).join(' OR ');
      return parent === 'and' || parent === 'not' ? `(${s})` : s;
    }
    default:
      return '';
  }
}

/** Canonical query text for an AST ("" for null). parse(toQueryString(ast)) gives the same tree. */
export function toQueryString(ast) {
  return ast ? str(ast, null) : '';
}

/** Free-text and value strings to mark in results (positive terms only, no regexes). */
export function highlightTerms(ast) {
  const out = new Set();
  const walk = (node, negated) => {
    if (!node) return;
    if (node.type === 'and' || node.type === 'or') node.items.forEach((n) => walk(n, negated));
    else if (node.type === 'not') walk(node.item, !negated);
    else if (!negated && node.op !== '!=' && !(node.op && /[<>]/.test(node.op))) {
      for (const v of node.values) {
        if (v.kind === 'regex' || node.op === '~') continue;
        if (v.text.includes('*')) {
          const longest = v.text.split('*').sort((a, b) => b.length - a.length)[0];
          if (longest.length >= 2) out.add(longest);
          continue;
        }
        if (/\/\d+$/.test(v.text) && parseNet(v.text)) continue;
        if (v.text) out.add(v.text);
      }
    }
  };
  walk(ast, false);
  return [...out];
}

// --- planner ------------------------------------------------------------------------------------------

const SESSION_DEVICE = {
  src: (v) => (parseNet(v) && !v.includes('*') && !v.includes('-') ? v : null),
  dst: (v) => (parseNet(v) && !v.includes('*') && !v.includes('-') ? v : null),
  sport: (v) => (/^\d+$/.test(v) && Number(v) <= 65535 ? String(Number(v)) : null),
  dport: (v) => (/^\d+$/.test(v) && Number(v) <= 65535 ? String(Number(v)) : null),
  proto: (v) => {
    const low = v.toLowerCase();
    if (['tcp', 'udp', 'icmp', 'icmp6', 'gre', 'esp', 'ah', 'sctp', 'pim', 'ospf'].includes(low)) return low;
    return /^\d+$/.test(low) && Number(low) <= 255 ? String(Number(low)) : null;
  },
  app: (v) => (/^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/.test(v) ? v : null),
  iface: (v) => (/^[a-z][a-z0-9-]{1,9}(\d+(\/\d+){0,3})?(\.\d{1,5})?$/.test(v) ? v : null),
};

const MAX_TERMS = 4;
const MAX_TERM_LEN = 120;
const MAX_EXPRESSION = 256;
const EXPR_CHARS = /^[A-Za-z0-9_.:/=!<>&|() -]+$/;
const EXPR_VALUE = /^[A-Za-z0-9_.:/-]+$/;

function single(node) {
  return node.type === 'term' && node.values.length === 1 ? node.values[0] : null;
}

function plainFree(node) {
  const v = single(node);
  if (!v || node.key || v.kind === 'regex' || hasWildcard(v)) return null;
  if (!v.text || v.text.length > MAX_TERM_LEN || /[\n\r]/.test(v.text)) return null;
  return v;
}

function addrLike(text) {
  return /[.:]/.test(text) && parseNet(text) !== null;
}

function bytes(s) {
  return typeof TextEncoder === 'function' ? new TextEncoder().encode(s).length : s.length;
}

/** Report-expression text for a node (or null if the device cannot evaluate it). */
function reportExpr(node, negate, fields) {
  if (node.type === 'not') return reportExpr(node.item, !negate, fields);
  if (node.type === 'and' || node.type === 'or') {
    const parts = node.items.map((n) => reportExpr(n, negate, fields));
    if (parts.some((p) => p === null)) return null;
    const joinOr = (node.type === 'or') !== negate;
    return `(${parts.join(joinOr ? ' || ' : ' && ')})`;
  }
  if (!node.key) return null;
  const hit = resolveKey(fields, node.key);
  if (!hit || !hit.def.report) return null;
  const keys = Array.isArray(hit.def.report) ? hit.def.report : [hit.def.report];
  let op = node.op === ':' ? '=' : node.op;
  if (op === '~') return null;
  const vals = [];
  for (const v of node.values) {
    if (v.kind === 'regex' || hasWildcard(v)) return null;
    let t = v.text;
    if (hit.name === 'proto') {
      const n = PROTO_NUM[t.toLowerCase()];
      if (n) t = String(n);
      else if (!/^\d+$/.test(t)) return null;
    }
    if (hit.def.type === 'ip' && !parseNet(t)) return null;
    if (hit.def.type === 'ip' && t.includes('*')) return null;
    if (hit.def.type === 'int' && !/^\d+$/.test(t)) return null;
    if (!EXPR_VALUE.test(t)) return null;
    vals.push(t);
  }
  const ordered = hit.def.type === 'int';
  if ((op === '>' || op === '<' || op === '>=' || op === '<=') && (!ordered || vals.length !== 1)) return null;
  let n = vals.length === 1 && ordered ? Number(vals[0]) : null;
  if (negate) {
    const flip = { '=': '!=', '!=': '=', '>=': '<', '<=': '>', '>': '<=', '<': '>=' };
    op = flip[op];
  }
  if (op === '>') { op = '>='; n += 1; vals[0] = String(n); }
  if (op === '<') {
    if (n === 0) return null;
    op = '<=';
    n -= 1;
    vals[0] = String(n);
  }
  const atoms = [];
  if (op === '!=') {
    for (const v of vals) for (const k of keys) atoms.push(`${k}!=${v}`);
    return atoms.length === 1 ? atoms[0] : `(${atoms.join(' && ')})`;
  }
  for (const v of vals) for (const k of keys) atoms.push(`${k}${op}${v}`);
  return atoms.length === 1 ? atoms[0] : `(${atoms.join(' || ')})`;
}

function reportTime(ms) {
  return new Date(ms).toISOString().slice(0, 19);
}

function bufferTimeText(ms) {
  const iso = new Date(ms).toISOString();
  return `${iso.slice(0, 10)}.${iso.slice(11, 19)}`;
}

/**
 * Splits a query into device-side and browser-side parts. `view` is "sessions", "policies", "logs"
 * (file), "logs:file", "logs:report" or "logs:buffer" (or pass {source} as `opts`). Returns
 * {device, expression?, browser, explain:[{text, where, refine?, pos, end}], terms?}; `device` is ready
 * to merge into the API query (sessions: src..iface; logs file: contains/exclude newline-joined;
 * report: expression, start, stop; buffer: since). Terms marked `refine` narrow on the device and are
 * also checked in the browser (the device does a superset match).
 */
export function plan(ast, view, opts = {}) {
  const { base, source: vs } = viewOf(view);
  const source = base === 'logs' ? (opts.source || vs || 'file') : null;
  const fields = FIELDS[base] || {};
  const out = { view: base, source, device: {}, browser: ast || null, explain: [] };
  if (!ast) return out;
  const items = ast.type === 'and' ? ast.items : [ast];
  const where = new Map(); // item -> {where, refine}
  const keepInBrowser = new Set();

  if (base === 'sessions') {
    for (const it of items) {
      const v = single(it);
      if (!v || !it.key || (it.op !== ':' && it.op !== '=') || v.kind === 'regex' || hasWildcard(v)) continue;
      const hit = resolveKey(fields, it.key);
      if (!hit || !SESSION_DEVICE[hit.name] || out.device[hit.name] !== undefined) continue;
      const value = SESSION_DEVICE[hit.name](v.text);
      if (value === null) continue;
      out.device[hit.name] = value;
      where.set(it, { where: 'device' });
    }
  } else if (base === 'logs' && source === 'file') {
    const contains = [];
    const exclude = [];
    // 1. Exact: plain free text -> contains; negated plain free text -> exclude.
    for (const it of items) {
      const free = plainFree(it);
      if (free && contains.length < MAX_TERMS) {
        contains.push(free.text);
        if (addrLike(free.text)) {
          keepInBrowser.add(it);
          where.set(it, { where: 'device', refine: true });
        } else {
          where.set(it, { where: 'device' });
        }
        continue;
      }
      if (it.type === 'not' && it.item.type === 'term') {
        const nf = plainFree(it.item);
        if (nf && !addrLike(nf.text) && exclude.length < MAX_TERMS) {
          exclude.push(nf.text);
          where.set(it, { where: 'device' });
        }
      }
    }
    // 2. Hints: a literal field value appears verbatim in matching lines, so it can narrow the tail
    //    on the device (superset) while the browser applies the exact field match.
    for (const it of items) {
      if (where.has(it) || contains.length >= MAX_TERMS) continue;
      const v = single(it);
      if (!v || !it.key || (it.op !== ':' && it.op !== '=') || v.kind === 'regex' || hasWildcard(v)) continue;
      const hit = resolveKey(fields, it.key);
      if (!hit || !hit.def.verbatim || v.text.length > MAX_TERM_LEN || /[\n\r]/.test(v.text)) continue;
      if (hit.def.type === 'ip' && (!parseNet(v.text) || /[/*-]/.test(v.text))) continue;
      if (hit.def.type === 'int' && !/^\d+$/.test(v.text)) continue;
      contains.push(v.text);
      keepInBrowser.add(it);
      where.set(it, { where: 'device', refine: true });
    }
    if (contains.length) out.device.contains = contains.join('\n');
    if (exclude.length) out.device.exclude = exclude.join('\n');
    out.terms = { contains, exclude };
  } else if (base === 'logs' && source === 'report') {
    const parts = [];
    let full = false;
    for (const it of items) {
      const tm = timeBound(it, fields);
      if (tm) {
        if (tm.start !== undefined && out.device.start === undefined) out.device.start = reportTime(tm.start);
        else if (tm.stop !== undefined && out.device.stop === undefined) out.device.stop = reportTime(tm.stop);
        else continue;
        keepInBrowser.add(it);
        where.set(it, { where: 'device', refine: true });
        continue;
      }
      if (full) continue;
      let e = reportExpr(it, false, fields);
      if (e === null) continue;
      if (e.startsWith('(') && items.length === 1) e = e.slice(1, -1);
      const candidate = [...parts, e].join(' && ');
      if (bytes(candidate) > MAX_EXPRESSION || !EXPR_CHARS.test(candidate)) {
        full = true; // largest AND-prefix that fits: the rest is filtered in the browser
        continue;
      }
      parts.push(e);
      where.set(it, { where: 'device' });
    }
    if (parts.length) {
      out.expression = parts.join(' && ');
      out.device.expression = out.expression;
    }
  } else if (base === 'logs' && source === 'buffer') {
    for (const it of items) {
      const tm = timeBound(it, fields);
      if (tm && tm.since !== undefined && out.device.since === undefined) {
        out.device.since = bufferTimeText(tm.since);
        keepInBrowser.add(it);
        where.set(it, { where: 'device', refine: true });
      }
    }
  }

  const rest = items.filter((it) => !where.has(it) || keepInBrowser.has(it));
  out.browser = rest.length === 0 ? null : rest.length === 1 ? rest[0] : { type: 'and', items: rest, pos: rest[0].pos, end: rest[rest.length - 1].end };
  for (const it of items) {
    const w = where.get(it);
    const e = { text: toQueryString(it), where: w ? 'device' : 'browser', pos: it.gpos ?? it.pos, end: it.gend ?? it.end };
    if (w && w.refine) e.refine = true;
    out.explain.push(e);
  }
  return out;
}

/** start/stop/since bounds from a positive time (or age) comparison. */
function timeBound(node, fields) {
  if (node.type !== 'term' || !node.key || node.values.length !== 1) return null;
  const hit = resolveKey(fields, node.key);
  if (!hit) return null;
  const v = node.values[0];
  if (hit.name === 'time') {
    const t = parseTime(v.text);
    if (!t) return null;
    if (node.op === '>=' || node.op === '>') return { start: node.op === '>' ? t.hi + 1 : t.lo, since: (node.op === '>' ? t.hi + 1 : t.lo) - 1000 };
    if (node.op === '<=' || node.op === '<') return { stop: node.op === '<' ? t.lo - 1 : t.hi };
    return null;
  }
  if (hit.name === 'age' && (node.op === '<' || node.op === '<=')) {
    const d = parseDuration(v.text);
    if (d === null) return null;
    const start = Date.now() - d * 1000;
    return { start, since: start - 1000 };
  }
  return null;
}

/** "Device filtered: dport=443 · Browser filtered: policy=allow-web, bytes>1M" (or "" with no terms). */
export function explainText(p) {
  if (!p || !p.explain || !p.explain.length) return '';
  const dev = p.explain.filter((e) => e.where === 'device').map((e) => (e.refine ? `${e.text} (checked in browser)` : e.text));
  const bro = p.explain.filter((e) => e.where === 'browser').map((e) => e.text);
  const parts = [];
  if (dev.length) parts.push(`Device filtered: ${dev.join(', ')}`);
  if (bro.length) parts.push(`Browser filtered: ${bro.join(', ')}`);
  return parts.join(' \u00b7 ');
}

// --- autocomplete ---------------------------------------------------------------------------------------

const OPS_FOR = {
  int: [':', '>=', '<=', '>', '<', '!='],
  size: ['>', '<', '>=', '<='],
  duration: ['>', '<', '>=', '<='],
  time: ['>=', '<=', ':'],
  ip: [':', '!='],
  text: [':', '!=', '~'],
  enum: [':', '!='],
};

function quoteIfNeeded(v) {
  return /[\s()"'|]/.test(v) ? `"${v.replace(/"/g, '\\"')}"` : v;
}

/**
 * Suggestions for the text at `caret`: `[{label, insert, detail, kind, from, to}]`. Replace
 * text.slice(from, to) with `insert`. `ctx` = {view, rows, inventory, all}; `all` lists every key
 * when nothing is typed for the current term (the bar sets it on ArrowDown).
 */
export function suggest(text, caret, ctx = {}) {
  const s = String(text ?? '');
  const at = Math.max(0, Math.min(caret ?? s.length, s.length));
  const { base } = viewOf(ctx.view);
  const fields = FIELDS[base];
  if (!fields) return [];
  // The fragment being typed: back to whitespace or a parenthesis, honouring an open quote.
  let start = at;
  let quotes = 0;
  for (let i = 0; i < at; i++) if (s[i] === '"') quotes += 1;
  if (quotes % 2 === 1) {
    start = s.lastIndexOf('"', at - 1);
    while (start > 0 && !isSpace(s[start - 1]) && s[start - 1] !== '(') start -= 1;
  } else {
    while (start > 0 && !isSpace(s[start - 1]) && s[start - 1] !== '(' && s[start - 1] !== ')') start -= 1;
  }
  let end = at;
  while (end < s.length && !isSpace(s[end]) && s[end] !== ')' && quotes % 2 === 0) end += 1;
  let from = start;
  while (from < at && (s[from] === '-' || s[from] === '!')) from += 1;
  const frag = s.slice(from, at);
  const out = [];
  const rows = ctx.rows || [];
  const inv = ctx.inventory || null;

  const km = /^([A-Za-z_][\w.-]*)(!=|>=|<=|=|>|<|~|:)(.*)$/s.exec(frag);
  if (km) {
    const hit = resolveKey(fields, km[1]);
    if (!hit) return [];
    const head = `${km[1]}${km[2]}`;
    const lastPipe = km[3].lastIndexOf('|');
    const prior = lastPipe >= 0 ? km[3].slice(0, lastPipe + 1) : '';
    const typed = (lastPipe >= 0 ? km[3].slice(lastPipe + 1) : km[3]).replace(/^"/, '').toLowerCase();
    let values = [];
    try {
      values = hit.def.values ? hit.def.values(rows, inv) : [];
    } catch (_e) {
      values = [];
    }
    const ranked = [];
    for (const v of values) {
      const low = String(v).toLowerCase();
      if (typed && low === typed) continue;
      if (!typed || low.startsWith(typed)) ranked.push([0, v]);
      else if (low.includes(typed)) ranked.push([1, v]);
    }
    ranked.sort((a, b) => a[0] - b[0]);
    for (const [, v] of ranked.slice(0, 12)) {
      out.push({ label: String(v), insert: `${head}${prior}${quoteIfNeeded(String(v))}`, detail: hit.def.label, kind: 'value', from, to: end });
    }
    if (!out.length && !typed) {
      const ex = { ip: '10.10.0.0/16', int: '443', size: '1M', duration: '5m', time: '2026-11-24T07:40' }[hit.def.type];
      if (ex) out.push({ label: `${head}${ex}`, insert: `${head}${ex}`, detail: `example: ${hit.def.label}`, kind: 'example', from, to: end });
    }
    return out;
  }

  const low = frag.toLowerCase();
  if (!s.trim()) {
    for (const ex of EXAMPLES[base] || []) out.push({ label: ex, insert: ex, detail: 'example', kind: 'example', from: 0, to: s.length });
    return out;
  }
  // Nothing typed yet for this term: stay quiet unless the list was asked for (ctx.all).
  if (!low && !ctx.all) return out;
  // Exact key typed: offer its operators.
  const exact = resolveKey(fields, low);
  if (exact && low && exact.name === low) {
    for (const op of OPS_FOR[exact.def.type] || [':']) {
      out.push({ label: `${frag}${op}`, insert: `${frag}${op}`, detail: exact.def.label, kind: 'op', from, to: end });
    }
  }
  for (const [name, def] of Object.entries(fields)) {
    if (exact && exact.name === name && exact.name === low) continue;
    let matched = name.startsWith(low) ? name : null;
    if (!matched && low.length >= 2) matched = (def.aliases || []).find((a) => a.startsWith(low)) || null;
    if (!matched) continue;
    const where = def.device ? ' \u00b7 device' : '';
    out.push({ label: `${name}:`, insert: `${name}:`, detail: `${def.label}${matched !== name ? ` (alias ${matched})` : ''}${where}`, kind: 'key', from, to: end });
  }
  // Values of any key that contain the fragment ("allow" -> policy:allow-web).
  if (low.length >= 2) {
    const seen = new Set();
    for (const [name, def] of Object.entries(fields)) {
      if (!def.values || def.type === 'int' || out.length >= 14) continue;
      let values = [];
      try {
        values = def.values(rows, inv);
      } catch (_e) {
        continue;
      }
      for (const v of values) {
        const sv = String(v);
        if (!sv.toLowerCase().includes(low) || seen.has(`${name}:${sv}`)) continue;
        seen.add(`${name}:${sv}`);
        out.push({ label: `${name}:${sv}`, insert: `${name}:${quoteIfNeeded(sv)}`, detail: def.label, kind: 'value', from, to: end });
        if (out.length >= 14) break;
      }
    }
  }
  if (low && start > 0) {
    for (const kw of ['AND', 'OR', 'NOT']) {
      if (kw.toLowerCase().startsWith(low) && kw.toLowerCase() !== low) out.push({ label: kw, insert: kw, detail: 'operator', kind: 'keyword', from, to: end });
    }
  }
  return out.slice(0, 14);
}

/** Example queries for a view (shown when the bar is empty). */
export function examples(view) {
  return (EXAMPLES[viewOf(view).base] || []).slice();
}

/** Keys of a view with their labels, for help panels: [{key, aliases, type, label, device}]. */
export function describe(view) {
  const fields = FIELDS[viewOf(view).base] || {};
  return Object.entries(fields).map(([key, d]) => ({ key, aliases: d.aliases || [], type: d.type, label: d.label || '', device: Boolean(d.device || d.report) }));
}
