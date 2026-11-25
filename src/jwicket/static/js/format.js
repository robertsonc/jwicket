// format.js: numbers, sizes, rates, durations and times for display; control and format characters in
// device text (controlParts, plain, cliUnsafe); the device's configured time zone (deviceZone,
// naiveToUtc). Pure; safe in node tests.
//
// Sizes are decimal (1 kB = 1000 B), as network counters are. Times are shown in UTC, the way the
// API reports them, and labelled as such where they appear.

const NF = new Intl.NumberFormat('en-US');
const DASH = '—';

function finite(n) {
  const v = typeof n === 'string' && n.trim() !== '' ? Number(n) : n;
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
}

/** 12345 -> "12,345"; null -> "—" */
export function num(n) {
  const v = finite(n);
  return v === null ? DASH : NF.format(v);
}

/** 1534 -> "1.5k", 524288 -> "524k", 2100000 -> "2.1M" */
export function compact(n) {
  const v = finite(n);
  if (v === null) return DASH;
  const abs = Math.abs(v);
  if (abs < 1000) return String(Math.round(v));
  const units = ['k', 'M', 'G', 'T'];
  let x = v / 1000;
  let i = 0;
  while (Math.abs(x) >= 1000 && i < units.length - 1) {
    x /= 1000;
    i += 1;
  }
  const digits = Math.abs(x) < 10 ? 1 : 0;
  return `${x.toFixed(digits).replace(/\.0$/, '')}${units[i]}`;
}

/** 1100000 -> "1.1 MB" */
export function bytes(n) {
  const v = finite(n);
  if (v === null) return DASH;
  const abs = Math.abs(v);
  if (abs < 1000) return `${Math.round(v)} B`;
  const units = ['kB', 'MB', 'GB', 'TB', 'PB'];
  let x = v / 1000;
  let i = 0;
  while (Math.abs(x) >= 1000 && i < units.length - 1) {
    x /= 1000;
    i += 1;
  }
  const digits = Math.abs(x) >= 100 ? 0 : 1;
  return `${x.toFixed(digits)} ${units[i]}`;
}

/** bytes per second -> "1.2 MB/s" */
export function rate(bytesPerSec) {
  const v = finite(bytesPerSec);
  if (v === null) return DASH;
  if (v > 0 && v < 1) return '<1 B/s';
  return `${bytes(v)}/s`;
}

function pad2(n) {
  return String(n).padStart(2, '0');
}

/** 38 -> "38 s", 724 -> "12m 04s", 11520 -> "3h 12m", 190000 -> "2d 4h" */
export function duration(seconds) {
  const v = finite(seconds);
  if (v === null) return DASH;
  const s = Math.max(0, Math.round(v));
  if (s < 60) return `${s} s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${pad2(s % 60)}s`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ${pad2(Math.floor((s % 3600) / 60))}m`;
  return `${Math.floor(s / 86400)}d ${Math.floor((s % 86400) / 3600)}h`;
}

/** Date | ms epoch | ISO string -> Date (or null) */
export function toDate(value) {
  if (value === null || value === undefined || value === '') return null;
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value;
  const d = new Date(typeof value === 'number' ? value : String(value));
  return Number.isNaN(d.getTime()) ? null : d;
}

/** "just now", "12 s ago", "5 min ago", "3 h ago", "2 d ago" */
export function ago(date, now = Date.now()) {
  const d = toDate(date);
  if (!d) return DASH;
  const s = Math.round((now - d.getTime()) / 1000);
  if (s < 5) return 'just now';
  if (s < 60) return `${s} s ago`;
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}

/** "07:44:22" in UTC */
export function time(date) {
  const d = toDate(date);
  if (!d) return DASH;
  return `${pad2(d.getUTCHours())}:${pad2(d.getUTCMinutes())}:${pad2(d.getUTCSeconds())}`;
}

/** "2026-11-24 07:44:22 UTC" */
export function stamp(date) {
  const d = toDate(date);
  if (!d) return DASH;
  return `${d.getUTCFullYear()}-${pad2(d.getUTCMonth() + 1)}-${pad2(d.getUTCDate())} ${time(d)} UTC`;
}

function pluralOf(word) {
  if (/[^aeiou]y$/i.test(word)) return `${word.slice(0, -1)}ies`;
  if (/(s|x|z|ch|sh)$/i.test(word)) return `${word}es`;
  return `${word}s`;
}

/** plural(3, 'policy') -> "3 policies"; plural(1, 'zone') -> "1 zone"; plural(2, 'child', 'children') */
export function plural(n, word, pluralWord) {
  const v = finite(n);
  const many = pluralWord || pluralOf(word);
  return `${num(v)} ${v === 1 ? word : many}`;
}

/** 0.0314 -> "3.1%"; tiny non-zero values read "<0.1%" instead of a misleading 0 */
export function pct(part, total) {
  const p = finite(part);
  const t = finite(total);
  if (p === null || t === null || t <= 0) return DASH;
  const v = (p / t) * 100;
  if (v > 0 && v < 0.1) return '<0.1%';
  return `${v < 10 ? v.toFixed(1) : Math.round(v)}%`;
}

// ---- control and format characters in device text -------------------------------------------------

// Characters that are invisible or change the direction of the text around them: C0 controls other
// than tab and line feed, DEL and the C1 controls, the soft hyphen, the Arabic letter mark, the
// Mongolian vowel separator, zero-width characters and LRM/RLM, line and paragraph separators,
// bidirectional embeddings and overrides, word joiners and invisible operators, bidirectional
// isolates and deprecated format characters, the byte-order mark, and the interlinear annotation
// characters. Device text is attacker-influenced (names, descriptions, comments, user names, URLs):
// a right-to-left override would reorder the rest of a line on screen, and a zero-width space makes
// two different names look the same. Views show each one as a visible badge (dom.vis) and write it
// as "<U+XXXX>" in titles, labels and toasts (plain). No surrogate is in the class, so splitting a
// string around these characters never cuts an astral character (an emoji) in half.
export const CONTROL_CLASS = '\u0000-\u0008\u000b-\u001f\u007f-\u009f\u00ad\u061c\u180e\u200b-\u200f\u2028-\u202e\u2060-\u2064\u2066-\u206f\ufeff\ufff9-\ufffb';
export const CONTROL_RE = new RegExp(`[${CONTROL_CLASS}]`);
const CONTROL_G = new RegExp(`[${CONTROL_CLASS}]`, 'g');
// `all`: tab and line feed too, for names, which must stay on one line.
const CONTROL_ALL_RE = new RegExp(`[\t\n${CONTROL_CLASS}]`);
const CONTROL_ALL_G = new RegExp(`[\t\n${CONTROL_CLASS}]`, 'g');
// What must never go into a command pasted into the device CLI: every C0 control (tab, line feed and
// carriage return included), DEL and the C1 controls, and the line and paragraph separators. Format
// characters (bidi marks, zero-width characters) are not in this set: they are shown as badges and
// copied exactly, so the command names the same object as the device.
const CLI_UNSAFE = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/;

const reOf = (all) => (all ? CONTROL_ALL_RE : CONTROL_RE);
const globalOf = (all) => (all ? CONTROL_ALL_G : CONTROL_G);

/** "U+202E" for one character (at least 4 upper-case hex digits). */
export function controlName(ch) {
  const cp = String(ch ?? '').codePointAt(0);
  return `U+${(cp === undefined ? 0 : cp).toString(16).toUpperCase().padStart(4, '0')}`;
}

/**
 * `s` split around control and format characters, in order:
 * `[{text: 'web'}, {ctl: 'U+200B', ch: '\u200b'}, {text: 'proxy'}]`. '' gives []; a string with none
 * gives `[{text: s}]`. With `all: true`, tab and line feed are split out too (for names).
 */
export function controlParts(s, { all = false } = {}) {
  const str = String(s ?? '');
  if (!str) return [];
  if (!reOf(all).test(str)) return [{ text: str }];
  const out = [];
  let run = '';
  for (let i = 0; i < str.length; i += 1) {
    const ch = str[i];
    if (reOf(all).test(ch)) {
      if (run) out.push({ text: run });
      run = '';
      out.push({ ctl: controlName(ch), ch });
    } else {
      run += ch;
    }
  }
  if (run) out.push({ text: run });
  return out;
}

/** `s` with each control or format character written as "<U+XXXX>": for titles, aria labels, toasts. */
export function plain(s, { all = false } = {}) {
  const str = String(s ?? '');
  return reOf(all).test(str) ? str.replace(globalOf(all), (c) => `<${controlName(c)}>`) : str;
}

/** Whether `s` holds any control or format character (tab and line feed too with `all`). */
export function hasControls(s, { all = false } = {}) {
  return reOf(all).test(String(s ?? ''));
}

/** How many control or format characters `s` holds (tab and line feed not counted). */
export function countControls(s) {
  const str = String(s ?? '');
  if (!CONTROL_RE.test(str)) return 0;
  return (str.match(CONTROL_G) || []).length;
}

/** True when `s` must never be put into a pasted CLI command (line breaks, C0/C1 controls, U+2028/9). */
export function cliUnsafe(s) {
  return CLI_UNSAFE.test(String(s ?? ''));
}

// ---- the device's configured time zone (snapshot `clock`) -----------------------------------------

// A Junos time-zone value J-Wicket may hand to Intl: an IANA-style name starting with a letter. Offset
// forms are refused even when Intl accepts them: the sign convention of Junos "GMT+n" / "GMT-n" is not
// known (POSIX-style Etc/GMT+8 means UTC-8), so such a value is never converted.
const ZONE_NAME = /^[A-Za-z][A-Za-z0-9_+\-/]{0,63}$/;
const ZONE_OFFSET = /^(?:Etc\/)?(?:GMT|UTC|UT)[+-]/i;
const ZONE_FORMATS = new Map();

function zoneFormat(zone) {
  if (typeof zone !== 'string' || !ZONE_NAME.test(zone) || ZONE_OFFSET.test(zone)) return null;
  if (ZONE_FORMATS.has(zone)) return ZONE_FORMATS.get(zone);
  let f = null;
  try {
    f = new Intl.DateTimeFormat('en-US', {
      timeZone: zone, hourCycle: 'h23', year: 'numeric', month: 'numeric', day: 'numeric',
      hour: 'numeric', minute: 'numeric', second: 'numeric',
    });
  } catch (_err) {
    f = null; // not a zone this browser knows (PDT, a typo, a Junos-only name)
  }
  if (ZONE_FORMATS.size > 64) ZONE_FORMATS.clear();
  ZONE_FORMATS.set(zone, f);
  return f;
}

/**
 * What J-Wicket can say about the device's time zone, from the inventory snapshot's `clock`:
 * `{ zone, label, convertible }`. `convertible` is true only when the configuration was read and its
 * `time-zone` is an IANA name this browser's Intl accepts; then `zone` is that name and times can be
 * shown in it. Otherwise:
 *   - not configured: label "UTC (Junos default)" (the default is verified on the HPE time-zone page);
 *   - a value Intl does not accept, or a GMT+n style offset: "<value> (not convertible here)";
 *   - configuration not read: "not known (configuration not read: <status>)". J-Wicket never assumes
 *     UTC when it could not read the configuration.
 * A time-zone statement that is deactivated is reported by the server as not configured; that the
 * default then applies is inferred, and the label says so. The value is "configured", never "in effect":
 * Junos applies a change to every process only after a reboot.
 */
export function deviceZone(clock) {
  if (!clock || typeof clock !== 'object') return { zone: null, label: 'not known', convertible: false };
  if (clock.status !== 'ok') {
    return { zone: null, label: `not known (configuration not read: ${plain(String(clock.status || 'unknown'))})`, convertible: false };
  }
  const raw = typeof clock.time_zone === 'string' && clock.time_zone ? clock.time_zone : null;
  if (!raw) {
    if (typeof clock.deactivated === 'string' && clock.deactivated) {
      return {
        zone: null,
        label: `UTC (Junos default; the configured time-zone ${plain(clock.deactivated, { all: true })} is deactivated, so J-Wicket reads it as not in effect: inferred)`,
        convertible: false,
      };
    }
    return { zone: null, label: 'UTC (Junos default)', convertible: false };
  }
  if (!zoneFormat(raw)) return { zone: raw, label: `${plain(raw, { all: true })} (not convertible here)`, convertible: false };
  return { zone: raw, label: raw, convertible: true };
}

// Milliseconds `zone` is ahead of UTC at the instant `utcMs` (whole seconds).
function zoneOffsetMs(utcMs, fmt) {
  const whole = utcMs - (((utcMs % 1000) + 1000) % 1000);
  const p = {};
  for (const part of fmt.formatToParts(new Date(whole))) p[part.type] = part.value;
  const asUtc = Date.UTC(Number(p.year), Number(p.month) - 1, Number(p.day), Number(p.hour) % 24, Number(p.minute), Number(p.second));
  return asUtc - whole;
}

/**
 * A naive wall-clock time (`ms` read as if it were UTC, as J-Wicket reads zone-less log timestamps)
 * taken to be in `zone`, as real UTC ms. DST-aware through Intl: Europe/Paris 2026-07-01 12:00 gives
 * 10:00Z, 2026-12-01 12:00 gives 11:00Z. A wall time skipped by a DST change maps forward by the
 * change; a repeated one maps to its first occurrence. Null when `zone` is not convertible.
 */
export function naiveToUtc(ms, zone) {
  const fmt = zoneFormat(zone);
  const v = finite(ms);
  if (!fmt || v === null) return null;
  // The offsets a day either side bracket any one DST change near this wall time.
  const before = zoneOffsetMs(v - 86400000, fmt);
  const after = zoneOffsetMs(v + 86400000, fmt);
  const valid = (off) => zoneOffsetMs(v - off, fmt) === off;
  const okBefore = valid(before);
  const okAfter = valid(after);
  if (okBefore && okAfter) return v - Math.max(before, after); // repeated hour: the first occurrence
  if (okBefore) return v - before;
  if (okAfter) return v - after;
  const here = zoneOffsetMs(v, fmt);
  if (valid(here)) return v - here;
  return v - Math.min(before, after); // skipped hour: forward by the change
}
