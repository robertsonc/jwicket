// format.js: numbers, sizes, rates, durations and times for display. Pure; safe in node tests.
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
