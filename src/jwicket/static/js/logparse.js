// J-Wicket log line parser, tokenizer and decoder. Pure logic: no DOM, nothing runs at import time.
//
// Formats (research notes 51 and 52):
//   * RFC 5424 / structured-data: "<14>1 TS HOST APP PROCID MSGID [sd-id k="v" ...] text", also without
//     <PRI>, without an SD-ID (on-box report output), bracketless ("show security log query"), unquoted
//     values (url=<scheme>://...), keys with spaces (D3P error="..."), curly-quote and missing-quote typos.
//   * BSD (default syslog): "Mon DD HH:MM:SS[.mmm][ YYYY] HOST proc[pid]: [%FAC-n-]TAG: text", tag and
//     pid optional, one or two spaces after the time; plus lines with no "proc:" part.
//   * Security log buffer lines as J-Wicket's API renders them: "YYYY-MM-DD.HH:MM:SS proc[pid]: TAG: text".
// RT_FLOW bodies in BSD text are positional and change between releases: the documented prefix
// (5-tuple, service, NAT tuple, rule types/names, protocol, policy, zones, session id, counters) is
// parsed and the rest is kept as text. Structured-data keys always win over positional guesses.
//
// tokenize(line) is lossless: the token texts concatenate back to the exact input line.

export const SEVERITIES = ['emergency', 'alert', 'critical', 'error', 'warning', 'notice', 'info', 'debug'];

const AUTH_RE = /^(SSHD_|JSSHD_|LOGIN_|LIBJNX_LOGIN|UI_AUTH|UI_LOGIN_EVENT|UI_LOGOUT_EVENT|FWAUTH_|PAM_|AUTHD_)/;

/** Event families, in the order the Logs toolbar shows them. `match(tag)` is exclusive except "other". */
export const FAMILIES = [
  { id: 'create', label: 'Flow create', match: (t) => /^RT_FLOW_(SESSION|STREAM)_CREATE/.test(t || '') },
  { id: 'close', label: 'Flow close', match: (t) => /^RT_FLOW_(SESSION|STREAM)_CLOSE/.test(t || '') },
  { id: 'deny', label: 'Flow deny', match: (t) => /^RT_FLOW_(SESSION|STREAM)_DENY/.test(t || '') },
  { id: 'screen', label: 'Screen', match: (t) => /^RT_SCREEN/.test(t || '') },
  {
    id: 'idp', label: 'IDP & threats',
    match: (t) => /^(IDP_|AV_|ANTIVIRUS_|WEBFILTER_|AAMW_|SECINTEL_|ANTISPAM_|CONTENT_FILTERING_|UTM_)/.test(t || ''),
  },
  { id: 'vpn', label: 'VPN (KMD/IKE)', match: (t) => /^(KMD_|IKE_|IKED_|RT_IPSEC_|IPSEC_|PKID_)/.test(t || '') },
  { id: 'commit', label: 'Commit & CLI', match: (t) => /^UI_/.test(t || '') && !AUTH_RE.test(t) },
  { id: 'auth', label: 'Auth', match: (t) => AUTH_RE.test(t || '') },
  { id: 'snmp', label: 'SNMP', match: (t) => /^(SNMP_|SNMPD_|MIB2D_)/.test(t || '') },
  {
    id: 'chassis', label: 'Chassis & HA',
    match: (t) => /^(CHASSISD_|CHASSISM_|JSRPD_|FPC_|PFE_|LICENSE_|SYSTEM_|DCD_)/.test(t || ''),
  },
  { id: 'other', label: 'Other', match: () => true },
];

const DAEMON_FAMILY = {
  sshd: 'auth', login: 'auth', 'sshd-session': 'auth', su: 'auth', sudo: 'auth',
  mgd: 'commit', cli: 'commit', kmd: 'vpn', iked: 'vpn', snmpd: 'snmp', mib2d: 'snmp',
  chassisd: 'chassis', jsrpd: 'chassis', idpd: 'idp',
};

/** Family id for a tag (and, for untagged lines, the daemon name). */
export function family(tag, daemon) {
  if (tag) {
    for (const f of FAMILIES) if (f.id !== 'other' && f.match(tag)) return f.id;
    return 'other';
  }
  const d = String(daemon || '').replace(/^\//, '').toLowerCase();
  return DAEMON_FAMILY[d] || 'other';
}

// Default severity by tag when the line does not carry one (System Log Explorer, 24.4R1).
const TAG_SEVERITY = {
  UI_COMMIT: 5, UI_COMMIT_COMPLETED: 4, UI_COMMIT_PROGRESS: 6, UI_COMMIT_NOT_CONFIRMED: 5,
  UI_COMMIT_ROLLBACK_FAILED: 3, UI_NETCONF_CMD: 6, UI_JUNOSCRIPT_CMD: 6, UI_CMDLINE_READ_LINE: 6,
  UI_LOGIN_EVENT: 6, UI_LOGOUT_EVENT: 6, UI_AUTH_EVENT: 6, UI_AUTH_INVALID: 5, UI_DBASE_LOGIN_EVENT: 5,
  UI_DBASE_LOGOUT_EVENT: 5, UI_CFG_AUDIT_SET: 6, UI_LOAD_EVENT: 5, UI_RESTART_EVENT: 4, UI_REBOOT_EVENT: 4,
  UI_CHILD_STATUS: 6, UI_CHILD_EXITED: 5,
  SSHD_LOGIN_FAILED: 5, SSHD_LOGIN_ATTEMPTS_THRESHOLD: 5, LOGIN_FAILED: 5, LIBJNX_LOGIN_ACCOUNT_LOCKED: 5,
  KMD_VPN_UP_ALARM_USER: 6, KMD_VPN_DOWN_ALARM_USER: 3, KMD_PM_SA_ESTABLISHED: 6, KMD_PM_SA_DELETED: 5,
  KMD_VPN_TS_MISMATCH: 3, IKE_VPN_UP_ALARM_USER: 6, IKE_VPN_DOWN_ALARM_USER: 3,
  JSRPD_RG_STATE_CHANGE: 1, JSRPD_NODE_STATE_CHANGE: 3, JSRPD_HA_CONTROL_LINK_DOWN: 1, JSRPD_SPLIT_BRAIN: 3,
  SNMP_TRAP_LINK_DOWN: 4, SNMP_TRAP_LINK_UP: 6, SNMPD_TRAP_COLD_START: 2, SNMPD_TRAP_WARM_START: 3,
  SNMPD_AUTH_FAILURE: 5, LICENSE_EXPIRED: 1, LICENSE_NEARING_EXPIRY: 1, CHASSISD_FAN_FAILURE: 3,
  AV_VIRUS_DETECTED_MT: 4, WEBFILTER_URL_BLOCKED: 4, WEBFILTER_URL_PERMITTED: 6, IDP_ATTACK_LOG_EVENT: 6,
  SYSTEM_OPERATIONAL: 5, SYSTEM_ABNORMAL_SHUTDOWN: 5,
};

function tagSeverity(tag) {
  if (!tag) return null;
  if (Object.prototype.hasOwnProperty.call(TAG_SEVERITY, tag)) return TAG_SEVERITY[tag];
  if (/^RT_FLOW_|^APPTRACK_|^RT_NAT_/.test(tag)) return 6;
  if (/^RT_SCREEN_/.test(tag)) return 3;
  if (/^CHASSISD_SNMP_TRAP/.test(tag)) return 5;
  return null;
}

export function severityName(n) {
  return Number.isInteger(n) && n >= 0 && n < 8 ? SEVERITIES[n] : null;
}

// --- small helpers ---------------------------------------------------------------------------------

const PLACEHOLDER = /^(?:N\/A|NA|None|NONE|UNKNOWN|unknown|-|0x0|)$/;
const PROTO_NAMES = { 1: 'icmp', 2: 'igmp', 6: 'tcp', 17: 'udp', 47: 'gre', 50: 'esp', 51: 'ah', 58: 'icmp6', 89: 'ospf', 103: 'pim', 132: 'sctp' };
const MONTHS = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };

const isPlaceholder = (v) => v === undefined || v === null || PLACEHOLDER.test(String(v).trim());
const isInt = (w) => /^\d+$/.test(w || '');

/** "192.0.2.2/24" -> "192.0.2.2" (report output appends masks to host addresses). */
function hostOf(addr) {
  if (addr === undefined || addr === null) return null;
  const s = String(addr).trim();
  if (isPlaceholder(s)) return null;
  const slash = s.indexOf('/');
  return slash > 0 ? s.slice(0, slash) : s;
}

function protoName(id) {
  if (id === undefined || id === null || id === '') return null;
  const s = String(id).trim();
  if (isInt(s)) return PROTO_NAMES[Number(s)] || `proto ${s}`;
  return s.toLowerCase();
}

function toInt(v) {
  if (v === undefined || v === null) return null;
  const s = String(v).trim();
  return isInt(s) ? Number(s) : null;
}

// --- header grammars -------------------------------------------------------------------------------

const R_5424 = /^(?:(<(\d{1,3})>(\d{1,2})) )?(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|[+-]\d\d:?\d\d)?) (\S+) (\S+) (\S+) (\S+)(?= |$)/d;
const R_BUFFER = /^(\d{4}-\d\d-\d\d[.T ]\d\d:\d\d:\d\d(?:\.\d{1,9})?(?: ?(?:Z|[+-]\d\d:?\d\d|[A-Z]{2,5}))?|-) ([^\s:[\]]+)(\[(\d+)\])?: ([A-Z][A-Z0-9_]*|-):(?: |$)/d;
const R_BSD = /^((Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) {1,2}(\d{1,2}) (\d\d):(\d\d):(\d\d)(?:\.(\d{1,6}))?(?: (\d{4}))?)( +)(\S+) ([^\s:[\]]+)(\[(\d+)\])?: (?:(%([A-Z0-9_]+)-([0-7])(?:-([A-Z][A-Z0-9_]*))?): |([A-Z][A-Z0-9_]{2,}): )?/d;
const R_BSD_HOST = /^((Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) {1,2}(\d{1,2}) (\d\d):(\d\d):(\d\d)(?:\.(\d{1,6}))?(?: (\d{4}))?)( +)(\S+)(?: |$)/d;

function isoTime(ts) {
  if (!ts) return null;
  let s = ts.replace(/([+-]\d\d)(\d\d)$/, '$1:$2');
  if (!/(Z|[+-]\d\d:\d\d)$/.test(s)) s += 'Z';
  const t = Date.parse(s);
  return Number.isFinite(t) ? t : null;
}

function bufferTime(ts) {
  const m = /^(\d{4})-(\d\d)-(\d\d)[.T ](\d\d):(\d\d):(\d\d)(\.\d+)?(?: ?(Z|[+-]\d\d:?\d\d))?/.exec(ts || '');
  if (!m) return null;
  const iso = `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}${m[7] || ''}${m[8] || 'Z'}`;
  return isoTime(iso);
}

function bsdTime(m, now) {
  const mon = MONTHS[m[2]];
  const day = Number(m[3]);
  const ms = m[7] ? Math.round(Number(`0.${m[7]}`) * 1000) : 0;
  const nowDate = new Date(now);
  let year = m[8] ? Number(m[8]) : nowDate.getUTCFullYear();
  let t = Date.UTC(year, mon, day, Number(m[4]), Number(m[5]), Number(m[6]), ms);
  // Default Junos timestamps carry no year: a date more than two days ahead of the clock is last year's.
  if (!m[8] && t > now + 2 * 86400000) {
    year -= 1;
    t = Date.UTC(year, mon, day, Number(m[4]), Number(m[5]), Number(m[6]), ms);
  }
  return t;
}

// --- structured data -------------------------------------------------------------------------------

/**
 * Reads RFC 5424 SD elements starting at `p` (a "["), or bracketless key="value" pairs when
 * `bare` is set. Records spans for highlighting. Returns the position after the structured data.
 */
function readStructured(line, p, out, bare) {
  const n = line.length;
  const spans = out.spans;
  const fields = out.fields;
  while (p < n && (bare || line[p] === '[')) {
    if (!bare) {
      spans.push([p, p + 1, 'text']);
      p += 1;
      // SD-ID: the first token when it carries no "=" (e.g. junos@2636.1.1.1.2.129).
      const idm = /[^\s\]="]+(?=[\s\]])/y;
      idm.lastIndex = p;
      const im = idm.exec(line);
      if (im) {
        spans.push([p, p + im[0].length, 'sdid']);
        if (!out.sdid) out.sdid = im[0];
        p += im[0].length;
      }
    }
    for (;;) {
      while (p < n && line[p] === ' ') p += 1;
      if (p >= n) break;
      if (!bare && line[p] === ']') {
        spans.push([p, p + 1, 'text']);
        p += 1;
        break;
      }
      // Key: up to "=" (keys may contain spaces: `D3P error="..."`).
      const km = /[^\s="\]][^="\]]*?(?==)/y;
      km.lastIndex = p;
      const k = km.exec(line);
      if (!k) {
        // Not a pair: the rest of this element is text.
        const close = bare ? n : line.indexOf(']', p);
        p = close < 0 ? n : close;
        continue;
      }
      const key = k[0];
      spans.push([p, p + key.length, 'key']);
      p += key.length;
      spans.push([p, p + 1, 'text']); // "="
      p += 1;
      let value;
      let vs;
      let ve;
      if (line[p] === '"') {
        spans.push([p, p + 1, 'text']);
        p += 1;
        vs = p;
        let buf = '';
        let closed = -1;
        while (p < n) {
          const c = line[p];
          if (c === '\\' && p + 1 < n) {
            buf += line[p + 1];
            p += 2;
            continue;
          }
          if (c === '"') {
            closed = p;
            break;
          }
          buf += c;
          p += 1;
        }
        // A missing closing quote shows up as `value next-key=` before the quote we found.
        const miss = closed >= 0 ? /\s([A-Za-z][\w.-]*)=$/.exec(buf) : null;
        if (miss) {
          const cut = vs + miss.index;
          value = line.slice(vs, cut).replace(/\\(.)/g, '$1');
          ve = cut;
          p = cut;
        } else {
          value = buf;
          ve = closed >= 0 ? closed : n;
          p = ve;
        }
        if (ve > vs) spans.push([vs, ve, 'value', key, value]);
        if (!miss && closed >= 0) {
          spans.push([closed, closed + 1, 'text']);
          p = closed + 1;
        }
      } else {
        const vm = bare ? /[^\s]*/y : /[^\s\]]*/y;
        vm.lastIndex = p;
        const v = vm.exec(line);
        vs = p;
        ve = p + (v ? v[0].length : 0);
        value = line.slice(vs, ve).replace(/^[\u201c\u201d"]+|[\u201c\u201d"]+$/g, '');
        if (ve > vs) spans.push([vs, ve, 'value', key, value]);
        p = ve;
      }
      if (!Object.prototype.hasOwnProperty.call(fields, key)) fields[key] = value;
    }
    if (bare) break;
    if (line[p] !== '[') break;
  }
  return p;
}

// --- RT_FLOW positional bodies ---------------------------------------------------------------------

const TUPLE = /^(.+?)\/(\d+)(-->|->)(.+?)\/(\d+)$/;
const COUNT = /^(\d+)\((\d+)\)$/;
const USERROLE = /^(.*)\((.*)\)$/;
const IFACE_FULL = /^(?:[a-z]{1,6}-\d+(?:\/\d+){1,3}(?:\.\d+)?|(?:reth|ae|st|lo|fxp|em|me|irb|vlan|fab|swfab|gr|lt|ip|pp|ppp|vtep)\d+(?:\.\d+)?|(?:irb|vlan)\.\d+)$/;
const ENCRYPTED = /^(?:Yes|No|yes|no|UNKNOWN|N\/A)$/;

function wordsOf(text, base) {
  const out = [];
  const re = /\S+/g;
  let m;
  while ((m = re.exec(text))) out.push({ w: m[0], s: base + m.index, e: base + m.index + m[0].length });
  return out;
}

function tupleSpans(spans, word, m, nat) {
  let p = word.s;
  const a = m[1].length;
  const t = nat ? 'nat' : 'ip';
  spans.push([p, p + a, t, nat ? 'natsrc' : 'src', m[1]]);
  p += a;
  spans.push([p, p + 1 + m[2].length, nat ? 'nat' : 'port', nat ? null : 'sport', m[2]]);
  p += 1 + m[2].length;
  spans.push([p, p + m[3].length, 'arrow']);
  p += m[3].length;
  spans.push([p, p + m[4].length, t, nat ? 'natdst' : 'dst', m[4]]);
  p += m[4].length;
  spans.push([p, p + 1 + m[5].length, nat ? 'nat' : 'port', nat ? null : 'dport', m[5]]);
}

function setF(f, key, value) {
  if (value === undefined || value === null) return;
  if (!Object.prototype.hasOwnProperty.call(f, key)) f[key] = value;
}

function wordClass(w) {
  if (BAD_WORDS.test(w)) return 'bad';
  if (GOOD_WORDS.test(w)) return 'good';
  return 'val';
}

/** Splits the NAT rule section (0, 2 or 4 fields; rule types may be two words, e.g. "source rule"). */
function natRules(ws, f) {
  const w = ws.map((x) => x.w);
  if (w.length === 2) {
    setF(f, 'src-nat-rule-name', w[0]);
    setF(f, 'dst-nat-rule-name', w[1]);
    return;
  }
  const out = [];
  let i = 0;
  for (let part = 0; part < 2 && i < w.length; part++) {
    let type = w[i];
    if (!isPlaceholder(type) && w[i + 1] === 'rule') {
      type = `${w[i]} rule`;
      i += 1;
    }
    i += 1;
    const name = w[i];
    i += 1;
    out.push([type, name]);
  }
  if (i === w.length && out.length === 2) {
    setF(f, 'src-nat-rule-type', out[0][0]);
    setF(f, 'src-nat-rule-name', out[0][1]);
    setF(f, 'dst-nat-rule-type', out[1][0]);
    setF(f, 'dst-nat-rule-name', out[1][1]);
  }
}

/** Parses an RT_FLOW body ("session created ...", "session closed <reason>: ...", "session denied ..."). */
function flowBody(event, msg, base, f, spans) {
  let off = 0;
  const lsys = /^Lsys (\S+): /.exec(msg);
  if (lsys) {
    setF(f, 'logical-system-name', lsys[1]);
    spans.push([base + 5, base + 5 + lsys[1].length, 'val', 'lsys', lsys[1]]);
    off = lsys[0].length;
  }
  const rest = msg.slice(off);
  let head;
  if (event === 'close') {
    head = /^(?:AppTrack )?session closed (.*?): /.exec(rest);
    if (!head) return;
    const rs = base + off + head[0].indexOf(head[1]);
    setF(f, 'reason', head[1]);
    spans.push([rs, rs + head[1].length, wordClass(head[1].split(' ').pop()) === 'bad' ? 'bad' : 'val', 'reason', head[1]]);
  } else if (event === 'create') {
    head = /^(?:AppTrack )?session created /.exec(rest);
  } else if (event === 'deny') {
    head = /^session denied /.exec(rest);
  } else {
    head = /^session update: /.exec(rest);
  }
  if (!head) return;
  const ws = wordsOf(rest.slice(head[0].length), base + off + head[0].length);
  const t1 = ws[0] && TUPLE.exec(ws[0].w);
  if (!t1) return;
  setF(f, 'source-address', t1[1]);
  setF(f, 'source-port', t1[2]);
  setF(f, 'destination-address', t1[4]);
  setF(f, 'destination-port', t1[5]);
  tupleSpans(spans, ws[0], t1, false);
  let i = 1;
  const hex = (x) => x && /^0x[0-9a-fA-F]+$/.test(x.w);
  if (hex(ws[i])) {
    setF(f, 'connection-tag', ws[i].w);
    spans.push([ws[i].s, ws[i].e, 'num']);
    i += 1;
  }
  const take = (word, key, type, k) => {
    if (!word) return;
    setF(f, key, word.w);
    spans.push([word.s, word.e, type, k, word.w]);
  };

  if (event === 'deny') {
    let pk = ws[i] && COUNT.exec(ws[i].w);
    if (!pk && ws[i + 1] && COUNT.exec(ws[i + 1].w)) {
      take(ws[i], 'service-name', 'val', 'service');
      i += 1;
      pk = COUNT.exec(ws[i].w);
    }
    if (!pk) {
      shortForm(ws, i, f, spans);
      return;
    }
    setF(f, 'protocol-id', pk[1]);
    setF(f, 'icmp-type', pk[2]);
    spans.push([ws[i].s, ws[i].s + pk[1].length, 'proto', 'proto', pk[1]]);
    i += 1;
    take(ws[i], 'policy-name', 'policy', 'policy');
    take(ws[i + 1], 'source-zone-name', 'zone', 'from');
    take(ws[i + 2], 'destination-zone-name', 'zone', 'to');
    let k = i + 3;
    if (ws[k] && !USERROLE.test(ws[k].w)) {
      take(ws[k], 'application', 'val', 'app');
      if (ws[k + 1] && !USERROLE.test(ws[k + 1].w)) take(ws[k + 1], 'nested-application', 'val', 'nested');
      k += ws[k + 1] && !USERROLE.test(ws[k + 1].w) ? 2 : 1;
    }
    if (ws[k] && USERROLE.test(ws[k].w)) {
      const ur = USERROLE.exec(ws[k].w);
      setF(f, 'username', ur[1]);
      setF(f, 'roles', ur[2]);
      if (!isPlaceholder(ur[1])) spans.push([ws[k].s, ws[k].s + ur[1].length, 'user', 'user', ur[1]]);
      k += 1;
    }
    if (ws[k] && IFACE_FULL.test(ws[k].w)) {
      take(ws[k], 'packet-incoming-interface', 'iface', 'iface');
      k += 1;
    }
    if (ws[k] && ENCRYPTED.test(ws[k].w)) {
      setF(f, 'encrypted', ws[k].w);
      k += 1;
    }
    const rs = k;
    while (ws[k] && !isInt(ws[k].w)) k += 1;
    if (k > rs) {
      const reason = ws.slice(rs, k).map((x) => x.w).join(' ');
      setF(f, 'reason', reason);
      spans.push([ws[rs].s, ws[k - 1].e, /deny|drop|denied/i.test(reason) ? 'bad' : 'val', 'reason', reason]);
    }
    if (ws[k] && isInt(ws[k].w)) take(ws[k], 'session-id', 'num', 'session');
    return;
  }

  if (ws[i] && !TUPLE.test(ws[i].w)) {
    take(ws[i], 'service-name', 'val', 'service');
    i += 1;
  }
  const t2 = ws[i] && TUPLE.exec(ws[i].w);
  if (!t2) {
    shortForm(ws, i, f, spans);
    return;
  }
  setF(f, 'nat-source-address', t2[1]);
  setF(f, 'nat-source-port', t2[2]);
  setF(f, 'nat-destination-address', t2[4]);
  setF(f, 'nat-destination-port', t2[5]);
  tupleSpans(spans, ws[i], t2, true);
  i += 1;
  if (hex(ws[i])) {
    setF(f, 'nat-connection-tag', ws[i].w);
    spans.push([ws[i].s, ws[i].e, 'num']);
    i += 1;
  }
  // Anchor on "<protocol> <policy> <from> <to> <session-id>": the rule section before it varies.
  let j = -1;
  for (let c = i; c <= Math.min(i + 8, ws.length - 5); c++) {
    if (!isInt(ws[c].w) || Number(ws[c].w) > 255 || !isInt(ws[c + 4].w)) continue;
    if (event === 'close' && !(ws[c + 5] && COUNT.test(ws[c + 5].w))) continue;
    j = c;
    break;
  }
  if (j < 0) return;
  natRules(ws.slice(i, j), f);
  for (let c = i; c < j; c++) if (!isPlaceholder(ws[c].w) && ws[c].w !== 'rule') spans.push([ws[c].s, ws[c].e, 'nat']);
  take(ws[j], 'protocol-id', 'proto', 'proto');
  take(ws[j + 1], 'policy-name', 'policy', 'policy');
  take(ws[j + 2], 'source-zone-name', 'zone', 'from');
  take(ws[j + 3], 'destination-zone-name', 'zone', 'to');
  take(ws[j + 4], 'session-id', 'num', 'session');
  let k = j + 5;
  const user = (word) => {
    const ur = USERROLE.exec(word.w);
    setF(f, 'username', ur[1]);
    setF(f, 'roles', ur[2]);
    if (!isPlaceholder(ur[1])) spans.push([word.s, word.s + ur[1].length, 'user', 'user', ur[1]]);
  };
  if (event === 'close') {
    const c1 = ws[k] && COUNT.exec(ws[k].w);
    if (c1) {
      setF(f, 'packets-from-client', c1[1]);
      setF(f, 'bytes-from-client', c1[2]);
      spans.push([ws[k].s, ws[k].e, 'num']);
      k += 1;
    }
    const c2 = ws[k] && COUNT.exec(ws[k].w);
    if (c2) {
      setF(f, 'packets-from-server', c2[1]);
      setF(f, 'bytes-from-server', c2[2]);
      spans.push([ws[k].s, ws[k].e, 'num']);
      k += 1;
    }
    if (ws[k] && isInt(ws[k].w)) {
      take(ws[k], 'elapsed-time', 'num', 'dur');
      k += 1;
    }
    let ur = -1;
    for (let c = k; c < Math.min(k + 3, ws.length); c++) {
      if (USERROLE.test(ws[c].w) && !COUNT.test(ws[c].w)) {
        ur = c;
        break;
      }
    }
    if (ur >= 0) {
      if (ur - k >= 1) take(ws[k], 'application', 'val', 'app');
      if (ur - k >= 2) take(ws[k + 1], 'nested-application', 'val', 'nested');
      user(ws[ur]);
      k = ur + 1;
    }
    if (ws[k] && IFACE_FULL.test(ws[k].w)) {
      take(ws[k], 'packet-incoming-interface', 'iface', 'iface');
      k += 1;
    }
    if (ur >= 0 && ws[k] && ENCRYPTED.test(ws[k].w)) setF(f, 'encrypted', ws[k].w);
    return;
  }
  // create / update
  if (ws[k] && USERROLE.test(ws[k].w)) {
    user(ws[k]);
    k += 1;
  }
  if (ws[k] && IFACE_FULL.test(ws[k].w)) {
    take(ws[k], 'packet-incoming-interface', 'iface', 'iface');
    k += 1;
    if (ws[k]) take(ws[k], 'application', 'val', 'app');
    if (ws[k + 1]) take(ws[k + 1], 'nested-application', 'val', 'nested');
    if (ws[k + 2] && ENCRYPTED.test(ws[k + 2].w)) setF(f, 'encrypted', ws[k + 2].w);
  }
}

/** Abbreviated bodies ("<tuple> [<service>] <policy> <from> <to>") as some buffer views print them. */
function shortForm(ws, i, f, spans) {
  let rest = ws.slice(i);
  if (rest.length === 4) {
    setF(f, 'service-name', rest[0].w);
    spans.push([rest[0].s, rest[0].e, 'val', 'service', rest[0].w]);
    rest = rest.slice(1);
  }
  if (rest.length !== 3) return;
  const [policy, from, to] = rest;
  setF(f, 'policy-name', policy.w);
  setF(f, 'source-zone-name', from.w);
  setF(f, 'destination-zone-name', to.w);
  spans.push([policy.s, policy.e, 'policy', 'policy', policy.w]);
  spans.push([from.s, from.e, 'zone', 'from', from.w]);
  spans.push([to.s, to.e, 'zone', 'to', to.w]);
}

function flowEvent(tag) {
  const m = /^(?:RT_FLOW_(?:SESSION|STREAM)|APPTRACK_SESSION)_(CREATE|CLOSE|DENY|UPDATE)/.exec(tag || '');
  return m ? m[1].toLowerCase() : null;
}

// --- other message bodies --------------------------------------------------------------------------

function screenText(msg, f) {
  const m = /^(.*?) source: ([^,]+?)(?::(\d+))?, destination: ([^,]+?)(?::(\d+))?,(?: protocol-id: (\d+),)? zone name: ([^,]+), interface name: ([^,]+), action: (\S+)/.exec(msg);
  if (!m) return;
  setF(f, 'attack-name', m[1]);
  setF(f, 'source-address', m[2]);
  if (m[3]) setF(f, 'source-port', m[3]);
  setF(f, 'destination-address', m[4]);
  if (m[5]) setF(f, 'destination-port', m[5]);
  if (m[6]) setF(f, 'protocol-id', m[6]);
  setF(f, 'source-zone-name', m[7]);
  setF(f, 'interface-name', m[8]);
  setF(f, 'action', m[9]);
}

function idpText(msg, f) {
  const m = /Attack log <(.+?)\/(\d+)->(.+?)\/(\d+)> for (\S+) protocol and service (\S+) application (\S+) by rule (\S+) of rulebase (\S+) in policy ([^.\s]+)\.(.*)$/.exec(msg);
  if (!m) return;
  setF(f, 'source-address', m[1]);
  setF(f, 'source-port', m[2]);
  setF(f, 'destination-address', m[3]);
  setF(f, 'destination-port', m[4]);
  setF(f, 'protocol-name', m[5]);
  setF(f, 'service-name', m[6]);
  setF(f, 'application-name', m[7]);
  setF(f, 'rule-name', m[8]);
  setF(f, 'rulebase-name', m[9]);
  setF(f, 'policy-name', m[10]);
  const tail = m[11];
  const kv = /(?:^|[\s,])(id|action|threat-severity|name|repeat|session-id)=([^,\s]+)/g;
  let k;
  while ((k = kv.exec(tail))) setF(f, k[1] === 'name' ? 'attack-name' : k[1] === 'id' ? 'export-id' : k[1], k[2]);
  const intf = /intf:([^:\s]+):(\S+?)->([^:\s]+):([^,\s]+)/.exec(tail);
  if (intf) {
    setF(f, 'source-zone-name', intf[1]);
    setF(f, 'source-interface-name', intf[2]);
    setF(f, 'destination-zone-name', intf[3]);
    setF(f, 'destination-interface-name', intf[4]);
  }
}

function userText(msg, f, daemon) {
  const u = /\bUser '([^']*)'/.exec(msg) || /\bfor user '([^']*)'/.exec(msg);
  if (u) setF(f, 'username', u[1]);
  if (/sshd/.test(daemon || '')) {
    const a = /^(Accepted|Failed) (\S+) for (?:invalid user )?(\S+) from (\S+) port (\d+)/.exec(msg);
    if (a) {
      setF(f, 'username', a[3]);
      setF(f, 'source-address', a[4]);
      setF(f, 'source-port', a[5]);
      setF(f, 'auth-method', a[2]);
      setF(f, 'result', a[1].toLowerCase());
    }
  }
  const host = /from host '([^']+)'/.exec(msg);
  if (host) setF(f, 'source-address', host[1]);
}

// --- analysis ----------------------------------------------------------------------------------------

function analyze(line, now) {
  const fields = {};
  const spans = [];
  const r = {
    format: 'unknown', ts: null, time: null, host: null, daemon: null, pid: null, tag: null,
    family: 'other', severity: null, severitySource: null, facility: null, fields, message: line,
    line, sdid: null, flow: null,
  };
  const state = { spans, fields, sdid: null };
  let msgStart = 0;
  let m;
  const I = (g) => (m.indices[g] ? m.indices[g] : null);
  const span = (g, type, k, q) => {
    const ix = I(g);
    if (ix && ix[1] > ix[0]) spans.push([ix[0], ix[1], type, k, q]);
  };

  if ((m = R_BUFFER.exec(line))) {
    r.format = 'buffer';
    r.ts = m[1] === '-' ? null : m[1];
    r.time = r.ts ? bufferTime(r.ts) : null;
    r.daemon = m[2];
    r.pid = m[4] || null;
    r.tag = m[5] === '-' ? null : m[5];
    if (r.ts) span(1, 'ts');
    span(2, 'daemon', 'daemon', m[2]);
    span(3, 'pid');
    if (r.tag) span(5, 'tag', 'tag', r.tag);
    msgStart = m[0].length;
  } else if ((m = R_5424.exec(line))) {
    r.format = 'rfc5424';
    if (m[2]) {
      const pri = Number(m[2]);
      r.severity = pri & 7;
      r.facility = pri >> 3;
      r.severitySource = 'pri';
      span(1, 'pri');
    }
    r.ts = m[4];
    r.time = isoTime(m[4]);
    span(4, 'ts');
    r.host = m[5] === '-' ? null : m[5];
    if (r.host) span(5, 'host', 'host', r.host);
    r.daemon = m[6] === '-' ? null : m[6];
    if (r.daemon) span(6, 'daemon', 'daemon', r.daemon);
    r.pid = m[7] === '-' ? null : m[7];
    if (r.pid) span(7, 'pid');
    r.tag = m[8] === '-' ? null : m[8];
    if (r.tag) span(8, 'tag', 'tag', r.tag);
    let p = m[0].length;
    if (line[p] === ' ') p += 1;
    if (line[p] === '[') {
      p = readStructured(line, p, state, false);
      if (line[p] === ' ') p += 1;
    } else if (line.startsWith('- ', p) || (line[p] === '-' && p === line.length - 1)) {
      p += line[p + 1] === ' ' ? 2 : 1;
    } else if (/^[A-Za-z][\w.-]*="/.test(line.slice(p, p + 80))) {
      p = readStructured(line, p, state, true);
    }
    msgStart = p;
    r.sdid = state.sdid;
  } else if ((m = R_BSD.exec(line))) {
    r.format = 'bsd';
    r.ts = m[1];
    r.time = bsdTime(m, now);
    span(1, 'ts');
    r.host = m[10];
    span(10, 'host', 'host', m[10]);
    r.daemon = m[11];
    span(11, 'daemon', 'daemon', m[11]);
    r.pid = m[13] || null;
    span(12, 'pid');
    if (m[14]) {
      r.facility = m[15];
      r.severity = Number(m[16]);
      r.severitySource = 'explicit';
      r.tag = m[17] || null;
      const pi = I(14);
      const ti = I(17);
      spans.push([pi[0], ti ? ti[0] : pi[1], 'pri']);
      if (ti) spans.push([ti[0], ti[1], 'tag', 'tag', m[17]]);
    } else if (m[18]) {
      r.tag = m[18];
      span(18, 'tag', 'tag', m[18]);
    }
    msgStart = m[0].length;
  } else if ((m = R_BSD_HOST.exec(line))) {
    r.format = 'bsd';
    r.ts = m[1];
    r.time = bsdTime(m, now);
    span(1, 'ts');
    r.host = m[10];
    span(10, 'host', 'host', m[10]);
    msgStart = m[0].length;
  }

  r.message = line.slice(msgStart);
  if (r.severity === null) {
    const s = tagSeverity(r.tag);
    if (s !== null) {
      r.severity = s;
      r.severitySource = 'catalog';
    }
  }
  r.family = family(r.tag, r.daemon);

  // Message bodies the UI explains (fields fill in only what structured data did not provide).
  const ev = flowEvent(r.tag);
  if (ev) flowBody(ev, r.message, msgStart, fields, spans);
  else if (/^RT_SCREEN/.test(r.tag || '')) screenText(r.message, fields);
  else if (/^IDP_ATTACK/.test(r.tag || '')) idpText(r.message, fields);
  userText(r.message, fields, r.daemon);

  if (fields['session-id-32'] !== undefined && fields['session-id'] === undefined) fields['session-id'] = fields['session-id-32'];
  if (ev) r.flow = flowSummary(ev, r.tag, fields);
  return { r, spans, msgStart };
}

function flowSummary(event, tag, f) {
  const src = hostOf(f['source-address']);
  const dst = hostOf(f['destination-address']);
  const natSrc = hostOf(f['nat-source-address']);
  const natDst = hostOf(f['nat-destination-address']);
  const sport = toInt(f['source-port']);
  const dport = toInt(f['destination-port']);
  const natSport = toInt(f['nat-source-port']);
  const natDport = toInt(f['nat-destination-port']);
  const sid = toInt(f['session-id']);
  const pid = f['protocol-id'];
  return {
    event,
    stream: /STREAM/.test(tag),
    sessionId: sid,
    src, sport, dst, dport,
    protocol: protoName(pid),
    protocolId: isInt(String(pid ?? '')) ? Number(pid) : null,
    service: isPlaceholder(f['service-name']) ? null : f['service-name'],
    policy: isPlaceholder(f['policy-name']) ? null : f['policy-name'],
    from: isPlaceholder(f['source-zone-name']) ? null : f['source-zone-name'],
    to: isPlaceholder(f['destination-zone-name']) ? null : f['destination-zone-name'],
    app: isPlaceholder(f.application) ? null : f.application,
    nested: isPlaceholder(f['nested-application']) ? null : f['nested-application'],
    user: isPlaceholder(f.username) ? null : f.username,
    iface: isPlaceholder(f['packet-incoming-interface']) ? null : f['packet-incoming-interface'],
    reason: f.reason === undefined ? null : f.reason,
    natSrc, natSport, natDst, natDport,
    snat: Boolean(natSrc && src && (natSrc !== src || (natSport !== null && sport !== null && natSport !== sport))),
    dnat: Boolean(natDst && dst && (natDst !== dst || (natDport !== null && dport !== null && natDport !== dport))),
    snatRule: isPlaceholder(f['src-nat-rule-name']) ? null : f['src-nat-rule-name'],
    dnatRule: isPlaceholder(f['dst-nat-rule-name']) ? null : f['dst-nat-rule-name'],
    packetsClient: toInt(f['packets-from-client']),
    bytesClient: toInt(f['bytes-from-client']),
    packetsServer: toInt(f['packets-from-server']),
    bytesServer: toInt(f['bytes-from-server']),
    elapsed: toInt(f['elapsed-time']),
    lsys: f['logical-system-name'] || null,
  };
}

const PARSE_CACHE = new Map();
const TOKEN_CACHE = new Map();
const CACHE_MAX = 6000;

function remember(cache, key, value) {
  if (cache.size >= CACHE_MAX) cache.clear();
  cache.set(key, value);
  return value;
}

/**
 * Parses one log line. Results without `opts` are memoised: treat them as read-only.
 * `opts.now` (ms) anchors the year of BSD timestamps, which carry none. Timestamps without a zone
 * are read as UTC (the device's local zone is not known to the browser).
 */
export function parse(line, opts) {
  const s = String(line ?? '');
  if (!opts) {
    const hit = PARSE_CACHE.get(s);
    if (hit) return hit;
  }
  let r;
  try {
    r = analyze(s, opts && Number.isFinite(opts.now) ? opts.now : Date.now()).r;
  } catch (_err) {
    r = {
      format: 'unknown', ts: null, time: null, host: null, daemon: null, pid: null, tag: null, family: 'other',
      severity: null, severitySource: null, facility: null, fields: {}, message: s, line: s, sdid: null, flow: null,
    };
  }
  return opts ? r : remember(PARSE_CACHE, s, r);
}

// --- tokenizer -------------------------------------------------------------------------------------

const BAD_WORDS = /^(?:denied|deny|drop|dropped|dropping|discard|discarded|failed|failure|fail|fails|error|errors|down|invalid|reject|rejected|blocked|block|unauthorized|attack|flood|spoofing|abnormal|mismatch|expired|lost|dead|refused|violation|alarm|unreachable|timeout|timed|aborted|panic|critical)$/i;
const GOOD_WORDS = /^(?:up|established|accepted|accept|complete|completed|success|successful|succeeded|permit|permitted|allowed|allow|online|loaded|recovered|restored|ok|cleared|operational)$/i;
const PROTO_WORDS = /^(?:tcp|udp|icmp|icmp6|icmpv6|gre|esp|ah|sctp|ospf|pim|igmp)$/i;

const RX_WS = /\s+/y;
const RX_ARROW = /-->|->|=>|<-|\u2192/y;
const RX_V4 = /(?<![\d.])(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}(?![\d])/y;
const RX_V6 = /(?<![\w:.])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:(?<=:)(?:\d{1,3}\.){3}\d{1,3})?(?![\w:])/y;
const RX_PORT = /[/:]\d{1,5}(?!\d)/y;
const V4_FULL = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const RX_IFACE = /(?<![\w-])(?:(?:ge|xe|et|fe|ae|reth|st|lo|fxp|em|me|irb|vlan|fab|swfab|gr|lt|ip|pp|ppp|at|so|t1|e1|ms|sp|wlan|cl|dl|mt|vtep)-?\d+(?:\/\d+){0,3}(?:\.\d+)?|(?:irb|vlan)\.\d+)(?![\w/])/y;
const RX_QUOTE = /'[^'\n]*'|"[^"\n]*"/y;
const RX_HEX = /0x[0-9A-Fa-f]+(?![\w])/y;
const RX_KEYEQ = /[A-Za-z][\w.-]*(?==[^\s=])/y;
const RX_WORD = /[A-Za-z_](?:[\w.@]|-(?!-?>))*/y;
const RX_NUM = /\d+(?:\.\d+)?[A-Za-z%]*/y;

function sticky(re, s, p, end) {
  re.lastIndex = p;
  const m = re.exec(s);
  if (!m || m.index !== p || !m[0]) return 0;
  return Math.min(m[0].length, end - p);
}

function validV6(s) {
  if (!s.includes(':')) return false;
  const dbl = s.split('::');
  if (dbl.length > 2) return false;
  const v4 = /(?:\d{1,3}\.){3}\d{1,3}$/.test(s);
  const groups = (part) => (part ? part.split(':') : []);
  const head = groups(dbl[0]);
  const tail = dbl.length === 2 ? groups(dbl[1]) : [];
  const all = [...head, ...tail];
  if (v4) all.pop();
  if (!all.every((g) => /^[0-9A-Fa-f]{1,4}$/.test(g))) return false;
  const count = all.length + (v4 ? 2 : 0);
  return dbl.length === 2 ? count < 8 : count === 8;
}

/** Field types for structured-data and key=value values: returns [tokenType, filterKey]. */
function valueType(key, value) {
  const kl = key.toLowerCase().trim();
  if (isPlaceholder(value)) return ['val', null];
  if (/^nat-(source|destination)-address$/.test(kl)) return ['nat', kl.includes('source') ? 'natsrc' : 'natdst'];
  if (/^nat-.*port$/.test(kl)) return ['nat', null];
  if (/(^|-)address$/.test(kl) || kl === 'ip' || kl === 'src' || kl === 'dst') {
    return ['ip', kl.startsWith('source') ? 'src' : kl.startsWith('destination') ? 'dst' : 'ip'];
  }
  if (/(^|-)port$/.test(kl)) return ['port', kl.startsWith('source') ? 'sport' : kl.startsWith('destination') ? 'dport' : null];
  if (kl === 'protocol-id' || kl === 'protocol' || kl === 'protocol-name') return ['proto', 'proto'];
  if (kl === 'policy-name' || kl === 'policy') return ['policy', 'policy'];
  if (/zone(-name)?$/.test(kl)) return ['zone', kl.startsWith('source') ? 'from' : kl.startsWith('destination') ? 'to' : 'zone'];
  if (/interface(-name)?$/.test(kl) || kl === 'ifname') return ['iface', 'iface'];
  if (kl === 'username' || kl === 'user') return ['user', 'user'];
  if (kl === 'session-id' || kl === 'session-id-32' || kl === 'session_id') return ['num', 'session'];
  if (kl === 'reason' || kl === 'action') {
    const last = String(value).split(/\s+/).pop();
    const c = wordClass(last);
    return [c === 'val' && /deny|drop|block/i.test(value) ? 'bad' : c, kl === 'reason' ? 'reason' : null];
  }
  if (kl === 'application') return ['val', 'app'];
  if (kl === 'service-name') return ['val', 'service'];
  if (kl === 'nested-application') return ['val', 'nested'];
  if (kl === 'logical-system-name') return ['val', 'lsys'];
  if (/^-?\d+(\.\d+)?$/.test(String(value))) return ['num', null];
  return ['val', null];
}

class Emitter {
  constructor(line, hints, r) {
    this.line = line;
    this.pos = 0;
    this.toks = [];
    this.hints = hints;
    this.authLine = r.family === 'auth';
  }

  push(t, len, k, q) {
    if (len <= 0) return;
    const v = this.line.slice(this.pos, this.pos + len);
    this.pos += len;
    const last = this.toks[this.toks.length - 1];
    if (t === 'text' && last && last.t === 'text') {
      last.v += v;
      return;
    }
    const tok = { t, v };
    if (k) tok.k = k;
    if (q !== undefined && q !== null && q !== v) tok.q = q;
    this.toks.push(tok);
  }

  typed(sp) {
    const [s, e, t, k, q] = sp;
    if (s < this.pos || e <= s) return;
    if (t === 'value') {
      const [vt, vk] = valueType(k, q);
      this.push(vt, e - s, vk, q);
    } else {
      this.push(t, e - s, k, q);
    }
  }

  before(n) {
    return this.line.slice(Math.max(0, this.pos - n), this.pos);
  }

  word(len) {
    const w = this.line.slice(this.pos, this.pos + len);
    const h = this.hints;
    if (h && h.zones && h.zones.has(w)) return this.push('zone', len, 'zone');
    if (h && h.policies && h.policies.has(w)) return this.push('policy', len, 'policy');
    const b = this.before(24);
    if (/(?:\bzone(?: name)?[:=]|\b(?:from|to|source|destination)-zone[:=]?)\s*$/i.test(b)) return this.push('zone', len, 'zone');
    if (/\bpolicy[:=]?\s+$/i.test(b)) return this.push('policy', len, 'policy');
    if (h && h.ifaces && h.ifaces.has(w)) return this.push('iface', len, 'iface');
    if (PROTO_WORDS.test(w)) return this.push('proto', len, 'proto', w.toLowerCase());
    if (BAD_WORDS.test(w)) return this.push('bad', len);
    if (GOOD_WORDS.test(w)) return this.push('good', len);
    if (this.authLine && /\b(?:for|user)\s+$/.test(b) && !/^(?:user|invalid|host)$/.test(w)) return this.push('user', len, 'user');
    return this.push('text', len);
  }

  ip(len, v6) {
    const ip = this.line.slice(this.pos, this.pos + len);
    if (v6 && !validV6(ip)) return false;
    this.push('ip', len, 'ip');
    const end = this.line.length;
    const pl = sticky(RX_PORT, this.line, this.pos, end);
    if (pl && !(v6 && this.line[this.pos] === ':')) this.push('port', pl, null, this.line.slice(this.pos + 1, this.pos + pl));
    return true;
  }

  quoted(len) {
    const s = this.line;
    const inner = s.slice(this.pos + 1, this.pos + len - 1);
    const b = this.before(12);
    const isUser = /\b(?:User|user)\s+$/.test(b);
    const isIp = V4_FULL.test(inner);
    if (isUser || isIp || validV6(inner)) {
      this.push('text', 1);
      this.push(isUser ? 'user' : 'ip', inner.length, isUser ? 'user' : 'ip');
      this.push('text', 1);
      return;
    }
    this.push('str', len);
  }

  generic(end) {
    const s = this.line;
    while (this.pos < end) {
      const p = this.pos;
      let len;
      if ((len = sticky(RX_WS, s, p, end))) { this.push('text', len); continue; }
      if ((len = sticky(RX_ARROW, s, p, end))) { this.push('arrow', len); continue; }
      if ((len = sticky(RX_V4, s, p, end))) { this.ip(len, false); continue; }
      if ((len = sticky(RX_V6, s, p, end)) && this.ip(len, true)) continue;
      if ((len = sticky(RX_IFACE, s, p, end))) { this.push('iface', len, 'iface'); continue; }
      if ((len = sticky(RX_QUOTE, s, p, end))) { this.quoted(len); continue; }
      if ((len = sticky(RX_HEX, s, p, end))) { this.push('num', len); continue; }
      if ((len = sticky(RX_KEYEQ, s, p, end))) {
        const key = s.slice(p, p + len);
        this.push('key', len);
        this.push('text', 1); // "="
        const q = s[this.pos] === '"' || s[this.pos] === "'" ? s[this.pos] : null;
        if (q) {
          const close = s.indexOf(q, this.pos + 1);
          if (close > 0 && close < end) {
            this.push('text', 1);
            const value = s.slice(this.pos, close);
            const [vt, vk] = valueType(key, value);
            this.push(vt, value.length, vk);
            this.push('text', 1);
          }
          continue;
        }
        const vm = /[^\s,;)\]>]+/y;
        const vl = sticky(vm, s, this.pos, end);
        if (vl) {
          const value = s.slice(this.pos, this.pos + vl);
          const [vt, vk] = valueType(key, value);
          if (vt === 'ip' || vt === 'nat') {
            // key=ip:port style values
            const l4 = sticky(RX_V4, s, this.pos, end);
            if (l4 && l4 < vl) {
              this.push(vt, l4, vk);
              this.push('port', vl - l4);
              continue;
            }
          }
          this.push(vt, vl, vk);
        }
        continue;
      }
      if ((len = sticky(RX_WORD, s, p, end))) { this.word(len); continue; }
      if ((len = sticky(RX_NUM, s, p, end))) { this.push('num', len); continue; }
      this.push('text', 1);
    }
  }
}

function toSet(x) {
  if (!x) return null;
  if (x instanceof Set) return x;
  if (Array.isArray(x)) return new Set(x);
  return null;
}

/** Statistics for tests: how many lines needed the lossless fallback (should stay 0). */
export const _stats = { fallbacks: 0 };

/**
 * Tokens for one line, `[{t, v, k?, q?}]`: `t` is the highlight type (tk-<t>), `v` the exact text,
 * `k` the query key a click should filter on, `q` the filter value when it differs from `v`.
 * `hints` ({zones, policies, ifaces} as Sets or arrays) mark known names inside free text.
 */
export function tokenize(line, hints) {
  const s = String(line ?? '');
  const h = hints ? { zones: toSet(hints.zones), policies: toSet(hints.policies), ifaces: toSet(hints.ifaces) } : null;
  if (!h) {
    const hit = TOKEN_CACHE.get(s);
    if (hit) return hit;
  }
  let toks;
  try {
    const { r, spans } = analyze(s, Date.now());
    const em = new Emitter(s, h, r);
    spans.sort((a, b) => a[0] - b[0] || b[1] - a[1]);
    for (const sp of spans) {
      if (sp[0] < em.pos) continue;
      em.generic(sp[0]);
      em.typed(sp);
    }
    em.generic(s.length);
    toks = em.toks;
    let joined = '';
    for (const t of toks) joined += t.v;
    if (joined !== s) throw new Error('lossy');
  } catch (_err) {
    _stats.fallbacks += 1;
    toks = s ? [{ t: 'text', v: s }] : [];
  }
  return h ? toks : remember(TOKEN_CACHE, s, toks);
}

// --- decode ----------------------------------------------------------------------------------------

function fmtBytes(n) {
  if (!Number.isFinite(n)) return null;
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${i === 0 ? v : v >= 100 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}

function fmtDuration(s) {
  if (!Number.isFinite(s)) return null;
  if (s < 60) return `${s} s`;
  if (s < 3600) return `${Math.floor(s / 60)} min ${s % 60} s`;
  const h = Math.floor(s / 3600);
  return `${h} h ${Math.floor((s % 3600) / 60)} min`;
}

function hostPort(ip, port) {
  if (!ip) return '?';
  const a = ip.includes(':') ? `[${ip}]` : ip;
  return port === null || port === undefined ? a : `${a}:${port}`;
}

function tupleText(fl) {
  const proto = fl.protocol ? `${fl.protocol.toUpperCase()} ` : '';
  const svc = fl.service ? ` (${fl.service})` : '';
  return `${proto}${hostPort(fl.src, fl.sport)} \u2192 ${hostPort(fl.dst, fl.dport)}${svc}`;
}

function natText(fl) {
  const out = [];
  if (fl.snat) {
    out.push(`SNAT ${hostPort(fl.src, fl.sport)} \u2192 ${hostPort(fl.natSrc, fl.natSport)}${fl.snatRule ? ` (rule ${fl.snatRule})` : ''}`);
  }
  if (fl.dnat) {
    out.push(`DNAT ${hostPort(fl.dst, fl.dport)} \u2192 ${hostPort(fl.natDst, fl.natDport)}${fl.dnatRule ? ` (rule ${fl.dnatRule})` : ''}`);
  }
  return out;
}

function zonesText(fl, via) {
  if (!fl.from && !fl.to) return fl.policy ? `${via} ${fl.policy}` : null;
  const z = `${fl.from || '?'} \u2192 ${fl.to || '?'}`;
  return fl.policy ? `${z} ${via} ${fl.policy}` : z;
}

function decodeFlow(fl) {
  const what = fl.stream ? 'Stream' : 'Session';
  const id = fl.sessionId ? ` ${fl.sessionId}` : '';
  const parts = [];
  if (fl.event === 'close') {
    const dur = fmtDuration(fl.elapsed);
    parts.push(`${what}${id} closed${fl.reason ? ` (${fl.reason})` : ''}${dur ? ` after ${dur}` : ''}`);
    parts.push(tupleText(fl));
    const total = (fl.bytesClient || 0) + (fl.bytesServer || 0);
    if (fl.bytesClient !== null || fl.bytesServer !== null) {
      parts.push(`${fmtBytes(total)} (\u2191 ${fmtBytes(fl.bytesClient || 0)} \u2193 ${fmtBytes(fl.bytesServer || 0)})`);
    }
    const z = zonesText(fl, 'via');
    if (z) parts.push(z);
  } else if (fl.event === 'deny') {
    parts.push(`${what}${fl.sessionId ? id : ''} denied${fl.policy ? ` by ${fl.policy}` : ''}`);
    parts.push(tupleText(fl));
    if (fl.from || fl.to) parts.push(`${fl.from || '?'} \u2192 ${fl.to || '?'}`);
    if (fl.reason) parts.push(fl.reason);
  } else {
    parts.push(`${what}${id} ${fl.event === 'update' ? 'updated' : 'created'}`);
    parts.push(tupleText(fl));
    const z = zonesText(fl, 'via');
    if (z) parts.push(z);
  }
  parts.push(...natText(fl));
  if (fl.app) parts.push(`app ${fl.app}${fl.nested ? `/${fl.nested}` : ''}`);
  if (fl.user) parts.push(`user ${fl.user}`);
  if (fl.lsys) parts.push(`logical system ${fl.lsys}`);
  return parts.join(' \u00b7 ');
}

/** A one-line human sentence for RT_FLOW, screen, IDP, commit, login and a few common events; else null. */
export function decode(parsed) {
  if (!parsed) return null;
  const p = typeof parsed === 'string' ? parse(parsed) : parsed;
  const f = p.fields || {};
  const tag = p.tag || '';
  if (p.flow) return decodeFlow(p.flow);
  if (/^RT_SCREEN/.test(tag)) {
    const attack = f['attack-name'];
    if (!attack) return null;
    const src = hostPort(hostOf(f['source-address']), toInt(f['source-port']));
    const dst = hostPort(hostOf(f['destination-address']), toInt(f['destination-port']));
    const parts = [`Screen: ${attack}${f.action ? ` (${f.action})` : ''}`, `${src} \u2192 ${dst}`];
    if (f['source-zone-name']) parts.push(`zone ${f['source-zone-name']}`);
    if (f['interface-name']) parts.push(f['interface-name']);
    return parts.join(' \u00b7 ');
  }
  if (/^IDP_ATTACK/.test(tag)) {
    const name = f['attack-name'] && f['attack-name'] !== '-' ? f['attack-name'] : 'attack';
    const sev = f['threat-severity'] ? ` (${f['threat-severity']})` : '';
    const parts = [`IDP ${name}${sev}${f.action ? `: ${f.action}` : ''}`];
    if (f['source-address']) {
      parts.push(`${hostPort(hostOf(f['source-address']), toInt(f['source-port']))} \u2192 ${hostPort(hostOf(f['destination-address']), toInt(f['destination-port']))}`);
    }
    if (f['source-zone-name'] || f['destination-zone-name']) parts.push(`${f['source-zone-name'] || '?'} \u2192 ${f['destination-zone-name'] || '?'}`);
    if (f['rule-name']) parts.push(`rule ${f['rule-name']}${f['rulebase-name'] ? ` of ${f['rulebase-name']}` : ''}`);
    if (f['policy-name']) parts.push(`IDP policy ${f['policy-name']}`);
    return parts.join(' \u00b7 ');
  }
  const msg = p.message || '';
  const user = f.username;
  if (/COMMIT/.test(tag)) {
    let m;
    if ((m = /requested '([^']+)' operation(?: \(comment: (.*)\))?/.exec(msg))) {
      return `${user || 'Someone'} requested ${m[1]}${m[2] && m[2] !== 'none' ? ` (comment: ${m[2]})` : ''}`;
    }
    if ((m = /performed (commit[\w -]*?)(?:: (.*))?$/.exec(msg))) {
      return `${user || 'Someone'} performed ${m[1]}${m[2] ? ` (${m[2]})` : ''}`;
    }
    if ((m = /has requested commit on '([^']+)' ephemeral database/.exec(msg))) {
      return `${user || 'Someone'} requested a commit of ephemeral database ${m[1]}`;
    }
    if (tag === 'UI_COMMIT_COMPLETED' || /commit complete/i.test(msg)) return 'Commit completed';
    if (tag === 'UI_COMMIT_NOT_CONFIRMED') return `Commit was not confirmed: ${msg.replace(/^Commit was not confirmed;\s*/, '')}`;
    if (tag === 'UI_COMMIT_PROGRESS') return `Commit in progress: ${msg.replace(/^Commit operation in progress:\s*/, '')}`;
    return `Commit: ${msg}`;
  }
  if (tag === 'UI_LOGIN_EVENT') {
    const cls = /class '([^']*)'/.exec(msg);
    const conn = /ssh-connection '(\S+)/.exec(msg);
    const mode = /client-mode '([^']*)'/.exec(msg);
    return `${user || 'Someone'} signed in${cls ? ` (class ${cls[1]})` : ''}${conn ? ` from ${conn[1]}` : ''}${mode ? ` using ${mode[1]}` : ''}`;
  }
  if (tag === 'UI_LOGOUT_EVENT') return `${user || 'Someone'} signed out`;
  if (tag === 'UI_AUTH_EVENT') {
    const lvl = /permission level '([^']*)'/.exec(msg);
    return `${/Authenticated user '([^']*)'/.exec(msg)?.[1] || user || 'Someone'} authenticated${lvl ? ` at permission level ${lvl[1]}` : ''}`;
  }
  if (/^UI_AUTH_INVALID/.test(tag)) return `Authentication failed for ${user || /user '([^']*)'/.exec(msg)?.[1] || 'a user'}`;
  if (tag === 'UI_DBASE_LOGIN_EVENT') return `${user || 'Someone'} entered configuration mode`;
  if (tag === 'UI_DBASE_LOGOUT_EVENT') return `${user || 'Someone'} left configuration mode`;
  if (tag === 'UI_CMDLINE_READ_LINE') {
    const c = /command '(.*)'$/.exec(msg);
    return `${user || 'Someone'} ran: ${c ? c[1].trim() : msg}`;
  }
  if (tag === 'UI_NETCONF_CMD') {
    const c = /command '(.*)'$/.exec(msg);
    return `${user || 'Someone'} ran over NETCONF: ${c ? c[1].trim() : msg}`;
  }
  if (/^(SSHD_LOGIN_FAILED|LOGIN_FAILED)/.test(tag)) {
    return `Sign-in failed for ${user || /user '?([^' ]+)/.exec(msg)?.[1] || 'a user'}${f['source-address'] ? ` from ${f['source-address']}` : ''}`;
  }
  if (/sshd/.test(p.daemon || '') && f.result) {
    const ok = f.result === 'accepted';
    return `${ok ? 'Signed in' : 'Sign-in failed'}: ${f.username} (${f['auth-method']}) from ${hostPort(f['source-address'], toInt(f['source-port']))} over SSH`;
  }
  if (/^(KMD|IKE)_VPN_(UP|DOWN)_ALARM_USER/.test(tag)) {
    const m = /VPN (\S+) from (\S+) is (up|down)/.exec(msg);
    if (m) return `VPN ${m[1]} is ${m[3]} (peer ${m[2]})`;
  }
  if (/^SNMP_TRAP_LINK_(UP|DOWN)/.test(tag)) {
    const m = /ifName (\S+)/.exec(msg);
    if (m) return `Interface ${m[1]} link ${tag.endsWith('UP') ? 'up' : 'down'}`;
  }
  return null;
}

/** True for the UI_NETCONF_CMD lines that record `user`'s own reads (J-Wicket polling noise). */
export function isSelfRead(parsed, user) {
  if (!parsed || !user) return false;
  const p = typeof parsed === 'string' ? parse(parsed) : parsed;
  if (p.tag !== 'UI_NETCONF_CMD') return false;
  const who = (p.fields && p.fields.username) || (/User '([^']*)' used NETCONF client/.exec(p.message || '') || [])[1];
  return who === user;
}
