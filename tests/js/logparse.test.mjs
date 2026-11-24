// Unit tests for src/jwicket/static/js/logparse.js. Run: node --test tests/js/
// Corpus: tests/fixtures/log-samples/juniper-docs.txt (verbatim Juniper documentation lines) and
// devserver-sample.txt (synthetic lines from the development server's fixture; see the README there).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as lp from '../../src/jwicket/static/js/logparse.js';

const read = (name) => readFileSync(new URL(`../fixtures/log-samples/${name}`, import.meta.url), 'utf8').split('\n').filter((l) => l.length > 0);
const DOCS = read('juniper-docs.txt');
const DEV = read('devserver-sample.txt');
const NOW = Date.parse('2026-11-24T08:00:00Z');

const joined = (toks) => toks.map((t) => t.v).join('');
const host = (a) => (a === undefined || a === null ? null : String(a).split('/')[0]);
const int = (v) => (v === undefined || v === null || !/^\d+$/.test(String(v)) ? null : Number(v));
const hp = (ip, port) => `${ip.includes(':') ? `[${ip}]` : ip}:${port}`;

/** Structured-data pairs extracted independently of the parser (quoted values only). */
function sdPairs(line) {
  const out = {};
  for (const m of line.matchAll(/(?:^|[\s[])([A-Za-z][\w-]*)="([^"]*)"/g)) if (!(m[1] in out)) out[m[1]] = m[2];
  return out;
}

function expectedFromSD(line) {
  const f = sdPairs(line);
  const src = host(f['source-address']);
  const dst = host(f['destination-address']);
  const nsrc = host(f['nat-source-address']);
  const ndst = host(f['nat-destination-address']);
  const real = (v) => v && !/^(N\/A|None|UNKNOWN)$/.test(v);
  return {
    sessionId: int(f['session-id'] ?? f['session-id-32']),
    src, sport: int(f['source-port']), dst, dport: int(f['destination-port']),
    policy: real(f['policy-name']) ? f['policy-name'] : null,
    from: real(f['source-zone-name']) ? f['source-zone-name'] : null,
    to: real(f['destination-zone-name']) ? f['destination-zone-name'] : null,
    snat: Boolean(nsrc && real(nsrc) && (nsrc !== src || f['nat-source-port'] !== f['source-port'])),
    dnat: Boolean(ndst && real(ndst) && (ndst !== dst || f['nat-destination-port'] !== f['destination-port'])),
    natSrc: nsrc, natSport: int(f['nat-source-port']), natDst: ndst, natDport: int(f['nat-destination-port']),
  };
}

function checkFlow(line, exp) {
  const p = lp.parse(line, { now: NOW });
  assert.ok(p.flow, `no flow decoded: ${line}`);
  const fl = p.flow;
  for (const k of ['sessionId', 'src', 'sport', 'dst', 'dport', 'policy', 'from', 'to', 'snat', 'dnat']) {
    if (exp[k] !== undefined) assert.deepEqual(fl[k], exp[k], `${k} in ${line}`);
  }
  const s = lp.decode(p);
  assert.equal(typeof s, 'string', line);
  if (exp.sessionId) assert.ok(s.includes(` ${exp.sessionId} `) || s.includes(` ${exp.sessionId}`), `session id in "${s}"`);
  assert.ok(s.includes(`${hp(exp.src, exp.sport)} → ${hp(exp.dst, exp.dport)}`), `5-tuple in "${s}"`);
  if (exp.policy) assert.ok(s.includes(exp.policy), `policy in "${s}"`);
  if (exp.from && exp.to) assert.ok(s.includes(`${exp.from} → ${exp.to}`), `zones in "${s}"`);
  if (exp.snat) assert.ok(s.includes(`SNAT ${hp(exp.src, exp.sport)} → ${hp(exp.natSrc, exp.natSport)}`), `SNAT in "${s}"`);
  else assert.ok(!s.includes('SNAT'), `no SNAT in "${s}"`);
  if (exp.dnat) assert.ok(s.includes(`DNAT ${hp(exp.dst, exp.dport)} → ${hp(exp.natDst, exp.natDport)}`), `DNAT in "${s}"`);
  else assert.ok(!s.includes('DNAT'), `no DNAT in "${s}"`);
  return p;
}

// --- lossless tokenisation ----------------------------------------------------------------------------

test('every corpus line tokenises back to exactly itself', () => {
  const before = lp._stats.fallbacks;
  assert.equal(DOCS.length, 46);
  assert.equal(DEV.length, 300);
  for (const line of [...DOCS, ...DEV]) {
    const toks = lp.tokenize(line);
    assert.equal(joined(toks), line);
    assert.ok(toks.every((t) => typeof t.t === 'string' && t.v.length > 0), line);
    assert.ok(toks.length > 1, `highlighted, not one text token: ${line}`);
  }
  assert.equal(lp._stats.fallbacks, before, 'no line needed the plain-text fallback');
});

test('tokenisation stays lossless on every prefix of every corpus line, and with hints', () => {
  const before = lp._stats.fallbacks;
  const hints = { zones: ['trust', 'untrust', 'dmz'], policies: ['allow-web'], ifaces: new Set(['st0.0']) };
  for (const line of [...DOCS, ...DEV.slice(0, 60)]) {
    for (let n = 0; n <= line.length; n += 7) {
      const cut = line.slice(0, n);
      assert.equal(joined(lp.tokenize(cut)), cut);
    }
    assert.equal(joined(lp.tokenize(line, hints)), line);
  }
  for (const odd of ['', ' ', '   x', 'été → café', '[[[', '"', 'a="', '<14>1', '<14>1 2026-11-24T00:00:00Z h a - T [', 'Nov 24 07:00:00 h p[: x', '::: :: :']) {
    assert.equal(joined(lp.tokenize(odd)), odd, JSON.stringify(odd));
  }
  assert.equal(lp._stats.fallbacks, before);
});

test('token types: header, structured data, flow roles, NAT and click-to-filter keys', () => {
  const line = DEV.find((l) => l.includes('RT_FLOW_SESSION_CLOSE') && l.includes('src-nat-rule-type="source rule"'));
  const toks = lp.tokenize(line);
  const of = (t) => toks.filter((x) => x.t === t);
  assert.deepEqual(of('pri').map((x) => x.v), ['<14>1']);
  assert.equal(of('ts').length, 1);
  assert.deepEqual(of('host').map((x) => x.v), ['branch-fw-01']);
  assert.deepEqual(of('daemon').map((x) => x.v), ['RT_FLOW']);
  assert.deepEqual(of('tag').map((x) => [x.v, x.k]), [['RT_FLOW_SESSION_CLOSE', 'tag']]);
  assert.deepEqual(of('sdid').map((x) => x.v), ['junos@2636.1.1.1.2.129']);
  assert.ok(of('key').some((x) => x.v === 'source-address'));
  const p = lp.parse(line);
  assert.ok(of('policy').some((x) => x.v === p.fields['policy-name'] && x.k === 'policy'));
  assert.ok(of('zone').some((x) => x.k === 'from' && x.v === p.fields['source-zone-name']));
  assert.ok(of('zone').some((x) => x.k === 'to' && x.v === p.fields['destination-zone-name']));
  assert.ok(of('nat').some((x) => x.k === 'natsrc' && x.v === p.fields['nat-source-address']));
  assert.ok(of('ip').some((x) => x.k === 'src' && x.v === p.fields['source-address']));
  assert.ok(of('port').some((x) => x.k === 'dport'));
  assert.ok(of('iface').some((x) => x.v === 'ge-0/0/1.0'));
  assert.ok(of('num').some((x) => x.k === 'session' && x.v === p.fields['session-id']));
  // The text body after "]" is highlighted too: tuple, arrow, reason.
  assert.ok(of('arrow').length >= 1);

  const bsd = lp.tokenize('Nov 24 07:45:19 branch-fw-01 RT_FLOW: RT_FLOW_SESSION_DENY: session denied 198.51.100.66/10239->203.0.113.2/22 0x0 junos-telnet 6(0) deny-inbound untrust trust UNKNOWN UNKNOWN N/A(N/A) ge-0/0/0.0 No policy deny');
  const t = (type) => bsd.filter((x) => x.t === type).map((x) => x.v);
  assert.deepEqual(t('ip'), ['198.51.100.66', '203.0.113.2']);
  assert.deepEqual(t('port'), ['/10239', '/22']);
  assert.deepEqual(bsd.filter((x) => x.t === 'port').map((x) => x.q), ['10239', '22']);
  assert.deepEqual(t('arrow'), ['->']);
  assert.deepEqual(t('policy'), ['deny-inbound']);
  assert.deepEqual(t('zone'), ['untrust', 'trust']);
  assert.deepEqual(t('iface'), ['ge-0/0/0.0']);
  assert.ok(t('bad').includes('denied'));
  assert.ok(t('bad').includes('policy deny'));
  assert.deepEqual(t('pid'), []);

  const ui = lp.tokenize("Apr 11 10:27:25 router1 mgd[3606]: UI_DBASE_LOGIN_EVENT: User 'barbara' entering configuration mode");
  assert.deepEqual(ui.filter((x) => x.t === 'user').map((x) => x.v), ['barbara']);
  assert.deepEqual(ui.filter((x) => x.t === 'pid').map((x) => x.v), ['[3606]']);
  const ep = lp.tokenize('Aug 21 12:36:30 router1 chassisd[522]: %DAEMON-6-CHASSISD_PARSE_COMPLETE: Using new configuration');
  assert.deepEqual(ep.filter((x) => x.t === 'pri').map((x) => x.v), ['%DAEMON-6-']);
  assert.deepEqual(ep.filter((x) => x.t === 'tag').map((x) => x.v), ['CHASSISD_PARSE_COMPLETE']);
  const snmp = lp.tokenize('Apr 11 11:46:37 router1 mib2d[2905]: SNMP_TRAP_LINK_DOWN: ifIndex 82, ifAdminStatus up(1), ifOperStatus down(2), ifName at-1/0/0');
  assert.deepEqual(snmp.filter((x) => x.t === 'good').map((x) => x.v), ['up']);
  assert.deepEqual(snmp.filter((x) => x.t === 'bad').map((x) => x.v), ['down']);
  assert.deepEqual(snmp.filter((x) => x.t === 'iface').map((x) => x.v), ['at-1/0/0']);
  const scr = lp.tokenize('Nov 24 07:50:04 branch-fw-01 RT_SCREEN: RT_SCREEN_TCP: SYN flood! source: 198.51.100.7:49001, destination: 203.0.113.2:443, zone name: untrust, interface name: ge-0/0/0.0, action: drop');
  assert.deepEqual(scr.filter((x) => x.t === 'zone').map((x) => x.v), ['untrust']);
  assert.deepEqual(scr.filter((x) => x.t === 'port').map((x) => x.v), [':49001', ':443']);
  assert.ok(scr.some((x) => x.t === 'bad' && x.v === 'drop'));
  const v6 = lp.tokenize(DOCS.find((l) => l.includes('3001::2')));
  assert.ok(v6.some((x) => x.t === 'ip' && x.v === '3001::2'));
  const hinted = lp.tokenize('Nov 24 07:00:00 fw kmd[1]: KMD_X: tunnel st0.0 to dmz for allow-web', { zones: ['dmz'], policies: ['allow-web'], ifaces: ['st0.0'] });
  assert.deepEqual(hinted.filter((x) => ['zone', 'policy', 'iface'].includes(x.t)).map((x) => [x.t, x.v]), [['iface', 'st0.0'], ['zone', 'dmz'], ['policy', 'allow-web']]);
});

// --- RT_FLOW decoding over the corpora ----------------------------------------------------------------

test('every documented RT_FLOW line decodes with the right session id, 5-tuple, policy, zones and NAT', () => {
  const bsd = {
    'TCP SERVER RST': { sessionId: 250003018, src: '30.0.0.2', sport: 54584, dst: '50.0.0.2', dport: 8081, policy: 'p1', from: 'green', to: 'red', snat: false, dnat: false },
    'TCP CLIENT RST': { sessionId: 240003072, src: '30.0.0.2', sport: 46488, dst: '50.0.0.2', dport: 23, policy: 'p1', from: 'green', to: 'red', snat: false, dnat: false },
  };
  let n = 0;
  for (const line of DOCS) {
    const p = lp.parse(line);
    if (!/^RT_FLOW_/.test(p.tag || '')) continue;
    n += 1;
    if (p.format === 'bsd') {
      const key = Object.keys(bsd).find((k) => line.includes(k));
      const fl = checkFlow(line, bsd[key]).flow;
      assert.equal(fl.reason, key);
      assert.equal(fl.protocol, 'tcp');
      assert.equal(fl.iface, 'ge-11/0/0.0');
      assert.equal(fl.bytesClient + fl.bytesServer, key === 'TCP SERVER RST' ? 100 : 160);
    } else {
      checkFlow(line, expectedFromSD(line));
    }
  }
  assert.equal(n, 12);
});

test('every dev-server RT_FLOW line decodes correctly (structured data, BSD text and buffer)', () => {
  const counts = { sd: 0, bsd: 0, buffer: 0, snat: 0, dnat: 0 };
  const denyRe = /RT_FLOW_SESSION_DENY: session denied (\S+)\/(\d+)->(\S+)\/(\d+) 0x0 (\S+) (\d+)\((\d+)\) (\S+) (\S+) (\S+) (\S+) (\S+) (\S+)\((\S+)\) (\S+) (\S+) (.*)$/;
  const bufRe = /^(\S+) flowd: (RT_FLOW_SESSION_\w+): session (?:created|closed (.+?):|denied) (\S+)\/(\d+)->(\S+)\/(\d+) (\S+) (\S+) (\S+) (\S+)$/;
  for (const line of DEV) {
    const p = lp.parse(line, { now: NOW });
    if (!/^RT_FLOW_/.test(p.tag || '')) continue;
    if (p.format === 'rfc5424') {
      counts.sd += 1;
      const exp = expectedFromSD(line);
      if (exp.snat) counts.snat += 1;
      if (exp.dnat) counts.dnat += 1;
      checkFlow(line, exp);
      // The text after the structured data repeats the 5-tuple; both readings agree.
      const tail = /\] session (?:created|closed .+?:|denied) (\S+)\/(\d+)->(\S+)\/(\d+)$/.exec(line);
      assert.ok(tail, line);
      assert.deepEqual([tail[1], Number(tail[2]), tail[3], Number(tail[4])], [exp.src, exp.sport, exp.dst, exp.dport]);
      assert.equal(p.time, Date.parse(line.split(' ')[1]));
      if (p.tag === 'RT_FLOW_SESSION_CLOSE') {
        const f = sdPairs(line);
        assert.equal(p.flow.reason, f.reason);
        assert.equal(p.flow.elapsed, Number(f['elapsed-time']));
        assert.equal(p.flow.bytesServer, Number(f['bytes-from-server']));
      }
    } else if (p.format === 'bsd') {
      counts.bsd += 1;
      const m = denyRe.exec(line);
      assert.ok(m, line);
      const fl = checkFlow(line, { sessionId: null, src: m[1], sport: Number(m[2]), dst: m[3], dport: Number(m[4]), policy: m[8], from: m[9], to: m[10], snat: false, dnat: false }).flow;
      assert.equal(fl.service, m[5]);
      assert.equal(fl.protocolId, Number(m[6]));
      assert.equal(fl.iface, m[15]);
      assert.equal(fl.reason, m[17]);
      assert.equal(p.fields.encrypted, m[16]);
    } else {
      assert.equal(p.format, 'buffer', line);
      counts.buffer += 1;
      const m = bufRe.exec(line);
      assert.ok(m, line);
      const fl = checkFlow(line, { src: m[4], sport: Number(m[5]), dst: m[6], dport: Number(m[7]), policy: m[9], from: m[10], to: m[11], snat: false, dnat: false }).flow;
      assert.equal(p.tag, m[2]);
      assert.equal(fl.service, m[8]);
      if (m[3]) assert.equal(fl.reason, m[3]);
      assert.equal(p.daemon, 'flowd');
      const [d, t] = m[1].split('.');
      assert.equal(p.time, Date.parse(`${d}T${t}Z`));
    }
  }
  assert.equal(counts.sd, 140);
  assert.ok(counts.bsd >= 60, `${counts.bsd} BSD deny lines`);
  assert.equal(counts.buffer, 60);
  assert.ok(counts.snat > 20 && counts.dnat > 5, JSON.stringify(counts));
});

// --- formats --------------------------------------------------------------------------------------

test('RFC 5424: PRI severity and facility, SD-ID, no SD-ID, bracketless, no PRI', () => {
  const sd = lp.parse('<165>1 2007-02-15T09:17:15.719Z router1 mgd 3046 UI_DBASE_LOGOUT_EVENT [junos@2636.1.1.1.2.18 username="user"] User \'user\' exiting configuration mode');
  assert.equal(sd.format, 'rfc5424');
  assert.equal(sd.severity, 5);
  assert.equal(sd.facility, 20);
  assert.equal(sd.severitySource, 'pri');
  assert.equal(sd.sdid, 'junos@2636.1.1.1.2.18');
  assert.deepEqual([sd.host, sd.daemon, sd.pid, sd.tag], ['router1', 'mgd', '3046', 'UI_DBASE_LOGOUT_EVENT']);
  assert.equal(sd.fields.username, 'user');
  assert.equal(sd.message, "User 'user' exiting configuration mode");
  assert.equal(sd.time, Date.UTC(2007, 1, 15, 9, 17, 15, 719));
  assert.equal(sd.family, 'commit');
  const noId = lp.parse(DOCS.find((l) => l.includes('RT_LOG_SELF_TEST - RT_FLOW_SESSION_DENY')));
  assert.equal(noId.sdid, null);
  assert.equal(noId.fields['policy-name'], 'Fake policy');
  assert.equal(noId.time, Date.UTC(2023, 1, 26, 23, 15, 52), 'no zone: read as UTC');
  const bare = lp.parse(DOCS[0]);
  assert.equal(bare.fields.reason, 'CLI');
  assert.equal(bare.fields['session-id-32'], '30');
  assert.equal(bare.fields['session-id'], '30', 'session-id-32 is an alias of session-id');
  assert.equal(bare.time, Date.UTC(2013, 10, 29, 8, 1, 26, 820), 'offset honoured');
  const nopri = lp.parse(DOCS.find((l) => l.startsWith('2023-05-19') && l.includes('STREAM_DENY')));
  assert.equal(nopri.format, 'rfc5424');
  assert.equal(nopri.severity, 6, 'from the tag catalog');
  assert.equal(nopri.severitySource, 'catalog');
  assert.equal(nopri.flow.stream, true);
  assert.equal(nopri.flow.sessionId, 80000059);
  assert.equal(lp.parse(DOCS.find((l) => l.startsWith('<8>1'))).severity, 0);
  assert.equal(lp.severityName(lp.parse(DOCS.find((l) => l.startsWith('<11>1'))).severity), 'error');
});

test('structured data quirks: unquoted values, keys with spaces, trailing spaces, typos', () => {
  const av = lp.parse(DOCS.find((l) => l.includes('AV_VIRUS_DETECTED_MT')));
  assert.equal(av.fields.url, 'http://www.viruslist.com/en/search?VN=EICAR-Test-File');
  assert.equal(av.fields.filename, 'Fake file');
  assert.equal(lp.parse(DOCS.find((l) => l.includes('ANTISPAM'))).fields['source-name'], 'spamtest@spamtest.com');
  assert.equal(lp.parse(DOCS.find((l) => l.includes('RT_IPSEC_D3P_ERR'))).fields['D3P error'], 'Fake error');
  assert.equal(lp.parse(DOCS.find((l) => l.includes('CLOSE_LS'))).fields.encrypted, 'No ');
  // [CMD-DETAIL] has a missing closing quote; [FLOW-SESS] has a curly opening quote.
  const miss = lp.parse('<14>1 2022-06-15T05:04:59 10.49.18.230 RT_FLOW - RT_FLOW_SESSION_CLOSE [reason="TCP FIN" nat-source-address="192.0.3.3/24" nat-source-port="47452" nat-destination-address="198.51.100.3/24 nat-destination-port="80" protocol-id="6" session-id="785"]');
  assert.equal(miss.fields['nat-destination-address'], '198.51.100.3/24');
  assert.equal(miss.fields['nat-destination-port'], '80');
  assert.equal(miss.fields['protocol-id'], '6');
  assert.equal(miss.flow.sessionId, 785);
  const curly = '<14>1 2010-09-30T14:55:07.188+08:00 mrpp-srx550-dut01 RT_FLOW - RT_FLOW_SESSION_CLOSE [junos@2626.192.0.2.1.40 reason="response received" source-address="192.0.2.1" source-port="1" destination-address="198.51.100.12" destination-port="46384" service-name="icmp" nat-source-address="192.0.2.1" nat-source-port="1" nat-destination-address=”198.51.100.12" nat-destination-port="46384" src-nat-rule-name="None" dst-nat-rule-name="None" protocol-id="1" policy-name="policy1" source-zone-name="trustZone" destination-zone-name="untrustZone" session-id-32="41" packets-from-client="1" bytes-from-client="84" packets-from-server="1" bytes-from-server="84" elapsed-time="0" packet-incoming-interface="ge-0/0/1.0"] session closed response received: 192.0.2.1/1-->198.51.100.12/46384 icmp 192.0.2.1/1-->198.51.100.12/46384 None None 1 policy1 trustZone untrustZone 41 1(84) 1(84) 0 ge-0/0/1.0';
  const c = checkFlow(curly, { sessionId: 41, src: '192.0.2.1', sport: 1, dst: '198.51.100.12', dport: 46384, policy: 'policy1', from: 'trustZone', to: 'untrustZone', snat: false, dnat: false });
  assert.equal(c.fields['nat-destination-address'], '198.51.100.12');
  assert.equal(c.flow.protocol, 'icmp');
  assert.equal(joined(lp.tokenize(curly)), curly);
  assert.ok(lp.tokenize(curly).filter((t) => t.t === 'arrow').length >= 2, 'the text body after "]" is tokenised');
});

test('BSD: default, explicit-priority, year and millisecond time formats, year inference', () => {
  const d = lp.parse('Aug 21 12:36:30 router1 chassisd[522]: CHASSISD_PARSE_COMPLETE: Using new configuration', { now: NOW });
  assert.deepEqual([d.format, d.host, d.daemon, d.pid, d.tag, d.message], ['bsd', 'router1', 'chassisd', '522', 'CHASSISD_PARSE_COMPLETE', 'Using new configuration']);
  assert.equal(d.time, Date.UTC(2026, 7, 21, 12, 36, 30));
  assert.equal(d.family, 'chassis');
  const ep = lp.parse('Feb 23 07:38:19 router1 snmpd[359]: %DAEMON-2-SNMPD_TRAP_COLD_START: trap_generate_cold: SNMP trap: cold start');
  assert.deepEqual([ep.tag, ep.severity, ep.facility, ep.severitySource], ['SNMPD_TRAP_COLD_START', 2, 'DAEMON', 'explicit']);
  assert.equal(ep.message, 'trap_generate_cold: SNMP trap: cold start');
  const kern = lp.parse('Apr 16 21:41:22  vScapa1-RE0-re0 kernel: %KERN-6-TCP: MD5 Hash failed for (2.2.2.2, 39213)->(1.1.1.1, 179)');
  assert.deepEqual([kern.host, kern.daemon, kern.tag, kern.severity, kern.facility], ['vScapa1-RE0-re0', 'kernel', 'TCP', 6, 'KERN']);
  const ym = lp.parse('Aug 21 12:36:30.401 2006 router1 chassisd[522]: CHASSISD_PARSE_COMPLETE: Using new configuration', { now: NOW });
  assert.equal(ym.time, Date.UTC(2006, 7, 21, 12, 36, 30, 401));
  assert.equal(ym.ts, 'Aug 21 12:36:30.401 2006');
  assert.equal(lp.parse('Aug 21 12:36:30.401 router1 chassisd[522]: X_Y: z', { now: NOW }).time, Date.UTC(2026, 7, 21, 12, 36, 30, 401));
  assert.equal(lp.parse('Aug 21 12:36:30 2006 router1 chassisd[522]: X_Y: z', { now: NOW }).time, Date.UTC(2006, 7, 21, 12, 36, 30));
  const nye = lp.parse('Dec 31 23:59:59 fw mgd[1]: UI_COMMIT_COMPLETED: commit complete', { now: Date.UTC(2027, 0, 1, 0, 0, 30) });
  assert.equal(nye.time, Date.UTC(2026, 11, 31, 23, 59, 59), 'a date ahead of the clock is last year');
  const pad = lp.parse('Jul 17 20:26:04  sourpunch RT_FLOW: RT_FLOW_SESSION_CREATE: session created 3.3.3.5/2->4.4.4.2/63 0x0 None 3.3.3.5/2->4.4.4.2/63 0x0 N/A N/A N/A N/A 17 p2 TRUST UNTRUST 2617282058 N/A(N/A) xe-7/0/0.0 UNKNOWN UNKNOWN UNKNOWN N/A N/A -1 N/A N/A N/A');
  assert.equal(pad.host, 'sourpunch');
  const untagged = lp.parse('Apr 13 21:02:48 dev1 last message repeated 4 times');
  assert.deepEqual([untagged.format, untagged.host, untagged.daemon, untagged.tag, untagged.message], ['bsd', 'dev1', null, null, 'last message repeated 4 times']);
  const kernel = lp.parse(DOCS.find((l) => l.includes('/kernel')));
  assert.deepEqual([kernel.daemon, kernel.tag], ['/kernel', null]);
  const nested = lp.parse(DOCS.find((l) => l.includes('QFABRIC')));
  assert.equal(nested.tag, 'QFABRIC_INTERNAL_SYSLOG');
  assert.ok(nested.message.startsWith('Mar 28 18:00:16 ED1486 file: UI_COMMIT:'));
  assert.equal(lp.parse('no recognisable header here').format, 'unknown');
});

test('routing-engine buffer lines as the API renders them', () => {
  const b = lp.parse('2026-11-24.07:44:13 flowd: RT_FLOW_SESSION_CREATE: session created 10.10.0.20/10882->10.20.0.11/22 junos-ssh admin-to-dmz trust dmz');
  assert.deepEqual([b.format, b.ts, b.daemon, b.pid, b.tag, b.family], ['buffer', '2026-11-24.07:44:13', 'flowd', null, 'RT_FLOW_SESSION_CREATE', 'create']);
  assert.equal(b.time, Date.UTC(2026, 10, 24, 7, 44, 13));
  assert.deepEqual([b.flow.policy, b.flow.from, b.flow.to, b.flow.service], ['admin-to-dmz', 'trust', 'dmz', 'junos-ssh']);
  const withPid = lp.parse('2026-11-24.07:44:13 flowd[1402]: RT_FLOW_SESSION_DENY: session denied 1.1.1.2/2-->2.2.2.2/54812 icmp 1(8) policy1 trustZone untrustZone N/A(N/A) ge-0/0/1.0');
  assert.equal(withPid.pid, '1402');
  assert.deepEqual([withPid.flow.protocol, withPid.fields['icmp-type'], withPid.flow.policy, withPid.flow.from, withPid.flow.to, withPid.flow.iface], ['icmp', '8', 'policy1', 'trustZone', 'untrustZone', 'ge-0/0/1.0']);
  const old = lp.parse('2010-10-22.13:28:37 flowd: RT_FLOW_SESSION_CREATE: session created 1.1.1.2/1-->2.2.2.2/1308 icmp 1.1.1.2/1-->2.2.2.2/1308 None None 1 policy1 trustZone untrustZone 52 N/A(N/A) ge-0/0/1.0');
  checkFlow(old.line, { sessionId: 52, src: '1.1.1.2', sport: 1, dst: '2.2.2.2', dport: 1308, policy: 'policy1', from: 'trustZone', to: 'untrustZone', snat: false, dnat: false });
  const dashes = lp.parse('- -: -: nothing known');
  assert.equal(dashes.format, 'buffer');
  assert.equal(dashes.tag, null);
});

test('RT_FLOW BSD positional bodies across releases (24.4 template, NAT rule types, LSYS)', () => {
  // Bodies follow the System Log Explorer 24.4R1 templates; addresses are documentation ranges.
  const close = 'Nov 24 07:40:00 fw RT_FLOW: RT_FLOW_SESSION_CLOSE: session closed TCP FIN: 10.10.0.12/51234->198.51.100.20/443 0x0 junos-https 203.0.113.2/40123->198.51.100.20/443 0x0 source rule src-nat-egress N/A N/A 6 allow-web trust untrust 129585 12(2210) 22(1153433) 38 SSL UNKNOWN N/A(N/A) ge-0/0/1.0 No Web N/A 2 N/A NA 0 0.0.0.0/0->0.0.0.0/0 NA N/A N/A Off root 0 N/A N/A N/A';
  const c = checkFlow(close, { sessionId: 129585, src: '10.10.0.12', sport: 51234, dst: '198.51.100.20', dport: 443, policy: 'allow-web', from: 'trust', to: 'untrust', snat: true, dnat: false, natSrc: '203.0.113.2', natSport: 40123 });
  assert.deepEqual([c.fields['src-nat-rule-type'], c.fields['src-nat-rule-name'], c.fields['dst-nat-rule-type'], c.fields['dst-nat-rule-name']], ['source rule', 'src-nat-egress', 'N/A', 'N/A']);
  assert.deepEqual([c.flow.packetsClient, c.flow.bytesClient, c.flow.packetsServer, c.flow.bytesServer, c.flow.elapsed], [12, 2210, 22, 1153433, 38]);
  assert.deepEqual([c.flow.app, c.flow.iface, c.fields.encrypted, c.flow.snatRule], ['SSL', 'ge-0/0/1.0', 'No', 'src-nat-egress']);
  assert.ok(lp.decode(c).startsWith('Session 129585 closed (TCP FIN) after 38 s'));
  assert.ok(lp.decode(c).includes('SNAT 10.10.0.12:51234 → 203.0.113.2:40123 (rule src-nat-egress)'));
  // Decimal byte units, as format.bytes() and the Sessions view use: 2210 + 1153433 = 1155643 B.
  assert.ok(lp.decode(c).includes('1.2 MB (↑ 2.2 kB ↓ 1.2 MB)'), lp.decode(c));
  const dnat = 'Nov 24 07:41:00 fw RT_FLOW: RT_FLOW_SESSION_CREATE: session created 198.51.100.130/51000->203.0.113.11/443 0x0 junos-https 198.51.100.130/51000->10.20.0.11/443 0x0 N/A N/A destination rule dnat-web 6 publish-web untrust dmz 129586 N/A(N/A) ge-0/0/0.0 SSL UNKNOWN No';
  const d = checkFlow(dnat, { sessionId: 129586, src: '198.51.100.130', sport: 51000, dst: '203.0.113.11', dport: 443, policy: 'publish-web', from: 'untrust', to: 'dmz', snat: false, dnat: true, natDst: '10.20.0.11', natDport: 443 });
  assert.equal(d.fields['dst-nat-rule-name'], 'dnat-web');
  assert.ok(lp.decode(d).includes('DNAT 203.0.113.11:443 → 10.20.0.11:443 (rule dnat-web)'));
  const deny = 'Nov 24 07:42:00 fw RT_FLOW: RT_FLOW_SESSION_DENY: session denied 198.51.100.66/40400->203.0.113.2/3389 0x0 junos-rdp 6(0) deny-inbound untrust trust UNKNOWN UNKNOWN N/A(N/A) ge-0/0/0.0 No policy deny 0 N/A N/A -1 N/A N/A N/A';
  const n = checkFlow(deny, { src: '198.51.100.66', sport: 40400, dst: '203.0.113.2', dport: 3389, policy: 'deny-inbound', from: 'untrust', to: 'trust', snat: false, dnat: false });
  assert.deepEqual([n.flow.reason, n.fields['session-id'], n.flow.service], ['policy deny', '0', 'junos-rdp']);
  assert.ok(lp.decode(n).startsWith('Session denied by deny-inbound'));
  const sour = lp.parse('Jul 17 20:26:04  sourpunch RT_FLOW: RT_FLOW_SESSION_CREATE: session created 3.3.3.5/2->4.4.4.2/63 0x0 None 3.3.3.5/2->4.4.4.2/63 0x0 N/A N/A N/A N/A 17 p2 TRUST UNTRUST 2617282058 N/A(N/A) xe-7/0/0.0 UNKNOWN UNKNOWN UNKNOWN N/A N/A -1 N/A N/A N/A');
  assert.deepEqual([sour.flow.sessionId, sour.flow.protocol, sour.flow.policy, sour.flow.from, sour.flow.to, sour.flow.iface, sour.flow.snat], [2617282058, 'udp', 'p2', 'TRUST', 'UNTRUST', 'xe-7/0/0.0', false]);
  const ls = lp.parse('Nov 24 07:43:00 fw RT_FLOW: RT_FLOW_SESSION_CREATE_LS: Lsys LSYS1: session created 10.1.1.2/5000->10.2.2.2/80 0x0 junos-http 10.1.1.2/5000->10.2.2.2/80 0x0 N/A N/A N/A N/A 6 p-lsys lsys1-trust lsys1-untrust 60000218 N/A(N/A) ge-0/0/2.0 HTTP UNKNOWN No');
  assert.deepEqual([ls.family, ls.flow.lsys, ls.flow.sessionId, ls.flow.policy], ['create', 'LSYS1', 60000218, 'p-lsys']);
  assert.ok(lp.decode(ls).includes('logical system LSYS1'));
  const lsTok = lp.tokenize(ls.line);
  assert.ok(lsTok.some((t) => t.k === 'lsys' && t.v === 'LSYS1'));
});

// --- families, decode, self reads -------------------------------------------------------------------

test('FAMILIES: display order, exclusive matching, daemon fallback', () => {
  assert.deepEqual(lp.FAMILIES.map((f) => f.id), ['create', 'close', 'deny', 'screen', 'idp', 'vpn', 'commit', 'auth', 'snmp', 'chassis', 'other']);
  const cases = {
    RT_FLOW_SESSION_CREATE: 'create', RT_FLOW_SESSION_CREATE_LS: 'create', RT_FLOW_STREAM_CREATE: 'create',
    RT_FLOW_SESSION_CLOSE: 'close', RT_FLOW_SESSION_DENY: 'deny', RT_FLOW_STREAM_DENY: 'deny', RT_SCREEN_TCP: 'screen',
    IDP_ATTACK_LOG_EVENT: 'idp', AV_VIRUS_DETECTED_MT: 'idp', WEBFILTER_URL_BLOCKED: 'idp', KMD_VPN_UP_ALARM_USER: 'vpn',
    IKE_GATEWAY_PEER_FAILED: 'vpn', RT_IPSEC_BAD_SPI: 'vpn', UI_COMMIT: 'commit', UI_CMDLINE_READ_LINE: 'commit',
    UI_NETCONF_CMD: 'commit', UI_LOGIN_EVENT: 'auth', UI_AUTH_INVALID: 'auth', SSHD_LOGIN_FAILED: 'auth', LOGIN_FAILED: 'auth',
    SNMP_TRAP_LINK_DOWN: 'snmp', SNMPD_TRAP_COLD_START: 'snmp', CHASSISD_FAN_FAILURE: 'chassis', JSRPD_RG_STATE_CHANGE: 'chassis',
    RPD_BGP_NEIGHBOR_STATE_CHANGED: 'other', APPTRACK_SESSION_CLOSE: 'other',
  };
  for (const [tag, id] of Object.entries(cases)) {
    assert.equal(lp.family(tag), id, tag);
    const hits = lp.FAMILIES.filter((f) => f.id !== 'other' && f.match(tag)).map((f) => f.id);
    assert.deepEqual(hits, id === 'other' ? [] : [id], tag);
  }
  assert.equal(lp.family(null, 'sshd'), 'auth');
  assert.equal(lp.family(null, '/kernel'), 'other');
  assert.equal(lp.family(null, 'kmd'), 'vpn');
  assert.equal(lp.parse(DEV.find((l) => l.includes('sshd['))).family, 'auth');
});

test('decode: screen, IDP, commit, configuration mode, login, VPN, link', () => {
  const d = (l) => lp.decode(lp.parse(l));
  assert.equal(d('Nov 24 07:50:04 branch-fw-01 RT_SCREEN: RT_SCREEN_TCP: SYN flood! source: 198.51.100.7:49001, destination: 203.0.113.2:443, zone name: untrust, interface name: ge-0/0/0.0, action: drop'),
    'Screen: SYN flood! (drop) · 198.51.100.7:49001 → 203.0.113.2:443 · zone untrust · ge-0/0/0.0');
  assert.equal(d(DOCS.find((l) => l.includes('RT_SCREEN_IP'))), 'Screen: test (test_action) · 192.0.2.1 → 198.51.100.2 · zone Fake src zone · test_interface');
  // IDP text as the development fixture writes it (synthetic, after the documented template).
  const idp = lp.parse('Nov 24 07:51:00 branch-fw-01 RT_IDP: IDP_ATTACK_LOG_EVENT: IDP: SIG Attack log <198.51.100.66/51515->10.20.0.10/443> for TCP protocol and service SERVICE_IDP application HTTP by rule 3 of rulebase IPS in policy recommended. attack: id=1234, action=DROP, threat-severity=HIGH, name=HTTP:STC:SCRIPT:UNI-SHELLCODE, intf:untrust:ge-0/0/0.0->dmz:ge-0/0/2.0');
  assert.equal(idp.family, 'idp');
  assert.deepEqual([idp.fields['attack-name'], idp.fields.action, idp.fields['source-zone-name'], idp.fields['destination-zone-name'], idp.fields['destination-port']], ['HTTP:STC:SCRIPT:UNI-SHELLCODE', 'DROP', 'untrust', 'dmz', '443']);
  assert.equal(lp.decode(idp), 'IDP HTTP:STC:SCRIPT:UNI-SHELLCODE (HIGH): DROP · 198.51.100.66:51515 → 10.20.0.10:443 · untrust → dmz · rule 3 of IPS · IDP policy recommended');
  assert.ok(d(DOCS.find((l) => l.includes('IDP_ATTACK_LOG_EVENT'))).startsWith('IDP attack (INFO): TRAFFIC_IPACTION_NOTIFY'));
  assert.equal(d("Apr 11 11:36:15 router1 mgd[3606]: UI_COMMIT: User 'root' performed commit: no comment"), 'root performed commit (no comment)');
  assert.equal(d("Nov 24 07:00:00 fw mgd[1]: UI_COMMIT: User 'admin' requested 'commit' operation (comment: none)"), 'admin requested commit');
  assert.equal(d("Nov 24 07:00:00 fw mgd[1]: UI_COMMIT: User 'admin' requested 'commit confirmed' operation (comment: change 42)"), 'admin requested commit confirmed (comment: change 42)');
  assert.equal(d('Nov 23 22:00:19 branch-fw-01 mgd[1402]: UI_COMMIT_COMPLETED: commit complete'), 'Commit completed');
  assert.equal(d(DOCS.find((l) => l.includes('UI_EPHEMERAL_COMMIT:'))), 'user requested a commit of ephemeral database eph1');
  assert.equal(d(DOCS.find((l) => l.includes('UI_DBASE_LOGIN_EVENT'))), 'barbara entered configuration mode');
  assert.equal(d("Nov 24 07:52:40 branch-fw-01 mgd[2001]: UI_LOGIN_EVENT: User 'admin' login, class 'j-super-user' [2001], ssh-connection '10.10.0.21 51234 10.10.0.1 22', client-mode 'cli'"), 'admin signed in (class j-super-user) from 10.10.0.21 using cli');
  assert.equal(d("Nov 24 07:52:40 fw mgd[2001]: UI_LOGOUT_EVENT: User 'admin' logout"), 'admin signed out');
  assert.equal(d("Nov 24 07:00:00 branch-fw-01 sshd[4001]: SSHD_LOGIN_FAILED: Login failed for user 'root' from host '198.51.100.66'"), 'Sign-in failed for root from 198.51.100.66');
  assert.equal(d('Nov 24 07:51:13 branch-fw-01 sshd[6121]: Accepted password for admin from 10.10.0.20 port 56710 ssh2'), 'Signed in: admin (password) from 10.10.0.20:56710 over SSH');
  assert.equal(d("Nov 24 07:00:00 fw mgd[1]: UI_CMDLINE_READ_LINE: User 'admin', command 'show security flow session summary '"), 'admin ran: show security flow session summary');
  assert.equal(d('Nov 24 07:00:00 branch-fw-01 kmd[1]: KMD_VPN_UP_ALARM_USER: VPN to-hq from 198.51.100.200 is up. Local-ip: 203.0.113.2, gateway name: gw-hq'), 'VPN to-hq is up (peer 198.51.100.200)');
  assert.equal(d(DOCS.find((l) => l.includes('SNMP_TRAP_LINK_DOWN'))), 'Interface at-1/0/0 link down');
  assert.equal(d(DOCS.find((l) => l.includes('CHASSISD_PARSE_COMPLETE'))), null);
  assert.equal(lp.decode(null), null);
  assert.ok(lp.decode(DOCS[2]).startsWith('Session 69 created'), 'decode accepts a raw line too');
});

test('isSelfRead: UI_NETCONF_CMD lines of the signed-in user only', () => {
  const bsd = "Nov 24 07:45:01 branch-fw-01 mgd[4242]: UI_NETCONF_CMD: User 'admin' used NETCONF client to run command 'get-flow-session-information'";
  const sd = '<190>1 2026-11-24T07:45:01.000Z branch-fw-01 mgd 4242 UI_NETCONF_CMD [junos@2636.1.1.1.2.129 username="admin" hostname="branch-fw-01" command="get-log"] User \'admin\' used NETCONF client to run command \'get-log\'';
  assert.equal(lp.isSelfRead(lp.parse(bsd), 'admin'), true);
  assert.equal(lp.isSelfRead(lp.parse(sd), 'admin'), true);
  assert.equal(lp.isSelfRead(bsd, 'admin'), true, 'accepts a raw line');
  assert.equal(lp.isSelfRead(lp.parse(bsd), 'alice'), false);
  assert.equal(lp.isSelfRead(lp.parse(bsd), ''), false);
  assert.equal(lp.isSelfRead(lp.parse(bsd.replace('UI_NETCONF_CMD', 'UI_JUNOSCRIPT_CMD').replace('NETCONF', 'JUNOScript')), 'admin'), false);
  assert.equal(lp.isSelfRead(lp.parse("Nov 24 07:45:01 fw mgd[1]: UI_CMDLINE_READ_LINE: User 'admin', command 'show log'"), 'admin'), false);
  assert.equal(lp.isSelfRead(null, 'admin'), false);
  assert.equal(lp.parse(sd).family, 'commit');
});

test('parse is memoised and never throws', () => {
  const a = lp.parse(DEV[0]);
  assert.equal(lp.parse(DEV[0]), a);
  assert.notEqual(lp.parse(DEV[0], { now: NOW }), a, 'options bypass the cache');
  for (const odd of [undefined, null, 42, '', '<999>1 x', '[a="b"]', 'Nov 99 99:99:99 h p: x']) {
    const p = lp.parse(odd);
    assert.equal(typeof p.format, 'string');
    assert.equal(typeof p.fields, 'object');
  }
});

test('control and format characters become their own "ctl" tokens and stay lossless', () => {
  const rlo = '‮';
  const line = `<14>1 2026-11-24T11:17:57.433Z branch-fw-01 RT_FLOW - RT_FLOW_SESSION_DENY [junos@2636.1.1.1.2.129 source-address="198.51.100.9" source-zone-name="untrust${rlo}" username="${rlo}resu"] x​y \u0085z ⁦w⁩`;
  const toks = lp.tokenize(line);
  assert.equal(joined(toks), line);
  const ctl = toks.filter((t) => t.t === 'ctl');
  assert.deepEqual(ctl.map((t) => t.v), [rlo, rlo, '​', '\u0085', '⁦', '⁩']);
  for (const t of toks) if (t.t !== 'ctl') assert.ok(!lp.CONTROL_RE.test(t.v), `control char left inside ${JSON.stringify(t)}`);
  const zone = toks.find((t) => t.t === 'zone' && t.v === 'untrust');
  assert.equal(zone.k, 'from');
  assert.equal(zone.q, `untrust${rlo}`, 'a split value keeps its exact filter value');
  assert.equal(lp.countControls(line), 6);
  assert.equal(lp.controlName(rlo), 'U+202E');
  assert.ok(lp.escapeControls(line).endsWith('x<U+200B>y <U+0085>z <U+2066>w<U+2069>'));
  assert.equal(lp.escapeControls('plain\ttext'), 'plain\ttext', 'tab is not a control here');
  for (const l of [...DOCS, ...DEV]) assert.equal(lp.countControls(l), 0, 'the corpus holds no control characters');
});

test('header offsets (hdr) and zoned timestamps', () => {
  for (const line of [...DOCS, ...DEV]) {
    const p = lp.parse(line, { now: NOW });
    const h = p.hdr;
    assert.ok(h && Number.isInteger(h.body), line);
    if (p.ts && h.ts) assert.equal(line.slice(h.ts[0], h.ts[1]), p.ts, `ts in ${line}`);
    if (h.host) assert.equal(line.slice(h.host[0], h.host[1]).trimEnd(), p.host || '-', `host in ${line}`);
    if (h.pri) assert.match(line.slice(h.pri[0], h.pri[1]), /^<\d{1,3}>\d{1,2} $/);
    if (h.procid) assert.match(line.slice(h.procid[0], h.procid[1]), /^- ?$/);
    if (h.sdid) assert.equal(line.slice(h.sdid[0], h.sdid[1]).trimEnd(), `[${p.sdid}`);
    assert.equal(line.slice(h.body), p.message, `body in ${line}`);
  }
  assert.equal(lp.parse('<14>1 2026-11-24T07:54:52.741Z h RT_FLOW - X - m').zoned, true);
  assert.equal(lp.parse('<14>1 2026-11-24T07:54:52 h RT_FLOW - X - m').zoned, false, 'report output carries no zone');
  assert.equal(lp.parse('Nov 24 13:07:49 h mgd[1]: UI_COMMIT: x').zoned, false, 'BSD time is the device clock');
  assert.equal(lp.parse('2026-11-24.13:08:16 flowd: RT_FLOW_SESSION_CREATE: x').zoned, false);
});

test('summary: the 5-tuple, policy, zones, NAT, reason and counters first, the rest faint', () => {
  const close = DEV.find((l) => /RT_FLOW_SESSION_CLOSE \[/.test(l) && /src-nat-rule-type="source rule"/.test(l));
  const p = lp.parse(close, { now: NOW });
  const toks = lp.summary(p);
  const text = joined(toks);
  const fl = p.flow;
  assert.ok(text.startsWith(`${fl.src}:${fl.sport} → ${fl.dst}:${fl.dport} tcp · ${fl.policy} · ${fl.from} → ${fl.to} · SNAT ${fl.natSrc}:${fl.natSport} · ${fl.reason} · `), text);
  assert.ok(text.includes(`session-id=${fl.sessionId}`), 'session id among the rest');
  assert.ok(!/source-address=|N\/A|UNKNOWN|connection-tag=0/.test(text), `summarised keys and placeholders left out: ${text}`);
  const roles = Object.fromEntries(toks.filter((t) => t.k).map((t) => [t.k, t.q ?? t.v]));
  assert.equal(roles.src, fl.src);
  assert.equal(roles.sport, String(fl.sport));
  assert.equal(roles.dport, String(fl.dport));
  assert.equal(roles.policy, fl.policy);
  assert.equal(roles.from, fl.from);
  assert.equal(roles.reason, fl.reason);
  const firstFaint = toks.findIndex((t) => t.f);
  assert.ok(firstFaint > 0 && toks.slice(firstFaint).every((t) => t.f), 'faint tokens come last');
  assert.ok(toks.some((t) => t.nc && t.t === 'num'), 'byte and duration totals are not filter values');
  const padded = joined(lp.summary(p, { pad: true }));
  assert.equal(padded.indexOf('→'), 22, 'padded: the arrow sits in a fixed column');
  assert.equal(lp.flowBadge(p), 'CLOSE');
  assert.equal(lp.summary(lp.parse('Nov 24 13:07:49 h mgd[1]: UI_COMMIT: x')), null);
  // BSD text and buffer forms summarise too
  for (const l of DEV.filter((x) => /RT_FLOW_SESSION_(CREATE|CLOSE|DENY)/.test(x))) {
    const q = lp.parse(l, { now: NOW });
    const s = joined(lp.summary(q));
    assert.ok(s.includes(`${q.flow.src}:${q.flow.sport} → ${q.flow.dst}:${q.flow.dport}`), `${l} -> ${s}`);
  }
});

test('summary without the remaining fields (phone rows)', () => {
  const line = DEV.find((l) => /RT_FLOW_SESSION_CREATE \[/.test(l));
  const p = lp.parse(line, { now: NOW });
  const toks = lp.summary(p, { rest: false });
  assert.ok(toks.length > 0 && toks.every((t) => !t.f), 'no faint fields');
  assert.ok(!joined(toks).includes('session-id='));
});
