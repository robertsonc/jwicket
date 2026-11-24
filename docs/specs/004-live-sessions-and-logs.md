# Spec 004: Live sessions and logs (read-only)

| Field | Value |
| --- | --- |
| Status | **Backend and browser engines implemented on synthetic fixtures. Sessions and Logs views built in the working tree, not yet committed, not yet checked in a browser. Never run on a device. Nothing qualified.** |
| Parity priority | `P0`, with Spec 001 (the owner's binding addition to the first slices; see the [charter](../charter.md)). The J-Web rows it covers are in the [parity ledger](../parity/jweb-24.4.csv) |
| Gate | Part of G1 (foundation exit: Q-LOAD-02, Q-LOAD-03 are G1 tests); qualified at G2 with Q-LOG-01 |
| Decides scope | Project owner. G1 sign-off: the named security reviewer |
| Code | [`live.py`](../../src/jwicket/live.py), [`junos/sessions.py`](../../src/jwicket/junos/sessions.py), [`junos/logs.py`](../../src/jwicket/junos/logs.py), [`junos/session.py`](../../src/jwicket/junos/session.py) (allowlist, `LOGS_FILTER`), browser engines [`static/js/query.js`](../../src/jwicket/static/js/query.js) and [`static/js/logparse.js`](../../src/jwicket/static/js/logparse.js) |
| Tests | [`test_live.py`](../../tests/test_live.py), [`tests/js/query.test.mjs`](../../tests/js/query.test.mjs), [`tests/js/logparse.test.mjs`](../../tests/js/logparse.test.mjs), corpus [`tests/fixtures/log-samples/`](../../tests/fixtures/log-samples/README.md) |
| Decisions it rests on | [ADR 0002](../adr/0002-junos-delegated-sign-in.md), [0004](../adr/0004-no-sample-data.md), [0007](../adr/0007-offline-capable-meaning.md); Spec 001 for policy and zone context |

## 1. Status

The point: J-Wicket can show `show security flow session` output and the device's logs live, with
filters pushed to the device where Junos supports them, and it refuses to pull a session table so
large that listing it would load the routing engine. That is true **on synthetic fixtures
only**. The per-session XML element names are J-Wicket's inference; no recorded reply exists.

| Part | State | Evidence |
| --- | --- | --- |
| `/api/sessions`: validated device-side filters, filtered count, refusal, row cap, cluster and SPU locations | Implemented | `test_live.py`: `SessionFilterTests`, `SessionParseTests`, `LiveHttpTests`: pass |
| `/api/logs/sources`: syslog files, security log mode, streams, on-box reporting, RE buffer | Implemented | `LogSourceTests`, `ModeAndExpressionTests`, `LiveHttpTests`, `ReportHttpTests`: pass |
| `/api/logs`: file tail with cursor and rotation, report reads with `expression`, buffer reads | Implemented | `TailTests`, `ReportHttpTests`, `ModeAndExpressionTests`: pass |
| Query language and pushdown planner (`query.js`) | Implemented | `tests/js/query.test.mjs`: pass (2026-11-24) |
| Log tokeniser, parser, decoder, self-read detection (`logparse.js`) | Implemented | `tests/js/logparse.test.mjs`: pass (2026-11-24) on 46 verbatim documentation lines and the development-server corpus |
| Sessions view, Logs view, flow diagram, histogram, query bar widget | **Built in the working tree, not yet committed, not yet checked in a browser** (AC-004-20 not met) | None yet: no browser check has run |
| On a device | **Not run.** The spike called `get-flow-session-information` with `summary` on one vSRX as the daemon's account; no reply was recorded and the panel was not checked | [Spike report](../evidence/2026-11-23-vsrx-spike/docs/J-Wicket-spike-report-and-product-plan.md) |

In parity-ledger terms the 26 rows this backend covers stay `specified` until AC-004-20 passes:
each is an operation done in the browser, and a row becomes `implemented` only when its criteria
pass, the browser check included ([ledger method, section 5](../parity/README.md#5-statuses)).

The development server's live data (`jwicket/fixtures.py`, `LiveModel`) is generated from the same
inferred element names the parser reads. Session tests therefore prove that the parser and the
fixture agree, not that either matches Junos. Q-REL-01 replaces them with recorded replies.

## 2. Problem

During an incident an operator asks: is this flow up, which policy let it through, is it NATed,
how much is it moving, and why did that other one close or get denied? The CLI answers with
`show security flow session` and `show log`, but:

- **Listing sessions is expensive for the device.** For a list request the data plane sends every
  matching session to the routing engine. A Juniper support reply citing KB28956 describes
  routing-engine CPU at "Idle 0 percent" after `show security flow session`. There is no option
  to cap the number of sessions returned (section 7.4).
- **Logs are in different places depending on configuration.** In stream mode traffic logs leave
  the box and are not stored locally unless on-box reporting or a stream file is configured; in
  event mode they go through the routing engine's syslog (section 7.7). An empty log pane that
  does not say why is a wrong answer.
- **Reading a log file returns the whole file.** `get-log` has no offset, line-count or tail
  parameter (section 7.8).

J-Web 24.4 baseline (**verified**, J-Web 24.4 guide,
[Monitor Session](https://networkingdocs.hpe.com/documentation/us/en/software/jweb-srx24.4/jweb-srx/topics/concept/j-web-security-session-log-monitoring.html),
[System Log](https://networkingdocs.hpe.com/documentation/us/en/software/jweb-srx24.4/jweb-srx/topics/concept/j-web-security-system-log-monitoring.html)):

- Monitor > Logs (Session, Threats, Web Filtering, ATP, VPN, All Events): a time picker, a manual
  Refresh icon (no live tail), Show/Hide Columns, Export to CSV limited to 100 rows, a filter bar
  with `=`, `!=`, `>=`, `<=`, AND and nested and/or with netmask search since 23.1R1, Save Filter
  and Load Filter, and a Detailed Log View. Not available on the SRX5000 line.
- Monitor > Logs > Session is built from session logs, not the live table. That it reads the
  on-box reporting database is **inferred**. In the parity inventory of the 24.4 guide, no Monitor
  page lists the live flow-session table.
- Monitor > Logs > System (from 23.2R1; SRX300 line from 23.4R2): pick a syslog file, last hour by
  default, Refresh, filter on Event and Message with `=` only.

The owner's binding requirement: log viewing with syntax highlighting, and `show security flow
session` output visible with powerful inline, live filtering. Read-only.

## 3. Users and jobs

| User | Job | What Spec 004 gives them |
| --- | --- | --- |
| Operator during an incident | "Is 10.10.3.4 reaching 198.51.100.20:443, through which policy, NATed to what?" | Session list filtered on the device by address, port, protocol, application or interface; per-session wings, NAT, policy name and index |
| Same | "How full is the session table?" | Active of maximum from the summary, on every poll |
| Same | "What just got denied, and by which policy?" | RT_FLOW_SESSION_DENY lines highlighted and decoded |
| Same | "Why did this session close, and how much did it move?" | RT_FLOW_SESSION_CLOSE decoded: reason, counters, elapsed time; session timeline from CREATE to CLOSE |
| Operator or SE | "Where are my traffic logs on this box?" | The sources card: security log mode (configured or documented default), stream hosts, on-box reporting, RE buffer, syslog files with their contents |
| Change reviewer | "Who committed what, when?" | `UI_COMMIT*` and `UI_CMDLINE_*` lines from syslog files the class can read |
| Read-only operator | "Why can't I see logs?" | An explicit `denied` state: reading syslog files needs the Junos `trace` permission |
| SE in a demo | "Show what on-box management can feel like." | Live table and tail with typed filters, highlighting and drill-down, on fixtures today |

## 4. Scope and non-scope

**In scope (implemented in the backend):**

- Root-scope flow sessions with seven device-side filters (source prefix, destination prefix,
  source port, destination port, protocol, application, interface), a filtered count, a
  table-wide gauge, a refusal threshold and a row cap.
- Log sources discovered from `system syslog file` and `security log`, plus the documented default
  mode for the model.
- Reading a syslog file with a cursor-based tail, rotation detection and substring filters.
- Reading the on-box reporting database (`show security log report in-detail <type>`, ten types)
  with time window, count and `expression`.
- Reading the routing-engine security log buffer (`show security log`) since a time.
- Browser-side query language, pushdown planning, tokenising, highlighting and decoding.

**Out of scope:**

| Not here | Why, and where it goes |
| --- | --- |
| Clearing sessions, `monitor security flow` | State-changing. `clear-flow-session*` and `monitor-security-flow-*` (file, filter, start, stop; XML API Explorer catalog) are never allowlisted. `monitor security flow` and flow traceoptions "cannot run in parallel" (**verified**, [flow session monitoring](https://networkingdocs.hpe.com/documentation/us/en/software/junos/flow-packet-processing/topics/topic-map/security-flow-session-and-error-handling.html)) |
| Sessions and logs of logical and tenant systems | `/api/sessions?scope=` other than `root` returns 400; logs take no scope. Needs the `logical-system` / `tenant` RPC options recorded (Q-REL-01). Open question 4 |
| Other session filters: `policy-id`, `zone`, `nat`, `session-state`, `node`, the `*-more-than` / `*-less-than` ranges; `extensive`, `pretty`; single-session `get-flow-session-by-identifier` | Element names and release support unrecorded (section 7.1). Open question 3 |
| `show security log report summary / in-interval / top`, `start-from` paging, the threat-specific `atp-*`, `dns`, `utm-*` sub-types | Later spec; the interval report would feed the histogram from the device |
| Binary or protobuf log files (`get-security-hpl-infile`, `get-security-stream-hpl-infile`), archived `.gz` files, `get-syslog-events` | Reply shapes and permissions unknown; not allowlisted |
| Server push (WebSocket, long poll) | Live means incremental polling; the stdlib server is HTTP/1.0, one request per connection |
| Server-side log export or retention | Export is a client-side download of what the browser holds |

## 5. Behaviour

### 5.1 Endpoints

| Request | Purpose |
| --- | --- |
| `GET /api/sessions?src=&dst=&sport=&dport=&proto=&app=&iface=&limit=&scope=root` | Filtered session list, count and gauge |
| `GET /api/logs/sources` | Where logs are on this device |
| `GET /api/logs?source=file:<name>&cursor=&lines=&contains=&exclude=` | Tail a syslog file (`file=<name>` is accepted as a short form; default `messages`) |
| `GET /api/logs?source=report&type=<t>&start=&stop=&count=&expression=` | Read the on-box reporting database |
| `GET /api/logs?source=buffer&since=` | Read the routing-engine security log buffer |

Common responses:

| Status | When | Body |
| --- | --- | --- |
| 200 | Any completed read, including failed device reads | Payload with explicit states (below) |
| 400 | A parameter failed validation | `{error}` saying which value or parameter failed |
| 401 | No session; or the device session was lost during the read | `{error}`; `signed_out: true` in the second case |
| 429 | Same operator, same endpoint (for logs: same `source`) within 1.5 s | `{error, retry_after_s}` and `Retry-After` |

Every response's `meta` has `read_at`, `read_as {user, backend}`, `fixture` and
`suggested_interval_s` (5).

### 5.2 Sessions

**Parameters** (validated in [`sessions.device_filters`](../../src/jwicket/junos/sessions.py); any
other key is ignored):

| Query key | RPC parameter | Accepted value |
| --- | --- | --- |
| `src` | `source-prefix` | IPv4/IPv6 address or prefix; host bits are cleared (`10.10.3.4/16` becomes `10.10.0.0/16`); a bare address becomes /32 or /128 |
| `dst` | `destination-prefix` | Same |
| `sport`, `dport` | `source-port`, `destination-port` | 0 to 65535 |
| `proto` | `protocol` | `tcp udp icmp icmp6 gre esp ah sctp pim ospf`, or 0 to 255 |
| `app` | `application` | `^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$` |
| `iface` | `interface` | `^[a-z][a-z0-9-]{1,9}(\d+(/\d+){0,3})?(\.\d{1,5})?$` |
| `limit` | (not sent) | Rows returned to the browser: default 500, clamped to 1..2000 |
| `scope` | (not sent) | Only `root`; anything else is 400 |

**One poll:**

```mermaid
flowchart TD
    Q["GET /api/sessions with validated filters"] --> T{"Throttle: 1.5 s since this operator's last sessions read?"}
    T -- no --> E429["429 Retry-After"]
    T -- yes --> S1["RPC 1: get-flow-session-information summary + filters<br/>gives the matching count"]
    S1 --> F{"Any device-side filter?"}
    F -- no --> G1["Gauge = this summary (cache it)"]
    F -- yes --> GC{"Cached gauge younger than 30 s?"}
    GC -- yes --> G2["Gauge = cached"]
    GC -- no --> G3["Extra RPC: unfiltered summary (cache it)"]
    G1 --> M{"matching count known and above MAX_UNFILTERED (5000)?"}
    G2 --> M
    G3 --> M
    M -- yes --> R["sessions.status = refused, rows = [ ]"]
    M -- "no, or count unknown" --> L["RPC 2: get-flow-session-information + filters<br/>parse, keep first limit rows"]
```

The matching count is the summary's `displayed-session-count` (what a filtered summary returns);
with no filters and no such element, it is the summary's `active-sessions`. Both are summed over
nodes and SPUs.

**Known gap (fail-open).** When the count is unknown, the list is pulled anyway. That happens when
the summary RPC fails (denied, unsupported, timeout) or when its reply lacks the expected count
element. On a loaded device a summary timeout followed by an unbounded list is the case the
refusal exists to prevent. Open question 1.

**Response:**

```json
{
  "meta": {"read_at": "2026-11-24T06:00:00Z", "read_as": {"user": "alice", "backend": "netconf"},
           "fixture": false, "suggested_interval_s": 5, "device_filters": {"destination-port": "443"},
           "limit": 500, "min_interval_s": 1.5},
  "summary": {"status": "ok", "active": 1342, "max": 65536, "failed": 0, "matching": null},
  "matching": 87,
  "sessions": {"status": "ok", "rows": ["<session row>"], "returned": 87, "truncated": false, "device_count": 87}
}
```

- `summary` is the table-wide gauge (`active`, `max`, `failed`, `matching` from the reply that
  produced it) or a panel error `{status, message}`. On a filtered poll it may be up to 30 s old;
  the response does not say how old (open question 10).
- `matching` is the count used for the refusal decision, or `null`.
- `sessions.status` is `ok`, `refused` (with `message` and the count), `denied`, `unsupported` or
  `failed` (with `message`). `rows` is always present.
- `returned` counts every `flow-session` in the reply; `truncated` is true when that exceeds
  `limit`; `device_count` sums the reply's `displayed-session-count` values, or `null`. The full
  reply is still transferred and parsed before the cap, so `limit` bounds the browser's work, not
  the device's.

**Session row** ([`sessions._session`](../../src/jwicket/junos/sessions.py)):

| Key | Meaning |
| --- | --- |
| `id` | `<location>:<session-id>` when a location is known, else the session id; unique within a reply even when both cluster nodes report the same session |
| `session_id`, `location` | Device session id; `node0`, `node1`, an SPU label such as `on FPC0 PIC1:`, or both |
| `status`, `state` | From `status` and `session-state` |
| `policy`, `policy_index` | `name/index` split on the last `/`; index `null` when absent |
| `timeout`, `configured_timeout`, `start_time`, `duration` | Integers where parseable; `start_time` raw |
| `application` | `application`, else `dynamic-application-name` |
| `in`, `out` | Wings: `{direction, src, sport, dst, dport, proto, iface, packets, bytes, tunnel}`. `in` is the wing whose direction starts "In" (else the first wing); `out` the one starting "Out", or `null` for one-winged sessions |
| `nat` | `{source, destination}` inferred from the wings (section 7.6) |
| `extra` | Up to 24 scalar child elements the model does not name (first 200 characters each), shown, never dropped |

### 5.3 Log sources

`GET /api/logs/sources` reads `get-software-information` (model, cached 10 minutes) and the
configuration with `LOGS_FILTER` (`system/syslog`, `security/log`), then caches the result for
60 s per web session. It is not throttled; the cache bounds it.

```json
{
  "meta": {"read_at": "...", "read_as": {"user": "alice", "backend": "netconf"}, "fixture": false, "suggested_interval_s": 5},
  "sources": {
    "status": "ok",
    "files": [
      {"id": "file:messages", "name": "messages", "contents": ["any notice", "authorization info"], "match": null, "structured_data": false, "group": null},
      {"id": "file:traffic-log", "name": "traffic-log", "contents": ["any any"], "match": "RT_FLOW_SESSION", "structured_data": true, "group": null}
    ],
    "traffic": {"mode": "event", "effective_mode": "event", "mode_basis": "set in the configuration",
                "streams": [], "report": false, "format": null,
                "where": "Traffic logs are handled by the routing engine: they appear in the security log buffer and in any syslog file that takes them (for example one matching RT_FLOW)."},
    "databases": [{"id": "buffer", "name": "Security log buffer (routing engine)"}],
    "self_noise": "Junos logs every NETCONF request as UI_NETCONF_CMD, ..."
  }
}
```

- `files`: one per `system syslog file` whose name matches `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`;
  path-like names are dropped. If none is named `messages`, a `messages` entry is added with
  `assumed: true`. `contents` is `"<facility> <severity>"`. `group` is always `null` today.
- `traffic.mode` is the configured mode or `null`; `effective_mode` and `mode_basis` fall back to
  the documented default for the model: `event` for vSRX; `stream` for model names starting
  `srx3`, `srx5`, `srx1500`, `srx4100`, `srx4200`; otherwise `null` with "the default for this
  model is not documented".
- `traffic.where` is one sentence for the operator. Stream: "Traffic logs are streamed off the
  device to `<hosts>`; they are not stored here." (plus "On-box reporting keeps a local copy." when
  `report` is set). Stream-event: streamed, ending with a full stop, plus the on-box note. Event:
  as in the example. Unknown: "The security log mode is not set and `<basis>`; check 'show
  security log' on the device."
- `databases` holds `report` (with `types`) when `security log report` is set, the effective mode
  is `stream` or `stream-event`, and the model does not start with `srx54`, `srx56` or `srx58`; and
  `buffer` when the effective mode is `event` or `stream-event`.
- On failure `sources` is `{status: denied | unsupported | failed, message}`.

### 5.4 Reading logs

**Syslog file** (`source=file:<name>`; [`logs.tail`](../../src/jwicket/junos/logs.py)):

| Parameter | Rule |
| --- | --- |
| `<name>` | Must be one of `sources.files` (including the assumed `messages`) |
| `cursor` | `<count>:<12 hex digits>`, from the previous response |
| `lines` | Default 500, clamped to 1..2000 |
| `contains`, `exclude` | Newline-separated, at most 4 terms of at most 120 characters each; case-insensitive substring |

One `get-log` returns the whole file. J-Wicket strips control characters (keeping tab), drops
leading and trailing blank lines, keeps the newest 5000 lines (`MAX_WINDOW`), then applies the
cursor and the substring filters in the daemon before anything is sent to the browser. A regular
expression from the browser never runs on the device.

```json
{"meta": {"...": "...", "source": "file:traffic-log", "min_interval_s": 1.5, "structured_data": true, "self_noise": "..."},
 "log": {"status": "ok", "lines": ["..."], "cursor": "4211:3f9a0c21b7d4", "reset": false, "dropped": 0, "window": 4211, "scanned": 12}}
```

```mermaid
stateDiagram-v2
    [*] --> FirstRead: no cursor
    FirstRead --> Following: scan whole window, return newest matching lines, issue cursor
    Following --> Following: line at cursor position has the cursor digest, return lines after it
    Following --> Searching: position moved (window slid or file rewritten)
    Searching --> Following: digest found further back, return lines after it
    Searching --> Reset: digest not in window (rotated)
    Reset --> Following: reset true, return newest matching lines of the new window
```

- `dropped` counts matching lines beyond `lines` (oldest dropped first).
- `window` is the number of lines kept; `scanned` the number examined after the cursor.
- The cursor is the line count and a SHA-256 prefix of the last line. When the window slides, the
  search finds the most recent identical line, so repeated identical lines can be skipped. Lines
  that rotated out between two polls are not recovered; `reset` says so.

**On-box report** (`source=report`): `type` is one of `session-all` (default), `session-close`,
`session-create`, `session-deny`, `screen`, `idp-all`, `utm-all`, `ipsec-vpn`, `threat`, `all`, and
selects RPC `get-sec-log-report-detail-<type>`. Parameters: `count` (default 500, 1..2000),
`start` and `stop` (`YYYY-MM-DDTHH:MM:SS`), `expression` (at most 256 bytes of
`A-Z a-z 0-9 _ . : / = ! < > & | ( ) -` and space). They are sent as RPC parameters
`count`, `start_time`, `stop_time`, `expression`, never as CLI text. The response's `log` is
`{status, lines (newest 2000), type, cursor: null, reset: false}`. There is no cursor: the browser
moves `start` to the newest line's time and removes duplicates. `source=report` is accepted even
when `sources.databases` does not offer it; the device's answer then decides the state.

**RE buffer** (`source=buffer`): `since` (`YYYY-MM-DD.HH:MM:SS`) is sent as `newer_than` to
`get-security-log-information`. The response's `log` is `{status, cursor: null, reset: false,
events, lines, disabled}`: `events` are structured (`time, id, message, severity, result, user,
interface, protocol, policy, src, sport, dst, dport, process, pid`), `lines` render each as
`<time> <process>[<pid>]: <id>: <message>`, both capped at the newest 2000. `disabled` is true when
the reply carries `security-logs-disabled`.

**Explicit states for logs:**

| State | Where it shows |
| --- | --- |
| `denied`, `unsupported`, `failed` | `sources.status`, or `log.status` with `lines: []` and `message` |
| `reset: true` | File rotated or rewritten; the browser must say so |
| `dropped > 0` | More lines matched than were returned |
| `assumed: true` | `messages` is not in the configuration; reading it may fail |
| `disabled: true` | Security logging is disabled (buffer) |
| No `report` / no `buffer` in `databases` | Not configured or not offered on this model; `traffic.where` explains |
| `effective_mode: null` | Mode not set and the model's default is not documented |
| 400 | Unknown file, bad cursor, too many terms, bad report type, time or expression |

### 5.5 Rate limits and device cost

| Read | Minimum interval (server) | RPCs per poll |
| --- | --- | --- |
| Sessions, unfiltered | 1.5 s per operator | 2 (summary, list); 1 when refused |
| Sessions, filtered | 1.5 s per operator | 2, plus 1 unfiltered summary at most every 30 s |
| Log file | 1.5 s per operator per source | 1 `get-log` (whole file), plus the sources refresh: 1 configuration read every 60 s and 1 software read every 10 min |
| Report, buffer | 1.5 s per operator per source | 1, plus the sources refresh |
| Sources | cache 60 s | 2 on a cache miss |

The browser polls at `suggested_interval_s` (5 s) by default, offers 2, 5, 10 and 30 s, and never
goes below `meta.min_interval_s`. Each RPC can add a `UI_NETCONF_CMD` line on the device (7.12). Each
operator's reads are serialised on their session lock, and the session cap (`max_sessions`,
default 4) bounds concurrency.

### 5.6 Audit

- `read_sessions` on **every** sessions poll: user, source address, the device filters, row count,
  status. At 5 s that is 720 records an hour per open Sessions view (open question 9).
- `read_log` on the first read of a source only (no `cursor`, `start` or `since`): user, source,
  log source, status.
- `session_lost` when the device session ends during a read.

## 6. Data sources

| Read | RPC and parameters | Permission | Status |
| --- | --- | --- | --- |
| Session list | `get-flow-session-information` with `source-prefix`, `destination-prefix`, `source-port`, `destination-port`, `protocol`, `application`, `interface` (PyEZ keywords with underscores) | `view` (**verified**, "Required Privilege Level: view", [show security flow session](https://networkingdocs.hpe.com/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-security-flow-session.html)) | RPC name **verified** (`\| display xml rpc` in a [Juniper community post](https://community.networking.hpe.com/blogs/karel-hendrych/2024/02/07/using-junos-snmp-utility-mib-on-juniper-srx); XML API Explorer 25.4 catalog). CLI options **verified**. XML parameter element names **inferred** (CLI keyword = element name). `protocol` element **verified** |
| Summary and filtered summary | Same RPC with `summary` (plus filters) | `view` | **verified** (`summary=True` in the community post and Juniper's [HealthBot rules](https://github.com/Juniper/healthbot-rules/blob/master/juniper_official/Security/srx-flow-session-summary-netconf.rule)) |
| Syslog file | `get-log` with `filename` | `trace` (**verified**, [show log](https://networkingdocs.hpe.com/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-log.html), [trace permission](https://networkingdocs.hpe.com/documentation/us/en/software/junos/user-access/topics/concept/access-privilege-permission-bits-trace.html)) | RPC, parameter and reply `file-content` **verified** (XML API Explorer 24.4; [24.4R2 RPC YANG](https://raw.githubusercontent.com/Juniper/yang/master/24.4/24.4R2/native/conf-and-rpcs/junos-es/rpc/models/junos-es-rpc-log@2024-01-01.yang)). No offset or tail parameter in any catalogued release: **verified**. Text encoding of the reply (CDATA, leading newline): **unknown** |
| On-box report | `get-sec-log-report-detail-<type>` with `count`, `start-time`, `stop-time`, `expression` | CLI pages say `view` (**verified**, [in-detail](https://networkingdocs.hpe.com/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-security-log-report-in-detail.html)); the RPCs are on no permission-bit page: **unknown** | RPC names and inputs **verified** in the [24.4R2 security RPC YANG](https://github.com/Juniper/yang/blob/master/24.4/24.4R2/native/conf-and-rpcs/junos-es/rpc/models/junos-es-rpc-security@2024-01-01.yang). CLI-to-RPC pairing **inferred**. The YANG has no `output`, so the reply wrapper is **unknown**; J-Wicket reads text from `output` or `file-content` |
| RE buffer | `get-security-log-information` with `newer-than` | Listed under the `security` and `security-control` bits (**verified**, [security permission](https://networkingdocs.hpe.com/documentation/us/en/software/junos/user-access/topics/concept/access-privilege-permission-bits-security.html)); the CLI page says `view` (**verified**, [show security log](https://networkingdocs.hpe.com/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-security-log.html)) | RPC, inputs, output elements (`security-event`, `security-event-*`, `process/{name,pid}`, `security-logs-disabled`) **verified** in YANG |
| Log configuration | `get-configuration` committed with `LOGS_FILTER` | as configuration | `system syslog file` tree **verified**; `security log` leaves (`mode`, `report`, `stream/host`, `format`) **verified** in YANG; the XML form of `stream host` (J-Wicket reads `ipaddr`, `name` or text) **inferred** |
| Model | `get-software-information` | not recorded | as Spec 001 |

All of these are in `ALLOWED_RPCS` ([`session.py`](../../src/jwicket/junos/session.py)); every
entry starts with `get-`.

## 7. Junos semantics this feature depends on

Sources for this section: Juniper CLI references and topics linked inline, Juniper's 24.4R2 YANG,
the Juniper System Log Explorer, Juniper's HealthBot rules, and the corpus in
[`tests/fixtures/log-samples/juniper-docs.txt`](../../tests/fixtures/log-samples/juniper-docs.txt).

### 7.1 Session filters

- The CLI options `source-prefix`, `destination-prefix`, `source-port`, `destination-port`,
  `protocol`, `application` ("Predefined application name"), `interface` ("Name of incoming or
  outgoing interface"), and many more (`policy-id`, `zone`, `nat`, `session-state`, `node`,
  `bytes-more-than`...) exist: **verified** ([show security flow session](https://networkingdocs.hpe.com/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-security-flow-session.html)).
  The release that added the range filters is **unknown**.
- Several filters in one request are ANDed: **inferred**. No page states it.
- There is no count, limit or page option: **verified** by its absence from the current syntax
  block. CLI pipes (`| count`, `| last`) run after the full output is produced and do not reduce
  the transfer: **inferred**.

### 7.2 Summary and filtered summary

- Unfiltered summary: `flow-session-summary-information` with `active-sessions` and
  `max-sessions`, per node in a cluster (`multi-routing-engine-item/re-name`) and per SPU on
  multi-SPU platforms (`flow-fpc-pic-id`): **verified** (Juniper HealthBot tables).
  `failed-sessions` is **inferred** by symmetry.
- Filtered summary: a `flow-session-information` with `displayed-session-valid`, `-pending`,
  `-other` and `displayed-session-count` under `security-flow-information`: **verified** (verbatim
  `| display xml` in the community post). That is why J-Wicket can count before it lists.
- The device reports its own `max-sessions`; J-Wicket does not hard-code platform limits.

### 7.3 Per-session reply elements

`flow-session`, `session-identifier`, `status`, `session-state`, `policy`, `timeout`,
`configured-timeout`, `start-time`, `duration`, `flow-information` with `direction`,
`source-address`, `source-port`, `destination-address`, `destination-port`, `protocol`,
`interface-name`, `pkt-cnt`, `byte-cnt`: all **inferred** from the CLI field names. No Juniper page
or official repository found so far shows a per-session `| display xml`. The XML API Explorer
lists two different `flow-session` definitions, so the shape varies by context. Q-REL-01.

### 7.4 Cost of listing, and the refusal threshold

- For a list request the SPUs send every matching session to the routing engine, which can drive
  RE CPU to idle 0 percent: **verified** as a Juniper support quote of KB28956 in a
  [community thread](https://community.networking.hpe.com/discussion/info-over-logs) (KB28956
  itself is behind the support portal and was not read).
- The summary is cheap compared with the list: **inferred** (Juniper's own monitoring polls it).
- `MAX_UNFILTERED = 5000` is J-Wicket's choice, not a Junos number. Despite its name it applies to
  the matching count with or without filters. Q-LOAD-02 measures list cost at 1k, 5k and 20k
  sessions and decides whether 5000 stands.

### 7.5 Clusters, SPUs and Multinode HA

- In a chassis cluster each session appears on both nodes, `Active` on one and `Backup` on the
  other; the backup copy shows zero counters: **verified** (samples on
  [show security flow session extensive node](https://networkingdocs.hpe.com/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-security-flow-session-extensive-node.html)).
  J-Wicket keeps both copies, distinguishes them by `location`, and leaves hiding backup copies to
  the browser. Which XML element carries Active/Backup is **unknown**; it lands in `extra` if it is
  a scalar. J-Wicket does not send `node primary` or `node local`, so cluster lists transfer both
  copies.
- `parse_summary` sums `active-sessions` over nodes. Whether a node's count includes its backup
  copies is **unknown**; if it does, the gauge and the refusal count double on a cluster.
  Q-HA-01.
- On multi-SPU platforms a `flow-fpc-pic-id` label (text starting "on FPC") groups the sessions
  that follow it: **verified** label, pairing by document order **inferred**.
- Four-node Multinode HA adds `HA State: Warm` and domain/node ids: **verified** in CLI samples,
  not parsed (Q-HA-03).

### 7.6 NAT, policy name and time fields

- The reverse (`Out`) wing carries the translated addresses: **verified** by sample
  ([flow session nat](https://networkingdocs.hpe.com/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-security-flow-session-nat.html)).
  J-Wicket's rule, source NAT when `out.dst/dport` differs from `in.src/sport` and destination NAT
  when `out.src/sport` differs from `in.dst/dport`, is **inferred**.
- "Policy name: Name and ID of the policy that the first packet of the session matched", printed
  `name/id`: **verified**. Pre-ID sessions show `pre-id-default-policy/n`; a stand-alone tunnel
  session shows `Policy name: N/A`: **verified** samples.
- `Start time` is documented as an offset from system start, but newer samples look like epoch
  seconds: the meaning varies (**verified** samples, **unknown** rule). The UI derives age from
  `duration`.

### 7.7 Where traffic logs are, by security log mode

The table is J-Wicket's model, built from the statements below it; what the buffer holds in each
mode is inferred (7.10).

| Effective mode | Traffic logs on the box | J-Wicket sources |
| --- | --- | --- |
| `event` | Through the routing engine: the security log buffer, and any syslog file whose contents take them | `buffer`; syslog files (for example one with `match RT_FLOW`) |
| `stream` | Not on the RE. Sent to the stream hosts. Kept locally only by on-box reporting (`security log report`) or a stream `file` destination | `report` when configured and not SRX5000; otherwise none, and `where` says so |
| `stream-event` | Both | `report` (if configured) and `buffer` |
| unknown | Not stated | none; `where` asks the operator to check `show security log` |

- `mode (event | stream | stream-event)`; stream-event from 20.2R1: **verified**
  ([mode statement](https://networkingdocs.hpe.com/documentation/us/en/software/junos/cli-reference/topics/ref/statement/security-edit-mode-security-logging.html)).
- Documented defaults: event on vSRX; stream on SRX1400, SRX1500 (from 15.1X49-D140), SRX3400,
  SRX3600, SRX4100, SRX4200, SRX5400, SRX5600, SRX5800; stream on SRX300, SRX320, SRX340, SRX345,
  SRX550, SRX550M from 18.3R3 except in 18.4R1, 18.4R2, 19.1 and 19.2R1: **verified** (same page).
  A general statement elsewhere says "The default logging mode is stream mode": **verified**, and
  contradicts the vSRX line. SRX1600, SRX2300, SRX4120, SRX4300, SRX4600, SRX4700 are not named.
  J-Wicket shows the documented default with its basis and never presents it as configured.
  Q-LOG-01 records the effective behaviour per platform.
- On-box reporting needs `security log mode stream` and `security log report`: **verified**
  ([Feature Explorer 8049](https://apps.juniper.net/feature-explorer/feature/8049),
  [SRX1600 logging](https://networkingdocs.hpe.com/documentation/us/en/software/platform/srx1600-srx4120-srx4300-configuration-essentials/topics/concept/srx1600-srx4120-srx4300-logging-snmp-telemetry.html)).
  SRX5000 is not in its platform list, and J-Web's Logs pages are not available on SRX5000:
  **verified**. Without an SSD the database lives in memory and is lost at reboot; cluster nodes do
  not synchronise it: **verified**
  ([system logging for a security device](https://networkingdocs.hpe.com/documentation/us/en/software/junos/network-mgmt/topics/topic-map/system-logging-for-a-security-device.html)).
  Factory default since 19.3R1 does not include it: **verified** (the same page also says the
  opposite; the release-specific sentence is taken).

```mermaid
flowchart TD
    C["security log mode (configured, else documented default for the model)"] --> E{"Mode"}
    E -- event --> EV["Offer RE buffer; RT_FLOW lines appear in syslog files that take them"]
    E -- stream --> ST{"security log report set and not SRX5000?"}
    E -- stream-event --> SE["Offer RE buffer"]
    SE --> ST
    ST -- yes --> RP["Offer on-box report"]
    ST -- no --> OFF["Say: streamed to the listed hosts, not stored here"]
    E -- unknown --> UK["Say: mode not set, default not documented, check show security log"]
```

### 7.8 System log files and `get-log`

- `<get-log><filename>name</filename></get-log>` returns the whole file in `file-content`, with no
  offset, start, line-count or tail parameter: **verified**. Pipes are not usable over NETCONF
  except `| display xml rpc`: **verified** (PyEZ `Device.cli()` docstring,
  [py-junos-eznc](https://github.com/Juniper/py-junos-eznc/blob/master/lib/jnpr/junos/device.py)).
  So each poll moves the whole file.
- It needs the `trace` permission: **verified**. Predefined classes: `operator` = clear, network,
  reset, trace, view; `read-only` = view: **verified**
  ([login classes](https://networkingdocs.hpe.com/documentation/us/en/software/junos/user-access/topics/topic-map/junos-os-login-class-overview.html)).
  So a `read-only` user is denied: **inferred**. How Junos words that denial is **unknown**
  (Q-AUTH-03). J-Wicket never reads `/var/log` as the daemon's account.
- Whether `get-log` refuses names outside `/var/log`: **unknown**. J-Wicket only sends names from
  the configuration that pass a strict pattern.
- Default rotation is 1 MB and 10 files: **verified**
  ([system logging overview](https://networkingdocs.hpe.com/documentation/us/en/software/junos/network-mgmt/topics/topic-map/system-logging.html)).
  At defaults a poll moves at most about 1 MB; larger configured sizes move more. Q-LOAD-01.
- Line formats J-Wicket must parse in the browser: BSD default, `explicit-priority`
  (`%FACILITY-n-TAG`), `time-format year millisecond`, RFC 5424 `structured-data` with
  `<pri>` (severity = pri & 7): **verified** samples in the corpus.

### 7.9 On-box reporting and its `expression` filter

- `expression` is a leaf-list of type `jt:policy-algebra`, "Expression to handle multiple
  options": **verified** (YANG). Operators `=`, `!=`, `>=`, `<=`, `&&`, `||`, parentheses and
  netmask-aware addresses, from 23.1R1, "The total length of the expression is limited to 256
  bytes including the brackets": **verified**
  ([Feature Explorer 6853](https://apps.juniper.net/feature-explorer/feature/6853)). Example:
  `show security log report in-detail all expression ( source-address=192.0.3.2/24 && ( session-id=785 || session-id=786 ))`
  (**verified**, in-detail page).
- The accepted keys are the structured-data keys (`source-address`, `destination-port`,
  `policy-name`, `session-id`...): **inferred**. The browser planner uses `source-address`,
  `destination-address`, `source-port`, `destination-port`, `protocol-id`, `policy-name`,
  `source-zone-name`, `destination-zone-name`, `session-id`, `application`, `username`, `reason`.
- J-Wicket's character set is its own restriction, stricter than Junos's.
- Feature Explorer documents `expression` for `in-detail all` and `summary all`; another page says
  "the 'all' option does not have any filter except start-time and stop-time". Which types accept
  `expression` is **unknown** (open question 5).
- `count` is 1..65535 and `start-time` / `stop-time` are `YYYY-MM-DDTHH:MM:SS`: **verified** (YANG).
  Which records `count` returns without `start-time` (oldest or newest first), and the time zone
  of `start-time`: **unknown** (open question 6).
- Report output is RFC 5424-style text with no SD-ID, values sometimes unquoted, addresses
  sometimes with `/len`: **verified** samples (including the device's `RT_LOG_SELF_TEST` lines with
  fake values).

### 7.10 Security log buffer

`show security log` "Display[s] security event logs": **verified**
([show security log](https://networkingdocs.hpe.com/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-security-log.html)).
`security log limit`, "Limit number of security log entries to keep in memory", defaults to
10000: **verified** (YANG). That `show security log` reads that routing-engine buffer, and that the
buffer holds traffic events only in event or stream-event mode: **inferred**. Whether stream-event puts RT_FLOW there:
**unknown** (Q-LOG-01).

### 7.11 RT_FLOW fields and close reasons

- `session-id` and `session-id-32` are both used for the session id; `_LS` tags carry
  `logical-system-name`; the CLOSE template grew from 50 attributes in 22.2R1 to 57 in 24.4R1:
  **verified** (System Log Explorer). The browser parses structured data by key and BSD text only
  for its documented prefix.
- Close reasons, verbatim and separated here by semicolons (one value contains a comma): unset;
  TCP CLIENT RST; TCP SERVER RST; TCP FIN; response received; ICMP error; aged out; ALG; HA; idle
  Timeout; auth; IDP; synproxy failure; synproxy limit; parent closed; CLI; CP NACK; CP delete;
  policy delete; fwd session; multicast route change; first path reroute, session recreated;
  source NAT allocation failure; other; error create IKE pass-through template; IKE pass-through
  child session ageout; sess timeout on pending state; unknown: **verified** ([flow session monitoring](https://networkingdocs.hpe.com/documentation/us/en/software/junos/flow-packet-processing/topics/topic-map/security-flow-session-and-error-handling.html),
  Table 2). A policy deny is not a close reason; it is a separate deny event. Newer releases may
  add reasons, so the list is open-ended.
- `session-id-32` in logs is the same number as `Session ID` in the session table: **inferred**.

### 7.12 J-Wicket's own reads in the logs (`UI_NETCONF_CMD`)

- Junos logs `UI_NETCONF_CMD`, "User '`<username>`' used NETCONF client to run command
  '`<command>`'", severity info, facility LOG_AUTH: **verified**
  ([System Log Explorer](https://apps.juniper.net/syslog-explorer/)).
- So every J-Wicket RPC adds a line to any syslog file that takes authorization info:
  **inferred**. Tailing such a file at 5 s means the file always has new lines, many of them
  J-Wicket's own. The server sends `self_noise` text; the browser hides the signed-in user's own
  `UI_NETCONF_CMD` lines by default and counts them. Volume is Q-LOAD-03.

## 8. UI requirements

The Sessions and Logs views are part of UI v2. These are requirements. "Engine" means the
pure-logic module exists and is unit-tested; "open" means not yet confirmed in the view. The views
are built in the working tree, not yet committed, and no requirement has been checked in a browser
(AC-004-20).

**Shared**

| ID | Requirement | Status |
| --- | --- | --- |
| UI-004-01 | One query language for Sessions, Logs and Policies: `OR`/`or`/`\|\|`, `AND`/`and`/`&&` or juxtaposition, `NOT`/`not`/`-`/`!`, parentheses, `key op value` with `= != >= <= > < ~` (`~` regex, browser only), `key:value`, bare text, quoted strings, `/regex/flags`, `v1\|v2` alternatives, CIDR-aware addresses, sizes with k/M/G, durations with s/m/h, `*` wildcards. Parse errors inline with position, never thrown | Engine |
| UI-004-02 | Pushdown planner: only positive, top-level AND-ed `=`/`:` terms on device-capable keys go to the device (Sessions: `src dst sport dport proto app iface`; log files: up to 4 plain words to `contains`, negated words to `exclude`; reports: an `expression`). Everything else filters in the browser. Each term is a chip, gold "device" or sky "browser", and one sentence explains the split | Engine; chips open |
| UI-004-03 | Autocomplete for keys, operators and known values (zones, policies, applications, interfaces from the inventory and current data), keyboard navigable | Engine (`suggest`); widget open |
| UI-004-04 | Live is incremental polling: default 5 s, choices 2, 5, 10, 30 s, never faster than `meta.min_interval_s`; pause and resume; polling stops while the tab is hidden; 429 `Retry-After` is honoured; a LIVE/PAUSED pill and the last read time are always visible | Shell API module; views open |
| UI-004-05 | View, filters and selection live in the URL hash, never in storage. Saved queries (query text only) may be kept in `localStorage` after an explicit "Save query"; never device data. Query text can name addresses, policies and users, so this is open question 14 for the security reviewer | Shell (hash routing); saved queries open |
| UI-004-06 | Fixture banner whenever `meta.fixture` is true; read-as chip with the `lab-token` variant | Shell |

**Sessions view** (`/api/sessions`)

| ID | Requirement | Status |
| --- | --- | --- |
| UI-004-10 | Header strip: active-of-max gauge from `summary`; sessions-per-poll sparkline; new and ended since the last poll; "device returned N of M (limit)" when `truncated`; the device filters in force | Open (gauge and sparkline widgets exist) |
| UI-004-11 | `sessions.status == "refused"`: a card with the matching count, why J-Wicket refused (the data-plane-to-RE transfer), and one-click narrowing suggestions; never an empty table | Open |
| UI-004-12 | `summary` or `sessions` in `denied`, `unsupported` or `failed`: a state card with the server message; never an empty table | Open |
| UI-004-13 | Virtualised table, smooth at 2,000 rows: status dot, ID, policy (link to the policy in Spec 001's view), zones from to (from the inventory's policy-to-zone map), protocol, source ip:port, destination ip:port, NAT badge (SNAT translated source, DNAT translated destination), application, in and out interfaces, bytes each way, packets, live rate from deltas between polls, duration, remaining timeout. Sortable, with a "hold order" toggle so rows do not jump; column chooser; density toggle | Open |
| UI-004-14 | Click any value to filter by it, Alt/Option-click to exclude; hover shows `=` and `≠` buttons | Open |
| UI-004-15 | Live diff keyed by `id`: new rows flash; rows gone from the latest poll stay one poll as "ended", struck through, then leave. Per-session byte history is kept in memory for this tab only | Open |
| UI-004-16 | Chassis clusters: "hide backup copies" on by default, using `location` and any state in `extra`; the count of hidden copies shown | Open |
| UI-004-17 | Facets: top 8 by source, destination, destination port, application, policy, interface over the current result; click to filter, Alt-click to exclude | Open |
| UI-004-18 | Detail panel: flow diagram client, ingress interface and zone, SRX with policy and NAT translation in both directions, egress interface and zone, server; both wings' counters; timeouts; state; location; `extra` fields; live bytes sparkline; "Open policy"; "Show logs for this session" (Logs with `session:<id>` or the 5-tuple); "Copy as CLI" `show security flow session session-identifier <id>` built from a validated numeric id | Open |
| UI-004-19 | Export the current filtered view as CSV or JSON in the browser, stamped with device, user, read time and the query | Open |

**Logs view** (`/api/logs/sources`, `/api/logs`)

| ID | Requirement | Status |
| --- | --- | --- |
| UI-004-30 | Source picker from `sources.files` (name, contents, match, structured-data, assumed) and `sources.databases` | Open |
| UI-004-31 | A "Where are my traffic logs?" card from `sources.traffic`: mode, whether configured or the documented default and its basis, streams with hosts, on-box reporting, and the `where` sentence. Off-box streaming is said plainly with the stream host | Open |
| UI-004-32 | Toolbar: query bar; event family toggles with counts (Flow create, Flow close, Flow deny, Screen, IDP, VPN (KMD), Commit/CLI (UI_*), Auth (sshd/login), SNMP, Chassis, Other); Follow; wrap; pause; lines in window | Engine (`FAMILIES`); view open |
| UI-004-33 | Histogram above the stream, events per time bucket stacked by family, in SVG; brushing adds a `time` filter, double-click clears | Open |
| UI-004-34 | Virtualised monospace stream; every visible line tokenised by `logparse.tokenize` and highlighted by token type (`ts host daemon pid tag sdid key val ip port arrow proto zone policy iface nat num str bad good user text pri`); tokens concatenate back to the exact line | Engine; view open |
| UI-004-35 | Click any token to filter by it, Alt to exclude; search matches marked | Open |
| UI-004-36 | Decoded panel: for RT_FLOW lines (structured data and BSD text) a one-sentence decode, the field table, and a session timeline (CREATE, CLOSE, DENY with the same session id) with a link to the live session if it is in the last Sessions poll; generic lines as a key/value table; "Copy line" | Engine (`decode`); view open |
| UI-004-37 | Close-reason badges from the verified list in 7.11; unknown reasons shown verbatim; deny events styled as denies, not as a close reason | Open (open question 8) |
| UI-004-38 | File tail: when not following, a "N new lines" pill; `reset: true` shows a visible rotation notice; `dropped > 0` says how many matching lines were not returned | Open |
| UI-004-39 | Report and buffer: live by moving `start` (or `since`) to the newest line's time and removing duplicates | Open |
| UI-004-40 | The signed-in user's own `UI_NETCONF_CMD` lines hidden by default with a counter ("N of your own J-Wicket reads hidden · show") and the `self_noise` text; other users' lines are never hidden | Engine (`isSelfRead`); view open |
| UI-004-41 | Log states: `denied` says the Junos `trace` permission is needed for syslog files; `unsupported`, `failed`, `disabled`, `assumed`, `effective_mode: null` each have a card | Open |
| UI-004-42 | Beat the J-Web 24.4 baseline: live tail, highlighting, typed query with autocomplete, no export cap, saved queries, NAT and session drill-down | Open |

**Accessibility and performance** (both views): keyboard everything (`/` focus query, `space`
pause, `j`/`k` move, `Enter` open, `n`/`N` next and previous match, `f` follow); `role="grid"` with
`aria-rowcount` and `aria-rowindex`; a polite live region announcing new sessions at most every
10 s; AA contrast in both themes; animations off under `prefers-reduced-motion`; main-thread work
per poll under about 8 ms for 2,000 rows on a laptop.

## 9. Security considerations

- **Read-only.** Only `get-*` RPCs are allowlisted. Clearing sessions and `monitor security flow`
  are excluded by design.
- **No injection path to the device.** Every filter value is parsed and normalised before it
  becomes an RPC parameter (addresses through `ipaddress`, ports and protocol numbers as integers,
  names through strict patterns). PyEZ sends parameters as XML elements; J-Wicket never builds CLI
  text. Browser regular expressions never reach the device; substring filters run in the daemon.
- **No file paths from requests.** A log file is read only if its name is in the device's own
  `system syslog file` configuration and matches a strict pattern (`test_validate_file_allowlist`,
  `test_log_file_allowlist_and_validation`).
- **Logs are attacker-influenced text.** Hostnames, URLs in web-filter logs and user names from
  failed logins can be chosen by an attacker. Control characters are stripped server-side
  (`test_control_characters_removed`); the browser renders every token with `textContent`, builds
  filters as query text, and builds any URL only from validated values. CSP with Trusted Types
  backs this up.
- **Exposure follows Junos.** With the `netconf` backend an operator sees only what their class
  gets from `show log`, `show security log` and the reports. Logs can hold user names, source
  addresses and commands other administrators typed (`UI_CMDLINE_READ_LINE`). With the
  `lab-token` backend reads run as the daemon's account (in the spike, a super-user class), which
  is why that backend is loopback-only and labelled.
- **Protecting the routing engine.** Refusal above 5,000 matching sessions; row cap 2,000; log
  window 5,000 lines; returned lines capped at 2,000; 1.5 s minimum per endpoint and source per
  operator; one RPC at a time per operator; session cap. Known weaknesses: the refusal fails open
  when the count is unknown (open question 1); `get-log` moves the whole file every poll with no
  size cap in J-Wicket (open question 7).
- **Audit volume.** Sessions polling writes one audit record per poll (open question 9).
- **Browser storage.** No device data in storage; per-session history lives in memory for the
  tab; exports are explicit downloads ([ADR 0007](../adr/0007-offline-capable-meaning.md)). The one
  thing kept is query text the operator saved (UI-004-05), which can still name addresses,
  policies and users on a shared workstation (open question 14).
- **Hiding is display only.** Hiding the user's own `UI_NETCONF_CMD` lines is a browser filter with
  a visible counter; it never hides another user's lines and never removes anything server-side.
- **Regex in the browser.** `~` and `/regex/` run in the operator's own tab; a pathological
  pattern can stall that tab, not the device.

## 10. Acceptance tests

"Met (fixtures)" means the named tests pass against synthetic fixtures; "Met (unit)" means a pure
browser module passes its unit tests. Nothing is met on a device. Test names are `Class.method`
in [`test_live.py`](../../tests/test_live.py) unless another file is named.

| ID | Criterion | Tests | Status |
| --- | --- | --- | --- |
| AC-004-01 | Filters map to RPC parameters, host bits normalised, bad values refused (400), unknown keys ignored, limit clamped | `SessionFilterTests.test_valid_filters_map_to_rpc_parameters`, `.test_host_bits_are_normalised_not_rejected`, `.test_bad_values_are_refused`, `.test_limit`, `LiveHttpTests.test_sessions_pushdown_filters`, `.test_sessions_bad_filter_is_400` | Met (fixtures). Element names: Q-REL-01 |
| AC-004-02 | Rows are refused when the matching count exceeds `MAX_UNFILTERED`, and allowed when a narrower filter brings it under | `LiveHttpTests.test_refusal_follows_the_matching_count` | Met (fixtures). Threshold: Q-LOAD-02. Fail-open when the count is unknown is **not** tested (open question 1) |
| AC-004-03 | A filtered read keeps the table-wide gauge | `LiveHttpTests.test_filtered_read_keeps_the_table_wide_gauge` | Met (fixtures) |
| AC-004-04 | Wings, policy name and index, source NAT, cluster and SPU locations with distinct ids, truncation stated, summary summed over nodes | `SessionParseTests.test_wings_policy_and_source_nat`, `.test_cluster_and_spu_locations_keep_ids_distinct`, `.test_limit_truncates_and_says_so`, `.test_policy_without_index`, `.test_summary_sums_nodes` | Met (fixtures) on **inferred** element names |
| AC-004-05 | Sign-in required; 1.5 s rate limit with `Retry-After`; non-root scope refused | `LiveHttpTests.test_requires_sign_in`, `.test_sessions_read_and_rate_limit`, `.test_sessions_scope_other_than_root_refused` | Met (fixtures) |
| AC-004-06 | Denied reads are explicit states for sources, log lines and sessions | `LiveHttpTests.test_denied_log_read_is_an_explicit_state` | Met (fixtures). Real denial wording: Q-AUTH-03 |
| AC-004-07 | Sources: configured files only, path-like names dropped, `messages` assumed, structured-data flag, stream mode explained with its host | `LogSourceTests.test_files_and_stream_mode`, `.test_messages_assumed_when_not_configured`, `.test_validate_file_allowlist`, `ReportHttpTests.test_sources_explain_stream_mode`, `LiveHttpTests.test_log_sources_and_tail` | Met (fixtures) |
| AC-004-08 | Documented default mode per model; `null` where undocumented | `ModeAndExpressionTests.test_default_modes` | Met (unit). Effective behaviour: Q-LOG-01 |
| AC-004-09 | `report` offered only when configured in stream mode; `buffer` in event mode | `LiveHttpTests.test_report_source_is_offered_only_when_configured`, `.test_event_mode_buffer_source`, `ReportHttpTests.test_sources_explain_stream_mode` | Met (fixtures) |
| AC-004-10 | Tail: last N on first read; only new lines after; window slide found by digest; rotation is a reset; substring filters with drop count; cursor and term validation; control characters removed; reply text shapes | `TailTests.*` (8 tests) | Met (unit) |
| AC-004-11 | Unknown files, bad cursors, bad `lines` refused with 400 | `LiveHttpTests.test_log_file_allowlist_and_validation` | Met (fixtures) |
| AC-004-12 | `contains` filters on the server side of the wire | `LiveHttpTests.test_log_contains_filter_pushdown` | Met (fixtures) |
| AC-004-13 | Report read; type, expression length and characters, times and count validated | `ReportHttpTests.test_report_read_and_validation`, `ModeAndExpressionTests.test_expression_validation` | Met (fixtures). Reply wrapper: Q-REL-01 |
| AC-004-14 | Buffer events and rendered lines; `since` format enforced; `self_noise` present | `ModeAndExpressionTests.test_buffer_events_shape`, `LiveHttpTests.test_event_mode_buffer_source` | Met (fixtures) |
| AC-004-15 | Query language, typed comparisons, CIDR matching, sessions/logs/policies fields | [`query.test.mjs`](../../tests/js/query.test.mjs): "terms: key:value, key=value, comparisons, bare values", "CIDR-aware address matching (IPv4 and IPv6)", "sizes, durations and integer comparisons", "logs fields over parsed lines: severity order, NAT, time and age", "FIELDS cover each view with typed keys and getters", and the rest of the file | Met (unit) |
| AC-004-16 | Pushdown planner for sessions, log files and reports, with the 256-byte AND-prefix fallback | `query.test.mjs`: "sessions pushdown: positive top-level AND-ed ":"/"=" terms on device keys", "sessions pushdown keeps negations, ORs, alternatives, wildcards, ranges and bad values in the browser", "logs file pushdown: contains / exclude, at most 4 terms of 120 characters", "logs report pushdown: the J-Web expression syntax", "logs report pushdown falls back to the largest AND-prefix within 256 bytes", "time terms set report start/stop and the buffer "since", and stay in the browser" | Met (unit) |
| AC-004-17 | Every corpus line tokenises back to exactly itself | [`logparse.test.mjs`](../../tests/js/logparse.test.mjs): "every corpus line tokenises back to exactly itself", "tokenisation stays lossless on every prefix of every corpus line, and with hints" | Met (unit) on 46 documentation lines and the development-server corpus |
| AC-004-18 | RT_FLOW decoding (structured data, BSD text across releases, buffer), other families, formats | `logparse.test.mjs`: "every documented RT_FLOW line decodes with the right session id, 5-tuple, policy, zones and NAT", "every dev-server RT_FLOW line decodes correctly (structured data, BSD text and buffer)", "RT_FLOW BSD positional bodies across releases (24.4 template, NAT rule types, LSYS)", "RFC 5424: PRI severity and facility, SD-ID, no SD-ID, bracketless, no PRI", "BSD: default, explicit-priority, year and millisecond time formats, year inference", "decode: screen, IDP, commit, configuration mode, login, VPN, link" | Met (unit) |
| AC-004-19 | Own-read detection: `UI_NETCONF_CMD` lines of the signed-in user only | `logparse.test.mjs`: "isSelfRead: UI_NETCONF_CMD lines of the signed-in user only" | Met (unit); hiding in the view open |
| AC-004-20 | UI requirements UI-004-01 to UI-004-42 in a browser against the development server (`branch`: event mode, syslog files, buffer; `cluster-lsys`: cluster, stream mode, on-box report; `auditor`), with no console errors or CSP violations, and smooth at 2,000 rows | Browser check against the development server, by hand or driven by an external, development-only browser tool ([CONTRIBUTING, browser rules](../../CONTRIBUTING.md#browser)), screenshots at desktop and phone widths | **Not met**: the views are built in the working tree, not yet committed, and not yet checked in a browser |
| AC-004-21 | AC-004-01 to -14 pass against recorded replies from a qualified platform, including a cluster and a multi-SPU platform | Q-REL-01 recorded fixtures | **Not met**: no recorded reply exists |
| AC-004-22 | On a qualified platform, listing up to `MAX_UNFILTERED` sessions at the default interval keeps RE CPU and mgd within the Q-LOAD-02 pass criterion | Q-LOAD-02 | **Not met** |

## 11. Qualification needed

Definitions, methods and pass criteria are in [governance.md](../governance.md).

| Test | What it settles for Spec 004 |
| --- | --- |
| Q-REL-01 | Recorded `get-flow-session-information` replies: list (brief), summary, filtered summary, on a branch device, a cluster and a multi-SPU platform; `\| display xml rpc` for each filter used; `get-log` reply encoding; the `get-sec-log-report-detail-*` reply wrapper; `get-security-log-information` reply; the error each returns when denied or unsupported |
| Q-LOAD-02 | List cost at 1k, 5k and 20k sessions; whether `MAX_UNFILTERED = 5000` stands, per platform class |
| Q-LOAD-01 | Sustained polling of sessions and of `get-log` on a 1 MB and a larger file: RE CPU, memory, mgd |
| Q-LOAD-03 | `UI_NETCONF_CMD` lines per minute per open view at 2, 5, 10, 30 s |
| Q-LOG-01 | Log source matrix per security log mode and platform: effective default mode, what lands in the buffer, report availability (none on SRX5000), which report types accept `expression`, `count` ordering, time zone |
| Q-AUTH-03 | `read-only` class on `get-log` (denied, and how); `view`-only class on the report RPCs and on `get-security-log-information` |
| Q-AUTH-01 | Reads run as the signed-in operator, so the permission results above are the operator's |
| Q-HA-01, Q-HA-02, Q-HA-03 | Active/Backup copies and their XML; summary counts per node; which node serves the page; MNHA session fields |
| Q-HW-01 | Parsing a 2,000-row list and a 1 MB log on an SRX300-class RE |
| Q-SEC-01 | Review of filter validation, log rendering and exposure |

## 12. Open questions

| # | Question | Who decides | Settled by |
| --- | --- | --- | --- |
| 1 | Close the fail-open: when the matching count is unknown (summary failed or count element missing), refuse the list, or allow it only with a device-side filter? | Security reviewer, then contributors | Unit test, Q-LOAD-02 |
| 2 | Is 5,000 the right refusal threshold, the same on every platform? The documentation review suggested about 2,000 as an example | Owner | Q-LOAD-02 |
| 3 | Add `node primary` or `node local` on clusters to halve the transfer, and more device filters (`policy-id`, `zone`, `nat`, ranges)? Each needs its `\| display xml rpc` recorded | Owner, then contributors | Q-REL-01, Q-HA-01 |
| 4 | Sessions and logs for logical and tenant systems | Owner | Q-REL-01, Q-AUTH-03 |
| 5 | Which report types accept `expression`? J-Wicket sends it to any of the ten types | Contributors | Q-LOG-01 |
| 6 | Report reads without `start`: which records does `count` return, and should J-Wicket send `descending`? What time zone do `start-time` and `stop-time` use? | Contributors | Q-LOG-01 |
| 7 | `get-log` moves the whole file each poll and J-Wicket does not cap the reply size. Add a cheap change check first, cap the size, or probe `get-syslog-events` (count and time filters in its schema, runtime behaviour unknown)? | Contributors, security reviewer | Q-LOAD-01, Q-REL-01 |
| 8 | The v2 design notes list "policy deny" among the close-reason badges and omit several documented reasons. "policy deny" is not a close reason (a deny is its own event). Use the verified list in 7.11 | UI owner | This spec |
| 9 | One audit record per sessions poll: keep, sample, or record only filter changes (as logs do)? | Security reviewer | Q-SEC-01 |
| 10 | The cached gauge carries no read time of its own; add `summary.read_at` so the UI can show its age | Contributors | Unit test |
| 11 | Log files configured in groups have `group: null`; archived `.gz` files are not offered | Owner | Parity ledger |
| 12 | vSRX default mode: event per the mode page, stream per the general statement. Show which on the lab vSRX | Lab owner | Q-LOG-01 |
| 13 | Single-session drill-down through `get-flow-session-by-identifier` (named in the XML API Explorer 25.4 catalog) instead of the full list | Owner | Q-REL-01 |
| 14 | Saved queries (UI-004-05) keep query text in `localStorage`, and that text can name addresses, policies and users. Acceptable on shared workstations, with Spec 001 open question 13 (query state in the URL hash)? Architecture section 11 and ADR 0007 allow it only as operator-saved query text, never device replies | Security reviewer | Q-SEC-01 |
