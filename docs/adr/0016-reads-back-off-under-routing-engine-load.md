# ADR 0016: Reads back off when the routing engine is busy

Status: Proposed (2026-11-27). Written by a contributor; the owner has not accepted it (governance
D22). Nothing in it is built, and every number in it is provisional until Q-LOAD-04 measures it.

## Context

J-Wicket's reads cost the same whatever the routing engine is doing. The admission path has three
guards, and none of them looks at routing-engine load:

- fixed per-operator read floors, 1.5 s for Spec 004's endpoints and 2 s for Spec 001's
  ([`api.throttle_read`](../../src/jwicket/api.py), `SESSIONS_INTERVAL_S` and `LOGS_INTERVAL_S` in
  [`live.py`](../../src/jwicket/live.py), `MIN_READ_INTERVAL_S` in `api.py`);
- the session-list refusal above `MAX_UNFILTERED = 5000` matching sessions
  ([`live._guard`](../../src/jwicket/live.py), [`junos/sessions.py`](../../src/jwicket/junos/sessions.py)),
  which is J-Wicket's own number and untested (Spec 004 section 7.4, Q-LOAD-02);
- one device turn per operator, waiting at most 5 s ([`api.device_turn`](../../src/jwicket/api.py)),
  and at most two read handlers per account ([`api.add_read_route`](../../src/jwicket/api.py)).

Routing-engine CPU is already read, by `GET /api/health`, but only to draw the Overview's chart
(Spec 004 section 5.7). The only feedback is indirect: the browser keeps one poll in flight
([`views/sessions.js`](../../src/jwicket/static/js/views/sessions.js), `poll`), so a slower device
answers fewer polls. That slows J-Wicket in proportion to latency, not to load, and not at all
while latency is still normal.

Two more facts shape the choice:

- The floors are per web session. With the default four operators (`[auth] max_sessions`), the
  device sees up to four times one operator's load, and nothing caps the total.
- A session list makes the data plane send every matching session to the routing engine, which a
  2015 community-forum reply links to "Idle 0 percent" (Spec 004 section 7.4; **inferred** for
  current releases). It is the one read whose cost grows with something J-Wicket does not control.

A review suggestion of 2026-11-27 proposed refusing lists and doubling read floors at 85 % RE CPU.
This record keeps the direction and changes the mechanism, for the reasons in Decision.

## Decision

1. **A device-wide pressure level gates the expensive reads.** The daemon keeps one level,
   `normal`, `elevated`, `high` or `unknown`, for the device. Only reads whose cost can grow (the
   session list, `get-log` of a whole file, report and buffer reads, the log-sources configuration
   read) consult it. The signals that measure the device (the counted summary, the summary-only
   gauge and `/api/health`) are never refused for pressure, so J-Wicket can always see the device
   recover and tell the operator how many sessions match.
2. **Two signals, both cheap.** Routing-engine busy CPU from `get-route-engine-information`, an RPC
   already allowlisted and recorded on SRX4100 25.2R1-S1.4, read at most once per sampling interval
   for the whole daemon and refreshed for free by any `/api/health` read. And the latency of the
   counted summary J-Wicket already sends before each list, which costs no RPC and sees a
   saturated management process that an all-core CPU average can hide (**inferred**: whether mgd is
   bound to one core on the SRX routing engine is unknown).
3. **Hysteresis, two windows, and steps of one.** A level is entered on the reply's sustained window
   or on two consecutive short-window samples, left only after the sustained window has stayed a
   margin below the entry threshold for several samples and a minimum dwell, and changed one step
   at a time. This keeps J-Wicket's own list pulls, which raise the short window they are measured
   by, from flipping the level on every poll.
4. **Degrade by cost, not by switch.** `elevated` lowers the list cap, raises floors, pauses the
   Overview's background list and allows one session list in flight for the whole daemon. `high`
   sends no list RPC and slows whole-file log reads to one per 30 s per operator. The exact table is
   in [Spec 004 section 5.8](../specs/004-live-sessions-and-logs.md#58-read-pressure-backing-off-when-the-routing-engine-is-busy).
5. **The level is shared; the figures are not.** Every web session sees the level and its reason
   codes, because back-off has to be device-wide to bound total load. CPU figures reach only a web
   session whose own read returned them, so a class that is denied `get-route-engine-information`
   learns a coarse level, never a number. Samples run on the requesting operator's own NETCONF
   session ([ADR 0002](0002-junos-delegated-sign-in.md)); the daemon's account makes no reads.
6. **Failing.** A sample that times out or takes longer than its limit counts as `high`. A sample
   that is denied or unsupported, with no other operator's fresh sample, gives `unknown`, which
   behaves as `normal` and says so. Every threshold is a setting with a provisional default.

## Consequences

- During the incidents J-Wicket is for, a busy routing engine pauses the session list. The
  operator still gets the matching count, the gauge, health and bounded log reads, and the page says
  why the list is paused and what to run instead (`show security flow session summary`). There is
  no override; Spec 004 open question 17 asks whether there should be one.
- One more allowlisted RPC call path: at most one `get-route-engine-information` per sampling
  interval, daemon-wide, only while someone runs an expensive read. Each adds a `UI_NETCONF_CMD`
  line (Spec 004 section 7.12, Q-LOAD-03).
- Sharing the level crosses web sessions for the first time: until now no device-derived value was
  shared between login classes (Spec 004 section 5.5). The security reviewer has to agree (D1,
  Spec 004 open question 15).
- The thresholds rest on what `cpu-idle` and `cpu-idle1` to `cpu-idle3` measure, which no
  Juniper page found says (Spec 004 section 5.7). Q-LOAD-04 pairs the XML with the CLI text first.
- J-Wicket backs off for load it did not cause (another administrator, a routing event). That is
  intended: it cannot fix that load and should not add to it. The banner does not blame J-Wicket.
- It does not settle `MAX_UNFILTERED`. Q-LOAD-02 still decides the normal cap; this record only adds
  a lower one under pressure.

## Would be proven wrong by

Q-LOAD-04 (proposed, governance section 4.12), on the lab SRX4100 first:

- if J-Wicket's own reads are not a measurable share of routing-engine CPU even at the largest list
  it allows, the mechanism costs more (sampling, complexity, paused lists) than it saves;
- if the sampling itself raises routing-engine CPU or mgd measurably at its interval;
- if no setting of the thresholds avoids repeated level changes at a steady load.

Any of these sends the design back to a fixed, lower list cap with no runtime sensor.
