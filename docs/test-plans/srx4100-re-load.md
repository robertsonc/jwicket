# Test plan: routing-engine load on the lab SRX4100 (Q-LOAD-02 and Q-LOAD-04)

**Draft, 2026-11-27. Nothing in this plan has run.** No step runs against the SRX4100 until its
owner gives the go for that phase, in writing, in the pull request or the lab record. Every
budget it checks against is written into [governance](../governance.md) before the run (D9); a run
without budgets records numbers and cannot pass ([governance 4.1](../governance.md#41-how-to-read-an-entry)).

What it settles:

- **Q-LOAD-02**: the cost of a session list at 1k, 2k, 5k, 10k and 20k sessions, and whether
  `MAX_UNFILTERED = 5000` stands on this platform class ([Spec 004, 7.4](../specs/004-live-sessions-and-logs.md#74-cost-of-listing-and-the-refusal-threshold)).
- **Q-LOAD-04** (proposed): what the routing-engine CPU windows measure, what a sample costs, and
  the values P1 to P12 of [Spec 004, 5.8](../specs/004-live-sessions-and-logs.md#58-read-pressure-backing-off-when-the-routing-engine-is-busy).
- Numbers toward **Q-LOAD-01** and **Q-LOAD-03**, which keep their own methods.

What it cannot settle: anything about another platform or release, a chassis cluster, a multi-SPU
list layout, or the SRX300 class (Q-HW-01). One device, one release, standalone.

## 1. The device, and why it is treated as live

| | |
| --- | --- |
| Platform | SRX4100, standalone, Junos 25.2R1-S1.4 ([evidence, 2026-11-24](../evidence/2026-11-24-srx4100-lab/README.md)) |
| Role | The owner's lab device. The 2026-11-24 record says it "carries lab traffic only and is not a production firewall" |
| Why this plan still treats it as live | It has run for months (uptime about 326 days in the [recorded reply](../../tests/fixtures/recorded-srx4100-25.2R1-S1.4/get-route-engine-information.xml)); it is managed by Security Director Cloud over `outbound-ssh`; whatever it forwards for the owner's lab stops if the routing engine or the data plane stalls. Nothing here assumes it is disposable |
| Resting load, one reading | Routing-engine idle 78 % (unsuffixed), 76, 69, 69 (`*1` to `*3`); load average 1.80, 2.14, 2.11. One sample, time of day unknown: phase 0 measures the real baseline |

## 2. What could drop or disturb traffic

Each row is a reason to stop and ask before the phase that carries it.

| Risk | Where | Why it matters | Mitigation in this plan |
| --- | --- | --- | --- |
| **Configuration changes** for the load hosts (zones, interfaces, a permit policy, an address book) | Setup | A wrong commit can cut the owner's own traffic or management access | Prefer an existing lab-only path with no change at all. Any change is listed in full in the lab record first, committed with `commit confirmed 5`, confirmed only after the canary and management checks pass, and removed in phase 5 |
| **Session logging** on the policy the load uses (`then log session-init` / `session-close`) | Phases 2 to 4 | 20,000 sessions opening and closing can flood syslog and, in stream mode, Security Director Cloud's log feed; it adds routing-engine load the test would wrongly blame on J-Wicket | Read the policy's `then log` and `security log` mode first; use a policy that does not log, or stop and ask |
| **Source NAT** on the load path | Phases 2 to 4 | A NAT pool or port exhaustion drops other users' new sessions | Use a path with no NAT; check `show security nat source summary` before and after |
| **Screens and session limits** (`screen ids-option ... limit-session`) | Phases 2 to 4 | The load is refused, or the screen fires on other hosts | Read the zone's screens first; spread load over several source addresses |
| **Routing-engine saturation** | Phases 2 to 4 | Routing protocols, BFD, `outbound-ssh` to Security Director Cloud, the CLI and J-Web all live on the routing engine | Abort criteria (section 5); no hold above 90 % short-window busy; thresholds above 90 % are tested by lowering them in the build, not by loading the device |
| **Large list pulls at 10k and 20k** | Phase 2 | The very read the KB title warns about ("Idle 0 percent") | One pull at a time, at least 60 s apart, from a separate lab client, at most 3 pulls per size; abort criteria apply between pulls |
| **The load hosts' traffic** | Phases 2 to 4 | Shares links with the owner's traffic | Under 1,000 packets a second in total (UDP keepalives); the canary measures loss |

## 3. Setup

- **Builds.** Phases 0 to 3 need no new J-Wicket code: they run on a published lab pre-release
  (0.1.0.dev4 or later), installed by its documented procedure, unchanged ([evidence rule 2](../governance.md#6-evidence-rules)).
  Phase 4 needs [Spec 004 section 5.8](../specs/004-live-sessions-and-logs.md#58-read-pressure-backing-off-when-the-routing-engine-is-busy)
  built, with its thresholds settable, and runs on that build's own release.
- **Accounts.** The lab accounts of 2026-11-25 (`jw-ro`, `jw-op`, `jw-su`, Q-AUTH-01) for
  J-Wicket's operators; one more lab-only account, class `read-only` plus `view`, for the
  collector, so its reads are attributable and countable apart from J-Wicket's.
- **Load hosts.** Two lab hosts on lab-only segments, A behind one zone and B behind another, with
  a permit path between them and none of the risks in section 2. B runs a UDP sink.
- **Session generator.** A script on host A that opens N UDP flows to B (distinct source ports over
  several source addresses) and sends one small packet on each flow every 20 s, so the sessions
  stay up under the default UDP timeout without a configuration change. 20,000 flows is about 1,000
  packets a second. The count is checked with `show security flow session summary` before each
  measurement, not assumed. That the default UDP inactivity timeout on this release is longer than
  20 s is **inferred**; the generator's first run checks it by watching the count hold.
- **Collector** (a desk host on the lab management network): every 5 s, one
  `get-route-engine-information` and one `get-performance-summary-information` over NETCONF as the
  collector account; every 30 s, `show system processes extensive` over the CLI for mgd and the top
  processes by CPU. Its own cost is measured in phase 0 and subtracted.
- **Driver** (the same desk host): drives J-Wicket's API as signed-in operators with a fixed
  schedule (the browser's own intervals), records every response's status, `meta`, latency and
  size. Browsers are used only for the UI checks of phase 4.
- **Canary**: a continuous ping and a small TCP stream through the device on the owner's normal
  path, recording loss and latency, plus a timed `show version` and `show route summary` from a CLI
  session every 60 s.
- **Time.** An agreed window, with the owner reachable. Device clock and desk clocks recorded.

## 4. Phases

| Phase | What | J-Wicket build | Settles |
| --- | --- | --- | --- |
| 0 | **Baseline.** 30 min with nobody signed in to J-Wicket and the generator off; then 30 min with the collector at 5 s; then 10 min at 1 s, to see the collector's own cost | Installed, idle | Resting routing-engine CPU and mgd; the cost of one `get-route-engine-information` (the sampling cost P10 rests on) |
| 1 | **Window semantics.** With the collector at 1 s, run one 60 s burst of list pulls at the current table size, then stop. Record, side by side, the XML (`cpu-idle`, `cpu-idle1` to `-3`) and the CLI text of `show chassis routing-engine` at the same moments | Installed, idle | What each window measures (Spec 004 open question 21): which set reacts in seconds, which over about a minute, which over 5 and 15 minutes |
| 2 | **Session-table sweep.** At 0, 1k, 2k, 5k, 6k, 10k and 20k sessions, hold each 10 min. At each size: one operator on Sessions at 5 s, unfiltered and then filtered to about 100 matches; then four operators (the default `max_sessions`) at once; then, at 10k and 20k only, single direct list pulls from the collector account (J-Wicket refuses them above 5,000) | Pre-release | Q-LOAD-02: summary and list cost per size; whether 5,000 stands; that 6k is refused before any list RPC (AC-004-02 on a device); the four-operator total that the per-session floors do not bound |
| 3 | **Load without J-Wicket's lists.** Raise routing-engine busy in steps to about 50, 70 and 85 % (short window), holding each 5 min, using list pulls and configuration reads from the collector account only. Record summary-read latency from J-Wicket's gauge (`rows=none`) at each step | Pre-release | The latency signal P3: how summary latency moves with CPU; whether mgd saturates before the all-core figure says so |
| 4 | **Back-off.** Repeat phase 3's steps with section 5.8 built: once with its provisional thresholds, once with P1, P2, P4 and P5 lowered by 30 points so `high` is reached at about 55 to 65 % real busy. Four operators on Sessions, Logs and the Overview. Then hold a steady load at each level boundary for 10 min | Section 5.8 build | AC-004-37; the values for AC-004-38 |
| 5 | **Recovery and cleanup.** Generator off; watch the level step down; sign everyone out; remove any configuration added in setup and show it is gone (`show \| compare rollback`); collector off; canary 10 min clean | Either | The way down; restoration |

Phase 2's 10k and 20k direct pulls and phase 3's 85 % step are the two moments most likely to
disturb the device. Each needs its own go on the day, after phase 0 and 1 results are in.

## 5. Abort criteria (any one stops the phase, generator and pulls off at once)

- Short-window routing-engine busy at or above 90 % for more than 60 s, or idle 0 on any sample.
- Any canary loss above its phase-0 level, or canary latency above twice its phase-0 99th percentile.
- A timed CLI `show version` above 5 s, or a CLI session that does not answer.
- Any routing-protocol, BFD or chassis alarm, or a `KERNEL`, `chassisd` or `mgd` error line that was
  not in phase 0's logs.
- Security Director Cloud's `outbound-ssh` session drops (seen in `show system connections` or the system log; which check is best on this release is **inferred**).
- Data-plane (SPU) CPU above its phase-0 level by more than 20 points: the test is about the routing
  engine and must not load the data plane.
- The owner says stop.

After an abort: wait for phase-0 levels, record what happened, and ask before resuming.

## 6. Metrics

| Metric | Source | Phases |
| --- | --- | --- |
| Routing-engine busy, all four windows; load average | Collector, `get-route-engine-information` | All |
| mgd CPU and the top processes by CPU | Collector, `show system processes extensive` every 30 s | All |
| Data-plane CPU and session counts | Collector, `get-performance-summary-information` | All |
| Per-read latency, reply size, status, `meta` | Driver | 2 to 4 |
| RPCs per minute J-Wicket sends, by RPC | Device `UI_NETCONF_CMD` lines for the J-Wicket accounts (Q-LOAD-03) | 2 to 4 |
| J-Wicket's resident memory and CPU | `show system processes extensive`, the J-Wicket process | 2 to 4 |
| Level, level changes, `reasons`, samples per minute | Driver (`meta.pressure`), audit `read_pressure` | 4 |
| Canary loss and latency; CLI timings | Canary | All |

## 7. Pass and fail, per criterion

Budgets B1 to B6 are written into governance (Q-LOAD-02, Q-LOAD-04) by the owner before phase 2;
the values in brackets are this plan's suggestions, not budgets.

| Criterion | Pass | Fail |
| --- | --- | --- |
| Q-LOAD-02 pass (governance) and AC-004-22 | At 5,000 matching sessions, one operator listing at 5 s adds at most B1 [15 points] of sustained routing-engine busy over phase 0, and no abort criterion fires | It adds more, or an abort fires: the cap is lowered to the largest size that passed, and Spec 004 open question 2 records it |
| `MAX_UNFILTERED` per platform class | The largest tested size that passes B1 is recorded; 5,000 stands if it is that size or larger | Recorded size below 5,000: the cap changes in a pull request with this evidence |
| Four operators | Four operators at 5,000 add at most B2 [30 points] | More: Spec 004 open question 18 (one list in flight daemon-wide) is answered yes |
| Refusal above the cap (AC-004-02 on a device) | At 6k J-Wicket answers `refused` and the device logs no list RPC for that request | Any list RPC logged |
| Sampling cost (AC-004-37, part) | One `get-route-engine-information` per 10 s adds at most B3 [1 point] of sustained busy and no measurable mgd time | More: P10 is raised, or sampling is dropped and ADR 0016 is reopened ("Would be proven wrong by") |
| Window semantics (open question 21) | Each window's behaviour in phase 1 is named and matches the CLI text | Ambiguous: section 5.8 keeps the latency signal only until Q-REL-01 records more |
| Level entry (AC-004-37, part) | Each level is reached within two sampling intervals (20 s) of the device crossing its threshold | Slower, or a level is missed |
| Back-off effect (AC-004-37, part) | J-Wicket's RPCs per minute at `elevated` and `high` fall as Spec 004 5.8.3's table says (within 10 %), and at `high` no list RPC is logged | Any list RPC at `high`, or the rates do not fall |
| No flapping (AC-004-37, part) | At a steady load at each boundary, at most 2 level changes in 10 minutes | More: P7, P8 or P9 are raised and phase 4 repeats |
| J-Wicket's share at `high` | J-Wicket's own reads add at most B4 [5 points] at `high` with four operators | More: section 5.8.3's `high` column is tightened |
| Recovery | The level steps down within B5 [3 min] of load returning to phase-0 levels, one step at a time | Stuck, or straight to `normal` |
| Cleanup | Configuration equals the pre-run commit; session table back to phase-0 size; canary clean for 10 min | Anything left |
| Thresholds recorded (AC-004-38) | P1 to P12 written into Spec 004 5.8 with this platform class, each from a measured number | Any left provisional for this class |

## 8. Evidence

The owner or the lab owner files the results under `docs/evidence/<date>-srx4100-<release>/` as
[CONTRIBUTING](../../CONTRIBUTING.md#add-a-qualification-result) says, with every deviation from
this plan. This plan is not evidence and records nothing; it does not edit existing evidence.
