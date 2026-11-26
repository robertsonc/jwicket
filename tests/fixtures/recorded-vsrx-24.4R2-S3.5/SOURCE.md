# Recorded replies: vSRX, Junos 24.4R2-S3.5

Captured by Dot on 26 November 2026 (UTC), on a standalone vSRX in Corey Robertson's
temporary Juniper vLab. Two lab hosts sent ICMP across the existing lab VPN under a
temporary, exact host-to-host ICMP policy. A separate temporary syslog source held one
synthetic marker. The reads were captured over NETCONF and compared with native Junos
CLI reads. The CLI and NETCONF reads are separate samples of a changing session table,
so their counts need not agree.

| File | NETCONF request | Operator |
| --- | --- | --- |
| `get-flow-session-information-filtered.xml` | `get-flow-session-information` with `source-prefix`, `destination-prefix`, and `protocol=icmp` | Lab super-user class |
| `get-flow-session-information-matching.xml` | Same filters with `<summary/>` | Lab super-user class |
| `get-flow-session-information-summary.xml` | `get-flow-session-information` with `<summary/>` and no filters | Lab super-user class |
| `get-log-allowed.xml` | `get-log` with `<filename>jwicket-qrel</filename>` | Lab super-user class |
| `get-log-denied.xml` | Same `get-log` request | Temporary restricted class |

The filtered CLI forms were `show security flow session source-prefix <host-A>/32
destination-prefix <host-B>/32 protocol icmp` and the same command with `summary`.
The file read was `show log jwicket-qrel`. The device's `display xml rpc` output
confirmed those request names and leaves.

The XML files retain the whole NETCONF reply, including its original wrapper, namespaces,
elements and order. Redaction in the filtered session list replaces endpoint and gateway
addresses with documentation addresses and pseudonymizes session IDs, start times,
nonzero ICMP identifiers, nonzero session tokens, route handles and tunnel IDs. The same
input value is replaced consistently within each field or group of related fields. The
allowed log's host, time and PID are substituted; the test policy, filename and log
marker are synthetic and unchanged. The two summary replies and denied reply needed
no redaction. No credentials, user configuration, unrelated traffic or raw CLI transcript
are retained here.

The filtered list has four ICMP rows and the filtered summary has four matches.
The unfiltered summary has six active sessions, not four; the two requests serve
different panels. Junos reported the session state as `sess-state` in these list rows.
The allowed log uses `file-content`; the restricted reply uses an `rpc-error` whose
message is classified as a permission denial. These five replies add second-platform
evidence for Q-REL-01; they do not qualify the platform or complete Q-REL-01.

Replay: `PYTHONPATH=src python3 -m unittest discover -s tests -p test_recorded_vsrx.py`.
