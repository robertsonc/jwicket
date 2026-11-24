# Log line samples

`juniper-docs.txt` holds log lines copied **verbatim** from Juniper documentation and the Junos
System Log Explorer (collected 2026-11-24; sources listed below). They are the parser and
highlighter corpus for `src/jwicket/static/js/logparse.js`: every line must tokenise back to exactly
itself, and RT_FLOW lines must decode to the right fields.

They are documentation examples, not captures from a J-Wicket qualification device. Some are old
(2007–2013), some come from the on-box report "self test" (no SD-ID, fake values), and they cover:
structured-data with and without an SD-ID, `session-id` and `session-id-32`, logical-system `_LS`
variants, IPv6, BSD positional RT_FLOW text, `explicit-priority` (`%FACILITY-n-TAG`), and common
system daemons.

Sources:

- System logging for a security device: https://networkingdocs.hpe.com/documentation/us/en/software/junos/network-mgmt/topics/topic-map/system-logging-for-a-security-device.html
- show security log report in-detail: https://networkingdocs.hpe.com/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-security-log-report-in-detail.html
- System Log Explorer, RT_FLOW_SESSION_CREATE / CLOSE / DENY: https://apps.juniper.net/syslog-explorer/
- Junos system log message format, explicit-priority, structured-data: Junos system log monitoring guide on networkingdocs.hpe.com

Recorded lines from qualification devices go in a sibling file named after the device and
release, with a note on what was redacted.
