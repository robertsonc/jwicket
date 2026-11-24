# J-Web 24.4 parity ledger: summary

This page summarises [`jweb-24.4.csv`](jweb-24.4.csv), the row-by-row ledger of J-Web for SRX Series 24.4 pages and operations. The CSV is authoritative. The method, the columns and the status and priority vocabularies are in [README.md](README.md). [`tests/test_parity_ledger.py`](../../tests/test_parity_ledger.py) fails when a count table or row list on this page no longer matches the CSV, and prints the expected table.

State on 2026-11-24. Built by merging two halves drafted from the research inventory: Network and Security Services (367 rows), and every other menu plus Getting Started, Security Director Cloud onboarding and the banner (552 rows, 38 of them duplicates of the first half and dropped). See the [merge record](#merge-record).

## The point

- **881 rows** over 190 pages and dialogs: the six menus, Getting Started, "Add SRX Series Firewall to Security Director Cloud" and the banner.
- **No row is `implemented` yet.** For 38 rows covered by Spec 001 and Spec 004, every backend and browser-engine criterion passes on synthetic fixtures, but each is an operation done in the browser, and the browser checks of both specs (AC-001-21, AC-004-20) have not passed: the v2 views are built in the working tree, not yet committed, not yet checked in a browser. The 38 rows are held at `specified` until those criteria pass ([method, section 5](README.md#5-statuses)); each row's notes name the criteria that do pass. None has run on a device. **No row is `qualified`**, because no platform cell is qualified ([governance 3.2](../governance.md#32-what-qualified-platform-means)).
- **G2 read parity is far off.** 195 rows are `P0` or `P1` (G2 needs each one implemented and qualified; the governance text also counts approved `out-of-scope` rows and qualified `replace` rows, a **proposed** addition, [D7](../governance.md#25-decisions-pending)). None is `implemented`; 17 are `replace` and would count once the replacement is implemented and qualified; 0 are `out-of-scope`. The other 178 are not implemented: 52 `specified` (38 of them the held rows above), 126 `planned`. 2 of the `planned` ones, sign-in and sign-out, are built but have no spec ([gap 1](#owner-decisions)).
- **Every `replace` (32) and `out-of-scope` (23) row is a proposal.** Each says "Owner approval pending"; the owner decides ([governance, decision rights](../governance.md#1-decision-rights)).
- **Priorities are proposals too.** The `P0` rows follow the owner's framing (Specs 001 and 004 are the first slices); the rest follow charter section 6 and the [catalog](../catalog.md). [Gaps](#gaps-and-open-questions) lists where the two disagree.

## Counts by menu and status

<!-- ledger-table: menu-status -->
| Menu | Rows | implemented | qualified | specified | planned | replace | out-of-scope | unassessed |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Dashboard | 34 | 0 | 0 | 2 | 30 | 0 | 0 | 2 |
| Monitor | 151 | 0 | 0 | 32 | 108 | 11 | 0 | 0 |
| Device Administration | 173 | 0 | 0 | 1 | 153 | 11 | 8 | 0 |
| Network | 198 | 0 | 0 | 0 | 195 | 1 | 2 | 0 |
| Security Policies & Objects | 113 | 0 | 0 | 26 | 85 | 2 | 0 | 0 |
| Security Services | 171 | 0 | 0 | 0 | 161 | 0 | 0 | 10 |
| Getting Started | 24 | 0 | 0 | 6 | 3 | 0 | 11 | 4 |
| Add SRX Series Firewall to Security Director Cloud | 2 | 0 | 0 | 0 | 0 | 1 | 1 | 0 |
| Banner (top pane) | 15 | 0 | 0 | 3 | 4 | 6 | 1 | 1 |
| **Total** | 881 | 0 | 0 | 70 | 739 | 32 | 23 | 17 |

## Counts by priority and status

<!-- ledger-table: priority-status -->
| Priority | Rows | implemented | qualified | specified | planned | replace | out-of-scope | unassessed |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P0 | 52 | 0 | 0 | 38 | 4 | 10 | 0 | 0 |
| P1 | 143 | 0 | 0 | 14 | 122 | 7 | 0 | 0 |
| P2 | 70 | 0 | 0 | 18 | 44 | 8 | 0 | 0 |
| P3 | 276 | 0 | 0 | 0 | 276 | 0 | 0 | 0 |
| P4 | 340 | 0 | 0 | 0 | 293 | 7 | 23 | 17 |
| **Total** | 881 | 0 | 0 | 70 | 739 | 32 | 23 | 17 |

## Counts by menu and priority

<!-- ledger-table: menu-priority -->
| Menu | Rows | P0 | P1 | P2 | P3 | P4 |
| --- | --- | --- | --- | --- | --- | --- |
| Dashboard | 34 | 2 | 20 | 0 | 5 | 7 |
| Monitor | 151 | 28 | 35 | 0 | 88 | 0 |
| Device Administration | 173 | 2 | 33 | 2 | 81 | 55 |
| Network | 198 | 0 | 32 | 31 | 56 | 79 |
| Security Policies & Objects | 113 | 7 | 13 | 32 | 43 | 18 |
| Security Services | 171 | 0 | 7 | 0 | 2 | 162 |
| Getting Started | 24 | 6 | 2 | 1 | 0 | 15 |
| Add SRX Series Firewall to Security Director Cloud | 2 | 1 | 0 | 0 | 0 | 1 |
| Banner (top pane) | 15 | 6 | 1 | 4 | 1 | 3 |
| **Total** | 881 | 52 | 143 | 70 | 276 | 340 |

## Counts by spec and status

The `spec` column names the spec that covers the row: for `replace` rows, the spec that delivers the alternative. [001](../specs/001-policy-inventory.md), [002](../specs/002-change-protocol.md), [003](../specs/003-firewall-policy-builder.md), [004](../specs/004-live-sessions-and-logs.md).

<!-- ledger-table: spec-status -->
| Spec | Rows | implemented | qualified | specified | planned | replace | out-of-scope | unassessed |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 001 | 19 | 0 | 0 | 14 | 0 | 5 | 0 | 0 |
| 002 | 7 | 0 | 0 | 0 | 0 | 7 | 0 | 0 |
| 003 | 19 | 0 | 0 | 18 | 0 | 1 | 0 | 0 |
| 004 | 49 | 0 | 0 | 38 | 0 | 11 | 0 | 0 |
| (none) | 787 | 0 | 0 | 0 | 739 | 8 | 23 | 17 |
| **Total** | 881 | 0 | 0 | 70 | 739 | 32 | 23 | 17 |

## Counts by source status

`source_status` says whether the J-Web 24.4 page and operation are documented as the row describes. The Junos mapping carries its own marker inside `junos_hierarchy`.

<!-- ledger-table: source-status -->
| Source status | Rows |
| --- | --- |
| verified | 876 |
| inferred | 1 |
| unknown | 4 |
| **Total** | 881 |

## `P0` rows (52)

Foundation and first slices: Specs 001 and 004, the scope banner, sign-in and access.

<!-- ledger-rows: P0 -->
| ID | Menu path | Operation | Status | Spec |
| --- | --- | --- | --- | --- |
| `DASH-W-SYSID-IDENTITY` | Dashboard | view: hostname and software version | `specified` | 001 |
| `DASH-W-SECRES-SESSIONS` | Dashboard | view: sessions (maximum and activated) | `specified` | 004 |
| `MON-LOGS-SESSION-VIEW` | Monitor > Logs > Session | view/list log records (Time, Log Type, zones, IPs and ports, User, Application, Action, Policy, Bandwidth ... | `specified` | 004 |
| `MON-LOGS-SESSION-TIME` | Monitor > Logs > Session | time range: Last list, or Customize then Apply | `specified` | 004 |
| `MON-LOGS-SESSION-REFRESH` | Monitor > Logs > Session | Refresh (manual) | `replace` | 004 |
| `MON-LOGS-SESSION-FILTER` | Monitor > Logs > Session | filter bar (13 fields: source and destination IP, Session ID, Log type, User, Application, zones, countries ... | `specified` | 004 |
| `MON-LOGS-SESSION-DETAIL` | Monitor > Logs > Session | View Details: Detailed Log View | `specified` | 004 |
| `MON-LOGS-THREATS-VIEW` | Monitor > Logs > Threats | view/list log records (Time, Log Type, Name, Severity, zones, IPs and ports, User, Application, Action ... | `specified` | 004 |
| `MON-LOGS-THREATS-TIME` | Monitor > Logs > Threats | time range: Last list, or Customize then Apply | `specified` | 004 |
| `MON-LOGS-THREATS-REFRESH` | Monitor > Logs > Threats | Refresh (manual) | `replace` | 004 |
| `MON-LOGS-THREATS-FILTER` | Monitor > Logs > Threats | filter bar (the same 13 fields as Session; since 23.1R1 =, !=, >=, <=, AND, nested and/or, netmask on IPs); X ... | `specified` | 004 |
| `MON-LOGS-THREATS-DETAIL` | Monitor > Logs > Threats | View Details: Detailed Log View | `specified` | 004 |
| `MON-LOGS-WEBFILTER-VIEW` | Monitor > Logs > Web Filtering | view/list log records (Time, Log Type, zones and IPs, User, Destination Port, Application, Action, Session ... | `specified` | 004 |
| `MON-LOGS-WEBFILTER-TIME` | Monitor > Logs > Web Filtering | time range: Last list, or Customize then Apply | `specified` | 004 |
| `MON-LOGS-WEBFILTER-REFRESH` | Monitor > Logs > Web Filtering | Refresh (manual) | `replace` | 004 |
| `MON-LOGS-WEBFILTER-FILTER` | Monitor > Logs > Web Filtering | filter bar (12 fields, without Protocol; since 23.1R1 =, !=, >=, <=, AND, nested and/or, netmask on IPs); X ... | `specified` | 004 |
| `MON-LOGS-VPN-VIEW` | Monitor > Logs > VPN | view/list log records (Time, Log Type (Bad SPI, Replay, PV decryption, PV encryption, PV sm keygen, PV ... | `specified` | 004 |
| `MON-LOGS-VPN-TIME` | Monitor > Logs > VPN | time range: Last list, or Customize then Apply | `specified` | 004 |
| `MON-LOGS-VPN-REFRESH` | Monitor > Logs > VPN | Refresh (manual) | `replace` | 004 |
| `MON-LOGS-VPN-FILTER` | Monitor > Logs > VPN | filter bar (only Log type; since 23.1R1 =, !=, >=, <=, AND, nested and/or, netmask on IPs); X clears | `specified` | 004 |
| `MON-LOGS-ALLEVENTS-VIEW` | Monitor > Logs > All Events | view/list log records (the union of Session, Threats, Web Filtering, ATP and VPN columns) | `specified` | 004 |
| `MON-LOGS-ALLEVENTS-TIME` | Monitor > Logs > All Events | time range: Last list, or Customize then Apply | `specified` | 004 |
| `MON-LOGS-ALLEVENTS-REFRESH` | Monitor > Logs > All Events | Refresh (manual) | `replace` | 004 |
| `MON-LOGS-ALLEVENTS-FILTER` | Monitor > Logs > All Events | filter bar (13 fields; since 23.1R1 =, !=, >=, <=, AND, nested and/or, netmask on IPs); X clears | `specified` | 004 |
| `MON-LOGS-ALLEVENTS-DETAIL` | Monitor > Logs > All Events | View Details: Detailed Log View | `specified` | 004 |
| `MON-LOGS-SYSTEM-VIEW` | Monitor > Logs > System | Show logs of file: select a syslog file; view lines (Time, Event, Message, Process hidden by default) | `specified` | 004 |
| `MON-LOGS-SYSTEM-DURATION` | Monitor > Logs > System | Duration: Last list, or Customize then Apply (default last hour) | `specified` | 004 |
| `MON-LOGS-SYSTEM-REFRESH` | Monitor > Logs > System | Refresh (manual) | `replace` | 004 |
| `MON-LOGS-SYSTEM-FILTER` | Monitor > Logs > System | Filter with = only, on Event and Message; X clears | `specified` | 004 |
| `MON-LOGS-SYSTEM-DETAIL` | Monitor > Logs > System | Detailed View: System Log Details page | `specified` | 004 |
| `DA-BASIC-SECLOG-VIEW` | Device Administration > Basic Settings | view (mode stream, UTC timestamp, source address or interface, format binary/sd-syslog/syslog, transport ... | `specified` | 004 |
| `DA-MT-LSYS-ENTER` | Device Administration > Multi Tenancy > Logical Systems | Enter LSYS (a root user switches context to a logical system) | `replace` | 001 |
| `SPO-SECPOL-VIEW` | Security Policies & Objects > Security Policies | view/list rules grouped by zone context (Seq, Rule Name with description on hover, Source Zone, Source ... | `specified` | 001 |
| `SPO-SECPOL-SEARCH` | Security Policies & Objects > Security Policies | advanced search (AND, OR, !=, comma lists, parentheses; junos: prefix ignored; saved rules searchable only ... | `specified` | 001 |
| `SPO-ZONES-ZONE-VIEW` | Security Policies & Objects > Zones/Screens | view/list (Zone name, Type, Host-inbound Services, Host-inbound Protocols, Interfaces, Screen, Description) | `specified` | 001 |
| `SPO-ZONEADDR-VIEW` | Security Policies & Objects > Zone Addresses | view/list two grids: Addresses (Zone, Name, Type, IP Address, Description) and Address Sets (Zone, Name ... | `specified` | 001 |
| `SPO-GLOBADDR-VIEW` | Security Policies & Objects > Global Addresses | view/list (Address Book Name, Attached Zone, Global, Address/Address-Set Name, Address Value, Address-Set ... | `specified` | 001 |
| `SPO-SERVICES-CUSTOM-VIEW` | Security Policies & Objects > Services | view/list (Application Name, Description, Application-Protocol, IP-Protocol, Source-Port, Destination-Port) | `specified` | 001 |
| `SPO-SERVICES-GROUP-VIEW` | Security Policies & Objects > Services | view/list (Application Group Name, Members, Description) | `specified` | 001 |
| `GS-ACCESS-HTTPS` | Getting Started > Access the J-Web User Interface | reach the UI over HTTPS (default); accept the self-signed certificate on first login | `planned` |  |
| `GS-ACCESS-LOGIN` | Getting Started > Access the J-Web User Interface | log in (user name and password) | `planned` |  |
| `GS-EXPLORE-NAV` | Getting Started > Explore J-Web | navigate with the Dashboard, Monitor and Configure tabs (Configure = Device Administration, Network, Security ... | `planned` |  |
| `GS-EXPLORE-TABLESEARCH` | Getting Started > Explore J-Web | Table Search (magnifier; searches the visible fields) | `specified` | 004 |
| `GS-EXPLORE-ADVSEARCH` | Getting Started > Explore J-Web | Advanced Search (logical operators; an icon shows whether the filter string is valid; Spacebar inserts AND or ... | `specified` | 004 |
| `GS-EXPLORE-MESSAGES` | Getting Started > Explore J-Web | Success, Information, Alert and Warning messages at the top of the main pane | `specified` | 001 |
| `SDC-MANAGEDLABEL` | Add SRX Series Firewall to Security Director Cloud | after onboarding the label reads 'Managed by Juniper Security Director Cloud' (doc: 'Manged'), greyed out; it ... | `replace` | 001 |
| `BAN-DEVICEDETAILS` | Banner (top pane) | view details of the device you have accessed (contents not documented) | `specified` | 001 |
| `BAN-USER` | Banner (top pane) | show the logged-in user type; click the user name or arrow to log out | `planned` |  |
| `BAN-MODE` | Banner (top pane) | show whether the device is in standard, chassis cluster (HA) or passive mode | `specified` | 001 |
| `BAN-SCOPE-ENTER` | Banner (top pane) | select a tenant or LSYS to enter it; since 23.1R1 shows name and count (for example 'Tenant (5)'); points to ... | `replace` | 001 |
| `BAN-SCOPE-EXIT` | Banner (top pane) | Exit Tenant or Exit Logical System to return to root context; data refreshes once the configuration cache ... | `replace` | 001 |
| `BAN-LAUNCHPAD-IDENTITY` | Banner (top pane) | view model, host name and software version | `specified` | 001 |

## `P1` rows (143)

See everything, read-only. Most have no spec yet: each area needs a read spec ([governance, roadmap phase 2](../governance.md#7-roadmap)).

<!-- ledger-rows: P1 -->
| ID | Menu path | Operation | Status | Spec |
| --- | --- | --- | --- | --- |
| `DASH-VIEW` | Dashboard | view the widget dashboard (default page shows all widget thumbnails) | `planned` |  |
| `DASH-REFRESH` | Dashboard | refresh the whole page (refresh icon); data auto-refreshes every minute from a cache until it ages; interval ... | `planned` |  |
| `DASH-W-SYSALARMS` | Dashboard | view (received time, severity, description, action) | `planned` |  |
| `DASH-W-SYSID-OTHER` | Dashboard | view: serial number, BIOS version, uptime, system time | `planned` |  |
| `DASH-W-LOGINS` | Dashboard | view (user, login time, idle time, host) | `planned` |  |
| `DASH-W-FILEUSAGE-VIEW` | Dashboard | view space used by log, temporary, crash and database files | `planned` |  |
| `DASH-W-RESOURCE` | Dashboard | view CPU, memory and storage for data and control planes; hover CPU Control for the 1-minute load average | `planned` |  |
| `DASH-W-IFDROPS` | Dashboard | view the top 5 interfaces by dropped packets (top count to become 10) | `planned` |  |
| `DASH-W-SECRES-OTHER` | Dashboard | view: firewall/VPN policies and IPsec VPNs (maximum, configured, activated) | `planned` |  |
| `DASH-W-STORAGE` | Dashboard | view used and available storage and usage of other system components | `planned` |  |
| `DASH-W-NATSRC-VIEW` | Dashboard | view the top 10 source translation hits | `planned` |  |
| `DASH-W-NATSRC-MORE` | Dashboard | More Details: open Monitor > Logs > All Events | `planned` |  |
| `DASH-W-NATDST-VIEW` | Dashboard | view the top 10 destination translation hits | `planned` |  |
| `DASH-W-NATDST-MORE` | Dashboard | More Details: open Monitor > Logs > All Events | `planned` |  |
| `DASH-W-IPSEC-VIEW` | Dashboard | view status counts by topology (ADVPN Hub and Spoke, Remote Access, Site-to-Site/Hub and Spoke) | `planned` |  |
| `DASH-W-IPSEC-MORE` | Dashboard | More Details: open Monitor > Network > IPsec VPN | `planned` |  |
| `DASH-W-VPNMON-VIEW` | Dashboard | view total VPNs or remote users (Juniper Secure Connect, NCP Exclusive Entry Client); Up green, Down red ... | `planned` |  |
| `DASH-W-VPNMON-MORE` | Dashboard | More Details: open Monitor > Network > IPsec VPN filtered by VPN name | `planned` |  |
| `DASH-W-ZONEBW` | Dashboard | view zones with the highest throughput by incoming and outgoing bytes | `planned` |  |
| `DASH-W-ZONEDROPS` | Dashboard | view zones with the most packet drops | `planned` |  |
| `MON-NET-IF-VIEW` | Monitor > Network > Interfaces | view all physical and logical interfaces (Interface, Link Status, Address, Zone, Host Inbound Traffic ... | `planned` |  |
| `MON-NET-IF-DETAIL` | Monitor > Network > Interfaces | View Details: extensive statistics (status, traffic, IP, I/O errors, CoS, statistics) | `planned` |  |
| `MON-NET-DHCP-VIEW` | Monitor > Network > DHCP Server Bindings | view dynamic and static leases, conflicts, pools and statistics (Client IP, MAC Address, State, Lease Time ... | `planned` |  |
| `MON-NET-IPSEC-VIEW` | Monitor > Network > IPsec VPN | view IKE and IPsec configuration, SAs and statistics with sortable columns (Remote Gateway, IKE Status, Local ... | `planned` |  |
| `MON-NET-IPSEC-STATS` | Monitor > Network > IPsec VPN | IPsec Statistics: global or for the selected VPN | `planned` |  |
| `MON-NET-IPSEC-REFRESH` | Monitor > Network > IPsec VPN | Refresh operational data; configuration data comes from a cache refreshed only after a commit and reopening ... | `planned` |  |
| `MON-LOGS-SESSION-EXPORT` | Monitor > Logs > Session | Export to CSV (at most 100 rows) | `replace` | 004 |
| `MON-LOGS-SESSION-SAVEFILTER` | Monitor > Logs > Session | Save Filter (named) | `specified` | 004 |
| `MON-LOGS-SESSION-LOADFILTER` | Monitor > Logs > Session | Load Filter (hover shows the query; saved filters can be deleted) | `specified` | 004 |
| `MON-LOGS-THREATS-EXPORT` | Monitor > Logs > Threats | Export to CSV (at most 100 rows) | `replace` | 004 |
| `MON-LOGS-THREATS-SAVEFILTER` | Monitor > Logs > Threats | Save Filter (named) | `specified` | 004 |
| `MON-LOGS-THREATS-LOADFILTER` | Monitor > Logs > Threats | Load Filter (hover shows the query; saved filters can be deleted) | `specified` | 004 |
| `MON-LOGS-WEBFILTER-EXPORT` | Monitor > Logs > Web Filtering | Export to CSV (at most 100 rows) | `replace` | 004 |
| `MON-LOGS-WEBFILTER-SAVEFILTER` | Monitor > Logs > Web Filtering | Save Filter (named) | `specified` | 004 |
| `MON-LOGS-WEBFILTER-LOADFILTER` | Monitor > Logs > Web Filtering | Load Filter (hover shows the query; saved filters can be deleted) | `specified` | 004 |
| `MON-LOGS-ATP-VIEW` | Monitor > Logs > ATP | view/list log records (Time, Log Type (Action, Malware event, SMTP action, IMAP action), zones, IPs and ... | `planned` |  |
| `MON-LOGS-ATP-TIME` | Monitor > Logs > ATP | time range: Last list, or Customize then Apply | `planned` |  |
| `MON-LOGS-ATP-REFRESH` | Monitor > Logs > ATP | Refresh (manual) | `planned` |  |
| `MON-LOGS-ATP-EXPORT` | Monitor > Logs > ATP | Export to CSV (at most 100 rows) | `planned` |  |
| `MON-LOGS-ATP-FILTER` | Monitor > Logs > ATP | filter bar (13 fields; since 23.1R1 =, !=, >=, <=, AND, nested and/or, netmask on IPs); X clears | `planned` |  |
| `MON-LOGS-ATP-SAVEFILTER` | Monitor > Logs > ATP | Save Filter (named) | `planned` |  |
| `MON-LOGS-ATP-LOADFILTER` | Monitor > Logs > ATP | Load Filter (hover shows the query; saved filters can be deleted) | `planned` |  |
| `MON-LOGS-VPN-EXPORT` | Monitor > Logs > VPN | Export to CSV (at most 100 rows) | `replace` | 004 |
| `MON-LOGS-VPN-SAVEFILTER` | Monitor > Logs > VPN | Save Filter (named) | `specified` | 004 |
| `MON-LOGS-VPN-LOADFILTER` | Monitor > Logs > VPN | Load Filter (hover shows the query; saved filters can be deleted) | `specified` | 004 |
| `MON-LOGS-ALLEVENTS-EXPORT` | Monitor > Logs > All Events | Export to CSV (at most 100 rows) | `replace` | 004 |
| `MON-LOGS-ALLEVENTS-SAVEFILTER` | Monitor > Logs > All Events | Save Filter (named) | `specified` | 004 |
| `MON-LOGS-ALLEVENTS-LOADFILTER` | Monitor > Logs > All Events | Load Filter (hover shows the query; saved filters can be deleted) | `specified` | 004 |
| `MON-LOGS-ALARMS-VIEW` | Monitor > Logs > Alarms | view the alarm list (Time, Type, Severity, Description) | `planned` |  |
| `MON-STATS-TP-AAMW-VIEW` | Monitor > Statistics > Threat Prevention | Advanced Anti Malware Session Statistics: sessions TOTAL, HTTP, HTTPS, SMTP, SMTPS, and a graph | `planned` |  |
| `MON-STATS-TP-SECINTEL-VIEW` | Monitor > Statistics > Threat Prevention | Security Intelligence Session Statistics: select Profile; sessions TOTAL, PERMIT, BLOCK-DROP, BLOCK-CLOSE ... | `planned` |  |
| `MON-STATS-IKE-VIEW` | Monitor > Statistics > Phase I | view IKE SAs (SA Index, Remote Address, State UP or DOWN, Initiator Cookie, Responder Cookie, Mode Main or ... | `planned` |  |
| `MON-STATS-IPSEC-VIEW` | Monitor > Statistics > Phase II | view IPsec Statistics counters (ESP encrypted and decrypted bytes, AH input and output, errors) and the IPsec ... | `planned` |  |
| `MON-STATS-DNS-VIEW` | Monitor > Statistics > DNS Security | view counters: DNS Sessions (cache hits and misses; permitted, dropped and sinkholed C2 sessions), DNS ... | `planned` |  |
| `MON-STATS-ETI-VIEW` | Monitor > Statistics > ETI | view counters: ETI Sessions (inspected, allowlisted, detected) and ETI Submissions (success, failure) | `planned` |  |
| `DA-BASIC-SYSID-VIEW` | Device Administration > Basic Settings | view (host name, domain name, root password, DNS servers, domain search) | `planned` |  |
| `DA-BASIC-TIME-VIEW` | Device Administration > Basic Settings | view (time zone; NTP servers; time source NTP, Computer or Manual) | `planned` |  |
| `DA-BASIC-MGMT-VIEW` | Device Administration > Basic Settings | view (management interface, loopback address, default gateway) | `planned` |  |
| `DA-BASIC-SVC-VIEW` | Device Administration > Basic Settings | view (Telnet, SSH, FTP, NETCONF, xnm-ssl) | `planned` |  |
| `DA-BASIC-HTTPS-VIEW` | Device Administration > Basic Settings | view (HTTPS interfaces, certificate type, port, virtual-domain certificates, management URL, session idle ... | `planned` |  |
| `DA-BASIC-WEBAPI-VIEW` | Device Administration > Basic Settings | view (hostnames; http, https, client, user) | `planned` |  |
| `DA-BASIC-REST-VIEW` | Device Administration > Basic Settings | view (allowed sources, connection limit, explorer, HTTP and HTTPS addresses and ports, cipher list, server ... | `planned` |  |
| `DA-BASIC-SNMP-VIEW` | Device Administration > Basic Settings | view (communities, trap groups and targets) | `planned` |  |
| `DA-CLUSTER-SETUP-STATUS` | Device Administration > Cluster Management > Cluster (HA) Setup | view control and fabric link status (green up, red down, orange one of the dual links up, grey fabric not ... | `planned` |  |
| `DA-CLUSTERCFG-VIEW` | Device Administration > Cluster Management > Cluster Configuration | view node settings and HA cluster settings (interfaces, redundancy groups) | `planned` |  |
| `DA-USERS-VIEW` | Device Administration > Users & Roles > Users | view local users, authentication method and order, RADIUS and TACACS+ servers, password settings | `planned` |  |
| `DA-ROLES-VIEW` | Device Administration > Users & Roles > Roles | view/list roles (Name, Role Scope, Predefined or Custom) with Detailed View, show/hide columns, advanced ... | `replace` |  |
| `DA-MT-RP-VIEW` | Device Administration > Multi Tenancy > Resource Profiles | view/list (Profile Name, Configured Resource, LSYS/Tenants) | `planned` |  |
| `DA-MT-RP-DETAIL` | Device Administration > Multi Tenancy > Resource Profiles | Detailed View | `planned` |  |
| `DA-MT-LSYS-VIEW` | Device Administration > Multi Tenancy > Logical Systems | view/list (Name, Resource Profile, Users, Assigned Interfaces, Zone) | `planned` |  |
| `DA-MT-LSYS-DETAIL` | Device Administration > Multi Tenancy > Logical Systems | Detailed View | `planned` |  |
| `DA-MT-TEN-VIEW` | Device Administration > Multi Tenancy > Tenants | view/list (Name, Resource Profile, Users, Assigned Interfaces, Zones, Routing Instance) | `planned` |  |
| `DA-MT-TEN-DETAIL` | Device Administration > Multi Tenancy > Tenants | Detailed View | `planned` |  |
| `DA-CERT-VIEW` | Device Administration > Certificate Management > Certificates | view by device certificate, certificate authority or all; Refresh | `planned` |  |
| `DA-CERT-DETAIL` | Device Administration > Certificate Management > Certificates | Detailed View | `planned` |  |
| `DA-CAGROUP-VIEW` | Device Administration > Certificate Management > Trusted Certificate Authority | view/list (Group Name, CA Profiles, Used For: IPsec VPN or SSL proxy) | `planned` |  |
| `DA-LIC-VIEW` | Device Administration > License Management | view (Feature, Licenses Used, Installed, Needed, Expires on) | `planned` |  |
| `DA-SECPKG-IPS-VIEW` | Device Administration > Security Package Management | view installed (version, status, published, detector) and the ten latest versions; View Details | `planned` |  |
| `DA-SECPKG-APP-VIEW` | Device Administration > Security Package Management | view installed and the ten latest versions; View Details | `planned` |  |
| `DA-SECPKG-URL-VIEW` | Device Administration > Security Package Management | view the EWF or NextGen package (version, status, base filter ng-default-filter or ewf-default-filter) | `planned` |  |
| `DA-ATP-ENROLL-STATUS` | Device Administration > ATP Management > Enrollment | view enrollment state (progress and errors shown inline) | `planned` |  |
| `DA-ATP-DIAG-VIEW` | Device Administration > ATP Management > Diagnostics | view server details, connection plane, service plane and proxy | `planned` |  |
| `DA-OPS-FILES-VIEW` | Device Administration > Operations > Files | view files by category | `planned` |  |
| `DA-OPS-FILES-DOWNLOAD` | Device Administration > Operations > Files | Download per category | `planned` |  |
| `DA-CFG-HISTORY-LIST` | Device Administration > Configuration Management > History | list commits (Number, Date/Time, User, Client: cli, junoscript, snmp, button, autoinstall, other; Comment ... | `planned` |  |
| `DA-CFG-HISTORY-COMPARE` | Device Administration > Configuration Management > History | Compare two versions side by side, colour-coded | `planned` |  |
| `DA-CFG-RESCUE-VIEW` | Device Administration > Configuration Management > Rescue | View the rescue configuration (OK) | `planned` |  |
| `DA-TOOLS-CLIVIEW` | Device Administration > Tools > CLI Viewer | view the current configuration, including uncommitted changes; OK, Commit Options > Commit, Cancel | `replace` | 001 |
| `NET-IFACE-LIST` | Network > Connectivity > Interfaces | View the interface tree: physical interfaces with their logical units (several IPs per unit collapse), Expand ... | `planned` |  |
| `NET-IFACE-FILTER` | Network > Connectivity > Interfaces | Filter by Interface Type, Interface State (Admin Up / Link Up / Admin Up & Link Down / Admin Down) or Zone ... | `planned` |  |
| `NET-VLAN-LIST` | Network > Connectivity > VLAN | List VLANs: Name, VLAN ID/List, Interface Assigned, Description; show/hide columns | `planned` |  |
| `NET-VLAN-SEARCH` | Network > Connectivity > VLAN | Advanced search (filter context menu, AND/OR, valid/invalid indicator) | `planned` |  |
| `NET-LAG-LIST` | Network > Connectivity > Link Aggregation | List LAGs: Name, Link/Admin status, Interfaces, VLAN ID, IP, VLAN Tagging Type, LACP link-protection ... | `planned` |  |
| `NET-LAG-SEARCH` | Network > Connectivity > Link Aggregation | Search for text in the table; Clear All | `planned` |  |
| `NET-DHCPC-LIST` | Network > DHCP > DHCP Client | List DHCP client settings: Interface Name, DHCP Client Identifier, Server, Lease Time | `planned` |  |
| `NET-DHCPS-LIST` | Network > DHCP > DHCP Server | View the Pools grid (routing instance, pool name, network addresses) and the Groups grid (group name ... | `planned` |  |
| `NET-FWF4-LIST` | Network > Firewall Filters > IPV4 | Filter summary: expand a filter to see its terms, match conditions and actions | `planned` |  |
| `NET-FWF4-SEARCH` | Network > Firewall Filters > IPV4 | Search by filter name or term name, `*` wildcard | `planned` |  |
| `NET-FWF6-LIST` | Network > Firewall Filters > IPV6 | Filter summary: expand a filter to see its terms, match conditions and actions | `planned` |  |
| `NET-FWF6-SEARCH` | Network > Firewall Filters > IPV6 | Search by filter name or term name, `*` wildcard | `planned` |  |
| `NET-FWFASSIGN-LIST` | Network > Firewall Filters > Assign To Interfaces | List logical interfaces with Link State and IPv4/IPv6 input and output filters | `planned` |  |
| `NET-NATPOL-LIST` | Network > NAT > Policies | One grid for all NAT rules: Seq, Hits, Rule Name, NAT Type (source/destination/static), Source Ingress ... | `planned` |  |
| `NET-NATPOL-HITS` | Network > NAT > Policies | Hits column per NAT rule | `planned` |  |
| `NET-NATPOOL-LIST` | Network > NAT > Pools | List pools: Pool Name, Pool Type (source/destination), Pool Address, Proxy ARP/ND, Description | `planned` |  |
| `NET-DNAT-LIST` | Network > NAT > Destination | Rule-set grid (Name, From, Rule, Description) and Rules grid (match source/destination, IP protocol ... | `planned` |  |
| `NET-DNAT-FILTER` | Network > NAT > Destination | Filter or sort rule sets by From | `planned` |  |
| `NET-STATICNAT-LIST` | Network > NAT > Static | Rule-set grid and Rules grid (source/destination addresses and ports, prefix, mapped port, thresholds) | `planned` |  |
| `NET-STATICNAT-FILTER` | Network > NAT > Static | Filter rule sets by From | `planned` |  |
| `NET-PROXYARP-LIST` | Network > NAT > Proxy ARP/ND | List proxy ARP and proxy ND entries: Interface, Address | `planned` |  |
| `NET-STATICRT-LIST` | Network > Routing > Static Routing | List static routes: Route, Next-hop, Routing Instance | `planned` |  |
| `NET-RIP-LIST` | Network > Routing > RIP | Select a routing instance; view the RIP Instances grid (instance, neighbors, routing instance, export/import ... | `planned` |  |
| `NET-OSPF-LIST` | Network > Routing > OSPF | Filter by instance; grid: Area ID, Area Type, Member Interfaces, Version (OSPF/OSPFv3), Routing Instance ... | `planned` |  |
| `NET-OSPF-SEARCH` | Network > Routing > OSPF | Advanced search | `planned` |  |
| `NET-BGP-LIST` | Network > Routing > BGP | Select a routing instance; Group grid (Group Name, Status, Peer ASN, Type, Dynamic/Static Peers, Routing ... | `planned` |  |
| `NET-RI-LIST` | Network > Routing > Routing Instances | Grid: Name, Type, Assigned Interfaces, Description; show/hide columns | `planned` |  |
| `NET-RI-SEARCH` | Network > Routing > Routing Instances | Advanced search | `planned` |  |
| `NET-RTPOL-LIST` | Network > Routing > Policies | Grid: Name, From (Prefix/Protocol/Interface or Address), To (Protocol/Interface or Address), Action, Move To | `planned` |  |
| `NET-FWDMODE-VIEW` | Network > Routing > Forwarding Mode | View forwarding mode for IPv6 (None, drop, flow-based, packet-based), ISO (None, packet-based) and MPLS ... | `planned` |  |
| `NET-IPSEC-LIST` | Network > VPN > IPsec VPN | Grid: Name, IKE Status, VPN Topology, Dead Peer, Routing Mode, Connection and more; show/hide columns | `planned` |  |
| `NET-IPSEC-SEARCH` | Network > VPN > IPsec VPN | Advanced search | `planned` |  |
| `SPO-SECPOL-HITS` | Security Policies & Objects > Security Policies | Hits column (rule hit count) | `planned` |  |
| `SPO-SECPOL-GO-VIEW` | Security Policies & Objects > Security Policies | view Pre-id Default Policy (session timeouts ICMP, ICMP6, OSPF, TCP, UDP, Others 4-86400 s; log session ... | `planned` |  |
| `SPO-MSP-VIEW` | Security Policies & Objects > Metadata Streaming Policy | view/list (Source Zone, Destination Zone, Metadata Streaming Profile) | `planned` |  |
| `SPO-ZONES-SCREEN-VIEW` | Security Policies & Objects > Zones/Screens | view/list (Screen name, Type, Description) | `planned` |  |
| `SPO-ZONEADDR-DETAIL` | Security Policies & Objects > Zone Addresses | Detailed View (More or the icon) | `specified` | 001 |
| `SPO-ZONEADDR-SEARCH` | Security Policies & Objects > Zone Addresses | search text (search icon; X or Clear All) | `specified` | 001 |
| `SPO-SERVICES-PREDEF-VIEW` | Security Policies & Objects > Services | view only (Application Name, Application-Protocol, IP-Protocol, Source-Port, Destination-Port) | `planned` |  |
| `SPO-DYNAPP-VIEW` | Security Policies & Objects > Dynamic Applications | view/list all enabled and disabled signatures (Name, Object Type, Category, Subcategory, Risk ... | `planned` |  |
| `SPO-DYNAPP-PKG-VIEW` | Security Policies & Objects > Dynamic Applications | status line: installed package version, latest available, whether one is downloaded | `planned` |  |
| `SPO-DYNAPP-DETAIL` | Security Policies & Objects > Dynamic Applications | Detailed View (More, right-click or hover) | `planned` |  |
| `SPO-APPTRACK-VIEW` | Security Policies & Objects > Application Tracking | view the form: enable application tracking; logging type (log as session created, or delay logging the first ... | `planned` |  |
| `SPO-SCHED-VIEW` | Security Policies & Objects > Schedules | view/list (Name, Description, Start Date, End Date, Second Start Date, Second End Date; expandable days ... | `planned` |  |
| `SPO-SCHED-DETAIL` | Security Policies & Objects > Schedules | Detailed View | `planned` |  |
| `SVC-ALG-VIEW` | Security Services > ALG | View the ALG form: Main (PPTP, RSH, RTSP, SQL, TALK, TFTP), DNS (doctoring, maximum message length, oversize ... | `planned` |  |
| `SVC-ACCPROF-LIST` | Security Services > Firewall Authentication > Access Profile | List profiles: Profile Name, Local Users, LDAP Servers, RADIUS Servers; show/hide columns | `planned` |  |
| `SVC-ACCPROF-SEARCH` | Security Services > Firewall Authentication > Access Profile | Advanced search | `planned` |  |
| `SVC-ACCPROF-DETAIL` | Security Services > Firewall Authentication > Access Profile | Detailed View (More, right-click or hover) | `planned` |  |
| `SVC-ADDRPOOL-LIST` | Security Services > Firewall Authentication > Address Pools | List pools: Identifier, Subnet, Primary/Secondary DNS, Primary/Secondary WINS, Named Address Ranges, Excluded ... | `planned` |  |
| `SVC-ADDRPOOL-SEARCH` | Security Services > Firewall Authentication > Address Pools | Search for text (partial or full keyword; X or Clear All resets) and column filter | `planned` |  |
| `SVC-ADDRPOOL-DETAIL` | Security Services > Firewall Authentication > Address Pools | Detailed View (More, right-click or hover) | `planned` |  |
| `GS-EXPLORE-COLUMNS` | Getting Started > Explore J-Web | Show/Hide Columns | `specified` | 004 |
| `GS-EXPLORE-FILTER` | Getting Started > Explore J-Web | Filter (category and subcategory pick lists) | `specified` | 004 |
| `BAN-LAUNCHPAD-OTHER` | Banner (top pane) | view serial number, system time, system uptime, number of active users, physical interfaces up and down | `planned` |  |

## `replace` rows (32): what J-Wicket offers instead

Owner approval is pending on every row.

<!-- ledger-rows: replace -->
| ID | Menu path | Operation | Priority | Spec | What replaces it |
| --- | --- | --- | --- | --- | --- |
| `MON-LOGS-SESSION-REFRESH` | Monitor > Logs > Session | Refresh (manual) | P0 | 004 | Live tail instead of a manual Refresh: report reads move their start time forward and remove duplicates, at a visible interval (default 5 s, never faster than meta.min_interval_s; UI-004-04, -39). Owner approval pending. |
| `MON-LOGS-SESSION-EXPORT` | Monitor > Logs > Session | Export to CSV (at most 100 rows) | P1 | 004 | J-Web exports at most 100 rows. The J-Wicket Logs view (working tree) exports every line it holds, up to its 2,000 to 10,000-line window, as raw .log, CSV or JSON, made in the browser with no extra device read (Spec 004 UI-004-42). Owner approval pending. |
| `MON-LOGS-THREATS-REFRESH` | Monitor > Logs > Threats | Refresh (manual) | P0 | 004 | Live tail instead of a manual Refresh: report reads move their start time forward and remove duplicates, at a visible interval (default 5 s, never faster than meta.min_interval_s; UI-004-04, -39). Owner approval pending. |
| `MON-LOGS-THREATS-EXPORT` | Monitor > Logs > Threats | Export to CSV (at most 100 rows) | P1 | 004 | J-Web exports at most 100 rows. The J-Wicket Logs view (working tree) exports every line it holds, up to its 2,000 to 10,000-line window, as raw .log, CSV or JSON, made in the browser with no extra device read (Spec 004 UI-004-42). Owner approval pending. |
| `MON-LOGS-WEBFILTER-REFRESH` | Monitor > Logs > Web Filtering | Refresh (manual) | P0 | 004 | Live tail instead of a manual Refresh: report reads move their start time forward and remove duplicates, at a visible interval (default 5 s, never faster than meta.min_interval_s; UI-004-04, -39). Owner approval pending. |
| `MON-LOGS-WEBFILTER-EXPORT` | Monitor > Logs > Web Filtering | Export to CSV (at most 100 rows) | P1 | 004 | J-Web exports at most 100 rows. The J-Wicket Logs view (working tree) exports every line it holds, up to its 2,000 to 10,000-line window, as raw .log, CSV or JSON, made in the browser with no extra device read (Spec 004 UI-004-42). Owner approval pending. |
| `MON-LOGS-VPN-REFRESH` | Monitor > Logs > VPN | Refresh (manual) | P0 | 004 | Live tail instead of a manual Refresh: report reads move their start time forward and remove duplicates, at a visible interval (default 5 s, never faster than meta.min_interval_s; UI-004-04, -39). Owner approval pending. |
| `MON-LOGS-VPN-EXPORT` | Monitor > Logs > VPN | Export to CSV (at most 100 rows) | P1 | 004 | J-Web exports at most 100 rows. The J-Wicket Logs view (working tree) exports every line it holds, up to its 2,000 to 10,000-line window, as raw .log, CSV or JSON, made in the browser with no extra device read (Spec 004 UI-004-42). Owner approval pending. |
| `MON-LOGS-ALLEVENTS-REFRESH` | Monitor > Logs > All Events | Refresh (manual) | P0 | 004 | Live tail instead of a manual Refresh: report reads move their start time forward and remove duplicates, at a visible interval (default 5 s, never faster than meta.min_interval_s; UI-004-04, -39). Owner approval pending. |
| `MON-LOGS-ALLEVENTS-EXPORT` | Monitor > Logs > All Events | Export to CSV (at most 100 rows) | P1 | 004 | J-Web exports at most 100 rows. The J-Wicket Logs view (working tree) exports every line it holds, up to its 2,000 to 10,000-line window, as raw .log, CSV or JSON, made in the browser with no extra device read (Spec 004 UI-004-42). Owner approval pending. |
| `MON-LOGS-SYSTEM-REFRESH` | Monitor > Logs > System | Refresh (manual) | P0 | 004 | Live tail: each poll returns only the lines after the cursor; rotation is shown as a reset (Spec 004 section 5.4; default 5 s). Owner approval pending. |
| `DA-BASIC-SAVE` | Device Administration > Basic Settings | page actions Save, Cancel and Commit; unsaved-change pop-up on navigation | P2 | 002 | One typed change, one review, a confirmed commit (Spec 002; catalog O6). Owner approval pending. |
| `DA-ROLES-VIEW` | Device Administration > Users & Roles > Roles | view/list roles (Name, Role Scope, Predefined or Custom) with Detailed View, show/hide columns, advanced ... | P1 |  | J-Wicket has no roles of its own; every read runs with the operator's Junos login class (ADR 0002, charter non-goal), and the scope banner names the Junos user the data was read as. A read view of login classes is planned (catalog O31, view P1). Owner approval pending. |
| `DA-ROLES-CREATE` | Device Administration > Users & Roles > Roles | Create a Role (custom: Full, Read-only or No access per menu and first-level submenu, including Commit ... | P4 |  | A Junos login-class editor would be a guided change through Spec 002 (catalog O31, edit P4). J-Web's menu-scoped roles do not map one-to-one to login classes, and how J-Web stores them is unknown (WP3 gap 2). Owner approval pending. |
| `DA-ROLES-EDIT` | Device Administration > Users & Roles > Roles | Edit a Role (custom roles only) | P4 |  | A Junos login-class editor would be a guided change through Spec 002 (catalog O31, edit P4). J-Web's menu-scoped roles do not map one-to-one to login classes, and how J-Web stores them is unknown (WP3 gap 2). Owner approval pending. |
| `DA-ROLES-DELETE` | Device Administration > Users & Roles > Roles | Delete a Role (custom roles only) | P4 |  | A Junos login-class editor would be a guided change through Spec 002 (catalog O31, edit P4). J-Web's menu-scoped roles do not map one-to-one to login classes, and how J-Web stores them is unknown (WP3 gap 2). Owner approval pending. |
| `DA-MT-LSYS-ENTER` | Device Administration > Multi Tenancy > Logical Systems | Enter LSYS (a root user switches context to a logical system) | P0 | 001 | J-Wicket's scope selector reads root, lsys:<name> or tenant:<name> as separate inventories, never merged, and never widens the operator's Junos scope (GET /api/inventory?scope=, Spec 001, fixtures). Sessions and logs are root only (Spec 004 open question 4). Owner approval pending. |
| `DA-CFG-UPLOAD` | Device Administration > Configuration Management > Upload | file path or Browse, then Upload and Commit; syntax checked before commit; the file replaces the existing ... | P4 |  | An uploaded file becomes a whole-configuration diff the operator reviews and applies only through Spec 002 (catalog O7; Spec 002 section 2.2 leaves it to a later spec). A whole configuration holds password hashes and secrets; needs the whole-configuration ADR first (catalog section 3.2). Owner approval pending. |
| `DA-CFG-HISTORY-ROLLBACK` | Device Administration > Configuration Management > History | Rollback to a version (loads and commits at once, unlike the CLI rollback; logged 'Rolled back via ... | P2 | 002 | Rollback is a change like any other: previewed, then a confirmed commit that Junos undoes unless the operator confirms it (Spec 002 section 9.4; catalog O10 and N5). Owner approval pending. |
| `DA-TOOLS-CLIVIEW` | Device Administration > Tools > CLI Viewer | view the current configuration, including uncommitted changes; OK, Commit Options > Commit, Cancel | P1 | 001 | Scoped configuration views with group provenance from the committed database (the Spec 001 pattern, built on fixtures for policies, zones, address books and applications). J-Wicket never shows the shared candidate (ADR 0005) or a whole configuration with secrets; committing is Spec 002's job (catalog O19). Owner approval pending. |
| `DA-TOOLS-CLIEDIT` | Device Administration > Tools > CLI Editor | edit the configuration as text; Commit loads, replaces and commits; syntax checked; previous configuration ... | P4 |  | A text change becomes a Spec 002 diff the operator reviews (catalog O20); whole-configuration replace and lost comments are the J-Web hazards. A whole configuration holds password hashes and secrets; needs the whole-configuration ADR first (catalog section 3.2). Owner approval pending. |
| `DA-TOOLS-PNC` | Device Administration > Tools > Point and Click CLI | tree editor over the top-level stanzas (access ... wlan): Configure, Edit, Delete per stanza; Expand all ... | P4 |  | Purpose-built pages with typed changes through Spec 002 (catalog O21). Owner approval pending. |
| `NET-PROXYARP-WIZARD` | Network > NAT > Proxy ARP/ND | Launch Wizard (opens the NAT wizard) | P4 |  | Replace (catalog W5): NAT read views first, then a NAT builder on the Spec 003 pattern that previews the rule, pool and proxy-ARP changes together, keeps rule-set order and group ownership, and commits only through Spec 002. Spec 003 lists NAT as its non-goal pointing here. J-Web's wizard steps are undocumented in 24.4. Owner approval pending. |
| `SPO-SECPOL-CREATEBEFOREAFTER` | Security Policies & Objects > Security Policies | More > Create Rule Before / Create Rule After (also right-click): the new rule inherits name and zones ... | P2 | 003 | J-Wicket does not create an any/any Deny placeholder, which saved as is would shadow every later rule in its context. The operator states the match and the placement before or after a named rule in one policy.add (Spec 003 sections 4.3 and 6.4). Owner approval pending. |
| `SPO-SECPOL-SAVEDISCARD` | Security Policies & Objects > Security Policies | page-level Save or Discard of staged rule edits, then the banner commit, before any further action | P2 | 002 | Every J-Wicket change is one typed change with one review: private-copy preview, diff, then a confirmed commit (Spec 002 section 2.2). There is no J-Wicket staging area. Owner approval pending. |
| `SDC-MANAGEDLABEL` | Add SRX Series Firewall to Security Director Cloud | after onboarding the label reads 'Managed by Juniper Security Director Cloud' (doc: 'Manged'), greyed out; it ... | P0 | 001 | J-Wicket shows 'also managed from <client>' from outbound-SSH clients in the configuration, worded as detected, never 'not managed' (facts.central_management, AC-001-15, fixtures; ADR 0009); which client names mean SD, SD Cloud or Mist is Q-MGMT-01. Owner approval pending. |
| `BAN-COMMIT` | Banner (top pane) | Commit your configurations | P2 | 002 | Commit only what this operator previewed, under an exclusive lock that fails if anyone else has uncommitted changes, and always as a confirmed commit (Spec 002; catalog O1). Owner approval pending. |
| `BAN-VIEWCHANGES` | Banner (top pane) | View configuration changes | P2 | 002 | The device diff and the effective view after inheritance and commit scripts, bound by hash to what is committed (Spec 002 section 2.2; catalog O2). Reading the shared candidate is outside ADR 0005. Owner approval pending. |
| `BAN-AUTOROLLBACK` | Banner (top pane) | Commit the changes with autorollback | P2 | 002 | Every J-Wicket commit is a confirmed commit; confirmation is a second, explicit commit from the browser, and Junos's timer is the only automatic rescue (Spec 002 P4, P5; catalog O3). Owner approval pending. |
| `BAN-DISCARD` | Banner (top pane) | Discard your configuration | P2 | 002 | J-Wicket discards only its own private copy or its own load under its own lock, never the shared candidate (Spec 002 section 2.2). Owner approval pending. |
| `BAN-SCOPE-ENTER` | Banner (top pane) | select a tenant or LSYS to enter it; since 23.1R1 shows name and count (for example 'Tenant (5)'); points to ... | P0 | 001 | J-Wicket's scope selector (root, lsys:<name>, tenant:<name>) with per-scope policy counts (scope_summaries); each scope is a separate inventory read from the committed configuration, never widened beyond the operator's Junos identity (Spec 001, fixtures; catalog O39). Sessions and logs are root only (Spec 004). Owner approval pending. |
| `BAN-SCOPE-EXIT` | Banner (top pane) | Exit Tenant or Exit Logical System to return to root context; data refreshes once the configuration cache ... | P0 | 001 | Choosing root is a fresh committed read; J-Wicket keeps no configuration cache between reads. Owner approval pending. |

## `out-of-scope` rows (23): why

Owner approval is pending on every row. Each keeps `P4`, which applies only if the owner rejects the proposal.

<!-- ledger-rows: out-of-scope -->
| ID | Menu path | Operation | Priority | Reason |
| --- | --- | --- | --- | --- |
| `DA-CLUSTER-SETUP-WIZARD` | Device Administration > Cluster Management > Cluster (HA) Setup | run the wizard: select unit (Node 0 or Node 1), primary configuration, Reboot and Continue, secondary ... | P4 | Reason: it erases and reboots both units, needs physical access to recover, and JET files are not synchronized to the peer, so J-Wicket would remove itself (catalog W3). Owner approval pending. |
| `DA-OPS-HALT` | Device Administration > Operations > Reboot | Halt immediately | P4 | Reason: recovery needs physical access (catalog O12). Owner approval pending. |
| `DA-SW-UPLOAD` | Device Administration > Software Management > Upload Package | choose a file; Reboot If Required; Do not save backup; Format and re-partition; Upload and Install Package | P4 | Reason: J-Wicket would take a large upload through its bounded HTTP server and then upgrade the system it runs on; five of J-Web's 2023 advisories were unauthenticated file upload or read (catalog O14). Q-RT-05. Owner approval pending. |
| `DA-SW-ROLLBACK` | Device Administration > Software Management > Rollback | Rollback to the previously installed version (cannot be stopped; reboot needed) | P4 | Reason: as DA-SW-UPLOAD (catalog O15). Owner approval pending. |
| `DA-SW-INSTALL` | Device Administration > Software Management > Install Package | fetch from FTP or HTTP (package location, user, password; Reboot If Required; Do not save backup; Format and ... | P4 | Reason: as DA-SW-UPLOAD, and absent from the 24.4 guide (catalog O16). Needs a live 24.4 J-Web check. Owner approval pending. |
| `DA-CFG-HISTORY-DOWNLOAD` | Device Administration > Configuration Management > History | Download a version (ASCII) | P4 | Reason: a whole configuration carries secrets; out of scope until a whole-configuration ADR says how they are handled (catalog O8). Owner approval pending. |
| `DA-TOOLS-CLITERM` | Device Administration > Tools > CLI Terminal | interactive Junos CLI (operational and configuration modes; ? help; Space completes, Tab does not) | P4 | Reason: operators already have SSH, and a browser shell widens the attack surface (catalog O18). Owner approval pending. |
| `DA-RESET` | Device Administration > Reset Configuration | Reset, warning, Proceed to Launch: resets the configuration and reruns the Setup Wizard | P4 | Reason: the reset removes J-Wicket's own configuration (extension service, scripts, NETCONF), so J-Wicket cannot run the wizard that follows (catalog W2). Owner approval pending. |
| `NET-IPSEC-IKEPKG` | Network > VPN > IPsec VPN | Install / Uninstall the IKE package from Global Settings (reboot required afterwards) | P4 | Out of scope (proposed, catalog O14): a software install on the device J-Wicket runs on, followed by a reboot, outside the configuration-change model; J-Web's upload and install paths have a history of advisories. The package is installed from the CLI. Priority applies only if the owner rejects the proposal. Owner approval pending. |
| `NET-DYNVPN-WIZARD` | Network > VPN > Dynamic VPN | Launch Wizard (opens the VPN wizard) | P4 | Out of scope (proposed, catalog W6 Dynamic VPN wizard): SRX300 line only and its steps are not documented in 24.4, so there is no parity target; the page's own forms remain P4 rows. Priority applies only if the owner rejects the proposal. Owner approval pending. |
| `GS-ACCESS-FACTORYDEFAULT` | Getting Started > Access the J-Web User Interface | first login on a factory-default device: browse to https://<IP>; the Setup Wizard opens (per-model ... | P4 | Reason: J-Wicket runs from Junos configuration (extension service, Python, NETCONF), so it cannot exist on a factory-default device; factory setup stays with the console, J-Web or ZTP (catalog W1). Owner approval pending. |
| `GS-ACCESS-SKIPSETUP` | Getting Started > Access the J-Web User Interface | Skip Setup: Device Password screen; enter the root password, OK commits it; log in again | P4 | Reason: as GS-ACCESS-FACTORYDEFAULT (catalog W1). Owner approval pending. |
| `GS-SETUP-MODE` | Getting Started > The J-Web Setup Wizard | choose a mode (Standalone, Cluster (HA), Passive (Tap)) and Start; the wizard validates required fields when ... | P4 | Reason: a first-boot wizard on a factory-default device, where J-Wicket cannot run (catalog W1). Owner approval pending. |
| `GS-SETUP-CREDENTIALS` | Getting Started > The J-Web Setup Wizard | Device Credentials step (device name; root password, mandatory; SSH for root; admin account) | P4 | Reason: a first-boot wizard on a factory-default device, where J-Wicket cannot run (catalog W1). On an installed device the same settings are the DA-BASIC-SYSID and DA-USERS rows. Owner approval pending. |
| `GS-SETUP-TIME` | Getting Started > The J-Web Setup Wizard | Time step (time zone; NTP servers; computer time; manual date and time) | P4 | Reason: a first-boot wizard on a factory-default device, where J-Wicket cannot run (catalog W1). On an installed device the same settings are the DA-BASIC-TIME rows. Owner approval pending. |
| `GS-SETUP-MGMT` | Getting Started > The J-Web Setup Wizard | Management Interface step (interface or None, IPv4/IPv6 address, mask, static route, next hop; Access ... | P4 | Reason: a first-boot wizard on a factory-default device, where J-Wicket cannot run (catalog W1). On an installed device the same settings are the DA-BASIC-MGMT and DA-BASIC-SVC rows. Owner approval pending. |
| `GS-SETUP-ZONES` | Getting Started > The J-Web Setup Wizard | Zones & Interfaces step (trust-to-untrust policy; trust and untrust zone interfaces add, edit, delete ... | P4 | Reason: a first-boot wizard on a factory-default device, where J-Wicket cannot run (catalog W1). On an installed device the same settings are the SPO-ZONES and SPO-SECPOL rows; the wizard creates trust and untrust even when absent, a brownfield hazard (catalog section 3.2). Owner approval pending. |
| `GS-SETUP-DNS` | Getting Started > The J-Web Setup Wizard | DNS Servers & Default Gateways step | P4 | Reason: a first-boot wizard on a factory-default device, where J-Wicket cannot run (catalog W1). On an installed device the same settings are the DA-BASIC-SYSID and DA-BASIC-MGMT rows. Owner approval pending. |
| `GS-SETUP-TAP` | Getting Started > The J-Web Setup Wizard | Tap Settings step (Passive): Tap interface; IP-IP and GRE tunnel inspection | P4 | Reason: a first-boot wizard on a factory-default device, where J-Wicket cannot run (catalog W1). Owner approval pending. |
| `GS-SETUP-ADVSVC` | Getting Started > The J-Web Setup Wizard | Security Policy & Advanced Services step (Passive): Content Security licence key and Install License (WF, AV ... | P4 | Reason: a first-boot wizard on a factory-default device, where J-Wicket cannot run (catalog W1). Owner approval pending. |
| `GS-SETUP-SUMMARY` | Getting Started > The J-Web Setup Wizard | Summary step: Edit Configuration or Finish (one commit; on failure the CLI error shows and the wizard stays ... | P4 | Reason: a first-boot wizard on a factory-default device, where J-Wicket cannot run (catalog W1). Owner approval pending. |
| `SDC-ADD` | Add SRX Series Firewall to Security Director Cloud | add the device: location and SD Cloud account email and password, Next; organization, Proceed; progress while ... | P4 | Reason: onboarding hands configuration ownership to a cloud service, passes cloud credentials through the device and commits configuration from the Cloud API with no documented preview (catalog W8); managing other devices is a charter non-goal. Owner approval pending. |
| `BAN-COMMITPREFS` | Banner (top pane) | Commit the changes in your preferred way | P4 | Reason: one commit model, Spec 002's (catalog O5). Owner approval pending. |

## Gaps and open questions

From the notes of both halves and the merge. Each says who decides or what settles it.

### Owner decisions

1. **Sign-in and sign-out are built but held at `planned`** (`GS-ACCESS-LOGIN`, `BAN-USER`). The code and its tests exist (ADR 0002, `api.py`, `auth/`, `tests/test_auth.py`), but `implemented` needs a spec and no numbered spec owns sign-in. Write a sign-in spec, or add sign-in criteria to Spec 001. `GS-ACCESS-HTTPS` (`P0`, `planned`) is the TLS half: `settings.py` already refuses a non-loopback bind without a certificate, but the TLS and certificate-provisioning spec that governance phase 1 names is not written ([ADR 0003](../adr/0003-tls-off-loopback.md)) and Q-TLS-01 has not run.
2. **Security Services read priority.** Charter section 6 puts content security, IDP and advanced threat features at `P4`; catalog W7 and W11 propose read views at `P1`. The ledger follows the charter. If the owner takes the catalog's view, 48 Security Services read rows (ids ending `-LIST`, `-SEARCH`, `-DETAIL` or `-VIEW`) move to `P1`, and G2 grows with them.
3. **`P1` proposals beyond the charter's list.** ALG read, Access Profile and Address Pools reads (the `P1` IPsec VPN page's remote-access VPNs refer to them) and RIP read are `P1`; CoS, Application QoS and Compliance reads are `P4`. On the other menus, read views are `P1` and maps, charts and reports `P3`. `P1` rows gate G2, so each is worth the owner's confirmation.
4. **Rows held at `specified` for their browser check.** The 38 Spec 001 and Spec 004 rows listed in [the point](#the-point) pass every backend and browser-engine criterion on fixtures and wait only for AC-001-21 or AC-004-20. The method keeps them at `specified` because the status means a row's acceptance criteria pass. The alternative is an owner decision: redefine `implemented` as "every fixture-runnable criterion except the browser check passes", record it in the [method](README.md#5-statuses) and governance, and mark each such row "backend only".
5. **Show/Hide Columns on log pages** (`MON-LOGS-*-COLUMNS`) is `planned` `P3`, not `replace`. The Logs view shows verbatim, highlighted lines with a decoded field table, not a column grid. Whether that counts as a better alternative is the owner's call.
6. **All 32 `replace` and 23 `out-of-scope` rows await approval**, and all priorities are proposals.

### Unknowns a lab run settles

7. **Existence in the 24.4 UI is unknown** for `DASH-THREATACTIVITY`, `DASH-PREFS`, `DA-SW-INSTALL` (cited from the 23.4 guide: the only topic the 24.4 guide dropped) and `GS-EXPLORE-WIZ-PPPOE`. A J-Web 24.4 reference observation on the lab device settles them ([governance 4.12](../governance.md#412-proposed-additions)). It would also find pages the guide does not document: the ledger is only as complete as the guide.
8. **The Junos mapping is inferred on most rows.** RPC names are known only for the allowlisted reads, the guide's Network chapter names almost no statements, and 34 rows carry an unknown part in `junos_hierarchy`. Q-REL-01 settles reply shapes; a lab `show | compare` after each J-Web save would settle what J-Web writes.
9. **Log families per report type are inferred.** Which J-Web threat families the `screen`, `idp-all`, `utm-all` and `threat` report types hold is Q-LOG-01. The Web Filtering log rows are built through `utm-all` on that inference (held at `specified`, gap 4). ATP log rows stay `planned`: no `atp-*` type is allowlisted.
10. **Save and commit semantics** of the Network and Security Services pages are not documented. That OK, Save and Finish write the candidate configuration and the banner's Commit menu commits it is inferred. Cross-cutting (catalog O6).
11. **Units.** J-Web's AppQoS rate limiter takes Mbps and MB, Junos takes kbps and bytes; the conversion J-Web applies is unknown (`NET-APPQOS-RL-ADD`).

### Code and spec follow-ups

12. **"Nothing dropped silently" now holds per object, with two exceptions.** Since 2026-11-24 `inventory.py` reports unmodeled settings for zones, interfaces, address entries, sets and books, applications and application sets as well as policies (AC-001-06), so `application-tracking`, `source-identity-log`, `tcp-rst` and application fields such as `application-protocol` are warned about. Still not reported: statements inside an application `term` (terms are counted only) and functional zones such as `management`, which the inventory does not read (`SPO-ZONES-ZONE-VIEW`, `SPO-SERVICES-CUSTOM-VIEW`).
13. **The inventory filter reads only `[edit security]` `policies`, `zones` and `address-book`** (since 2026-11-24, Spec 001 open question 8), so NAT, IKE, IPsec, UTM, IDP, ALG and remote-access configuration, and their secrets, are no longer fetched. Every IPsec, NAT and Security Services row that later becomes a read needs its own narrow filter. Root `[edit services]`, `[edit access]`, `[edit interfaces]`, routing and CoS are not fetched at all.
14. **Working-tree dependence.** Several rows cite UI code that is not committed yet (`static/js/views/overview.js`, the `views/logs.js` export, saved queries in `widgets/querybar.js`). Re-check `DASH-VIEW`, `MON-LOGS-*-EXPORT`, `-SAVEFILTER` and `-LOADFILTER` when it lands. The v2 Policies, Objects, Sessions and Logs views are built in the working tree, not yet committed, not yet checked in a browser (AC-001-21 and AC-004-20 not met), so the 38 rows they would move stay `specified` ([gap 4](#owner-decisions)).
15. **Write-row notes cite Spec 002 check 9** (access path at risk, no filters on lo0). That check is proposed in Spec 002, not accepted.
16. **J-Wicket-only features have no rows.** The ledger is keyed to J-Web pages, so the inventory export, the live flow-session table and the scope banner's extra fields appear in the notes of the closest row (`SPO-SECPOL-VIEW`, `MON-LOGS-SESSION-VIEW`, `BAN-DEVICEDETAILS`) and in the catalog (N1 to N5).

### Data quality

17. **Secrets.** IPsec pre-shared keys, Dynamic VPN templates, access profiles (RADIUS and LDAP secrets, local users), UAC, Active Directory, JIMS and routing-protocol authentication all carry secrets. The row notes say a read view must copy only modeled fields, as `inventory.py` does.
18. **Guide defects** (the Compliance SRX300 contradiction, the BGP task-list link, the Dynamic VPN "Resource Profiles" text, RIP's "logical system profile", the Local Authentication and Authentication Priority copy errors) are kept in `platform_notes` or `jwicket_notes` and not copied as behaviour.
19. **Split rows.** `DASH-W-SYSID-*`, `DASH-W-SECRES-*` and `BAN-LAUNCHPAD-*` split one J-Web element so that the built part does not claim the rest.
20. **Markers in `junos_hierarchy`.** Before 2026-11-24, 323 of the 881 cells used none of the bracket or parenthesis markers the [method](README.md#4-columns) listed: 100 were a bare `n/a`, 25 used the undefined "(statement exists)" or "(exists)", two (`DA-USERS-EDIT`, `DA-USERS-DELETE`) had no marker at all, and the rest carried the marker word inside the text. The method now defines `exists` and the `n/a (<reason>)` and `as <ID>` forms; the bare `n/a` cells read "n/a (UI operation with no Junos hierarchy of its own; inferred)"; the two `DA-USERS` rows are marked; and [`tests/test_docs.py`](../../tests/test_docs.py) fails on a cell without a marker. Two styles remain: Network and Security Services rows lead with `[inferred]`, `[CLI-ref verified]`, `[doc]` or `[unknown]`, the other menus end with a parenthesis. A later pass may unify them.
21. **Source status.** 5 rows are not `verified`: `DASH-THREATACTIVITY`, `DASH-PREFS`, `DA-SW-INSTALL`, `NET-DYNVPN-LIST`, `GS-EXPLORE-WIZ-PPPOE`. `NET-DYNVPN-LIST` is `inferred` because the guide records Add, Edit and Delete on Dynamic VPN but no grid columns.
22. **Row granularity differs by half.** Network and Security Services fold Show/Hide Columns, Expand/Collapse All and Clear All Selections into the page's list row, and advanced search with the column filter into one `-SEARCH` row. The other menus give Show/Hide Columns its own `-COLUMNS` row. Row counts are therefore not strictly comparable across menus; a later pass should pick one rule.

## Merge record

- **Sources.** Half a: Network and Security Services, 367 rows, from research work packages WP1 and WP2. Half b: Dashboard, Monitor, Device Administration, Security Policies & Objects, Getting Started, Security Director Cloud onboarding and the banner, 552 rows, from WP3 to WP5 and the critic's missing-page list. Statuses in both come from the code and Specs 001 to 004, not from the specs' intentions.
- **Order.** Menus in the order Dashboard, Monitor, Device Administration, Network, Security Policies & Objects, Security Services, then the cross-cutting rows: Getting Started, Security Director Cloud onboarding, the banner. Within a menu, the guide's table-of-contents order.
- **Duplicates dropped (38).** Half b added Network and Security Services rows for pages the critic and the wizard catalog named, to be kept only if half a had no row. They were matched by menu path and operation, not by id. Every one is covered:

| Half-b row (dropped) | Operation | Covered by |
| --- | --- | --- |
| `NET-IF-GLOBALOPTS` | edit Global Options (MAC table size, MAC limit) | `NET-IFACE-GLOBAL` |
| `NET-NAT-POOLS-GLOBALOPTS` | edit Global Options | `NET-NATPOOL-GLOBAL` |
| `NET-ROUTING-POLICIES-GLOBALOPTS` | edit Global Options | `NET-RTPOL-GLOBAL` |
| `NET-ROUTING-POLICIES-TEST` | test a routing policy | `NET-RTPOL-TEST` |
| `NET-ROUTING-POLICIES-CLONE` | clone a routing policy | `NET-RTPOL-CLONE` |
| `NET-VPN-IPSEC-GLOBALSETTINGS` | edit Global Settings | `NET-IPSEC-GLOBAL` |
| `NET-VPN-IPSEC-RA-JSC` | create a remote access VPN | `NET-IPSEC-JSC-ADD` |
| `NET-VPN-IPSEC-RA-NCP` | create a remote access VPN | `NET-IPSEC-NCP-ADD` |
| `NET-VPN-DYNVPN-GLOBALSETTINGS` | edit Global Settings | `NET-DYNVPN-GLOBAL` |
| `NET-VPN-DYNVPN-TEMPLATE` | edit the IPsec template | `NET-DYNVPN-TEMPLATE` |
| `NET-VPN-DYNVPN-WIZARD` | Launch Wizard (guided steps; steps not documented) | `NET-DYNVPN-WIZARD` |
| `NET-NAT-PROXYARP-WIZARD` | Launch Wizard (basic NAT steps; not documented) | `NET-PROXYARP-WIZARD` |
| `NET-DHCP-SERVER-GROUPS-GLOBALSETTINGS` | edit Global Settings | `NET-DHCPS-ORDER` |
| `NET-LAG-GLOBALSETTINGS` | edit Global Settings | `NET-LAG-GLOBAL` |
| `NET-LAG-ADDLOGICAL` | add a logical interface to a LAG | `NET-LAG-ADDIFL` |
| `NET-VLAN-ASSIGNIF` | assign an interface to a VLAN | `NET-VLAN-ASSIGN` |
| `NET-WLAN-AP` | create, edit and delete access points | `NET-WLAN-AP-ADD`, `NET-WLAN-AP-EDIT`, `NET-WLAN-AP-DELETE` |
| `NET-WLAN-RADIO` | create, edit and delete radio settings | `NET-WLAN-RADIO-ADD`, `NET-WLAN-RADIO-EDIT`, `NET-WLAN-RADIO-DELETE` |
| `NET-RIP-GLOBAL` | edit and delete RIP global settings | `NET-RIP-GLOBAL-EDIT`, `NET-RIP-GLOBAL-DELETE` |
| `NET-BGP-GLOBALINFO` | edit (or disable) global information | `NET-BGP-GLOBAL-EDIT`, `NET-BGP-GLOBAL-DISABLE` |
| `NET-APPQOS-RATELIMITER` | add, edit, clone and delete rate limiter profiles | `NET-APPQOS-RL-ADD`, `NET-APPQOS-RL-EDIT`, `NET-APPQOS-RL-CLONE`, `NET-APPQOS-RL-DELETE` |
| `SS-CS-AV-WIZARD` | + opens the wizard: intro page, Next, pages per Table 242, Finish, Summary ... | `SVC-AV-ADD` |
| `SS-CS-WF-ADD` | + opens tabs per Tables 250-252; Finish saves, Back returns, Cancel discards | `SVC-WF-ADD` |
| `SS-CS-CF-ADD` | complete the pages, Finish, Summary page | `SVC-CF-ADD` |
| `SS-CS-POLICY-ADD` | Next through Name and per-protocol antivirus and web filtering profile pages ... | `SVC-CSPOL-ADD` |
| `SS-FWAUTH-JIMS-ADD` | General page, Next, Advanced Settings page, Finish | `SVC-JIMS-ADD` |
| `SS-IPS-POLICIES-IMPORT` | import predefined IPS policies | `SVC-IPSPOL-IMPORT` |
| `SS-IPS-POLICIES-RULES` | add, edit and delete IPS policy rules | `SVC-IPSPOL-RULE-ADD`, `SVC-IPSPOL-RULE-EDIT`, `SVC-IPSPOL-RULE-DELETE` |
| `SS-IPS-SIGS-SNORT` | import Snort rules | `SVC-IPSSIG-IMPORT-SNORT` |
| `SS-IPS-SIGS-GROUPS` | create static and dynamic signature groups | `SVC-IPSSIG-ADD-STATIC`, `SVC-IPSSIG-ADD-DYNAMIC` |
| `SS-MSP-DNSFILTER` | configure the DNS filter | `SVC-MSP-DNSFILTER` |
| `SS-ATP-SECINTEL-SINKHOLE` | configure DNS sinkhole settings | `SVC-SECINTEL-SINKHOLE` |
| `SS-CS-CUSTOMOBJ-MIME` | add a MIME Pattern List | `SVC-CUSTOBJ-ADD-MIME` |
| `SS-CS-CUSTOMOBJ-FILEEXT` | add a File Extension List | `SVC-CUSTOBJ-ADD-FILEEXT` |
| `SS-CS-CUSTOMOBJ-PROTOCMD` | add a Protocol Command List | `SVC-CUSTOBJ-ADD-PROTOCMD` |
| `SS-CS-CUSTOMOBJ-URLPATTERN` | add a URL Pattern List | `SVC-CUSTOBJ-ADD-URLPAT` |
| `SS-CS-CUSTOMOBJ-URLCATEGORY` | add a URL Category List | `SVC-CUSTOBJ-ADD-URLCAT` |
| `SS-CS-CUSTOMOBJ-CUSTOMMSG` | add a Custom Message List | `SVC-CUSTOBJ-ADD-CUSTMSG` |

- **Kept and renamed (2).** Half a had no row for the guide's two Content Security workflow topics: `SS-CS-AV-EXAMPLE` became `SVC-AV-WORKFLOW`; `SS-CS-WF-EXAMPLE` became `SVC-WF-WORKFLOW`. Both stay `unassessed` `P4`.
- **Held back (2).** `GS-ACCESS-LOGIN` and `BAN-USER` arrived as `implemented` with no spec; they are `planned` here until a spec covers sign-in (gap 1).
