# Security policy

J-Wicket is at the **foundation stage**. It is not installable on a production SRX, no version is
supported, and nothing in this repository has run on a customer platform. Lab pre-releases, when
the owner publishes one, are lab-only and unsupported. If you find a vulnerability, report it
**privately to the project owner**. Do not open a public issue.

The full threat model, trust boundaries and the reasoning behind each control are in
[docs/architecture.md](docs/architecture.md#14-threat-model).

## Report a vulnerability

- **Do not** open a public issue, pull request or discussion about it, and do not post details
  anywhere public.
- If the repository's **Security** tab offers **Report a vulnerability** (GitHub private
  vulnerability reporting), use it.
- Otherwise, contact the project owner (Corey Robertson) through a private channel you already
  have. Ask for a private place to send details before you send them.
- Include, where you can:
  - the commit or pre-release tag, or the bundle's `payload_sha256` from
    `python3 -I dist/jwicket.py --bundle-self-test`;
  - the file, route or setting involved;
  - steps to reproduce, preferably against the development server (`make dev`) and its synthetic
    fixtures;
  - what an attacker needs (no session, a signed-in session, a particular login class, the
    `netconf` or `lab-token` backend, local access to the device) and what they gain.
- Test only against the development server, your own disposable lab equipment, or devices you are
  authorized to test. Never against a production firewall.

The project owner acknowledges the report, decides the fix and its disclosure, and credits you if
you want. There is no response-time commitment at this stage.

Vulnerabilities in Junos or J-Web themselves belong to Juniper's security incident response team,
not here. If a J-Wicket finding depends on a Junos behaviour, say so in the report.

## Supported versions

| Version | Supported |
| --- | --- |
| `0.1.0.dev1` (the default branch) | **No.** Foundation stage: development and lab qualification only |
| Lab pre-releases `vX.Y.Z.devN` (none published yet; the first, `v0.1.0.dev1`, waits for the owner's go) | **No.** Lab only and unsupported: for qualification runs on a disposable lab vSRX, or lab hardware attested with `--lab-hardware` and a typed `lab only`, never a production firewall. A fix lands in a later pre-release, not in a published one, which is immutable |

No release or pre-release has been made. Fixes land on the default branch. Support and
signed-package positions are decided at gates G4 and G5 ([governance.md](docs/governance.md)).
Until then J-Wicket runs only on lab devices: by the lab procedure in
[docs/deploy-lab.md](docs/deploy-lab.md) (a disposable vSRX or owner-approved lab hardware; a loopback bind behind
an SSH tunnel where the release allows forwarding, or TLS on fxp0 as on the lab SRX4100),
or by the lab-gated installers of [docs/install.md](docs/install.md), which have not run on any
device and whose design is [Spec 006](docs/specs/006-installation.md).

## Security properties and their tests

Every test below runs in CI on Python 3.7, 3.9, 3.11 and 3.13 (`make test` locally), **against synthetic
fixtures**, except `PinnedHttpsTests`, which needs the pinned `cryptography` (50.0.2 needs Python 3.9.2
or later) and is skipped where it is not installed: it runs in the `install-autospec` job, on Python
3.12 with the hash-pinned `requirements-install.txt`. A passing test shows what the code does; it proves nothing about a device. The device
tests that will are named in the last column and defined in [governance.md](docs/governance.md).

| Property | Code | Tests | Proven on a device by |
| --- | --- | --- | --- |
| Junos decides identity and rights. Sign-in hands the user name and password to Junos in a NETCONF session to the device's own loopback; J-Wicket stores no password and has no roles. Only the typed password can sign anyone in: PyEZ is told not to offer the keys in the daemon account's `~/.ssh` (`look_for_keys=False`) and not to read its `~/.ssh/config` (`ssh_config` set to `/dev/null`), whose `Port`, `HostName`, `IdentityFile` and `ProxyCommand` would otherwise override the checked loopback address and port. Both are `Device()` keyword arguments of PyEZ 2.7.4 (read in its `jnpr/junos/device.py`); PyEZ ignores keyword arguments it does not know, so whether the on-box PyEZ honours them is checked by Q-AUTH-01. | [`auth/backends.py`](src/jwicket/auth/backends.py), [`junos/session.py`](src/jwicket/junos/session.py) | `NetconfBackendTests` ([`test_auth.py`](tests/test_auth.py)); `test_open_passes_credentials_to_pyez_and_classifies_failures` ([`test_session.py`](tests/test_session.py)) | Q-AUTH-01, Q-AUTH-02, Q-AUTH-03 |
| Read-only. Only allowlisted read RPCs can be sent (`ALLOWED_RPCS`, every name starting `get-`). An RPC name is a constant, except the on-box report reads, whose name is `get-sec-log-report-detail-<type>` with `<type>` taken from a fixed list (`REPORT_TYPES`) after the request's value is checked against it; every name is checked against `ALLOWED_RPCS` before it is sent. Configuration reads are a separate method (`get_configuration`, not in `ALLOWED_RPCS`) that takes only the constant filters in `junos/session.py`. No configuration filter is built from request input. | [`junos/session.py`](src/jwicket/junos/session.py), [`live.py`](src/jwicket/live.py), [`junos/logs.py`](src/jwicket/junos/logs.py) | `test_allowlist_is_read_only`, `test_check_rpc`, `test_disallowed_rpc_never_reaches_the_device`, `test_disallowed_rpc_refused_before_pyez_is_touched` ([`test_session.py`](tests/test_session.py)); `test_report_read_and_validation` ([`test_live.py`](tests/test_live.py)) | Q-REL-01 |
| Narrow reads, no secrets out. Configuration reads use fixed subtree filters: for the inventory, `[edit security]` `policies`, `zones` and `address-book` plus `applications`, per scope (each logical or tenant system narrowed to its name and the same subtrees), the configured time zone (the one `system time-zone` leaf; owner decision OD-05's default, which the owner may veto), the outbound-SSH clients and `chassis high-availability`; never all of `[edit security]`, which holds IKE pre-shared keys, and never a whole logical system. That Junos answers such a filter with the key and only the selected children of every list entry, with its `inactive` attribute, is **inferred** from subtree filtering and checked by Q-REL-01. Only modelled fields are returned; outbound-SSH `secret` and `device-id` never are. | [`junos/session.py`](src/jwicket/junos/session.py), [`junos/inventory.py`](src/jwicket/junos/inventory.py), [`junos/facts.py`](src/jwicket/junos/facts.py) | `test_inventory_filter_is_narrow`, `test_minimal_filter` ([`test_session.py`](tests/test_session.py)); `test_no_secret_in_any_response`; `test_no_secret_or_device_id_in_serialised_inventory`; `test_secret_never_returned_even_when_shaped_like_a_target` | Q-REL-01 |
| Denied reads show as denied, never as empty or as sample data. A reply that is not in the expected shape (no `<configuration>`) is a `failed` panel, not an HTTP 500. | [`api.py`](src/jwicket/api.py), [`live.py`](src/jwicket/live.py), [`junos/errors.py`](src/jwicket/junos/errors.py) | `test_auditor_is_denied_the_configuration`; `test_denied_log_read_is_an_explicit_state`, `test_denied_or_unsupported_summary_is_that_state_without_a_list`, `MalformedReplyTests` ([`test_live.py`](tests/test_live.py)); `test_missing_security_section_is_not_presented_as_empty`; `test_reply_without_configuration_is_a_failed_panel` ([`test_api_units.py`](tests/test_api_units.py)); `ClassifyTests` ([`test_errors.py`](tests/test_errors.py)) | Q-AUTH-03 |
| The listener fails closed. Default bind `127.0.0.1`; any other bind needs TLS (no plaintext switch); the NETCONF host must be loopback and its port below 1024; `lab-token` only on loopback; an unknown or out-of-range setting refuses the start. | [`settings.py`](src/jwicket/settings.py) | `TransportRuleTests`, `AuthRuleTests`, `StructureTests`, `RangeTests` ([`test_settings.py`](tests/test_settings.py)) | Q-RT-02, Q-TLS-01 |
| Trusted files only. Settings, token and TLS files must be regular files owned by the daemon account or root, not writable by others; secrets mode 0600. Every directory from `/` down to the file must belong to root or the daemon account and must not be group- or other-writable unless sticky; a symbolic link on the way is followed only if root owns it (at most 40). The settings file and the lab token are opened first (`O_NOFOLLOW`), their owner, mode and type are taken from the opened file (`fstat`), and the name must still lead to the same file (device and inode). TLS files are checked by path and then loaded by path, because `ssl` loads certificates only from a path; the directory rule is what keeps another account from swapping them in between. | [`settings.py`](src/jwicket/settings.py), [`app.py`](src/jwicket/app.py) | `FileTrustTests`, including `test_owner_and_mode_come_from_the_opened_file`, `test_directory_owned_by_another_account_refused`, `test_symlinked_directory_followed_only_when_root_owns_the_link`, `test_tls_files` ([`test_settings.py`](tests/test_settings.py)) | Q-RT-02, Q-TLS-01 |
| Web sessions. A random token in the cookie; the server keeps only its SHA-256. `HttpOnly`, `SameSite=Strict`, plus `Secure` and the `__Host-` prefix under TLS. The cookie name carries a random suffix chosen at each start (`jwicket-<8 hex>`, or `__Host-jwicket-<8 hex>` under TLS), so two J-Wicket daemons reached through tunnels on one workstation do not overwrite each other's cookie; a restart signs everyone out anyway. Idle and absolute timeouts. Idle time counts from the last foreground request: a GET carrying `X-JWicket-Background: 1`, which the browser puts on its own polls, does not reset it. That header can only shorten a session: it never moves a deadline later, an expired session is refused whatever it says, and it affects only the sender's own session. At most `max_sessions` (4) sessions, and a sign-in over that cap is refused with 503 (nobody else is evicted); the 503 says how many sessions are open and when one must end, but names no user and no source (owner decision OD-13's default, which the owner may veto). Two sessions per Junos user by default (`max_sessions_per_user`), so a third sign-in by the same user, compared case-insensitively, closes that user's oldest session (audited as `session_replaced`). A fresh token on every sign-in; a sign-in ends the browser's existing session only after Junos accepts it, so a failed sign-in leaves that session alive. Sign-out, timeout, replacement and session loss close the operator's device session. When a session ends, a tombstone under the token's digest keeps only the reason and the time, so that cookie's next request gets a 401 saying why (`replaced`, `idle`, `absolute`, `signed-out`, `session-lost`, or `unknown` when nothing is kept). Tombstones are bounded (at most `max(64, 4 * max_sessions)`, none older than the absolute limit), hold no user name, source, token, CSRF token or device data, and never authenticate anything. | [`auth/sessions.py`](src/jwicket/auth/sessions.py), [`web/http.py`](src/jwicket/web/http.py), [`api.py`](src/jwicket/api.py) | `SessionStoreTests`, `BackgroundTouchTests`, `TombstoneTests`, `SessionLimitTests` ([`test_auth.py`](tests/test_auth.py)); `test_cookie_names`, `SignInRequiredTests` ([`test_api_units.py`](tests/test_api_units.py)); `test_login_sets_a_strict_session_cookie`, `test_new_login_replaces_the_old_session`, `test_failed_sign_in_keeps_the_existing_session`, `test_signing_out_tells_the_other_tabs`, `test_one_account_cannot_hold_every_slot`, `test_planted_cookie_is_never_adopted`, `BackgroundRequestTests`, `SessionLostTests`, `CapacityTests` ([`test_http_server.py`](tests/test_http_server.py)) | Q-AUTH-01 |
| Cross-site requests. `Origin` must equal the page origin on sign-in and sign-out; sign-out also needs the CSRF token header. | [`api.py`](src/jwicket/api.py), [`web/http.py`](src/jwicket/web/http.py) | `test_login_requires_same_origin`, `test_logout_needs_origin_and_csrf_and_clears_the_cookie` ([`test_http_server.py`](tests/test_http_server.py)); `test_same_origin` ([`test_api_units.py`](tests/test_api_units.py)) | Q-SEC-01 |
| Browser hardening. Strict Content-Security-Policy with no inline script or style and Trusted Types required; no framing; `nosniff`; `no-store`; the same headers on every response, including errors the standard library generates. The UI never parses strings as HTML or code. | [`web/http.py`](src/jwicket/web/http.py), [`web/server.py`](src/jwicket/web/server.py), [`static/`](src/jwicket/static/) | `test_csp_is_strict`; `test_headers_on_every_response_including_errors`, `test_stdlib_generated_errors_also_carry_security_headers`; `test_no_html_or_code_injection_apis`, `IndexHtmlTests` ([`test_static.py`](tests/test_static.py)) | Q-SEC-01 |
| A filter cannot freeze the operator's tab. Every `~` and `/regex/` term, typed or arriving in a crafted link, runs in J-Wicket's own linear-time matcher (a Pike VM), never in the browser's backtracking `RegExp`: one line costs at most (length + 1) times the pattern's NFA states, at most 768 states, over at most the first 2,048 characters. Lookaround, back-references, oversized patterns and syntax the matcher does not read exactly are refused with a plain message. Which characters each class or escape matches is still the browser's own answer. Logs also time-boxes a refilter. This is the operator's own tab only: the pattern never reaches the device or the daemon ([ADR 0013](docs/adr/0013-user-regexes-run-in-a-linear-time-matcher.md)). | [`static/js/regexvm.js`](src/jwicket/static/js/regexvm.js), [`static/js/query.js`](src/jwicket/static/js/query.js), [`static/js/views/logs.js`](src/jwicket/static/js/views/logs.js) | [`regexvm.test.mjs`](tests/js/regexvm.test.mjs) (the 97 patterns a hunt found against the earlier static check, linear time at 512 to 2,048 characters, a differential test against the engine); the "regular expressions: ..." tests in [`query.test.mjs`](tests/js/query.test.mjs). These run under `node --test` in CI's js job, not on Python | Q-SEC-01 (browser only, nothing to prove on a device) |
| Small surface. No upload route; the only POST routes are sign-in and sign-out; static files from an in-memory allowlist; no filesystem path built from a request. | [`api.py`](src/jwicket/api.py), [`resources.py`](src/jwicket/resources.py) | `RoutingTests` ([`test_http_server.py`](tests/test_http_server.py)); `ResourceTests` ([`test_api_units.py`](tests/test_api_units.py)) | Q-SEC-01 |
| Validated input. Scopes, session filters, log sources and file names, report types, expressions and times, buffer times, cursors, line counts and substring terms are checked before any device read, so a bad value costs no RPC and no read slot. Whether a log file is in the configuration is checked after the (cached) sources read. Sign-in user names and secrets are checked before anything reaches Junos. | [`api.py`](src/jwicket/api.py), [`live.py`](src/jwicket/live.py), [`junos/sessions.py`](src/jwicket/junos/sessions.py), [`junos/logs.py`](src/jwicket/junos/logs.py), [`auth/backends.py`](src/jwicket/auth/backends.py) | `test_malformed_scope_is_400`; `test_bad_values_are_refused`, `test_log_file_allowlist_and_validation`, `test_expression_validation`, `test_terms_and_cursor_validation`, `test_bad_parameters_are_400_before_any_device_read`, `test_a_bad_request_does_not_use_up_the_read_slot` ([`test_live.py`](tests/test_live.py)); `test_bad_input_never_reaches_junos` ([`test_auth.py`](tests/test_auth.py)) | Q-SEC-01 |
| Bounded load on the routing engine. Connection cap (8). The TLS handshake, request line, headers and body must all arrive within `socket_timeout_s` (10 s) or the connection is shut down without an answer; the request line and headers together are capped at 16 KiB (431, or 414 for a request line alone over the cap); body and query caps. A read on an operator's device session waits at most 5 s for that operator's previous read, then gets 429 with `Retry-After: 2` and `reason: busy`. A read floor per endpoint per operator (and per log source), also while the log sources cannot be read, and a read within it gets 429 with `reason: rate`; a failed sources read is cached. A request identical to one the same web session made within the floor (another tab, say) gets that read instead of a 429, at no device cost (not system health, which keeps no read, or export, which always reads afresh); at most one request per web session and endpoint (and log source) waits for an identical read still running, and any other gets 429 at once. A stored read is used for at most 2 s after it began, is never handed to another web session, and is dropped at the session's next request or the reaper's next pass (owner decision OD-07's default, which the owner may veto). The Overview's session gauge (`rows=none`) costs 1 RPC, or none when the gauge was read in the last 5 s. No session list unless the match count is known to be at most 5,000. Sign-in limits that only failed sign-ins use up, and at most `login_concurrent` (2) sign-ins checked at once (see known gap 8). | [`web/server.py`](src/jwicket/web/server.py), [`auth/throttle.py`](src/jwicket/auth/throttle.py), [`api.py`](src/jwicket/api.py), [`live.py`](src/jwicket/live.py) | `ConnectionCapTests`, `IdleConnectionTests`, `SlowClientTests`, `TlsDeadlineTests`, `HeadSizeTests`, `BodyAndHostTests`, `test_login_is_throttled_with_retry_after`, `test_requests_that_never_reach_junos_do_not_lock_anyone_out`, `test_spraying_user_names_hits_the_per_source_cap`, `test_too_many_concurrent_sign_ins_is_429`, `test_reading_again_within_two_seconds_is_429`, `ReuseHttpTests` ([`test_http_server.py`](tests/test_http_server.py)); `ThrottleTests` ([`test_auth.py`](tests/test_auth.py)); `SessionGuardTests`, `LogSourcesFailureTests`, `test_refusal_follows_the_matching_count`, `ReuseTests` ([`test_live.py`](tests/test_live.py)) | Q-LOAD-01, Q-LOAD-02, Q-AUTH-04 |
| The audit trail never holds a password, token, cookie, CSRF token or raw configuration. A failed sign-in is recorded with `user` null and `user_hash`, the first 16 hex characters of an HMAC-SHA256 of the case-folded name under a random key made at each start, because the commonest wrong value in the user-name field is a password; the plain name is recorded only once Junos has accepted the sign-in. Session ends without an event of their own (idle, absolute, shutdown) are recorded as `session_ended` with the user, the session's source and the reason; a sign-in that ends the browser's earlier session records `logout` with `reason: new-sign-in`. | [`logs.py`](src/jwicket/logs.py), [`api.py`](src/jwicket/api.py) | `test_forbidden_fields_are_dropped`, `test_long_values_truncated_and_newlines_removed`, `test_keyed_hash_correlates_within_a_trail_only` ([`test_audit.py`](tests/test_audit.py)); `test_audit_trail_never_holds_credentials`, `test_failed_sign_in_records_a_hash_not_the_user_name`, `test_idle_expiry_is_audited_once_without_secrets`, `test_new_sign_in_in_the_same_browser_is_audited_as_a_logout` ([`test_http_server.py`](tests/test_http_server.py)); `test_on_end_for_idle_absolute_and_shutdown` ([`test_auth.py`](tests/test_auth.py)) | Q-SEC-01 |
| Clients without a session cannot flush the audit trail. Refused cross-origin sign-ins, throttled sign-ins and malformed user names or empty secrets are aggregated per (event, source, reason) in 60 s windows: the first is written at once, repeats as one line with `repeated` when the window ends; beyond 64 aggregates in a window the source is recorded as `various`. Session polls are recorded only when their filters or outcome change. A reply reused from the same session's read just made writes no audit line, because no device read happened (owner decision OD-06's default, which the owner may veto). | [`logs.py`](src/jwicket/logs.py), [`api.py`](src/jwicket/api.py), [`live.py`](src/jwicket/live.py) | `RefusalAggregationTests` ([`test_audit.py`](tests/test_audit.py)); `test_unauthenticated_refusals_cannot_flush_the_audit_trail`, `test_reused_reads_are_not_audited` ([`test_http_server.py`](tests/test_http_server.py)); `test_repeated_polls_are_audited_once` ([`test_live.py`](tests/test_live.py)) | Q-SEC-01 |
| The diagnostic log cannot be forged or used to plant terminal escapes. Every message the daemon's handlers write has control characters (C0, DEL, 0x80 to 0x9f) escaped as `\xNN` and the backslash as `\\`; tracebacks keep their line breaks. The device's own error text, cut to 500 characters, is logged there at INFO and never sent to the browser. | [`logs.py`](src/jwicket/logs.py), [`api.py`](src/jwicket/api.py) | `DiagnosticLogEscapeTests` ([`test_http_server.py`](tests/test_http_server.py)); `test_device_error_text_goes_to_the_diagnostic_log_only` ([`test_api_units.py`](tests/test_api_units.py)) | Q-SEC-01 |
| No runtime internet dependency; no device data in browser storage (`localStorage` holds UI preferences and operator-saved query text only; Spec 004 open question 14). | [`static/`](src/jwicket/static/) | `test_no_external_urls` (HTML, scripts, styles), `test_no_device_data_in_browser_storage` ([`test_static.py`](tests/test_static.py)) | Q-SEC-01 |
| Exports cannot inject spreadsheet formulas. | [`api.py`](src/jwicket/api.py) | `CsvInjectionTests` ([`test_http_server.py`](tests/test_http_server.py)); `test_formula_prefixes_are_neutralised` | Q-SEC-01 |
| The build is what was reviewed. `dist/jwicket.py` is deterministic and carries a payload SHA-256; its importer serves only embedded modules; development modules are not shipped. Before any other import it removes its own directory (and the directory a symbolic link to it points at, `''` and `.`) from `sys.path`, using built-in modules only, so a `json.py` or `hashlib.py` placed beside it cannot run inside the daemon. The self-test fails, and the daemon refuses to start (exit 2), if any loaded module's file is in that directory. | [`tools/bundle.py`](tools/bundle.py) | `BundleIsolationTests` ([`test_bundle.py`](tests/test_bundle.py)); CI `bundle` job: rebuild and compare (`--check`), isolated `--bundle-self-test` ([`ci.yml`](.github/workflows/ci.yml)) | Q-RT-02, Q-RT-03 |

### Installer properties and their tests

The installers ([Spec 006](docs/specs/006-installation.md), code in
[`tools/jwicket_install/`](tools/jwicket_install/) and [`deploy/`](deploy/)) write configuration and
files on a lab device, so they carry their own invariants (INV-01 to INV-12, Spec 006 section 5.1).
Their tests run against fake device sessions and synthetic replies. With `JWICKET_REQUIRE_PYEZ=1`
(CI job `install-autospec`) the fakes are built from the real PyEZ, `paramiko` and `scp` signatures;
without those packages those tests skip. None of it proves what a device does: every device step is
unverified until Q-INST-06, which is proposed, like Q-INST-01 to Q-INST-05 ([governance, section
4.12](docs/governance.md#412-proposed-additions)).

| Property | Code | Tests | Proven on a device by |
| --- | --- | --- | --- |
| Nothing is written before the gate. A dry run sends reads only; the typed host name is compared exactly with the one the device reports and is never printed before the prompt; an empty answer, no terminal or a missing host name never passes (INV-01, INV-05). | [`plan.py`](tools/jwicket_install/plan.py), [`workstation.py`](tools/jwicket_install/workstation.py) | `GateTests` ([`test_install_plan.py`](tests/test_install_plan.py)); `DryRunTests`, `GateTests` ([`test_install_workstation.py`](tests/test_install_workstation.py)) | Q-INST-06 |
| No path sends `commit check`, `<check/>` or `<validate>`: a `commit check` or `<check/>` confirms a pending confirmed commit (**verified**), and that one sent by another user or session confirms someone else's is **inferred** (Q-INST-03); the pending state is re-read on the locked session before every commit and confirm; only the installer's own bootstrap may be pending, matched by user, comment, nonce and exact delta (INV-02, INV-03). | [`workstation.py`](tools/jwicket_install/workstation.py), [`transport.py`](tools/jwicket_install/transport.py), [`plan.py`](tools/jwicket_install/plan.py) | `ForeignPendingTests`, `ConfirmGuardTests` ([`test_install_adversarial.py`](tests/test_install_adversarial.py)); `BootstrapTests` ([`test_install_plan.py`](tests/test_install_plan.py), [`test_install_workstation.py`](tests/test_install_workstation.py)); `test_no_commit_check_or_validate_is_ever_sent`; `StaticTests` ([`test_install_cli.py`](tests/test_install_cli.py)) | Q-INST-01, Q-INST-03 |
| Every write is a confirmed commit, compared with the plan before it commits and before it is confirmed, and confirmed only when every health check passes at least 60 s before the deadline; a failure is never confirmed and a revert stage removes what the run added (INV-04). | [`workstation.py`](tools/jwicket_install/workstation.py), [`health.py`](tools/jwicket_install/health.py) | `ApplyOrderTests`, `ConfirmTests`, `RevertTests` ([`test_install_workstation.py`](tests/test_install_workstation.py)); `HealthTests` ([`test_install_adversarial.py`](tests/test_install_adversarial.py)) | Q-INST-03, Q-INST-06 |
| Configured files are never written in place, renamed over or deleted outside the copy right before their checksum commit; shared statements are removed only when Junos's commit history and the workstation record agree this installer added them and nothing else relies on them (INV-06, INV-11). | [`plan.py`](tools/jwicket_install/plan.py) | `ConfiguredPathTests`, `OwnershipTests`, `InverseTests` ([`test_install_plan.py`](tests/test_install_plan.py)); `UpgradeTests`, `UninstallTests` ([`test_install_workstation.py`](tests/test_install_workstation.py)) | Q-INST-06 |
| A bundle or op script is used for `--apply` only with one provenance source independent of the release page; downloads are by tag, capped at 16 MB, `https` only, with at most 3 redirects to listed hosts (INV-07). | [`provenance.py`](tools/jwicket_install/provenance.py) | `FetchTests`, `SchemeTests`, `ReleaseTests`, `SourceTests` ([`test_install_provenance.py`](tests/test_install_provenance.py)) | Q-INST-06 |
| No password option: SSH agent, key or a `getpass` prompt. No credential in argv, logs, receipts, the journal or the plan JSON; no device secret read, and a planted secret never survives parsing (INV-08). With `--access tls` the private key is made in memory, sent by SCP with mode 0600, never written to the workstation's disk, logged, printed or read back; only the certificate's SHA-256 fingerprint is printed and recorded. | [`cli.py`](tools/jwicket_install/cli.py), [`state.py`](tools/jwicket_install/state.py), [`transport.py`](tools/jwicket_install/transport.py), [`workstation.py`](tools/jwicket_install/workstation.py) | `CredentialTests` ([`test_install_cli.py`](tests/test_install_cli.py)); `SecretTests` ([`test_install_state.py`](tests/test_install_state.py)); `TlsAccessTests` ([`test_install_workstation.py`](tests/test_install_workstation.py)); `PinnedHttpsTests` ([`test_install_adversarial.py`](tests/test_install_adversarial.py)) | Q-SEC-01, Q-INST-06 |
| Every SSH connection checks the host key against one verified entry; an unknown key stops the run; two ports with different keys refuse before any write (INV-09). | [`hostkeys.py`](tools/jwicket_install/hostkeys.py), [`transport.py`](tools/jwicket_install/transport.py) | [`test_install_hostkeys.py`](tests/test_install_hostkeys.py) | Q-INST-05, Q-INST-06 |
| One listener, never off loopback without TLS (INV-10): with `--access tls` (the default) the rendered settings bind the one address the operator names, with TLS and a Host allowlist of that address and port, in `mgmt_junos` when `system management-instance` is set, and a wildcard, loopback, multicast, link-local, reserved or IPv6 address is refused (R-BIND); the installer does not check that the address is the management address (it defaults to `--host`, and the posture warning says so); with `--access tunnel` they bind `127.0.0.1`, and the tunnel binds the workstation end to `127.0.0.1`. The extension-service `routing-instance` statement is never rendered. Health check C8 trusts only a certificate this installer made and recorded for this device (this run's, or the kept pair the workstation record names; its SHA-256 pinned, no CA store), and no check opens an SSH forwarding channel. Device text never becomes a template, path, command or configuration line; hostile input is refused before rendering (INV-12). | [`plan.py`](tools/jwicket_install/plan.py), [`render.py`](tools/jwicket_install/render.py), [`transport.py`](tools/jwicket_install/transport.py) | `SettingsTests`, `AccessTests`, `ValidationTests`, `RefusalTests` ([`test_install_plan.py`](tests/test_install_plan.py)); `TunnelTests`, `TlsUnitTests`, `JsonTokenTests` ([`test_install_render.py`](tests/test_install_render.py)); `PinnedHttpsTests` ([`test_install_adversarial.py`](tests/test_install_adversarial.py)); [`test_ansible_contract.py`](tests/test_ansible_contract.py) | Q-SEC-01, Q-TLS-01 |
| No `shell=True`, `eval`, `exec` or `os.system`; no PyEZ helper that runs the shell; the one shell use is the fixed veriexec read; installer code never in the daemon or the bundle. | [`tools/jwicket_install/`](tools/jwicket_install/) | `StaticTests`, including `test_installer_code_is_not_in_the_daemon` ([`test_install_cli.py`](tests/test_install_cli.py)); ruff `S` | Q-SEC-01 |
| No installer creates, changes or removes the state directory: root makes it once (a super-user-class account cannot, verified on the lab SRX4100). It is trusted only if the daemon's rule accepts it (a directory, not a link, owned by the daemon's account, mode 0700); otherwise R-STATEDIR refuses before any write and prints root's step, and it is listed again after the gate. No installer logs in as root or asks for the root password. | [`plan.py`](tools/jwicket_install/plan.py), [`workstation.py`](tools/jwicket_install/workstation.py), [`op_template.py`](tools/jwicket_install/op_template.py) | `StateDirectoryTests` ([`test_install_plan.py`](tests/test_install_plan.py)); `StateDirTests` ([`test_install_workstation.py`](tests/test_install_workstation.py)); `DirectoryTests` ([`test_install_op.py`](tests/test_install_op.py)) | Q-INST-01 |
| The container image runs as a non-root user from a base pinned by digest, with dependencies installed by hash; it refuses `--apply` without a `/state` mount. | [`deploy/container/`](deploy/container/) | [`test_container_contract.py`](tests/test_container_contract.py) | CI image build |
| Releases come only from a commit on `main` with three equal versions and a `vX.Y.Z.devN` tag; every action is pinned by commit SHA; only the `publish` job may write releases (`contents: write`), and a release that fails `gh release verify` is deleted. That only the owner can push such a tag, and that `main` needs review, are repository settings outside the tree (proposed, [ADR 0012](docs/adr/0012-installer-design.md)). | [`release.yml`](.github/workflows/release.yml), [`tools/release_check.py`](tools/release_check.py) | `ReleaseWorkflowTests`, `CiWorkflowTests` ([`test_workflows.py`](tests/test_workflows.py)); [`test_release_check.py`](tests/test_release_check.py); CI `actionlint` | The first pre-release (D14) |
| Daemon changes for the installers (D2, D3): result files only into a trusted `/var/db/jwicket` (the running uid's, not group- or other-writable, not a link), opened with `O_NOFOLLOW`, mode 0600, never into a FIFO; a missing settings file still refuses the start. | [`tools/bundle.py`](tools/bundle.py), [`app.py`](src/jwicket/app.py), [`api.py`](src/jwicket/api.py) | `ResultFileTests`, `UntrustedDirectoryTests`, `FailClosedTests` ([`test_result_files.py`](tests/test_result_files.py)); [`test_api_build.py`](tests/test_api_build.py); `BundleFeatureTests` ([`test_bundle.py`](tests/test_bundle.py)) | Q-SEC-01, Q-INST-06 |

## Known gaps

These are known and open. A report that adds an exploit path or a device result is welcome; a
report that only restates one is not needed.

1. **TLS on a device is lightly tested.** On one lab SRX4100 the on-box `ssl` module served TLS
   1.2 and 1.3 with a self-signed certificate made on the box and refused TLS 1.0 and 1.1; the
   cookie was `__Host-` prefixed and `Secure`, HSTS was sent, and a key at mode 0644 refused the
   start ([evidence](docs/evidence/2026-11-24-srx4100-lab/README.md)). How a trusted certificate
   gets onto a device is undecided, and compression and handshake time were not checked (Q-TLS-01,
   met except a provisioning path). `Secure` cookies and HSTS apply only under TLS. Without TLS the only access path is
   a loopback bind reached through an SSH tunnel, and on Junos 25.2 the SSH service refused to
   forward (Q-NET-03). So the installers default to `--access tls` (the owner's decision of
   2026-11-25, [ADR 0011](docs/adr/0011-owner-decisions-lab-gated-install.md)): a new HTTPS listener
   on the management address, with a self-signed certificate the operator checks by its SHA-256
   fingerprint. That opens J-Wicket's sign-in page to anything that reaches that address; the
   installer's certificate and its upload have not run on a device (Q-INST-06).
2. **Per-operator NETCONF sign-in is only partly proven.** On the lab SRX4100 accounts of the
   `read-only`, `operator` and `super-user` classes signed in over NETCONF to loopback, the device
   attributed every RPC to the signed-in user, sign-out closed the device session, and Junos refused
   a wrong password. Still open: whether the on-box PyEZ refuses a wrong password even when the
   daemon account holds an SSH key that user accepts (Q-AUTH-01); whether RADIUS and TACACS+ users
   get their mapped class (Q-AUTH-02); what other least-privilege classes see (`read-only` and
   `operator` were denied the configuration) and whether Junos omits or refuses hidden configuration
   (Q-AUTH-03);
   and how Junos lockout interacts with J-Wicket's sign-in limits (Q-AUTH-04). The fallback options
   are in [docs/architecture.md](docs/architecture.md#13-if-per-operator-sign-in-fails-q-auth-01).
3. **No penetration test.** No external test (Q-SEC-02, required before live writes at G4) and no
   internal review against the J-Web advisory classes yet (Q-SEC-01, required at G1).
4. **Replies recorded on one platform and one release only.** J-Wicket's reads worked on one lab
   SRX4100, and nine of its replies were recorded there as fixtures, which the parsers' tests read
   (three mismatches with the synthetic fixtures were found and fixed). Every other platform and
   release is unrecorded, the other tests parse synthetic replies, and the error texts used to tell
   `denied` from `failed` are recorded nowhere: a configuration denial was seen once on the device
   and shown as denied (Q-AUTH-03), not stored (Q-REL-01). The device's error text reaches the
   diagnostic log (INFO), so lab runs can record it.
5. **The password passes through process memory.** J-Wicket keeps no copy, but PyEZ's `Device`
   object holds it for the life of the operator's device session, and Python cannot guarantee it is
   wiped. Multi-factor prompts are not supported.
6. **The `lab-token` backend shares one identity.** Every read runs as the daemon account. It is
   allowed only on a loopback bind and says so on every screen. The spike's token crossed the
   internet in clear text and is treated as burned.
7. **Unsigned code on the routing engine.** `set system scripts language python3` is a change to the
   device's security posture. There is no signed package. The lab procedure checks the bundle's
   SHA-256 by hand. The installers check it on the device and pin it with `checksum sha-256` on each
   J-Wicket JET stanza; that statement is in the SRX schema at 23.2R1, but whether Junos enforces it
   at start and respawn is unknown (Q-INST-02), so nothing may rely on the pin yet. On the lab
   SRX4100 Junos put `/var/db/scripts/jet` first on a JET app's `sys.path` (Q-RT-03), so a `.py`
   file planted there is importable; files beside the bundle still cannot replace modules inside it
   (the `sys.path` scrub above), and anyone who can write `/var/db/scripts/jet/` can also replace
   the bundle.
8. **Code-level gaps** found while documenting, listed in
   [docs/architecture.md](docs/architecture.md#15-known-gaps-in-the-current-code): authentication is
   checked per handler, not centrally; there is no Host allowlist unless one is set, which leaves
   the unauthenticated routes open to DNS rebinding through the tunnel; a user confined to a logical
   system may see their scope labelled "Root system"; a configuration part hidden by a deny rule
   cannot be told from one that is not configured; other services on the same host can receive the
   session cookie, because cookies are not isolated by port (RFC 6265, section 8.5). The sign-in
   limits still allow two deliberate lockouts: anyone who fails a named account's sign-in 5 times a
   minute from the same address blocks that account from that address, as Junos retry options can
   (Q-AUTH-04); and behind the SSH tunnel every client is `127.0.0.1`, so 20 failed sign-ins a
   minute under any user names delay every tunnel user's sign-in for up to a minute. Each of those
   failures reached Junos, which logs it and applies its own retry options.
9. **The audit trail is local, and by default not a file of its own.** With `[log] audit_file`
   unset (the default) audit records go to the diagnostic log, which with `[log] file` unset (also
   the default) goes only to standard error; where a daemonized JET app's standard error goes is
   unknown (Q-RT-02). With `audit_file` set, the trail is a rotated file of `max_bytes` times
   (`backups` + 1), about 4 MB at the defaults. It is not tamper-evident and not forwarded off the
   device. How long 4 MB lasts depends on use and has not been measured. An estimate from the
   aggregation limits (at most 68 aggregates, two lines each, per minute, at about 120 to 170 bytes a
   line): refusals of clients without a session add at most about 20 KB a minute, so a flood from
   many addresses needs about three hours to push out a 4 MB trail, and one address two to three
   days.
   Failed sign-ins that reached Junos are still written one per attempt, bounded by the sign-in
   limits and by how fast Junos refuses a password (unmeasured).
10. **`GET /api/session` is unauthenticated** and returns the J-Wicket version and sign-in backend,
    and, from a bundle, `build`: the first 16 hex characters of its payload digest, so an installer
    can tell which build is listening (Spec 006 change D3). The digest names public code. To a
    client presenting the cookie of a session that ended, it (and every 401) also says why and when
    that session ended; nothing else about it. With the installers' default `--access tls` (the
    owner's decision of 2026-11-25, ADR 0011) it is reachable by anything that reaches the
    management address, not only through a tunnel, and check C8 reads it there.
11. **The installers are new surface, and the gate is an attestation.** Typing the host name proves
    intent, not that the box is a lab device: the model check and the production signs cannot detect
    a production cloud vSRX. With `--lab-hardware` a physical SRX passes the model check once the
    operator types `lab only` after the production signs; that statement is recorded and proves
    nothing either. Neither answer proves a person typed it: `--gate-from-stdin` is accepted with
    `--method ansible`, which is a label the caller sets, not a check, so any script (or `docker run
    -i` of the M3 image) can pipe both the host name and `lab only`. Only the Ansible play's own
    `pause` asks a person at a terminal. For its window (10 minutes by default, up to 30 with
    `--bootstrap-minutes`) the NETCONF or op-script bootstrap is active before the gate, and another
    administrator's commit in that window would confirm it (inferred from Juniper's `commit`
    reference, Q-INST-03). The daemon
    runs as the installing super-user-class account, so a compromise of J-Wicket is a compromise of
    the device (a G1 least-privilege gap, governance D16). The R-PENDING exception for the
    installer's own bootstrap, the op script's trust chain, the parsing of device replies and the
    result files (D2) are for Q-SEC-01. None of it has run on a device.

## Threat summary

J-Wicket is a hand-written web server on the routing engine, the position that made J-Web a
liability. J-Web's 2023-2025 advisories (Juniper SIRT CVE records) fall into the classes below; each
row says what J-Wicket does about it. Details and tests per row are in
[docs/architecture.md](docs/architecture.md#14-threat-model).

| J-Web class (advisories) | J-Wicket's control |
| --- | --- |
| Unauthenticated file upload or read (CVE-2023-28962, -28963, -36846, -36847, -36851) | No upload route; two small JSON POST routes; static files from an in-memory allowlist |
| Environment manipulation leading to code execution (CVE-2023-36844, -36845) | No CGI, no PHP, no subprocess; no arguments under Junos; settings from one trusted file; only embedded modules can be imported, and the bundle's own directory is removed from `sys.path` before any import |
| Cross-site scripting (CVE-2024-21620) | Strict CSP with Trusted Types; DOM built without HTML parsing; a test bans HTML and code injection APIs |
| Missing authentication; configuration in temporary files (CVE-2023-36846, -36847, -36851, CVE-2024-21619) | A session for every data route; only modelled fields leave the adapters; no device data on disk; `no-store` |
| XPath or command injection, session reuse after logout (CVE-2024-39565) | RPC allowlist; RPC names are constants or come from a fixed list; configuration filters are constants; validated parameters; one device session per operator, closed on sign-out |
| Cross-site request forgery (no 2023-2025 J-Web CVE found) | `SameSite=Strict`; `Origin` checked on both POST routes; CSRF token on sign-out; every GET read-only |
| Listener on more interfaces than intended (CVE-2025-6549) | One bind address, loopback by default, TLS required off loopback, optional Host allowlist |
| Pre-authentication memory corruption (CVE-2024-21591) | Pure Python with bounded inputs (a whole-request read deadline, a 16 KiB head cap); CPython, `ssl` and OpenSSL remain underneath |
| Privilege-model error in Junos (CVE-2023-44182) | Inherited from Junos; keep Junos current |

Delegating sign-in and authorization to Junos is designed to remove the largest class of J-Web's
problems, a web tier doing its own security work. Whether it works on a device is Q-AUTH-01 to
Q-AUTH-03, and J-Wicket's own pre-authentication surface (the page, its static assets, `/healthz`,
the session status and sign-in) still needs Q-SEC-01 and Q-SEC-02. It does not make J-Wicket immune
to Junos's own bugs, and it does not replace the review and the penetration test.
