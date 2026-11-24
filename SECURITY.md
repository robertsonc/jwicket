# Security policy

J-Wicket is at the **foundation stage**. It is not installable on a production SRX, no version is
supported, and nothing in this repository has run on a customer platform. If you find a
vulnerability, report it **privately to the project owner**. Do not open a public issue.

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
  - the commit, or the bundle's `payload_sha256` from `python3 -I dist/jwicket.py --bundle-self-test`;
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
| `0.1.0.dev0` (the default branch) | **No.** Foundation stage: development and lab qualification only |

No release has been made. Fixes land on the default branch. Support and signed-package positions
are decided at gates G4 and G5 ([governance.md](docs/governance.md)). Until then, the only
documented way to run J-Wicket on a device is the lab procedure in
[docs/deploy-lab.md](docs/deploy-lab.md): a disposable vSRX, a loopback bind, and an SSH tunnel.

## Security properties and their tests

Every test below runs in CI on Python 3.9, 3.11 and 3.13 (`make test` locally), **against synthetic
fixtures**. A passing test shows what the code does; it proves nothing about a device. The device
tests that will are named in the last column and defined in [governance.md](docs/governance.md).

| Property | Code | Tests | Proven on a device by |
| --- | --- | --- | --- |
| Junos decides identity and rights. Sign-in hands the user name and password to Junos in a NETCONF session to the device's own loopback; J-Wicket stores no password and has no roles. | [`auth/backends.py`](src/jwicket/auth/backends.py), [`junos/session.py`](src/jwicket/junos/session.py) | `NetconfBackendTests` ([`test_auth.py`](tests/test_auth.py)); `test_open_passes_credentials_to_pyez_and_classifies_failures` ([`test_session.py`](tests/test_session.py)) | Q-AUTH-01, Q-AUTH-02, Q-AUTH-03 |
| Read-only. Only allowlisted read RPCs can be sent; no RPC name or configuration filter is built from request input. | [`junos/session.py`](src/jwicket/junos/session.py) | `test_allowlist_is_read_only`, `test_disallowed_rpc_never_reaches_the_device`, `test_disallowed_rpc_refused_before_pyez_is_touched` ([`test_session.py`](tests/test_session.py)) | Q-REL-01 |
| Narrow reads, no secrets out. Only the configuration subtrees a feature needs are read; only modelled fields are returned; outbound-SSH `secret` and `device-id` never are. | [`junos/session.py`](src/jwicket/junos/session.py), [`junos/inventory.py`](src/jwicket/junos/inventory.py), [`junos/facts.py`](src/jwicket/junos/facts.py) | `test_inventory_filter_is_narrow`; `test_no_secret_in_any_response`; `test_no_secret_or_device_id_in_serialised_inventory`; `test_secret_never_returned_even_when_shaped_like_a_target` | Q-REL-01 |
| Denied reads show as denied, never as empty or as sample data. | [`api.py`](src/jwicket/api.py), [`junos/errors.py`](src/jwicket/junos/errors.py) | `test_auditor_is_denied_the_configuration`; `test_denied_log_read_is_an_explicit_state`; `test_missing_security_section_is_not_presented_as_empty`; `ClassifyTests` ([`test_errors.py`](tests/test_errors.py)) | Q-AUTH-03 |
| The listener fails closed. Default bind `127.0.0.1`; any other bind needs TLS (no plaintext switch); the NETCONF host must be loopback and its port below 1024; `lab-token` only on loopback; an unknown or out-of-range setting refuses the start. | [`settings.py`](src/jwicket/settings.py) | `TransportRuleTests`, `AuthRuleTests`, `StructureTests`, `RangeTests` ([`test_settings.py`](tests/test_settings.py)) | Q-RT-02, Q-TLS-01 |
| Trusted files only. Settings, token and TLS files must be regular files owned by the daemon account or root, not writable by others; secrets mode 0600; opened, then checked. | [`settings.py`](src/jwicket/settings.py) | `FileTrustTests` ([`test_settings.py`](tests/test_settings.py)) | Q-RT-02 |
| Web sessions. A random token in the cookie; the server keeps only its SHA-256. `HttpOnly`, `SameSite=Strict`, plus `Secure` and the `__Host-` name under TLS. Idle and absolute timeouts; a cap with no eviction; a fresh token on every sign-in. Sign-out, timeout and session loss close the operator's device session. | [`auth/sessions.py`](src/jwicket/auth/sessions.py), [`web/http.py`](src/jwicket/web/http.py), [`api.py`](src/jwicket/api.py) | `SessionStoreTests` ([`test_auth.py`](tests/test_auth.py)); `test_login_sets_a_strict_session_cookie`, `test_new_login_replaces_the_old_session`, `test_planted_cookie_is_never_adopted`, `SessionLostTests` ([`test_http_server.py`](tests/test_http_server.py)) | Q-AUTH-01 |
| Cross-site requests. `Origin` must equal the page origin on sign-in and sign-out; sign-out also needs the CSRF token header. | [`api.py`](src/jwicket/api.py), [`web/http.py`](src/jwicket/web/http.py) | `test_login_requires_same_origin`, `test_logout_needs_origin_and_csrf_and_clears_the_cookie` ([`test_http_server.py`](tests/test_http_server.py)); `test_same_origin` ([`test_api_units.py`](tests/test_api_units.py)) | Q-SEC-01 |
| Browser hardening. Strict Content-Security-Policy with no inline script or style and Trusted Types required; no framing; `nosniff`; `no-store`; the same headers on every response, including errors the standard library generates. The UI never parses strings as HTML or code. | [`web/http.py`](src/jwicket/web/http.py), [`web/server.py`](src/jwicket/web/server.py), [`static/`](src/jwicket/static/) | `test_csp_is_strict`; `test_headers_on_every_response_including_errors`, `test_stdlib_generated_errors_also_carry_security_headers`; `test_no_html_or_code_injection_apis`, `IndexHtmlTests` ([`test_static.py`](tests/test_static.py)) | Q-SEC-01 |
| Small surface. No upload route; the only POST routes are sign-in and sign-out; static files from an in-memory allowlist; no filesystem path built from a request. | [`api.py`](src/jwicket/api.py), [`resources.py`](src/jwicket/resources.py) | `RoutingTests` ([`test_http_server.py`](tests/test_http_server.py)); `ResourceTests` ([`test_api_units.py`](tests/test_api_units.py)) | Q-SEC-01 |
| Validated input. Scopes, session filters, log file names, report expressions, cursors and times are checked before anything reaches Junos. | [`api.py`](src/jwicket/api.py), [`junos/sessions.py`](src/jwicket/junos/sessions.py), [`junos/logs.py`](src/jwicket/junos/logs.py) | `test_malformed_scope_is_400`; `test_bad_values_are_refused`, `test_log_file_allowlist_and_validation`, `test_expression_validation`, `test_terms_and_cursor_validation` ([`test_live.py`](tests/test_live.py)); `test_bad_input_never_reaches_junos` | Q-SEC-01 |
| Bounded load on the routing engine. Connection cap, socket timeouts, body and query caps, sign-in throttle, a read floor per endpoint per operator, and no session list when more than 5,000 sessions match. | [`web/server.py`](src/jwicket/web/server.py), [`auth/throttle.py`](src/jwicket/auth/throttle.py), [`api.py`](src/jwicket/api.py), [`live.py`](src/jwicket/live.py) | `ConnectionCapTests`, `IdleConnectionTests`, `BodyAndHostTests`, `test_login_is_throttled_with_retry_after`, `test_reading_again_within_two_seconds_is_429`; `ThrottleTests`; `test_refusal_follows_the_matching_count` | Q-LOAD-01, Q-LOAD-02, Q-AUTH-04 |
| The audit trail never holds a password, token, cookie, CSRF token or raw configuration. | [`logs.py`](src/jwicket/logs.py) | `test_forbidden_fields_are_dropped`, `test_long_values_truncated_and_newlines_removed` ([`test_audit.py`](tests/test_audit.py)); `test_audit_trail_never_holds_credentials` | Q-SEC-01 |
| No runtime internet dependency; no device data in browser storage (`localStorage` holds UI preferences and operator-saved query text only; Spec 004 open question 14). | [`static/`](src/jwicket/static/) | `test_no_external_urls` (HTML, scripts, styles), `test_no_device_data_in_browser_storage` ([`test_static.py`](tests/test_static.py)) | Q-SEC-01 |
| Exports cannot inject spreadsheet formulas. | [`api.py`](src/jwicket/api.py) | `CsvInjectionTests` ([`test_http_server.py`](tests/test_http_server.py)); `test_formula_prefixes_are_neutralised` | Q-SEC-01 |
| The build is what was reviewed. `dist/jwicket.py` is deterministic and carries a payload SHA-256; its importer serves only embedded modules; development modules are not shipped. | [`tools/bundle.py`](tools/bundle.py) | CI `bundle` job: rebuild and compare (`--check`), isolated `--bundle-self-test` ([`ci.yml`](.github/workflows/ci.yml)) | Q-RT-02, Q-RT-03 |

## Known gaps

These are known and open. A report that adds an exploit path or a device result is welcome; a
report that only restates one is not needed.

1. **No TLS on a device yet.** The on-box `ssl` module has never been exercised, and how a
   certificate gets onto the device is undecided (Q-TLS-01). Until then the only access path is a
   loopback bind reached through an SSH tunnel, with plain HTTP between the two loopback ends.
   `Secure` cookies and HSTS apply only under TLS.
2. **Per-operator NETCONF sign-in is unproven.** Whether on-box Python can open a NETCONF-over-SSH
   session to loopback as another user (Q-AUTH-01), whether RADIUS and TACACS+ users get their
   mapped class (Q-AUTH-02), what least-privilege classes see and whether Junos omits or refuses
   hidden configuration (Q-AUTH-03), and how Junos lockout interacts with J-Wicket's throttle
   (Q-AUTH-04) are all open. The fallback options are in
   [docs/architecture.md](docs/architecture.md#13-if-per-operator-sign-in-fails-q-auth-01).
3. **No penetration test.** No external test (Q-SEC-02, required before live writes at G4) and no
   internal review against the J-Web advisory classes yet (Q-SEC-01, required at G1).
4. **Nothing has run on a device.** Every reply J-Wicket parses is synthetic, and the error texts it
   uses to tell `denied` from `failed` are unverified (Q-REL-01).
5. **The password passes through process memory.** J-Wicket keeps no copy, but PyEZ's `Device`
   object holds it for the life of the operator's device session, and Python cannot guarantee it is
   wiped. Multi-factor prompts are not supported.
6. **The `lab-token` backend shares one identity.** Every read runs as the daemon account. It is
   allowed only on a loopback bind and says so on every screen. The spike's token crossed the
   internet in clear text and is treated as burned.
7. **Unsigned code on the routing engine.** `set system scripts language python3` is a change to the
   device's security posture. There is no signed package. The bundle's SHA-256 is checked by hand;
   the Junos `checksum` option for JET files is not used yet.
8. **Code-level gaps** found while documenting, listed in
   [docs/architecture.md](docs/architecture.md#15-known-gaps-in-the-current-code): the session-list
   guard fails open when the summary read fails; cluster session counts may double; behind the SSH
   tunnel every operator shares one sign-in budget; authentication is checked per handler, not
   centrally; there is no Host allowlist unless one is set, which leaves the unauthenticated routes
   open to DNS rebinding through the tunnel; a user confined to a logical system may see their scope
   labelled "Root system"; a configuration part hidden by a deny rule cannot be told from one that
   is not configured.
9. **The audit trail is local.** About 4 MB of rotated files by default, not tamper-evident, not
   forwarded off the device.
10. **`GET /api/session` is unauthenticated** and returns the J-Wicket version and sign-in backend.

## Threat summary

J-Wicket is a hand-written web server on the routing engine, the position that made J-Web a
liability. J-Web's 2023-2025 advisories (Juniper SIRT CVE records) fall into the classes below; each
row says what J-Wicket does about it. Details and tests per row are in
[docs/architecture.md](docs/architecture.md#14-threat-model).

| J-Web class (advisories) | J-Wicket's control |
| --- | --- |
| Unauthenticated file upload or read (CVE-2023-28962, -28963, -36846, -36847, -36851) | No upload route; two small JSON POST routes; static files from an in-memory allowlist |
| Environment manipulation leading to code execution (CVE-2023-36844, -36845) | No CGI, no PHP, no subprocess; no arguments under Junos; settings from one trusted file; only embedded modules can be imported |
| Cross-site scripting (CVE-2024-21620) | Strict CSP with Trusted Types; DOM built without HTML parsing; a test bans HTML and code injection APIs |
| Missing authentication; configuration in temporary files (CVE-2023-36846, -36847, -36851, CVE-2024-21619) | A session for every data route; only modelled fields leave the adapters; no device data on disk; `no-store` |
| XPath or command injection, session reuse after logout (CVE-2024-39565) | RPC allowlist; no request input in RPC names or filters; validated parameters; one device session per operator, closed on sign-out |
| Cross-site request forgery (no 2023-2025 J-Web CVE found) | `SameSite=Strict`; `Origin` checked on both POST routes; CSRF token on sign-out; every GET read-only |
| Listener on more interfaces than intended (CVE-2025-6549) | One bind address, loopback by default, TLS required off loopback, optional Host allowlist |
| Pre-authentication memory corruption (CVE-2024-21591) | Pure Python with bounded inputs; CPython, `ssl` and OpenSSL remain underneath |
| Privilege-model error in Junos (CVE-2023-44182) | Inherited from Junos; keep Junos current |

Delegating sign-in and authorization to Junos is designed to remove the largest class of J-Web's
problems, a web tier doing its own security work. Whether it works on a device is Q-AUTH-01 to
Q-AUTH-03, and J-Wicket's own pre-authentication surface (the page, its static assets, `/healthz`,
the session status and sign-in) still needs Q-SEC-01 and Q-SEC-02. It does not make J-Wicket immune
to Junos's own bugs, and it does not replace the review and the penetration test.
