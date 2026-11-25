# RPC input leaves from the SRX YANG (junos-es 23.2R1)

`junos-es-23.2R1-rpc-inputs.json` holds the input leaves of every RPC in `INSTALL_RPCS`
(`tools/jwicket_install/transport.py`) that the junos-es 23.2R1 YANG modules define. The test
`tests/test_install_autospec.py` (`YangArgumentTests`, AC-006-29) requires every argument name the
installer sends to be one of these leaves, or a value of an enumerated leaf: Junos sends the chosen
value of an enumeration as an empty element only where that form is documented or inferred
(`transport.EMPTY_ELEMENT_ARGS`): PyEZ 2.8.3 sends `file-list` with `<detail/>` for the leaf `style`
(verified, `jnpr/junos/utils/fs.py`), and for `get-flow-session-information` `<summary/>` for the leaf
`level` is **inferred**. Every other enumerated leaf is sent with its value as text, as Juniper documents
`request-script-refresh-from`: `<type>(commit | op | event | extension-service | snmp)</type>`
([refresh-from-cmd], **verified**). Lab test Q-INST-01 records the real requests with `| display xml rpc`.

This is a schema check, not a device check: it shows that the installer's argument names exist in the
SRX schema at 23.2R1. That they exist and behave the same on 24.4 is **inferred** (the research found
the same RPC list at 22.4R1 and 23.2R1 and no 24.x junos-es RPC module; one 24.x configuration module is
recorded below). Nothing here was captured from a device.

## Not checked here

| RPC | Why |
| --- | --- |
| `get-software-information` | Not in the modules read; J-Wicket's daemon sends it today (fixtures); the installer sends no argument |
| `file-copy` | Not in the SRX YANG (research F06); known from PyEZ 2.8.3 `FS.cp` only; Q-INST-01 |
| `get-configuration`, `lock-configuration`, `unlock-configuration`, `load-configuration`, `commit-configuration` | Junos XML protocol operations, not RPC modules; sent through PyEZ's `Config` and `get_config`, whose keywords `tests/test_install_autospec.py` checks against PyEZ 2.8.3 |

## Sources

Each module's revision statement reads `Junos: 23.2R1.14`. The files were downloaded by the Spec 006
research rounds on 2026-11-24 from the Juniper/yang repository and kept in the workflow's scratch
directory; the URLs of `junos-es-rpc-file` and `junos-es-rpc-request` are recorded in the research
facts (F06, F24); the other four follow the same repository path. The SHA-256 is of the file read.

| Module | URL | SHA-256 of the file read |
| --- | --- | --- |
| `junos-es-rpc-file` | `https://raw.githubusercontent.com/Juniper/yang/master/23.2/23.2R1/junos-es/rpc/junos-es-rpc-file@2023-01-01.yang` | `a75f6bc4301f12f4d9d3290fd98c4a04432a6e3fee889a41f4abd544804aef1f` |
| `junos-es-rpc-request` | `https://raw.githubusercontent.com/Juniper/yang/master/23.2/23.2R1/junos-es/rpc/junos-es-rpc-request@2023-01-01.yang` | `c6466573817042200d6ef03b7b8485216422577b9f97a04f9a1c3e94aee794cd` |
| `junos-es-rpc-extension-service` | `https://raw.githubusercontent.com/Juniper/yang/master/23.2/23.2R1/junos-es/rpc/junos-es-rpc-extension-service@2023-01-01.yang` | `3fd04fac45313ab8ea6c7b8e520b2da9d414c316b3f8ed77e63720812d46a846` |
| `junos-es-rpc-system` | `https://raw.githubusercontent.com/Juniper/yang/master/23.2/23.2R1/junos-es/rpc/junos-es-rpc-system@2023-01-01.yang` | `f40190129f9ddd4269479ee9149c668c3d70ccabbebbd883c9628d22dc722721` |
| `junos-es-rpc-chassis` | `https://raw.githubusercontent.com/Juniper/yang/master/23.2/23.2R1/junos-es/rpc/junos-es-rpc-chassis@2023-01-01.yang` | `81694a0cfeeea486dd5410647db31c3e435b1db274ad022d68d9d5b1891a6f3b` |
| `junos-es-rpc-security` | `https://raw.githubusercontent.com/Juniper/yang/master/23.2/23.2R1/junos-es/rpc/junos-es-rpc-security@2023-01-01.yang` | `a88e8d012fd0b53a8b47760dbede14ac611c904ca4f88e8dcf431fd3580ecd29` |

## How it was extracted

A small brace-matching YANG reader (kept outside the repository) walked each `rpc <name> { input {
... } }` block, following `uses` of the module's own groupings and descending into `choice` and `case`,
and recorded each `leaf` and `leaf-list` name with the `enum` values of its type; a nested `container`
is recorded by name only. To refresh after a schema change: download the modules above, re-run an
equivalent reader, replace the JSON, update the SHA-256 column, and review the diff.

# Configuration paths from the SRX YANG (junos-es 23.2R1)

`junos-es-23.2R1-config-paths.json` lists every container, list, leaf and leaf-list of the junos-es
23.2R1 configuration schema under the subtrees the installer's select-only configuration read
(`transport.CONFIG_FILTER`, spec 8.3) asks for, to three levels below each, plus the top-level `groups`
list (its key `name`) and `apply-groups`. `tests/test_install_autospec.py` (`ConfigFilterSchemaTests`)
requires every element path of `CONFIG_FILTER` to be one of them. Two facts it records: `system scripts`
has no `event` container (event scripts are configured under `event-options event-script file`), and
`system services web-management` has `https` but no `http` container at 23.2R1. The root `system
management-instance` is one empty leaf of `system` (grouping `juniper-system`, `type empty`), read for the
daemon's `[server] routing_instance` (revision R2). That 24.4 has the same paths is **inferred** (Q-INST-01).

| Module | URL | SHA-256 of the file read |
| --- | --- | --- |
| `junos-es-conf-root` | `https://raw.githubusercontent.com/Juniper/yang/master/23.2/23.2R1/junos-es/conf/junos-es-conf-root@2023-01-01.yang` | `1e253f239f3740b3661d4166b82586b2f9289de6906519139cc14ec9a320f6c7` |
| `junos-es-conf-system` | `https://raw.githubusercontent.com/Juniper/yang/master/23.2/23.2R1/junos-es/conf/junos-es-conf-system@2023-01-01.yang` | `c256a4b41f1db1c7975e7a7333557fa198e55ead2105841b28a3b9edafd2cfe2` |
| `junos-es-conf-chassis` | `https://raw.githubusercontent.com/Juniper/yang/master/23.2/23.2R1/junos-es/conf/junos-es-conf-chassis@2023-01-01.yang` | `3ed6ffab22361b0546c835c90277f0d46376eddcc28e637fdec94ad1afd17d28` |
| `junos-es-conf-event-options` | `https://raw.githubusercontent.com/Juniper/yang/master/23.2/23.2R1/junos-es/conf/junos-es-conf-event-options@2023-01-01.yang` | `8ed9b467db7d4b4d030989ad0f13f663be43589cc8e90dcc9d88b1c4d1253216` |

The modules were downloaded on 2026-11-25 (each revision statement reads `Junos: 23.2R1.14`). A
brace-matching YANG reader (kept outside the repository) resolved each module's own `uses` groupings, the
`augment /jc:configuration` statements and `choice`/`case`, and recorded the node paths. To refresh:
download the modules, re-run an equivalent reader, replace the JSON, update the table, review the diff.

A second source, for the order of the levels the installer prints (`plan._COMPARE_SCHEMA_ORDER`) only:
a `junos-es-conf-system` module whose revision statement reads `Junos: 24.4R2.25`, also read by the
research (SHA-256 `346d2780fd938dfbbb0954be3644e03e5861ce3e784a3e82da6fe08e66395ccc`; its download URL
was not recorded). It lists `system` scripts, services, extensions; `scripts` op before language; `scripts
op` file before allow-url-for-python; an extension-service `file` checksum, daemonize,
respawn-on-normal-exit, username, as 23.2R1 does; but `system services` lists netconf before ssh, where
23.2R1 lists ssh first. The JSON above is still 23.2R1's.
