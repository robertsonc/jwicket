"""The installer's calls against the real signatures (Spec 006, AC-006-29).

* ``YangArgumentTests`` (always run): every argument name in ``INSTALL_RPCS`` is an input leaf, or an
  enumeration value of one, in the junos-es 23.2R1 YANG fixture (tests/fixtures/install_rpc/).
* ``AutospecTests``: the PyEZ adapter and the own SSH client against ``unittest.mock.create_autospec``
  of the pinned junos-eznc 2.8.3, paramiko and scp, so a wrong method or keyword fails. They skip when
  those libraries are not installed, and fail instead with ``JWICKET_REQUIRE_PYEZ=1`` (the CI
  ``install-autospec`` job installs requirements-install.txt and sets it).

A passing test shows the calls fit the libraries' signatures; it proves nothing about a device.
"""

from __future__ import annotations

import inspect
import io
import json
import os
import re
import types
import unittest
from typing import Any, Dict, Set
from unittest import mock
from unittest.mock import create_autospec

import fakes_junos as f
from install_support import REPO

from jwicket_install import hostkeys, plan, transport

FIXTURE = REPO / "tests" / "fixtures" / "install_rpc" / "junos-es-23.2R1-rpc-inputs.json"
REQUIRE = os.environ.get("JWICKET_REQUIRE_PYEZ") == "1"


def _libraries() -> Any:
    try:
        import jnpr.junos  # noqa: F401
        import paramiko  # noqa: F401
        import scp  # noqa: F401
    except ImportError as exc:
        if REQUIRE:
            raise AssertionError(f"JWICKET_REQUIRE_PYEZ=1 but the pinned libraries are missing: {exc}") from exc
        return None
    return True


class YangArgumentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_every_yang_sourced_rpc_and_argument_is_in_the_schema(self) -> None:
        rpcs = self.fixture["rpcs"]
        for name, spec in transport.INSTALL_RPCS.items():
            if not spec.source.startswith("yang:"):
                continue
            self.assertIn(name, rpcs, f"{name} is not in the junos-es 23.2R1 fixture")
            self.assertEqual(rpcs[name]["module"], spec.source[len("yang:") :], name)
            leaves: Dict[str, Any] = rpcs[name]["leaves"]
            allowed: Set[str] = set(leaves)
            # An enumeration value is an argument name only where the installer documents the empty-element
            # form (transport.EMPTY_ELEMENT_ARGS); any other enumerated leaf is sent with its value as text.
            for (rpc, leaf), value in transport.EMPTY_ELEMENT_ARGS.items():
                if rpc == name:
                    self.assertIn(value, leaves.get(leaf, []), f"{name}: {value!r} is not a value of {leaf!r}")
                    allowed.add(value)
            for argument in spec.args:
                self.assertIn(argument, allowed, f"{name}: argument {argument!r} is not an input leaf at 23.2R1")

    def test_refresh_from_sends_its_type_as_text(self) -> None:
        """JF-04: Juniper documents <type>extension-service</type> ([refresh-from-cmd]), not an empty element."""
        args = transport.INSTALL_RPCS["request-script-refresh-from"].args
        self.assertIn("type", args)
        self.assertNotIn("extension-service", args)
        self.assertIn("extension-service", self.fixture["rpcs"]["request-script-refresh-from"]["leaves"]["type"])

    def test_fixture_records_its_sources(self) -> None:
        for module, record in self.fixture["modules"].items():
            self.assertEqual(record["junos"], "Junos: 23.2R1.14", module)
            self.assertRegex(record["file_sha256"], r"^[0-9a-f]{64}$")
            self.assertTrue(record["url"].startswith("https://raw.githubusercontent.com/Juniper/yang/"))
        readme = (FIXTURE.parent / "README.md").read_text(encoding="utf-8")
        for record in self.fixture["modules"].values():
            self.assertIn(record["file_sha256"], readme)

    def test_never_sent_arguments_are_absent(self) -> None:
        self.assertNotIn("purge", transport.INSTALL_RPCS["file-delete"].args)
        self.assertNotIn("invoke-debugger", transport.INSTALL_RPCS["extension-service-start"].args)
        for spec in transport.INSTALL_RPCS.values():
            self.assertNotIn("recurse", spec.args)

    def test_no_directory_rpc_can_be_sent(self) -> None:
        """Revision R4: a super-user-class account's 'file make-directory' under /var/db was refused on
        SRX4100 (verified); root makes the directory, and no directory RPC is in the list at all."""
        for name in ("make-directory", "delete-directory"):
            self.assertNotIn(name, transport.INSTALL_RPCS)
            self.assertIn(name, self.fixture["rpcs"])  # the schema has them; the installer never uses them
            with self.assertRaises(ValueError):
                transport.check_rpc(name, {"directory": plan.STATE_DIR}, "write")

    def test_non_yang_rpcs_are_labelled(self) -> None:
        sources = {
            name: spec.source for name, spec in transport.INSTALL_RPCS.items() if not spec.source.startswith("yang:")
        }
        self.assertEqual(sources["file-copy"], "pyez")
        self.assertEqual(sources["get-software-information"], "j-wicket")
        for name in ("get-configuration", "lock-configuration", "load-configuration", "commit-configuration"):
            self.assertEqual(sources[name], "junos-xml-protocol")


CONF_FIXTURE = REPO / "tests" / "fixtures" / "install_rpc" / "junos-es-23.2R1-config-paths.json"


def _filter_paths(xml_text: str) -> Set[str]:
    """Every element path of a select-only filter, below its <configuration> root."""
    import xml.etree.ElementTree as ET

    root = ET.fromstring(xml_text)
    out: Set[str] = set()

    def walk(node: Any, prefix: str) -> None:
        for kid in node:
            path = f"{prefix}/{kid.tag}" if prefix else kid.tag
            out.add(path)
            walk(kid, path)

    walk(root, "")
    return out


class ConfigFilterSchemaTests(unittest.TestCase):
    """JF-02, JF-05: every element of the select-only filter is a node of the junos-es 23.2R1 conf YANG."""

    def setUp(self) -> None:
        self.fixture = json.loads(CONF_FIXTURE.read_text(encoding="utf-8"))
        self.paths = {entry.rsplit(" ", 1)[0] for entry in self.fixture["paths"]}

    def test_every_filter_path_is_in_the_schema(self) -> None:
        for path in sorted(_filter_paths(transport.CONFIG_FILTER)):
            self.assertIn(path, self.paths, f"CONFIG_FILTER asks for {path}, which junos-es 23.2R1 does not have")

    def test_event_scripts_are_read_where_junos_configures_them(self) -> None:
        self.assertNotIn("system/scripts/event", self.paths)
        self.assertIn("event-options/event-script/file/name", self.paths)
        self.assertIn("event-options/event-script/file/name", _filter_paths(transport.CONFIG_FILTER))
        self.assertNotIn("system/scripts/event", _filter_paths(transport.CONFIG_FILTER))

    def test_web_management_has_no_http_at_23_2(self) -> None:
        self.assertNotIn("system/services/web-management/http", self.paths)
        self.assertIn("system/services/web-management/https/port", self.paths)
        self.assertNotIn("system/services/web-management/http", _filter_paths(transport.CONFIG_FILTER))

    def test_every_walked_subtree_is_in_the_filter(self) -> None:
        from jwicket_install import state

        selected = _filter_paths(transport.CONFIG_FILTER)
        for subtree in state.WALKED:
            self.assertIn("/".join(subtree), selected)
        for _, path in plan.SCRIPT_FILE_PATHS:
            self.assertIn("/".join((*path, "name")), selected)

    def test_fixture_records_its_sources(self) -> None:
        readme = (CONF_FIXTURE.parent / "README.md").read_text(encoding="utf-8")
        for module, record in self.fixture["modules"].items():
            self.assertEqual(record["junos"], "Junos: 23.2R1.14", module)
            self.assertIn(record["file_sha256"], readme)
            self.assertTrue(record["url"].startswith("https://raw.githubusercontent.com/Juniper/yang/"))


@unittest.skipUnless(
    _libraries(), "junos-eznc, paramiko and scp are not installed (JWICKET_REQUIRE_PYEZ=1 fails instead)"
)
class AutospecTests(unittest.TestCase):
    def setUp(self) -> None:
        from jnpr.junos import exception as ez

        self.ez = ez
        self.clock = f.FakeClock(f.FakeDevice())

    # -- PyEZ -----------------------------------------------------------------------------------------

    def test_device_keywords_are_ones_pyez_reads(self) -> None:
        from jnpr.junos import Device

        source = inspect.getsource(Device.__init__)
        read = set(re.findall(r'kvargs\.get\("([a-z_]+)"', source))
        session = transport.PyezNetconf(
            transport.Target("lab1", f.USER, 22),
            transport.Credentials("/k", "fixture-pass"),
            "cfg",
            self.clock,
            device_factory=create_autospec(Device),
            config_factory=lambda d: None,
            errors=self.ez,
        )
        kwargs = session.device_kwargs()
        self.assertTrue(set(kwargs) <= read, set(kwargs) - read)
        self.assertIs(kwargs["hostkey_verify"], True)

    def adapter(self, dev: Any) -> Any:
        from jnpr.junos.utils.config import Config

        cu = create_autospec(Config, instance=True)
        session = transport.PyezNetconf(
            transport.Target("lab1", f.USER),
            transport.Credentials(),
            "cfg",
            self.clock,
            device_factory=lambda **kw: dev,
            config_factory=lambda d: cu,
            errors=self.ez,
        )
        session.open()
        return session, cu

    def test_config_calls_fit_pyez_config(self) -> None:
        from jnpr.junos import Device

        dev = create_autospec(Device, instance=True)
        session, cu = self.adapter(dev)
        dev.open.assert_called_once_with()
        session.lock()
        session.load_set(["set system scripts language python3"])
        session.discard()
        session.load_rollback(1)
        session.commit("jwicket 0.1.0.dev1 sha256:1f1f1f1f1f1f runtime lab-install", plan.Minutes(5))
        session.commit("jwicket 0.1.0.dev1 sha256:1f1f1f1f1f1f runtime confirmed", None)
        session.unlock()
        cu.lock.assert_called_once_with()
        cu.load.assert_called_once_with("set system scripts language python3", format="set")
        self.assertEqual(cu.rollback.call_args_list, [mock.call(0), mock.call(1)])
        cu.commit.assert_any_call(
            comment="jwicket 0.1.0.dev1 sha256:1f1f1f1f1f1f runtime lab-install", timeout=120, confirm=5
        )
        cu.commit.assert_any_call(comment="jwicket 0.1.0.dev1 sha256:1f1f1f1f1f1f runtime confirmed", timeout=120)
        for call in cu.commit.call_args_list:
            self.assertNotIn("check", call.kwargs)

    def test_config_errors_map_to_refusals(self) -> None:
        from jnpr.junos import Device

        dev = create_autospec(Device, instance=True)
        session, cu = self.adapter(dev)
        cu.lock.side_effect = self.ez.LockError(rsp=None)
        with self.assertRaises(transport.DeviceRefused):
            session.lock()
        cu.commit.side_effect = self.ez.RpcTimeoutError(dev, "commit-configuration", 120)
        with self.assertRaises(transport.OutcomeUnknown):
            session.commit("jwicket x", plan.Minutes(5))
        cu.commit.side_effect = self.ez.ConnectClosedError(dev)
        with self.assertRaises(transport.SessionLost):
            session.commit("jwicket x", None)

    def test_get_config_fits_the_rpc_meta(self) -> None:
        from jnpr.junos import Device
        from jnpr.junos.rpcmeta import _RpcMetaExec
        from lxml import etree

        dev = create_autospec(Device, instance=True)
        rpc = create_autospec(_RpcMetaExec, instance=True)
        rpc.get_config.return_value = etree.XML("<configuration><system/></configuration>")
        dev.rpc = rpc
        session, _ = self.adapter(dev)
        text = session.get_configuration(database="committed", inherit=True)
        self.assertIn("<configuration>", str(text))
        kwargs = rpc.get_config.call_args.kwargs
        self.assertEqual(kwargs["options"], {"database": "committed", "inherit": "inherit"})
        self.assertEqual(kwargs["dev_timeout"], 60)
        self.assertEqual(kwargs["filter_xml"].tag, "configuration")

    def test_dynamic_rpcs_send_hyphenated_arguments_and_retry_reads_only(self) -> None:
        from jnpr.junos import Device
        from lxml import etree

        dev = create_autospec(Device, instance=True)
        dev.rpc = mock.MagicMock()
        dev.rpc.file_list.return_value = etree.XML("<directory-list/>")
        dev.rpc.jet_application_status.return_value = etree.XML("<output>Process-id: 1</output>")
        session, _ = self.adapter(dev)
        session.read("file-list", detail=True, path="/var/db")
        dev.rpc.file_list.assert_called_once_with(dev_timeout=60, detail=True, path="/var/db")
        session.read("jet-application-status", **{"application-name": "jwicket.py"})
        dev.rpc.jet_application_status.assert_called_once_with(dev_timeout=60, application_name="jwicket.py")
        dev.rpc.file_show.side_effect = self.ez.RpcTimeoutError(dev, "file-show", 60)
        with self.assertRaises(transport.ReadTimeout):
            session.read("file-show", filename="/var/db/jwicket/jwicket.log")
        self.assertEqual(dev.rpc.file_show.call_count, 4)  # one read and three retries
        dev.rpc.file_delete.side_effect = self.ez.RpcTimeoutError(dev, "file-delete", 60)
        with self.assertRaises(transport.OutcomeUnknown):
            session.write("file-delete", path="/var/db/scripts/jet/jwicket-next.py")
        self.assertEqual(dev.rpc.file_delete.call_count, 1)  # never retried
        dev.rpc.file_list.side_effect = self.ez.RpcError(rsp=None)
        self.assertIsInstance(session.read("file-list", detail=True, path="/x"), transport.state.RpcErrorReply)

    def test_raw_replies_never_reach_the_logs(self) -> None:
        """SC-13, spec 8.10: the real adapter logs RPC names and sizes at DEBUG, never a reply's text."""
        import logging

        from jnpr.junos import Device
        from lxml import etree

        marker = "MARKER-REPLY-TEXT-7f3a"
        records: list = []

        class Capture(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                records.append(self.format(record))

        handler = Capture(level=logging.DEBUG)
        logger = logging.getLogger("jwicket_install")
        old = logger.level
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        self.addCleanup(logger.removeHandler, handler)
        self.addCleanup(logger.setLevel, old)
        dev = create_autospec(Device, instance=True)
        dev.rpc = mock.MagicMock()
        dev.rpc.file_show.return_value = etree.XML(f"<file-content>{marker}</file-content>")
        dev.rpc.jet_application_status.return_value = etree.XML(f"<output>{marker}</output>")
        dev.rpc.get_config.return_value = etree.XML(f"<configuration><version>{marker}</version></configuration>")
        dev.rpc.get_configuration.return_value = etree.XML(f"<configuration-output>{marker}</configuration-output>")
        dev.rpc.file_delete.side_effect = self.ez.RpcError(
            rsp=etree.XML(f"<rpc-error><error-message>{marker}</error-message></rpc-error>")
        )
        session, _ = self.adapter(dev)
        self.assertIn(marker, str(session.read("file-show", filename="/var/db/jwicket/jwicket.log")))
        session.read("jet-application-status", **{"application-name": "jwicket.py"})
        session.get_configuration(database="committed", inherit=False)
        self.assertEqual(session.compare(0), marker)
        with self.assertRaises(transport.DeviceRefused):
            session.write("file-delete", path="/var/db/scripts/jet/jwicket-next.py")
        self.assertTrue(records)  # DEBUG ran
        for line in records:
            self.assertNotIn(marker, line)

    # -- paramiko and scp -----------------------------------------------------------------------------

    def paramiko_module(self) -> Any:
        import paramiko

        return types.SimpleNamespace(
            SSHClient=create_autospec(paramiko.SSHClient),
            Transport=create_autospec(paramiko.Transport),
            RejectPolicy=paramiko.RejectPolicy,
            BadHostKeyException=paramiko.BadHostKeyException,
            AuthenticationException=paramiko.AuthenticationException,
            SSHException=paramiko.SSHException,
            ChannelException=paramiko.ChannelException,
        )

    def test_ssh_client_connect_keywords_fit_paramiko(self) -> None:
        module = self.paramiko_module()
        client = transport.OwnSsh(
            transport.Target("lab1", f.USER, 2222),
            transport.Credentials(),
            f.KEY_A,
            hostkeys.algorithms_for(["ssh-ed25519"]),
        )
        with mock.patch.object(transport, "_paramiko", return_value=module):
            client.open()
        instance = module.SSHClient.return_value
        instance.set_missing_host_key_policy.assert_called_once()
        policy = instance.set_missing_host_key_policy.call_args.args[0]
        self.assertIsInstance(policy, module.RejectPolicy)
        instance.connect.assert_called_once()
        self.assertEqual(instance.connect.call_args.kwargs["port"], 2222)
        self.assertFalse(instance.load_system_host_keys.called)  # pinned to the one verified key

    def test_scp_and_the_veriexec_read_fit_scp_and_paramiko(self) -> None:
        import paramiko
        import scp

        module = self.paramiko_module()
        scp_class = create_autospec(scp.SCPClient)
        scp_instance = scp_class.return_value
        scp_instance.__enter__.return_value = scp_instance
        client = transport.OwnSsh(transport.Target("lab1", f.USER), transport.Credentials(), f.KEY_A, ())
        ssh_client = create_autospec(paramiko.SSHClient, instance=True)
        transport_instance = create_autospec(paramiko.Transport, instance=True)
        transport_instance.is_active.return_value = True
        ssh_client.get_transport.return_value = transport_instance
        client._client = ssh_client
        with mock.patch.object(transport, "_scp_client", return_value=scp_class), mock.patch.object(
            transport, "_paramiko", return_value=module
        ):
            client.put(b"data", plan.STAGING_PATH, 0o644)
            fl, path = scp_instance.putfo.call_args.args
            self.assertEqual((path, scp_instance.putfo.call_args.kwargs), (plan.STAGING_PATH, {"mode": "0644"}))
            self.assertIsInstance(fl, io.BytesIO)
            scp_class.assert_called_with(transport_instance, socket_timeout=30)
            client.get(plan.LOG_PATH, "/tmp/evidence/jwicket.log")
            scp_instance.get.assert_called_once_with(plan.LOG_PATH, "/tmp/evidence/jwicket.log")
            # Revision R3: the own client opens no forwarding channel (refused on SRX4100, verified).
            self.assertFalse(hasattr(client, "channel") or hasattr(client, "open_forward"))
            session = create_autospec(paramiko.Channel, instance=True)
            session.recv.side_effect = [b"security.mac.veriexec.state: loaded active enforce\n", b""]
            transport_instance.open_session.return_value = session
            self.assertIn("loaded active enforce", str(client.veriexec()))
            session.exec_command.assert_called_once_with(plan.SHELL_START)
            session.sendall.assert_called_once_with(f"{plan.SHELL_VERIEXEC}\n{plan.SHELL_EXIT}\n".encode("ascii"))
        self.assertFalse(transport_instance.open_channel.called)

    def test_bare_transport_key_fetch_fits_paramiko(self) -> None:
        import paramiko

        module = self.paramiko_module()
        instance = module.Transport.return_value
        options = mock.NonCallableMagicMock()
        options.key_types = ("ssh-ed25519", "rsa-sha2-512")
        instance.get_security_options.return_value = options
        key = create_autospec(paramiko.PKey, instance=True)
        key.get_name.return_value = "ssh-ed25519"
        key.asbytes.return_value = f.KEY_A[1]
        instance.get_remote_server_key.return_value = key
        with mock.patch.object(transport, "_paramiko", return_value=module), mock.patch.object(
            transport.socket, "create_connection", return_value=mock.MagicMock()
        ) as connect:
            found = transport.fetch_host_key("lab1", 22, ("ssh-ed25519",))
        self.assertEqual(found, f.KEY_A)
        connect.assert_called_once_with(("lab1", 22), timeout=30)
        instance.start_client.assert_called_once_with(timeout=30)
        self.assertEqual(options.key_types, ["ssh-ed25519"])
        instance.close.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
