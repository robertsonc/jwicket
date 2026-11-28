"""The command line, static bans and credential handling (Spec 006, AC-006-21, -22, -30), the access
options of revision R2, --lab-hardware (R5) and ``open`` (R3: it forwards nothing). The device is the
recording fake of tests/fakes_junos.py, injected through ``cli.main(executor_factory=...)``."""

from __future__ import annotations

import argparse
import ast
import contextlib
import io
import json
import logging
import re
import shlex
import tempfile
import unittest
from pathlib import Path
from typing import Any, ClassVar, List, Sequence, Set, Tuple
from unittest import mock

import fakes_junos as f
from install_support import REPO, plan

from jwicket_install import cli, receipt, transport

PACKAGE = REPO / "tools" / "jwicket_install"
INSTALLER_MODULES = (
    "cli",
    "workstation",
    "transport",
    "hostkeys",
    "health",
    "provenance",
    "receipt",
    "tunnel",
    "__main__",
)


class CliBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.device = f.FakeDevice()
        self.harness = f.Harness(self.device, self.root)
        self.data = f.make_bundle()
        self.bundle = self.root / "jwicket.py"
        self.bundle.write_bytes(self.data)
        self.sha = f.bundle_identity(self.data).file_sha256

    def run_cli(self, argv: Sequence[str], *answers: str, **console_kwargs: Any) -> Tuple[int, f.FakeConsole]:
        console = f.FakeConsole(self.device, answers or f.gate_answers(), **console_kwargs)
        with mock.patch.object(receipt, "default_state_dir", return_value=self.harness.store.root):
            code = cli.main(list(argv), executor_factory=self.harness.factory(), console=console)
        return code, console

    def install_args(self, *extra: str) -> List[str]:
        return [
            "install",
            "--host",
            f.ADDRESS,
            "--user",
            f.USER,
            "--bundle",
            str(self.bundle),
            "--expect-sha256",
            self.sha,
            "--expect-source",
            "local-build",
            *extra,
        ]


class GuideTests(CliBase):
    def guided(self, *answers: str, **settings: Any) -> Tuple[int, f.FakeConsole]:
        artifact = (self.data, f.bundle_identity(self.data), f.provenance_ok(), self.bundle)
        with mock.patch.object(cli, "obtain_bundle", return_value=artifact):
            return self.run_cli(["guide"], *answers, **settings)

    def test_existing_account_default_password_and_read_only_preview(self) -> None:
        code, console = self.guided(f.ADDRESS, f.USER, "ready", "", "")
        self.assertEqual(code, plan.EXIT_OK)
        self.assertIn("SRX management IPv4", console.prompts[0])
        self.assertIn("non-root super-user", console.prompts[1])
        self.assertIn("not a personal login key", console.text())
        self.assertIn("Preview only", console.text())
        self.assertIn("clean-up-manual-guided-setup", console.text().split("Preview only")[1])
        self.assertFalse(any(call[0] in f.WRITES for call in self.device.calls))
        self.assertNotIn(("gate",), self.device.calls)

    def test_new_account_is_an_explicit_manual_setup_not_a_remote_mutation(self) -> None:
        code, console = self.guided(f.ADDRESS, "", "ready", "")
        self.assertEqual(code, plan.EXIT_REFUSED)
        self.assertIn("set system login user jwicket class super-user", console.text())
        self.assertIn("Junos super-user has full device permissions", console.text())
        self.assertIn("commit confirmed 5", console.text())
        self.assertIn("chown jwicket /var/db/jwicket", console.text())
        self.assertTrue(all(call[0] == "prompt" for call in self.device.calls))

    def test_rejects_root_bad_address_and_piped_input_before_contact(self) -> None:
        for answers, settings, expected in (
            ((f.ADDRESS, "root"), {}, plan.EXIT_REFUSED),
            (("host.example",), {}, plan.EXIT_INPUT),
            ((f.ADDRESS, f.USER), {"interactive": False}, plan.EXIT_GATE),
        ):
            with self.subTest(answers=answers):
                self.device.calls.clear()
                code, _ = self.guided(*answers, **settings)
                self.assertEqual(code, expected)
                self.assertTrue(all(call[0] == "prompt" for call in self.device.calls))

    def test_apply_still_needs_native_hostname_and_checks_tls_first(self) -> None:
        code, console = self.guided(f.ADDRESS, f.USER, "ready", "a", "apply", "wrong-host")
        self.assertEqual(code, plan.EXIT_GATE)
        self.assertIn(("gate",), self.device.calls)
        self.assertFalse(any(call[0] in f.WRITES for call in self.device.calls))
        self.assertIn("management ingress allows TCP 9443", console.text())

    def test_apply_runs_real_workflow_against_fixture(self) -> None:
        code, console = self.guided(f.ADDRESS, f.USER, "ready", "a", "apply", f.HOST)
        self.assertEqual(code, plan.EXIT_OK, console.text())
        self.assertTrue(any(call[0] in f.WRITES for call in self.device.calls))
        self.assertIn("one denied read", console.text())

    def test_password_is_prompted_once_for_nonroot_and_not_echoed(self) -> None:
        console = f.FakeConsole(self.device, [f.ADDRESS, f.USER, "ready", "", "apply", f.HOST])
        artifact = (self.data, f.bundle_identity(self.data), f.provenance_ok(), self.bundle)
        factory = self.harness.factory()

        def use_fake(target: Any, ui: Any, run: Any, args: Any, creds: Any) -> Any:
            self.assertEqual(target.user, f.USER)
            self.assertEqual(creds.password, "fixture-nonroot-password")
            return factory(target, ui, run)

        with contextlib.ExitStack() as stack:
            terminal = stack.enter_context(mock.patch.object(cli.sys, "stdin"))
            terminal.isatty.return_value = True
            ask = stack.enter_context(
                mock.patch.object(cli.getpass, "getpass", return_value="fixture-nonroot-password")
            )
            execute = stack.enter_context(mock.patch.object(cli, "_real_executor", side_effect=use_fake))
            stack.enter_context(mock.patch.object(cli, "obtain_bundle", return_value=artifact))
            code = cli.main(["guide"], console=console)
        self.assertEqual(code, plan.EXIT_OK, console.text())
        ask.assert_called_once_with(f"SSH password for {f.USER}: ")
        self.assertEqual(execute.call_count, 2)
        self.assertNotIn("fixture-nonroot-password", console.text())

    def test_netconf_off_prints_exact_bootstrap_without_applying(self) -> None:
        self.device = f.FakeDevice(netconf=False)
        self.harness = f.Harness(self.device, self.root)
        code, console = self.guided(f.ADDRESS, f.USER, "ready", "")
        self.assertEqual(code, plan.EXIT_REFUSED, console.text())
        self.assertIn("--bootstrap-nonce", console.text())
        self.assertIn("--password-prompt", console.text())
        self.assertIn("including after a NETCONF bootstrap", console.text())
        self.assertFalse(any(call[0] in f.WRITES for call in self.device.calls))

    def test_blocked_preview_is_not_an_apply_prompt(self) -> None:
        self.device = f.FakeDevice(config=(("system services outbound-ssh client fixture-manager", ""),))
        self.harness = f.Harness(self.device, self.root)
        code, console = self.guided(f.ADDRESS, f.USER, "ready", "a", "apply", f.HOST)
        self.assertEqual(code, plan.EXIT_REFUSED, console.text())
        self.assertIn("R-MANAGED (blocks)", console.text())
        self.assertIn("clean-up-manual-guided-setup", console.text().split("R-MANAGED (blocks)")[1])
        self.assertFalse(any("Type apply" in prompt for prompt in console.prompts))
        self.assertFalse(any(call[0] in f.WRITES for call in self.device.calls))


class SurfaceTests(CliBase):
    """AC-006-30: exit codes of 9.7, one JSON document with --json, DEVICE_STATUS first."""

    def test_device_status_is_the_first_line(self) -> None:
        code, console = self.run_cli(self.install_args())
        self.assertEqual(code, plan.EXIT_OK)
        self.assertEqual(console.out.getvalue().splitlines()[0], plan.DEVICE_STATUS)
        for argv in (
            ["status", "--host", f.ADDRESS, "--user", f.USER],
            ["uninstall", "--host", f.ADDRESS, "--user", f.USER],
            ["bootstrap", "--user", f.USER],
            [
                "render",
                "--method",
                "cli",
                "--user",
                f.USER,
                "--bundle",
                str(self.bundle),
                "--expect-sha256",
                self.sha,
                "--expect-source",
                "local-build",
                "--access",
                "tunnel",
            ],
        ):
            _, console = self.run_cli(argv)
            self.assertEqual(console.out.getvalue().splitlines()[0], plan.DEVICE_STATUS, argv[0])

    def test_json_dry_run_prints_one_plan_document(self) -> None:
        code, console = self.run_cli(self.install_args("--json"))
        self.assertEqual(code, plan.EXIT_OK)
        document = json.loads(console.out.getvalue())
        self.assertEqual(document["schema"], plan.PLAN_SCHEMA)
        self.assertFalse(document["blocked"])
        self.assertIn(plan.DEVICE_STATUS, console.err.getvalue())
        self.assertNotIn(f.HOST, console.out.getvalue())

    def test_the_dry_run_prints_each_warning_once_and_names_kept_statements(self) -> None:
        """OPD-08: DEVICE_STATUS and the account warning once; a kept statement as its set line; the
        listener the runtime commit starts."""
        code, console = self.run_cli(self.install_args())
        self.assertEqual(code, plan.EXIT_OK)
        text = console.text()
        self.assertEqual(text.count(plan.DEVICE_STATUS), 1)
        self.assertEqual(text.count(plan.root_blast_radius(f.USER)), 1)
        self.assertIn("  set system services netconf ssh", text)
        self.assertNotIn("kept: S8", text)
        self.assertIn("listening with TLS on 192.0.2.10:9443", text)
        self.assertIn("Blast radius: posture:", text)

    def test_json_apply_prints_one_result_document(self) -> None:
        code, console = self.run_cli(
            self.install_args("--apply", "--method", "ansible", "--gate-from-stdin", "--json"),
            interactive=False,
            stdin_text=f.HOST + "\n",
        )
        self.assertEqual(code, plan.EXIT_OK, console.err.getvalue())
        document = json.loads(console.out.getvalue())
        self.assertEqual(document["exit"], 0)
        self.assertEqual(document["confirmed_stages"], ["diagnostics", "runtime"])
        self.assertEqual(document["receipt"], "written")
        self.assertEqual(document["plan"]["schema"], 2)

    def test_gate_from_stdin_is_refused_outside_the_play(self) -> None:
        """SEC-07, SC-21: spec 6.3 and 8.2, --gate-from-stdin only with M2's --method ansible (exit 2)."""
        for argv in (
            self.install_args("--apply", "--gate-from-stdin"),
            self.install_args("--apply", "--gate-from-stdin", "--method", "container"),
            ["uninstall", "--host", f.ADDRESS, "--user", f.USER, "--apply", "--gate-from-stdin"],
        ):
            with self.subTest(argv=argv):
                code, console = self.run_cli(argv, interactive=False, stdin_text=f.HOST + "\n")
                self.assertEqual(code, plan.EXIT_INPUT)
                self.assertIn("Ansible play only", console.text())
        self.assertEqual(self.device.calls, [])

    def test_exit_codes(self) -> None:
        self.assertEqual(self.run_cli(self.install_args("--apply"), "wrong")[0], plan.EXIT_GATE)
        self.assertEqual(self.run_cli(self.install_args("--apply"), "x", interactive=False)[0], plan.EXIT_GATE)
        bad_user = ["install", "--host", f.ADDRESS, "--user", "root;x", "--bundle", str(self.bundle)]
        self.assertEqual(self.run_cli(bad_user)[0], plan.EXIT_INPUT)
        self.assertEqual(self.run_cli(self.install_args("--confirm-minutes", "99"))[0], plan.EXIT_INPUT)
        with self.assertRaises(SystemExit) as caught:
            self.run_cli(["install", "--nonsense"])
        self.assertEqual(caught.exception.code, 2)

    def test_no_abbreviation_stands_for_an_option(self) -> None:
        # allow_abbrev=False: '--app' is not '--apply', '--gate' not '--gate-from-stdin' (exit 2, nothing run).
        for argv in (
            self.install_args("--app"),
            self.install_args("--gate", "--apply"),
            ["uninstall", "--host", f.ADDRESS, "--user", f.USER, "--appl"],
            ["status", "--ho", f.ADDRESS, "--user", f.USER],
        ):
            with self.subTest(argv=argv), self.assertRaises(SystemExit) as caught, mock.patch("sys.stderr"):
                self.run_cli(argv)
            self.assertEqual(caught.exception.code, 2)
        self.assertEqual(self.device.calls, [])

    def test_apply_without_provenance_is_exit_7_before_any_contact(self) -> None:
        argv = ["install", "--host", f.ADDRESS, "--user", f.USER, "--bundle", str(self.bundle), "--apply"]
        code, console = self.run_cli(argv)
        self.assertEqual(code, plan.EXIT_INTEGRITY)
        self.assertEqual(self.device.calls, [])
        self.assertIn("R-PROVENANCE", console.text())

    def test_dry_run_without_provenance_shows_the_refusal(self) -> None:
        argv = ["install", "--host", f.ADDRESS, "--user", f.USER, "--bundle", str(self.bundle)]
        code, console = self.run_cli(argv)
        self.assertEqual(code, plan.EXIT_REFUSED)
        self.assertIn("R-PROVENANCE", console.text())
        self.assertEqual(self.device.writes_before("never"), [])

    def test_wrong_expected_hash_is_exit_7(self) -> None:
        argv = self.install_args()
        argv[argv.index(self.sha)] = "0" * 64
        self.assertEqual(self.run_cli(argv)[0], plan.EXIT_INTEGRITY)
        self.assertEqual(self.device.calls, [])

    def test_bootstrap_render_and_offline_cli_units(self) -> None:
        code, console = self.run_cli(["bootstrap", "--user", f.USER, "--json"])
        self.assertEqual(code, 0)
        document = json.loads(console.out.getvalue())
        self.assertEqual((document["kind"], document["keys"]), ("netconf", ["S8"]))
        set_dir = self.root / "sets"
        code, console = self.run_cli(
            [
                "render",
                "--method",
                "cli",
                "--user",
                f.USER,
                "--bundle",
                str(self.bundle),
                "--expect-sha256",
                self.sha,
                "--expect-source",
                "local-build",
                "--listen-address",
                f.ADDRESS,
                "--set-files",
                str(set_dir),
            ]
        )
        self.assertEqual(code, 0, console.text())
        self.assertIn("rendered offline", console.text().lower())
        self.assertTrue((set_dir / "jwicket-diagnostics.set").is_file())
        self.assertEqual(self.device.calls, [])  # offline: no device

    def test_render_with_host_gates_before_printing_units(self) -> None:
        argv = [
            "render",
            "--method",
            "cli",
            "--host",
            f.ADDRESS,
            "--user",
            f.USER,
            "--bundle",
            str(self.bundle),
            "--expect-sha256",
            self.sha,
            "--expect-source",
            "local-build",
        ]
        code, console = self.run_cli(argv, "wrong")
        self.assertEqual(code, plan.EXIT_GATE)
        self.assertNotIn("Unit 1", console.text())
        code, console = self.run_cli(argv)
        self.assertEqual(code, 0)
        self.assertIn(f"Rendered for {f.HOST}", console.text())
        self.assertEqual(self.device.writes_before("never"), [])

    def test_render_upgrade_needs_a_host(self) -> None:
        argv = ["render", "--method", "cli-uninstall", "--user", f.USER]
        self.assertEqual(self.run_cli(argv)[0], plan.EXIT_INPUT)

    def test_status_and_uninstall_commands(self) -> None:
        self.assertEqual(self.run_cli(self.install_args("--apply"))[0], 0)
        code, console = self.run_cli(["status", "--host", f.ADDRESS, "--user", f.USER, "--json"])
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(console.out.getvalue())["healthy"])
        code, _ = self.run_cli(["uninstall", "--host", f.ADDRESS, "--user", f.USER, "--apply", "--no-evidence"])
        self.assertEqual(code, 0)
        self.assertNotIn(plan.DAEMON_PATH, self.device.files)

    def test_version_option(self) -> None:
        with self.assertRaises(SystemExit) as caught, mock.patch("sys.stdout"):
            cli.main(["--version"])
        self.assertEqual(caught.exception.code, 0)


def _docstring_nodes(tree: ast.AST) -> set:
    nodes = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = getattr(node, "body", [])
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                nodes.add(id(body[0].value))
    return nodes


class StaticTests(unittest.TestCase):
    """AC-006-21: no shell, no eval or exec, no banned PyEZ helper, no check/validate anywhere in code."""

    BANNED_ATTRIBUTES: ClassVar[Set[str]] = {
        "safe_copy",
        "request_shell_execute",
        "kill_session",
        "commit_check",
        "symlink",
        "open_channel",  # no SSH forwarding channel of any kind (R3: refused on SRX4100)
        "invoke_shell",
        "make_directory",  # PyEZ's dynamic RPC for 'make-directory': root makes /var/db/jwicket (R4)
        "delete_directory",
    }
    # '<check/>' and '<validate>' as elements ('<checksum/>' in the configuration filter is fine).
    BANNED_TEXT = (
        re.compile(r"<check[\s/>]"),
        re.compile(r"<validate[\s/>]"),
        re.compile(r"commit check"),
        re.compile(r"request-shell-execute"),
        re.compile(r"kill-session"),
        re.compile(r"file-change-owner"),
        re.compile(r"direct-tcpip"),  # R3: no check, and no command, opens an SSH forwarding channel
        re.compile(r"\bsu root\b"),  # the installer never becomes root
    )
    # RPC names no code may pass (R4: 'file make-directory' was refused on SRX4100; root makes the
    # directory). Texts that explain the refusal mention the CLI command, never the bare RPC name.
    BANNED_RPC_NAMES = ("make-directory", "delete-directory")
    BANNED_IMPORTS = (
        "jnpr.junos.utils.fs",
        "jnpr.junos.utils.start_shell",
        "jnpr.junos.utils.sw",
        "jnpr.junos.utils.scp",
    )

    def modules(self) -> List[Path]:
        return sorted(PACKAGE.glob("*.py"))

    def test_no_shell_eval_exec_or_os_system(self) -> None:
        for path in self.modules():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func = node.func
                    if isinstance(func, ast.Name):
                        self.assertNotIn(func.id, ("eval", "exec"), f"{path.name}:{node.lineno}")
                    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                        self.assertNotEqual((func.value.id, func.attr), ("os", "system"), path.name)
                        self.assertNotEqual((func.value.id, func.attr), ("os", "popen"), path.name)
                    for keyword in node.keywords:
                        if keyword.arg == "shell":
                            self.assertFalse(
                                isinstance(keyword.value, ast.Constant) and keyword.value.value is True,
                                f"{path.name}:{node.lineno} shell=True",
                            )

    def test_no_banned_pyez_helpers_or_imports(self) -> None:
        for path in self.modules():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute):
                    self.assertNotIn(node.attr, self.BANNED_ATTRIBUTES, f"{path.name}:{node.lineno}")
                if isinstance(node, ast.Name):
                    self.assertNotEqual(node.id, "FS", f"{path.name}:{node.lineno}")
                    self.assertNotEqual(node.id, "StartShell", f"{path.name}:{node.lineno}")
                if isinstance(node, ast.ImportFrom) and node.module:
                    self.assertFalse(node.module.startswith(self.BANNED_IMPORTS), f"{path.name}: {node.module}")
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self.assertFalse(alias.name.startswith(self.BANNED_IMPORTS), path.name)

    def test_no_check_validate_or_shell_rpc_in_any_code_string(self) -> None:
        for path in self.modules():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            docstrings = _docstring_nodes(tree)
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings:
                    lowered = node.value.lower()
                    for banned in self.BANNED_TEXT:
                        self.assertIsNone(banned.search(lowered), f"{path.name}:{node.lineno}: {node.value[:60]!r}")

    def test_no_directory_rpc_name_is_a_code_string(self) -> None:
        for path in self.modules():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    self.assertNotIn(node.value.strip(), self.BANNED_RPC_NAMES, f"{path.name}:{node.lineno}")
        for name in self.BANNED_RPC_NAMES:
            self.assertNotIn(name, transport.INSTALL_RPCS)

    def test_install_rpcs_never_name_a_recursive_or_shell_operation(self) -> None:
        for name, spec in transport.INSTALL_RPCS.items():
            self.assertNotIn("recurse", spec.args, name)
            self.assertNotIn("shell", name)
            self.assertNotIn(name, ("file-put", "file-change-owner", "kill-session", "request-shell-execute"))

    def test_installer_code_is_not_in_the_daemon(self) -> None:
        """P10: the bundle carries src/jwicket only, which never imports the installer; the daemon's
        ALLOWED_RPCS holds none of the installer's writes."""
        for path in sorted((REPO / "src" / "jwicket").rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    self.assertFalse((node.module or "").startswith("jwicket_install"), path.name)
                if isinstance(node, ast.Import):
                    self.assertFalse(any(a.name.startswith("jwicket_install") for a in node.names), path.name)
        session = (REPO / "src" / "jwicket" / "junos" / "session.py").read_text(encoding="utf-8")
        for name in transport.WRITE_RPCS:
            self.assertNotIn(f'"{name}"', session)

    def test_pyez_paramiko_scp_cryptography_are_imported_lazily(self) -> None:
        for name in INSTALLER_MODULES:
            tree = ast.parse((PACKAGE / f"{name}.py").read_text(encoding="utf-8"))
            for node in tree.body:
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    modules = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or ""]
                    for module in modules:
                        self.assertFalse(
                            module.startswith(("jnpr", "paramiko", "scp", "ncclient", "lxml", "cryptography")), name
                        )


class CredentialTests(CliBase):
    """AC-006-22: no password option; getpass only; no password or token in any output or record."""

    def test_no_password_option_exists(self) -> None:
        parser = cli.build_parser()
        actions: List[argparse.Action] = []
        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                for sub in action.choices.values():
                    actions.extend(sub._actions)
        for action in actions:
            for option in action.option_strings:
                if "pass" in option:
                    self.assertEqual(option, "--password-prompt")
                    self.assertEqual(action.nargs, 0)
        with self.assertRaises(SystemExit):
            cli.build_parser().parse_args(["status", "--host", "h", "--user", "u", "--password", "x"])

    def test_password_comes_from_getpass_only(self) -> None:
        args = argparse.Namespace(identity_file=None, password_prompt=True, user=f.USER)
        with mock.patch.object(cli.getpass, "getpass", return_value="fixture-pass") as prompt, mock.patch.object(
            cli.sys.stdin, "isatty", return_value=True
        ):
            credentials = cli.credentials(args)
        prompt.assert_called_once()
        self.assertEqual(credentials.password, "fixture-pass")
        self.assertNotIn("fixture-pass", repr(credentials))
        with mock.patch.object(cli.sys.stdin, "isatty", return_value=False), self.assertRaises(cli.CliError):
            cli.credentials(args)

    def test_lab_token_never_appears_in_outputs_or_records(self) -> None:
        """The lab token half of AC-006-22 (the password half: the test after this one)."""
        records: List[str] = []

        class Capture(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                records.append(self.format(record))

        handler = Capture(level=logging.DEBUG)
        logger = logging.getLogger("jwicket_install")
        logger.addHandler(handler)
        old_level = logger.level
        logger.setLevel(logging.DEBUG)
        self.addCleanup(logger.removeHandler, handler)
        self.addCleanup(logger.setLevel, old_level)
        code, console = self.run_cli(["-v", "-v", *self.install_args("--apply", "--backend", "lab-token")])
        self.assertEqual(code, 0, console.text())
        token = self.device.files[plan.LAB_TOKEN_PATH].data.decode("ascii").strip()
        self.assertEqual(len(token), 48)
        self.assertEqual(self.device.files[plan.LAB_TOKEN_PATH].mode, 0o600)
        haystacks = [console.text(), "\n".join(records)]
        for path in self.harness.store.root.rglob("*"):
            if path.is_file():
                haystacks.append(path.read_text(encoding="utf-8", errors="replace"))
        haystacks.append(self.device.files[plan.RECEIPT_PATH].data.decode("utf-8"))
        for text in haystacks:
            self.assertNotIn(token, text)

    def test_a_typed_password_never_appears_in_outputs_logs_or_records(self) -> None:
        """SEC-06, AC-006-22, INV-08: the real CLI path (cli.credentials, _real_executor) with a password
        typed at getpass; the connector is a recording stand-in that holds it, as the real one would."""
        records: List[str] = []

        class Capture(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                records.append(self.format(record))

        handler = Capture(level=logging.DEBUG)
        logger = logging.getLogger("jwicket_install")
        logger.addHandler(handler)
        old_level = logger.level
        logger.setLevel(logging.DEBUG)
        self.addCleanup(logger.removeHandler, handler)
        self.addCleanup(logger.setLevel, old_level)
        received: List[transport.Credentials] = []
        device = self.device

        class RecordingConnector(f.FakeConnector):
            def __init__(self, target: transport.Target, credentials: transport.Credentials, clock: Any) -> None:
                super().__init__(device)
                received.append(credentials)
                logging.getLogger("jwicket_install.test").debug("connector for %r", credentials)

        console = f.FakeConsole(self.device, f.gate_answers())
        argv = [
            "-v",
            "-v",
            *self.install_args("--apply", "--password-prompt", "--known-hosts", str(self.harness.known)),
        ]
        harness = self.harness
        real_executor = cli.workstation.Executor

        def executor(*args: Any, **kwargs: Any) -> Any:  # the real CLI path, with the harness's TLS pair maker
            kwargs.setdefault("tls_maker", harness.tls_maker)
            return real_executor(*args, **kwargs)

        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(receipt, "default_state_dir", return_value=self.harness.store.root))
            prompt = stack.enter_context(mock.patch.object(cli.getpass, "getpass", return_value="fixture-pass"))
            stack.enter_context(mock.patch.object(cli.sys.stdin, "isatty", return_value=True))
            stack.enter_context(mock.patch.object(cli.transport, "RealConnector", RecordingConnector))
            stack.enter_context(mock.patch.object(cli.transport, "SystemClock", lambda: device.clock))
            stack.enter_context(mock.patch.object(cli, "Executor", executor))
            code = cli.main(argv, console=console)
        self.assertEqual(code, 0, console.text())
        prompt.assert_called_once()
        self.assertEqual([c.password for c in received], ["fixture-pass"])
        haystacks = [console.text(), "\n".join(records)]
        for path in self.harness.store.root.rglob("*"):
            if path.is_file():
                haystacks.append(path.read_text(encoding="utf-8", errors="replace"))
        haystacks.append(self.device.files[plan.RECEIPT_PATH].data.decode("utf-8"))
        haystacks.append(repr(self.device.calls))
        for text in haystacks:
            self.assertNotIn("fixture-pass", text)

    def test_repeated_verbose_flags_count(self) -> None:
        """'-v -v' is DEBUG. (Python 3.7's argparse does not group '-vv' when allow_abbrev is False,
        bpo-26967; the workstation floor with PyEZ is 3.8, where it does.)"""
        self.assertEqual(cli.build_parser().parse_args(["-v", "-v", "bootstrap", "--user", f.USER]).verbose, 2)

    def test_cli_holds_third_party_loggers_at_warning(self) -> None:
        cli.setup_logging(2)
        for name in cli.QUIET_LOGGERS:
            self.assertEqual(logging.getLogger(name).level, logging.WARNING)


if __name__ == "__main__":
    unittest.main()


class RenderUninstallTests(CliBase):
    def test_cli_uninstall_units_after_reads_and_the_gate(self) -> None:
        self.assertEqual(self.run_cli(self.install_args("--apply"))[0], 0)
        mark = len(self.device.calls)
        code, console = self.run_cli(["render", "--method", "cli-uninstall", "--host", f.ADDRESS, "--user", f.USER])
        self.assertEqual(code, 0, console.text())
        later = self.device.calls[mark:]
        self.assertFalse([c for c in later if c[0] in f.WRITES or (c[0] == "rpc" and c[1] in f.transport.WRITE_RPCS)])
        text = console.text()
        self.assertIn("delete system extensions extension-service application file jwicket.py", text)
        self.assertLess(text.find("Lab gate passed"), text.find("Unit "))  # the plan before, the units after


class OpenTests(CliBase):
    """`open` (spec 6.2 step 4, UI-006-06, revision R3): it forwards nothing. With --access tls it prints
    the URL and the certificate's fingerprint from this workstation's record and checks them with C8's
    pinned read; with --access tunnel the 'ssh -L' line to run by hand and TUNNEL_WARNING."""

    def test_tls_prints_the_url_and_the_fingerprint_and_reads_c8(self) -> None:
        self.assertEqual(self.run_cli(self.install_args("--apply"))[0], 0)
        mark = len(self.device.calls)
        code, console = self.run_cli(["open", "--host", f.ADDRESS, "--user", f.USER])
        self.assertEqual(code, plan.EXIT_OK, console.text())
        text = console.text()
        pair = self.harness.tls_pairs[0]
        self.assertIn("Browse to https://192.0.2.10:9443/", text)
        self.assertIn(plan.fingerprint_display(pair.cert_sha256), text)
        self.assertIn("C8 pass", text)
        later = [c[0] for c in self.device.calls[mark:]]
        self.assertEqual([n for n in later if n not in ("host-key", "https-get", "https-request")], [])

    def test_tunnel_prints_the_ssh_line_with_the_warning(self) -> None:
        self.assertEqual(self.run_cli(self.install_args("--apply", "--access", "tunnel"))[0], 0)
        code, console = self.run_cli(["open", "--host", f.ADDRESS, "--user", f.USER])
        self.assertEqual(code, plan.EXIT_OK, console.text())
        text = console.text()
        self.assertIn("ssh -L 127.0.0.1:8443:127.0.0.1:8443 labadmin@192.0.2.10", text)
        self.assertIn(plan.TUNNEL_WARNING, text)
        self.assertNotIn("https-get", self.device.names())

    def test_no_record_is_exit_1_with_how_to_reach_it(self) -> None:
        code, console = self.run_cli(["open", "--host", f.ADDRESS, "--user", f.USER])
        self.assertEqual(code, plan.EXIT_REFUSED)
        self.assertIn("no install record for this device", console.text())
        self.assertNotIn("ssh-open", self.device.names())  # a key exchange only, no sign-in

    def test_open_has_no_forwarding_option(self) -> None:
        with self.assertRaises(SystemExit), mock.patch("sys.stderr"):
            cli.build_parser().parse_args(["open", "--host", "h", "--user", "u", "--local-port", "1"])


class AccessArgumentTests(CliBase):
    """Revision R2: --access tls (the default) on --listen-address (default --host when it is an IP
    address), port 9443; --access tunnel on 127.0.0.1:8443. Bad combinations are exit 2 before contact."""

    def test_the_listen_address_defaults_to_an_ip_host(self) -> None:
        code, console = self.run_cli(self.install_args("--json"))
        self.assertEqual(code, plan.EXIT_OK, console.err.getvalue())
        document = json.loads(console.out.getvalue())
        self.assertEqual((document["access"], document["listen_address"]), ("tls", f.ADDRESS))

    def test_bad_combinations_are_exit_2_before_any_contact(self) -> None:
        cases = (
            ["install", "--host", "lab-vsrx-1", "--user", f.USER, "--bundle", str(self.bundle)],  # a name, no address
            self.install_args("--access", "tunnel", "--listen-address", f.ADDRESS),
            self.install_args("--listen-address", "192.0.2.010"),  # not canonical
            self.install_args("--listen-address", "lab-vsrx-1"),
            self.install_args("--backend", "lab-token", "--access", "tls"),  # the daemon refuses a shared token there
            self.install_args("--daemon-port", "80"),
        )
        for argv in cases:
            with self.subTest(argv=argv[-2:]):
                code, console = self.run_cli(argv)
                self.assertEqual(code, plan.EXIT_INPUT, console.text())
        self.assertEqual(self.device.calls, [])
        code, console = self.run_cli(cases[0])
        self.assertIn(plan.LISTEN_ADDRESS_REQUIRED, console.text())

    def test_a_named_host_with_an_explicit_listen_address_installs(self) -> None:
        argv = self.install_args("--apply", "--listen-address", f.ADDRESS)
        argv[argv.index(f.ADDRESS)] = "lab-vsrx-1"  # --host by name (the first ADDRESS is --host's)
        code, console = self.run_cli(argv)
        self.assertNotEqual(code, plan.EXIT_INPUT, console.text())

    def test_the_tls_result_document_carries_the_fingerprint_only(self) -> None:
        code, console = self.run_cli(
            self.install_args("--apply", "--method", "ansible", "--gate-from-stdin", "--json"),
            interactive=False,
            stdin_text=f.HOST + "\n",
        )
        self.assertEqual(code, plan.EXIT_OK, console.err.getvalue())
        document = json.loads(console.out.getvalue())
        pair = self.harness.tls_pairs[0]
        self.assertEqual(document["tls_cert_sha256"], pair.cert_sha256)
        self.assertEqual(document["port"], plan.DEFAULT_TLS_PORT)
        self.assertFalse(document["lab_hardware_attested"])
        self.assertNotIn(pair.key_pem.split(b"\n")[1].decode("ascii"), console.text())

    def test_status_reads_c8_from_the_record(self) -> None:
        self.assertEqual(self.run_cli(self.install_args("--apply"))[0], 0)
        code, console = self.run_cli(["status", "--host", f.ADDRESS, "--user", f.USER, "--json"])
        self.assertEqual(code, plan.EXIT_OK)
        document = json.loads(console.out.getvalue())
        self.assertEqual((document["access"], document["c8"], document["healthy"]), ("tls", "pass", True))


class MessageTests(CliBase):
    """OPX-13: messages that name the operator's actual mistake."""

    def test_fetch_offers_no_bundle_option(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            cli.build_parser().parse_args(["fetch", "--bundle", "x.py", "--out", "d"])
        self.assertNotIn("--bundle", cli._subparser(cli.build_parser(), "fetch").format_help())

    def test_render_upgrade_names_the_missing_host_first(self) -> None:
        code, console = self.run_cli(
            ["render", "--method", "cli", "--upgrade", "--release", "v0.1.0.dev1", "--user", "lab"]
        )
        self.assertEqual(code, plan.EXIT_INPUT)
        self.assertIn("needs --host", console.err.getvalue() + console.text())
        self.assertNotIn("--listen-address", console.err.getvalue())


def pasted(lines: Sequence[str]) -> str:
    """Unit E's lines as a POSIX shell reads them pasted: a line ending in ' \\' continues on the next."""
    return " ".join(line[:-2] if line.endswith(" \\") else line for line in lines)


class FollowUpTests(unittest.TestCase):
    """OPX-03: the command unit E of the NETCONF bootstrap prints is this dry run's own, so the run that
    follows installs what was reviewed: parsed again, it gives the same options and overrides. A unit shows
    each line through sanitize_display(line, 400), so no line may be longer, and no value may be cut."""

    def unit_e(self, lines: Sequence[str]) -> Tuple[str, ...]:
        """What unit E shows, after the executor puts the nonce in (workstation._print_bootstrap)."""
        from jwicket_install import render

        boot = plan.build_bootstrap(plan.Method.WORKSTATION, plan.Options(user="lab"), None, "k3v9qt")
        assert boot is not None  # a NETCONF bootstrap with no prior always adds S8
        units = render.render_bootstrap_units(boot, follow_up=[line.replace("<NONCE>", "k3v9qt") for line in lines])
        self.assertEqual(units[-1].number, "E")
        return units[-1].lines

    def test_the_printed_command_parses_to_the_dry_runs_options(self) -> None:
        argv = (
            "install --host lab-srx.example --user lab --release v0.1.0.dev1 --repo myfork/jwicket "
            "--identity-file /home/se/.ssh/lab_ed25519 --netconf-port 830 --layout group --no-jet-checksum "
            "--confirm-minutes 10 --bootstrap-minutes 15 --lab-hardware --ack-managed --trust-release-page-only "
            "--remove-diagnostics --password-prompt --transfer file-copy --url https://lab-mirror.example/jwicket.py "
            "--port 2222 --daemon-port 9444"
        ).split()
        for extra in (
            ["--listen-address", "192.0.2.10", "--keep-netconf"],
            ["--backend", "lab-token", "--access", "tunnel", "--remove-netconf-after"],
        ):
            with self.subTest(extra=extra):
                args = cli.build_parser().parse_args(argv + extra)
                lines = cli._follow_up(args)
                # Over 400 characters on one line, so one option to a line, each but the last continued.
                self.assertGreater(len(lines), 1)
                self.assertTrue(all(line.endswith(" \\") for line in lines[:-1]), lines)
                self.assertEqual(lines[-1], "  --bootstrap-nonce <NONCE>")
                self.assertTrue(all(len(line) <= 400 for line in lines))
                self.assertEqual(self.unit_e(lines), tuple(line.replace("<NONCE>", "k3v9qt") for line in lines))
                again = cli.build_parser().parse_args(shlex.split(pasted(lines).replace("<NONCE>", "k3v9qt"))[1:])
                differ = {k for k in vars(args) if getattr(args, k) != getattr(again, k)}
                self.assertEqual(differ, {"apply", "bootstrap_nonce"})
                self.assertEqual(cli.options_of(args), cli.options_of(again))
                self.assertEqual(cli.overrides_of(args), cli.overrides_of(again))

    def test_dry_run_only_flags_are_left_out(self) -> None:
        args = cli.build_parser().parse_args(
            ["install", "--host", "192.0.2.10", "--user", "lab", "--release", "v1", "--json", "--device-diff"]
        )
        (line,) = cli._follow_up(args)
        for flag in ("--json", "--device-diff", "--gate-from-stdin"):
            self.assertNotIn(flag, line)
        self.assertIn("--apply", line)
        self.assertTrue(line.endswith(" --bootstrap-nonce <NONCE>"), line)

    def test_a_long_value_is_printed_whole_never_cut(self) -> None:
        """A 261-character value used to be cut to 197 characters and '...' inside the command; now the
        command keeps it whole, on one line while the line fits, on its own line when it does not."""
        base = ["install", "--host", "192.0.2.10", "--user", "lab", "--release", "v1"]
        path = "/home/se/" + "k" * 240 + "/lab_ed25519"
        url = "https://lab-mirror.example/" + "d" * 180 + "/jwicket.py"
        for extra, count in (
            (["--identity-file", path], 1),
            (["--identity-file", path, "--transfer", "file-copy", "--url", url], 8),
        ):
            with self.subTest(count=count):
                args = cli.build_parser().parse_args(base + extra)
                lines = cli._follow_up(args)
                self.assertEqual(len(lines), count)
                self.assertTrue(any(f"--identity-file {path}" in line for line in lines))
                self.assertFalse(any("..." in line for line in lines))
                self.assertEqual(self.unit_e(lines), tuple(line.replace("<NONCE>", "k3v9qt") for line in lines))
                again = cli.build_parser().parse_args(shlex.split(pasted(lines).replace("<NONCE>", "k3v9qt"))[1:])
                self.assertEqual((again.identity_file, again.url), (path, args.url))

    def test_no_command_when_a_part_would_be_cut_or_changed(self) -> None:
        """Never a truncated or altered value inside a command the operator copies: one option longer than
        a unit line shows, or a value with characters the unit drops or replaces (or the nonce placeholder),
        gives no command, only a shell comment saying why, and the value is not echoed."""
        base = ["install", "--host", "192.0.2.10", "--user", "lab", "--release", "v1"]
        too_long = "/home/se/" + "k" * 400 + "/lab_ed25519"
        cases = (
            (["--identity-file", too_long], "the value of --identity-file is longer than the 400 characters"),
            (["--identity-file", "/home/se/.ssh/lab\tkey"], "the value of --identity-file holds characters"),
            (["--identity-file", "/home/se/.ssh/lab\nkey"], "the value of --identity-file holds characters"),
            (["--identity-file", "/home/se/.ssh/lab\x1b[2Jkey"], "the value of --identity-file holds characters"),
            (["--repo", "lab/<NONCE>"], "the value of --repo holds the nonce placeholder"),
        )
        for extra, reason in cases:
            with self.subTest(reason=reason):
                (line,) = cli._follow_up(cli.build_parser().parse_args(base + extra))
                self.assertTrue(line.startswith("# No command here: "), line)
                self.assertIn(reason, line)
                self.assertNotIn("...", line)
                self.assertNotIn(extra[1][:20], line)  # no part of the value, cut or whole
                self.assertTrue(line.endswith("--bootstrap-nonce <NONCE>."), line)
                self.assertEqual(self.unit_e([line]), (line.replace("<NONCE>", "k3v9qt"),))


class LabHardwareCliTests(CliBase):
    """Revision R5 through the command line: --lab-hardware on install, uninstall and render; M2's play
    gives 'lab only' on the line after the host name."""

    def setUp(self) -> None:
        super().setUp()
        self.device = f.lab_srx4100()
        self.harness = f.Harness(self.device, self.root / "srx4100")

    def test_the_flag_exists_where_a_device_is_changed_or_rendered(self) -> None:
        parser = cli.build_parser()
        for command in ("install", "uninstall", "render"):
            with self.subTest(command=command):
                argv = [command, "--host", f.ADDRESS, "--user", f.USER, plan.LAB_HARDWARE_FLAG]
                if command == "render":
                    argv[1:1] = ["--method", "cli-uninstall"]
                self.assertTrue(parser.parse_args(argv).lab_hardware)

    def test_the_play_path_records_the_attestation(self) -> None:
        argv = self.install_args(
            "--apply",
            "--method",
            "ansible",
            "--gate-from-stdin",
            "--json",
            plan.LAB_HARDWARE_FLAG,
            "--ack-managed",
            "--adopt",
        )
        code, console = self.run_cli(argv, interactive=False, stdin_text=f"{f.SRX4100_HOST}\nlab only\n")
        self.assertEqual(code, plan.EXIT_OK, console.err.getvalue())
        document = json.loads(console.out.getvalue())
        self.assertTrue(document["lab_hardware_attested"])
        self.assertEqual(document["plan"]["lab_hardware"], True)
        code, console = self.run_cli(
            ["uninstall", "--host", f.ADDRESS, "--user", f.USER, "--json", plan.LAB_HARDWARE_FLAG, "--ack-managed"]
        )
        self.assertEqual(code, plan.EXIT_OK, console.err.getvalue())
        body = json.loads(console.out.getvalue())["uninstall"]
        self.assertTrue(body["lab_hardware"])
        self.assertIn("outbound-ssh client: sd-cloud", body["production_signs"])  # for uninstall.yml, before the gate
