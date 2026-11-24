"""settings.py: every validation rule fails closed, and settings/secret files must be trustworthy."""

from __future__ import annotations

import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from jwicket import settings as S
from jwicket.settings import ConfigError, parse_settings

TLS = "tls_cert = /var/db/jwicket/cert.pem\ntls_key = /var/db/jwicket/key.pem\n"


def ini(server: str = "", auth: str = "", log: str = "") -> str:
    return f"[server]\n{server}\n[auth]\n{auth}\n[log]\n{log}\n"


class DefaultsTests(unittest.TestCase):
    def test_empty_file_gives_safe_defaults(self) -> None:
        got = parse_settings("")
        self.assertEqual(got.server.bind, "127.0.0.1")
        self.assertTrue(got.server.loopback)
        self.assertFalse(got.server.tls_enabled)
        self.assertEqual(got.server.port, 8443)
        self.assertEqual(got.server.allowed_hosts, ())
        self.assertEqual(got.auth.backend, "netconf")
        self.assertEqual(got.auth.netconf_host, "127.0.0.1")
        self.assertLess(got.auth.netconf_port, 1024)
        self.assertLessEqual(got.auth.session_idle_s, got.auth.session_absolute_s)
        self.assertIsNone(got.auth.lab_token_file)
        self.assertEqual(got.auth.max_sessions_per_user, 2)
        self.assertEqual(got.auth.login_failures_per_user_per_min, 5)
        self.assertEqual(got.auth.login_failures_per_source_per_min, 20)
        self.assertEqual(got.auth.login_concurrent, 2)

    def test_inline_comments_and_whitespace(self) -> None:
        got = parse_settings(ini(server="port = 9443 ; operator comment\nmax_connections = 4 # four"))
        self.assertEqual(got.server.port, 9443)
        self.assertEqual(got.server.max_connections, 4)

    def test_invalid_ini_is_a_config_error(self) -> None:
        with self.assertRaises(ConfigError):
            parse_settings("this is not ini")
        with self.assertRaises(ConfigError):
            parse_settings("[server]\nport = 1\nport = 2\n")  # duplicate option

    def test_ipv6_loopback_bind_is_normalised(self) -> None:
        got = parse_settings(ini(server="bind = 0:0:0:0:0:0:0:1"))
        self.assertEqual(got.server.bind, "::1")
        self.assertTrue(got.server.loopback)

    def test_tls_and_allowed_hosts_parse(self) -> None:
        hosts = "allowed_hosts = fw.example.net:8443, 192.0.2.1:8443"
        got = parse_settings(ini(server="bind = 192.0.2.1\n" + TLS + hosts))
        self.assertTrue(got.server.tls_enabled)
        self.assertFalse(got.server.loopback)
        self.assertEqual(got.server.allowed_hosts, ("fw.example.net:8443", "192.0.2.1:8443"))
        self.assertEqual(got.server.tls_cert, Path("/var/db/jwicket/cert.pem"))


class TransportRuleTests(unittest.TestCase):
    def test_non_loopback_bind_without_tls_is_refused(self) -> None:
        for bind in ("0.0.0.0", "192.0.2.1", "10.0.0.1", "::", "2001:db8::1"):  # noqa: S104 - refused, the point
            with self.subTest(bind=bind), self.assertRaises(ConfigError) as ctx:
                parse_settings(ini(server=f"bind = {bind}"))
            self.assertIn("TLS", str(ctx.exception))

    def test_non_loopback_bind_with_tls_is_allowed(self) -> None:
        got = parse_settings(ini(server="bind = 0.0.0.0\n" + TLS))
        self.assertEqual(got.server.bind, "0.0.0.0")  # noqa: S104 - allowed only because TLS is set

    def test_loopback_variants_allowed_without_tls(self) -> None:
        for bind in ("127.0.0.1", "127.0.0.2", "::1"):
            with self.subTest(bind=bind):
                self.assertTrue(parse_settings(ini(server=f"bind = {bind}")).server.loopback)

    def test_host_names_are_refused_for_bind(self) -> None:
        for bind in ("localhost", "fw.example.net", "127.0.0.1.nip.io"):
            with self.subTest(bind=bind), self.assertRaises(ConfigError) as ctx:
                parse_settings(ini(server=f"bind = {bind}"))
            self.assertIn("bind", str(ctx.exception))

    def test_tls_cert_and_key_must_be_set_together(self) -> None:
        for server in (
            "tls_cert = /var/db/jwicket/cert.pem",
            "tls_key = /var/db/jwicket/key.pem",
            "bind = 192.0.2.1\ntls_cert = /var/db/jwicket/cert.pem",
        ):
            with self.subTest(server=server), self.assertRaises(ConfigError) as ctx:
                parse_settings(ini(server=server))
            self.assertIn("tls", str(ctx.exception).lower())

    def test_tls_paths_must_be_absolute(self) -> None:
        with self.assertRaises(ConfigError):
            parse_settings(ini(server="tls_cert = cert.pem\ntls_key = /var/db/jwicket/key.pem"))

    def test_bad_allowed_hosts_entry_refused(self) -> None:
        for entry in ("fw example", "fw/../x", "a" * 300, "fw.example.net;rm"):
            with self.subTest(entry=entry), self.assertRaises(ConfigError):
                parse_settings(ini(server=f"allowed_hosts = {entry}"))

    def test_routing_instance_defaults_to_unset_and_parses(self) -> None:
        self.assertIsNone(parse_settings("").server.routing_instance)
        self.assertIsNone(parse_settings(ini(server="routing_instance =")).server.routing_instance)
        got = parse_settings(ini(server="routing_instance = mgmt_junos"))
        self.assertEqual(got.server.routing_instance, "mgmt_junos")

    def test_bad_routing_instance_refused(self) -> None:
        for name in ("mgmt junos", "-lead", "a;b", "x" * 129, "../etc"):
            with self.subTest(name=name), self.assertRaises(ConfigError):
                parse_settings(ini(server=f"routing_instance = {name}"))


class AuthRuleTests(unittest.TestCase):
    def test_netconf_host_must_be_loopback(self) -> None:
        for host in ("192.0.2.1", "10.0.0.1", "2001:db8::1", "0.0.0.0"):  # noqa: S104 - refused
            with self.subTest(host=host), self.assertRaises(ConfigError) as ctx:
                parse_settings(ini(auth=f"netconf_host = {host}"))
            self.assertIn("netconf_host", str(ctx.exception))
        for host in ("127.0.0.1", "::1"):
            with self.subTest(host=host):
                self.assertEqual(parse_settings(ini(auth=f"netconf_host = {host}")).auth.netconf_host, host)

    def test_netconf_host_name_refused(self) -> None:
        with self.assertRaises(ConfigError):
            parse_settings(ini(auth="netconf_host = localhost"))

    def test_netconf_port_must_be_privileged(self) -> None:
        for port in ("1024", "2830", "65535", "0", "-1"):
            with self.subTest(port=port), self.assertRaises(ConfigError):
                parse_settings(ini(auth=f"netconf_port = {port}"))
        for port in ("22", "830", "1023", "1"):
            with self.subTest(port=port):
                self.assertEqual(parse_settings(ini(auth=f"netconf_port = {port}")).auth.netconf_port, int(port))

    def test_lab_token_only_on_loopback(self) -> None:
        token = "lab_token_file = /var/db/jwicket/lab.token"
        with self.assertRaises(ConfigError) as ctx:
            parse_settings(ini(server="bind = 192.0.2.1\n" + TLS, auth="backend = lab-token\n" + token))
        self.assertIn("lab-token", str(ctx.exception))
        got = parse_settings(ini(auth="backend = lab-token\n" + token))
        self.assertEqual(got.auth.backend, "lab-token")
        self.assertEqual(got.auth.lab_token_file, Path("/var/db/jwicket/lab.token"))

    def test_lab_token_needs_a_token_file(self) -> None:
        with self.assertRaises(ConfigError) as ctx:
            parse_settings(ini(auth="backend = lab-token"))
        self.assertIn("lab_token_file", str(ctx.exception))

    def test_unknown_backend_refused(self) -> None:
        for backend in ("ldap", "none", "LAB-TOKEN", "fixture"):
            with self.subTest(backend=backend), self.assertRaises(ConfigError):
                parse_settings(ini(auth=f"backend = {backend}"))

    def test_idle_must_not_exceed_absolute(self) -> None:
        with self.assertRaises(ConfigError) as ctx:
            parse_settings(ini(auth="session_idle_s = 3600\nsession_absolute_s = 600"))
        self.assertIn("session_idle_s", str(ctx.exception))
        got = parse_settings(ini(auth="session_idle_s = 600\nsession_absolute_s = 600"))
        self.assertEqual(got.auth.session_idle_s, got.auth.session_absolute_s)


class RangeTests(unittest.TestCase):
    CASES = (
        ("server", "port", ("1023", "80", "65536", "x", "8443.5"), ("1024", "65535")),
        ("server", "max_connections", ("1", "65", "-3"), ("2", "64")),
        ("server", "socket_timeout_s", ("1", "61"), ("2", "60")),
        ("server", "max_body_bytes", ("1023", "65537"), ("1024", "65536")),
        ("auth", "rpc_timeout_s", ("4", "301"), ("5", "300")),
        ("auth", "session_idle_s", ("59", "3601"), ("60", "3600")),
        ("auth", "session_absolute_s", ("599", "86401"), ("3600", "86400")),
        ("auth", "max_sessions", ("0", "17"), ("1", "16")),
        ("auth", "max_sessions_per_user", ("0", "17"), ("1", "16")),
        ("auth", "login_failures_per_user_per_min", ("0", "61"), ("1", "60")),
        ("auth", "login_failures_per_source_per_min", ("0", "601"), ("1", "600")),
        ("auth", "login_concurrent", ("0", "9"), ("1", "8")),
        ("log", "max_bytes", ("9999", "50000001"), ("10000", "50000000")),
        ("log", "backups", ("0", "21"), ("1", "20")),
    )

    def test_out_of_range_values_refused_and_bounds_accepted(self) -> None:
        for section, key, bad, good in self.CASES:
            for value in bad:
                with self.subTest(key=key, value=value), self.assertRaises(ConfigError) as ctx:
                    parse_settings(ini(**{section: f"{key} = {value}"}))
                self.assertIn(key, str(ctx.exception))
            for value in good:
                with self.subTest(key=key, value=value):
                    parse_settings(ini(**{section: f"{key} = {value}"}))

    def test_log_level_choice(self) -> None:
        with self.assertRaises(ConfigError):
            parse_settings(ini(log="level = TRACE"))
        self.assertEqual(parse_settings(ini(log="level = DEBUG")).log.level, "DEBUG")

    def test_log_paths_must_be_absolute(self) -> None:
        for key in ("file", "audit_file"):
            with self.subTest(key=key), self.assertRaises(ConfigError):
                parse_settings(ini(log=f"{key} = logs/jwicket.log"))


class StructureTests(unittest.TestCase):
    def test_unknown_sections_refused(self) -> None:
        for text in ("[serverx]\nport = 9443\n", "[server]\n[tls]\ncert = /x\n", "[DEFAULTS]\nport = 1\n"):
            with self.subTest(text=text), self.assertRaises(ConfigError) as ctx:
                parse_settings(text)
            self.assertIn("unknown", str(ctx.exception))

    def test_unknown_keys_refused(self) -> None:
        """'validated completely': a misspelt key must not be silently ignored (it fails open:
        ``alowed_hosts`` would leave the Host allowlist empty, ``max_conections`` the default cap)."""
        for section, line in (
            ("server", "alowed_hosts = fw.example.net"),
            ("server", "max_conections = 2"),
            ("auth", "sesion_idle_s = 60"),
        ):
            with self.subTest(line=line), self.assertRaises(ConfigError):
                parse_settings(ini(**{section: line}))


class FileTrustTests(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="jwicket-settings-"))
        os.chmod(self.dir, 0o700)
        self.addCleanup(shutil.rmtree, self.dir, True)

    def write(self, name: str, text: str, mode: int) -> Path:
        path = self.dir / name
        path.write_text(text, encoding="utf-8")
        os.chmod(path, mode)
        return path

    def test_good_file_is_read(self) -> None:
        path = self.write("jwicket.ini", "[server]\nport = 9443\n", 0o644)
        self.assertEqual(S.read_trusted_text(path, label="settings file", secret=False), "[server]\nport = 9443\n")
        self.assertEqual(S.load_settings(path).server.port, 9443)
        self.assertEqual(S.load_settings(path).source, path)

    def test_missing_file(self) -> None:
        with self.assertRaises(ConfigError):
            S.load_settings(self.dir / "missing.ini")
        with self.assertRaises(ConfigError):
            S.check_trusted_file(self.dir / "missing.ini", label="x", secret=False)

    def test_symlink_refused(self) -> None:
        target = self.write("real.ini", "[server]\n", 0o644)
        link = self.dir / "link.ini"
        link.symlink_to(target)
        with self.assertRaises(ConfigError) as ctx:
            S.check_trusted_file(link, label="settings file", secret=False)
        self.assertIn("symbolic link", str(ctx.exception))
        with self.assertRaises(ConfigError):
            S.read_trusted_text(link, label="settings file", secret=False)
        with self.assertRaises(ConfigError):
            S.load_settings(link)

    def test_not_a_regular_file(self) -> None:
        sub = self.dir / "sub"
        sub.mkdir(mode=0o700)
        with self.assertRaises(ConfigError):
            S.check_trusted_file(sub, label="settings file", secret=False)
        with self.assertRaises(ConfigError):
            S.read_trusted_text(sub, label="settings file", secret=False)

    def test_group_or_other_writable_refused(self) -> None:
        for mode in (0o664, 0o646, 0o666, 0o620):
            path = self.write(f"w{mode:o}.ini", "[server]\n", mode)
            with self.subTest(mode=oct(mode)), self.assertRaises(ConfigError) as ctx:
                S.load_settings(path)
            self.assertIn("writable", str(ctx.exception))

    def test_secret_must_be_0600(self) -> None:
        for mode in (0o640, 0o604, 0o644, 0o610):
            path = self.write(f"s{mode:o}.token", "x" * 40, mode)
            with self.subTest(mode=oct(mode)), self.assertRaises(ConfigError) as ctx:
                S.check_trusted_file(path, label="lab token file", secret=True)
            self.assertIn("0600", str(ctx.exception))
        for mode in (0o600, 0o400):
            path = self.write(f"ok{mode:o}.token", "x" * 40, mode)
            with self.subTest(mode=oct(mode)):
                S.check_trusted_file(path, label="lab token file", secret=True)

    def test_non_secret_may_be_world_readable(self) -> None:
        S.check_trusted_file(self.write("cert.pem", "pem", 0o644), label="TLS certificate", secret=False)

    def test_parent_directory_writable_by_others_refused_unless_sticky(self) -> None:
        open_dir = self.dir / "open"
        open_dir.mkdir()
        os.chmod(open_dir, 0o777)  # noqa: S103 - the unsafe directory under test
        path = open_dir / "jwicket.ini"
        path.write_text("[server]\n", encoding="utf-8")
        os.chmod(path, 0o644)
        with self.assertRaises(ConfigError) as ctx:
            S.load_settings(path)
        self.assertIn("directory", str(ctx.exception))
        os.chmod(open_dir, 0o777 | stat.S_ISVTX)  # noqa: S103 - sticky, like /var/tmp
        S.load_settings(path)

    @unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0, "needs root to chown")
    def test_wrong_owner_refused(self) -> None:
        path = self.write("other.ini", "[server]\n", 0o644)
        os.chown(path, 54321, 54321)
        with self.assertRaises(ConfigError) as ctx:
            S.load_settings(path)
        self.assertIn("owned by uid 54321", str(ctx.exception))

    def test_read_trusted_text_reads_the_file_it_checked(self) -> None:
        """If the path is swapped for another file after it was opened, the read is refused."""
        path = self.write("jwicket.ini", "[server]\nport = 9443\n", 0o644)
        other = self.write("swap.ini", "[server]\nport = 9999\n", 0o644)
        real_check = S.check_directories

        def check_then_swap(p: Path, **kw: Any) -> None:
            real_check(p, **kw)
            os.replace(other, path)

        swap = mock.patch.object(S, "check_directories", side_effect=check_then_swap)
        with swap, self.assertRaises(ConfigError) as ctx:
            S.read_trusted_text(path, label="settings file", secret=False)
        self.assertIn("changed", str(ctx.exception))

    def test_owner_and_mode_come_from_the_opened_file(self) -> None:
        """SECU-9: owner, mode and type are taken from the open file (fstat), not from a fresh lookup of
        the name, so a name pointed at a good file during the check cannot vouch for the file read."""
        path = self.write("jwicket.ini", "[server]\nport = 9443\n", 0o644)
        real_fstat = os.fstat

        def writable_by_others(fd: int) -> os.stat_result:
            st = real_fstat(fd)
            values = list(st)
            values[0] = stat.S_IFREG | 0o666
            return os.stat_result(values)

        with mock.patch.object(S.os, "fstat", side_effect=writable_by_others), self.assertRaises(ConfigError) as ctx:
            S.read_trusted_text(path, label="settings file", secret=False)
        self.assertIn("writable", str(ctx.exception))

    def test_directory_owned_by_another_account_refused(self) -> None:
        """SECU-9: the owner of a directory can swap the names in it, so every directory above a trusted
        file must belong to root or to the daemon's account (mode 0755 alone is not enough)."""
        other = self.dir / "other"
        other.mkdir(mode=0o755)
        path = other / "jwicket.ini"
        path.write_text("[server]\n", encoding="utf-8")
        os.chmod(path, 0o644)
        if os.geteuid() == 0:
            os.chown(other, 1234, 1234)
        # As root the directory now belongs to uid 1234; as any other user it belongs to that user,
        # so trusting root alone makes it "another account" either way.
        with mock.patch.object(S, "_trusted_uids", return_value=frozenset({0})):
            for call in (
                lambda: S.load_settings(path),
                lambda: S.check_trusted_file(path, label="TLS certificate", secret=False),
            ):
                with self.assertRaises(ConfigError) as ctx:
                    call()
                self.assertIn("directory", str(ctx.exception))
                self.assertIn("owned by uid", str(ctx.exception))
        if os.geteuid() == 0:
            with self.assertRaises(ConfigError) as ctx:
                S.load_settings(path)
            self.assertIn(f"directory {other}", str(ctx.exception))

    def test_symlinked_directory_followed_only_when_root_owns_the_link(self) -> None:
        real = self.dir / "real"
        real.mkdir(mode=0o700)
        path = real / "jwicket.ini"
        path.write_text("[server]\nport = 9443\n", encoding="utf-8")
        os.chmod(path, 0o644)
        link = self.dir / "link"
        link.symlink_to(real)
        via_link = link / "jwicket.ini"
        if os.geteuid() == 0:
            self.assertEqual(S.load_settings(via_link).server.port, 9443)  # root's own link is followed
            os.lchown(link, 54321, 54321)
            with self.assertRaises(ConfigError) as ctx:
                S.load_settings(via_link)
        else:
            with self.assertRaises(ConfigError) as ctx:  # a link this user owns is not root's
                S.load_settings(via_link)
        self.assertIn("symbolic link owned by uid", str(ctx.exception))

    def test_directory_walk_resolves_dot_dot_like_the_kernel(self) -> None:
        sub = self.dir / "a"
        sub.mkdir(mode=0o700)
        path = self.write("jwicket.ini", "[server]\nport = 9443\n", 0o644)
        self.assertEqual(S.load_settings(sub / ".." / path.name).server.port, 9443)

    def test_lab_token_length_and_mode(self) -> None:
        short = self.write("short.token", "a" * (S.MIN_LAB_TOKEN_LEN - 1) + "\n", 0o600)
        with self.assertRaises(ConfigError) as ctx:
            S.load_lab_token(short)
        self.assertIn("shorter", str(ctx.exception))
        # Surrounding whitespace does not count towards the length.
        padded = self.write("padded.token", "   " + "b" * (S.MIN_LAB_TOKEN_LEN - 1) + "   \n", 0o600)
        with self.assertRaises(ConfigError):
            S.load_lab_token(padded)
        good = self.write("good.token", "c" * S.MIN_LAB_TOKEN_LEN + "\n", 0o600)
        self.assertEqual(S.load_lab_token(good), b"c" * S.MIN_LAB_TOKEN_LEN)
        readable = self.write("readable.token", "d" * 40, 0o644)
        with self.assertRaises(ConfigError):
            S.load_lab_token(readable)

    def test_lab_token_must_be_ascii(self) -> None:
        path = self.write("utf8.token", "\u00e9" * 40, 0o600)
        with self.assertRaises(ConfigError):
            S.load_lab_token(path)

    def test_tls_files(self) -> None:
        cert = self.write("cert.pem", "pem", 0o644)
        key = self.write("key.pem", "pem", 0o644)
        server = S.ServerSettings(bind="192.0.2.1", tls_cert=cert, tls_key=key)
        with self.assertRaises(ConfigError) as ctx:
            S.check_tls_files(server)
        self.assertIn("private key", str(ctx.exception))
        os.chmod(key, 0o600)
        S.check_tls_files(server)


if __name__ == "__main__":
    unittest.main()
