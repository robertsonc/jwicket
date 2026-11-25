"""Downloads and provenance (Spec 006 section 8.9, INV-07, AC-006-24 and AC-006-25).

FetchTests run a local HTTP server on 127.0.0.1 (port 0). The production fetcher accepts https only, so
those tests build a Fetcher with ``schemes=("http",)`` and ``hosts={"127.0.0.1"}``: the same redirect,
hop, cap and retry code, with the scheme rule tested separately. No GitHub host is contacted: ``gh`` and
``git`` are recording stand-ins."""

from __future__ import annotations

import hashlib
import http.server
import threading
import unittest
import urllib.request
from pathlib import Path
from typing import Any, ClassVar, Dict, List, Optional, Sequence, Tuple
from unittest import mock

import fakes_junos as f
from install_support import plan

from jwicket_install import provenance

TAG = "v0.1.0.dev1"
REPO = "owner/jwicket"


class Handler(http.server.BaseHTTPRequestHandler):
    routes: ClassVar[Dict[str, Any]] = {}
    hits: ClassVar[List[str]] = []

    def do_GET(self) -> None:  # noqa: N802 - http.server's name
        self.hits.append(self.path)
        status, headers, body = self.routes.get(self.path, (404, {}, b"missing"))
        if callable(body):
            status, headers, body = body()
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        if "Content-Length" not in headers:
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: Any) -> None:
        return


class FetchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self) -> None:
        Handler.routes = {}
        Handler.hits = []
        self.sleeps: List[float] = []
        self.fetcher = provenance.Fetcher(
            hosts=frozenset({"127.0.0.1"}), schemes=("http",), timeout=5, sleep=self.sleeps.append
        )

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def redirect(self, path: str, target: str) -> None:
        Handler.routes[path] = (302, {"Location": target}, b"")

    def test_plain_download(self) -> None:
        Handler.routes["/a"] = (200, {}, b"bundle")
        self.assertEqual(self.fetcher.get(self.url("/a")), b"bundle")

    def test_three_redirects_are_followed_and_a_fourth_is_refused(self) -> None:
        for hop in range(4):
            self.redirect(f"/r{hop}", self.url(f"/r{hop + 1}"))
        Handler.routes["/r4"] = (200, {}, b"end")
        self.assertEqual(self.fetcher.get(self.url("/r1")), b"end")  # r1 -> r2 -> r3 -> r4: three hops
        with self.assertRaises(provenance.ProvenanceError) as caught:
            self.fetcher.get(self.url("/r0"))  # four hops
        self.assertIn("redirects", str(caught.exception))

    def test_redirect_to_another_host_is_refused(self) -> None:
        self.redirect("/x", "http://evil.example/bundle")
        with self.assertRaises(provenance.ProvenanceError) as caught:
            self.fetcher.get(self.url("/x"))
        self.assertIn("not in the allowed list", str(caught.exception))
        self.assertEqual(Handler.hits, ["/x"])  # no retry of a refusal

    def test_a_signed_asset_url_with_a_query_is_followed(self) -> None:
        """SEC-01: GitHub sends an asset download on to a signed URL with a query string."""
        signed = "/github-production-release-asset/212613049/x?sp=r&sv=2018-11-09&sr=b&spr=https&se=2026"
        self.redirect("/asset", self.url(signed))
        Handler.routes[signed] = (200, {}, b"bundle")
        self.assertEqual(self.fetcher.get(self.url("/asset")), b"bundle")
        self.assertEqual(Handler.hits, ["/asset", signed])

    def test_a_query_on_the_first_url_is_refused(self) -> None:
        Handler.routes["/a?x=1"] = (200, {}, b"bundle")
        with self.assertRaises(provenance.ProvenanceError) as caught:
            self.fetcher.get(self.url("/a?x=1"))
        self.assertIn("query", str(caught.exception))
        self.assertEqual(Handler.hits, [])

    def test_a_query_is_accepted_on_asset_hosts_only(self) -> None:
        handler = provenance.StrictRedirectHandler(
            frozenset({provenance.RELEASE_HOST, provenance.RECORD_HOST, *provenance.ASSET_HOSTS})
        )
        request = urllib.request.Request(f"https://github.com/{REPO}/releases/download/{TAG}/jwicket.py")
        signed = "https://release-assets.githubusercontent.com/github-production-release-asset/1/x?sp=r&sig=abc"
        self.assertIsNotNone(handler.redirect_request(request, None, 302, "Found", {}, signed))
        for refused in (
            f"https://github.com/{REPO}/releases/download/{TAG}/jwicket.py?x=1",
            f"https://raw.githubusercontent.com/{REPO}/main/x?token=1",
            "https://release-assets.githubusercontent.com/x#frag",
            "https://user:pw@release-assets.githubusercontent.com/x?sp=r",
            "http://release-assets.githubusercontent.com/x?sp=r",
        ):
            with self.subTest(url=refused), self.assertRaises(provenance.ProvenanceError):
                handler.redirect_request(request, None, 302, "Found", {}, refused)

    def test_oversize_is_refused_by_header_and_by_count(self) -> None:
        Handler.routes["/big"] = (200, {"Content-Length": str(17 * 1024 * 1024)}, b"x")
        with self.assertRaises(provenance.ProvenanceError):
            self.fetcher.get(self.url("/big"))
        Handler.routes["/stream"] = (200, {"Content-Length": "2000"}, b"y" * 2000)
        with self.assertRaises(provenance.ProvenanceError):
            self.fetcher.get(self.url("/stream"), limit=1000)

    def test_reads_retry_with_back_off(self) -> None:
        state = {"n": 0}

        def flaky() -> Tuple[int, Dict[str, str], bytes]:
            state["n"] += 1
            return (503, {}, b"busy") if state["n"] < 3 else (200, {}, b"ok")

        Handler.routes["/flaky"] = (0, {}, flaky)  # type: ignore[assignment]
        self.assertEqual(self.fetcher.get(self.url("/flaky")), b"ok")
        self.assertEqual(self.sleeps, [1, 2])

    def test_not_found_is_not_retried(self) -> None:
        with self.assertRaises(provenance.ProvenanceError):
            self.fetcher.get(self.url("/nothing"))
        self.assertEqual(Handler.hits, ["/nothing"])

    def test_every_open_has_a_timeout(self) -> None:
        Handler.routes["/a"] = (200, {}, b"bundle")
        seen: List[Any] = []
        real = urllib.request.OpenerDirector.open

        def spy(self: Any, url: Any, data: Any = None, timeout: Any = None) -> Any:
            seen.append(timeout)
            return real(self, url, data, timeout)

        with mock.patch.object(urllib.request.OpenerDirector, "open", spy):
            self.fetcher.get(self.url("/a"))
        self.assertEqual(seen, [5])
        self.assertEqual(provenance.Fetcher().timeout, plan.TIMEOUTS["http"])


class SchemeTests(unittest.TestCase):
    """The production fetcher: https only, github.com and the asset hosts only, per-tag URLs only."""

    def test_http_url_refused(self) -> None:
        with self.assertRaises(provenance.ProvenanceError):
            provenance.Fetcher().get("http://github.com/owner/jwicket/releases/download/v0.1.0.dev1/jwicket.py")

    def test_https_to_http_redirect_refused(self) -> None:
        handler = provenance.StrictRedirectHandler(frozenset({"github.com"}))
        request = urllib.request.Request("https://github.com/owner/jwicket/releases/download/v0.1.0.dev1/jwicket.py")
        with self.assertRaises(provenance.ProvenanceError):
            handler.redirect_request(request, None, 302, "Found", {}, "http://github.com/x")
        with self.assertRaises(provenance.ProvenanceError):
            handler.redirect_request(request, None, 302, "Found", {}, "https://user:pw@github.com/x")
        allowed = handler.redirect_request(
            request, None, 302, "Found", {}, "https://github.com/owner/jwicket/releases/download/v0.1.0.dev1/b"
        )
        self.assertIsNotNone(allowed)

    def test_per_tag_urls_only(self) -> None:
        self.assertEqual(
            provenance.release_url(REPO, TAG, "jwicket.py"),
            "https://github.com/owner/jwicket/releases/download/v0.1.0.dev1/jwicket.py",
        )
        for bad in ("latest", "v0.1.0", "v0.1.0-dev.1", "v0.1.0.dev1;x"):
            with self.assertRaises(plan.InputError):
                provenance.release_url(REPO, bad, "jwicket.py")
        with self.assertRaises(plan.InputError):
            provenance.validate_repo("owner/../x/y")
        self.assertIn(provenance.RELEASE_HOST, provenance.Fetcher().hosts)
        self.assertNotIn(provenance.RECORD_HOST, provenance.Fetcher().hosts)


class StubFetcher(provenance.Fetcher):
    def __init__(self, files: Dict[str, bytes]) -> None:
        super().__init__()
        self.files = files
        self.urls: List[str] = []

    def get(self, url: str, limit: int = provenance.MAX_DOWNLOAD_BYTES, *, extra_hosts: Any = frozenset()) -> bytes:
        self.urls.append(url)
        if url not in self.files:
            raise provenance.ProvenanceError(f"download refused: HTTP 404 for {url}")
        return self.files[url]


def sums_for(data: bytes, name: str = "jwicket.py") -> bytes:
    return f"{hashlib.sha256(data).hexdigest()}  {name}\n".encode("ascii")


class ReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.data = f.make_bundle()

    def fetcher(self, data: bytes, sums: bytes) -> StubFetcher:
        return StubFetcher(
            {
                provenance.release_url(REPO, TAG, "jwicket.py"): data,
                provenance.release_url(REPO, TAG, "SHA256SUMS"): sums,
            }
        )

    def test_release_download_checks_sums_and_the_tag(self) -> None:
        download = provenance.fetch_release(self.fetcher(self.data, sums_for(self.data)), REPO, TAG)
        self.assertEqual(download.identity.version, "0.1.0.dev1")

    def test_sha_mismatch_refused(self) -> None:
        with self.assertRaises(provenance.ProvenanceError) as caught:
            provenance.fetch_release(self.fetcher(self.data, sums_for(b"other")), REPO, TAG)
        self.assertIn("SHA256SUMS says", str(caught.exception))

    def test_version_and_tag_mismatch_refused(self) -> None:
        data = f.make_bundle("0.1.0.dev2")
        with self.assertRaises(provenance.ProvenanceError) as caught:
            provenance.fetch_release(self.fetcher(data, sums_for(data)), REPO, TAG)
        self.assertIn("the tag says 0.1.0.dev1", str(caught.exception))

    def test_malformed_sums_refused(self) -> None:
        with self.assertRaises(provenance.ProvenanceError):
            provenance.parse_sums("not a line\n")


class Recorder:
    def __init__(self, answers: Optional[Dict[str, Tuple[int, str]]] = None) -> None:
        self.calls: List[Tuple[List[str], Dict[str, Any]]] = []
        self.answers = answers or {}

    def __call__(self, argv: Sequence[str], **kwargs: Any) -> Tuple[int, str]:
        self.assertions(argv, kwargs)
        self.calls.append((list(argv), kwargs))
        for prefix, answer in self.answers.items():
            if " ".join(argv[1:]).startswith(prefix):
                return answer
        return 1, ""

    @staticmethod
    def assertions(argv: Sequence[str], kwargs: Dict[str, Any]) -> None:
        assert isinstance(argv, list) and all(isinstance(a, str) for a in argv), argv
        assert "shell" not in kwargs
        assert isinstance(kwargs.get("timeout"), int) and kwargs["timeout"] > 0


def which(name: str) -> Optional[str]:
    return {"gh": "/usr/bin/gh", "git": "/usr/bin/git"}.get(name)


class SourceTests(unittest.TestCase):
    """AC-006-24: each of P-A to P-E through stand-ins; none means 'none' (exit 7 for --apply)."""

    def setUp(self) -> None:
        self.data = f.make_bundle()
        self.identity = f.bundle_identity(self.data)
        self.path = Path("/tmp/jwicket.py")
        self.sha = self.identity.file_sha256

    def establish(self, sources: provenance.Sources, runner: Recorder, fetcher: Optional[Any] = None) -> Any:
        return provenance.establish(
            self.data, self.identity, self.path, sources, runner=runner, fetcher=fetcher or StubFetcher({}), which=which
        )

    def test_p_a_immutable_release(self) -> None:
        runner = Recorder({f"release verify-asset {TAG}": (0, "")})
        prov, _ = self.establish(provenance.Sources(repo=REPO, tag=TAG), runner)
        self.assertEqual((prov.kind, prov.evidence), ("immutable-release", True))
        self.assertEqual(
            runner.calls[0][0], ["/usr/bin/gh", "release", "verify-asset", TAG, str(self.path), "--repo", REPO]
        )

    def test_p_b_attestation_with_ancestry(self) -> None:
        commit = "a1" * 20
        runner = Recorder({"attestation verify": (0, ""), f"api repos/{REPO}/compare/{commit}...main": (0, "ahead\n")})
        prov, attempts = self.establish(provenance.Sources(repo=REPO, tag=TAG), runner)
        self.assertEqual(prov.kind, "attestation")
        argv = runner.calls[1][0]
        self.assertIn("--signer-workflow", argv)
        self.assertIn(f"{REPO}/.github/workflows/release.yml", argv)
        self.assertIn(f"refs/tags/{TAG}", argv)
        self.assertEqual([a.source for a in attempts], ["P-A", "P-B"])

    def test_p_b_binds_the_attestation_to_the_header_commit(self) -> None:
        """SEC-02: the attested source commit must be the header's before its ancestry counts."""
        commit = "a1" * 20
        runner = Recorder({"attestation verify": (0, ""), f"api repos/{REPO}/compare/{commit}...main": (0, "ahead\n")})
        self.establish(provenance.Sources(repo=REPO, tag=TAG), runner)
        argv = runner.calls[1][0]
        self.assertEqual(argv[argv.index("--source-digest") + 1], commit)

    def test_p_b_fails_when_the_attested_commit_is_not_the_header_commit(self) -> None:
        attested = "b2" * 20  # what the attestation's source digest really is

        class Attested(Recorder):
            def __call__(self, argv: Sequence[str], **kwargs: Any) -> Tuple[int, str]:
                super().__call__(argv, **kwargs)
                if "attestation" in argv:
                    return (0, "") if argv[argv.index("--source-digest") + 1] == attested else (1, "")
                return (0, "ahead\n") if "api" in argv else (1, "")

        runner = Attested()
        prov, attempts = self.establish(provenance.Sources(repo=REPO, tag=TAG), runner)
        self.assertEqual(prov.kind, "none")
        self.assertEqual([a.outcome for a in attempts if a.source == "P-B"], ["failed"])
        self.assertFalse(any("api" in call[0] for call in runner.calls))  # no ancestry check of a header claim

    def test_a_relative_gh_from_path_is_not_run(self) -> None:
        """SEC-08: an empty or '.' PATH entry makes which() return 'gh'; that counts as not installed."""
        runner = Recorder({f"release verify-asset {TAG}": (0, "")})
        prov, attempts = provenance.establish(
            self.data,
            self.identity,
            self.path,
            provenance.Sources(repo=REPO, tag=TAG),
            runner=runner,
            fetcher=StubFetcher({}),
            which=lambda name: name,
        )
        self.assertNotEqual(prov.kind, "immutable-release")
        self.assertEqual(runner.calls, [])
        self.assertIn(("P-A", "skipped"), [(a.source, a.outcome) for a in attempts])

    def test_p_b_needs_main_ancestry(self) -> None:
        runner = Recorder({"attestation verify": (0, ""), "api repos": (0, "diverged\n")})
        prov, _ = self.establish(provenance.Sources(repo=REPO, tag=TAG), runner)
        self.assertEqual(prov.kind, "none")

    def test_p_c_release_record(self) -> None:
        record = provenance.record_url(REPO, TAG)
        fetcher = StubFetcher({record: sums_for(self.data)})
        prov, _ = self.establish(provenance.Sources(repo=REPO, tag=TAG, use_gh=False), Recorder(), fetcher)
        self.assertEqual(prov.kind, "release-record")
        self.assertEqual(fetcher.urls, [record])

    def test_p_c_disagreement_is_fatal(self) -> None:
        fetcher = StubFetcher({provenance.record_url(REPO, TAG): sums_for(b"another build")})
        with self.assertRaises(provenance.ProvenanceError):
            self.establish(provenance.Sources(repo=REPO, tag=TAG, use_gh=False), Recorder(), fetcher)

    def test_p_c_from_a_checkout_with_git(self) -> None:
        runner = Recorder({"-C /src show origin/main:docs/releases": (0, sums_for(self.data).decode())})
        prov, _ = self.establish(provenance.Sources(repo=REPO, tag=TAG, use_gh=False, checkout=Path("/src")), runner)
        self.assertEqual(prov.kind, "release-record")

    def test_p_d_reproduction(self) -> None:
        commit = "a1" * 20
        built: Dict[str, bytes] = {}

        def runner(argv: Sequence[str], **kwargs: Any) -> Tuple[int, str]:
            Recorder.assertions(list(argv), kwargs)
            if argv[1:4] == ["-C", "/src", "rev-parse"]:
                return 0, commit + "\n"
            if "tools/bundle.py" in argv:
                self.assertEqual(kwargs["cwd"], "/src")
                self.assertNotIn("SSH_AUTH_SOCK", kwargs["env"])
                out = Path(argv[argv.index("--out") + 1])
                out.write_bytes(self.data)
                built["ok"] = self.data
                return 0, ""
            return 1, ""

        prov, _ = provenance.establish(
            self.data,
            self.identity,
            self.path,
            provenance.Sources(repo=REPO, tag=None, use_gh=False, checkout=Path("/src"), reproduce=True),
            runner=runner,
            fetcher=None,
            which=which,
        )
        self.assertEqual(prov.kind, "reproduced")
        self.assertIn("ok", built)

    def test_p_e_operator_hash(self) -> None:
        prov, _ = self.establish(
            provenance.Sources(repo=REPO, expect_sha256=self.sha, expect_source="lab-wiki"), Recorder()
        )
        self.assertEqual((prov.kind, prov.detail), ("operator-hash", ("lab-wiki",)))
        with self.assertRaises(provenance.ProvenanceError):
            self.establish(provenance.Sources(repo=REPO, expect_sha256="0" * 64, expect_source="lab-wiki"), Recorder())
        with self.assertRaises(plan.InputError):
            self.establish(provenance.Sources(repo=REPO, expect_sha256=self.sha, expect_source="two words"), Recorder())

    def test_no_source_and_the_release_page_only_stamp(self) -> None:
        prov, _ = self.establish(provenance.Sources(repo=REPO, tag=TAG, use_gh=False), Recorder())
        self.assertEqual((prov.kind, prov.evidence), ("none", False))
        prov, _ = self.establish(
            provenance.Sources(repo=REPO, tag=TAG, use_gh=False, trust_release_page_only=True), Recorder()
        )
        self.assertEqual((prov.kind, prov.evidence), ("release-page-only", False))
        built = plan.build_install_plan(
            self.identity,
            prov,
            f.options(),
            *self._facts_prior(),
            method=plan.Method.WORKSTATION,
            overrides=frozenset({"--trust-release-page-only"}),
        )
        self.assertTrue(built.receipt.not_evidence)
        self.assertFalse(built.blocked)

    def _facts_prior(self) -> Tuple[plan.DeviceFacts, plan.PriorState]:
        import install_support as s

        return s.prepared("fresh-vsrx")

    def test_local_self_test_scrubbed(self) -> None:
        seen: List[Tuple[List[str], Dict[str, Any]]] = []

        def runner(argv: Sequence[str], **kwargs: Any) -> Tuple[int, str]:
            Recorder.assertions(list(argv), kwargs)
            seen.append((list(argv), kwargs))
            return 0, "{}"

        ok, _ = provenance.local_self_test(self.data, runner)
        self.assertTrue(ok)
        argv, kwargs = seen[0]
        self.assertEqual(argv[1:2], ["-I"])
        self.assertEqual(argv[-1], "--bundle-self-test")
        self.assertEqual(set(kwargs["env"]), {"PATH", "HOME", "LANG"})
        self.assertEqual(kwargs["env"]["HOME"], kwargs["cwd"])
        self.assertEqual(kwargs["timeout"], 60)


if __name__ == "__main__":
    unittest.main()
