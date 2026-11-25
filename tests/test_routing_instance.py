"""app.routing_instance: the listener alone is created in the configured Junos routing instance."""

from __future__ import annotations

import sys
import types
import unittest
from typing import List
from unittest import mock

from jwicket.app import routing_instance
from jwicket.settings import ConfigError


class RoutingInstanceTests(unittest.TestCase):
    def fake_jcs(self, calls: List[str]) -> types.ModuleType:
        jcs = types.ModuleType("jcs")
        jcs.set_routing_instance = calls.append  # type: ignore[attr-defined]
        return jcs

    def test_unset_does_not_touch_jcs(self) -> None:
        with mock.patch.dict(sys.modules, {"jcs": None}), routing_instance(None):
            pass  # importing jcs here would raise ImportError

    def test_switches_in_and_back_to_default(self) -> None:
        calls: List[str] = []
        with mock.patch.dict(sys.modules, {"jcs": self.fake_jcs(calls)}):
            with routing_instance("mgmt_junos"):
                self.assertEqual(calls, ["mgmt_junos"])
            self.assertEqual(calls, ["mgmt_junos", "default"])

    def test_switches_back_when_the_bind_fails(self) -> None:
        calls: List[str] = []
        jcs = self.fake_jcs(calls)
        with mock.patch.dict(sys.modules, {"jcs": jcs}), self.assertRaises(OSError), routing_instance("mgmt_junos"):
            raise OSError(49, "Can't assign requested address")
        self.assertEqual(calls, ["mgmt_junos", "default"])

    def test_without_jcs_refuses_with_the_setting_named(self) -> None:
        no_jcs = mock.patch.dict(sys.modules, {"jcs": None})
        with no_jcs, self.assertRaises(ConfigError) as cm, routing_instance("mgmt_junos"):
            pass
        self.assertIn("routing_instance", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
