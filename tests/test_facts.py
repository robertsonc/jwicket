"""junos/facts.py: identity, HA mode and central management for the scope banner."""

from __future__ import annotations

import json
import unittest
from xml.etree import ElementTree

from helpers import BRANCH, BRANCH_SECRETS, CLUSTER, xml

from jwicket.junos import facts as F


class SoftwareTests(unittest.TestCase):
    def test_single_routing_engine(self) -> None:
        got = F.software(ElementTree.parse(BRANCH / "get-software-information.xml").getroot())
        self.assertEqual(
            got,
            {"status": "ok", "hostname": "branch-fw-01", "model": "vsrx", "version": "24.4R2-S3.5", "nodes": []},
        )

    def test_multi_routing_engine(self) -> None:
        got = F.software(ElementTree.parse(CLUSTER / "get-software-information.xml").getroot())
        self.assertEqual(got["status"], "ok")
        self.assertEqual((got["hostname"], got["model"], got["version"]), ("dc-fw-a", "srx4600", "24.4R2-S3.5"))
        self.assertEqual(
            got["nodes"],
            [
                {"node": "node0", "hostname": "dc-fw-a", "model": "srx4600", "version": "24.4R2-S3.5"},
                {"node": "node1", "hostname": "dc-fw-b", "model": "srx4600", "version": "24.4R2-S3.5"},
            ],
        )

    def test_namespaced_rpc_reply(self) -> None:
        reply = xml(
            '<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" '
            'xmlns:junos="http://xml.juniper.net/junos/24.4R2/junos"><software-information>'
            "<host-name>fw</host-name><product-model>srx345</product-model><junos-version>24.4R2</junos-version>"
            "</software-information></rpc-reply>"
        )
        got = F.software(reply)
        self.assertEqual((got["status"], got["hostname"], got["model"]), ("ok", "fw", "srx345"))

    def test_empty_reply_is_failed(self) -> None:
        got = F.software(xml("<rpc-reply/>"))
        self.assertEqual(got["status"], "failed")
        self.assertTrue(got["message"])


GROUPED = """
<chassis-cluster-status>
  <cluster-id>7</cluster-id>
  <redundancy-group>
    <redundancy-group-id>0</redundancy-group-id>
    <device-stats><device-name>node0</device-name><device-priority>200</device-priority>
      <redundancy-group-status>primary</redundancy-group-status><preempt>no</preempt></device-stats>
    <device-stats><device-name>node1</device-name><device-priority>100</device-priority>
      <redundancy-group-status>secondary</redundancy-group-status></device-stats>
  </redundancy-group>
</chassis-cluster-status>
"""


class ClusterTests(unittest.TestCase):
    def test_flat_device_stats_layout(self) -> None:
        got = F.cluster(ElementTree.parse(CLUSTER / "get-chassis-cluster-status.xml").getroot())
        self.assertEqual(got["status"], "ok")
        self.assertEqual(got["mode"], "chassis-cluster")
        self.assertEqual(got["cluster_id"], "1")
        self.assertIsNone(got["local_node"])
        self.assertEqual(
            got["redundancy_groups"],
            [
                {"id": "0", "nodes": [{"name": "node0", "priority": "200", "status": "primary"},
                                      {"name": "node1", "priority": "100", "status": "secondary"}]},
                {"id": "1", "nodes": [{"name": "node0", "priority": "100", "status": "secondary"},
                                      {"name": "node1", "priority": "200", "status": "primary"}]},
            ],
        )

    def test_grouped_device_stats_layout(self) -> None:
        got = F.cluster(xml(GROUPED))
        self.assertEqual(got["cluster_id"], "7")
        self.assertEqual(
            got["redundancy_groups"],
            [{"id": "0", "nodes": [{"name": "node0", "priority": "200", "status": "primary"},
                                   {"name": "node1", "priority": "100", "status": "secondary"}]}],
        )

    def test_wrapped_and_namespaced(self) -> None:
        wrapped = xml(
            '<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><multi-routing-engine-results>'
            "<multi-routing-engine-item><re-name>node0</re-name>" + GROUPED
            + "</multi-routing-engine-item></multi-routing-engine-results></rpc-reply>"
        )
        got = F.cluster(wrapped)
        self.assertEqual((got["mode"], got["cluster_id"]), ("chassis-cluster", "7"))
        self.assertEqual(len(got["redundancy_groups"][0]["nodes"]), 2)

    def test_unrecognised_reply_is_unknown_not_guessed(self) -> None:
        for text in ("<output>error: chassis cluster is not enabled</output>", "<rpc-reply><ok/></rpc-reply>"):
            with self.subTest(text=text):
                got = F.cluster(xml(text))
                self.assertEqual(got["mode"], "unknown")
                self.assertNotIn("redundancy_groups", got)
                self.assertTrue(got["message"])

    def test_fields_before_any_device_name_are_ignored(self) -> None:
        got = F.cluster(xml(
            "<chassis-cluster-status><redundancy-group><redundancy-group-id>0</redundancy-group-id><device-stats>"
            "<device-priority>9</device-priority><device-name>node0</device-name></device-stats></redundancy-group>"
            "</chassis-cluster-status>"
        ))
        self.assertEqual(got["redundancy_groups"][0]["nodes"], [{"name": "node0", "priority": None, "status": None}])

    def test_standalone(self) -> None:
        self.assertEqual(F.standalone(), {"status": "ok", "mode": "standalone"})


class ManagementTests(unittest.TestCase):
    def test_branch_outbound_ssh_client_without_secret(self) -> None:
        cfg = ElementTree.parse(BRANCH / "config.xml").getroot()
        got = F.central_management(cfg)
        self.assertEqual(
            got,
            {"status": "ok",
             "clients": [{"client": "central-mgr", "targets": ["192.0.2.10:7804"], "services": ["netconf"],
                          "inactive": False}],
             "managed": True},
        )
        dumped = json.dumps(got)
        for value in BRANCH_SECRETS:
            with self.subTest(value=value):
                self.assertNotIn(value, dumped)

    def test_secret_never_returned_even_when_shaped_like_a_target(self) -> None:
        cfg = xml(
            "<configuration><system><services><outbound-ssh><client><name>sdc</name>"
            "<secret>TOP-SECRET-VALUE</secret><device-id>DEV-ID-VALUE</device-id>"
            "<keep-alive><retry>3</retry></keep-alive><reconnect-strategy>sticky</reconnect-strategy>"
            "<services><netconf/></services>"
            "<servers><name>192.0.2.20</name><port>443</port></servers><servers><name>sd.example.net</name></servers>"
            "</client><client><secret>NAMELESS-SECRET</secret></client></outbound-ssh></services></system></configuration>"
        )
        got = F.central_management(cfg)
        self.assertEqual(got["clients"], [{"client": "sdc", "targets": ["192.0.2.20:443", "sd.example.net"],
                                           "services": ["netconf"], "inactive": False}])
        dumped = json.dumps(got)
        for value in ("TOP-SECRET-VALUE", "DEV-ID-VALUE", "NAMELESS-SECRET"):
            self.assertNotIn(value, dumped)

    def test_deactivated_client_is_listed_but_does_not_manage(self) -> None:
        """JUNO-10: a deactivated outbound-ssh client (or block above it) is not in effect."""
        client = "<client{a}><name>sdc</name><servers><name>192.0.2.20</name></servers></client>"
        for doc in (
            "<configuration><system><services><outbound-ssh>" + client.format(a=' inactive="inactive"')
            + "</outbound-ssh></services></system></configuration>",
            '<configuration><system><services><outbound-ssh inactive="inactive">' + client.format(a="")
            + "</outbound-ssh></services></system></configuration>",
            '<configuration><system inactive="inactive"><services><outbound-ssh>' + client.format(a="")
            + "</outbound-ssh></services></system></configuration>",
        ):
            with self.subTest(doc=doc[:60]):
                got = F.central_management(xml(doc))
                self.assertFalse(got["managed"])
                self.assertEqual([(c["client"], c["inactive"]) for c in got["clients"]], [("sdc", True)])

    def test_deactivated_mnha_is_not_configured(self) -> None:
        for doc in ('<configuration><chassis><high-availability inactive="inactive"><local-id>1</local-id>'
                    "</high-availability></chassis></configuration>",
                    '<configuration><chassis inactive="inactive"><high-availability><local-id>1</local-id>'
                    "</high-availability></chassis></configuration>"):
            with self.subTest(doc=doc[:50]):
                self.assertFalse(F.mnha_configured(xml(doc)))

    def test_unmanaged(self) -> None:
        self.assertEqual(F.central_management(None), {"status": "ok", "clients": [], "managed": False})
        self.assertFalse(F.central_management(xml("<configuration><system/></configuration>"))["managed"])

    def test_mnha_configured(self) -> None:
        self.assertTrue(F.mnha_configured(xml("<configuration><chassis><high-availability><local-id>1</local-id>"
                                              "</high-availability></chassis></configuration>")))
        self.assertFalse(F.mnha_configured(xml("<configuration><chassis><cluster/></chassis></configuration>")))
        self.assertFalse(F.mnha_configured(None))
        cfg = ElementTree.parse(BRANCH / "config.xml").getroot()
        self.assertFalse(F.mnha_configured(cfg))


if __name__ == "__main__":
    unittest.main()
