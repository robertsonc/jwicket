"""junos/xmlutil.py: local-name lookups that work whether or not namespaces survived the transport."""

from __future__ import annotations

import unittest
from xml.etree import ElementTree

from helpers import xml, xml_with_comments

from jwicket.junos import xmlutil as X

# A release-specific junos namespace URI (it changes per release), as a recorded reply keeps it.
NS_REPLY = """
<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
           xmlns:junos="http://xml.juniper.net/junos/23.4R1/junos">
  <configuration junos:commit-user="admin">
    <security>
      <policies>
        <policy junos:group="corp-baseline">
          <name>p1</name>
          <match><source-address>a</source-address><source-address>b</source-address></match>
        </policy>
      </policies>
    </security>
  </configuration>
</rpc-reply>
"""

# The same data after PyEZ strips namespaces: junos:group becomes a plain group attribute.
PLAIN_REPLY = """
<rpc-reply>
  <configuration commit-user="admin">
    <security>
      <policies>
        <policy group="corp-baseline">
          <name>p1</name>
          <match><source-address>a</source-address><source-address>b</source-address></match>
        </policy>
      </policies>
    </security>
  </configuration>
</rpc-reply>
"""


class LocalNameTests(unittest.TestCase):
    def test_local(self) -> None:
        self.assertEqual(X.local("{urn:x}policy"), "policy")
        self.assertEqual(X.local("policy"), "policy")
        self.assertEqual(X.local(ElementTree.Comment), "")
        self.assertEqual(X.local(None), "")

    def test_same_lookups_with_and_without_namespaces(self) -> None:
        for label, text in (("namespaced", NS_REPLY), ("plain", PLAIN_REPLY)):
            with self.subTest(label):
                root = xml(text)
                cfg = X.kid(root, "configuration")
                self.assertIsNotNone(cfg)
                policy = X.path(cfg, "security", "policies", "policy")
                self.assertIsNotNone(policy)
                self.assertEqual(X.text(policy, "name"), "p1")
                self.assertEqual(X.texts(X.kid(policy, "match"), "source-address"), ["a", "b"])
                self.assertEqual(X.group_of(policy), "corp-baseline")
                self.assertEqual(X.attr(cfg, "commit-user"), "admin")
                self.assertEqual(X.child_tags(policy), ["name", "match"])

    def test_group_attribute_under_any_release_uri(self) -> None:
        for uri in ("http://xml.juniper.net/junos/24.4R2/junos", "http://xml.juniper.net/junos/21.2R3-S4/junos"):
            with self.subTest(uri=uri):
                el = xml(f'<policy xmlns:junos="{uri}" junos:group="g1"><name>x</name></policy>')
                self.assertEqual(X.group_of(el), "g1")

    def test_attr_missing_and_none(self) -> None:
        el = xml("<a b='1'/>")
        self.assertIsNone(X.attr(el, "c"))
        self.assertIsNone(X.attr(None, "b"))
        self.assertEqual(X.attr(el, "b"), "1")

    def test_none_safe(self) -> None:
        self.assertEqual(list(X.kids(None)), [])
        self.assertIsNone(X.kid(None, "a"))
        self.assertIsNone(X.path(None, "a", "b"))
        self.assertIsNone(X.text(None, "a"))
        self.assertEqual(X.texts(None, "a"), [])
        self.assertEqual(X.names(None, "a"), [])
        self.assertFalse(X.is_inactive(None))
        self.assertEqual(X.groups_in(None), [])
        self.assertEqual(X.inherited_parts(None), [])
        self.assertFalse(X.present(None, "a"))


class TextTests(unittest.TestCase):
    def test_text_strips_and_empty_is_none(self) -> None:
        el = xml("<a><b>  v  </b><c>   </c><d/></a>")
        self.assertEqual(X.text(el, "b"), "v")
        self.assertIsNone(X.text(el, "c"))
        self.assertIsNone(X.text(el, "d"))
        self.assertIsNone(X.text(el, "missing"))

    def test_names_keyed_list(self) -> None:
        el = xml("<set><address><name>a</name></address><address><name>b</name></address><address/></set>")
        self.assertEqual(X.names(el, "address"), ["a", "b"])

    def test_texts_skips_empty(self) -> None:
        el = xml("<m><x>1</x><x/><x>2</x></m>")
        self.assertEqual(X.texts(el, "x"), ["1", "2"])

    def test_present(self) -> None:
        el = xml("<then><permit/></then>")
        self.assertTrue(X.present(el, "permit"))
        self.assertFalse(X.present(el, "deny"))


class CommentTests(unittest.TestCase):
    TEXT = """
    <policy group="g">
      <!-- a comment the operator wrote: annotate "..." -->
      <name>p</name>
      <!-- another -->
      <then><!-- inside --><permit/></then>
    </policy>
    """

    def test_comments_are_ignored_everywhere(self) -> None:
        el = xml_with_comments(self.TEXT)
        # Prove the parser really kept the comments.
        self.assertTrue(any(child.tag is ElementTree.Comment for child in el))
        self.assertEqual(X.child_tags(el), ["name", "then"])
        self.assertEqual([X.local(c.tag) for c in X.kids(el)], ["name", "then"])
        self.assertEqual(X.text(el, "name"), "p")
        self.assertTrue(X.present(X.kid(el, "then"), "permit"))
        self.assertEqual(X.child_tags(X.kid(el, "then")), ["permit"])
        self.assertEqual(X.groups_in(el), ["g"])
        self.assertEqual(X.inherited_parts(el), [])


class InactiveTests(unittest.TestCase):
    def test_inactive_plain_and_namespaced(self) -> None:
        self.assertTrue(X.is_inactive(xml('<policy inactive="inactive"/>')))
        self.assertTrue(X.is_inactive(xml('<policy xmlns:j="urn:j" j:inactive="inactive"/>')))
        self.assertFalse(X.is_inactive(xml("<policy/>")))
        self.assertFalse(X.is_inactive(xml('<policy inactive="false"/>')))


class ProvenanceTests(unittest.TestCase):
    def test_fully_inherited_node_has_no_inherited_parts(self) -> None:
        el = xml(
            '<policy group="g"><name group="g">p</name><match group="g"><application group="g">any</application>'
            '</match></policy>'
        )
        self.assertEqual(X.group_of(el), "g")
        self.assertEqual(X.inherited_parts(el), [])
        self.assertEqual(X.groups_in(el), ["g"])

    def test_partial_inheritance_names_the_inherited_child(self) -> None:
        el = xml(
            "<policy><name>p</name><match><application>any</application></match>"
            '<then><permit/><log group="logging"><session-close group="logging"/></log></then></policy>'
        )
        self.assertIsNone(X.group_of(el))
        self.assertEqual(X.inherited_parts(el), ["then"])
        self.assertEqual(X.groups_in(el), ["logging"])

    def test_child_from_a_different_group_than_the_node(self) -> None:
        el = xml('<policy group="g1"><name group="g1">p</name><then group="g2"><deny group="g2"/></then></policy>')
        self.assertEqual(X.inherited_parts(el), ["then"])
        self.assertEqual(X.groups_in(el), ["g1", "g2"])

    def test_inherited_parts_deduplicated_and_ordered(self) -> None:
        el = xml(
            '<match><source-address group="a">x</source-address><source-address group="a">y</source-address>'
            '<application group="b">z</application><destination-address>any</destination-address></match>'
        )
        self.assertEqual(X.inherited_parts(el), ["source-address", "application"])
        self.assertEqual(X.groups_in(el), ["a", "b"])

    def test_namespaced_group_attribute_drives_provenance(self) -> None:
        el = xml(
            '<policy xmlns:junos="http://xml.juniper.net/junos/24.4R2/junos"><name>p</name>'
            '<then junos:group="g"><permit junos:group="g"/></then></policy>'
        )
        self.assertEqual(X.inherited_parts(el), ["then"])
        self.assertEqual(X.groups_in(el), ["g"])


if __name__ == "__main__":
    unittest.main()
