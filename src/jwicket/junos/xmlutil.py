"""Namespace-agnostic helpers for Junos XML replies.

PyEZ normally strips namespaces from replies, which turns ``junos:group`` into ``group``; recorded
fixtures and other transports may keep them. Every lookup here therefore matches on local names, for
elements and for attributes. Attributes in Junos configuration XML are metadata only (inactive,
protect, junos:group, junos:changed...), so matching the local name ``group`` cannot collide with
configuration data.

The element type is whatever ElementTree-compatible implementation produced it (lxml on the device,
xml.etree in tests); only ``.tag``, ``.attrib``, ``.text`` and iteration are used.
"""

from __future__ import annotations

from typing import Any, Iterator, List, Optional

Element = Any  # lxml.etree._Element or xml.etree.ElementTree.Element


def local(tag: Any) -> str:
    if not isinstance(tag, str):  # comments and processing instructions
        return ""
    return tag.rsplit("}", 1)[-1]


def kids(node: Optional[Element], name: Optional[str] = None) -> Iterator[Element]:
    if node is None:
        return
    for child in node:
        tag = local(child.tag)
        if tag and (name is None or tag == name):
            yield child


def kid(node: Optional[Element], name: str) -> Optional[Element]:
    return next(kids(node, name), None)


def path(node: Optional[Element], *names: str) -> Optional[Element]:
    for name in names:
        node = kid(node, name)
        if node is None:
            return None
    return node


def text_of(node: Optional[Element]) -> Optional[str]:
    if node is None or node.text is None:
        return None
    value = str(node.text).strip()
    return value or None


def text(node: Optional[Element], name: str) -> Optional[str]:
    return text_of(kid(node, name))


def texts(node: Optional[Element], name: str) -> List[str]:
    """A Junos leaf-list: repeated ``<name>value</name>`` elements."""
    out = []
    for child in kids(node, name):
        value = text_of(child)
        if value is not None:
            out.append(value)
    return out


def names(node: Optional[Element], name: str) -> List[str]:
    """A Junos keyed list: repeated ``<name><name>key</name>...</name>`` elements."""
    out = []
    for child in kids(node, name):
        key = text(child, "name")
        if key is not None:
            out.append(key)
    return out


def attr(node: Optional[Element], name: str) -> Optional[str]:
    if node is None:
        return None
    for key, value in node.attrib.items():
        if local(key) == name:
            return str(value)
    return None


def is_inactive(node: Optional[Element]) -> bool:
    return attr(node, "inactive") == "inactive"


def group_of(node: Optional[Element]) -> Optional[str]:
    """The configuration group this element was inherited from, when read with groups="groups"."""
    return attr(node, "group")


def inherited_parts(node: Optional[Element]) -> List[str]:
    """Child element names (one level down) that came from a group different from the node's own."""
    own = group_of(node)
    seen: List[str] = []
    for child in kids(node):
        grp = group_of(child)
        if grp is None:
            for grandchild in child.iter():
                grp = group_of(grandchild)
                if grp is not None:
                    break
        if grp is not None and grp != own:
            tag = local(child.tag)
            if tag not in seen:
                seen.append(tag)
    return seen


def groups_in(node: Optional[Element]) -> List[str]:
    """Every distinct group that contributed anything to this subtree, in first-seen order."""
    seen: List[str] = []
    if node is None:
        return seen
    for element in node.iter():
        grp = group_of(element)
        if grp is not None and grp not in seen:
            seen.append(grp)
    return seen


def present(node: Optional[Element], name: str) -> bool:
    return kid(node, name) is not None


def child_tags(node: Optional[Element]) -> List[str]:
    return [local(child.tag) for child in kids(node)]
