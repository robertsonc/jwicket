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

from typing import Any, Dict, Iterator, List, Optional, Tuple

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


# --- deactivated statements -----------------------------------------------------------------------
# A deactivated statement stays in the configuration but is not in effect ("deactivated statements
# ... do not take effect when you issue the commit command", Junos CLI user guide, modifying the
# configuration). These helpers separate what is in effect from what is only written down.


def active_kids(node: Optional[Element], name: Optional[str] = None) -> Iterator[Element]:
    """Children that are not deactivated (their own ``inactive`` attribute only)."""
    for child in kids(node, name):
        if not is_inactive(child):
            yield child


def active_kid(node: Optional[Element], name: str) -> Optional[Element]:
    return next(active_kids(node, name), None)


def active_path(node: Optional[Element], *names: str) -> Optional[Element]:
    """Like :func:`path`, but None when the node or any step on the way is deactivated."""
    if node is None or is_inactive(node):
        return None
    for name in names:
        node = active_kid(node, name)
        if node is None:
            return None
    return node


def deactivated_parts(node: Optional[Element], skip: Tuple[str, ...] = ("name",)) -> List[str]:
    """Deactivated statements directly under ``node``, written as in the CLI: ``<tag> <value>`` for a
    leaf (``screen trust-screen``, ``destination-port 2121``), ``<tag> <name>`` for a keyed entry, else
    ``<tag>``. Children named in ``skip`` (keys, members reported elsewhere) are left out."""
    out: List[str] = []
    for child in kids(node):
        tag = local(child.tag)
        if tag == COMMENT or tag in skip or not is_inactive(child):
            continue
        value = text(child, "name") if len(child) else text_of(child)
        out.append(f"{tag} {value}" if value else tag)
    return out


def split_names(node: Optional[Element], name: str) -> Tuple[List[str], List[str]]:
    """A keyed list split into (active keys, deactivated keys)."""
    active: List[str] = []
    inactive: List[str] = []
    for child in kids(node, name):
        key = text(child, "name")
        if key is not None:
            (inactive if is_inactive(child) else active).append(key)
    return active, inactive


# --- configuration comments -----------------------------------------------------------------------
# ``annotate`` writes a comment that Junos XML returns as <junos:comment> on the line before the
# statement it annotates (Junos XML protocol guide, configuration mapping to JSON). Namespaces are
# matched by local name, so it is the element named "comment". It is not configuration: it is never
# reported as an unmodelled setting, and it is attached to the statement that follows it.

COMMENT = "comment"


def statement_tags(node: Optional[Element]) -> List[str]:
    """Child element names that are configuration statements (comments left out)."""
    return [tag for tag in child_tags(node) if tag != COMMENT]


def comments_before(node: Optional[Element]) -> Dict[int, str]:
    """For each child of ``node`` that follows one or more comments: id(child) -> their text."""
    found: Dict[int, str] = {}
    pending: List[str] = []
    for child in kids(node):
        if local(child.tag) == COMMENT:
            value = text_of(child)
            if value is not None:
                pending.append(value)
            continue
        if pending:
            found[id(child)] = "\n".join(pending)
            pending = []
    return found


def trailing_comment(node: Optional[Element]) -> Optional[str]:
    """Comments after the last statement in ``node`` (they annotate nothing that follows), joined by a
    line break; None when there are none."""
    pending: List[str] = []
    for child in kids(node):
        if local(child.tag) == COMMENT:
            value = text_of(child)
            if value is not None:
                pending.append(value)
        else:
            pending = []
    return "\n".join(pending) or None


def inner_comments(node: Optional[Element]) -> List[Dict[str, Optional[str]]]:
    """Every comment inside ``node`` with the statement it annotates (``before``: that statement's
    name, or None when it ends its block)."""
    out: List[Dict[str, Optional[str]]] = []
    if node is None:
        return out
    for parent in node.iter():
        children = list(kids(parent))
        for index, child in enumerate(children):
            if local(child.tag) != COMMENT:
                continue
            value = text_of(child)
            if value is None:
                continue
            following = next((local(c.tag) for c in children[index + 1:] if local(c.tag) != COMMENT), None)
            out.append({"before": following, "text": value})
    return out
