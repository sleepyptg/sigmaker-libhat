"""Validation helpers for IDA form strings.

IDA's C++ form parser is unforgiving and reports failures with an opaque
``form: error at ...`` warning that dumps the remainder of the form, without
pointing at the offending item.  The helpers here catch the mistakes that are
easy to make when editing a form by hand:

* a missing ``>`` that closes a radio/checkbox item,
* ``::`` inside an item hint or label, which IDA parses as a field separator
  and therefore rejects the whole form,
* a radio/checkbox group placeholder that shares its name with one of its own
  items, which makes the group invisible to the C++ side,
* a malformed tab line (``<=:label``).  A tab line closes the tab whose fields
  are listed *above* it, so it has to end with ``>`` like every other item.
"""

from __future__ import annotations

import re
import typing

__all__ = [
    "validate_form_text",
    "validate_group_names",
]

_ITEM_RE = re.compile(r"<([^<>]*)>")
_TYPE_SUFFIX_RE = re.compile(r":\{[^}]*\}\s*$")
_PLACEHOLDER_RE = re.compile(r"\{([A-Za-z_][A-Za-z_0-9]*)\}")
_LINE_ENDING_PLACEHOLDER_RE = re.compile(r"\{([A-Za-z_][A-Za-z_0-9]*)\}\s*$")
_TAB_MARKER = "<=:"
_STANDALONE_CONTROLS = frozenset({"FormChangeCb"})


def validate_form_text(form_text: str) -> typing.List[str]:
    """Return a list of problems found in an IDA form string.

    An empty list means the text follows the conventions IDA's form parser
    accepts.
    """

    problems: typing.List[str] = []
    for lineno, line in enumerate(form_text.splitlines(), 1):
        if _TAB_MARKER in line and not line.rstrip().endswith(">"):
            problems.append(
                f"line {lineno}: tab line must end with '>' - it closes the tab "
                f"whose fields are listed above it: {line.strip()!r}"
            )
        elif line.count("<") > line.count(">"):
            problems.append(
                f"line {lineno}: unbalanced '<'/'>' - an item is missing its "
                f"closing '>': {line.strip()!r}"
            )
        trailing = _LINE_ENDING_PLACEHOLDER_RE.search(line)
        if trailing and trailing.group(1) not in _STANDALONE_CONTROLS:
            problems.append(
                f"line {lineno}: control {trailing.group(1)!r} ends the line "
                f"without a closing '>' - IDA drops the group it belongs to: "
                f"{line.strip()!r}"
            )
        for match in _ITEM_RE.finditer(line):
            spec = _TYPE_SUFFIX_RE.sub("", match.group(1))
            if "::" in spec:
                problems.append(
                    f"line {lineno}: '::' inside an item hint or label breaks "
                    f"IDA's form parser: {spec!r}"
                )
    return problems


def validate_group_names(
    controls: typing.Mapping[str, typing.Any],
) -> typing.List[str]:
    """Return problems with group controls whose items share the group name.

    ``idaapi.Form`` resolves a placeholder to a single control.  When a group
    and one of its items use the same name the item shadows the group, so the
    group never reaches the C++ form and its value cannot be read back.
    """

    problems: typing.List[str] = []
    for name, control in controls.items():
        children = getattr(control, "children_names", None)
        if not children:
            continue
        for child in children:
            if child == name:
                problems.append(
                    f"group {name!r} shares its name with one of its items; "
                    f"rename the item so the group stays addressable"
                )
    return problems
