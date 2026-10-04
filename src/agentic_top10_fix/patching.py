"""Applying search/replace edits and rendering diffs."""
from __future__ import annotations

import difflib
from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class Edit:
    find: str
    replace: str
    rule_id: str = ""


class EditError(ValueError):
    pass


def apply_edits(text: str, edits: List[Edit]) -> str:
    """Apply edits in order. Each `find` must match exactly one place in the current text."""
    crlf = "\r\n" in text
    for i, edit in enumerate(edits, start=1):
        find, replace = edit.find, edit.replace
        if crlf and "\r\n" not in find:
            find, replace = find.replace("\n", "\r\n"), replace.replace("\n", "\r\n")
        if not find:
            raise EditError(f"edit {i}: empty find text")
        count = text.count(find)
        if count == 0:
            raise EditError(f"edit {i}: find text not found in the file (it must be copied exactly, including "
                            f"indentation): {find[:120]!r}")
        if count > 1:
            raise EditError(f"edit {i}: find text matches {count} places; include more surrounding lines so it "
                            f"is unique: {find[:120]!r}")
        text = text.replace(find, replace, 1)
    return text


def unified_diff(path: str, before: str, after: str) -> str:
    """A git-applicable unified diff (including the no-newline-at-end marker)."""
    out = []
    for line in difflib.unified_diff(before.splitlines(keepends=True), after.splitlines(keepends=True),
                                     fromfile=f"a/{path}", tofile=f"b/{path}"):
        out.append(line if line.endswith("\n") else line + "\n\\ No newline at end of file\n")
    return "".join(out)
