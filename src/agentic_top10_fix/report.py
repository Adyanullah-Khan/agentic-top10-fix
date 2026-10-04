"""Summaries of a remediation run: terminal text, JSON and a Markdown pull-request body."""
from __future__ import annotations

import json
from typing import List, Optional

from agentic_top10.rules import RULES

from . import __version__
from .engine import FileOutcome
from .llm import Usage
from .patching import unified_diff


def _title(rule_id: str) -> str:
    rule = RULES.get(rule_id)
    return rule.title if rule else rule_id


def totals(outcomes: List[FileOutcome]) -> dict:
    return {
        "files_changed": sum(1 for o in outcomes if o.changed),
        "fixed": sum(len(o.fixed) for o in outcomes),
        "fixed_by_codemod": sum(1 for o in outcomes for _, m in o.fixed if m == "codemod"),
        "fixed_by_llm": sum(1 for o in outcomes for _, m in o.fixed if m == "llm"),
        "remaining": sum(len(o.remaining) for o in outcomes),
        "manual": sum(len(o.manual) for o in outcomes),
        "errors": sum(1 for o in outcomes if o.error),
    }


def to_text(outcomes: List[FileOutcome], usage: Usage, show_diff: bool = True) -> str:
    out = []
    for o in outcomes:
        if o.error:
            out.append(f"! {o.path}: {o.error}")
            continue
        if show_diff and o.changed:
            out.append(unified_diff(o.path, o.original, o.patched).rstrip("\n"))
        for issue, method in o.fixed:
            out.append(f"  fixed    {issue.rule_id} {o.path}:{issue.line} ({method})")
        for issue, reason in o.remaining:
            out.append(f"  open     {issue.rule_id} {o.path}:{issue.line}: {reason}")
        for issue, guidance in o.manual:
            out.append(f"  manual   {issue.rule_id} {o.path}:{issue.line}: {guidance}")
    t = totals(outcomes)
    out.append("")
    out.append(f"Fixed {t['fixed']} finding(s) in {t['files_changed']} file(s) ({t['fixed_by_codemod']} by codemod, "
               f"{t['fixed_by_llm']} by LLM); {t['remaining']} still open; {t['manual']} need manual work.")
    if usage.calls:
        out.append(f"LLM: {usage.calls} call(s), {usage.input_tokens} input / {usage.output_tokens} output tokens.")
    return "\n".join(out)


def to_dict(outcomes: List[FileOutcome], usage: Usage, provider: Optional[str], model: Optional[str]) -> dict:
    def issue(i):
        return {"rule_id": i.rule_id, "line": i.line, "severity": i.severity.label, "message": i.message}

    return {
        "tool": "agentic-top10-fix",
        "version": __version__,
        "provider": provider,
        "model": model,
        "summary": totals(outcomes),
        "usage": vars(usage),
        "files": [{
            "path": o.path,
            "changed": o.changed,
            "error": o.error,
            "fixed": [dict(issue(i), method=m) for i, m in o.fixed],
            "remaining": [dict(issue(i), reason=r) for i, r in o.remaining],
            "manual": [dict(issue(i), guidance=g) for i, g in o.manual],
            "notes": o.notes,
            "diff": unified_diff(o.path, o.original, o.patched) if o.changed else "",
        } for o in outcomes],
    }


def to_json(outcomes, usage, provider, model) -> str:
    return json.dumps(to_dict(outcomes, usage, provider, model), indent=2)


def _md(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def to_markdown(outcomes: List[FileOutcome], usage: Usage, provider: Optional[str], model: Optional[str]) -> str:
    t = totals(outcomes)
    lines = ["## Agentic Top 10 Fix", "",
             f"Fixed **{t['fixed']}** finding(s) in **{t['files_changed']}** file(s) "
             f"({t['fixed_by_codemod']} by deterministic codemods, {t['fixed_by_llm']} by "
             f"{model or 'LLM'}). Every change was re-scanned with agentic-top10-scan and syntax-checked before it "
             "was kept.", ""]
    if t["fixed"]:
        lines += ["### Fixed", "", "| Rule | Location | How |", "|---|---|---|"]
        for o in outcomes:
            for i, m in o.fixed:
                lines.append(f"| `{i.rule_id}` {_md(_title(i.rule_id))} | `{o.path}:{i.line}` | {m} |")
        lines.append("")
    notes = [(o.path, n) for o in outcomes for n in o.notes if n]
    if notes:
        lines += ["### Notes from the fixer", ""] + [f"- `{p}`: {_md(n)}" for p, n in notes] + [""]
    if t["remaining"]:
        lines += ["### Still open", "", "| Rule | Location | Why |", "|---|---|---|"]
        for o in outcomes:
            for i, r in o.remaining:
                lines.append(f"| `{i.rule_id}` | `{o.path}:{i.line}` | {_md(r)} |")
        lines.append("")
    if t["manual"]:
        lines += ["### Needs a human decision", "", "| Rule | Location | What to do |", "|---|---|---|"]
        for o in outcomes:
            for i, g in o.manual:
                lines.append(f"| `{i.rule_id}` | `{o.path}:{i.line}` | {_md(g)} |")
        lines.append("")
    errors = [o for o in outcomes if o.error]
    if errors:
        lines += ["### Skipped files", ""] + [f"- `{o.path}`: {_md(o.error)}" for o in errors] + [""]
    lines += ["> **Review before merging.** Automated fixes can change behaviour: check new constants (allowlists, "
              "root directories, limits) and run your tests. The scanner only proves the reported pattern is gone, "
              "not that the code is correct.", ""]
    if usage.calls:
        lines.append(f"<sub>{usage.calls} LLM call(s) via {provider}, {usage.input_tokens} input / "
                     f"{usage.output_tokens} output tokens. agentic-top10-fix {__version__}.</sub>")
    return "\n".join(lines) + "\n"
