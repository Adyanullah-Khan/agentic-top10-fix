"""Checks a candidate file before it is kept: syntax, attempts to game the scanner, and a re-scan.

The re-scan runs the scanner's own analyzers on the candidate text in memory, so a patch only counts as a fix
if the scanner agrees.
"""
from __future__ import annotations

import ast
import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from agentic_top10.analyzers import text_checks
from agentic_top10.configfiles import load_jsonc, load_toml
from agentic_top10.models import FileContext, Finding, ProjectState
from agentic_top10.scanner import ANALYZERS, _postprocess, classify, name_is_lock
from agentic_top10.settings import Settings

import yaml

PROJECT_LEVEL_RULES = {"ATS-ASI10-04"}  # produced from facts across files, re-checked separately below
SUPPRESSION_RE = re.compile(r"agentic-top10:\s*ignore", re.I)


@dataclass
class Rescan:
    findings: List[Finding]
    unlogged_tools: List[str] = field(default_factory=list)

    def counts(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for f in self.findings:
            out[f.rule_id] = out.get(f.rule_id, 0) + 1
        if self.unlogged_tools:
            out["ATS-ASI10-04"] = 1
        return out


def rescan(rel: str, text: str, root: Path) -> Rescan:
    project = ProjectState(root=root, is_agent_project=True)  # the original scan already established this
    ctx = FileContext(root / rel, rel, text, classify(rel, text), project)
    if not name_is_lock(rel):
        text_checks.analyze(ctx)
    analyzer = ANALYZERS.get(ctx.kind)
    if analyzer:
        analyzer(ctx)
    findings = _postprocess({rel: ctx}, Settings(fail_on=None, include_tests=True))
    return Rescan(findings, [t.name for t in project.tools if not t.logs])


def syntax_error(rel: str, text: str) -> Optional[str]:
    suffix = Path(rel).suffix.lower()
    try:
        if suffix == ".py":
            ast.parse(text)
        elif suffix in (".json", ".jsonc"):
            load_jsonc(text)
        elif suffix in (".yml", ".yaml"):
            yaml.safe_load(text)
        elif suffix == ".toml" and load_toml(text) is None and text.strip():
            return "invalid TOML"
        elif suffix in (".js", ".mjs", ".cjs") and shutil.which("node"):
            proc = subprocess.run(["node", "--check", "-"], input=text, capture_output=True, text=True, timeout=30,
                                  check=False)
            if proc.returncode != 0:
                return proc.stderr.strip().splitlines()[0] if proc.stderr.strip() else "node --check failed"
    except SyntaxError as exc:
        return f"SyntaxError: {exc.msg} (line {exc.lineno})"
    except (ValueError, yaml.YAMLError) as exc:
        return f"{type(exc).__name__}: {str(exc).splitlines()[0]}"
    except (OSError, subprocess.SubprocessError):
        return None
    return None


def gaming_problem(original: str, candidate: str) -> Optional[str]:
    """Reject patches that silence the scanner or gut the file instead of fixing it."""
    if len(SUPPRESSION_RE.findall(candidate)) > len(SUPPRESSION_RE.findall(original)):
        return "the patch adds an agentic-top10 suppression comment instead of fixing the code"
    old_lines, new_lines = original.splitlines(), candidate.splitlines()
    removed = len(old_lines) - len(new_lines)
    if removed > max(30, len(old_lines) // 2):
        return f"the patch removes {removed} of {len(old_lines)} lines; that looks like deleting functionality"
    return None


def jsonable(findings: List[Finding]) -> str:
    return json.dumps([{"rule_id": f.rule_id, "line": f.line, "message": f.message} for f in findings])
