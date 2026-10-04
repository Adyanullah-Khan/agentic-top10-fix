"""Scanner findings: loaded from an agentic-top10-scan JSON/SARIF report, or produced by running the scanner."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List

from agentic_top10.models import Severity
from agentic_top10.scanner import scan
from agentic_top10.settings import Settings


@dataclass(frozen=True)
class Issue:
    rule_id: str
    path: str
    line: int
    severity: Severity
    message: str
    evidence: str = ""

    def label(self) -> str:
        return f"{self.rule_id} {self.path}:{self.line}"


class ReportError(ValueError):
    pass


def load_report(report_path: Path) -> List[Issue]:
    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ReportError(f"cannot read report {report_path}: {exc}") from exc
    if isinstance(data, dict) and isinstance(data.get("findings"), list):
        return [Issue(f["rule_id"], f["path"], int(f["line"]), Severity.parse(f["severity"]), f.get("message", ""),
                      f.get("evidence", "")) for f in data["findings"]]
    if isinstance(data, dict) and isinstance(data.get("runs"), list):
        issues = []
        for run in data["runs"]:
            for res in run.get("results", []):
                loc = res["locations"][0]["physicalLocation"]
                props = res.get("properties", {})
                issues.append(Issue(res["ruleId"], loc["artifactLocation"]["uri"], int(loc["region"]["startLine"]),
                                    Severity.parse(props.get("severity", "medium")),
                                    res.get("message", {}).get("text", "")))
        return issues
    raise ReportError(f"{report_path} is not an agentic-top10-scan JSON or SARIF report")


def scan_issues(target: Path, include_tests: bool = False, exclude: List[str] = ()) -> List[Issue]:
    settings = Settings(fail_on=None, include_tests=include_tests, exclude=list(exclude))
    result = scan(target, settings, base=target if target.is_dir() else target.parent)
    return [Issue(f.rule_id, f.path, f.line, f.severity, f.message, f.evidence) for f in result.findings]
