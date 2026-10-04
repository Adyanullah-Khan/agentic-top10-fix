"""Per-file remediation loop: codemods first, then LLM rounds, and a re-scan gate on every change."""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

from agentic_top10.models import Finding, Severity
from agentic_top10.scanner import classify

from . import verify
from .codemods import CODEMODS, ONLINE_RULES, CodemodContext, ensure_import_os
from .issues import Issue
from .llm import LLMError, Usage, build_user_prompt, redact_secrets
from .patching import EditError, apply_edits
from .playbooks import playbook_for


@dataclass
class Options:
    min_severity: Severity = Severity.LOW
    rules: Optional[Set[str]] = None
    skip_rules: Set[str] = field(default_factory=set)
    max_rounds: int = 3
    max_llm_calls: int = 30
    max_file_chars: int = 200_000
    include_workflows: bool = True


@dataclass
class FileOutcome:
    path: str
    original: str
    patched: str
    fixed: List[Tuple[Issue, str]] = field(default_factory=list)       # (issue, "codemod" | "llm")
    remaining: List[Tuple[Issue, str]] = field(default_factory=list)   # (issue, reason)
    manual: List[Tuple[Issue, str]] = field(default_factory=list)      # (issue, guidance)
    notes: List[str] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def changed(self) -> bool:
        return self.patched != self.original


def _norm(text: str) -> str:
    return " ".join(text.split())


def _as_issue(f: Finding) -> Issue:
    return Issue(f.rule_id, f.path, f.line, f.severity, f.message, f.evidence)


def split_fixed(before: List[Issue], after: List[Issue]) -> Tuple[List[Issue], List[Issue]]:
    """Which of `before` are gone in `after` (counted per rule, matched by evidence where possible)."""
    after_by_rule: Dict[str, List[Issue]] = defaultdict(list)
    for a in after:
        after_by_rule[a.rule_id].append(a)
    fixed, remaining = [], []
    before_by_rule: Dict[str, List[Issue]] = defaultdict(list)
    for b in before:
        before_by_rule[b.rule_id].append(b)
    for rule, items in before_by_rule.items():
        pool = list(after_by_rule.get(rule, []))
        keep = []
        for item in items:
            match = next((a for a in pool if _norm(a.evidence) == _norm(item.evidence) and item.evidence), None)
            if match is not None:
                pool.remove(match)
                keep.append(item)
        rest = [i for i in items if i not in keep]
        extra = max(0, len(after_by_rule.get(rule, [])) - len(keep))
        keep += rest[:extra]
        remaining += keep
        fixed += rest[extra:]
    return fixed, remaining


class Engine:
    def __init__(self, root: Path, provider=None, options: Optional[Options] = None,
                 codemod_ctx: Optional[CodemodContext] = None):
        self.root = root.resolve()
        self.provider = provider
        self.options = options or Options()
        self.codemod_ctx = codemod_ctx or CodemodContext()
        self.usage = Usage()

    # ---- selection
    def selected(self, issue: Issue) -> bool:
        o = self.options
        if issue.severity < o.min_severity or issue.rule_id in o.skip_rules:
            return False
        if o.rules is not None and issue.rule_id not in o.rules:
            return False
        if not o.include_workflows and issue.path.startswith(".github/workflows/"):
            return False
        return True

    def _resolve(self, rel: str) -> Optional[Path]:
        candidate = self.root / rel
        if candidate.is_symlink():
            return None
        path = candidate.resolve()
        try:
            path.relative_to(self.root)
        except ValueError:
            return None  # a report path outside the project (e.g. "../../etc/passwd") is never touched
        return path if path.is_file() else None

    def run(self, issues: Iterable[Issue]) -> List[FileOutcome]:
        by_file: Dict[str, List[Issue]] = defaultdict(list)
        for issue in issues:
            if self.selected(issue):
                by_file[issue.path].append(issue)
        return [self.fix_file(path, items) for path, items in sorted(by_file.items())]

    # ---- per file
    def _targets(self, rel: str, text: str, rules: Set[str], report_issues: List[Issue]) -> List[Issue]:
        scan = verify.rescan(rel, text, self.root)
        found = [_as_issue(f) for f in scan.findings if f.rule_id in rules]
        if "ATS-ASI10-04" in rules and scan.unlogged_tools:
            line = next((i.line for i in report_issues if i.rule_id == "ATS-ASI10-04"), 1)
            found.append(Issue("ATS-ASI10-04", rel, line, Severity.LOW,
                               f"Agent tools without audit logging: {', '.join(sorted(set(scan.unlogged_tools)))}."))
        return found

    def fix_file(self, rel: str, report_issues: List[Issue]) -> FileOutcome:
        path = self._resolve(rel)
        if path is None:
            return FileOutcome(rel, "", "", error="file not found inside the project (or is a symlink)")
        try:
            original = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            return FileOutcome(rel, "", "", error=f"cannot read file: {exc}")
        outcome = FileOutcome(rel, original, original)
        rules = {i.rule_id for i in report_issues}
        targets = self._targets(rel, original, rules, report_issues)
        if not targets:
            outcome.notes.append("The findings from the report are no longer present in this file.")
            return outcome

        # 1. codemods
        text, llm_rules, needs_online = original, set(), set()
        self.codemod_ctx.needs_import_os = False
        declaration = classify(rel, original) in ("manifest", "a2a")
        for issue in sorted(targets, key=lambda i: -i.line):
            mode = playbook_for(issue.rule_id).mode
            if mode == "llm" and declaration:
                continue  # editing a declaration without changing the system would only quiet the scanner
            if mode == "llm":
                llm_rules.add(issue.rule_id)
                continue
            if mode != "codemod":
                continue
            new = CODEMODS[issue.rule_id](text, issue, self.codemod_ctx)
            if new is not None:
                text = new
            elif issue.rule_id in ONLINE_RULES and not self.codemod_ctx.online:
                needs_online.add(issue.rule_id)
            elif issue.rule_id not in ONLINE_RULES and issue.rule_id != "ATS-ASI03-01":
                llm_rules.add(issue.rule_id)  # shape the codemod doesn't handle: let the LLM try
        if self.codemod_ctx.needs_import_os:
            text = ensure_import_os(text)
        after_codemods = targets
        if text != original:
            problem = verify.syntax_error(rel, text)
            scan = self._targets(rel, text, rules, report_issues)
            regressions = self._regressions(rel, original, text)
            if problem or regressions:
                outcome.notes.append(f"Discarded deterministic fixes: {problem or regressions}")
                text = original
                llm_rules |= {i.rule_id for i in targets if playbook_for(i.rule_id).mode == "codemod"}
            else:
                after_codemods = scan
        fixed_by_codemod, _ = split_fixed(targets, after_codemods)

        # 2. LLM rounds
        current, current_issues = text, after_codemods
        reasons: Dict[str, str] = {}
        mitigated: Dict[str, str] = {}
        feedback = None
        rounds = 0
        pending = [i for i in current_issues if i.rule_id in llm_rules]
        while pending and self.provider is not None and rounds < self.options.max_rounds:
            if self.usage.calls >= self.options.max_llm_calls:
                reasons.setdefault("*", f"LLM call budget ({self.options.max_llm_calls}) used up")
                break
            if len(current) > self.options.max_file_chars:
                reasons.setdefault("*", f"file is larger than --max-file-chars ({self.options.max_file_chars})")
                break
            redaction = redact_secrets(current)
            prompt = build_user_prompt(rel, redaction.text, pending, feedback)
            rounds += 1
            self.usage.calls += 1
            try:
                proposal = self.provider.propose(prompt, redaction)
            except LLMError as exc:
                reasons.setdefault("*", str(exc))
                break
            self.usage.input_tokens += proposal.input_tokens
            self.usage.output_tokens += proposal.output_tokens
            for u in proposal.unfixable:
                reasons[str(u.get("rule_id"))] = str(u.get("reason", "model could not fix it safely"))
            if not proposal.edits:
                break
            try:
                candidate = apply_edits(current, proposal.edits)
            except EditError as exc:
                feedback = f"Your edits could not be applied: {exc}"
                continue
            problem = verify.syntax_error(rel, candidate) or verify.gaming_problem(original, candidate)
            if problem:
                feedback = f"Your edits were rejected: {problem}."
                continue
            regressions = self._regressions(rel, current, candidate)
            if regressions:
                feedback = f"Your edits were rejected because they introduced new findings: {regressions}"
                continue
            new_targets = self._targets(rel, candidate, rules, report_issues)
            gone, _ = split_fixed(current_issues, new_targets)
            lowered = self._lowered(current_issues, new_targets)
            if not gone and not lowered:
                feedback = "Your edits did not remove any finding; the scanner still reports all of them."
                continue
            for rule_id, change in lowered.items():
                mitigated.setdefault(rule_id, change)
            current, current_issues = candidate, new_targets
            if proposal.summary:
                outcome.notes.append(proposal.summary)
            # A finding that is still reported at lower severity is a capability, not a bug: stop retrying it.
            pending = [i for i in current_issues if i.rule_id in llm_rules and i.rule_id not in mitigated]
            if pending:
                feedback = "Your previous edits were kept. The re-scan still reports the findings listed above."

        # 3. outcome
        outcome.patched = current
        fixed, remaining = split_fixed(targets, current_issues)
        outcome.fixed = [(i, "codemod" if i in fixed_by_codemod else "llm") for i in fixed]
        for issue in remaining:
            pb = playbook_for(issue.rule_id)
            if pb.mode == "manual":
                outcome.manual.append((issue, pb.guidance))
            elif declaration and issue.rule_id not in llm_rules:
                outcome.manual.append((issue, "This file declares how the agent system behaves. Change the running "
                                              "system first, then update the declaration to match."))
            elif issue.rule_id in needs_online:
                outcome.remaining.append((issue, "re-run with --online to look up the version/commit to pin"))
            elif issue.rule_id == "ATS-ASI03-01" and issue.rule_id not in llm_rules:
                outcome.manual.append((issue, "Move this credential to a secret store and rotate it."))
            elif issue.rule_id in mitigated:
                outcome.remaining.append((issue, f"mitigated ({mitigated[issue.rule_id]}); the scanner still flags "
                                                 "the capability, so a human should accept or remove it"))
            elif self.provider is None:
                outcome.remaining.append((issue, "needs the LLM step (no provider configured)"))
            else:
                outcome.remaining.append((issue, reasons.get(issue.rule_id) or reasons.get("*") or
                                          f"not fixed after {rounds} LLM round(s)"))
        return outcome

    @staticmethod
    def _lowered(before: List[Issue], after: List[Issue]) -> Dict[str, str]:
        """Rules whose findings remain but at a lower maximum severity, e.g. {"ATS-ASI02-01": "critical -> medium"}."""
        out = {}
        for rule_id in {i.rule_id for i in after}:
            old = [i.severity for i in before if i.rule_id == rule_id]
            new = [i.severity for i in after if i.rule_id == rule_id]
            if old and len(new) <= len(old) and max(new) < max(old):
                out[rule_id] = f"{max(old).label} -> {max(new).label}"
        return out

    def _regressions(self, rel: str, before_text: str, after_text: str) -> str:
        """Findings of medium severity or above (any rule) that the change introduced."""
        before = Counter(f.rule_id for f in verify.rescan(rel, before_text, self.root).findings)
        after_findings = verify.rescan(rel, after_text, self.root).findings
        after = Counter(f.rule_id for f in after_findings)
        new = [f"{f.rule_id} line {f.line}: {f.message}" for f in after_findings
               if after[f.rule_id] > before[f.rule_id] and f.severity >= Severity.MEDIUM]
        return "; ".join(dict.fromkeys(new))
