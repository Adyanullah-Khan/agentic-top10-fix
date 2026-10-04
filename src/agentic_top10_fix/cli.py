"""Command line: agentic-top10-fix [PATH] [--report scan.json] [--apply] ..."""
from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

from agentic_top10.models import Severity

from . import __version__, report
from .codemods import CodemodContext
from .engine import Engine, FileOutcome, Options
from .issues import ReportError, load_report, scan_issues
from .llm import LLMError, make_provider
from .patching import unified_diff

EXIT_OK, EXIT_REMAINING, EXIT_ERROR = 0, 1, 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="agentic-top10-fix",
        description="Fix agentic-top10-scan findings: deterministic codemods first, then LLM patches. Every change "
                    "is syntax-checked and re-scanned before it is kept. Dry run by default (prints a diff).",
    )
    p.add_argument("path", nargs="?", default=".", help="project directory (default: .)")
    p.add_argument("--report", help="agentic-top10-scan JSON or SARIF report (default: run the scanner on PATH)")
    p.add_argument("--apply", action="store_true", help="write the fixes to disk (default: dry run)")
    p.add_argument("--diff-file", help="write a git-applicable patch to this file")
    p.add_argument("--report-json", help="write a JSON summary")
    p.add_argument("--report-md", help="write a Markdown summary (pull-request body)")
    p.add_argument("--provider", choices=["auto", "anthropic", "openai", "none"], default="auto",
                   help="LLM backend; auto picks Anthropic if ANTHROPIC_API_KEY is set, else an OpenAI-compatible "
                        "endpoint if OPENAI_API_KEY/OPENAI_BASE_URL/--base-url is set, else codemods only")
    p.add_argument("--model", help="model name (default: claude-opus-5-5 for anthropic, gpt-4o for openai)")
    p.add_argument("--base-url", help="OpenAI-compatible base URL, e.g. http://my-server:8000/v1 for vLLM/Ollama")
    p.add_argument("--effort", default="high", choices=["low", "medium", "high", "xhigh", "max"],
                   help="Claude effort level (default: high)")
    p.add_argument("--online", action="store_true",
                   help="allow network lookups to pin versions (npm/PyPI) and action commit SHAs (GitHub API)")
    p.add_argument("--min-severity", default="low", choices=[s.label for s in Severity])
    p.add_argument("--rules", help="comma-separated rule IDs to fix (default: all)")
    p.add_argument("--skip-rules", default="", help="comma-separated rule IDs to leave alone")
    p.add_argument("--max-rounds", type=int, default=3, help="LLM attempts per file (default: 3)")
    p.add_argument("--max-llm-calls", type=int, default=30, help="LLM calls for the whole run (default: 30)")
    p.add_argument("--max-file-chars", type=int, default=200_000, help="skip the LLM for larger files")
    p.add_argument("--no-workflows", action="store_true", help="do not modify .github/workflows files")
    p.add_argument("--include-tests", action="store_true", help="when running the scanner, include test code")
    p.add_argument("--verify-cmd", help="with --apply: command to run after each patched file (e.g. 'pytest -q'); a "
                                        "file whose patch makes it fail is reverted. Runs your code, so only use it "
                                        "where that is safe (CI container).")
    p.add_argument("--verify-timeout", type=int, default=900)
    p.add_argument("--fail-on-remaining", action="store_true", help="exit 1 if fixable findings remain open")
    p.add_argument("--quiet", "-q", action="store_true", help="do not print diffs")
    p.add_argument("--version", action="version", version=f"agentic-top10-fix {__version__}")
    return p


def _csv(value: Optional[str]) -> List[str]:
    return [v.strip() for v in (value or "").split(",") if v.strip()]


def _run_verify(cmd: str, cwd: Path, timeout: int) -> bool:
    try:
        return subprocess.run(shlex.split(cmd), cwd=cwd, timeout=timeout, check=False).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def apply_outcomes(root: Path, outcomes: List[FileOutcome], verify_cmd: Optional[str], timeout: int) -> List[str]:
    """Write patched files. With verify_cmd, keep a file only if the command still passes after writing it."""
    messages = []
    for o in outcomes:
        if not o.changed or o.error:
            continue
        target = root / o.path
        target.write_text(o.patched, encoding="utf-8")
        if verify_cmd and not _run_verify(verify_cmd, root, timeout):
            target.write_text(o.original, encoding="utf-8")
            messages.append(f"reverted {o.path}: '{verify_cmd}' failed with the patch applied")
            o.remaining = [(i, "patch reverted: verify command failed") for i, _ in o.fixed] + o.remaining
            o.fixed = []
            o.patched = o.original
    return messages


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"agentic-top10-fix: not a directory: {args.path}", file=sys.stderr)
        return EXIT_ERROR
    if args.verify_cmd and not args.apply:
        print("agentic-top10-fix: --verify-cmd needs --apply", file=sys.stderr)
        return EXIT_ERROR

    try:
        issues = load_report(Path(args.report)) if args.report else scan_issues(root, args.include_tests)
        provider = make_provider(args.provider, args.model, args.base_url, args.effort)
    except (ReportError, LLMError) as exc:
        print(f"agentic-top10-fix: {exc}", file=sys.stderr)
        return EXIT_ERROR
    if provider is None and args.provider == "auto":
        print("agentic-top10-fix: no LLM configured (set ANTHROPIC_API_KEY, or OPENAI_API_KEY / --base-url); "
              "running deterministic codemods only", file=sys.stderr)

    options = Options(min_severity=Severity.parse(args.min_severity), rules=set(_csv(args.rules)) or None,
                      skip_rules=set(_csv(args.skip_rules)), max_rounds=args.max_rounds,
                      max_llm_calls=args.max_llm_calls, max_file_chars=args.max_file_chars,
                      include_workflows=not args.no_workflows)
    ctx = CodemodContext(online=args.online, github_token=os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"))
    engine = Engine(root, provider, options, ctx)
    outcomes = engine.run(issues)

    messages = apply_outcomes(root, outcomes, args.verify_cmd, args.verify_timeout) if args.apply else []
    provider_name = getattr(provider, "name", None)
    model = getattr(provider, "model", None)
    try:
        if args.diff_file:
            Path(args.diff_file).write_text("".join(unified_diff(o.path, o.original, o.patched)
                                                    for o in outcomes if o.changed), encoding="utf-8")
        if args.report_json:
            Path(args.report_json).write_text(report.to_json(outcomes, engine.usage, provider_name, model),
                                              encoding="utf-8")
        if args.report_md:
            Path(args.report_md).write_text(report.to_markdown(outcomes, engine.usage, provider_name, model),
                                            encoding="utf-8")
    except OSError as exc:
        print(f"agentic-top10-fix: could not write output: {exc}", file=sys.stderr)
        return EXIT_ERROR

    print(report.to_text(outcomes, engine.usage, show_diff=not args.quiet))
    for m in messages:
        print(f"agentic-top10-fix: {m}", file=sys.stderr)
    if not args.apply and any(o.changed for o in outcomes):
        print("Dry run: re-run with --apply to write these changes.", file=sys.stderr)
    if args.fail_on_remaining and any(o.remaining for o in outcomes):
        return EXIT_REMAINING
    return EXIT_OK
