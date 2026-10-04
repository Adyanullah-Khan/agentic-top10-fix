"""Deterministic fixes for common shapes. No LLM, no network unless --online.

Each codemod takes (text, issue, ctx) and returns the new text, or None when it cannot handle this case (the
engine then hands the issue to the LLM, or reports it as manual).
"""
from __future__ import annotations

import ast
import json
import re
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional

from agentic_top10 import textutil
from agentic_top10.analyzers.python_code import LIMIT_KWS

from .issues import Issue

HttpGet = Callable[[str, Dict[str, str]], str]
PY_SUFFIXES = {".py"}
JS_SUFFIXES = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"}
ONLINE_RULES = {"ATS-ASI04-01", "ATS-ASI04-04"}


def default_http_get(url: str, headers: Dict[str, str]) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "agentic-top10-fix", **headers})
    with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310 - fixed https endpoints only
        return resp.read().decode("utf-8")


@dataclass
class CodemodContext:
    online: bool = False
    http_get: HttpGet = default_http_get
    github_token: Optional[str] = None
    needs_import_os: bool = False  # set when a Python secret was moved to os.environ


# ── helpers ──────────────────────────────────────────────────────────────────

def _lines(text: str) -> List[str]:
    return text.splitlines(keepends=True)


def _statement_span(text: str, lineno: int) -> tuple:
    """First/last line of the smallest Python statement containing `lineno` (calls often span lines)."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return lineno, lineno
    best = (lineno, lineno)
    size = None
    for node in ast.walk(tree):
        if isinstance(node, ast.stmt) and node.lineno <= lineno <= (node.end_lineno or node.lineno):
            span = (node.end_lineno or node.lineno) - node.lineno
            if size is None or span < size:
                best, size = (node.lineno, node.end_lineno or node.lineno), span
    return best


def _sub_line(text: str, lineno: int, subs, python: bool = False) -> Optional[str]:
    """Regex substitutions on the issue's line (or, for Python, the whole statement containing it)."""
    lines = _lines(text)
    if not 1 <= lineno <= len(lines):
        return None
    first, last = _statement_span(text, lineno) if python else (lineno, lineno)
    original = region = "".join(lines[first - 1:last])
    for pattern, repl in subs:
        region = re.sub(pattern, repl, region, flags=re.M)
    if region == original:
        return None
    return "".join(lines[:first - 1]) + region + "".join(lines[last:])


def _is_py(issue: Issue) -> bool:
    return Path(issue.path).suffix.lower() in PY_SUFFIXES


def _offset(lines: List[str], lineno: int, col_bytes: int) -> int:
    """Absolute character offset of an AST position (AST columns are UTF-8 byte offsets)."""
    line = lines[lineno - 1]
    col = len(line.encode("utf-8")[:col_bytes].decode("utf-8", errors="ignore"))
    return sum(len(x) for x in lines[:lineno - 1]) + col


def _dotted(node) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def _calls_on_line(text: str, lineno: int) -> List[ast.Call]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and n.lineno == lineno]
    return sorted(calls, key=lambda n: n.col_offset)


def _add_kwarg(text: str, call: ast.Call, source: str) -> str:
    lines = _lines(text)
    args = list(call.args) + list(call.keywords)
    if args:
        last = max(args, key=lambda n: (n.end_lineno, n.end_col_offset))
        pos = _offset(lines, last.end_lineno, last.end_col_offset)
        return text[:pos] + ", " + source + text[pos:]
    pos = _offset(lines, call.end_lineno, call.end_col_offset) - 1  # just before ")"
    return text[:pos] + source + text[pos:]


def ensure_import_os(text: str) -> str:
    if re.search(r"^(import os\b|import [\w, ]*\bos\b|from os import)", text, re.M):
        return text
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return text
    lines = _lines(text)
    insert_at = 0
    for stmt in tree.body:
        is_doc = isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str)
        is_future = isinstance(stmt, ast.ImportFrom) and stmt.module == "__future__"
        if (is_doc and insert_at == 0) or is_future:
            insert_at = stmt.end_lineno
            continue
        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
            insert_at = stmt.lineno - 1
        break
    lines.insert(insert_at, "import os\n")
    return "".join(lines)


# ── codemods ─────────────────────────────────────────────────────────────────

def strip_hidden_unicode(text: str, issue: Issue, ctx: CodemodContext) -> Optional[str]:
    lines = _lines(text)
    if not 1 <= issue.line <= len(lines):
        return None
    line = lines[issue.line - 1]
    out = []
    for i, ch in enumerate(line):
        cp = ord(ch)
        if not textutil.HIDDEN_CHAR_RE.match(ch):
            out.append(ch)
        elif cp == 0xFEFF and issue.line == 1 and i == 0:
            out.append(ch)
        elif cp in (0x200C, 0x200D) and any(ord(c) > 0x7F for c in line[max(0, i - 1):i] + line[i + 1:i + 2]):
            out.append(ch)  # joiner inside an emoji or non-Latin script: legitimate
    new = "".join(out)
    if new == line:
        return None
    lines[issue.line - 1] = new
    return "".join(lines)


def enable_tls_verification(text: str, issue: Issue, ctx: CodemodContext) -> Optional[str]:
    return _sub_line(text, issue.line, [
        (r"\bverify\s*=\s*False\b", "verify=True"),
        (r"\brejectUnauthorized\s*:\s*false\b", "rejectUnauthorized: true"),
        (r"\bssl\._create_unverified_context\(\)", "ssl.create_default_context()"),
    ], python=_is_py(issue))


KIND_ENV = {
    "Anthropic API key": "ANTHROPIC_API_KEY", "OpenAI API key": "OPENAI_API_KEY",
    "OpenAI project key": "OPENAI_API_KEY", "AWS access key ID": "AWS_ACCESS_KEY_ID", "GitHub token": "GITHUB_TOKEN",
    "GitHub fine-grained token": "GITHUB_TOKEN", "Slack token": "SLACK_TOKEN", "Google API key": "GOOGLE_API_KEY",
    "Stripe live key": "STRIPE_API_KEY", "Hugging Face token": "HF_TOKEN", "Groq API key": "GROQ_API_KEY",
}


def secret_to_env(text: str, issue: Issue, ctx: CodemodContext) -> Optional[str]:
    suffix = Path(issue.path).suffix.lower()
    if suffix not in PY_SUFFIXES | JS_SUFFIXES:
        return None  # config files: the secret has to move to a secret store by hand
    lines = _lines(text)
    if not 1 <= issue.line <= len(lines):
        return None
    line = lines[issue.line - 1]
    for start, end, kind, value in textutil.iter_secrets(line):
        qs = start - 1
        if qs < 0 or line[qs] not in "'\"`":
            continue
        qe = line.find(line[qs], end)
        if qe < 0 or line[qs + 1:qe] != value:
            continue
        m = re.search(r"""["']?([A-Za-z_][A-Za-z0-9_]*)["']?\s*(?::=|=|:)\s*$""", line[:qs])
        env = re.sub(r"[^A-Za-z0-9]+", "_", m.group(1)).upper() if m else KIND_ENV.get(kind)
        if env in (None, "API_KEY", "KEY", "TOKEN", "SECRET", "PASSWORD") and kind in KIND_ENV:
            env = KIND_ENV[kind]
        if not env:
            continue
        expr = f'os.environ["{env}"]' if suffix in PY_SUFFIXES else f"process.env.{env}"
        lines[issue.line - 1] = line[:qs] + expr + line[qe + 1:]
        if suffix in PY_SUFFIXES:
            ctx.needs_import_os = True
        return "".join(lines)
    return None


def safe_yaml(text: str, issue: Issue, ctx: CodemodContext) -> Optional[str]:
    if Path(issue.path).suffix.lower() not in PY_SUFFIXES:
        return None
    for call in _calls_on_line(text, issue.line):
        name = _dotted(call.func)
        if name.rsplit(".", 1)[-1] not in ("load", "unsafe_load", "load_all", "unsafe_load_all") or \
                not name.startswith("yaml."):
            continue
        lines = _lines(text)
        safe = "safe_load_all" if name.endswith("_all") else "safe_load"
        cuts = []  # (start, end, replacement), applied right to left
        loader_kw = next((k for k in call.keywords if k.arg == "Loader"), None)
        if loader_kw is not None:
            if not _dotted(loader_kw.value).endswith(("SafeLoader", "CSafeLoader", "BaseLoader")):
                prev = [n for n in call.args + call.keywords if n is not loader_kw]
                start = _offset(lines, prev[-1].end_lineno, prev[-1].end_col_offset) if prev else \
                    _offset(lines, loader_kw.lineno, loader_kw.col_offset)
                cuts.append((start, _offset(lines, loader_kw.end_lineno, loader_kw.end_col_offset), ""))
        elif len(call.args) > 1:
            cuts.append((_offset(lines, call.args[0].end_lineno, call.args[0].end_col_offset),
                         _offset(lines, call.args[1].end_lineno, call.args[1].end_col_offset), ""))
        fs = _offset(lines, call.func.lineno, call.func.col_offset)
        fe = _offset(lines, call.func.end_lineno, call.func.end_col_offset)
        cuts.append((fs, fe, name.rsplit(".", 1)[0] + "." + safe))
        for start, end, repl in sorted(cuts, reverse=True):
            text = text[:start] + repl + text[end:]
        return text
    return None


HTTP_CALLS = {"get", "post", "put", "patch", "delete", "head", "request", "urlopen", "options"}


def add_timeout(text: str, issue: Issue, ctx: CodemodContext) -> Optional[str]:
    if Path(issue.path).suffix.lower() not in PY_SUFFIXES:
        return None
    for call in _calls_on_line(text, issue.line):
        name = _dotted(call.func)
        if name.rsplit(".", 1)[-1] in HTTP_CALLS and not any(k.arg == "timeout" for k in call.keywords):
            if name.startswith(("requests.", "httpx.")) or name.endswith("urlopen") or name.startswith("session"):
                return _add_kwarg(text, call, "timeout=30")
    return None


PY_LIMIT_DEFAULTS = {"max_iterations": 15, "max_iter": 20, "max_turns": 20, "max_consecutive_auto_reply": 10,
                     "max_steps": 20, "max_round": 30, "max_rounds": 30, "recursion_limit": 50}
JS_LIMIT_DEFAULTS = {"maxIterations": 15, "maxSteps": 20, "maxTurns": 20, "recursionLimit": 50, "maxRounds": 30}
JS_LIMITS = {"maxIterations": 50, "maxSteps": 100, "maxTurns": 50, "recursionLimit": 200, "maxRounds": 100}


def loop_limit(text: str, issue: Issue, ctx: CodemodContext) -> Optional[str]:
    def py_kw(m):
        key, value = m.group(1), m.group(3)
        if value == "None" or int(value) > LIMIT_KWS.get(key, 0):
            return f"{key}{m.group(2)}{PY_LIMIT_DEFAULTS[key]}"
        return m.group(0)

    def py_dict(m):
        return m.group(1) + str(PY_LIMIT_DEFAULTS["recursion_limit"]) if int(m.group(2)) > LIMIT_KWS["recursion_limit"] \
            else m.group(0)

    def js(m):
        key, value = m.group(1), m.group(3)
        if not value.isdigit() or int(value) > JS_LIMITS[key]:
            return f"{key}{m.group(2)}{JS_LIMIT_DEFAULTS[key]}"
        return m.group(0)

    keys = "|".join(PY_LIMIT_DEFAULTS)
    return _sub_line(text, issue.line, [
        (rf"\b({keys})(\s*=\s*)(None|\d+)\b", py_kw),
        (r"""(["']recursion_limit["']\s*:\s*)(\d+)""", py_dict),
        (rf"\b({'|'.join(JS_LIMIT_DEFAULTS)})(\s*:\s*)(Infinity|null|Number\.MAX_SAFE_INTEGER|\d+)", js),
    ], python=_is_py(issue))


def sandbox_execution(text: str, issue: Issue, ctx: CodemodContext) -> Optional[str]:
    new = _sub_line(text, issue.line, [
        (r"""(["']use_docker["']\s*:\s*)False\b""", r"\1True"),
        (r"\b(use_docker\s*=\s*)False\b", r"\1True"),
        (r"""\b(code_execution_mode\s*=\s*)(["'])unsafe\2""", r"\1\2safe\2"),
        (r"""\b(executor_type\s*=\s*)(["'])local\2""", r"\1\2docker\2"),
    ], python=_is_py(issue))
    if new is None and "local executor" in issue.message and Path(issue.path).suffix == ".py":
        for call in _calls_on_line(text, issue.line):
            if _dotted(call.func).endswith("CodeAgent") and not any(k.arg == "executor_type" for k in call.keywords):
                return _add_kwarg(text, call, 'executor_type="docker"')
    return new


def restore_approval(text: str, issue: Issue, ctx: CodemodContext) -> Optional[str]:
    subs = [
        (r"""("defaultMode"\s*:\s*)"bypassPermissions\"""", r'\1"default"'),
        (r"""("chat\.tools\.(?:global\.)?autoApprove"\s*:\s*)true\b""", r"\1false"),
        (r"\b(auto_approve|auto_run|auto_confirm)(\s*=\s*)True\b", r"\1\2False"),
        (r"""\b(require_approval)(\s*=\s*)(["'])(never|none|auto)\3""", r"\1\2\3always\3"),
        (r"""\b(approval_policy)(\s*=\s*)(["'])never\3""", r"\1\2\3on-request\3"),
        (r"""(["']require_approval["']\s*:\s*)(["'])never\2""", r"\1\2always\2"),
        (r"""^(\s*approval_policy\s*=\s*)"never\"""", r'\1"on-request"'),
        (r"""^(\s*sandbox_mode\s*=\s*)"danger-full-access\"""", r'\1"workspace-write"'),
    ]
    if Path(issue.path).suffix.lower() in (".json", ".jsonc"):
        subs.append((r"""("trust"\s*:\s*)true\b""", r"\1false"))
    return _sub_line(text, issue.line, subs, python=_is_py(issue))


def disable_auto_mcp(text: str, issue: Issue, ctx: CodemodContext) -> Optional[str]:
    return _sub_line(text, issue.line, [(r"""("enableAllProjectMcpServers"\s*:\s*)true\b""", r"\1false")])


def https_url(text: str, issue: Issue, ctx: CodemodContext) -> Optional[str]:
    m = re.search(r"\(((?:http|ws)://[^)\s]+)\)", issue.message)
    if not m:
        return None
    url = m.group(1)
    secure = "https://" + url[7:] if url.startswith("http://") else "wss://" + url[5:]
    return _sub_line(text, issue.line, [(re.escape(url), secure.replace("\\", "\\\\"))])


def pin_action_sha(text: str, issue: Issue, ctx: CodemodContext) -> Optional[str]:
    m = re.search(r"Action '([^']+@[^']+)'", issue.message)
    if not ctx.online or not m:
        return None
    uses = m.group(1)
    action, ref = uses.rsplit("@", 1)
    parts = action.split("/")
    if len(parts) < 2:
        return None
    headers = {"Accept": "application/vnd.github.sha"}
    if ctx.github_token:
        headers["Authorization"] = f"Bearer {ctx.github_token}"
    try:
        sha = ctx.http_get(f"https://api.github.com/repos/{parts[0]}/{parts[1]}/commits/"
                           f"{urllib.parse.quote(ref, safe='')}", headers).strip()
    except Exception:  # noqa: BLE001 - offline or unknown ref: leave it for a human
        return None
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        return None
    lines = _lines(text)
    line = lines[issue.line - 1] if 1 <= issue.line <= len(lines) else ""
    if uses not in line:
        return None
    new = line.replace(uses, f"{action}@{sha}", 1)
    if "#" not in new.split(sha, 1)[1]:
        ending = new[len(new.rstrip("\r\n")):]
        new = new.rstrip("\r\n") + f" # {ref}" + ending
    lines[issue.line - 1] = new
    return "".join(lines)


def pin_mcp_package(text: str, issue: Issue, ctx: CodemodContext) -> Optional[str]:
    m = re.search(r"runs '([^']+)' via (\w+)", issue.message)
    if not ctx.online or not m:
        return None
    pkg, exe = m.group(1), m.group(2)
    try:
        if exe in ("uvx", "pipx", "uv"):
            version = json.loads(ctx.http_get(f"https://pypi.org/pypi/{urllib.parse.quote(pkg)}/json", {}))["info"]["version"]
            pinned = f"{pkg}=={version}"
        else:
            base = pkg.rsplit("@", 1)[0] if pkg.count("@") > (1 if pkg.startswith("@") else 0) else pkg
            version = json.loads(ctx.http_get(f"https://registry.npmjs.org/{urllib.parse.quote(base, safe='@')}/latest",
                                              {}))["version"]
            pinned = f"{base}@{version}"
    except Exception:  # noqa: BLE001
        return None
    lines = _lines(text)
    for i in range(max(0, issue.line - 1), min(len(lines), issue.line + 15)):
        for quote in ('"', "'"):
            token = f"{quote}{pkg}{quote}"
            if token in lines[i]:
                lines[i] = lines[i].replace(token, f"{quote}{pinned}{quote}", 1)
                return "".join(lines)
    return None


CODEMODS: Dict[str, Callable[[str, Issue, CodemodContext], Optional[str]]] = {
    "ATS-ASI01-04": strip_hidden_unicode,
    "ATS-ASI02-06": enable_tls_verification,
    "ATS-ASI03-01": secret_to_env,
    "ATS-ASI04-01": pin_mcp_package,
    "ATS-ASI04-04": pin_action_sha,
    "ATS-ASI04-07": disable_auto_mcp,
    "ATS-ASI05-04": sandbox_execution,
    "ATS-ASI05-05": safe_yaml,
    "ATS-ASI07-01": https_url,
    "ATS-ASI08-01": loop_limit,
    "ATS-ASI08-02": add_timeout,
    "ATS-ASI09-02": restore_approval,
}
