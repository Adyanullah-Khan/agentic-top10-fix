import json
import subprocess
import sys

from agentic_top10_fix import cli

from conftest import write

APP = '''
import requests
import yaml


def load(path):
    return yaml.load(open(path))


def ping():
    return requests.get("https://status.example-corp.net/ok", verify=False)
'''


def test_dry_run_then_apply_with_reports(tmp_path, capsys):
    write(tmp_path, {"app.py": APP})
    assert cli.main([str(tmp_path), "--provider", "none"]) == 0
    out = capsys.readouterr()
    assert "+    return yaml.safe_load(open(path))" in out.out and "Dry run" in out.err
    assert "yaml.load(open(path))" in (tmp_path / "app.py").read_text()  # untouched

    md, js, diff = tmp_path / "fix.md", tmp_path / "fix.json", tmp_path / "fix.patch"
    assert cli.main([str(tmp_path), "--provider", "none", "--apply", "--report-md", str(md), "--report-json", str(js),
                     "--diff-file", str(diff), "-q"]) == 0
    text = (tmp_path / "app.py").read_text()
    assert "yaml.safe_load(open(path))" in text and "verify=True" in text
    data = json.loads(js.read_text())
    assert data["summary"]["fixed_by_codemod"] >= 2
    assert "## Agentic Top 10 Fix" in md.read_text() and diff.read_text().startswith("--- a/app.py")


def test_report_input_and_verify_cmd_revert(tmp_path, capsys):
    write(tmp_path, {"app.py": APP})
    report = tmp_path / "scan.json"
    subprocess.run([sys.executable, "-m", "agentic_top10", str(tmp_path), "--format", "json", "-o", str(report),
                    "--fail-on", "none"], check=True)
    failing = f"{sys.executable} -c 'raise SystemExit(1)'"
    assert cli.main([str(tmp_path), "--report", str(report), "--provider", "none", "--apply",
                     "--verify-cmd", failing, "-q"]) == 0
    assert "reverted app.py" in capsys.readouterr().err
    assert "yaml.load(open(path))" in (tmp_path / "app.py").read_text()


def test_errors(tmp_path, capsys):
    assert cli.main([str(tmp_path / "nope")]) == 2
    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    assert cli.main([str(tmp_path), "--report", str(bad), "--provider", "none"]) == 2
    assert cli.main([str(tmp_path), "--verify-cmd", "true"]) == 2


def test_end_to_end_with_claude_backend(tmp_path, capsys, mock_server, monkeypatch):
    from conftest import anthropic_sse

    write(tmp_path, {"tools.py": '''
        import sqlite3
        from langchain_core.tools import tool


        @tool
        def find(name: str) -> list:
            """Find a customer."""
            conn = sqlite3.connect("crm.db")
            return conn.execute(f"SELECT * FROM customers WHERE name = '{name}'").fetchall()
    '''})
    patch = {"edits": [{"find": "conn.execute(f\"SELECT * FROM customers WHERE name = '{name}'\")",
                        "replace": "conn.execute(\"SELECT * FROM customers WHERE name = ?\", (name,))",
                        "rule_id": "ATS-ASI02-04"}],
             "unfixable": [], "summary": "Parameterised the customer query."}
    mock_server.replies.append((200, {"Content-Type": "text/event-stream"}, anthropic_sse(json.dumps(patch))))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("ANTHROPIC_BASE_URL", mock_server.url)
    md = tmp_path / "pr.md"
    assert cli.main([str(tmp_path), "--provider", "anthropic", "--rules", "ATS-ASI02-04", "--apply",
                     "--report-md", str(md), "-q"]) == 0
    assert "WHERE name = ?" in (tmp_path / "tools.py").read_text()
    assert "Parameterised the customer query." in md.read_text()
    assert "claude-opus-5-5" in md.read_text()
    assert "<untrusted_file path=\"tools.py\">" in mock_server.requests[0]["json"]["messages"][0]["content"]
