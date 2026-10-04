"""The remediation loop with a scripted fake LLM: what gets kept, rejected and reported."""
from agentic_top10_fix.engine import Engine, Options
from agentic_top10_fix.llm import LLMError

from conftest import FakeProvider, proposal

TOOL = '''
import sqlite3
from langchain_core.tools import tool


@tool
def find(name: str) -> list:
    """Find a customer."""
    conn = sqlite3.connect("crm.db")
    return conn.execute(f"SELECT * FROM customers WHERE name = '{name}'").fetchall()
'''

ORIGINAL_RUN = '''    return conn.execute(f"SELECT * FROM customers WHERE name = '{name}'").fetchall()'''
FIXED_RUN = '''    return conn.execute("SELECT * FROM customers WHERE name = ?", (name,)).fetchall()'''


def outcome_for(root, issues, provider, **opts):
    engine = Engine(root, provider, Options(**opts))
    [out] = [o for o in engine.run(issues) if o.path == "tools.py"]
    return out, engine


def test_good_patch_is_kept(project):
    root, issues = project({"tools.py": TOOL})
    fake = FakeProvider(proposal((ORIGINAL_RUN, FIXED_RUN, "ATS-ASI02-04"), summary="Allowlisted commands."))
    out, engine = outcome_for(root, issues, fake, rules={"ATS-ASI02-04"})
    assert out.changed and "?" in out.patched
    assert [(i.rule_id, m) for i, m in out.fixed] == [("ATS-ASI02-04", "llm")]
    assert out.notes == ["Allowlisted commands."]
    assert "<untrusted_file" in fake.prompts[0] and "ATS-ASI02-04" in fake.prompts[0]
    assert engine.usage.calls == 1


def test_suppression_comment_is_rejected_then_retried(project):
    root, issues = project({"tools.py": TOOL})
    cheat = ORIGINAL_RUN + "  # agentic-top10: ignore"
    fake = FakeProvider(proposal((ORIGINAL_RUN, cheat, "ATS-ASI02-04")),
                        proposal((ORIGINAL_RUN, FIXED_RUN, "ATS-ASI02-04")))
    out, _ = outcome_for(root, issues, fake, rules={"ATS-ASI02-04"})
    assert "agentic-top10: ignore" not in out.patched and out.fixed
    assert "suppression comment" in fake.prompts[1]


def test_regression_is_rejected(project):
    root, issues = project({"tools.py": TOOL})
    swap = "    return eval(name)"
    fake = FakeProvider(proposal((ORIGINAL_RUN, swap, "ATS-ASI02-04")))
    out, _ = outcome_for(root, issues, fake, rules={"ATS-ASI02-04"}, max_rounds=1)
    assert not out.changed  # eval(cmd) would be a new ATS-ASI05-01 finding, so the patch is discarded
    assert out.remaining and out.remaining[0][0].rule_id == "ATS-ASI02-04"


def test_bad_find_text_and_syntax_errors_get_feedback(project):
    root, issues = project({"tools.py": TOOL})
    fake = FakeProvider(proposal(("does not exist", "x", "ATS-ASI02-04")),
                        proposal((ORIGINAL_RUN, "    return conn.execute(", "ATS-ASI02-04")),
                        proposal((ORIGINAL_RUN, FIXED_RUN, "ATS-ASI02-04")))
    out, engine = outcome_for(root, issues, fake, rules={"ATS-ASI02-04"})
    assert out.fixed and engine.usage.calls == 3
    assert "could not be applied" in fake.prompts[1]
    assert "SyntaxError" in fake.prompts[2]


def test_unfixable_and_errors_are_reported(project):
    root, issues = project({"tools.py": TOOL})
    fake = FakeProvider(proposal(unfixable=[{"rule_id": "ATS-ASI02-04", "line": 10, "reason": "needs a schema change"}]))
    out, _ = outcome_for(root, issues, fake, rules={"ATS-ASI02-04"})
    assert out.remaining[0][1] == "needs a schema change"
    fake = FakeProvider(LLMError("Claude declined this file (refusal, category cyber)"))
    out, _ = outcome_for(root, issues, fake, rules={"ATS-ASI02-04"})
    assert "refusal" in out.remaining[0][1]


def test_secrets_never_reach_the_model(project):
    secret = "Zq8" + "Lm2Pw9Xr4Tn7Vb1Kc5Hd3Jf6"
    root, issues = project({"tools.py": TOOL + f'\nSERVICE_TOKEN = "{secret}"\n'})
    fake = FakeProvider(proposal((ORIGINAL_RUN, FIXED_RUN, "ATS-ASI02-04")))
    out, _ = outcome_for(root, issues, fake, rules={"ATS-ASI02-04", "ATS-ASI03-01"})
    assert secret not in "".join(fake.prompts)
    assert 'SERVICE_TOKEN = os.environ["SERVICE_TOKEN"]' in out.patched  # codemod, not the model
    assert {i.rule_id for i, _ in out.fixed} >= {"ATS-ASI03-01", "ATS-ASI02-04"}


def test_budget_and_report_paths_outside_root(project, tmp_path):
    root, issues = project({"tools.py": TOOL})
    fake = FakeProvider()
    out, _ = outcome_for(root, issues, fake, rules={"ATS-ASI02-04"}, max_llm_calls=0)
    assert "budget" in out.remaining[0][1] and fake.prompts == []
    from dataclasses import replace

    escaped = [replace(issues[0], path="../outside.py")]
    [res] = Engine(root, None).run(escaped)
    assert res.error and not res.changed


def test_ten_04_logging_is_verified(project):
    src = '''
        import logging
        from langchain_core.tools import tool


        @tool
        def lookup(q: str) -> str:
            """Look up."""
            return q
    '''
    root, issues = project({"tools.py": src})
    assert any(i.rule_id == "ATS-ASI10-04" for i in issues)
    logged = '    """Look up."""\n    logging.getLogger(__name__).info("tool=lookup q=%r", q)'
    fake = FakeProvider(proposal(('    """Look up."""', logged, "ATS-ASI10-04")))
    out, _ = outcome_for(root, issues, fake)
    assert [i.rule_id for i, _ in out.fixed] == ["ATS-ASI10-04"]


def test_capability_findings_count_as_mitigated(project):
    shell_tool = '''
        import subprocess
        from langchain_core.tools import tool


        @tool
        def run(cmd: str) -> str:
            """Run a command."""
            return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout
    '''
    root, issues = project({"tools.py": shell_tool})
    before = "    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout"
    after = ('    argv = {"date": ["date"], "uptime": ["uptime"]}[cmd]\n'
             '    return subprocess.run(argv, capture_output=True, text=True, timeout=30).stdout')
    fake = FakeProvider(proposal((before, after, "ATS-ASI02-01")))
    out, engine = outcome_for(root, issues, fake, rules={"ATS-ASI02-01"})
    assert out.changed and engine.usage.calls == 1  # no pointless retries
    [(issue, reason)] = out.remaining
    assert issue.rule_id == "ATS-ASI02-01" and reason.startswith("mitigated (critical -> medium)")
