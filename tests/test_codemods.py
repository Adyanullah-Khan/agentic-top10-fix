from agentic_top10.models import Severity

from agentic_top10_fix.codemods import (CodemodContext, add_timeout, ensure_import_os, enable_tls_verification,
                                        loop_limit, pin_action_sha, pin_mcp_package, restore_approval, safe_yaml,
                                        secret_to_env, strip_hidden_unicode)
from agentic_top10_fix.issues import Issue


def issue(rule, path, line, message=""):
    return Issue(rule, path, line, Severity.HIGH, message)


def test_add_timeout_single_and_multiline():
    text = 'import requests\nr = requests.get(url).text\nq = requests.request(\n    "POST", url, data=d\n)\n'
    out = add_timeout(text, issue("ATS-ASI08-02", "a.py", 2), CodemodContext())
    assert "requests.get(url, timeout=30).text" in out
    out = add_timeout(out, issue("ATS-ASI08-02", "a.py", 3), CodemodContext())
    assert 'data=d, timeout=30\n)' in out


def test_tls_and_loop_limits_across_lines():
    text = 'x = Agent(\n    role="r",\n    max_iter=500,\n    verify=False,\n)\n'
    out = loop_limit(text, issue("ATS-ASI08-01", "a.py", 1), CodemodContext())
    assert "max_iter=20" in out
    out = enable_tls_verification(out, issue("ATS-ASI02-06", "a.py", 1), CodemodContext())
    assert "verify=True" in out
    assert loop_limit("Runner.run(a, max_turns=30)\n", issue("ATS-ASI08-01", "a.py", 1), CodemodContext()) is None


def test_safe_yaml_variants():
    ctx = CodemodContext()
    assert safe_yaml("import yaml\ny = yaml.load(open('a'))\n", issue("ATS-ASI05-05", "a.py", 2), ctx) == \
        "import yaml\ny = yaml.safe_load(open('a'))\n"
    assert safe_yaml("import yaml\ny = yaml.load(f, Loader=yaml.FullLoader)\n", issue("ATS-ASI05-05", "a.py", 2),
                     ctx) == "import yaml\ny = yaml.safe_load(f)\n"
    assert safe_yaml("import pickle\ny = pickle.load(f)\n", issue("ATS-ASI05-05", "a.py", 2), ctx) is None


def test_secret_to_env_python_and_js():
    value = "Zq8" + "Lm2Pw9Xr4Tn7Vb1Kc5Hd3Jf6"
    ctx = CodemodContext()
    out = secret_to_env(f'"""Doc."""\nfrom x import y\nAPI_KEY = "{value}"\n', issue("ATS-ASI03-01", "a.py", 3), ctx)
    assert ctx.needs_import_os and 'API_KEY = os.environ["API_KEY"]' in out and value not in out
    assert ensure_import_os(out).splitlines()[1] == "import os"
    js = secret_to_env(f'const client = new Client({{ apiKey: "{value}" }});\n', issue("ATS-ASI03-01", "a.ts", 1),
                       CodemodContext())
    assert "apiKey: process.env.APIKEY" in js
    assert secret_to_env(f'key: "{value}"\n', issue("ATS-ASI03-01", "c.yaml", 1), CodemodContext()) is None


def test_hidden_unicode_keeps_emoji_joiners():
    text = "pirate \U0001f3f4‍☠️ plain​word\U000E0041\n"
    out = strip_hidden_unicode(text, issue("ATS-ASI01-04", "p.md", 1), CodemodContext())
    assert out == "pirate \U0001f3f4‍☠️ plainword\n"


def test_restore_approval_settings():
    ctx = CodemodContext()
    assert '"defaultMode": "default"' in restore_approval('{"defaultMode": "bypassPermissions"}\n',
                                                         issue("ATS-ASI09-02", ".claude/settings.json", 1), ctx)
    assert 'approval_policy = "on-request"' in restore_approval('approval_policy = "never"\n',
                                                               issue("ATS-ASI09-02", ".codex/config.toml", 1), ctx)


def test_online_pinning_uses_resolvers():
    calls = []

    def http_get(url, headers):
        calls.append(url)
        if "api.github.com" in url:
            return "3d3c42e5aac5ba805825da76410c181273ba90b1"
        return '{"version": "2025.8.21"}'

    ctx = CodemodContext(online=True, http_get=http_get)
    wf = "steps:\n  - uses: some-org/setup-codex@v1\n"
    out = pin_action_sha(wf, issue("ATS-ASI04-04", "w.yml", 2, "Action 'some-org/setup-codex@v1' is pinned"), ctx)
    assert "some-org/setup-codex@3d3c42e5aac5ba805825da76410c181273ba90b1 # v1" in out
    mcp = '{"mcpServers": {"fs": {\n  "command": "npx",\n  "args": ["-y", "@scope/server-fs", "/"]}}}\n'
    out = pin_mcp_package(mcp, issue("ATS-ASI04-01", ".mcp.json", 1, "MCP server 'fs' runs '@scope/server-fs' via npx"),
                          ctx)
    assert '"@scope/server-fs@2025.8.21"' in out
    assert any("registry.npmjs.org/@scope%2Fserver-fs/latest" in c for c in calls)
    offline = CodemodContext(online=False, http_get=http_get)
    assert pin_action_sha(wf, issue("ATS-ASI04-04", "w.yml", 2, "Action 'some-org/setup-codex@v1'"), offline) is None
