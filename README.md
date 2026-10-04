# Agentic Top 10 Fix

Turns findings from [Agentic Top 10 Scan](https://github.com/Adyanullah-Khan/agentic-top10-scan) into code fixes,
then checks every fix with the scanner before keeping it. It ships as a GitHub Action that opens a pull request and
as a command-line tool.

```
scan ──► findings ──► deterministic codemods ──► LLM patch rounds ──► verify ──► diff / PR
                                                       ▲                  │
                                                       └── feedback ◄─────┘
```

For each file with findings it:

1. **Re-scans the file** to get current line numbers. A stale report is fine.
2. **Applies deterministic codemods** where a rule has a safe mechanical fix: timeouts, TLS verification,
   `yaml.safe_load`, secrets moved to environment variables, loop limits, Docker sandboxing, approval settings,
   `https://`, and, with `--online`, pinning actions to commit SHAs and MCP packages to versions. No LLM is involved.
3. **Asks an LLM for minimal search/replace edits** for everything else. By default that's Claude (`claude-opus-5-5`);
   it can also be any OpenAI-compatible endpoint, including a model on your own server. The model gets the file, the
   findings, and a playbook for each rule.
4. **Verifies every candidate patch**, and rejects it if any of these happen:
   - it doesn't parse,
   - it adds an `agentic-top10: ignore` comment,
   - it deletes a large share of the file,
   - it introduces a new finding of medium severity or above,
   - the re-scan doesn't show the targeted findings gone or reduced in severity.

   When a patch is rejected, the reason goes back to the model for another round (3 rounds by default).
5. **Reports each finding** as fixed (by codemod or LLM), mitigated, still open with a reason, or needing a human
   decision.

Dry run is the default: you get a diff. `--apply` writes the files; the Action opens a pull request and never pushes
to your branch.

## Quick start (GitHub Action)

```yaml
# .github/workflows/agentic-top10-fix.yml
name: Agentic Top 10 Fix
on:
  workflow_dispatch:
  schedule:
    - cron: "0 4 * * 1"   # weekly

permissions:
  contents: write         # push the fix branch
  pull-requests: write    # open the pull request

jobs:
  fix:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Adyanullah-Khan/agentic-top10-fix@v0.1.0   # pin to a commit SHA in production
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          min-severity: medium
```

Two repository settings matter:

- **Allow pull requests from Actions.** Turn on *Settings → Actions → General → Allow GitHub Actions to create and
  approve pull requests*.
- **Workflow files are skipped by default.** The default `GITHUB_TOKEN` can't push changes to `.github/workflows`.
  To fix those too, pass a token with the `workflow` scope as `github-token` and set `include-workflows: true`.

Don't run this on `pull_request_target` or on untrusted forks. It sends repository code to the LLM and holds a
token that can write.

## Command line

```bash
pip install "agentic-top10-fix[anthropic] @ git+https://github.com/Adyanullah-Khan/agentic-top10-fix@v0.1.0"

agentic-top10-fix .                                 # scan, then print a diff of proposed fixes (dry run)
agentic-top10-fix . --apply                         # write them
agentic-top10-fix . --report scan.json --apply      # use an existing scanner report (JSON or SARIF)
agentic-top10-fix . --provider none                 # codemods only: no LLM, nothing leaves the machine
agentic-top10-fix . --apply --verify-cmd "pytest -q"  # drop any file's patch that breaks your tests
agentic-top10-fix . --online --rules ATS-ASI04-04   # pin GitHub Actions to commit SHAs
```

Requires Python 3.10+.

### Choosing the LLM

| Setting | Backend |
|---|---|
| `ANTHROPIC_API_KEY` set (or `--provider anthropic`) | Claude via the Anthropic SDK. Default model `claude-opus-5-5` with adaptive thinking, `--effort high`, JSON-schema structured output, prompt caching on the system prompt, and server-side refusal fallback |
| `--base-url http://server:8000/v1 --model llama3.1:70b` | Any OpenAI-compatible `/v1/chat/completions` server (vLLM, Ollama, llama.cpp, LM Studio) |
| `OPENAI_API_KEY` set (or `--provider openai`) | OpenAI, default model `gpt-4o` |
| none of the above | Codemods only |

A self-hosted model keeps code on your own hardware. Expect weaker patches from smaller models. The verification
loop rejects bad ones, but fewer findings will get fixed.

## How it applies the OWASP agentic controls to itself

The fixer is itself an agent that reads untrusted code and writes code, so it follows the same rules the scanner
checks:

| Risk | Control in this tool |
|---|---|
| ASI01 goal hijack | The file is wrapped in `<untrusted_file>` tags, and the system prompt says text inside it is never an instruction. The model can only return edits to that one file. |
| ASI03 secrets | Credentials are replaced with `__REDACTED_SECRET_n__` placeholders before anything is sent, and restored only inside applied edits. Hardcoded secrets in Python/JS are moved to environment variables by a codemod, so the model never sees them. |
| ASI05 code execution | Nothing the model writes is executed. Verification is static: parse plus re-scan. `--verify-cmd` runs your tests only when you ask for it. |
| ASI08 runaway loops | Per-file round limit (`--max-rounds`), whole-run call budget (`--max-llm-calls`), file size cap, and SDK timeouts and retries. |
| ASI09 human trust | Dry run by default. The Action opens a pull request for review and never pushes to your branch. |
| ASI02 report paths | Paths from a scanner report must resolve inside the project. Symlinks and `../` paths are refused. |

## What gets fixed how

Of the scanner's 57 rules:

- **12 have codemods:** ASI01-04, ASI02-06, ASI03-01 (Python/JS), ASI04-01 and ASI04-04 (with `--online`),
  ASI04-07, ASI05-04, ASI05-05, ASI07-01, ASI08-01, ASI08-02 and ASI09-02. Shapes a codemod can't handle go to the
  LLM.
- **34 are LLM-patched,** with a per-rule playbook (see `src/agentic_top10_fix/playbooks.py`). Examples: delimiting
  untrusted content, command lookup tables instead of shells, path confinement, parameterised SQL, approval gates,
  bounded retries, audit logging.
- **11 are reported for a human,** with guidance. These are findings in declarations (agent manifest, A2A agent card),
  where editing the declaration without changing the running system would only quiet the scanner. Also: choosing
  dependency versions, upgrading a vulnerable package, and moving a browser LLM call to a server.

Some findings describe a capability rather than a bug; for example, "this tool runs OS commands" is still true
after you restrict it to an allowlist. When a patch lowers such a finding's severity (critical → medium), it's
reported as **mitigated** and not retried.

## Outputs

- `--report-md`: a pull-request body listing fixes, notes from the model, open items and manual items.
- `--report-json`: machine-readable, including each file's diff.
- `--diff-file`: a git-applicable patch.
- Action outputs: `files-changed`, `fixed-count` and `pr-url`.

## Limitations

- "Fixed" means the scanner no longer reports the pattern and the file still parses. It doesn't prove the code is
  correct or that behaviour is unchanged. Review the pull request and run your tests (`--verify-cmd`).
- The scanner's own limits apply: findings it can't see won't be fixed.
- LLM patches cost tokens. `--max-llm-calls` caps a run, and the summary prints token usage.
- With Claude, a security-related request is occasionally declined by a safety classifier. The fixer enables
  server-side fallback to another model; if the whole chain declines, the finding is left open with the reason.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[test]"
pytest
```

The tests cover:

- every codemod,
- the engine's patch loop against a scripted fake model (kept, rejected, regressions, suppression attempts, budget,
  secrets),
- both LLM backends against local mock servers (request shape, structured output, refusals, response-format
  fallback),
- the CLI end to end.

## License

MIT
