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

## Step-by-step: add the fixer to your agent project

Route A runs on GitHub and opens a pull request with the fixes. Route B runs on your own computer and edits your
local copy. Both work with Claude, with your own self-hosted model, or with no AI at all (mechanical codemods only).

### A. On GitHub (opens a pull request)

1. **Get a Claude API key.** Go to [console.anthropic.com](https://console.anthropic.com), open **API keys**,
   click **Create key**, and copy it (it's shown only once). Skip this step if you'll use your own model or no AI;
   see "Using your own model" below.
2. **Store the key in your repository.** In your agent's repository, open **Settings → Secrets and variables →
   Actions → New repository secret**. Set *Name* to `ANTHROPIC_API_KEY`, paste the key into *Secret*, and click
   **Add secret**. The key is never shown in logs.
3. **Allow Actions to open pull requests.** Open **Settings → Actions → General**, scroll to *Workflow permissions*,
   tick **Allow GitHub Actions to create and approve pull requests**, and click **Save**. In an organisation, an
   owner may have to allow this at the organisation level first.
4. **Create the workflow file.** Click **Add file → Create new file**, name it
   `.github/workflows/agentic-top10-fix.yml`, and paste:

   ```yaml
   name: Agentic Top 10 Fix
   on:
     workflow_dispatch:          # adds a "Run workflow" button
     schedule:
       - cron: "0 4 * * 1"       # also every Monday 04:00 UTC

   permissions:
     contents: write             # push the branch with the fixes
     pull-requests: write        # open the pull request

   jobs:
     fix:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4
         - uses: Adyanullah-Khan/agentic-top10-fix@v0.1.0
           with:
             anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
             min-severity: medium   # start with the important findings
             max-llm-calls: "20"    # cost cap per run
   ```

5. **Save it.** Click **Commit changes…** and then **Commit changes**.
6. **Run it.** Open the **Actions** tab, select **Agentic Top 10 Fix** on the left, and click **Run workflow →
   Run workflow**. A run takes a few minutes, depending on how many files need AI fixes.
7. **Check the summary.** Open the run and scroll down. It lists what was fixed, what is still open and why, and
   what needs a decision from you.
8. **Review the pull request.** Open the **Pull requests** tab and click **Fix agentic security findings**:
   - Read the description. It lists every fix, plus notes from the model about anything you should check.
   - Open **Files changed** and look at each change, especially new constants such as allowlists, root folders or
     limits. Adjust them to your setup by editing the files in the pull request.
   - Let your tests run on the pull request, then **Merge**. Or close it if you don't want the changes.
9. **Confirm.** If you also use [Agentic Top 10 Scan](https://github.com/Adyanullah-Khan/agentic-top10-scan), its
   next run on `main` shows the fixed findings gone.

**No AI at all:** replace the `anthropic-api-key` line with `provider: none`. Only the mechanical codemods run, no
code leaves GitHub, and no secret is needed.

**Using your own model (for example on your own server):** GitHub's machines can't reach a server inside your home or
office network. Run the job on a machine that can:

1. In your repository, open **Settings → Actions → Runners → New self-hosted runner**, and run the commands it shows
   on a computer on the same network as your model server.
2. In the workflow, change `runs-on: ubuntu-latest` to `runs-on: self-hosted`, and replace the `with:` block with:

   ```yaml
           with:
             provider: openai                          # any OpenAI-compatible server
             base-url: http://my-model-server:8000/v1  # vLLM; Ollama uses port 11434
             model: llama3.1:70b                       # the model name your server serves
             min-severity: medium
   ```

   If your server needs a key, store it as a secret and add `openai-api-key: ${{ secrets.MODEL_API_KEY }}`.

**Good to know:**

- Workflow files under `.github/workflows` are left alone by default, because the standard token can't push changes
  to them. To include them, pass a personal access token with the `workflow` scope as `github-token` and set
  `include-workflows: true`.
- Don't trigger this workflow from `pull_request_target` or from forks. It sends code to the model and holds a token
  that can write to your repository.

### B. On your computer

1. **Check Python.** Run `python3 --version`; you need 3.10 or newer.
2. **Install the fixer** (it installs the scanner too):

   ```bash
   pip install "agentic-top10-fix[anthropic] @ git+https://github.com/Adyanullah-Khan/agentic-top10-fix@v0.1.0"
   ```

3. **Choose the model.**
   - **Claude:** `export ANTHROPIC_API_KEY="your-key-here"` on macOS/Linux, or
     `$env:ANTHROPIC_API_KEY="your-key-here"` in Windows PowerShell.
   - **Your own model:** nothing to set now; you'll pass `--base-url` and `--model` in step 5.
   - **No AI:** add `--provider none` to the commands below.
4. **Go to your agent project and save your work:** `cd path/to/your-agent`, then commit any changes so that
   `git status` is clean. That way every fix can be reviewed and undone with git.
5. **Preview the fixes (nothing is written yet):**

   ```bash
   agentic-top10-fix .
   # with your own model:
   agentic-top10-fix . --base-url http://my-model-server:11434/v1 --model llama3.1:70b
   ```

   You'll see a diff of every proposed change, then a summary of what is fixed, open, and needs a decision.
6. **Apply them:** run `agentic-top10-fix . --apply`. Add `--verify-cmd "pytest -q"` to automatically drop any
   file's fix that makes your tests fail.
7. **Review and commit.** Look at `git diff`, run your tests, and commit. To undo everything instead, run
   `git checkout -- .`.
8. **Re-scan to confirm:** `agentic-top10 .`

## Command-line reference

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
