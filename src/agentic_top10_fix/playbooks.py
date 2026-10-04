"""How each scanner rule gets fixed.

mode:
  codemod  a deterministic fixer handles common shapes; anything it can't handle goes to the LLM
  llm      the LLM writes the patch, guided by the playbook text below
  manual   reported with guidance only. Used where a "fix" would need a decision only the maintainers can make,
           or where editing a declaration (agent manifest, A2A card) without changing the running system would
           just make the scanner quiet without making anything safer.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict


@dataclass(frozen=True)
class Playbook:
    mode: str
    guidance: str


P = Playbook
PLAYBOOKS: Dict[str, Playbook] = {
    # ASI01 Agent Goal Hijack
    "ATS-ASI01-01": P("llm", "Wrap the untrusted value in explicit delimiters before it enters the prompt, e.g. "
                      "f\"<untrusted_external_data>\\n{page}\\n</untrusted_external_data>\", and add one sentence to the "
                      "prompt saying text inside those tags is data, never instructions. If it is placed in a system "
                      "prompt, move it to a user-role message instead."),
    "ATS-ASI01-02": P("llm", "Keep the system prompt a constant. Move the user-controlled value into a separate "
                          "user-role message (or a clearly delimited <user_input> block in the user message)."),
    "ATS-ASI01-03": P("llm", "Remove or reword the injection-style text. In a tool description, keep only a plain "
                          "statement of what the tool does and its parameters; delete hidden directives, <IMPORTANT> "
                          "blocks and references to secrets or files the tool does not need."),
    "ATS-ASI01-04": P("codemod", "Delete the invisible/bidi characters from the line."),
    "ATS-ASI01-05": P("llm", "Remove the templated image/link or the instruction to send data to a URL. If the "
                          "feature is needed, render links only from an allowlisted domain with no dynamic query string."),
    "ATS-ASI01-06": P("llm", "In GitHub workflows, never interpolate ${{ github.event.* }} text into run: or an "
                          "agent prompt directly. Pass it through an env: variable (e.g. env: ISSUE_BODY: ${{ "
                          "github.event.issue.body }}) and reference \"$ISSUE_BODY\" in the script, or let the agent "
                          "fetch the issue itself."),
    "ATS-ASI01-07": P("llm", "Add an if: condition to the agent job, e.g. if: contains(fromJSON('[\"OWNER\",\"MEMBER\","
                          "\"COLLABORATOR\"]'), github.event.comment.author_association || "
                          "github.event.issue.author_association)."),
    # ASI02 Tool Misuse
    "ATS-ASI02-01": P("llm", "Never pass model-chosen text to a shell. Map the model's choice through a fixed table "
                          "of argument lists, e.g. ALLOWED_COMMANDS = {\"status\": [\"git\", \"status\"]}; argv = "
                          "ALLOWED_COMMANDS[name] (raise ValueError for unknown names), then subprocess.run(argv, "
                          "shell=False, timeout=30). Prefer a Python API over a subprocess when one exists. If the "
                          "tool exists to run arbitrary commands, restrict it to the table rather than removing it."),
    "ATS-ASI02-02": P("llm", "Confine the path: base = Path(ALLOWED_ROOT).resolve(); target = (base / name).resolve(); "
                          "if not target.is_relative_to(base): raise ValueError(...). Define ALLOWED_ROOT as a module "
                          "constant (reuse an existing workspace/root variable if the file has one)."),
    "ATS-ASI02-03": P("llm", "Validate the URL before fetching: allow only https, check urlparse(url).hostname "
                          "against an ALLOWED_HOSTS set (module constant), and pass timeout=. Do not forward "
                          "credentials to model-chosen hosts."),
    "ATS-ASI02-04": P("llm", "Use parameterised queries (cursor.execute(\"... WHERE x = ?\", (value,))). If the model "
                          "legitimately writes SQL, add a guard that allows a single SELECT statement only (reject ';', "
                          "and statements starting with anything other than SELECT/WITH) and note that the connection "
                          "should use a read-only role."),
    "ATS-ASI02-05": P("llm", "Replace the general-purpose toolkit with narrow tools, or restrict it: "
                          "FileManagementToolkit(root_dir=..., selected_tools=[\"read_file\", \"list_directory\"]), "
                          "remove allow_dangerous_requests=True, drop shell/REPL tools. If you cannot replace it "
                          "without changing behaviour, list it as unfixable with the reason."),
    "ATS-ASI02-06": P("codemod", "Re-enable certificate verification (verify=True / remove verify=False; "
                              "rejectUnauthorized: true)."),
    "ATS-ASI02-07": P("manual", "Grant the tool the exact scopes it needs in the system that issues its credentials, "
                             "then update the manifest to match."),
    # ASI03 Identity & Privilege
    "ATS-ASI03-01": P("codemod", "Load the credential from the environment (os.environ[\"NAME\"] / process.env.NAME). "
                              "Also rotate the credential: it remains in git history."),
    "ATS-ASI03-02": P("llm", "Remove the secret from the prompt text entirely. Tools that need a credential should "
                          "read it themselves at call time; the model never needs to see it."),
    "ATS-ASI03-03": P("llm", "Add a minimal permissions: block to the agent job: contents: read, plus "
                          "pull-requests: write or issues: write only if the job comments. Remove write-all."),
    "ATS-ASI03-04": P("manual", "Move the model call to a server route and remove dangerouslyAllowBrowser / the "
                             "public key variable; this needs an architectural change."),
    "ATS-ASI03-05": P("manual", "Add authentication to the endpoint itself, then declare it in the manifest."),
    "ATS-ASI03-06": P("llm", "Remove privileged: true / --privileged, Docker socket and host-root mounts, host "
                          "network/PID, and cap_add ALL/SYS_ADMIN. For a Dockerfile, add a non-root user "
                          "(RUN useradd -m agent / USER agent) before CMD."),
    "ATS-ASI03-07": P("llm", "Set allow_delegation=False unless delegation is essential; if it is, leave the code and "
                          "list it as unfixable with the reason."),
    # ASI04 Supply chain
    "ATS-ASI04-01": P("codemod", "Pin the package to an exact version (pkg@1.2.3 / pkg==1.2.3) or the image to a "
                              "digest. Needs --online to look up the current version."),
    "ATS-ASI04-02": P("llm", "Remove trust_remote_code=True (or set False); load weights with safetensors; pin hub "
                          "pulls to a commit hash if one is known, otherwise list as unfixable. Never exec downloaded "
                          "content."),
    "ATS-ASI04-03": P("manual", "Pin exact versions or commit a lockfile (uv lock / pip-compile / npm ci) so "
                             "upgrades are deliberate."),
    "ATS-ASI04-04": P("codemod", "Pin the action to the full commit SHA of the current tag (owner/repo@<sha> # "
                              "v1). Needs --online to resolve the SHA."),
    "ATS-ASI04-05": P("manual", "Upgrade to a version that fixes the advisory."),
    "ATS-ASI04-06": P("llm", "Replace the dynamic import with an explicit mapping: PLUGINS = {\"name\": "
                          "\"package.module\"}; look the name up and raise on unknown names."),
    "ATS-ASI04-07": P("codemod", "Set enableAllProjectMcpServers to false and approve servers individually."),
    # ASI05 Code execution
    "ATS-ASI05-01": P("llm", "Replace eval/exec with a safe alternative: ast.literal_eval for literals, json.loads for "
                          "data, or a small explicit parser/dispatch table (e.g. an operator map for a calculator)."),
    "ATS-ASI05-02": P("llm", "Never execute model output. If the feature genuinely runs generated code, route it "
                          "through a function named run_in_sandbox(code) that raises NotImplementedError with a message "
                          "to configure a container/VM sandbox, so nothing executes on the host by default. For SQL, "
                          "apply the single-SELECT guard from ATS-ASI02-04."),
    "ATS-ASI05-03": P("llm", "Use subprocess.run([...], shell=False) with an argument list (shlex.split only on "
                          "trusted constants), add check=True and timeout=."),
    "ATS-ASI05-04": P("codemod", "Run generated code in a sandbox: use_docker=True for AutoGen, "
                              "code_execution_mode=\"safe\" for CrewAI, executor_type=\"docker\" for smolagents, remove "
                              "allow_dangerous_code=True, drop dangerous authorized imports."),
    "ATS-ASI05-05": P("codemod", "Use yaml.safe_load; replace pickle with json for data you control; never load "
                              "pickles from untrusted locations (allow_dangerous_deserialization=True must go)."),
    # ASI06 Memory
    "ATS-ASI06-01": P("llm", "Validate content before it is stored: add a function validate_memory_entry(text) "
                          "that rejects empty/oversized text and obvious injection markers, call it before the write, "
                          "and store provenance metadata (source, timestamp) with the entry."),
    "ATS-ASI06-02": P("llm", "Create memory per session/user instead of at module level (e.g. a dict keyed by "
                          "session_id, or construct it inside the request handler), and pass user_id= to mem0 calls."),
    "ATS-ASI06-03": P("llm", "Add a tenant/user metadata filter to the retrieval call (filter={\"user_id\": "
                          "user_id} or the store's equivalent)."),
    "ATS-ASI06-04": P("manual", "Implement per-user scoping, write validation and expiry in the memory layer, then "
                             "declare them in the manifest."),
    # ASI07 Inter-agent
    "ATS-ASI07-01": P("codemod", "Use https:// for remote agent/MCP/LLM endpoints (the server must support TLS)."),
    "ATS-ASI07-02": P("manual", "Enforce authentication on the agent server, then declare securitySchemes in the "
                             "agent card."),
    "ATS-ASI07-03": P("llm", "Require authentication on the route: in FastAPI add a dependency "
                          "(user=Depends(verify_api_key)) that checks an Authorization/X-API-Key header against "
                          "os.environ; in Flask add an equivalent check at the top of the handler that returns 401."),
    "ATS-ASI07-04": P("llm", "Read the bind host from the environment with a safe default: host=os.environ.get("
                          "\"HOST\", \"127.0.0.1\"). Containers can then set HOST=0.0.0.0 explicitly."),
    "ATS-ASI07-05": P("manual", "Add mutual TLS/OAuth2 and message signing between agents, then declare it."),
    # ASI08 Cascading failures
    "ATS-ASI08-01": P("codemod", "Set an explicit, modest limit (max_iterations=15, max_turns=20, max_iter=20, "
                              "recursion_limit=50). For while True loops around LLM calls, add a counter with a "
                              "MAX_STEPS constant and break when it is reached."),
    "ATS-ASI08-02": P("codemod", "Pass timeout=30 (or the file's existing timeout constant) to the call."),
    "ATS-ASI08-03": P("llm", "Bound the retries: @retry(stop=stop_after_attempt(5), wait=wait_exponential("
                          "multiplier=1, max=30)) (import both from tenacity); for backoff use max_tries=5."),
    "ATS-ASI08-04": P("llm", "Log the exception (logging.getLogger(__name__).exception(...)) and return an explicit "
                          "error result instead of silently passing."),
    "ATS-ASI08-05": P("manual", "Enforce iteration/runtime/cost limits in the agent runtime, then declare them."),
    # ASI09 Human trust
    "ATS-ASI09-01": P("llm", "Add a human approval step before the irreversible action. Prefer the framework's "
                          "mechanism if the file already uses it (LangGraph interrupt(), OpenAI Agents needs_approval="
                          "True); otherwise add a parameter approved: bool = False and return a message asking for "
                          "confirmation when it is not True, without performing the action."),
    "ATS-ASI09-02": P("codemod", "Turn approval back on: defaultMode \"default\", chat.tools.autoApprove false, remove "
                              "auto_approve/auto_run=True, require_approval \"always\" for write tools. Replace blanket "
                              "Bash(*) rules with specific commands."),
    "ATS-ASI09-03": P("llm", "Delete the deceptive or manipulative instruction; if a persona is needed, keep the name "
                          "but allow the agent to disclose that it is an AI when asked."),
    "ATS-ASI09-04": P("llm", "Replace the instruction with: confirm with the user before irreversible or "
                          "high-impact actions (sending, paying, deleting, deploying)."),
    "ATS-ASI09-05": P("manual", "Add an approval gate to the tool implementation, then set requires_approval: true."),
    # ASI10 Rogue agents
    "ATS-ASI10-01": P("llm", "Remove the agent's ability to write its own code, prompts or settings. If the tool "
                          "writes notes, confine it to a dedicated data directory that excludes source and config "
                          "files."),
    "ATS-ASI10-02": P("llm", "Remove the persistence mechanism (cron/systemd/launchctl/shell-profile/authorized_keys "
                          "writes, nohup/setsid). Return a message telling the user how to schedule the job "
                          "themselves instead."),
    "ATS-ASI10-03": P("llm", "Remove runtime package installation from the tool; return an error telling the user "
                          "to add the dependency to the project instead."),
    "ATS-ASI10-04": P("llm", "Add audit logging to each tool: logger = logging.getLogger(__name__) at module level, "
                          "and logger.info(\"tool=<name> args=%r\", ...) at the start of each tool (do not log "
                          "secrets)."),
    "ATS-ASI10-05": P("manual", "Build a kill switch and audit log into the deployment, then declare them."),
}


def playbook_for(rule_id: str) -> Playbook:
    return PLAYBOOKS.get(rule_id, Playbook("manual", "No automatic fix is defined for this rule."))


def playbook_text() -> str:
    """All playbooks, rendered for the (cached) system prompt."""
    lines = []
    for rule_id, pb in PLAYBOOKS.items():
        if pb.mode != "manual":
            lines.append(f"- {rule_id}: {pb.guidance}")
    return "\n".join(lines)
