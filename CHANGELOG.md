# Changelog

## v0.1.0 (2026-10-04)

First release.

- Reads agentic-top10-scan JSON/SARIF reports or runs the scanner itself.
- 12 deterministic codemods (no LLM), 34 LLM playbooks, 11 rules reported for a human decision.
- Claude backend (claude-opus-5-5, adaptive thinking, structured output, prompt caching, server-side refusal
  fallback) and an OpenAI-compatible backend for OpenAI or self-hosted models.
- Every patch is syntax-checked, checked for scanner suppression and large deletions, and re-scanned; rejected
  patches are fed back to the model for another round.
- Secret redaction before any LLM call; dry run by default; `--verify-cmd` drops patches that break tests.
- GitHub Action that opens a pull request with a Markdown summary.
