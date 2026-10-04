"""Both LLM backends against local mock servers: request shape, parsing, refusal and fallback handling."""
import json

import anthropic
import pytest

from agentic_top10_fix.llm import (DEFAULT_ANTHROPIC_MODEL, PATCH_SCHEMA, AnthropicProvider, LLMError,
                                   OpenAICompatibleProvider, redact_secrets)

from conftest import anthropic_sse

PATCH = {"edits": [{"find": "a", "replace": "b", "rule_id": "ATS-ASI05-01"}], "unfixable": [], "summary": "ok"}


def claude(server):
    client = anthropic.Anthropic(api_key="test-key", base_url=server.url, max_retries=0)
    return AnthropicProvider(client=client)


def test_anthropic_request_shape_and_parsing(mock_server):
    mock_server.replies.append((200, {"Content-Type": "text/event-stream"}, anthropic_sse(json.dumps(PATCH))))
    proposal = claude(mock_server).propose("PROMPT", redact_secrets("x"))
    assert [(e.find, e.replace, e.rule_id) for e in proposal.edits] == [("a", "b", "ATS-ASI05-01")]
    assert proposal.output_tokens == 55 and proposal.input_tokens == 1020
    req = mock_server.requests[0]
    body = req["json"]
    assert body["model"] == DEFAULT_ANTHROPIC_MODEL == "claude-opus-5-5"
    assert body["stream"] is True and body["max_tokens"] == 64000
    assert body["thinking"] == {"type": "adaptive"}
    assert body["output_config"] == {"effort": "high", "format": {"type": "json_schema", "schema": PATCH_SCHEMA}}
    assert body["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert body["fallbacks"] == "default"
    assert "server-side-fallback-2026-07-01" in req["headers"].get("anthropic-beta", "")
    assert body["messages"] == [{"role": "user", "content": "PROMPT"}]


def test_anthropic_refusal_and_truncation(mock_server):
    mock_server.replies.append((200, {"Content-Type": "text/event-stream"}, anthropic_sse("", "refusal")))
    with pytest.raises(LLMError, match="declined"):
        claude(mock_server).propose("P", redact_secrets("x"))
    mock_server.replies.append((200, {"Content-Type": "text/event-stream"}, anthropic_sse('{"edits": [', "max_tokens")))
    with pytest.raises(LLMError, match="cut off"):
        claude(mock_server).propose("P", redact_secrets("x"))


def test_anthropic_http_errors_become_llm_errors(mock_server):
    mock_server.replies.append((401, {"Content-Type": "application/json"},
                                {"type": "error", "error": {"type": "authentication_error", "message": "bad key"}}))
    with pytest.raises(LLMError, match="authentication"):
        claude(mock_server).propose("P", redact_secrets("x"))


def test_openai_compatible_falls_back_on_response_format(mock_server):
    mock_server.replies.append((400, {}, {"error": {"message": "response_format json_schema not supported"}}))
    mock_server.replies.append((200, {}, {"choices": [{"message": {"content": "```json\n" + json.dumps(PATCH) + "\n```"}}],
                                          "usage": {"prompt_tokens": 7, "completion_tokens": 3}}))
    provider = OpenAICompatibleProvider(model="llama3.1:70b", base_url=mock_server.url + "/v1", api_key="")
    proposal = provider.propose("PROMPT", redact_secrets("x"))
    assert proposal.edits[0].replace == "b" and proposal.input_tokens == 7
    first, second = (r["json"] for r in mock_server.requests)
    assert first["response_format"]["type"] == "json_schema"
    assert second["response_format"] == {"type": "json_object"}
    assert mock_server.requests[0]["path"] == "/v1/chat/completions"
    assert "Authorization" not in mock_server.requests[0]["headers"]


def test_redaction_round_trip():
    secret = "Zq8" + "Lm2Pw9Xr4Tn7Vb1Kc5Hd3Jf6"
    red = redact_secrets(f'A = 1\nAPI_KEY = "{secret}"\n')
    assert secret not in red.text and "__REDACTED_SECRET_1__" in red.text
    assert red.restore('API_KEY = "__REDACTED_SECRET_1__"') == f'API_KEY = "{secret}"'
