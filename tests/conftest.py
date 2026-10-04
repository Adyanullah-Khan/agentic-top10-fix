import json
import textwrap
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from agentic_top10_fix.issues import scan_issues
from agentic_top10_fix.llm import Proposal
from agentic_top10_fix.patching import Edit


def write(root: Path, files: dict) -> Path:
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(content).lstrip("\n"), encoding="utf-8")
    return root


@pytest.fixture
def project(tmp_path):
    def _make(files: dict):
        write(tmp_path, files)
        return tmp_path, scan_issues(tmp_path)
    return _make


class FakeProvider:
    """Scripted LLM: each call pops the next response (a Proposal, a callable(prompt)->Proposal, or an exception)."""

    name = "fake"
    model = "fake-model"

    def __init__(self, *responses):
        self.responses = list(responses)
        self.prompts = []

    def propose(self, prompt, redaction):
        self.prompts.append(prompt)
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        if callable(item):
            item = item(prompt)
        return Proposal([Edit(redaction.restore(e.find), redaction.restore(e.replace), e.rule_id)
                         for e in item.edits], item.unfixable, item.summary)


def proposal(*edits, unfixable=(), summary="fixed"):
    return Proposal([Edit(f, r, rule) for f, r, rule in edits], list(unfixable), summary)


class MockServer:
    """Tiny HTTP server that records requests and replies from a queue of (status, headers, body) tuples."""

    def __init__(self):
        self.requests = []
        self.replies = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                outer.requests.append({"path": self.path, "headers": dict(self.headers), "json": json.loads(body)})
                status, headers, payload = outer.replies.pop(0)
                data = payload.encode() if isinstance(payload, str) else json.dumps(payload).encode()
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()


@pytest.fixture
def mock_server():
    server = MockServer()
    yield server
    server.close()


def anthropic_sse(text: str, stop_reason: str = "end_turn") -> str:
    events = [
        ("message_start", {"type": "message_start", "message": {
            "id": "msg_test", "type": "message", "role": "assistant", "model": "claude-opus-5-5", "content": [],
            "stop_reason": None, "stop_sequence": None,
            "usage": {"input_tokens": 120, "output_tokens": 1, "cache_read_input_tokens": 900}}}),
        ("content_block_start", {"type": "content_block_start", "index": 0,
                                 "content_block": {"type": "text", "text": ""}}),
        ("content_block_delta", {"type": "content_block_delta", "index": 0,
                                 "delta": {"type": "text_delta", "text": text}}),
        ("content_block_stop", {"type": "content_block_stop", "index": 0}),
        ("message_delta", {"type": "message_delta", "delta": {"stop_reason": stop_reason, "stop_sequence": None},
                           "usage": {"output_tokens": 55}}),
        ("message_stop", {"type": "message_stop"}),
    ]
    return "".join(f"event: {name}\ndata: {json.dumps(data)}\n\n" for name, data in events)
