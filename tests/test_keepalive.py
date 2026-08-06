"""Connection-reuse test for the OpenRouter keep-alive transport.

Spins up a local HTTP server and verifies that sequential
_openrouter_call_messages calls reuse a single TCP connection
(requests.Session keep-alive) instead of opening one per call.
No external network, no LLM."""
import json
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ai.llm_client import LLMClient


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    connections = 0

    def setup(self):
        _Handler.connections += 1
        super().setup()

    def _send_json(self, obj, code=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        self._send_json({"choices": [{"message": {
            "role": "assistant", "content": "ok"}}], "usage": {}})

    def do_GET(self):
        self._send_json({})

    def log_message(self, *args):  # silence
        pass


class TestOpenRouterKeepAlive(unittest.TestCase):
    def setUp(self):
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.thread = threading.Thread(target=self.srv.serve_forever,
                                       daemon=True)
        self.thread.start()
        self.port = self.srv.server_address[1]
        _Handler.connections = 0

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def _client(self):
        client = LLMClient()
        client.openrouter_enabled = True
        client.openrouter_api_key = "sk-test"
        client.openrouter_base_url = f"http://127.0.0.1:{self.port}"
        client._openrouter_reachable_cache = True
        client._openrouter_last_probe = time.monotonic()
        return client

    def test_two_calls_reuse_one_connection(self):
        client = self._client()
        msg = [{"role": "user", "content": "hello"}]
        r1 = client._openrouter_call_messages(
            messages=msg, model_type="planner", temperature=0.1, max_tokens=10)
        r2 = client._openrouter_call_messages(
            messages=msg, model_type="planner", temperature=0.1, max_tokens=10)
        self.assertIsNotNone(r1)
        self.assertIsNotNone(r2)
        self.assertEqual(r1.choices[0].message.content, "ok")
        self.assertEqual(r2.choices[0].message.content, "ok")
        self.assertLessEqual(
            _Handler.connections, 1,
            f"expected 1 connection (keep-alive), saw {_Handler.connections}")

    def test_four_calls_reuse_one_connection(self):
        client = self._client()
        msg = [{"role": "user", "content": "hello"}]
        for _ in range(4):
            r = client._openrouter_call_messages(
                messages=msg, model_type="planner", temperature=0.1,
                max_tokens=10)
            self.assertIsNotNone(r)
        self.assertLessEqual(
            _Handler.connections, 1,
            f"expected 1 connection across 4 calls, saw {_Handler.connections}")


if __name__ == "__main__":
    unittest.main()
