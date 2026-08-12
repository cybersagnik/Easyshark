"""Dependency-free health and metrics endpoint for the monitor daemon."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Optional

from .observability import snapshot


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        token = getattr(self.server, "auth_token", None)
        if token and self.headers.get("X-EasyShark-Token") != token:
            self.send_response(401)
            self.end_headers()
            return
        if self.path == "/health":
            body = {"status": "ok"}
            health_fn = getattr(self.server, "health_fn", None)
            if health_fn:
                try:
                    body.update(health_fn())
                except Exception:
                    body["status"] = "degraded"
        elif self.path == "/metrics":
            body = snapshot()
        else:
            self.send_response(404)
            self.end_headers()
            return
        raw = json.dumps(body).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *_args):
        return


class HealthServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 8765,
                 token: str | None = None,
                 status_fn: Optional[Callable[[], dict]] = None):
        self.server = ThreadingHTTPServer((host, port), _Handler)
        self.server.auth_token = token
        self.server.health_fn = status_fn
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True, name="easyshark-health")

    def start(self) -> None:
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
