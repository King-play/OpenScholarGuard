"""Dependency-free HTTP API for OpenScholarGuard."""

from __future__ import annotations

import json
from collections.abc import Callable
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from openscholarguard.exceptions import OpenScholarGuardError
from openscholarguard.server.api import handle_health, handle_ingest, handle_sanitize, handle_scan
from openscholarguard.server.openapi import openapi_schema

JsonHandler = Callable[[dict[str, Any]], dict[str, Any]]


ROUTES: dict[tuple[str, str], JsonHandler] = {
    ("POST", "/v1/scan"): handle_scan,
    ("POST", "/v1/sanitize"): handle_sanitize,
    ("POST", "/v1/ingest"): handle_ingest,
}


def create_server(host: str = "127.0.0.1", port: int = 8765) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), OpenScholarGuardHandler)


def serve(host: str = "127.0.0.1", port: int = 8765) -> None:
    server = create_server(host=host, port=port)
    try:
        print(f"OpenScholarGuard API listening on http://{host}:{port}")
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down OpenScholarGuard API")
    finally:
        server.server_close()


class OpenScholarGuardHandler(BaseHTTPRequestHandler):
    server_version = "OpenScholarGuardHTTP/0.1"

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path in {"/health", "/v1/health"}:
            self._send_json(HTTPStatus.OK, handle_health())
            return
        if path in {"/openapi.json", "/v1/openapi.json"}:
            self._send_json(HTTPStatus.OK, openapi_schema())
            return
        if path in {"/", "/v1"}:
            self._send_json(HTTPStatus.OK, _index())
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found", "path": path})

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        route = ROUTES.get(("POST", path))
        if route is None:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found", "path": path})
            return
        try:
            payload = self._read_json()
            result = route(payload)
        except (OpenScholarGuardError, OSError, ValueError, json.JSONDecodeError) as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": type(exc).__name__, "message": str(exc)})
            return
        self._send_json(HTTPStatus.OK, result)

    def log_message(self, format: str, *args: object) -> None:
        if getattr(self.server, "quiet", False):
            return
        super().log_message(format, *args)

    def _read_json(self) -> dict[str, Any]:
        content_length = int(self.headers.get("Content-Length", "0"))
        if content_length <= 0:
            return {}
        body = self.rfile.read(content_length)
        payload = json.loads(body.decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("JSON request body must be an object.")
        return payload

    def _send_json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def _index() -> dict[str, object]:
    return {
        "service": "openscholarguard",
        "routes": {
            "GET /health": "service health",
            "GET /openapi.json": "OpenAPI schema",
            "POST /v1/scan": {"path": "paper.pdf", "profile": "ai-review"},
            "POST /v1/sanitize": {"path": "paper.pdf", "profile": "ai-review"},
            "POST /v1/ingest": {"path": "paper.pdf", "profile": "rag"},
        },
    }
