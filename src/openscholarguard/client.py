"""Zero-dependency Python client for the OpenScholarGuard HTTP API."""

from __future__ import annotations

import json
from typing import Any, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class OpenScholarGuardClientError(RuntimeError):
    """Raised when the API returns an error response or cannot be reached."""

    def __init__(self, message: str, *, status_code: Optional[int] = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class OpenScholarGuardClient:
    """Small standard-library client for OpenScholarGuard's local HTTP API."""

    def __init__(self, base_url: str = "http://127.0.0.1:8765", *, timeout: float = 30.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def health(self) -> dict[str, Any]:
        return self._get("/health")

    def openapi(self) -> dict[str, Any]:
        return self._get("/openapi.json")

    def scan_path(
        self,
        path: str,
        *,
        profile: str = "ai-review",
        rule_packs: Optional[list[str]] = None,
        llm_audit: bool = False,
        llm_options: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        return self._post(
            "/v1/scan",
            _with_scan_options(
                {"path": path, "profile": profile},
                rule_packs=rule_packs,
                llm_audit=llm_audit,
                llm_options=llm_options,
            ),
        )

    def scan_text(
        self,
        text: str,
        *,
        name: str = "submission.md",
        profile: str = "ai-review",
        rule_packs: Optional[list[str]] = None,
        llm_audit: bool = False,
        llm_options: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        return self._post(
            "/v1/scan",
            _with_scan_options(
                {"text": text, "name": name, "profile": profile},
                rule_packs=rule_packs,
                llm_audit=llm_audit,
                llm_options=llm_options,
            ),
        )

    def sanitize_path(
        self,
        path: str,
        *,
        profile: str = "ai-review",
        rule_packs: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        return self._post("/v1/sanitize", _with_rule_packs({"path": path, "profile": profile}, rule_packs))

    def sanitize_text(
        self,
        text: str,
        *,
        name: str = "submission.md",
        profile: str = "ai-review",
        rule_packs: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        return self._post(
            "/v1/sanitize",
            _with_rule_packs({"text": text, "name": name, "profile": profile}, rule_packs),
        )

    def ingest_path(
        self,
        path: str,
        *,
        profile: str = "rag",
        block_on: str = "high",
        allow_risk: bool = False,
        chunk_size: int = 1200,
        chunk_overlap: int = 120,
        min_chunk_chars: int = 40,
        include_findings: bool = True,
        rule_packs: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        return self._post(
            "/v1/ingest",
            _with_rule_packs(
                {
                "path": path,
                "profile": profile,
                "block_on": block_on,
                "allow_risk": allow_risk,
                "chunk_size": chunk_size,
                "chunk_overlap": chunk_overlap,
                "min_chunk_chars": min_chunk_chars,
                "include_findings": include_findings,
                },
                rule_packs,
            ),
        )

    def ingest_text(
        self,
        text: str,
        *,
        name: str = "submission.md",
        profile: str = "rag",
        block_on: str = "high",
        allow_risk: bool = False,
        chunk_size: int = 1200,
        chunk_overlap: int = 120,
        min_chunk_chars: int = 40,
        include_findings: bool = True,
        rule_packs: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        return self._post(
            "/v1/ingest",
            _with_rule_packs(
                {
                "text": text,
                "name": name,
                "profile": profile,
                "block_on": block_on,
                "allow_risk": allow_risk,
                "chunk_size": chunk_size,
                "chunk_overlap": chunk_overlap,
                "min_chunk_chars": min_chunk_chars,
                "include_findings": include_findings,
                },
                rule_packs,
            ),
        )

    def _get(self, path: str) -> dict[str, Any]:
        request = Request(self._url(path), method="GET")
        return self._send(request)

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        request = Request(
            self._url(path),
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        return self._send(request)

    def _send(self, request: Request) -> dict[str, Any]:
        try:
            with urlopen(request, timeout=self.timeout) as response:
                return _decode_json(response.read())
        except HTTPError as exc:
            payload = _decode_json(exc.read())
            message = str(payload.get("message") or payload.get("error") or exc)
            raise OpenScholarGuardClientError(message, status_code=exc.code) from exc
        except URLError as exc:
            raise OpenScholarGuardClientError(str(exc.reason)) from exc

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"


def _decode_json(data: bytes) -> dict[str, Any]:
    payload = json.loads(data.decode("utf-8"))
    if not isinstance(payload, dict):
        raise OpenScholarGuardClientError("Expected JSON object response.")
    return payload


def _with_rule_packs(payload: dict[str, Any], rule_packs: Optional[list[str]]) -> dict[str, Any]:
    if rule_packs:
        payload["rule_packs"] = rule_packs
    return payload


def _with_scan_options(
    payload: dict[str, Any],
    *,
    rule_packs: Optional[list[str]],
    llm_audit: bool,
    llm_options: Optional[dict[str, Any]],
) -> dict[str, Any]:
    _with_rule_packs(payload, rule_packs)
    if llm_audit:
        payload["llm_audit"] = True
    if llm_options:
        payload["llm_options"] = llm_options
    return payload
