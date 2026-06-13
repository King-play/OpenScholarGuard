"""LLM provider clients used by optional audit workflows."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from openscholarguard.exceptions import OpenScholarGuardError
from openscholarguard.llm.models import (
    FindingReview,
    LLMAuditRequest,
    LLMAuditResult,
    LLMAuditVerdict,
)


class LLMAuditError(OpenScholarGuardError):
    """Raised when an LLM audit provider cannot return usable output."""


class LLMAuditClient(ABC):
    """Provider interface for LLM audit requests."""

    @abstractmethod
    def audit(self, request: LLMAuditRequest) -> LLMAuditResult:
        """Return a structured audit result."""


class OpenAIResponsesClient(LLMAuditClient):
    """Minimal OpenAI Responses API client using the Python standard library."""

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        base_url: str = "https://api.openai.com/v1",
        timeout_seconds: float = 30.0,
    ) -> None:
        if not api_key:
            raise LLMAuditError("OpenAI API key is required.")
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    def audit(self, request: LLMAuditRequest) -> LLMAuditResult:
        response_payload = self._post(
            {
                "model": self.model,
                "instructions": request.instructions,
                "input": request.input_text,
                "text": {"format": _audit_json_schema()},
            }
        )
        output_text = _extract_output_text(response_payload)
        payload = _loads_object(output_text)
        return llm_audit_result_from_dict(
            payload,
            provider="openai",
            model=self.model,
            metadata={
                "response_id": response_payload.get("id"),
                "usage": response_payload.get("usage", {}),
            },
        )

    def _post(self, payload: dict[str, Any]) -> dict[str, Any]:
        data = json.dumps(payload).encode("utf-8")
        request = Request(
            f"{self.base_url}/responses",
            data=data,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                return _loads_object(response.read().decode("utf-8"))
        except HTTPError as exc:
            message = exc.read().decode("utf-8", errors="replace")
            raise LLMAuditError(f"OpenAI Responses API request failed with HTTP {exc.code}: {message}") from exc
        except URLError as exc:
            raise LLMAuditError(f"OpenAI Responses API request failed: {exc.reason}") from exc


class StaticLLMAuditClient(LLMAuditClient):
    """Deterministic client for tests and offline integrations."""

    def __init__(self, result: LLMAuditResult) -> None:
        self.result = result

    def audit(self, request: LLMAuditRequest) -> LLMAuditResult:
        return self.result


def llm_audit_result_from_dict(
    payload: dict[str, Any],
    *,
    provider: str,
    model: str,
    metadata: dict[str, Any] | None = None,
) -> LLMAuditResult:
    """Convert a provider JSON payload into an audit result."""

    reviews_payload = payload.get("reviews", [])
    if not isinstance(reviews_payload, list):
        raise LLMAuditError("LLM audit response field 'reviews' must be a list.")
    reviews = [_review_from_dict(item) for item in reviews_payload if isinstance(item, dict)]
    return LLMAuditResult(
        provider=provider,
        model=model,
        verdict=LLMAuditVerdict(str(payload.get("verdict", LLMAuditVerdict.UNCERTAIN.value))),
        confidence=_clamp_float(payload.get("confidence", 0.0)),
        summary=str(payload.get("summary", "")),
        reviews=reviews,
        warnings=[str(item) for item in payload.get("warnings", []) if isinstance(item, str)],
        metadata=metadata or {},
    )


def _review_from_dict(payload: dict[str, Any]) -> FindingReview:
    return FindingReview(
        finding_id=str(payload.get("finding_id", "")),
        verdict=LLMAuditVerdict(str(payload.get("verdict", LLMAuditVerdict.UNCERTAIN.value))),
        confidence=_clamp_float(payload.get("confidence", 0.0)),
        rationale=str(payload.get("rationale", "")),
        recommended_action=str(payload.get("recommended_action", "")),
    )


def _audit_json_schema() -> dict[str, Any]:
    verdicts = [verdict.value for verdict in LLMAuditVerdict]
    return {
        "type": "json_schema",
        "name": "openscholarguard_llm_audit",
        "strict": True,
        "schema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["verdict", "confidence", "summary", "reviews", "warnings"],
            "properties": {
                "verdict": {"type": "string", "enum": verdicts},
                "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                "summary": {"type": "string"},
                "warnings": {"type": "array", "items": {"type": "string"}},
                "reviews": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": [
                            "finding_id",
                            "verdict",
                            "confidence",
                            "rationale",
                            "recommended_action",
                        ],
                        "properties": {
                            "finding_id": {"type": "string"},
                            "verdict": {"type": "string", "enum": verdicts},
                            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                            "rationale": {"type": "string"},
                            "recommended_action": {"type": "string"},
                        },
                    },
                },
            },
        },
    }


def _extract_output_text(payload: dict[str, Any]) -> str:
    if isinstance(payload.get("output_text"), str):
        return str(payload["output_text"])
    chunks: list[str] = []
    for output_item in payload.get("output", []):
        if not isinstance(output_item, dict):
            continue
        for content_item in output_item.get("content", []):
            if isinstance(content_item, dict) and isinstance(content_item.get("text"), str):
                chunks.append(str(content_item["text"]))
    if chunks:
        return "".join(chunks)
    raise LLMAuditError("OpenAI Responses API response did not include text output.")


def _loads_object(raw: str) -> dict[str, Any]:
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise LLMAuditError(f"LLM audit response was not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise LLMAuditError("LLM audit response must be a JSON object.")
    return payload


def _clamp_float(value: object) -> float:
    if not isinstance(value, (float, int, str)):
        return 0.0
    try:
        number = float(value)
    except ValueError:
        return 0.0
    return min(1.0, max(0.0, number))
