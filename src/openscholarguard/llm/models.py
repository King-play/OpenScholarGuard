"""Data models for optional LLM-assisted audit."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class LLMAuditVerdict(str, Enum):
    """LLM audit verdicts for scan findings."""

    CONFIRMED = "confirmed"
    LIKELY = "likely"
    UNCERTAIN = "uncertain"
    FALSE_POSITIVE = "false_positive"
    NEEDS_HUMAN_REVIEW = "needs_human_review"


@dataclass(frozen=True)
class FindingReview:
    """LLM review for one scanner finding."""

    finding_id: str
    verdict: LLMAuditVerdict
    confidence: float
    rationale: str
    recommended_action: str


@dataclass(frozen=True)
class LLMAuditConfig:
    """Runtime configuration for an LLM audit provider."""

    provider: str = "openai"
    model: str = "gpt-4.1-mini"
    api_key_env: str = "OPENAI_API_KEY"
    base_url: str = "https://api.openai.com/v1"
    timeout_seconds: float = 30.0
    max_findings: int = 12
    max_snippet_chars: int = 700
    require_findings: bool = False


@dataclass(frozen=True)
class LLMAuditResult:
    """Structured LLM audit result."""

    provider: str
    model: str
    verdict: LLMAuditVerdict
    confidence: float
    summary: str
    reviews: list[FindingReview]
    warnings: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return _json_ready(asdict(self))

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)


@dataclass(frozen=True)
class LLMAuditRequest:
    """Provider-independent prompt payload."""

    instructions: str
    input_text: str


def _json_ready(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _json_ready(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_ready(item) for item in value]
    return value
