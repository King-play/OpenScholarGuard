"""Data models for guarded ingestion outputs."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

from openscholarguard.models import Severity, _json_ready
from openscholarguard.rules.models import RulePack


class IngestStatus(str, Enum):
    """Outcome of a guarded ingestion run."""

    READY = "ready"
    BLOCKED = "blocked"
    EMPTY = "empty"


@dataclass(frozen=True)
class IngestOptions:
    """Configuration for document ingestion."""

    profile: str = "rag"
    block_on: Severity = Severity.HIGH
    allow_risk: bool = False
    chunk_size: int = 1200
    chunk_overlap: int = 120
    min_chunk_chars: int = 40
    include_findings: bool = True
    rule_packs: tuple[RulePack, ...] = field(default_factory=tuple, repr=False, compare=False)


@dataclass(frozen=True)
class IngestChunk:
    """A sanitized chunk suitable for downstream RAG ingestion."""

    id: str
    text: str
    source_path: str
    ordinal: int
    start_char: int
    end_char: int
    sha256: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return _json_ready(asdict(self))


@dataclass(frozen=True)
class IngestResult:
    """Complete guarded ingestion result."""

    target: str
    status: IngestStatus
    profile: str
    block_on: Severity
    risk_score: int
    max_severity: Severity
    chunks: list[IngestChunk]
    sanitized_text: str
    findings: list[dict[str, Any]]
    removed: list[dict[str, Any]]
    warnings: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return _json_ready(asdict(self))

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)
