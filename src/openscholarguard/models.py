"""Core data models used by scanners, reports, and integrations."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional, Union


class Severity(str, Enum):
    """Finding severity values ordered by operational risk."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


SEVERITY_SCORE: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 20,
    Severity.MEDIUM: 45,
    Severity.HIGH: 75,
    Severity.CRITICAL: 95,
}


def utc_now() -> str:
    """Return a stable UTC timestamp for reports."""

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass(frozen=True)
class Location:
    """A human-readable location inside a document."""

    path: str
    page: Optional[int] = None
    line: Optional[int] = None
    section: Optional[str] = None
    field: Optional[str] = None
    block: Optional[int] = None
    span: Optional[int] = None

    def label(self) -> str:
        parts: list[str] = [self.path]
        if self.page is not None:
            parts.append(f"page {self.page}")
        if self.line is not None:
            parts.append(f"line {self.line}")
        if self.section:
            parts.append(self.section)
        if self.field:
            parts.append(self.field)
        return ": ".join(parts)


@dataclass(frozen=True)
class Finding:
    """A single detector result."""

    id: str
    detector_id: str
    title: str
    severity: Severity
    confidence: float
    location: Location
    snippet: str
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    tags: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ScanSummary:
    """Aggregated view of a scan result."""

    total_findings: int
    by_severity: dict[str, int]
    risk_score: int
    max_severity: Severity


@dataclass(frozen=True)
class ScanResult:
    """Complete output from a document scan."""

    target: str
    profile: str
    scanned_at: str
    summary: ScanSummary
    findings: list[Finding]
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return _json_ready(asdict(self))

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def has_at_least(self, severity: Severity) -> bool:
        threshold = SEVERITY_RANK[severity]
        return any(SEVERITY_RANK[finding.severity] >= threshold for finding in self.findings)


@dataclass(frozen=True)
class RemovedItem:
    """A document fragment removed or rewritten by the sanitizer."""

    reason: str
    location: Location
    snippet: str
    detector_id: Optional[str] = None


@dataclass(frozen=True)
class SanitizeResult:
    """Output of a sanitize operation."""

    target: str
    profile: str
    sanitized_at: str
    text: str
    removed: list[RemovedItem]
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return _json_ready(asdict(self))


def build_summary(findings: list[Finding]) -> ScanSummary:
    counts = {severity.value: 0 for severity in Severity}
    max_severity = Severity.INFO
    risk_score = 0
    for finding in findings:
        counts[finding.severity.value] += 1
        if SEVERITY_RANK[finding.severity] > SEVERITY_RANK[max_severity]:
            max_severity = finding.severity
        risk_score = max(risk_score, SEVERITY_SCORE[finding.severity])

    if findings:
        confidence_adjustment = min(5, round(sum(f.confidence for f in findings) / len(findings) * 5))
        risk_score = min(100, risk_score + confidence_adjustment)

    return ScanSummary(
        total_findings=len(findings),
        by_severity=counts,
        risk_score=risk_score,
        max_severity=max_severity,
    )


def make_finding_id(
    detector_id: str,
    location: Location,
    title: str,
    snippet: str,
) -> str:
    """Create a deterministic short identifier for a finding."""

    payload = "|".join(
        [
            detector_id,
            location.path,
            str(location.page),
            str(location.line),
            str(location.field),
            title,
            snippet[:240],
        ]
    )
    digest = hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()
    return f"osg-{digest[:12]}"


def normalize_path(path: Union[str, Path]) -> str:
    return str(Path(path).expanduser())


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda finding: (
            -SEVERITY_RANK[finding.severity],
            finding.location.path,
            finding.location.page or 0,
            finding.location.line or 0,
            finding.detector_id,
            finding.title,
        ),
    )


def _json_ready(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _json_ready(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_ready(item) for item in value]
    return value
