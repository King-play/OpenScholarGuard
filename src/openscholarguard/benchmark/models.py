"""Data models for benchmark datasets, generated samples, and evaluation results."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from openscholarguard.models import Severity, _json_ready


class AttackFamily(str, Enum):
    """High-level families used by DocPIBench-style benchmark cases."""

    CLEAN = "clean"
    DIRECT_INSTRUCTION = "direct_instruction"
    REVIEW_MANIPULATION = "review_manipulation"
    RAG_EXFILTRATION = "rag_exfiltration"
    ENCODED_PAYLOAD = "encoded_payload"
    INVISIBLE_UNICODE = "invisible_unicode"
    HIDDEN_HTML = "hidden_html"
    HIDDEN_LATEX = "hidden_latex"
    MULTILINGUAL = "multilingual"
    CUSTOM_POLICY = "custom_policy"
    METADATA_INJECTION = "metadata_injection"
    CITATION_MANIPULATION = "citation_manipulation"
    OCR_LAYER = "ocr_layer"
    IMAGE_TEXT = "image_text"
    FAKE_CITATION = "fake_citation"
    RAG_CONTAMINATION = "rag_contamination"
    HOMOGLYPH = "homoglyph"
    ROLE_PLAY_HIJACK = "role_play_hijack"
    AI_SLOP = "ai_slop"
    TOOL_EXFILTRATION = "tool_exfiltration"


@dataclass(frozen=True)
class BenchmarkCase:
    """A synthetic benchmark case with expected scanner behavior."""

    id: str
    family: AttackFamily
    title: str
    description: str
    expected_malicious: bool
    expected_detectors: list[str]
    minimum_severity: Severity
    template: str
    payload: str = ""
    tags: list[str] = field(default_factory=list)
    attack_goal: str = ""
    target_workflow: str = ""
    visibility: str = "model-visible"
    modality: str = "text"
    source: str = "synthetic"

    def render(self) -> str:
        return self.template.format(payload=self.payload)


@dataclass(frozen=True)
class BenchmarkDataset:
    """A named set of benchmark cases."""

    name: str
    version: str
    description: str
    cases: list[BenchmarkCase]

    def to_dict(self) -> dict[str, Any]:
        return _json_ready(asdict(self))


@dataclass(frozen=True)
class GeneratedSample:
    """A generated benchmark document on disk."""

    case_id: str
    path: str
    expected_malicious: bool
    expected_detectors: list[str]
    minimum_severity: Severity
    family: AttackFamily
    tags: list[str] = field(default_factory=list)
    attack_goal: str = ""
    target_workflow: str = ""
    visibility: str = ""
    modality: str = ""
    source: str = "synthetic"

    def to_dict(self) -> dict[str, Any]:
        return _json_ready(asdict(self))


@dataclass(frozen=True)
class BenchmarkSampleResult:
    """Evaluation outcome for one benchmark case."""

    case_id: str
    family: AttackFamily
    target: str
    expected_malicious: bool
    predicted_malicious: bool
    expected_detectors: list[str]
    matched_detectors: list[str]
    missing_detectors: list[str]
    unexpected_detectors: list[str]
    max_severity: Severity
    risk_score: int
    passed: bool


@dataclass(frozen=True)
class BenchmarkMetrics:
    """Aggregate binary and detector-level benchmark metrics."""

    total: int
    true_positive: int
    true_negative: int
    false_positive: int
    false_negative: int
    precision: float
    recall: float
    f1: float
    accuracy: float
    detector_recall: float


@dataclass(frozen=True)
class BenchmarkEvaluation:
    """Complete benchmark evaluation output."""

    dataset: str
    version: str
    profile: str
    fail_on: Severity
    metrics: BenchmarkMetrics
    samples: list[BenchmarkSampleResult]
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return _json_ready(asdict(self))

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)


@dataclass(frozen=True)
class LeaderboardEntry:
    """A reproducible leaderboard submission for one benchmarked system."""

    system: str
    version: str
    dataset: str
    dataset_version: str
    profile: str
    fail_on: Severity
    metrics: BenchmarkMetrics
    submitted_at: str
    runner: str = "openscholarguard"
    url: Optional[str] = None
    notes: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return _json_ready(asdict(self))


@dataclass(frozen=True)
class Leaderboard:
    """A sorted collection of benchmark entries."""

    name: str
    dataset: str
    dataset_version: str
    generated_at: str
    entries: list[LeaderboardEntry]

    def to_dict(self) -> dict[str, Any]:
        return _json_ready(asdict(self))

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)


def write_manifest(samples: list[GeneratedSample], output: str | Path) -> Path:
    output_path = Path(output).expanduser()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"samples": [sample.to_dict() for sample in samples]}
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return output_path


def load_manifest(path: str | Path) -> list[GeneratedSample]:
    manifest_path = Path(path).expanduser()
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    samples: list[GeneratedSample] = []
    for item in payload.get("samples", []):
        samples.append(
            GeneratedSample(
                case_id=item["case_id"],
                path=item["path"],
                expected_malicious=bool(item["expected_malicious"]),
                expected_detectors=list(item["expected_detectors"]),
                minimum_severity=Severity(item["minimum_severity"]),
                family=AttackFamily(item["family"]),
                tags=list(item.get("tags", [])),
                attack_goal=str(item.get("attack_goal", "")),
                target_workflow=str(item.get("target_workflow", "")),
                visibility=str(item.get("visibility", "")),
                modality=str(item.get("modality", "")),
                source=str(item.get("source", "synthetic")),
            )
        )
    return samples


def maybe_severity(value: Optional[str], default: Severity) -> Severity:
    return Severity(value) if value else default
