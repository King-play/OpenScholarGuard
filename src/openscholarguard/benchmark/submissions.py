"""Submission and leaderboard helpers for benchmark results."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional, Union

from openscholarguard.benchmark.models import (
    AttackFamily,
    BenchmarkEvaluation,
    BenchmarkMetrics,
    BenchmarkSampleResult,
    Leaderboard,
    LeaderboardEntry,
)
from openscholarguard.models import Severity, utc_now


def create_leaderboard_entry(
    evaluation: BenchmarkEvaluation,
    *,
    system: str,
    version: str,
    runner: str = "openscholarguard",
    url: Optional[str] = None,
    notes: Optional[str] = None,
) -> LeaderboardEntry:
    """Convert a benchmark evaluation into a leaderboard submission entry."""

    return LeaderboardEntry(
        system=system,
        version=version,
        dataset=evaluation.dataset,
        dataset_version=evaluation.version,
        profile=evaluation.profile,
        fail_on=evaluation.fail_on,
        metrics=evaluation.metrics,
        submitted_at=utc_now(),
        runner=runner,
        url=url,
        notes=notes,
    )


def write_leaderboard_entry(entry: LeaderboardEntry, output: Union[str, Path]) -> Path:
    """Write a leaderboard entry JSON file."""

    output_path = Path(output).expanduser()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(entry.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return output_path


def load_benchmark_evaluation(path: Union[str, Path]) -> BenchmarkEvaluation:
    """Load a benchmark evaluation JSON file."""

    evaluation_path = Path(path).expanduser()
    payload = json.loads(evaluation_path.read_text(encoding="utf-8"))
    metrics_payload = payload.get("metrics", {})
    if not isinstance(metrics_payload, dict):
        raise ValueError("Benchmark evaluation field 'metrics' must be an object.")
    samples_payload = payload.get("samples", [])
    if not isinstance(samples_payload, list):
        raise ValueError("Benchmark evaluation field 'samples' must be a list.")
    return BenchmarkEvaluation(
        dataset=str(payload["dataset"]),
        version=str(payload.get("version", "unknown")),
        profile=str(payload.get("profile", "ai-review")),
        fail_on=Severity(str(payload.get("fail_on", Severity.HIGH.value))),
        metrics=_metrics_from_dict(metrics_payload),
        samples=[_sample_from_dict(item) for item in samples_payload if isinstance(item, dict)],
        warnings=[str(item) for item in payload.get("warnings", []) if isinstance(item, str)],
    )


def load_leaderboard_entry(path: Union[str, Path]) -> LeaderboardEntry:
    """Load one leaderboard entry JSON file."""

    entry_path = Path(path).expanduser()
    payload = json.loads(entry_path.read_text(encoding="utf-8"))
    return _entry_from_dict(payload)


def load_leaderboard_entries(paths: list[Union[str, Path]]) -> list[LeaderboardEntry]:
    """Load leaderboard entries from files or directories."""

    entries: list[LeaderboardEntry] = []
    for raw_path in paths:
        path = Path(raw_path).expanduser()
        if path.is_dir():
            for entry_file in sorted(path.glob("*.json")):
                entries.append(load_leaderboard_entry(entry_file))
        else:
            entries.append(load_leaderboard_entry(path))
    return entries


def build_leaderboard(
    entries: list[LeaderboardEntry],
    *,
    name: str = "ScholarGuardBench",
    dataset: Optional[str] = None,
    dataset_version: Optional[str] = None,
) -> Leaderboard:
    """Create a sorted leaderboard from submission entries."""

    if not entries:
        raise ValueError("At least one leaderboard entry is required.")
    selected_dataset = dataset or entries[0].dataset
    selected_version = dataset_version or entries[0].dataset_version
    filtered_entries = [
        entry
        for entry in entries
        if entry.dataset == selected_dataset and entry.dataset_version == selected_version
    ]
    if not filtered_entries:
        raise ValueError(f"No entries match dataset {selected_dataset} {selected_version}.")
    return Leaderboard(
        name=name,
        dataset=selected_dataset,
        dataset_version=selected_version,
        generated_at=utc_now(),
        entries=sort_leaderboard_entries(filtered_entries),
    )


def sort_leaderboard_entries(entries: list[LeaderboardEntry]) -> list[LeaderboardEntry]:
    """Sort by detector recall, F1, accuracy, then system name."""

    return sorted(
        entries,
        key=lambda entry: (
            -entry.metrics.detector_recall,
            -entry.metrics.f1,
            -entry.metrics.accuracy,
            entry.system.lower(),
            entry.version.lower(),
        ),
    )


def _entry_from_dict(payload: dict[str, Any]) -> LeaderboardEntry:
    metrics_payload = payload.get("metrics", {})
    if not isinstance(metrics_payload, dict):
        raise ValueError("Leaderboard entry field 'metrics' must be an object.")
    return LeaderboardEntry(
        system=str(payload["system"]),
        version=str(payload.get("version", "unknown")),
        dataset=str(payload["dataset"]),
        dataset_version=str(payload.get("dataset_version", "unknown")),
        profile=str(payload.get("profile", "ai-review")),
        fail_on=Severity(str(payload.get("fail_on", Severity.HIGH.value))),
        metrics=_metrics_from_dict(metrics_payload),
        submitted_at=str(payload.get("submitted_at", "")),
        runner=str(payload.get("runner", "openscholarguard")),
        url=_optional_str(payload.get("url")),
        notes=_optional_str(payload.get("notes")),
    )


def _sample_from_dict(payload: dict[str, Any]) -> BenchmarkSampleResult:
    return BenchmarkSampleResult(
        case_id=str(payload["case_id"]),
        family=AttackFamily(str(payload["family"])),
        target=str(payload.get("target", "")),
        expected_malicious=bool(payload.get("expected_malicious", False)),
        predicted_malicious=bool(payload.get("predicted_malicious", False)),
        expected_detectors=[str(item) for item in payload.get("expected_detectors", [])],
        matched_detectors=[str(item) for item in payload.get("matched_detectors", [])],
        missing_detectors=[str(item) for item in payload.get("missing_detectors", [])],
        unexpected_detectors=[str(item) for item in payload.get("unexpected_detectors", [])],
        max_severity=Severity(str(payload.get("max_severity", Severity.INFO.value))),
        risk_score=int(payload.get("risk_score", 0)),
        passed=bool(payload.get("passed", False)),
    )


def _metrics_from_dict(payload: dict[str, Any]) -> BenchmarkMetrics:
    return BenchmarkMetrics(
        total=int(payload.get("total", 0)),
        true_positive=int(payload.get("true_positive", 0)),
        true_negative=int(payload.get("true_negative", 0)),
        false_positive=int(payload.get("false_positive", 0)),
        false_negative=int(payload.get("false_negative", 0)),
        precision=float(payload.get("precision", 0.0)),
        recall=float(payload.get("recall", 0.0)),
        f1=float(payload.get("f1", 0.0)),
        accuracy=float(payload.get("accuracy", 0.0)),
        detector_recall=float(payload.get("detector_recall", 0.0)),
    )


def _optional_str(value: object) -> Optional[str]:
    return str(value) if value is not None else None
