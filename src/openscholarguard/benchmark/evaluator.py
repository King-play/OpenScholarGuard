"""Benchmark evaluator for OpenScholarGuard scanners."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Optional

from openscholarguard.benchmark.datasets import get_builtin_dataset
from openscholarguard.benchmark.generator import generate_documents
from openscholarguard.benchmark.models import (
    BenchmarkDataset,
    BenchmarkEvaluation,
    BenchmarkMetrics,
    BenchmarkSampleResult,
    GeneratedSample,
    load_manifest,
)
from openscholarguard.models import SEVERITY_RANK, Severity
from openscholarguard.scanner import Scanner


def evaluate_builtin_dataset(
    name: str,
    *,
    profile: str = "ai-review",
    fail_on: Severity = Severity.HIGH,
    work_dir: Optional[str | Path] = None,
) -> BenchmarkEvaluation:
    return evaluate_benchmark(
        get_builtin_dataset(name),
        profile=profile,
        fail_on=fail_on,
        work_dir=work_dir,
    )


def evaluate_manifest(
    manifest: str | Path,
    *,
    dataset_name: str = "manifest",
    version: str = "local",
    profile: str = "ai-review",
    fail_on: Severity = Severity.HIGH,
) -> BenchmarkEvaluation:
    samples = load_manifest(manifest)
    return _evaluate_samples(
        samples,
        dataset_name=dataset_name,
        version=version,
        profile=profile,
        fail_on=fail_on,
    )


def evaluate_benchmark(
    dataset: BenchmarkDataset,
    *,
    profile: str = "ai-review",
    fail_on: Severity = Severity.HIGH,
    work_dir: Optional[str | Path] = None,
) -> BenchmarkEvaluation:
    target_dir = Path(work_dir).expanduser() if work_dir else Path(".openscholarguard-benchmark")
    samples = generate_documents(dataset, target_dir, include_manifest=True)
    return _evaluate_samples(
        samples,
        dataset_name=dataset.name,
        version=dataset.version,
        profile=profile,
        fail_on=fail_on,
    )


def _evaluate_samples(
    samples: Iterable[GeneratedSample],
    *,
    dataset_name: str,
    version: str,
    profile: str,
    fail_on: Severity,
) -> BenchmarkEvaluation:
    scanner = Scanner(profile=profile)
    sample_results: list[BenchmarkSampleResult] = []
    warnings: list[str] = []

    for sample in samples:
        scan = scanner.scan_path(sample.path)
        detector_ids = sorted({finding.detector_id for finding in scan.findings})
        actionable_detector_ids = sorted(
            {
                finding.detector_id
                for finding in scan.findings
                if SEVERITY_RANK[finding.severity] >= SEVERITY_RANK[fail_on]
            }
        )
        matched = sorted(set(sample.expected_detectors) & set(detector_ids))
        missing = sorted(set(sample.expected_detectors) - set(detector_ids))
        unexpected = sorted(set(actionable_detector_ids) - set(sample.expected_detectors))
        predicted_malicious = scan.has_at_least(fail_on)
        severity_ok = SEVERITY_RANK[scan.summary.max_severity] >= SEVERITY_RANK[sample.minimum_severity]

        if scan.errors:
            warnings.extend(f"{sample.case_id}: {error}" for error in scan.errors)

        passed = (
            predicted_malicious == sample.expected_malicious
            and not missing
            and (severity_ok or not sample.expected_malicious)
        )
        sample_results.append(
            BenchmarkSampleResult(
                case_id=sample.case_id,
                family=sample.family,
                target=sample.path,
                expected_malicious=sample.expected_malicious,
                predicted_malicious=predicted_malicious,
                expected_detectors=sample.expected_detectors,
                matched_detectors=matched,
                missing_detectors=missing,
                unexpected_detectors=unexpected,
                max_severity=scan.summary.max_severity,
                risk_score=scan.summary.risk_score,
                passed=passed,
            )
        )

    return BenchmarkEvaluation(
        dataset=dataset_name,
        version=version,
        profile=profile,
        fail_on=fail_on,
        metrics=_compute_metrics(sample_results),
        samples=sample_results,
        warnings=warnings,
    )


def _compute_metrics(samples: list[BenchmarkSampleResult]) -> BenchmarkMetrics:
    true_positive = sum(1 for sample in samples if sample.expected_malicious and sample.predicted_malicious)
    true_negative = sum(1 for sample in samples if not sample.expected_malicious and not sample.predicted_malicious)
    false_positive = sum(1 for sample in samples if not sample.expected_malicious and sample.predicted_malicious)
    false_negative = sum(1 for sample in samples if sample.expected_malicious and not sample.predicted_malicious)
    precision = _safe_div(true_positive, true_positive + false_positive)
    recall = _safe_div(true_positive, true_positive + false_negative)
    f1 = _safe_div(2 * precision * recall, precision + recall)
    accuracy = _safe_div(true_positive + true_negative, len(samples))

    expected_detector_total = sum(len(sample.expected_detectors) for sample in samples)
    matched_detector_total = sum(len(sample.matched_detectors) for sample in samples)
    detector_recall = _safe_div(matched_detector_total, expected_detector_total)

    return BenchmarkMetrics(
        total=len(samples),
        true_positive=true_positive,
        true_negative=true_negative,
        false_positive=false_positive,
        false_negative=false_negative,
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1=round(f1, 4),
        accuracy=round(accuracy, 4),
        detector_recall=round(detector_recall, 4),
    )


def _safe_div(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0
