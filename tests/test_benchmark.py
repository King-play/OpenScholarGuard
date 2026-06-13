from __future__ import annotations

from pathlib import Path

from openscholarguard.benchmark.datasets import get_builtin_dataset
from openscholarguard.benchmark.evaluator import evaluate_benchmark, evaluate_manifest
from openscholarguard.benchmark.generator import generate_documents
from openscholarguard.benchmark.leaderboard import (
    render_benchmark_html,
    render_benchmark_markdown,
    render_benchmark_text,
    write_benchmark_report,
)
from openscholarguard.models import Severity


def test_builtin_dataset_has_expected_coverage() -> None:
    dataset = get_builtin_dataset("docpibench-mini")

    families = {case.family.value for case in dataset.cases}

    assert dataset.version
    assert len([case for case in dataset.cases if case.expected_malicious]) == 10
    assert "clean" in families
    assert "review_manipulation" in families
    assert "citation_manipulation" in families
    assert all(case.id for case in dataset.cases)


def test_generate_documents_writes_manifest(tmp_path: Path) -> None:
    dataset = get_builtin_dataset("docpibench-mini")

    samples = generate_documents(dataset, tmp_path)

    assert len(samples) == len(dataset.cases)
    assert (tmp_path / "manifest.json").exists()
    assert all(Path(sample.path).exists() for sample in samples)


def test_evaluate_benchmark_passes_builtin_dataset(tmp_path: Path) -> None:
    dataset = get_builtin_dataset("docpibench-mini")

    evaluation = evaluate_benchmark(dataset, work_dir=tmp_path, fail_on=Severity.HIGH)

    assert evaluation.metrics.total == len(dataset.cases)
    assert evaluation.metrics.recall == 1.0
    assert evaluation.metrics.false_negative == 0
    assert all(sample.passed for sample in evaluation.samples)


def test_evaluate_manifest(tmp_path: Path) -> None:
    dataset = get_builtin_dataset("docpibench-mini")
    generate_documents(dataset, tmp_path)

    evaluation = evaluate_manifest(tmp_path / "manifest.json", fail_on=Severity.HIGH)

    assert evaluation.metrics.total == len(dataset.cases)
    assert evaluation.dataset == "manifest"


def test_benchmark_renderers_escape_html(tmp_path: Path) -> None:
    dataset = get_builtin_dataset("docpibench-mini")
    evaluation = evaluate_benchmark(dataset, work_dir=tmp_path, fail_on=Severity.HIGH)

    text = render_benchmark_text(evaluation)
    markdown = render_benchmark_markdown(evaluation)
    html = render_benchmark_html(evaluation)

    assert "OpenScholarGuard benchmark" in text
    assert "OpenScholarGuard Benchmark Report" in markdown
    assert "<table>" in html
    assert "docpibench-mini" in html


def test_write_benchmark_report(tmp_path: Path) -> None:
    dataset = get_builtin_dataset("docpibench-mini")
    evaluation = evaluate_benchmark(dataset, work_dir=tmp_path / "work", fail_on=Severity.HIGH)
    report = tmp_path / "benchmark.md"

    write_benchmark_report(evaluation, report)

    assert report.exists()
    assert "Benchmark Report" in report.read_text(encoding="utf-8")
