from __future__ import annotations

from pathlib import Path

from openscholarguard.benchmark.datasets import get_builtin_dataset
from openscholarguard.benchmark.evaluator import evaluate_benchmark, evaluate_manifest
from openscholarguard.benchmark.generator import generate_documents
from openscholarguard.benchmark.leaderboard import (
    render_benchmark_html,
    render_benchmark_markdown,
    render_benchmark_text,
    render_leaderboard_html,
    render_leaderboard_markdown,
    render_leaderboard_text,
    write_benchmark_report,
    write_leaderboard_report,
)
from openscholarguard.benchmark.publisher import publish_builtin_benchmark
from openscholarguard.benchmark.submissions import (
    build_leaderboard,
    create_leaderboard_entry,
    load_benchmark_evaluation,
    load_leaderboard_entries,
    write_leaderboard_entry,
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


def test_scholarguardbench_v0_has_formal_metadata() -> None:
    dataset = get_builtin_dataset("scholarguardbench-v0")

    families = {case.family.value for case in dataset.cases}

    assert dataset.version == "0.1.0"
    assert len(dataset.cases) == 21
    assert len([case for case in dataset.cases if case.expected_malicious]) == 19
    assert len([case for case in dataset.cases if not case.expected_malicious]) == 2
    assert {
        "ai_slop",
        "fake_citation",
        "homoglyph",
        "image_text",
        "metadata_injection",
        "ocr_layer",
        "rag_contamination",
        "role_play_hijack",
        "tool_exfiltration",
    }.issubset(families)
    assert all(case.attack_goal for case in dataset.cases)
    assert all(case.target_workflow for case in dataset.cases)
    assert all(case.visibility for case in dataset.cases)
    assert all(case.modality for case in dataset.cases)


def test_generate_documents_writes_manifest(tmp_path: Path) -> None:
    dataset = get_builtin_dataset("docpibench-mini")

    samples = generate_documents(dataset, tmp_path)

    assert len(samples) == len(dataset.cases)
    assert (tmp_path / "manifest.json").exists()
    assert all(Path(sample.path).exists() for sample in samples)


def test_generate_documents_preserves_benchmark_metadata(tmp_path: Path) -> None:
    dataset = get_builtin_dataset("scholarguardbench-v0")

    samples = generate_documents(dataset, tmp_path)

    sample = next(item for item in samples if item.case_id == "rag_poisoned_context")
    assert sample.attack_goal == "contaminate downstream retrieval-augmented answers"
    assert sample.target_workflow == "rag-ingestion"
    assert sample.visibility == "retrieved-context"
    assert sample.modality == "text"


def test_evaluate_benchmark_passes_builtin_dataset(tmp_path: Path) -> None:
    dataset = get_builtin_dataset("docpibench-mini")

    evaluation = evaluate_benchmark(dataset, work_dir=tmp_path, fail_on=Severity.HIGH)

    assert evaluation.metrics.total == len(dataset.cases)
    assert evaluation.metrics.recall == 1.0
    assert evaluation.metrics.false_negative == 0
    assert all(sample.passed for sample in evaluation.samples)


def test_evaluate_benchmark_passes_scholarguardbench_v0(tmp_path: Path) -> None:
    dataset = get_builtin_dataset("scholarguardbench-v0")

    evaluation = evaluate_benchmark(dataset, work_dir=tmp_path, fail_on=Severity.HIGH)

    assert evaluation.metrics.total == 21
    assert evaluation.metrics.recall == 1.0
    assert evaluation.metrics.detector_recall == 1.0
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


def test_leaderboard_entry_roundtrip_and_renderers(tmp_path: Path) -> None:
    dataset = get_builtin_dataset("docpibench-mini")
    evaluation = evaluate_benchmark(dataset, work_dir=tmp_path / "work", fail_on=Severity.HIGH)
    entry = create_leaderboard_entry(
        evaluation,
        system="OpenScholarGuard",
        version="0.1.0",
        url="https://github.com/King-play/OpenScholarGuard",
        notes="deterministic scanner baseline",
    )
    entry_path = write_leaderboard_entry(entry, tmp_path / "entries" / "openscholarguard.json")

    entries = load_leaderboard_entries([entry_path])
    leaderboard = build_leaderboard(entries)
    text = render_leaderboard_text(leaderboard)
    markdown = render_leaderboard_markdown(leaderboard)
    html = render_leaderboard_html(leaderboard)

    assert leaderboard.entries[0].system == "OpenScholarGuard"
    assert "ScholarGuardBench" in text
    assert "OpenScholarGuard" in markdown
    assert "<table>" in html


def test_write_leaderboard_report(tmp_path: Path) -> None:
    dataset = get_builtin_dataset("docpibench-mini")
    evaluation = evaluate_benchmark(dataset, work_dir=tmp_path / "work", fail_on=Severity.HIGH)
    entry = create_leaderboard_entry(evaluation, system="OpenScholarGuard", version="0.1.0")
    leaderboard = build_leaderboard([entry])
    report = tmp_path / "leaderboard.html"

    write_leaderboard_report(leaderboard, report)

    assert report.exists()
    assert "Leaderboard" in report.read_text(encoding="utf-8")


def test_load_benchmark_evaluation(tmp_path: Path) -> None:
    dataset = get_builtin_dataset("docpibench-mini")
    evaluation = evaluate_benchmark(dataset, work_dir=tmp_path / "work", fail_on=Severity.HIGH)
    evaluation_path = tmp_path / "evaluation.json"
    evaluation_path.write_text(evaluation.to_json(), encoding="utf-8")

    loaded = load_benchmark_evaluation(evaluation_path)

    assert loaded.dataset == evaluation.dataset
    assert loaded.metrics.f1 == evaluation.metrics.f1
    assert len(loaded.samples) == len(evaluation.samples)


def test_publish_builtin_benchmark_writes_publication_bundle(tmp_path: Path) -> None:
    publication = publish_builtin_benchmark(tmp_path / "publication")

    assert publication.evaluation_json.exists()
    assert publication.evaluation_markdown.exists()
    assert publication.evaluation_html.exists()
    assert publication.entry_json.exists()
    assert publication.leaderboard_json.exists()
    assert publication.leaderboard_markdown.exists()
    assert publication.leaderboard_html.exists()
    assert "scholarguardbench-v0" in publication.evaluation_markdown.read_text(encoding="utf-8")
    assert "OpenScholarGuard" in publication.leaderboard_markdown.read_text(encoding="utf-8")
