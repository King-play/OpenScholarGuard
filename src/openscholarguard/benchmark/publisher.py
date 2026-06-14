"""Create shareable benchmark publication bundles."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Union

from openscholarguard.benchmark.evaluator import evaluate_builtin_dataset
from openscholarguard.benchmark.leaderboard import write_benchmark_report, write_leaderboard_report
from openscholarguard.benchmark.submissions import (
    build_leaderboard,
    create_leaderboard_entry,
    write_leaderboard_entry,
)
from openscholarguard.models import Severity


@dataclass(frozen=True)
class BenchmarkPublication:
    """Paths written for a benchmark publication bundle."""

    output_dir: Path
    evaluation_json: Path
    evaluation_markdown: Path
    evaluation_html: Path
    entry_json: Path
    leaderboard_json: Path
    leaderboard_markdown: Path
    leaderboard_html: Path

    def to_dict(self) -> dict[str, str]:
        return {
            "output_dir": str(self.output_dir),
            "evaluation_json": str(self.evaluation_json),
            "evaluation_markdown": str(self.evaluation_markdown),
            "evaluation_html": str(self.evaluation_html),
            "entry_json": str(self.entry_json),
            "leaderboard_json": str(self.leaderboard_json),
            "leaderboard_markdown": str(self.leaderboard_markdown),
            "leaderboard_html": str(self.leaderboard_html),
        }


def publish_builtin_benchmark(
    output_dir: Union[str, Path],
    *,
    dataset: str = "docpibench-mini",
    profile: str = "ai-review",
    fail_on: Severity = Severity.HIGH,
    system: str = "OpenScholarGuard",
    version: str = "0.1.0",
    runner: str = "openscholarguard",
    url: Optional[str] = "https://github.com/King-play/OpenScholarGuard",
    notes: Optional[str] = "deterministic scanner baseline",
    leaderboard_name: str = "ScholarGuardBench",
) -> BenchmarkPublication:
    """Evaluate the built-in benchmark and write a publication-ready bundle."""

    output_path = Path(output_dir).expanduser()
    output_path.mkdir(parents=True, exist_ok=True)
    work_dir = output_path / "generated-samples"
    entries_dir = output_path / "entries"
    entries_dir.mkdir(parents=True, exist_ok=True)

    evaluation = evaluate_builtin_dataset(
        dataset,
        profile=profile,
        fail_on=fail_on,
        work_dir=work_dir,
    )
    entry = create_leaderboard_entry(
        evaluation,
        system=system,
        version=version,
        runner=runner,
        url=url,
        notes=notes,
    )
    leaderboard = build_leaderboard([entry], name=leaderboard_name)

    evaluation_json = output_path / "evaluation.json"
    evaluation_markdown = output_path / "evaluation.md"
    evaluation_html = output_path / "evaluation.html"
    entry_json = entries_dir / _entry_filename(system, version)
    leaderboard_json = output_path / "leaderboard.json"
    leaderboard_markdown = output_path / "leaderboard.md"
    leaderboard_html = output_path / "leaderboard.html"

    write_benchmark_report(evaluation, evaluation_json, fmt="json")
    write_benchmark_report(evaluation, evaluation_markdown, fmt="md")
    write_benchmark_report(evaluation, evaluation_html, fmt="html")
    write_leaderboard_entry(entry, entry_json)
    write_leaderboard_report(leaderboard, leaderboard_json, fmt="json")
    write_leaderboard_report(leaderboard, leaderboard_markdown, fmt="md")
    write_leaderboard_report(leaderboard, leaderboard_html, fmt="html")

    return BenchmarkPublication(
        output_dir=output_path,
        evaluation_json=evaluation_json,
        evaluation_markdown=evaluation_markdown,
        evaluation_html=evaluation_html,
        entry_json=entry_json,
        leaderboard_json=leaderboard_json,
        leaderboard_markdown=leaderboard_markdown,
        leaderboard_html=leaderboard_html,
    )


def _entry_filename(system: str, version: str) -> str:
    raw = f"{system}-{version}".lower()
    safe = "".join(char if char.isalnum() else "-" for char in raw).strip("-")
    while "--" in safe:
        safe = safe.replace("--", "-")
    return f"{safe or 'entry'}.json"
