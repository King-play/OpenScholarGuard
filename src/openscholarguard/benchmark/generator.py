"""Generate reproducible benchmark documents."""

from __future__ import annotations

import re
from pathlib import Path

from openscholarguard.benchmark.datasets import get_builtin_dataset
from openscholarguard.benchmark.models import BenchmarkDataset, GeneratedSample, write_manifest


def generate_documents(
    dataset: BenchmarkDataset,
    output_dir: str | Path,
    *,
    extension: str = ".md",
    include_manifest: bool = True,
) -> list[GeneratedSample]:
    """Render benchmark cases into document files."""

    suffix = extension if extension.startswith(".") else f".{extension}"
    target_dir = Path(output_dir).expanduser()
    target_dir.mkdir(parents=True, exist_ok=True)

    samples: list[GeneratedSample] = []
    for case in dataset.cases:
        path = target_dir / f"{_safe_filename(case.id)}{suffix}"
        path.write_text(case.render(), encoding="utf-8")
        samples.append(
            GeneratedSample(
                case_id=case.id,
                path=str(path),
                expected_malicious=case.expected_malicious,
                expected_detectors=case.expected_detectors,
                minimum_severity=case.minimum_severity,
                family=case.family,
            )
        )

    if include_manifest:
        write_manifest(samples, target_dir / "manifest.json")

    return samples


def generate_builtin_dataset(
    name: str,
    output_dir: str | Path,
    *,
    extension: str = ".md",
    include_manifest: bool = True,
) -> list[GeneratedSample]:
    return generate_documents(
        get_builtin_dataset(name),
        output_dir,
        extension=extension,
        include_manifest=include_manifest,
    )


def _safe_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._") or "sample"
