"""Export guarded ingestion results."""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Optional, Union

from openscholarguard.ingest.models import IngestResult


def render_jsonl(result: IngestResult) -> str:
    return "".join(json.dumps(chunk.to_dict(), sort_keys=True) + "\n" for chunk in result.chunks)


def render_manifest(result: IngestResult) -> str:
    payload = result.to_dict()
    payload["chunks"] = [chunk.to_dict() for chunk in result.chunks]
    return json.dumps(payload, indent=2, sort_keys=True)


def write_ingest_outputs(
    result: IngestResult,
    output_dir: Union[str, Path],
    *,
    basename: Optional[str] = None,
    write_text: bool = True,
    write_jsonl: bool = True,
    write_manifest_file: bool = True,
) -> dict[str, Path]:
    target_dir = Path(output_dir).expanduser()
    target_dir.mkdir(parents=True, exist_ok=True)
    stem = basename or _safe_stem(Path(result.target).stem)
    outputs: dict[str, Path] = {}

    if write_text:
        text_path = target_dir / f"{stem}.clean.md"
        text_path.write_text(result.sanitized_text, encoding="utf-8")
        outputs["text"] = text_path
    if write_jsonl:
        jsonl_path = target_dir / f"{stem}.chunks.jsonl"
        jsonl_path.write_text(render_jsonl(result), encoding="utf-8")
        outputs["jsonl"] = jsonl_path
    if write_manifest_file:
        manifest_path = target_dir / f"{stem}.manifest.json"
        manifest_path.write_text(render_manifest(result), encoding="utf-8")
        outputs["manifest"] = manifest_path
    return outputs


def write_jsonl_collection(results: Iterable[IngestResult], output: Union[str, Path]) -> Path:
    output_path = Path(output).expanduser()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        for result in results:
            for chunk in result.chunks:
                handle.write(json.dumps(chunk.to_dict(), sort_keys=True) + "\n")
    return output_path


def _safe_stem(value: str) -> str:
    safe = "".join(char if char.isalnum() or char in {"-", "_", "."} else "_" for char in value)
    return safe.strip("._") or "document"
