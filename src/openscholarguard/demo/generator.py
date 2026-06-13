"""Generate a shareable local demo bundle."""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Union

from openscholarguard.benchmark.datasets import get_builtin_dataset
from openscholarguard.benchmark.generator import generate_documents
from openscholarguard.benchmark.models import BenchmarkDataset
from openscholarguard.demo.html import render_demo_html
from openscholarguard.ingest.models import IngestOptions
from openscholarguard.ingest.pipeline import ingest_path
from openscholarguard.models import Severity
from openscholarguard.reporting import render_html_report
from openscholarguard.rules.registry import load_rule_pack
from openscholarguard.rules.verification import verify_rule_pack
from openscholarguard.sanitizer import sanitize_path
from openscholarguard.scanner import scan_path


@dataclass(frozen=True)
class DemoArtifacts:
    """Paths written by the demo generator."""

    output_dir: Path
    index_html: Path
    scan_json: Path
    scan_html: Path
    sanitized_markdown: Path
    sanitizer_manifest: Path
    ingest_manifest: Path
    chunks_jsonl: Path
    rule_pack_verification: Path
    sample_document: Path
    attack_gallery_manifest: Path

    def to_dict(self) -> dict[str, str]:
        return {
            "output_dir": str(self.output_dir),
            "index_html": str(self.index_html),
            "scan_json": str(self.scan_json),
            "scan_html": str(self.scan_html),
            "sanitized_markdown": str(self.sanitized_markdown),
            "sanitizer_manifest": str(self.sanitizer_manifest),
            "ingest_manifest": str(self.ingest_manifest),
            "chunks_jsonl": str(self.chunks_jsonl),
            "rule_pack_verification": str(self.rule_pack_verification),
            "sample_document": str(self.sample_document),
            "attack_gallery_manifest": str(self.attack_gallery_manifest),
        }


def generate_demo(
    output_dir: Union[str, Path],
    *,
    sample_path: Union[str, Path] = "examples/injected_paper.md",
    rule_pack_path: Union[str, Path] = "examples/rule-pack.json",
    profile: str = "ai-review",
    overwrite: bool = False,
) -> DemoArtifacts:
    """Generate a complete, static demo bundle."""

    output_path = Path(output_dir).expanduser()
    if output_path.exists() and any(output_path.iterdir()) and not overwrite:
        raise ValueError(f"Demo output directory already exists and is not empty: {output_path}")
    output_path.mkdir(parents=True, exist_ok=True)

    sample = Path(sample_path).expanduser()
    copied_sample = output_path / sample.name
    shutil.copyfile(sample, copied_sample)

    rule_pack = load_rule_pack(rule_pack_path)
    scan = scan_path(sample, profile=profile, rule_packs=[rule_pack])
    sanitized = sanitize_path(sample, profile=profile, rule_packs=[rule_pack])
    ingest = ingest_path(
        sample,
        options=IngestOptions(
            profile="rag",
            block_on=Severity.HIGH,
            allow_risk=True,
            min_chunk_chars=20,
            rule_packs=(rule_pack,),
        ),
    )
    verification = verify_rule_pack(rule_pack, require_tests=True)

    scan_json = output_path / "scan.json"
    scan_html = output_path / "scan.html"
    sanitized_markdown = output_path / "sanitized.md"
    sanitizer_manifest = output_path / "sanitize.manifest.json"
    ingest_manifest = output_path / "ingest.manifest.json"
    chunks_jsonl = output_path / "chunks.jsonl"
    rule_pack_verification = output_path / "rule-pack.verify.json"
    gallery_dir = output_path / "attack-gallery"
    attack_gallery_manifest = output_path / "attack-gallery.json"
    index_html = output_path / "index.html"

    _write_json(scan_json, scan.to_dict())
    scan_html.write_text(render_html_report(scan), encoding="utf-8")
    sanitized_markdown.write_text(sanitized.text, encoding="utf-8")
    _write_json(sanitizer_manifest, sanitized.to_dict())
    _write_json(ingest_manifest, ingest.to_dict())
    chunks_jsonl.write_text(
        "".join(json.dumps(chunk.to_dict(), sort_keys=True) + "\n" for chunk in ingest.chunks),
        encoding="utf-8",
    )
    _write_json(
        rule_pack_verification,
        {
            "passed": verification.passed,
            "fingerprint": verification.fingerprint,
            "tests": [
                {
                    "name": test.name,
                    "passed": test.passed,
                    "finding_count": test.finding_count,
                    "matched_rule_ids": list(test.matched_rule_ids),
                    "errors": list(test.errors),
                }
                for test in verification.tests
            ],
            "errors": list(verification.errors),
        },
    )
    gallery = _generate_attack_gallery(gallery_dir)
    _write_json(attack_gallery_manifest, gallery)
    index_html.write_text(
        render_demo_html(
            scan=scan,
            sanitized=sanitized,
            ingest=ingest,
            verification=verification,
            attack_gallery=gallery,
            artifacts={
                "scan_json": scan_json.name,
                "scan_html": scan_html.name,
                "sanitized_markdown": sanitized_markdown.name,
                "sanitizer_manifest": sanitizer_manifest.name,
                "ingest_manifest": ingest_manifest.name,
                "chunks_jsonl": chunks_jsonl.name,
                "rule_pack_verification": rule_pack_verification.name,
                "attack_gallery": attack_gallery_manifest.name,
                "sample_document": copied_sample.name,
            },
        ),
        encoding="utf-8",
    )

    return DemoArtifacts(
        output_dir=output_path,
        index_html=index_html,
        scan_json=scan_json,
        scan_html=scan_html,
        sanitized_markdown=sanitized_markdown,
        sanitizer_manifest=sanitizer_manifest,
        ingest_manifest=ingest_manifest,
        chunks_jsonl=chunks_jsonl,
        rule_pack_verification=rule_pack_verification,
        sample_document=copied_sample,
        attack_gallery_manifest=attack_gallery_manifest,
    )


def _write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _generate_attack_gallery(output_dir: Path) -> list[dict[str, object]]:
    dataset = get_builtin_dataset("docpibench-mini")
    attack_cases = [case for case in dataset.cases if case.expected_malicious][:10]
    samples = generate_documents(
        BenchmarkDataset(
            name="openscholarguard-attack-gallery",
            version=dataset.version,
            description="Ten synthetic document-borne prompt-injection examples for the static demo.",
            cases=attack_cases,
        ),
        output_dir,
        include_manifest=True,
    )
    sample_by_id = {sample.case_id: sample for sample in samples}
    return [
        {
            "id": case.id,
            "title": case.title,
            "family": case.family.value,
            "description": case.description,
            "minimum_severity": case.minimum_severity.value,
            "expected_detectors": case.expected_detectors,
            "tags": case.tags,
            "path": str(PurePosixPath("attack-gallery", Path(sample_by_id[case.id].path).name)),
            "payload_preview": case.payload[:280],
        }
        for case in attack_cases
    ]
