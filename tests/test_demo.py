from __future__ import annotations

import json
from pathlib import Path

from openscholarguard.cli import main
from openscholarguard.demo import generate_demo


def test_generate_demo_writes_shareable_artifacts(tmp_path: Path) -> None:
    artifacts = generate_demo(tmp_path / "demo")

    assert artifacts.index_html.exists()
    assert artifacts.scan_json.exists()
    assert artifacts.scan_html.exists()
    assert artifacts.sanitized_markdown.exists()
    assert artifacts.sanitizer_manifest.exists()
    assert artifacts.ingest_manifest.exists()
    assert artifacts.chunks_jsonl.exists()
    assert artifacts.rule_pack_verification.exists()
    assert artifacts.attack_gallery_manifest.exists()
    assert artifacts.sample_document.exists()

    html = artifacts.index_html.read_text(encoding="utf-8")
    scan = json.loads(artifacts.scan_json.read_text(encoding="utf-8"))
    verification = json.loads(artifacts.rule_pack_verification.read_text(encoding="utf-8"))
    gallery = json.loads(artifacts.attack_gallery_manifest.read_text(encoding="utf-8"))

    assert "OpenScholarGuard" in html
    assert "Ten synthetic attack examples" in html
    assert scan["summary"]["total_findings"] >= 1
    assert verification["passed"] is True
    assert len(gallery) == 10
    assert all("\\" not in item["path"] for item in gallery)
    assert all((artifacts.output_dir / item["path"]).exists() for item in gallery)


def test_generate_demo_refuses_non_empty_directory(tmp_path: Path) -> None:
    output_dir = tmp_path / "demo"
    output_dir.mkdir()
    (output_dir / "existing.txt").write_text("existing", encoding="utf-8")

    try:
        generate_demo(output_dir)
        raise AssertionError("Expected non-empty directory failure")
    except ValueError as exc:
        assert "already exists" in str(exc)


def test_cli_demo_generates_artifacts(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    output_dir = tmp_path / "demo"

    exit_code = main(["demo", "--output-dir", str(output_dir)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Demo written to" in captured.out
    assert (output_dir / "index.html").exists()
    assert (output_dir / "scan.json").exists()
