from __future__ import annotations

from pathlib import Path

import pytest

from openscholarguard.pdf_gallery import generate_pdf_attack_gallery


def test_generate_pdf_attack_gallery_writes_artifacts(tmp_path: Path) -> None:
    pytest.importorskip("fitz")

    artifacts = generate_pdf_attack_gallery(tmp_path / "gallery")

    assert artifacts.index_html.exists()
    assert artifacts.manifest_json.exists()
    assert len(artifacts.cases) == 10
    assert "PDF Attack Gallery" in artifacts.index_html.read_text(encoding="utf-8")
    for case in artifacts.cases:
        assert (artifacts.output_dir / case.pdf_path).exists()
        assert (artifacts.output_dir / case.screenshot_path).exists()
        assert (artifacts.output_dir / case.scan_report_path).exists()
        assert (artifacts.output_dir / case.deep_audit_path).exists()


def test_generate_pdf_attack_gallery_refuses_non_empty_output(tmp_path: Path) -> None:
    pytest.importorskip("fitz")
    output_dir = tmp_path / "gallery"
    output_dir.mkdir()
    (output_dir / "existing.txt").write_text("keep", encoding="utf-8")

    with pytest.raises(ValueError, match="already exists"):
        generate_pdf_attack_gallery(output_dir)

