from __future__ import annotations

from pathlib import Path

import pytest

from openscholarguard.pdf_audit import render_pdf_deep_markdown, scan_pdf_deep


def test_pdf_deep_audit_detects_visual_text_mismatch(tmp_path: Path) -> None:
    fitz = pytest.importorskip("fitz")
    pdf_path = tmp_path / "visual_only.pdf"
    document = fitz.open()
    page = document.new_page(width=220, height=220)
    page.draw_rect(fitz.Rect(30, 30, 190, 190), fill=(0, 0, 0), color=(0, 0, 0))
    document.save(pdf_path)
    document.close()

    result = scan_pdf_deep(pdf_path)
    markdown = render_pdf_deep_markdown(result)

    assert 1 in result.visual_mismatch_pages
    assert any(signal.kind == "visual_text_mismatch" for signal in result.signals)
    assert "PDF Deep Audit" in markdown
