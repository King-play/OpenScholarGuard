from __future__ import annotations

from pathlib import Path

import pytest

from openscholarguard.site import generate_site


def test_generate_site_writes_project_entrypoint(tmp_path: Path) -> None:
    artifacts = generate_site(tmp_path / "site")

    html = artifacts.index_html.read_text(encoding="utf-8")

    assert artifacts.index_html.exists()
    assert artifacts.demo.index_html.exists()
    assert artifacts.benchmark.leaderboard_html.exists()
    assert artifacts.pdf_gallery.index_html.exists()
    assert "OpenScholarGuard" in html
    assert "demo/index.html" not in html
    assert "ScholarGuardBench" in html
    assert "pdf-gallery/index.html" in html
    assert "benchmark/leaderboard.html" in html
    assert "OpenScholarGuard workflow" in html
    assert "https://github.com/King-play/OpenScholarGuard" in html


def test_generate_site_refuses_non_empty_output_without_overwrite(tmp_path: Path) -> None:
    output_dir = tmp_path / "site"
    output_dir.mkdir()
    (output_dir / "existing.txt").write_text("keep", encoding="utf-8")

    with pytest.raises(ValueError, match="already exists"):
        generate_site(output_dir)


def test_generate_site_overwrites_existing_output(tmp_path: Path) -> None:
    output_dir = tmp_path / "site"
    output_dir.mkdir()
    (output_dir / "existing.txt").write_text("replace", encoding="utf-8")

    artifacts = generate_site(output_dir, overwrite=True)

    assert artifacts.index_html.exists()
    assert not (output_dir / "existing.txt").exists()
