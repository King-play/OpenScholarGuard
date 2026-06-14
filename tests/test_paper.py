from __future__ import annotations

from pathlib import Path

import pytest

from openscholarguard.paper import generate_paper_skeleton


def test_generate_paper_skeleton_writes_latex_and_tables(tmp_path: Path) -> None:
    artifacts = generate_paper_skeleton(tmp_path / "paper")

    main_tex = artifacts.main_tex.read_text(encoding="utf-8")
    dataset_table = artifacts.dataset_table.read_text(encoding="utf-8")
    results_table = artifacts.results_table.read_text(encoding="utf-8")

    assert artifacts.main_tex.exists()
    assert artifacts.evaluation_json.exists()
    assert "OpenScholarGuard: Securing AI-Assisted Scholarly Review" in main_tex
    assert "scholarguardbench-v0" in main_tex
    assert "rag contamination" in dataset_table
    assert "OpenScholarGuard deterministic scanner" in results_table


def test_generate_paper_skeleton_refuses_non_empty_output(tmp_path: Path) -> None:
    output_dir = tmp_path / "paper"
    output_dir.mkdir()
    (output_dir / "keep.txt").write_text("keep", encoding="utf-8")

    with pytest.raises(ValueError, match="already exists"):
        generate_paper_skeleton(output_dir)
