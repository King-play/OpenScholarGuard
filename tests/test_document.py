from __future__ import annotations

from pathlib import Path

import pytest

from openscholarguard.document import load_document
from openscholarguard.exceptions import UnsupportedDocumentError


def test_load_text_document_has_lines(tmp_path: Path) -> None:
    path = tmp_path / "paper.tex"
    path.write_text("line one\nline two\n", encoding="utf-8")

    document = load_document(path)

    assert document.metadata["type"] == "text"
    assert len(document.chunks) == 2
    assert document.chunks[0].location.line == 1


def test_unsupported_file_type(tmp_path: Path) -> None:
    path = tmp_path / "paper.bin"
    path.write_bytes(b"\x00\x01")

    with pytest.raises(UnsupportedDocumentError):
        load_document(path)
