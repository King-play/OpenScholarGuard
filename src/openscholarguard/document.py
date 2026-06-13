"""Document loading and lightweight structural extraction."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Union

from openscholarguard.exceptions import DependencyMissingError, UnsupportedDocumentError
from openscholarguard.models import Location

SUPPORTED_TEXT_SUFFIXES = {".txt", ".md", ".markdown", ".tex", ".html", ".htm", ".xml", ".json", ".csv"}
SUPPORTED_PDF_SUFFIXES = {".pdf"}


@dataclass(frozen=True)
class TextChunk:
    """A chunk of text with enough context for useful reports."""

    text: str
    location: Location
    kind: str = "text"
    style: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Document:
    """A loaded document represented as text chunks and metadata."""

    path: Path
    text: str
    chunks: list[TextChunk]
    metadata: dict[str, Any]

    @property
    def sha256(self) -> str:
        if not self.path.exists():
            return hashlib.sha256(self.text.encode("utf-8", errors="replace")).hexdigest()
        return hashlib.sha256(self.path.read_bytes()).hexdigest()


def load_document(path: Union[str, Path]) -> Document:
    """Load a supported document into chunks."""

    document_path = Path(path).expanduser().resolve()
    if not document_path.exists():
        raise FileNotFoundError(str(document_path))

    suffix = document_path.suffix.lower()
    if suffix in SUPPORTED_TEXT_SUFFIXES:
        return _load_text_document(document_path)
    if suffix in SUPPORTED_PDF_SUFFIXES:
        return _load_pdf_document(document_path)

    raise UnsupportedDocumentError(
        f"Unsupported file type '{suffix or '<none>'}'. Supported: PDF, text, Markdown, TeX, HTML, JSON, CSV."
    )


def load_text_document(
    text: str,
    *,
    path: str = "<memory>",
    metadata: dict[str, Any] | None = None,
) -> Document:
    """Create a document from in-memory text."""

    document_path = Path(path)
    chunks = [
        TextChunk(
            text=line,
            location=Location(path=str(document_path), line=index),
            kind="line",
        )
        for index, line in enumerate(text.splitlines(), start=1)
    ]
    if not chunks:
        chunks = [TextChunk(text="", location=Location(path=str(document_path), line=1), kind="line")]
    return Document(
        path=document_path,
        text=text,
        chunks=chunks,
        metadata={
            "type": "text",
            "encoding": "utf-8",
            "bytes": len(text.encode("utf-8")),
            **(metadata or {}),
        },
    )


def _load_text_document(path: Path) -> Document:
    raw = path.read_bytes()
    encoding = _guess_encoding(raw)
    text = raw.decode(encoding, errors="replace")
    chunks = [
        TextChunk(
            text=line,
            location=Location(path=str(path), line=index),
            kind="line",
        )
        for index, line in enumerate(text.splitlines(), start=1)
    ]
    if not chunks:
        chunks = [TextChunk(text="", location=Location(path=str(path), line=1), kind="line")]

    return Document(
        path=path,
        text=text,
        chunks=chunks,
        metadata={
            "type": "text",
            "encoding": encoding,
            "bytes": len(raw),
        },
    )


def _load_pdf_document(path: Path) -> Document:
    try:
        import fitz  # type: ignore[import-untyped]
    except ImportError as exc:
        raise DependencyMissingError("Install PyMuPDF to scan PDF files: pip install pymupdf") from exc

    pdf = fitz.open(path)
    chunks: list[TextChunk] = []
    page_texts: list[str] = []
    metadata: dict[str, Any] = {
        "type": "pdf",
        "pages": pdf.page_count,
        "pdf_metadata": dict(pdf.metadata or {}),
    }

    try:
        chunks.extend(_extract_pdf_metadata_chunks(path, pdf.metadata or {}))
        for page_index, page in enumerate(pdf, start=1):
            page_text = page.get_text("text")
            page_texts.append(page_text)
            chunks.extend(_extract_pdf_text_chunks(path, page, page_index))
    finally:
        pdf.close()

    return Document(
        path=path,
        text="\n".join(page_texts),
        chunks=chunks or [TextChunk(text="", location=Location(path=str(path), page=1), kind="page")],
        metadata=metadata,
    )


def _extract_pdf_metadata_chunks(path: Path, metadata: dict[str, Any]) -> list[TextChunk]:
    chunks: list[TextChunk] = []
    for key, value in metadata.items():
        if value is None:
            continue
        text = str(value)
        if not text.strip():
            continue
        chunks.append(
            TextChunk(
                text=text,
                location=Location(path=str(path), field=f"pdf.metadata.{key}"),
                kind="metadata",
                style={"metadata_key": key},
            )
        )
    return chunks


def _extract_pdf_text_chunks(path: Path, page: Any, page_index: int) -> list[TextChunk]:
    raw = page.get_text("dict")
    chunks: list[TextChunk] = []
    page_rect = page.rect

    for block_index, block in enumerate(raw.get("blocks", [])):
        for line in block.get("lines", []):
            for span_index, span in enumerate(line.get("spans", [])):
                text = span.get("text", "")
                if not text:
                    continue
                bbox = span.get("bbox", [0, 0, 0, 0])
                color = int(span.get("color", 0))
                fill_opacity = span.get("alpha", span.get("fill_opacity", 1))
                chunks.append(
                    TextChunk(
                        text=text,
                        location=Location(
                            path=str(path),
                            page=page_index,
                            block=block_index,
                            span=span_index,
                        ),
                        kind="pdf-span",
                        style={
                            "font": span.get("font"),
                            "size": float(span.get("size", 0) or 0),
                            "color": _int_rgb(color),
                            "color_int": color,
                            "fill_opacity": fill_opacity,
                            "bbox": bbox,
                            "page_width": float(page_rect.width),
                            "page_height": float(page_rect.height),
                        },
                    )
                )

    return chunks


def _int_rgb(value: int) -> tuple[int, int, int]:
    red = (value >> 16) & 255
    green = (value >> 8) & 255
    blue = value & 255
    return red, green, blue


def _guess_encoding(raw: bytes) -> str:
    for encoding in ("utf-8-sig", "utf-8", "utf-16", "latin-1"):
        try:
            raw.decode(encoding)
            return encoding
        except UnicodeDecodeError:
            continue
    return "utf-8"
