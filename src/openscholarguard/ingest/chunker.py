"""Text chunking utilities for safe RAG ingestion."""

from __future__ import annotations

import hashlib
import re

from openscholarguard.ingest.models import IngestChunk


def chunk_text(
    text: str,
    *,
    source_path: str,
    chunk_size: int = 1200,
    chunk_overlap: int = 120,
    min_chunk_chars: int = 40,
    base_metadata: dict[str, object] | None = None,
) -> list[IngestChunk]:
    """Split text into stable, provenance-rich chunks."""

    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    if chunk_overlap < 0:
        raise ValueError("chunk_overlap must be non-negative")
    if chunk_overlap >= chunk_size:
        raise ValueError("chunk_overlap must be smaller than chunk_size")

    clean = _normalize_text(text)
    if not clean.strip():
        return []

    spans = _paragraph_aware_spans(clean, chunk_size=chunk_size, chunk_overlap=chunk_overlap)
    chunks: list[IngestChunk] = []
    for ordinal, (start, end) in enumerate(spans):
        chunk = clean[start:end].strip()
        if len(chunk) < min_chunk_chars and len(spans) > 1:
            continue
        sha = hashlib.sha256(chunk.encode("utf-8", errors="replace")).hexdigest()
        chunks.append(
            IngestChunk(
                id=f"chunk-{sha[:16]}",
                text=chunk,
                source_path=source_path,
                ordinal=ordinal,
                start_char=start,
                end_char=end,
                sha256=sha,
                metadata=dict(base_metadata or {}),
            )
        )
    return chunks


def _normalize_text(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _paragraph_aware_spans(
    text: str,
    *,
    chunk_size: int,
    chunk_overlap: int,
) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    start = 0
    length = len(text)
    while start < length:
        hard_end = min(length, start + chunk_size)
        end = _best_break(text, start, hard_end) if hard_end < length else hard_end
        if end <= start:
            end = hard_end
        spans.append((start, end))
        if end >= length:
            break
        start = max(0, end - chunk_overlap)
        while start < length and text[start].isspace():
            start += 1
    return spans


def _best_break(text: str, start: int, hard_end: int) -> int:
    window = text[start:hard_end]
    for separator in ("\n\n", "\n", ". ", "; ", ", "):
        index = window.rfind(separator)
        if index >= max(80, len(window) // 3):
            return start + index + len(separator)
    return hard_end
