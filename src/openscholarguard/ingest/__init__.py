"""Guarded ingestion pipeline for RAG and document-agent systems."""

from __future__ import annotations

from openscholarguard.ingest.chunker import chunk_text
from openscholarguard.ingest.models import IngestChunk, IngestOptions, IngestResult, IngestStatus
from openscholarguard.ingest.pipeline import ingest_path

__all__ = [
    "IngestChunk",
    "IngestOptions",
    "IngestResult",
    "IngestStatus",
    "chunk_text",
    "ingest_path",
]
