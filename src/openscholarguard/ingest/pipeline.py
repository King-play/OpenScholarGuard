"""Guarded ingestion pipeline."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Union

from openscholarguard.document import Document, load_document
from openscholarguard.ingest.chunker import chunk_text
from openscholarguard.ingest.models import IngestOptions, IngestResult, IngestStatus
from openscholarguard.models import SEVERITY_RANK, Severity, _json_ready
from openscholarguard.sanitizer import sanitize_document
from openscholarguard.scanner import Scanner


def ingest_path(path: Union[str, Path], *, options: IngestOptions | None = None) -> IngestResult:
    """Scan, sanitize, and chunk a document for guarded RAG ingestion."""

    active_options = options or IngestOptions()
    document = load_document(path)
    return ingest_document(document, options=active_options)


def ingest_document(document: Document, *, options: IngestOptions | None = None) -> IngestResult:
    """Scan, sanitize, and chunk a loaded document."""

    active_options = options or IngestOptions()
    rule_packs = list(active_options.rule_packs)
    scan = Scanner(profile=active_options.profile, rule_packs=rule_packs).scan_document(document)
    sanitizer_result = sanitize_document(
        document,
        profile=active_options.profile,
        rule_packs=rule_packs,
    )

    blocked = scan.has_at_least(active_options.block_on) and not active_options.allow_risk
    status = IngestStatus.BLOCKED if blocked else IngestStatus.READY
    warnings = list(scan.warnings) + list(scan.errors) + list(sanitizer_result.warnings)

    chunks = []
    if not blocked:
        chunks = chunk_text(
            sanitizer_result.text,
            source_path=str(document.path),
            chunk_size=active_options.chunk_size,
            chunk_overlap=active_options.chunk_overlap,
            min_chunk_chars=active_options.min_chunk_chars,
            base_metadata={
                "profile": active_options.profile,
                "risk_score": scan.summary.risk_score,
                "max_severity": scan.summary.max_severity.value,
                "blocked": False,
                "detectors": sorted({finding.detector_id for finding in scan.findings}),
                "source_sha256": document.sha256,
            },
        )
        if not chunks:
            status = IngestStatus.EMPTY

    findings = [_json_ready(asdict(finding)) for finding in scan.findings]
    removed = [_json_ready(asdict(item)) for item in sanitizer_result.removed]

    return IngestResult(
        target=str(document.path),
        status=status,
        profile=active_options.profile,
        block_on=active_options.block_on,
        risk_score=scan.summary.risk_score,
        max_severity=scan.summary.max_severity,
        chunks=chunks,
        sanitized_text="" if blocked else sanitizer_result.text,
        findings=findings if active_options.include_findings else [],
        removed=removed,
        warnings=warnings,
        metadata={
            "source_sha256": document.sha256,
            "document": document.metadata,
            "chunk_count": len(chunks),
            "allow_risk": active_options.allow_risk,
            "blocked": blocked,
        },
    )


def blocked_by_threshold(max_severity: Severity, block_on: Severity) -> bool:
    return SEVERITY_RANK[max_severity] >= SEVERITY_RANK[block_on]
