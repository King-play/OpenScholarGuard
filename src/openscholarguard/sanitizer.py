"""Document sanitizer for AI review and RAG ingestion."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Union

from openscholarguard.document import Document, load_document
from openscholarguard.models import Location, RemovedItem, SanitizeResult, utc_now
from openscholarguard.rules.models import RulePack
from openscholarguard.scanner import Scanner
from openscholarguard.text_utils import snippet, strip_invisible_controls

HIGH_RISK_DETECTORS = {
    "direct_prompt_instruction",
    "review_manipulation",
    "rag_exfiltration",
    "pdf_hidden_style",
    "pdf_metadata_instruction",
}

LATEX_HIDDEN_PATTERNS = (
    re.compile(r"\\(?:phantom|hphantom|vphantom)\s*\{[^}]{12,}\}", re.I | re.S),
    re.compile(r"\\makebox\s*\[\s*0\s*(?:pt|em|ex|in|cm|mm)?\s*\]\s*\{[^}]{12,}\}", re.I | re.S),
    re.compile(r"\\pdf(?:info|catalog)\s*\{[^}]{12,}\}", re.I | re.S),
)

HTML_HIDDEN_PATTERNS = (
    re.compile(
        r"<!--[^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0)[\s\S]*?-->",
        re.I,
    ),
    re.compile(r"<[^>]+(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0)[^>]*>.*?</[^>]+>", re.I | re.S),
)


def sanitize_path(
    path: Union[str, Path],
    *,
    profile: str = "ai-review",
    rule_packs: list[RulePack] | None = None,
) -> SanitizeResult:
    document = load_document(path)
    return sanitize_document(document, profile=profile, rule_packs=rule_packs)


def sanitize_document(
    document: Document,
    *,
    profile: str = "ai-review",
    rule_packs: list[RulePack] | None = None,
) -> SanitizeResult:
    scan = Scanner(profile=profile, rule_packs=rule_packs).scan_document(document)
    risky_locations = {
        _location_key(finding.location)
        for finding in scan.findings
        if finding.detector_id in HIGH_RISK_DETECTORS
    }
    removed: list[RemovedItem] = []
    safe_chunks: list[str] = []

    for chunk in document.chunks:
        text = strip_invisible_controls(chunk.text)
        text, pattern_removed = _strip_hidden_syntax(text, chunk.location)
        removed.extend(pattern_removed)

        if chunk.kind == "metadata":
            if _location_key(chunk.location) in risky_locations:
                removed.append(
                    RemovedItem(
                        reason="metadata instruction removed",
                        location=chunk.location,
                        snippet=snippet(chunk.text),
                        detector_id="pdf_metadata_instruction",
                    )
                )
            continue

        if _location_key(chunk.location) in risky_locations:
            removed.append(
                RemovedItem(
                    reason="high-risk instruction removed",
                    location=chunk.location,
                    snippet=snippet(chunk.text),
                )
            )
            continue

        if text.strip():
            safe_chunks.append(text)

    return SanitizeResult(
        target=str(document.path),
        profile=profile,
        sanitized_at=utc_now(),
        text=_join_chunks(safe_chunks),
        removed=removed,
        warnings=scan.warnings + scan.errors,
    )


def _strip_hidden_syntax(text: str, location: Location) -> tuple[str, list[RemovedItem]]:
    removed: list[RemovedItem] = []
    clean = text
    for pattern in (*LATEX_HIDDEN_PATTERNS, *HTML_HIDDEN_PATTERNS):
        matches = list(pattern.finditer(clean))
        for match in matches:
            removed.append(
                RemovedItem(
                    reason="hidden syntax removed",
                    location=location,
                    snippet=snippet(match.group(0)),
                )
            )
        clean = pattern.sub("", clean)
    return clean, removed


def _join_chunks(chunks: list[str]) -> str:
    output: list[str] = []
    previous = ""
    for chunk in chunks:
        stripped = chunk.strip()
        if not stripped:
            continue
        if previous and not previous.endswith((".", "!", "?", ":", ";", "-", "\n")):
            output.append(" ")
        elif output:
            output.append("\n")
        output.append(stripped)
        previous = stripped
    return "".join(output).strip() + "\n"


def _location_key(location: Location) -> tuple[object, ...]:
    return (
        location.path,
        location.page,
        location.line,
        location.section,
        location.field,
        location.block,
        location.span,
    )
