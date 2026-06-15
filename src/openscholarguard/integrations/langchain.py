"""LangChain integration helpers.

The module avoids importing LangChain directly so OpenScholarGuard stays dependency-free.
It works with LangChain `Document`-like objects that expose `page_content` and `metadata`.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from openscholarguard.document import load_text_document
from openscholarguard.models import Severity
from openscholarguard.sanitizer import sanitize_document
from openscholarguard.scanner import Scanner


@dataclass(frozen=True)
class LangChainGuardResult:
    """Guard result for one LangChain document."""

    document: Any
    blocked: bool
    risk_score: int
    max_severity: str
    finding_count: int


class OpenScholarGuardTransformer:
    """Sanitize or block LangChain `Document`-like objects before ingestion."""

    def __init__(
        self,
        *,
        profile: str = "rag",
        block_on: str = "high",
        allow_risk: bool = False,
    ) -> None:
        self.profile = profile
        self.block_on = Severity(block_on)
        self.allow_risk = allow_risk

    def transform_documents(self, documents: Iterable[Any], **_: Any) -> list[Any]:
        """Return sanitized documents, omitting blocked documents by default."""

        return [result.document for result in self.guard_documents(documents) if not result.blocked or self.allow_risk]

    def guard_documents(self, documents: Iterable[Any]) -> list[LangChainGuardResult]:
        """Return per-document guard metadata plus sanitized document objects."""

        results: list[LangChainGuardResult] = []
        for index, document in enumerate(documents):
            text = str(getattr(document, "page_content", ""))
            metadata = dict(getattr(document, "metadata", {}) or {})
            path = str(metadata.get("source") or f"<langchain:{index}>")
            loaded = load_text_document(text, path=path, metadata={"integration": "langchain"})
            sanitized = sanitize_document(loaded, profile=self.profile)
            scan = Scanner(profile=self.profile).scan_document(loaded)
            blocked = scan.has_at_least(self.block_on)
            output_text = sanitized.text if not blocked or self.allow_risk else ""
            output_metadata = {
                **metadata,
                "openscholarguard": {
                    "profile": self.profile,
                    "blocked": blocked,
                    "risk_score": scan.summary.risk_score,
                    "max_severity": scan.summary.max_severity.value,
                    "finding_count": scan.summary.total_findings,
                    "removed_count": len(sanitized.removed),
                },
            }
            results.append(
                LangChainGuardResult(
                    document=_rebuild_document(document, page_content=output_text, metadata=output_metadata),
                    blocked=blocked,
                    risk_score=scan.summary.risk_score,
                    max_severity=scan.summary.max_severity.value,
                    finding_count=scan.summary.total_findings,
                )
            )
        return results


def _rebuild_document(document: Any, *, page_content: str, metadata: dict[str, Any]) -> Any:
    document_type = document.__class__
    try:
        return document_type(page_content=page_content, metadata=metadata)
    except TypeError:
        try:
            clone = document_type(page_content)
            clone.metadata = metadata
            return clone
        except Exception:
            return {"page_content": page_content, "metadata": metadata}
