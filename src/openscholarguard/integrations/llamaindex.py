"""LlamaIndex integration helpers.

The module avoids importing LlamaIndex directly so the core package remains dependency-free.
It accepts LlamaIndex `Document`/`TextNode`-like objects that expose `text`,
`get_content()`, or `metadata`.
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
class LlamaIndexGuardResult:
    """Guard result for one LlamaIndex document or node."""

    node: Any
    blocked: bool
    risk_score: int
    max_severity: str
    finding_count: int


class OpenScholarGuardNodePostprocessor:
    """Filter or sanitize LlamaIndex nodes before retrieval or synthesis."""

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

    def postprocess_nodes(self, nodes: Iterable[Any], **_: Any) -> list[Any]:
        """Return sanitized nodes, omitting blocked nodes by default."""

        return [result.node for result in self.guard_nodes(nodes) if not result.blocked or self.allow_risk]

    def guard_nodes(self, nodes: Iterable[Any]) -> list[LlamaIndexGuardResult]:
        """Return per-node guard metadata plus sanitized node-like objects."""

        results: list[LlamaIndexGuardResult] = []
        scanner = Scanner(profile=self.profile)
        for index, node in enumerate(nodes):
            text = _node_text(node)
            metadata = dict(getattr(node, "metadata", {}) or {})
            path = str(metadata.get("source") or f"<llamaindex:{index}>")
            loaded = load_text_document(text, path=path, metadata={"integration": "llamaindex"})
            scan = scanner.scan_document(loaded)
            sanitized = sanitize_document(loaded, profile=self.profile)
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
                LlamaIndexGuardResult(
                    node=_rebuild_node(node, text=output_text, metadata=output_metadata),
                    blocked=blocked,
                    risk_score=scan.summary.risk_score,
                    max_severity=scan.summary.max_severity.value,
                    finding_count=scan.summary.total_findings,
                )
            )
        return results


def _node_text(node: Any) -> str:
    get_content = getattr(node, "get_content", None)
    if callable(get_content):
        return str(get_content())
    return str(getattr(node, "text", getattr(node, "page_content", "")))


def _rebuild_node(node: Any, *, text: str, metadata: dict[str, Any]) -> Any:
    node_type = node.__class__
    try:
        return node_type(text=text, metadata=metadata)
    except TypeError:
        try:
            return node_type(page_content=text, metadata=metadata)
        except TypeError:
            return {"text": text, "metadata": metadata}
