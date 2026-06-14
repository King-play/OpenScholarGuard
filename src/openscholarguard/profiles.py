"""Scanning profiles for different operating environments."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ScanProfile:
    """Configuration knobs for detector sensitivity."""

    name: str
    description: str
    enabled_detectors: frozenset[str]
    minimum_severity: str = "info"
    fail_on: str = "high"


ALL_DETECTORS = frozenset(
    {
        "direct_prompt_instruction",
        "review_manipulation",
        "rag_exfiltration",
        "encoded_payload",
        "invisible_unicode",
        "latex_hidden_content",
        "html_hidden_content",
        "ocr_layer_instruction",
        "image_text_instruction",
        "fake_citation",
        "rag_contamination",
        "homoglyph_prompt_injection",
        "role_play_hijack",
        "ai_slop",
        "tool_exfiltration",
        "pdf_hidden_style",
        "pdf_metadata_instruction",
        "suspicious_density",
    }
)


PROFILES: dict[str, ScanProfile] = {
    "ai-review": ScanProfile(
        name="ai-review",
        description="Strict profile for scholarly peer-review and AI reviewer workflows.",
        enabled_detectors=ALL_DETECTORS,
        fail_on="high",
    ),
    "rag": ScanProfile(
        name="rag",
        description="Profile for document ingestion into RAG and agent systems.",
        enabled_detectors=ALL_DETECTORS - {"review_manipulation"},
        fail_on="high",
    ),
    "baseline": ScanProfile(
        name="baseline",
        description="General-purpose document safety scan.",
        enabled_detectors=ALL_DETECTORS
        - {"review_manipulation", "suspicious_density"},
        fail_on="critical",
    ),
}


def get_profile(name: str) -> ScanProfile:
    try:
        return PROFILES[name]
    except KeyError as exc:
        choices = ", ".join(sorted(PROFILES))
        raise ValueError(f"Unknown profile '{name}'. Available profiles: {choices}") from exc
