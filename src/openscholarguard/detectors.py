"""Heuristic detectors for document-borne prompt injection and review manipulation."""

from __future__ import annotations

import base64
import binascii
import math
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Optional

from openscholarguard.document import Document, TextChunk
from openscholarguard.models import Finding, Location, Severity, make_finding_id
from openscholarguard.text_utils import find_invisible_controls, printable_ratio, snippet


@dataclass(frozen=True)
class DetectorContext:
    """Additional detector inputs."""

    profile: str


class Detector:
    """Base detector protocol implemented as a small class hierarchy."""

    id: str
    title: str

    def detect(self, document: Document, context: DetectorContext) -> list[Finding]:
        raise NotImplementedError

    def finding(
        self,
        *,
        title: str,
        severity: Severity,
        confidence: float,
        location: Location,
        text: str,
        evidence: Optional[dict[str, object]] = None,
        remediation: str = "",
        tags: Optional[list[str]] = None,
    ) -> Finding:
        evidence = evidence or {}
        clipped = snippet(text)
        return Finding(
            id=make_finding_id(self.id, location, title, clipped),
            detector_id=self.id,
            title=title,
            severity=severity,
            confidence=max(0.0, min(confidence, 1.0)),
            location=location,
            snippet=clipped,
            evidence=evidence,
            remediation=remediation,
            tags=tags or [],
        )


class RegexChunkDetector(Detector):
    """Detector that runs one or more regular expressions against each text chunk."""

    patterns: tuple[re.Pattern[str], ...]
    severity: Severity
    confidence: float
    remediation: str
    tags: list[str]

    def detect(self, document: Document, context: DetectorContext) -> list[Finding]:
        findings: list[Finding] = []
        for chunk in document.chunks:
            for pattern in self.patterns:
                match = pattern.search(chunk.text)
                if not match:
                    continue
                findings.append(
                    self.finding(
                        title=self.title,
                        severity=self.severity,
                        confidence=self.confidence,
                        location=chunk.location,
                        text=_window(chunk.text, match.start(), match.end()),
                        evidence={"pattern": pattern.pattern, "chunk_kind": chunk.kind},
                        remediation=self.remediation,
                        tags=self.tags,
                    )
                )
                break
        return findings


class DirectPromptInstructionDetector(RegexChunkDetector):
    id = "direct_prompt_instruction"
    title = "Direct instruction to override an AI system or reviewer"
    severity = Severity.HIGH
    confidence = 0.82
    remediation = "Treat the fragment as untrusted document content. Remove or isolate it before AI review or RAG ingestion."
    tags = ["prompt-injection", "instruction-hijacking"]
    patterns = (
        re.compile(r"\bignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?)\b", re.I),
        re.compile(r"\bdisregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?)\b", re.I),
        re.compile(r"\boverride\s+(the\s+)?(system|developer|reviewer|safety)\s+(prompt|message|instructions?)\b", re.I),
        re.compile(r"\byou\s+are\s+now\s+(?:an?|the)\s+[^.\n]{0,80}\b(system|reviewer|agent|assistant)\b", re.I),
        re.compile(r"\bdo\s+not\s+(?:follow|obey)\s+(?:the\s+)?(?:system|developer|reviewer)\s+(?:prompt|instructions?)\b", re.I),
    )


class ReviewManipulationDetector(RegexChunkDetector):
    id = "review_manipulation"
    title = "Attempt to manipulate peer-review outcome"
    severity = Severity.CRITICAL
    confidence = 0.9
    remediation = "Block this document from automated review until the hidden or manipulative content has been removed and audited."
    tags = ["ai-review", "peer-review", "manipulation"]
    patterns = (
        re.compile(r"\b(give|assign|return)\s+(this\s+paper\s+)?(?:a\s+)?(high|maximum|top|excellent|positive)\s+(score|rating|review)\b", re.I),
        re.compile(r"\b(recommend|accept)\s+(this\s+paper|the\s+paper|submission)\b", re.I),
        re.compile(r"\b(do\s+not|never)\s+(mention|report|flag|criticize)\s+(weaknesses|limitations|flaws|errors)\b", re.I),
        re.compile(r"\bwrite\s+(?:a\s+)?positive\s+review\b", re.I),
        re.compile(r"\bthis\s+paper\s+must\s+be\s+accepted\b", re.I),
        re.compile(
            "\\b\u8bc4\u5206\\s*(?:\u4e3a|\u7ed9)\\s*"
            "(?:\u6ee1\u5206|\u9ad8\u5206|10|100)\\b"
        ),
        re.compile(
            "\\b(?:\u8bf7|\u52a1\u5fc5).{0,20}"
            "(?:\u63a5\u6536|\u5f55\u7528|\u63a8\u8350).{0,20}"
            "(?:\u8fd9\u7bc7|\u672c\u6587|\u8bba\u6587)\\b"
        ),
    )


class RagExfiltrationDetector(RegexChunkDetector):
    id = "rag_exfiltration"
    title = "Instruction to leak prompts, secrets, or retrieved context"
    severity = Severity.HIGH
    confidence = 0.84
    remediation = "Do not expose system prompts, chain-of-thought, credentials, or retrieved private context. Remove this fragment before ingestion."
    tags = ["rag", "data-exfiltration", "secrets"]
    patterns = (
        re.compile(r"\b(reveal|print|output|return|show)\s+(the\s+)?(system|developer)\s+(prompt|message|instructions?)\b", re.I),
        re.compile(r"\b(leak|exfiltrate|dump)\s+(secrets?|credentials?|tokens?|api\s*keys?|context)\b", re.I),
        re.compile(r"\binclude\s+(all\s+)?retrieved\s+(documents?|context|chunks?)\b", re.I),
        re.compile(r"\bshow\s+(your\s+)?chain[-\s]?of[-\s]?thought\b", re.I),
    )


class LatexHiddenContentDetector(RegexChunkDetector):
    id = "latex_hidden_content"
    title = "Potentially hidden LaTeX instruction"
    severity = Severity.MEDIUM
    confidence = 0.74
    remediation = "Inspect hidden LaTeX commands. Remove content intended for machine readers but not human reviewers."
    tags = ["latex", "hidden-content"]
    patterns = (
        re.compile(r"\\(?:color|textcolor)\s*\{\s*(?:white|background|transparent)\s*\}", re.I),
        re.compile(r"\\fontsize\s*\{\s*(?:0|0\.\d+|1|2|3)\s*\}", re.I),
        re.compile(r"\\(?:phantom|hphantom|vphantom)\s*\{[^}]{12,}\}", re.I | re.S),
        re.compile(r"\\makebox\s*\[\s*0\s*(?:pt|em|ex|in|cm|mm)?\s*\]\s*\{[^}]{12,}\}", re.I | re.S),
        re.compile(r"\\pdf(?:info|catalog)\s*\{[^}]{12,}\}", re.I | re.S),
    )


class HtmlHiddenContentDetector(RegexChunkDetector):
    id = "html_hidden_content"
    title = "Potentially hidden HTML/CSS instruction"
    severity = Severity.MEDIUM
    confidence = 0.72
    remediation = "Inspect invisible HTML/CSS content before passing this document to an AI system."
    tags = ["html", "hidden-content"]
    patterns = (
        re.compile(r"display\s*:\s*none", re.I),
        re.compile(r"visibility\s*:\s*hidden", re.I),
        re.compile(r"opacity\s*:\s*0(?:\.0+)?", re.I),
        re.compile(r"font-size\s*:\s*(?:0|1|2|3)px", re.I),
        re.compile(r"color\s*:\s*(?:white|#fff(?:fff)?|rgba\([^)]*,\s*0\s*\))", re.I),
    )


class OcrLayerInstructionDetector(RegexChunkDetector):
    id = "ocr_layer_instruction"
    title = "OCR layer contains model-facing instruction"
    severity = Severity.HIGH
    confidence = 0.82
    remediation = "Inspect OCR-only text and keep hidden OCR layers out of AI-visible review or RAG input."
    tags = ["ocr", "hidden-content", "prompt-injection"]
    patterns = (
        re.compile(
            r"\b(?:ocr\s*layer|hidden\s*ocr|ocr\s*text|recognized\s*text)\b"
            r"[^.\n]{0,160}\b(?:ignore|override|accept\s+this\s+paper|system\s+prompt)\b",
            re.I,
        ),
    )


class ImageTextInstructionDetector(RegexChunkDetector):
    id = "image_text_instruction"
    title = "Image or alt-text contains model-facing instruction"
    severity = Severity.HIGH
    confidence = 0.8
    remediation = "Audit image text, alt text, and figure OCR before passing the document to a multimodal reviewer."
    tags = ["image", "multimodal", "prompt-injection"]
    patterns = (
        re.compile(
            r"\b(?:image\s*alt\s*text|alt\s*text|figure\s*text|embedded\s*image\s*text|image\s*ocr)\b"
            r"[^.\n]{0,160}\b(?:ignore|override|recommend|accept|system\s+prompt)\b",
            re.I,
        ),
    )


class FakeCitationDetector(RegexChunkDetector):
    id = "fake_citation"
    title = "Instruction to fabricate citations or references"
    severity = Severity.HIGH
    confidence = 0.78
    remediation = "Verify cited evidence against the bibliography and remove instructions to fabricate support."
    tags = ["citation", "integrity", "ai-slop"]
    patterns = (
        re.compile(r"\b(?:fabricate|invent|hallucinate|fake)\s+(?:citations?|references?)\b", re.I),
        re.compile(r"\bcite\s+(?:nonexistent|fake|fabricated)\s+(?:papers?|citations?|references?)\b", re.I),
    )


class RagContaminationDetector(RegexChunkDetector):
    id = "rag_contamination"
    title = "Instruction to contaminate future RAG retrieval"
    severity = Severity.HIGH
    confidence = 0.82
    remediation = "Remove retrieval-triggered instructions before indexing the document into a RAG or agent store."
    tags = ["rag", "retrieval", "poisoning"]
    patterns = (
        re.compile(
            r"\bwhen\s+(?:this\s+)?(?:chunk|document|context|passage)\s+is\s+retrieved\b"
            r"[^.\n]{0,180}\b(?:always|ignore|answer|include|claim)\b",
            re.I,
        ),
        re.compile(r"\bpoison\s+(?:the\s+)?(?:rag|retrieval|vector\s+(?:db|database|store))\b", re.I),
    )


class HomoglyphPromptInjectionDetector(RegexChunkDetector):
    id = "homoglyph_prompt_injection"
    title = "Mixed-script homoglyph prompt injection"
    severity = Severity.HIGH
    confidence = 0.7
    remediation = "Normalize mixed-script text and inspect suspicious instruction-like fragments manually."
    tags = ["unicode", "homoglyph", "obfuscation"]
    patterns = (
        re.compile(
            r"[\u0400-\u04ff][^.\n]{0,80}\b(?:system\s+prompt|instructions?|prompt)\b",
            re.I,
        ),
        re.compile(
            r"\bhomoglyph\s+payload\b[^.\n]{0,160}\b(?:ignore|reveal|system\s+prompt|instructions?)\b",
            re.I,
        ),
    )


class RolePlayHijackDetector(RegexChunkDetector):
    id = "role_play_hijack"
    title = "Role-play attempt to hijack reviewer authority"
    severity = Severity.HIGH
    confidence = 0.78
    remediation = "Treat role assignment in document content as untrusted text, not as agent instructions."
    tags = ["role-play", "authority-hijack", "ai-review"]
    patterns = (
        re.compile(
            r"\byou\s+are\s+now\s+(?:the\s+)?(?:senior\s+)?(?:area\s+chair|reviewer|meta[-\s]?reviewer)\b",
            re.I,
        ),
        re.compile(r"\bact\s+as\s+(?:the\s+)?(?:area\s+chair|reviewer|meta[-\s]?reviewer)\b", re.I),
    )


class AISlopDetector(RegexChunkDetector):
    id = "ai_slop"
    title = "Unreviewed AI-generated scholarly content signal"
    severity = Severity.HIGH
    confidence = 0.68
    remediation = "Require human verification of boilerplate, placeholders, citations, and experimental evidence."
    tags = ["ai-slop", "quality", "integrity"]
    patterns = (
        re.compile(r"\bas\s+an\s+ai\s+language\s+model\b", re.I),
        re.compile(r"\bTODO:\s+insert\s+real\s+(?:ablation|experiment|result|citation)", re.I),
        re.compile(r"\bplaceholder\s+citation\s+needed\b", re.I),
    )


class ToolExfiltrationDetector(RegexChunkDetector):
    id = "tool_exfiltration"
    title = "Instruction to exfiltrate secrets through agent tools"
    severity = Severity.HIGH
    confidence = 0.82
    remediation = "Do not grant document content authority to invoke tools or read environment secrets."
    tags = ["agent", "tools", "secrets"]
    patterns = (
        re.compile(
            r"\b(?:call|use|invoke)\s+(?:available\s+)?tools?\b"
            r"[^.\n]{0,180}\b(?:environment\s+variables?|api\s*keys?|credentials?|secrets?)\b",
            re.I,
        ),
        re.compile(r"\bread\s+environment\s+variables?\b[^.\n]{0,120}\b(?:leak|print|return|show)\b", re.I),
    )


class InvisibleUnicodeDetector(Detector):
    id = "invisible_unicode"
    title = "Invisible or bidirectional Unicode control characters"

    def detect(self, document: Document, context: DetectorContext) -> list[Finding]:
        findings: list[Finding] = []
        for chunk in document.chunks:
            matches = find_invisible_controls(chunk.text)
            if not matches:
                continue
            names = sorted({name for _, _, name in matches})
            severity = Severity.HIGH if any("RIGHT-TO-LEFT" in name or "LEFT-TO-RIGHT" in name for name in names) else Severity.MEDIUM
            findings.append(
                self.finding(
                    title=self.title,
                    severity=severity,
                    confidence=0.86,
                    location=chunk.location,
                    text=_context_around_index(chunk.text, matches[0][0]),
                    evidence={"count": len(matches), "characters": names[:12], "chunk_kind": chunk.kind},
                    remediation="Remove invisible controls and re-review rendered text, extracted text, and model-visible text.",
                    tags=["unicode", "hidden-content"],
                )
            )
        return findings


class EncodedPayloadDetector(Detector):
    id = "encoded_payload"
    title = "Encoded payload that may hide instructions"

    _base64_pattern = re.compile(r"\b(?:[A-Za-z0-9+/]{32,}={0,2}|[A-Za-z0-9_-]{32,}={0,2})\b")
    _hex_pattern = re.compile(r"\b(?:0x)?[0-9a-fA-F]{48,}\b")
    _instruction_pattern = re.compile(
        r"(ignore|override|system prompt|accept this paper|positive review|reveal|exfiltrate)",
        re.I,
    )

    def detect(self, document: Document, context: DetectorContext) -> list[Finding]:
        findings: list[Finding] = []
        for chunk in document.chunks:
            findings.extend(self._detect_base64(chunk))
            findings.extend(self._detect_hex(chunk))
        return findings

    def _detect_base64(self, chunk: TextChunk) -> list[Finding]:
        findings: list[Finding] = []
        for match in self._base64_pattern.finditer(chunk.text):
            token = match.group(0)
            decoded = _try_base64_decode(token)
            if decoded is None:
                continue
            decoded_text = decoded.decode("utf-8", errors="replace")
            if printable_ratio(decoded_text) < 0.8:
                continue
            severity = Severity.HIGH if self._instruction_pattern.search(decoded_text) else Severity.LOW
            confidence = 0.86 if severity is Severity.HIGH else 0.5
            findings.append(
                self.finding(
                    title=self.title,
                    severity=severity,
                    confidence=confidence,
                    location=chunk.location,
                    text=_window(chunk.text, match.start(), match.end()),
                    evidence={
                        "encoding": "base64",
                        "decoded_preview": snippet(decoded_text, limit=160),
                        "chunk_kind": chunk.kind,
                    },
                    remediation="Decode and inspect payloads. Remove encoded instructions before model ingestion.",
                    tags=["encoded", "obfuscation"],
                )
            )
        return findings

    def _detect_hex(self, chunk: TextChunk) -> list[Finding]:
        findings: list[Finding] = []
        for match in self._hex_pattern.finditer(chunk.text):
            token = match.group(0)
            candidate = token[2:] if token.lower().startswith("0x") else token
            if len(candidate) % 2:
                continue
            try:
                decoded = bytes.fromhex(candidate)
            except ValueError:
                continue
            decoded_text = decoded.decode("utf-8", errors="replace")
            if printable_ratio(decoded_text) < 0.8:
                continue
            severity = Severity.HIGH if self._instruction_pattern.search(decoded_text) else Severity.LOW
            findings.append(
                self.finding(
                    title=self.title,
                    severity=severity,
                    confidence=0.78 if severity is Severity.HIGH else 0.42,
                    location=chunk.location,
                    text=_window(chunk.text, match.start(), match.end()),
                    evidence={
                        "encoding": "hex",
                        "decoded_preview": snippet(decoded_text, limit=160),
                        "chunk_kind": chunk.kind,
                    },
                    remediation="Decode and inspect payloads. Remove encoded instructions before model ingestion.",
                    tags=["encoded", "obfuscation"],
                )
            )
        return findings


class PdfHiddenStyleDetector(Detector):
    id = "pdf_hidden_style"
    title = "PDF text style suggests hidden machine-readable content"

    def detect(self, document: Document, context: DetectorContext) -> list[Finding]:
        findings: list[Finding] = []
        for chunk in document.chunks:
            if chunk.kind != "pdf-span":
                continue
            style = chunk.style
            text = chunk.text.strip()
            if len(text) < 8:
                continue
            size = float(style.get("size", 0) or 0)
            color = style.get("color")
            opacity = style.get("fill_opacity", 1)
            bbox = style.get("bbox", [0, 0, 0, 0])

            reasons: list[str] = []
            if size and size <= 3.0:
                reasons.append("very-small-font")
            if isinstance(color, tuple) and _is_near_white(color):
                reasons.append("near-white-text")
            if isinstance(opacity, (float, int)) and float(opacity) <= 0.05:
                reasons.append("transparent-text")
            if _is_outside_page(bbox, style):
                reasons.append("outside-page-bounds")

            if not reasons:
                continue

            severity = Severity.HIGH if _looks_like_instruction(text) else Severity.MEDIUM
            findings.append(
                self.finding(
                    title=self.title,
                    severity=severity,
                    confidence=0.88 if severity is Severity.HIGH else 0.7,
                    location=chunk.location,
                    text=text,
                    evidence={
                        "reasons": reasons,
                        "font_size": size,
                        "color": color,
                        "fill_opacity": opacity,
                        "bbox": bbox,
                    },
                    remediation="Compare rendered PDF with extracted text. Remove hidden spans or keep them out of AI-visible input.",
                    tags=["pdf", "hidden-content"],
                )
            )
        return findings


class PdfMetadataInstructionDetector(Detector):
    id = "pdf_metadata_instruction"
    title = "PDF metadata contains model-facing instruction"

    def detect(self, document: Document, context: DetectorContext) -> list[Finding]:
        findings: list[Finding] = []
        for chunk in document.chunks:
            if chunk.kind != "metadata":
                continue
            if not _looks_like_instruction(chunk.text) and not _looks_like_review_manipulation(chunk.text):
                continue
            findings.append(
                self.finding(
                    title=self.title,
                    severity=Severity.HIGH,
                    confidence=0.86,
                    location=chunk.location,
                    text=chunk.text,
                    evidence={"metadata_key": chunk.style.get("metadata_key")},
                    remediation="Strip metadata before model ingestion and audit the original submission.",
                    tags=["pdf", "metadata", "prompt-injection"],
                )
            )
        return findings


class SuspiciousDensityDetector(Detector):
    id = "suspicious_density"
    title = "High density of suspicious instruction terms"

    _terms = (
        "ignore",
        "instruction",
        "prompt",
        "system",
        "reviewer",
        "accept",
        "score",
        "reveal",
        "secret",
        "hidden",
        "do not mention",
    )

    def detect(self, document: Document, context: DetectorContext) -> list[Finding]:
        words = re.findall(r"\w+", document.text.lower())
        if len(words) < 30:
            return []
        joined = " ".join(words)
        hits = sum(joined.count(term) for term in self._terms)
        density = hits / max(1, len(words)) * 1000
        if density < 8:
            return []
        return [
            self.finding(
                title=self.title,
                severity=Severity.LOW if density < 15 else Severity.MEDIUM,
                confidence=min(0.8, 0.35 + math.log1p(density) / 6),
                location=Location(path=str(document.path), section="document"),
                text=document.text[:800],
                evidence={"hits": hits, "terms_per_1000_words": round(density, 2)},
                remediation="Review the document for intentionally model-facing instructions.",
                tags=["heuristic", "density"],
            )
        ]


DETECTORS: dict[str, Detector] = {
    detector.id: detector
    for detector in (
        DirectPromptInstructionDetector(),
        ReviewManipulationDetector(),
        RagExfiltrationDetector(),
        EncodedPayloadDetector(),
        InvisibleUnicodeDetector(),
        LatexHiddenContentDetector(),
        HtmlHiddenContentDetector(),
        OcrLayerInstructionDetector(),
        ImageTextInstructionDetector(),
        FakeCitationDetector(),
        RagContaminationDetector(),
        HomoglyphPromptInjectionDetector(),
        RolePlayHijackDetector(),
        AISlopDetector(),
        ToolExfiltrationDetector(),
        PdfHiddenStyleDetector(),
        PdfMetadataInstructionDetector(),
        SuspiciousDensityDetector(),
    )
}


def get_detectors(enabled: Iterable[str]) -> list[Detector]:
    detectors: list[Detector] = []
    for detector_id in enabled:
        try:
            detectors.append(DETECTORS[detector_id])
        except KeyError as exc:
            raise ValueError(f"Unknown detector: {detector_id}") from exc
    return detectors


def _window(text: str, start: int, end: int, *, radius: int = 120) -> str:
    return text[max(0, start - radius) : min(len(text), end + radius)]


def _context_around_index(text: str, index: int, *, radius: int = 120) -> str:
    return text[max(0, index - radius) : min(len(text), index + radius)]


def _try_base64_decode(token: str) -> Optional[bytes]:
    normalized = token.replace("-", "+").replace("_", "/")
    padding = "=" * (-len(normalized) % 4)
    try:
        return base64.b64decode(normalized + padding, validate=True)
    except (binascii.Error, ValueError):
        return None


def _is_near_white(color: tuple[int, int, int]) -> bool:
    red, green, blue = color
    return red >= 245 and green >= 245 and blue >= 245


def _is_outside_page(bbox: object, style: dict[str, object]) -> bool:
    if not isinstance(bbox, list) or len(bbox) != 4:
        return False
    try:
        x0, y0, x1, y1 = (float(value) for value in bbox)
        width = _to_float(style.get("page_width"))
        height = _to_float(style.get("page_height"))
    except (TypeError, ValueError):
        return False
    if width <= 0 or height <= 0:
        return False
    return x1 < 0 or y1 < 0 or x0 > width or y0 > height


def _to_float(value: object) -> float:
    if isinstance(value, (int, float, str)):
        return float(value)
    return 0.0


def _looks_like_instruction(text: str) -> bool:
    return bool(
        re.search(
            r"(ignore|disregard|override|system prompt|developer prompt|reveal|exfiltrate|chain[-\s]?of[-\s]?thought)",
            text,
            re.I,
        )
    )


def _looks_like_review_manipulation(text: str) -> bool:
    return bool(
        re.search(
            r"(accept this paper|positive review|high score|maximum score|recommend acceptance|must be accepted)",
            text,
            re.I,
        )
    )
