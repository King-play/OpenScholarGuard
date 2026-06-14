"""PDF deep-audit utilities for OCR, image, and visual/text-layer mismatch signals."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from html import escape
from pathlib import Path
from typing import Any, Optional, Union

from openscholarguard.exceptions import DependencyMissingError
from openscholarguard.models import Severity, _json_ready


@dataclass(frozen=True)
class PdfDeepScanOptions:
    """Configuration for PDF deep-audit checks."""

    dpi: int = 96
    enable_ocr: bool = False
    ocr_language: str = "eng"
    min_text_chars: int = 24
    visual_nonwhite_threshold: float = 0.01


@dataclass(frozen=True)
class PdfDeepSignal:
    """One deep-audit signal from a PDF page or document."""

    kind: str
    title: str
    severity: Severity
    page: Optional[int]
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return _json_ready(asdict(self))


@dataclass(frozen=True)
class PdfDeepScanResult:
    """PDF deep-audit result."""

    path: str
    pages: int
    text_chars: int
    image_count: int
    hidden_span_count: int
    ocr_candidate_pages: list[int]
    visual_mismatch_pages: list[int]
    signals: list[PdfDeepSignal]
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return _json_ready(asdict(self))

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)


def scan_pdf_deep(path: Union[str, Path], *, options: PdfDeepScanOptions | None = None) -> PdfDeepScanResult:
    """Inspect PDF surfaces that ordinary text extraction can miss."""

    try:
        import fitz  # type: ignore[import-untyped]
    except ImportError as exc:
        raise DependencyMissingError("Install PyMuPDF to run PDF deep audit: pip install pymupdf") from exc

    options = options or PdfDeepScanOptions()
    pdf_path = Path(path).expanduser().resolve()
    pdf = fitz.open(pdf_path)
    page_count = pdf.page_count
    signals: list[PdfDeepSignal] = []
    warnings: list[str] = []
    text_chars = 0
    image_count = 0
    hidden_span_count = 0
    ocr_candidate_pages: list[int] = []
    visual_mismatch_pages: list[int] = []

    try:
        for page_index, page in enumerate(pdf, start=1):
            page_text = page.get_text("text") or ""
            page_text_chars = len(page_text.strip())
            text_chars += page_text_chars
            image_blocks = _image_block_count(page)
            page_images = len(page.get_images(full=True))
            page_image_count = max(image_blocks, page_images)
            image_count += page_image_count

            hidden_spans = _hidden_span_count(page)
            hidden_span_count += hidden_spans
            if hidden_spans:
                signals.append(
                    PdfDeepSignal(
                        kind="hidden_pdf_span",
                        title="PDF contains visually hidden text spans",
                        severity=Severity.HIGH,
                        page=page_index,
                        description="Tiny, near-white, transparent, or off-page spans may be model-visible but hard for humans to inspect.",
                        evidence={"hidden_span_count": hidden_spans},
                    )
                )

            if page_image_count and page_text_chars < options.min_text_chars:
                ocr_candidate_pages.append(page_index)
                signals.append(
                    PdfDeepSignal(
                        kind="ocr_candidate_page",
                        title="Image-heavy page has little extractable text",
                        severity=Severity.MEDIUM,
                        page=page_index,
                        description="This page may require OCR before prompt-injection scanning is complete.",
                        evidence={"image_count": page_image_count, "text_chars": page_text_chars},
                    )
                )

            nonwhite_ratio = _page_nonwhite_ratio(page, dpi=options.dpi)
            if nonwhite_ratio >= options.visual_nonwhite_threshold and page_text_chars < options.min_text_chars:
                visual_mismatch_pages.append(page_index)
                signals.append(
                    PdfDeepSignal(
                        kind="visual_text_mismatch",
                        title="Rendered page appears nonblank but text layer is sparse",
                        severity=Severity.HIGH,
                        page=page_index,
                        description="The visual page has content that is not represented in the extracted text layer.",
                        evidence={
                            "nonwhite_ratio": round(nonwhite_ratio, 5),
                            "text_chars": page_text_chars,
                        },
                    )
                )

            if options.enable_ocr:
                ocr_text = _try_extract_ocr_text(page, language=options.ocr_language, dpi=options.dpi, warnings=warnings)
                if ocr_text and len(ocr_text.strip()) > page_text_chars + options.min_text_chars:
                    signals.append(
                        PdfDeepSignal(
                            kind="ocr_text_delta",
                            title="OCR text adds substantial content beyond the PDF text layer",
                            severity=Severity.MEDIUM,
                            page=page_index,
                            description="OCR-visible content should be scanned before the document is trusted.",
                            evidence={
                                "text_chars": page_text_chars,
                                "ocr_chars": len(ocr_text.strip()),
                            },
                        )
                    )
    finally:
        pdf.close()

    return PdfDeepScanResult(
        path=str(pdf_path),
        pages=page_count,
        text_chars=text_chars,
        image_count=image_count,
        hidden_span_count=hidden_span_count,
        ocr_candidate_pages=ocr_candidate_pages,
        visual_mismatch_pages=visual_mismatch_pages,
        signals=signals,
        warnings=warnings,
    )


def render_pdf_deep_text(result: PdfDeepScanResult) -> str:
    lines = [
        f"OpenScholarGuard PDF deep audit: {result.path}",
        f"Pages: {result.pages}",
        f"Extracted text chars: {result.text_chars}",
        f"Images: {result.image_count}",
        f"Hidden spans: {result.hidden_span_count}",
        f"OCR candidate pages: {', '.join(str(page) for page in result.ocr_candidate_pages) or '-'}",
        f"Visual/text mismatch pages: {', '.join(str(page) for page in result.visual_mismatch_pages) or '-'}",
        "",
    ]
    for signal in result.signals:
        page = f"page {signal.page}" if signal.page else "document"
        lines.append(f"[{signal.severity.value.upper()}] {signal.kind} ({page}): {signal.title}")
        lines.append(f"  {signal.description}")
    if result.warnings:
        lines.append("")
        lines.append("Warnings:")
        lines.extend(f"  - {warning}" for warning in result.warnings)
    return "\n".join(lines).rstrip() + "\n"


def render_pdf_deep_markdown(result: PdfDeepScanResult) -> str:
    lines = [
        "# OpenScholarGuard PDF Deep Audit",
        "",
        f"- Path: `{result.path}`",
        f"- Pages: {result.pages}",
        f"- Extracted text chars: {result.text_chars}",
        f"- Images: {result.image_count}",
        f"- Hidden spans: {result.hidden_span_count}",
        "",
        "| Severity | Kind | Page | Signal |",
        "| --- | --- | ---: | --- |",
    ]
    for signal in result.signals:
        page = str(signal.page) if signal.page else "-"
        lines.append(f"| `{signal.severity.value}` | `{signal.kind}` | {page} | {signal.title} |")
    if result.warnings:
        lines.extend(["", "## Warnings", ""])
        lines.extend(f"- {warning}" for warning in result.warnings)
    return "\n".join(lines).rstrip() + "\n"


def render_pdf_deep_html(result: PdfDeepScanResult) -> str:
    rows = "\n".join(
        "<tr>"
        f"<td>{escape(signal.severity.value)}</td>"
        f"<td><code>{escape(signal.kind)}</code></td>"
        f"<td>{escape(str(signal.page or '-'))}</td>"
        f"<td>{escape(signal.title)}</td>"
        "</tr>"
        for signal in result.signals
    )
    payload = escape(result.to_json())
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>OpenScholarGuard PDF Deep Audit</title>
  <style>
    body {{ margin: 0; background: #f6f8fb; color: #111827; font: 14px/1.55 system-ui, sans-serif; }}
    main {{ width: min(1080px, calc(100vw - 32px)); margin: 32px auto; }}
    h1 {{ margin: 0 0 8px; }}
    .metrics {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin: 22px 0; }}
    .metric {{ background: #fff; border: 1px solid #d8e0eb; border-radius: 8px; padding: 14px; }}
    .metric strong {{ display: block; font-size: 22px; }}
    table {{ width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #d8e0eb; }}
    th, td {{ padding: 10px 12px; border-bottom: 1px solid #d8e0eb; text-align: left; }}
    th {{ background: #f1f5f9; }}
    pre {{ white-space: pre-wrap; overflow-wrap: anywhere; background: #101820; color: #fff; border-radius: 8px; padding: 12px; }}
  </style>
</head>
<body>
  <main>
    <h1>OpenScholarGuard PDF Deep Audit</h1>
    <p>{escape(result.path)}</p>
    <section class="metrics">
      <div class="metric"><span>Pages</span><strong>{result.pages}</strong></div>
      <div class="metric"><span>Text chars</span><strong>{result.text_chars}</strong></div>
      <div class="metric"><span>Images</span><strong>{result.image_count}</strong></div>
      <div class="metric"><span>Signals</span><strong>{len(result.signals)}</strong></div>
    </section>
    <table><thead><tr><th>Severity</th><th>Kind</th><th>Page</th><th>Signal</th></tr></thead><tbody>{rows}</tbody></table>
    <details><summary>Raw JSON</summary><pre>{payload}</pre></details>
  </main>
</body>
</html>
"""


def write_pdf_deep_report(
    result: PdfDeepScanResult,
    output: Union[str, Path],
    *,
    fmt: Optional[str] = None,
) -> Path:
    output_path = Path(output).expanduser()
    fmt = fmt or output_path.suffix.lower().lstrip(".") or "json"
    if fmt == "json":
        content = result.to_json()
    elif fmt in {"txt", "text"}:
        content = render_pdf_deep_text(result)
    elif fmt in {"md", "markdown"}:
        content = render_pdf_deep_markdown(result)
    elif fmt == "html":
        content = render_pdf_deep_html(result)
    else:
        raise ValueError(f"Unsupported PDF deep-audit format: {fmt}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")
    return output_path


def _image_block_count(page: Any) -> int:
    raw = page.get_text("dict")
    return sum(1 for block in raw.get("blocks", []) if block.get("type") == 1)


def _hidden_span_count(page: Any) -> int:
    raw = page.get_text("dict")
    page_rect = page.rect
    hidden = 0
    for block in raw.get("blocks", []):
        for line in block.get("lines", []):
            for span in line.get("spans", []):
                text = str(span.get("text", "")).strip()
                if len(text) < 4:
                    continue
                size = float(span.get("size", 0) or 0)
                color = _int_rgb(int(span.get("color", 0)))
                alpha = float(span.get("alpha", span.get("fill_opacity", 1)) or 1)
                bbox = span.get("bbox", [0, 0, 0, 0])
                if size <= 3 or _is_near_white(color) or alpha <= 0.05 or _outside_page(bbox, page_rect):
                    hidden += 1
    return hidden


def _page_nonwhite_ratio(page: Any, *, dpi: int) -> float:
    pixmap = page.get_pixmap(alpha=False, dpi=max(36, min(dpi, 144)))
    samples = pixmap.samples
    if not samples:
        return 0.0
    channels = pixmap.n
    pixels = max(1, len(samples) // channels)
    nonwhite = 0
    for offset in range(0, len(samples), channels):
        red = samples[offset]
        green = samples[offset + 1] if channels > 1 else red
        blue = samples[offset + 2] if channels > 2 else red
        if red < 245 or green < 245 or blue < 245:
            nonwhite += 1
    return nonwhite / pixels


def _try_extract_ocr_text(page: Any, *, language: str, dpi: int, warnings: list[str]) -> str:
    if not hasattr(page, "get_textpage_ocr"):
        warnings.append("PyMuPDF OCR textpage API is not available in this environment.")
        return ""
    try:
        textpage = page.get_textpage_ocr(language=language, dpi=dpi, full=True)
        return page.get_text("text", textpage=textpage)
    except Exception as exc:  # pragma: no cover - depends on local Tesseract/PyMuPDF build
        warnings.append(f"OCR extraction failed: {exc}")
        return ""


def _int_rgb(value: int) -> tuple[int, int, int]:
    red = (value >> 16) & 255
    green = (value >> 8) & 255
    blue = value & 255
    return red, green, blue


def _is_near_white(color: tuple[int, int, int]) -> bool:
    red, green, blue = color
    return red >= 245 and green >= 245 and blue >= 245


def _outside_page(bbox: object, page_rect: Any) -> bool:
    if not isinstance(bbox, list) or len(bbox) != 4:
        return False
    try:
        x0, y0, x1, y1 = (float(value) for value in bbox)
    except (TypeError, ValueError):
        return False
    return x1 < 0 or y1 < 0 or x0 > float(page_rect.width) or y0 > float(page_rect.height)
