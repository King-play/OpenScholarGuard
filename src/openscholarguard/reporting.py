"""Report renderers for scan and sanitize results."""

from __future__ import annotations

import json
from html import escape
from pathlib import Path
from typing import Optional, Union

from openscholarguard.models import Finding, ScanResult


def render_text_report(result: ScanResult) -> str:
    lines = [
        f"OpenScholarGuard scan: {result.target}",
        f"Profile: {result.profile}",
        f"Risk score: {result.summary.risk_score}/100",
        f"Max severity: {result.summary.max_severity.value}",
        f"Findings: {result.summary.total_findings}",
        "",
    ]
    for finding in result.findings:
        lines.extend(
            [
                f"[{finding.severity.value.upper()}] {finding.title}",
                f"  id: {finding.id}",
                f"  detector: {finding.detector_id}",
                f"  confidence: {finding.confidence:.2f}",
                f"  location: {finding.location.label()}",
                f"  snippet: {finding.snippet}",
            ]
        )
        if finding.remediation:
            lines.append(f"  remediation: {finding.remediation}")
        lines.append("")
    if result.errors:
        lines.append("Detector errors:")
        lines.extend(f"  - {error}" for error in result.errors)
    return "\n".join(lines).rstrip() + "\n"


def render_markdown_report(result: ScanResult) -> str:
    lines = [
        "# OpenScholarGuard Scan Report",
        "",
        f"- Target: `{result.target}`",
        f"- Profile: `{result.profile}`",
        f"- Scanned at: `{result.scanned_at}`",
        f"- Risk score: **{result.summary.risk_score}/100**",
        f"- Max severity: **{result.summary.max_severity.value}**",
        f"- Findings: **{result.summary.total_findings}**",
        "",
        "## Findings",
        "",
    ]
    if not result.findings:
        lines.append("No findings.")
        return "\n".join(lines) + "\n"

    for finding in result.findings:
        lines.extend(_markdown_finding(finding))
    return "\n".join(lines).rstrip() + "\n"


def render_html_report(result: ScanResult) -> str:
    findings_html = "\n".join(_html_finding(finding) for finding in result.findings)
    if not findings_html:
        findings_html = '<p class="empty">No findings.</p>'
    payload = escape(json.dumps(result.to_dict(), indent=2))
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>OpenScholarGuard Scan Report</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f6f7f9;
      --panel: #ffffff;
      --text: #17202a;
      --muted: #657181;
      --line: #d9dee6;
      --info: #4b6b8a;
      --low: #547a33;
      --medium: #9b6500;
      --high: #b44716;
      --critical: #a11b2b;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font: 14px/1.55 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }}
    main {{
      width: min(1120px, calc(100vw - 32px));
      margin: 32px auto;
    }}
    header {{
      border-bottom: 1px solid var(--line);
      margin-bottom: 20px;
      padding-bottom: 20px;
    }}
    h1 {{ font-size: 28px; margin: 0 0 8px; }}
    h2 {{ font-size: 18px; margin: 28px 0 12px; }}
    .muted {{ color: var(--muted); overflow-wrap: anywhere; }}
    .summary {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 12px;
      margin: 20px 0;
    }}
    .metric {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 14px;
    }}
    .metric strong {{ display: block; font-size: 22px; }}
    .finding {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-left: 5px solid var(--muted);
      border-radius: 8px;
      padding: 16px;
      margin: 12px 0;
    }}
    .finding.info {{ border-left-color: var(--info); }}
    .finding.low {{ border-left-color: var(--low); }}
    .finding.medium {{ border-left-color: var(--medium); }}
    .finding.high {{ border-left-color: var(--high); }}
    .finding.critical {{ border-left-color: var(--critical); }}
    .finding h3 {{ margin: 0 0 8px; font-size: 16px; }}
    .badge {{
      display: inline-block;
      border: 1px solid currentColor;
      border-radius: 999px;
      padding: 1px 8px;
      font-size: 12px;
      text-transform: uppercase;
    }}
    pre {{
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      background: #101820;
      color: #f5f7fa;
      border-radius: 8px;
      padding: 12px;
    }}
    code {{ overflow-wrap: anywhere; }}
    details {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px 16px;
      margin-top: 18px;
    }}
  </style>
</head>
<body>
  <main>
    <header>
      <h1>OpenScholarGuard Scan Report</h1>
      <div class="muted">{escape(result.target)}</div>
    </header>
    <section class="summary" aria-label="Scan summary">
      <div class="metric"><span>Risk score</span><strong>{result.summary.risk_score}/100</strong></div>
      <div class="metric"><span>Max severity</span><strong>{escape(result.summary.max_severity.value)}</strong></div>
      <div class="metric"><span>Findings</span><strong>{result.summary.total_findings}</strong></div>
      <div class="metric"><span>Profile</span><strong>{escape(result.profile)}</strong></div>
    </section>
    <h2>Findings</h2>
    {findings_html}
    <details>
      <summary>Raw JSON</summary>
      <pre>{payload}</pre>
    </details>
  </main>
</body>
</html>
"""


def write_report(
    result: ScanResult,
    output: Union[str, Path],
    *,
    fmt: Optional[str] = None,
) -> Path:
    output_path = Path(output).expanduser()
    fmt = fmt or _guess_format(output_path)
    if fmt == "json":
        content = result.to_json()
    elif fmt == "html":
        content = render_html_report(result)
    elif fmt in {"md", "markdown"}:
        content = render_markdown_report(result)
    elif fmt in {"txt", "text"}:
        content = render_text_report(result)
    else:
        raise ValueError(f"Unsupported report format: {fmt}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")
    return output_path


def _markdown_finding(finding: Finding) -> list[str]:
    lines = [
        f"### {finding.severity.value.upper()}: {finding.title}",
        "",
        f"- ID: `{finding.id}`",
        f"- Detector: `{finding.detector_id}`",
        f"- Confidence: `{finding.confidence:.2f}`",
        f"- Location: `{finding.location.label()}`",
        "",
        "```text",
        finding.snippet,
        "```",
        "",
    ]
    if finding.remediation:
        lines.extend(["Remediation: " + finding.remediation, ""])
    return lines


def _html_finding(finding: Finding) -> str:
    evidence = escape(json.dumps(finding.evidence, indent=2, sort_keys=True))
    return f"""
<article class="finding {escape(finding.severity.value)}">
  <h3><span class="badge">{escape(finding.severity.value)}</span> {escape(finding.title)}</h3>
  <div class="muted">Detector: <code>{escape(finding.detector_id)}</code> · Confidence: {finding.confidence:.2f}</div>
  <div class="muted">Location: {escape(finding.location.label())}</div>
  <pre>{escape(finding.snippet)}</pre>
  <p>{escape(finding.remediation)}</p>
  <details><summary>Evidence</summary><pre>{evidence}</pre></details>
</article>
"""


def _guess_format(path: Path) -> str:
    suffix = path.suffix.lower().lstrip(".")
    return suffix or "json"
