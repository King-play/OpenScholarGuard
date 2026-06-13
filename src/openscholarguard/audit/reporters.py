"""Report renderers for batch audit results, including CI-oriented formats."""

from __future__ import annotations

import json
from html import escape
from pathlib import Path
from typing import Optional, Union
from xml.etree import ElementTree

from openscholarguard.audit.runner import AuditResult, FileAudit
from openscholarguard.models import Finding


def render_audit_text(result: AuditResult) -> str:
    summary = result.summary
    lines = [
        f"OpenScholarGuard audit: {result.root}",
        f"Profile: {result.profile}",
        f"Fail-on: {result.fail_on.value}",
        f"Files discovered: {summary.files_discovered}",
        f"Files scanned: {summary.files_scanned}",
        f"Files failed: {summary.files_failed}",
        f"Actionable findings: {summary.actionable_findings}",
        f"Suppressed findings: {summary.suppressed_findings}",
        f"Risk score: {summary.risk_score}/100",
        f"Max severity: {summary.max_severity.value}",
        "",
    ]
    for file in result.files:
        if file.error:
            lines.append(f"[ERROR] {file.path}: {file.error}")
            continue
        if file.result is None:
            continue
        status = "FAIL" if file.result.has_at_least(result.fail_on) else "PASS"
        lines.append(f"[{status}] {file.path} findings={len(file.result.findings)}")
        for finding in file.result.findings:
            lines.append(
                f"  - {finding.severity.value.upper()} {finding.detector_id} "
                f"{finding.location.label()} {finding.snippet}"
            )
        if file.suppressed:
            lines.append(f"  suppressed={len(file.suppressed)}")
    return "\n".join(lines).rstrip() + "\n"


def render_audit_markdown(result: AuditResult) -> str:
    summary = result.summary
    lines = [
        "# OpenScholarGuard Audit Report",
        "",
        f"- Root: `{result.root}`",
        f"- Profile: `{result.profile}`",
        f"- Fail-on: `{result.fail_on.value}`",
        f"- Files discovered: **{summary.files_discovered}**",
        f"- Files scanned: **{summary.files_scanned}**",
        f"- Files failed: **{summary.files_failed}**",
        f"- Actionable findings: **{summary.actionable_findings}**",
        f"- Suppressed findings: **{summary.suppressed_findings}**",
        f"- Risk score: **{summary.risk_score}/100**",
        "",
        "## Files",
        "",
        "| Status | File | Findings | Suppressed | Error |",
        "| --- | --- | ---: | ---: | --- |",
    ]
    for file in result.files:
        status = _file_status(file, result)
        lines.append(
            f"| {status} | `{file.path}` | {_finding_count(file)} | "
            f"{len(file.suppressed)} | {file.error or '-'} |"
        )
    lines.extend(["", "## Findings", ""])
    for file in result.files:
        if file.result is None:
            continue
        for finding in file.result.findings:
            lines.extend(
                [
                    f"### {finding.severity.value.upper()}: {finding.title}",
                    "",
                    f"- File: `{file.path}`",
                    f"- Detector: `{finding.detector_id}`",
                    f"- Location: `{finding.location.label()}`",
                    "",
                    "```text",
                    finding.snippet,
                    "```",
                    "",
                ]
            )
    return "\n".join(lines).rstrip() + "\n"


def render_audit_html(result: AuditResult) -> str:
    summary = result.summary
    rows = "\n".join(_html_file_row(file, result) for file in result.files)
    findings = "\n".join(
        _html_finding(file, finding)
        for file in result.files
        if file.result is not None
        for finding in file.result.findings
    )
    if not findings:
        findings = '<p class="empty">No actionable findings.</p>'
    payload = escape(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>OpenScholarGuard Audit Report</title>
  <style>
    :root {{
      --bg: #f7f8fa;
      --panel: #ffffff;
      --text: #17202a;
      --muted: #657181;
      --line: #d9dee6;
      --pass: #2f7d46;
      --fail: #a11b2b;
      --accent: #385f8f;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font: 14px/1.55 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }}
    main {{ width: min(1120px, calc(100vw - 32px)); margin: 32px auto; }}
    header {{ border-bottom: 1px solid var(--line); padding-bottom: 20px; margin-bottom: 20px; }}
    h1 {{ font-size: 28px; margin: 0 0 8px; }}
    h2 {{ font-size: 18px; margin: 28px 0 12px; }}
    .muted {{ color: var(--muted); overflow-wrap: anywhere; }}
    .summary {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 12px;
      margin: 20px 0;
    }}
    .metric {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 14px;
    }}
    .metric strong {{ display: block; font-size: 22px; color: var(--accent); }}
    table {{
      width: 100%;
      border-collapse: collapse;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      overflow: hidden;
    }}
    th, td {{ padding: 10px 12px; border-bottom: 1px solid var(--line); text-align: left; }}
    th {{ background: #edf1f6; font-weight: 650; }}
    tr:last-child td {{ border-bottom: 0; }}
    .pass {{ color: var(--pass); font-weight: 700; }}
    .fail, .error {{ color: var(--fail); font-weight: 700; }}
    .finding {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 16px;
      margin: 12px 0;
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
      <h1>OpenScholarGuard Audit Report</h1>
      <div class="muted">{escape(result.root)}</div>
    </header>
    <section class="summary" aria-label="Audit summary">
      <div class="metric"><span>Files scanned</span><strong>{summary.files_scanned}</strong></div>
      <div class="metric"><span>Files failed</span><strong>{summary.files_failed}</strong></div>
      <div class="metric"><span>Findings</span><strong>{summary.actionable_findings}</strong></div>
      <div class="metric"><span>Suppressed</span><strong>{summary.suppressed_findings}</strong></div>
      <div class="metric"><span>Risk score</span><strong>{summary.risk_score}/100</strong></div>
    </section>
    <h2>Files</h2>
    <table>
      <thead><tr><th>Status</th><th>File</th><th>Findings</th><th>Suppressed</th><th>Error</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
    <h2>Findings</h2>
    {findings}
    <details>
      <summary>Raw JSON</summary>
      <pre>{payload}</pre>
    </details>
  </main>
</body>
</html>
"""


def render_sarif(result: AuditResult) -> str:
    rules: dict[str, dict[str, object]] = {}
    sarif_results: list[dict[str, object]] = []
    for file in result.files:
        if file.result is None:
            continue
        for finding in file.result.findings:
            rules.setdefault(
                finding.detector_id,
                {
                    "id": finding.detector_id,
                    "name": finding.title,
                    "shortDescription": {"text": finding.title},
                    "help": {"text": finding.remediation or "Review the finding evidence."},
                },
            )
            sarif_results.append(_sarif_result(finding, result.root))
    payload = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "OpenScholarGuard",
                        "informationUri": "https://github.com/King-play/OpenScholarGuard",
                        "rules": list(rules.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def render_junit(result: AuditResult) -> str:
    suite = ElementTree.Element(
        "testsuite",
        {
            "name": "OpenScholarGuard audit",
            "tests": str(result.summary.files_discovered),
            "failures": str(result.summary.files_failed),
            "errors": str(sum(1 for file in result.files if file.error)),
        },
    )
    for file in result.files:
        case = ElementTree.SubElement(
            suite,
            "testcase",
            {"classname": "openscholarguard.audit", "name": file.path},
        )
        if file.error:
            error = ElementTree.SubElement(case, "error", {"message": file.error})
            error.text = file.error
        elif file.result is not None and file.result.has_at_least(result.fail_on):
            failure = ElementTree.SubElement(
                case,
                "failure",
                {"message": f"{len(file.result.findings)} actionable findings"},
            )
            failure.text = "\n".join(
                f"{finding.severity.value}: {finding.detector_id}: {finding.snippet}"
                for finding in file.result.findings
            )
    return ElementTree.tostring(suite, encoding="unicode")


def write_audit_report(
    result: AuditResult,
    output: Union[str, Path],
    *,
    fmt: Optional[str] = None,
) -> Path:
    output_path = Path(output).expanduser()
    fmt = fmt or _guess_format(output_path)
    content = render_audit_report(result, fmt=fmt)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")
    return output_path


def render_audit_report(result: AuditResult, *, fmt: str) -> str:
    if fmt == "json":
        return json.dumps(result.to_dict(), indent=2, sort_keys=True)
    if fmt == "html":
        return render_audit_html(result)
    if fmt in {"md", "markdown"}:
        return render_audit_markdown(result)
    if fmt in {"txt", "text"}:
        return render_audit_text(result)
    if fmt == "sarif":
        return render_sarif(result)
    if fmt == "junit":
        return render_junit(result)
    raise ValueError(f"Unsupported audit report format: {fmt}")


def _file_status(file: FileAudit, result: AuditResult) -> str:
    if file.error:
        return "ERROR"
    if file.result is not None and file.result.has_at_least(result.fail_on):
        return "FAIL"
    return "PASS"


def _finding_count(file: FileAudit) -> int:
    return len(file.result.findings) if file.result is not None else 0


def _html_file_row(file: FileAudit, result: AuditResult) -> str:
    status = _file_status(file, result)
    status_class = status.lower()
    return f"""
<tr>
  <td class="{status_class}">{status}</td>
  <td><code>{escape(file.path)}</code></td>
  <td>{_finding_count(file)}</td>
  <td>{len(file.suppressed)}</td>
  <td>{escape(file.error or "-")}</td>
</tr>
"""


def _html_finding(file: FileAudit, finding: Finding) -> str:
    return f"""
<article class="finding">
  <h3>{escape(finding.severity.value.upper())}: {escape(finding.title)}</h3>
  <div class="muted"><code>{escape(file.path)}</code> · <code>{escape(finding.detector_id)}</code></div>
  <div class="muted">{escape(finding.location.label())}</div>
  <pre>{escape(finding.snippet)}</pre>
</article>
"""


def _sarif_result(finding: Finding, root: str) -> dict[str, object]:
    path = Path(finding.location.path)
    try:
        uri = path.resolve().relative_to(Path(root).resolve()).as_posix()
    except ValueError:
        uri = path.as_posix()
    region: dict[str, int] = {}
    if finding.location.line is not None:
        region["startLine"] = finding.location.line
    return {
        "ruleId": finding.detector_id,
        "level": _sarif_level(finding.severity.value),
        "message": {"text": f"{finding.title}: {finding.snippet}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": region or {"startLine": 1},
                }
            }
        ],
        "partialFingerprints": {"findingId": finding.id},
    }


def _sarif_level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"


def _guess_format(path: Path) -> str:
    suffix = path.suffix.lower().lstrip(".")
    if suffix == "xml":
        return "junit"
    return suffix or "json"
