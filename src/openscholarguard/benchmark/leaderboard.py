"""Render benchmark evaluations as human-readable reports."""

from __future__ import annotations

import json
from html import escape
from pathlib import Path
from typing import Optional, Union

from openscholarguard.benchmark.models import BenchmarkEvaluation, BenchmarkSampleResult


def render_benchmark_text(evaluation: BenchmarkEvaluation) -> str:
    metrics = evaluation.metrics
    lines = [
        f"OpenScholarGuard benchmark: {evaluation.dataset} {evaluation.version}",
        f"Profile: {evaluation.profile}",
        f"Fail-on: {evaluation.fail_on.value}",
        f"Samples: {metrics.total}",
        f"Accuracy: {metrics.accuracy:.4f}",
        f"Precision: {metrics.precision:.4f}",
        f"Recall: {metrics.recall:.4f}",
        f"F1: {metrics.f1:.4f}",
        f"Detector recall: {metrics.detector_recall:.4f}",
        "",
    ]
    for sample in evaluation.samples:
        status = "PASS" if sample.passed else "FAIL"
        lines.append(
            f"[{status}] {sample.case_id} "
            f"family={sample.family.value} expected={sample.expected_malicious} "
            f"predicted={sample.predicted_malicious} severity={sample.max_severity.value}"
        )
        if sample.missing_detectors:
            lines.append(f"  missing: {', '.join(sample.missing_detectors)}")
        if sample.unexpected_detectors:
            lines.append(f"  additional: {', '.join(sample.unexpected_detectors)}")
    if evaluation.warnings:
        lines.append("")
        lines.append("Warnings:")
        lines.extend(f"  - {warning}" for warning in evaluation.warnings)
    return "\n".join(lines).rstrip() + "\n"


def render_benchmark_markdown(evaluation: BenchmarkEvaluation) -> str:
    metrics = evaluation.metrics
    lines = [
        "# OpenScholarGuard Benchmark Report",
        "",
        f"- Dataset: `{evaluation.dataset}`",
        f"- Version: `{evaluation.version}`",
        f"- Profile: `{evaluation.profile}`",
        f"- Fail-on: `{evaluation.fail_on.value}`",
        "",
        "## Metrics",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| Samples | {metrics.total} |",
        f"| Accuracy | {metrics.accuracy:.4f} |",
        f"| Precision | {metrics.precision:.4f} |",
        f"| Recall | {metrics.recall:.4f} |",
        f"| F1 | {metrics.f1:.4f} |",
        f"| Detector recall | {metrics.detector_recall:.4f} |",
        "",
        "## Samples",
        "",
        "| Status | Case | Family | Expected | Predicted | Severity | Missing | Additional |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for sample in evaluation.samples:
        status = "PASS" if sample.passed else "FAIL"
        lines.append(
            "| "
            f"{status} | `{sample.case_id}` | `{sample.family.value}` | "
            f"{sample.expected_malicious} | {sample.predicted_malicious} | "
            f"`{sample.max_severity.value}` | {', '.join(sample.missing_detectors) or '-'} | "
            f"{', '.join(sample.unexpected_detectors) or '-'} |"
        )
    return "\n".join(lines).rstrip() + "\n"


def render_benchmark_html(evaluation: BenchmarkEvaluation) -> str:
    metrics = evaluation.metrics
    rows = "\n".join(_html_sample_row(sample) for sample in evaluation.samples)
    payload = escape(json.dumps(evaluation.to_dict(), indent=2, sort_keys=True))
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>OpenScholarGuard Benchmark Report</title>
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
    .muted {{ color: var(--muted); }}
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
    .fail {{ color: var(--fail); font-weight: 700; }}
    code {{ overflow-wrap: anywhere; }}
    pre {{
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      background: #101820;
      color: #f5f7fa;
      border-radius: 8px;
      padding: 12px;
    }}
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
      <h1>OpenScholarGuard Benchmark Report</h1>
      <div class="muted">{escape(evaluation.dataset)} {escape(evaluation.version)} · {escape(evaluation.profile)}</div>
    </header>
    <section class="summary" aria-label="Benchmark metrics">
      <div class="metric"><span>Accuracy</span><strong>{metrics.accuracy:.4f}</strong></div>
      <div class="metric"><span>Precision</span><strong>{metrics.precision:.4f}</strong></div>
      <div class="metric"><span>Recall</span><strong>{metrics.recall:.4f}</strong></div>
      <div class="metric"><span>F1</span><strong>{metrics.f1:.4f}</strong></div>
      <div class="metric"><span>Detector recall</span><strong>{metrics.detector_recall:.4f}</strong></div>
    </section>
    <h2>Samples</h2>
    <table>
      <thead>
        <tr>
          <th>Status</th>
          <th>Case</th>
          <th>Family</th>
          <th>Expected</th>
          <th>Predicted</th>
          <th>Severity</th>
          <th>Missing</th>
          <th>Additional</th>
        </tr>
      </thead>
      <tbody>
        {rows}
      </tbody>
    </table>
    <details>
      <summary>Raw JSON</summary>
      <pre>{payload}</pre>
    </details>
  </main>
</body>
</html>
"""


def write_benchmark_report(
    evaluation: BenchmarkEvaluation,
    output: Union[str, Path],
    *,
    fmt: Optional[str] = None,
) -> Path:
    output_path = Path(output).expanduser()
    fmt = fmt or _guess_format(output_path)
    if fmt == "json":
        content = evaluation.to_json()
    elif fmt == "html":
        content = render_benchmark_html(evaluation)
    elif fmt in {"md", "markdown"}:
        content = render_benchmark_markdown(evaluation)
    elif fmt in {"txt", "text"}:
        content = render_benchmark_text(evaluation)
    else:
        raise ValueError(f"Unsupported benchmark report format: {fmt}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")
    return output_path


def _html_sample_row(sample: BenchmarkSampleResult) -> str:
    status = "PASS" if sample.passed else "FAIL"
    status_class = "pass" if sample.passed else "fail"
    missing = ", ".join(sample.missing_detectors) or "-"
    additional = ", ".join(sample.unexpected_detectors) or "-"
    return f"""
<tr>
  <td class="{status_class}">{status}</td>
  <td><code>{escape(sample.case_id)}</code></td>
  <td>{escape(sample.family.value)}</td>
  <td>{escape(str(sample.expected_malicious))}</td>
  <td>{escape(str(sample.predicted_malicious))}</td>
  <td>{escape(sample.max_severity.value)}</td>
  <td>{escape(missing)}</td>
  <td>{escape(additional)}</td>
</tr>
"""


def _guess_format(path: Path) -> str:
    suffix = path.suffix.lower().lstrip(".")
    return suffix or "json"
