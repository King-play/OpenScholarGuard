"""Render benchmark evaluations as human-readable reports."""

from __future__ import annotations

import json
from html import escape
from pathlib import Path
from typing import Optional, Union

from openscholarguard.benchmark.models import (
    BenchmarkEvaluation,
    BenchmarkSampleResult,
    Leaderboard,
)


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


def render_leaderboard_text(leaderboard: Leaderboard) -> str:
    lines = [
        f"{leaderboard.name}: {leaderboard.dataset} {leaderboard.dataset_version}",
        f"Entries: {len(leaderboard.entries)}",
        "",
        "Rank  System                     Version       DetRecall  F1      Accuracy  Samples",
    ]
    for index, entry in enumerate(leaderboard.entries, start=1):
        lines.append(
            f"{index:<5} "
            f"{entry.system[:26]:<26} "
            f"{entry.version[:12]:<12} "
            f"{entry.metrics.detector_recall:<9.4f} "
            f"{entry.metrics.f1:<7.4f} "
            f"{entry.metrics.accuracy:<8.4f} "
            f"{entry.metrics.total}"
        )
    return "\n".join(lines).rstrip() + "\n"


def render_leaderboard_markdown(leaderboard: Leaderboard) -> str:
    lines = [
        f"# {leaderboard.name} Leaderboard",
        "",
        f"- Dataset: `{leaderboard.dataset}`",
        f"- Version: `{leaderboard.dataset_version}`",
        f"- Generated: `{leaderboard.generated_at}`",
        "",
        "| Rank | System | Version | Detector Recall | F1 | Accuracy | Samples | Runner |",
        "| ---: | --- | --- | ---: | ---: | ---: | ---: | --- |",
    ]
    for index, entry in enumerate(leaderboard.entries, start=1):
        system = _markdown_link(entry.system, entry.url)
        lines.append(
            f"| {index} | {system} | `{entry.version}` | "
            f"{entry.metrics.detector_recall:.4f} | {entry.metrics.f1:.4f} | "
            f"{entry.metrics.accuracy:.4f} | {entry.metrics.total} | `{entry.runner}` |"
        )
    return "\n".join(lines).rstrip() + "\n"


def render_leaderboard_html(leaderboard: Leaderboard) -> str:
    rows = "\n".join(_leaderboard_row(index, entry) for index, entry in enumerate(leaderboard.entries, start=1))
    payload = escape(json.dumps(leaderboard.to_dict(), indent=2, sort_keys=True))
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escape(leaderboard.name)} Leaderboard</title>
  <style>
    :root {{
      --bg: #f5f7fb;
      --panel: #ffffff;
      --ink: #111827;
      --muted: #667085;
      --line: #d8e0eb;
      --green: #087f5b;
      --blue: #175cd3;
      --shadow: 0 24px 70px rgba(17, 24, 39, 0.12);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      color: var(--ink);
      background:
        radial-gradient(circle at 15% 8%, rgba(8, 127, 91, 0.15), transparent 25rem),
        radial-gradient(circle at 85% 0%, rgba(23, 92, 211, 0.12), transparent 24rem),
        var(--bg);
      font: 14px/1.55 Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }}
    main {{ width: min(1180px, calc(100vw - 34px)); margin: 42px auto 68px; }}
    header {{ display: grid; gap: 14px; margin-bottom: 22px; }}
    h1 {{ margin: 0; font-size: clamp(34px, 5vw, 62px); line-height: 1; letter-spacing: 0; }}
    .lead {{ max-width: 780px; color: var(--muted); font-size: 17px; }}
    .summary {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
      gap: 12px;
      margin: 22px 0;
    }}
    .metric {{
      border: 1px solid var(--line);
      border-radius: 8px;
      background: rgba(255, 255, 255, 0.88);
      padding: 14px;
    }}
    .metric span {{ color: var(--muted); font-weight: 700; }}
    .metric strong {{ display: block; margin-top: 4px; font-size: 24px; }}
    .panel {{
      overflow: hidden;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel);
      box-shadow: var(--shadow);
    }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ padding: 13px 14px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; }}
    th {{ background: #f8fafc; color: #475467; font-size: 12px; text-transform: uppercase; }}
    tr:last-child td {{ border-bottom: 0; }}
    .rank {{ font-weight: 850; font-size: 20px; }}
    .system {{ font-weight: 800; }}
    .system a {{ color: var(--blue); text-decoration: none; }}
    .system a:hover {{ text-decoration: underline; }}
    .score {{ color: var(--green); font-weight: 850; }}
    .muted {{ color: var(--muted); }}
    code {{
      border: 1px solid var(--line);
      border-radius: 999px;
      background: #f8fafc;
      padding: 2px 7px;
      font-size: 12px;
    }}
    details {{
      margin-top: 18px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel);
      padding: 12px 16px;
    }}
    pre {{
      overflow: auto;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      border-radius: 8px;
      background: #101820;
      color: #f5f7fa;
      padding: 14px;
    }}
  </style>
</head>
<body>
  <main>
    <header>
      <h1>{escape(leaderboard.name)} Leaderboard</h1>
      <div class="lead">A reproducible ranking for document-borne prompt-injection and AI-review manipulation defenses.</div>
      <div class="summary">
        <div class="metric"><span>Dataset</span><strong>{escape(leaderboard.dataset)}</strong></div>
        <div class="metric"><span>Version</span><strong>{escape(leaderboard.dataset_version)}</strong></div>
        <div class="metric"><span>Entries</span><strong>{len(leaderboard.entries)}</strong></div>
        <div class="metric"><span>Generated</span><strong>{escape(leaderboard.generated_at[:10])}</strong></div>
      </div>
    </header>
    <section class="panel">
      <table>
        <thead>
          <tr>
            <th>Rank</th>
            <th>System</th>
            <th>Version</th>
            <th>Detector Recall</th>
            <th>F1</th>
            <th>Accuracy</th>
            <th>Samples</th>
            <th>Runner</th>
          </tr>
        </thead>
        <tbody>
          {rows}
        </tbody>
      </table>
    </section>
    <details>
      <summary>Raw leaderboard JSON</summary>
      <pre>{payload}</pre>
    </details>
  </main>
</body>
</html>
"""


def write_leaderboard_report(
    leaderboard: Leaderboard,
    output: Union[str, Path],
    *,
    fmt: Optional[str] = None,
) -> Path:
    output_path = Path(output).expanduser()
    fmt = fmt or _guess_format(output_path)
    if fmt == "json":
        content = leaderboard.to_json()
    elif fmt == "html":
        content = render_leaderboard_html(leaderboard)
    elif fmt in {"md", "markdown"}:
        content = render_leaderboard_markdown(leaderboard)
    elif fmt in {"txt", "text"}:
        content = render_leaderboard_text(leaderboard)
    else:
        raise ValueError(f"Unsupported leaderboard report format: {fmt}")
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


def _leaderboard_row(index: int, entry: object) -> str:
    from openscholarguard.benchmark.models import LeaderboardEntry

    if not isinstance(entry, LeaderboardEntry):
        raise TypeError("leaderboard row requires a LeaderboardEntry")
    system = escape(entry.system)
    system_html = f'<a href="{escape(entry.url)}">{system}</a>' if entry.url else system
    return f"""
<tr>
  <td class="rank">{index}</td>
  <td><span class="system">{system_html}</span><br><span class="muted">{escape(entry.notes or "")}</span></td>
  <td><code>{escape(entry.version)}</code></td>
  <td class="score">{entry.metrics.detector_recall:.4f}</td>
  <td>{entry.metrics.f1:.4f}</td>
  <td>{entry.metrics.accuracy:.4f}</td>
  <td>{entry.metrics.total}</td>
  <td><code>{escape(entry.runner)}</code></td>
</tr>
"""


def _markdown_link(label: str, url: Optional[str]) -> str:
    if not url:
        return label.replace("|", "\\|")
    safe_label = label.replace("|", "\\|")
    safe_url = url.replace(")", "%29")
    return f"[{safe_label}]({safe_url})"


def _guess_format(path: Path) -> str:
    suffix = path.suffix.lower().lstrip(".")
    return suffix or "json"
