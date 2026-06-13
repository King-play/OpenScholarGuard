"""Static HTML renderer for the shareable demo dashboard."""

from __future__ import annotations

import json
from html import escape
from pathlib import PurePath

from openscholarguard.ingest.models import IngestResult
from openscholarguard.models import Finding, SanitizeResult, ScanResult
from openscholarguard.rules.verification import RulePackVerification


def render_demo_html(
    *,
    scan: ScanResult,
    sanitized: SanitizeResult,
    ingest: IngestResult,
    verification: RulePackVerification,
    attack_gallery: list[dict[str, object]],
    artifacts: dict[str, str],
) -> str:
    """Render a polished static demo page."""

    severity_counts = scan.summary.by_severity
    finding_cards = "\n".join(_finding_card(finding) for finding in scan.findings[:4])
    verification_cards = "\n".join(
        _verification_card(test.name, test.passed, test.finding_count, test.matched_rule_ids)
        for test in verification.tests
    )
    attack_cards = "\n".join(_attack_card(item) for item in attack_gallery)
    artifact_cards = "\n".join(_artifact_card(label, path) for label, path in artifacts.items())
    before_text = _readable_snippet(scan.findings[0].snippet if scan.findings else "", limit=760)
    after_text = _readable_snippet(sanitized.text, limit=900)
    chunk_preview = _readable_snippet(
        json.dumps(ingest.chunks[0].to_dict() if ingest.chunks else {}, indent=2, sort_keys=True),
        limit=1100,
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>OpenScholarGuard Demo</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f5f7fb;
      --ink: #111827;
      --muted: #667085;
      --soft: #f8fafc;
      --panel: #ffffff;
      --line: #d8e0eb;
      --dark: #0b1220;
      --green: #087f5b;
      --green-soft: #dff8eb;
      --red: #c21f12;
      --red-soft: #ffe3de;
      --amber: #b76b00;
      --amber-soft: #fff1cc;
      --blue: #175cd3;
      --blue-soft: #dbeafe;
      --shadow: 0 28px 80px rgba(17, 24, 39, 0.16);
      --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
    }}
    * {{ box-sizing: border-box; }}
    html {{ scroll-behavior: smooth; }}
    body {{
      margin: 0;
      color: var(--ink);
      background:
        radial-gradient(circle at 18% 8%, rgba(8, 127, 91, 0.18), transparent 26rem),
        radial-gradient(circle at 82% 2%, rgba(23, 92, 211, 0.11), transparent 25rem),
        linear-gradient(180deg, #ffffff 0%, var(--bg) 46%, #ffffff 100%);
      font: 14px/1.55 Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }}
    a {{ color: inherit; }}
    .shell {{
      width: min(1220px, calc(100vw - 36px));
      margin: 0 auto;
    }}
    .nav {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 18px;
      padding: 18px 0;
    }}
    .brand {{
      display: flex;
      align-items: center;
      gap: 11px;
      font-weight: 820;
    }}
    .mark {{
      width: 36px;
      height: 36px;
      display: grid;
      place-items: center;
      border-radius: 8px;
      color: #ffffff;
      background: var(--dark);
      font-size: 13px;
      letter-spacing: 0;
    }}
    .nav-links {{
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      color: var(--muted);
      font-weight: 700;
    }}
    .nav-links a {{
      text-decoration: none;
      padding: 8px 10px;
      border: 1px solid transparent;
      border-radius: 8px;
    }}
    .nav-links a:hover {{ border-color: var(--line); background: #ffffff; }}
    .hero {{
      display: grid;
      grid-template-columns: minmax(0, 0.92fr) minmax(450px, 1.08fr);
      align-items: center;
      gap: 34px;
      min-height: min(820px, calc(100vh - 74px));
      padding: 54px 0 62px;
    }}
    .eyebrow {{
      display: inline-flex;
      align-items: center;
      gap: 9px;
      margin-bottom: 18px;
      padding: 7px 10px;
      border: 1px solid rgba(8, 127, 91, 0.18);
      border-radius: 999px;
      background: rgba(223, 248, 235, 0.82);
      color: #065f46;
      font-size: 13px;
      font-weight: 780;
    }}
    .pulse {{
      width: 8px;
      height: 8px;
      border-radius: 999px;
      background: var(--green);
      box-shadow: 0 0 0 5px rgba(8, 127, 91, 0.13);
    }}
    h1 {{
      max-width: 820px;
      margin: 0;
      font-size: clamp(44px, 7vw, 84px);
      line-height: 0.95;
      letter-spacing: 0;
    }}
    .lead {{
      max-width: 710px;
      margin: 20px 0 0;
      color: var(--muted);
      font-size: clamp(17px, 2vw, 20px);
    }}
    .hero-proof {{
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 10px;
      max-width: 700px;
      margin-top: 24px;
    }}
    .proof {{
      border: 1px solid var(--line);
      border-radius: 8px;
      background: rgba(255, 255, 255, 0.78);
      padding: 12px;
    }}
    .proof strong {{ display: block; font-size: 22px; line-height: 1; }}
    .proof span {{ display: block; margin-top: 5px; color: var(--muted); font-size: 12px; font-weight: 720; }}
    .actions {{
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      margin-top: 28px;
    }}
    .button {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 43px;
      border-radius: 8px;
      padding: 10px 14px;
      border: 1px solid var(--line);
      background: #ffffff;
      text-decoration: none;
      font-weight: 780;
    }}
    .button.primary {{
      border-color: var(--dark);
      background: var(--dark);
      color: #ffffff;
    }}
    .command {{
      max-width: 700px;
      margin-top: 16px;
      padding: 13px 15px;
      border: 1px solid #1f2937;
      border-radius: 8px;
      background: var(--dark);
      color: #ddf8eb;
      font: 13px/1.65 var(--mono);
      overflow-wrap: anywhere;
    }}
    .workspace {{
      overflow: hidden;
      border: 1px solid rgba(216, 224, 235, 0.95);
      border-radius: 8px;
      background: rgba(255, 255, 255, 0.94);
      box-shadow: var(--shadow);
      transform: translateY(10px);
    }}
    .workspace-top {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      padding: 14px 16px;
      border-bottom: 1px solid var(--line);
      background: rgba(248, 250, 252, 0.88);
    }}
    .traffic {{ display: flex; gap: 7px; }}
    .traffic span {{ width: 10px; height: 10px; border-radius: 999px; background: #cbd5e1; }}
    .workspace-body {{
      display: grid;
      grid-template-columns: 178px minmax(0, 1fr);
      min-height: 476px;
    }}
    .rail {{
      border-right: 1px solid var(--line);
      background: #fbfcfe;
      padding: 14px 12px;
    }}
    .rail-item {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      margin-bottom: 8px;
      padding: 10px 9px;
      border: 1px solid transparent;
      border-radius: 8px;
      color: var(--muted);
      font-weight: 720;
    }}
    .rail-item.active {{
      border-color: rgba(8, 127, 91, 0.22);
      background: var(--green-soft);
      color: #064e3b;
    }}
    .dot {{
      width: 8px;
      height: 8px;
      flex: none;
      border-radius: 999px;
      background: currentColor;
    }}
    .workspace-main {{ padding: 18px 18px 16px; }}
    .risk-summary {{
      display: grid;
      grid-template-columns: 130px minmax(0, 1fr);
      gap: 18px;
      align-items: center;
      padding: 16px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: linear-gradient(135deg, #ffffff, #f8fafc);
      box-shadow: 0 14px 40px rgba(17, 24, 39, 0.06);
    }}
    .gauge {{
      width: 118px;
      height: 118px;
      display: grid;
      place-items: center;
      border-radius: 999px;
      background: conic-gradient(var(--red) {scan.summary.risk_score * 3.6}deg, #e8edf4 0);
      box-shadow: inset 0 0 0 13px #ffffff, 0 10px 30px rgba(194, 31, 18, 0.16);
      color: var(--red);
      font-size: 34px;
      font-weight: 860;
    }}
    .risk-summary h2 {{ margin: 0 0 8px; font-size: 24px; line-height: 1.12; }}
    .risk-summary p {{ margin: 0; color: var(--muted); }}
    .mini-metrics {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 10px;
      margin-top: 14px;
    }}
    .mini {{
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #ffffff;
      padding: 11px;
    }}
    .mini span {{ color: var(--muted); font-size: 12px; font-weight: 760; }}
    .mini strong {{ display: block; margin-top: 3px; font-size: 23px; line-height: 1; }}
    .pipeline {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 10px;
      margin-top: 14px;
    }}
    .step {{
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #ffffff;
      padding: 12px 11px;
    }}
    .step b {{ display: block; margin-bottom: 4px; }}
    .step small {{ color: var(--muted); }}
    main {{ padding: 42px 0 78px; }}
    .section-head {{
      display: flex;
      justify-content: space-between;
      align-items: end;
      gap: 22px;
      margin-bottom: 16px;
    }}
    .section-head h2 {{ margin: 0; font-size: 30px; line-height: 1.1; }}
    .section-head p {{ max-width: 740px; margin: 7px 0 0; color: var(--muted); }}
    .split {{
      display: grid;
      grid-template-columns: minmax(0, 1.12fr) minmax(360px, 0.88fr);
      gap: 18px;
      margin-bottom: 34px;
    }}
    .panel {{
      border: 1px solid var(--line);
      border-radius: 8px;
      background: rgba(255, 255, 255, 0.94);
      padding: 18px;
    }}
    .finding-list {{ display: grid; gap: 12px; }}
    .finding {{
      display: grid;
      grid-template-columns: 116px minmax(0, 1fr);
      gap: 14px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #ffffff;
      padding: 14px;
    }}
    .badge, .status {{
      display: inline-flex;
      align-items: center;
      width: fit-content;
      border-radius: 999px;
      padding: 4px 9px;
      font-size: 12px;
      font-weight: 820;
      white-space: nowrap;
    }}
    .critical, .high {{ color: var(--red); background: var(--red-soft); }}
    .medium {{ color: var(--amber); background: var(--amber-soft); }}
    .low, .info {{ color: var(--blue); background: var(--blue-soft); }}
    .pass {{ color: var(--green); background: var(--green-soft); }}
    .fail {{ color: var(--red); background: var(--red-soft); }}
    .finding h3 {{ margin: 0 0 7px; font-size: 16px; line-height: 1.25; }}
    .meta {{
      display: flex;
      flex-wrap: wrap;
      gap: 7px;
      margin: 8px 0 0;
    }}
    .pill {{
      max-width: 100%;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      border: 1px solid var(--line);
      border-radius: 999px;
      background: var(--soft);
      color: var(--muted);
      padding: 3px 8px;
      font-size: 12px;
      font-weight: 650;
    }}
    .snippet {{ margin: 10px 0 0; color: #344054; overflow-wrap: anywhere; }}
    .verify-grid {{ display: grid; gap: 10px; }}
    .verify-card {{
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      align-items: center;
      gap: 12px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #ffffff;
      padding: 12px;
    }}
    .verify-card h3 {{ margin: 0; font-size: 15px; }}
    .verify-card p {{ margin: 4px 0 0; color: var(--muted); font-size: 13px; }}
    .compare {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 18px;
      margin-bottom: 34px;
    }}
    .code-head {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 11px;
    }}
    .code-head h3 {{ margin: 0; font-size: 17px; }}
    pre {{
      margin: 0;
      min-height: 250px;
      max-height: 366px;
      overflow: auto;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      border-radius: 8px;
      background: var(--dark);
      color: #e7edf6;
      padding: 16px;
      font: 13px/1.7 var(--mono);
    }}
    .artifact-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
      gap: 12px;
    }}
    .attack-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(238px, 1fr));
      gap: 12px;
      margin-bottom: 34px;
    }}
    .attack {{
      display: block;
      min-height: 188px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #ffffff;
      padding: 14px;
      text-decoration: none;
      transition: transform 150ms ease, box-shadow 150ms ease, border-color 150ms ease;
    }}
    .attack:hover {{
      transform: translateY(-2px);
      border-color: rgba(194, 31, 18, 0.3);
      box-shadow: 0 12px 32px rgba(17, 24, 39, 0.1);
    }}
    .attack h3 {{
      margin: 10px 0 7px;
      font-size: 16px;
      line-height: 1.25;
    }}
    .attack p {{
      margin: 0;
      color: var(--muted);
      font-size: 13px;
    }}
    .attack-tags {{
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      margin-top: 12px;
    }}
    .artifact {{
      display: block;
      min-height: 92px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #ffffff;
      padding: 14px;
      text-decoration: none;
      transition: transform 150ms ease, box-shadow 150ms ease, border-color 150ms ease;
    }}
    .artifact:hover {{
      transform: translateY(-2px);
      border-color: rgba(8, 127, 91, 0.38);
      box-shadow: 0 12px 32px rgba(17, 24, 39, 0.1);
    }}
    .artifact b {{ display: block; margin-bottom: 5px; }}
    .artifact span {{ color: var(--muted); font-size: 13px; overflow-wrap: anywhere; }}
    .footer {{
      padding: 28px 0 44px;
      color: var(--muted);
      text-align: center;
    }}
    @media (max-width: 980px) {{
      .hero, .split, .compare {{ grid-template-columns: 1fr; }}
      .hero {{ min-height: auto; }}
      .workspace-body, .risk-summary {{ grid-template-columns: 1fr; }}
      .rail {{ display: none; }}
      .mini-metrics, .pipeline, .hero-proof {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
    }}
    @media (max-width: 640px) {{
      .nav {{ align-items: flex-start; flex-direction: column; }}
      .mini-metrics, .pipeline, .hero-proof {{ grid-template-columns: 1fr; }}
      .finding {{ grid-template-columns: 1fr; }}
      .gauge {{ width: 116px; height: 116px; }}
    }}
  </style>
</head>
<body>
  <div class="shell">
    <nav class="nav">
      <div class="brand"><span class="mark">OSG</span> OpenScholarGuard</div>
      <div class="nav-links">
        <a href="#findings">Findings</a>
        <a href="#ingestion">Ingestion</a>
        <a href="scan.html">Full report</a>
      </div>
    </nav>
    <header class="hero">
      <div>
        <div class="eyebrow"><span class="pulse"></span> Live static demo - generated from real scanner output</div>
        <h1>See what an AI reviewer would miss.</h1>
        <p class="lead">OpenScholarGuard turns a suspicious paper into reviewable evidence, sanitized text, and safe RAG chunks before it reaches an AI-assisted review workflow.</p>
        <div class="hero-proof">
          <div class="proof"><strong>{scan.summary.risk_score}/100</strong><span>risk score</span></div>
          <div class="proof"><strong>{scan.summary.total_findings}</strong><span>findings</span></div>
          <div class="proof"><strong>{len(sanitized.removed)}</strong><span>fragments removed</span></div>
        </div>
        <div class="actions">
          <a class="button primary" href="scan.html">Open scan report</a>
          <a class="button" href="sanitized.md">View cleaned paper</a>
          <a class="button" href="rule-pack.verify.json">Rule-pack proof</a>
        </div>
        <div class="command">openscholarguard demo --output-dir demo-output --overwrite</div>
      </div>
      <aside class="workspace" aria-label="OpenScholarGuard safety workspace">
        <div class="workspace-top">
          <div class="traffic"><span></span><span></span><span></span></div>
          <strong>Review intake gate</strong>
        </div>
        <div class="workspace-body">
          <div class="rail">
            <div class="rail-item active"><span>Scan</span><span class="dot"></span></div>
            <div class="rail-item"><span>Sanitize</span><span class="dot"></span></div>
            <div class="rail-item"><span>Ingest</span><span class="dot"></span></div>
            <div class="rail-item"><span>Verify</span><span class="dot"></span></div>
          </div>
          <div class="workspace-main">
            <div class="risk-summary">
              <div class="gauge">{scan.summary.risk_score}</div>
              <div>
                <h2>{escape(scan.summary.max_severity.value.upper())} risk detected</h2>
                <p>{scan.summary.total_findings} signals found in a synthetic scholarly submission, including hidden review manipulation and prompt-injection content.</p>
              </div>
            </div>
            <div class="mini-metrics">
              <div class="mini"><span>Critical</span><strong>{severity_counts.get('critical', 0)}</strong></div>
              <div class="mini"><span>High</span><strong>{severity_counts.get('high', 0)}</strong></div>
              <div class="mini"><span>Rule tests</span><strong>{len(verification.tests)}</strong></div>
              <div class="mini"><span>Chunks</span><strong>{len(ingest.chunks)}</strong></div>
            </div>
            <div class="pipeline">
              <div class="step"><b>Scan</b><small>Detect hidden model-facing instructions.</small></div>
              <div class="step"><b>Sanitize</b><small>Remove risky fragments before review.</small></div>
              <div class="step"><b>Ingest</b><small>Emit guarded chunks with provenance.</small></div>
              <div class="step"><b>Verify</b><small>Run rule-pack tests for CI.</small></div>
            </div>
          </div>
        </div>
      </aside>
    </header>
    <main>
      <section id="findings">
        <div class="section-head">
          <div>
            <h2>Investigation-ready findings</h2>
            <p>Instead of dumping a dense table, the demo presents each signal with severity, detector, confidence, and a bounded snippet that a human reviewer can inspect.</p>
          </div>
        </div>
        <div class="split">
          <div class="panel"><div class="finding-list">{finding_cards}</div></div>
          <div class="panel">
            <div class="section-head">
              <div>
                <h2>Rules that test themselves</h2>
                <p>Custom policy packs include embedded positive and negative tests, so teams can review detector behavior before shipping it.</p>
              </div>
            </div>
            <div class="verify-grid">{verification_cards}</div>
          </div>
        </div>
      </section>
      <section id="ingestion">
        <div class="section-head">
          <div>
            <h2>Clean the document before it enters RAG</h2>
            <p>The demo keeps the workflow concrete: unsafe fragment, sanitized output, and a provenance-rich chunk ready for a document pipeline.</p>
          </div>
        </div>
        <div class="section-head">
          <div>
            <h2>Ten synthetic attack examples</h2>
            <p>Open each generated sample to inspect the document-borne attack pattern. Every case is synthetic, reproducible, and safe to publish.</p>
          </div>
        </div>
        <div class="attack-grid">{attack_cards}</div>
        <div class="compare">
          <div class="panel">
            <div class="code-head"><h3>Detected fragment</h3><span class="badge critical">unsafe</span></div>
            <pre>{escape(before_text)}</pre>
          </div>
          <div class="panel">
            <div class="code-head"><h3>Sanitized document</h3><span class="badge pass">cleaned</span></div>
            <pre>{escape(after_text)}</pre>
          </div>
        </div>
        <div class="compare">
          <div class="panel">
            <div class="code-head"><h3>RAG chunk preview</h3><span class="badge info">provenance</span></div>
            <pre>{escape(chunk_preview)}</pre>
          </div>
          <div class="panel">
            <div class="code-head"><h3>Generated artifacts</h3><span class="badge pass">static</span></div>
            <div class="artifact-grid">{artifact_cards}</div>
          </div>
        </div>
      </section>
    </main>
    <footer class="footer">Generated by OpenScholarGuard. No external scripts, network calls, or API keys are required for this demo.</footer>
  </div>
</body>
</html>
"""


def _finding_card(finding: Finding) -> str:
    severity = escape(finding.severity.value)
    detector = _pretty_detector(finding.detector_id)
    location = _friendly_location(finding.location.label())
    tags = " ".join(f'<span class="pill">{escape(tag)}</span>' for tag in finding.tags[:3])
    return f"""
    <article class="finding">
      <div><span class="badge {severity}">{severity.upper()}</span></div>
      <div>
        <h3>{escape(finding.title)}</h3>
        <div class="meta">
          <span class="pill">{escape(detector)}</span>
          <span class="pill">{escape(location)}</span>
          <span class="pill">confidence {finding.confidence:.2f}</span>
          {tags}
        </div>
        <p class="snippet">{escape(_readable_snippet(finding.snippet, limit=245))}</p>
      </div>
    </article>
    """


def _verification_card(
    name: str,
    passed: bool,
    finding_count: int,
    matched_rule_ids: tuple[str, ...],
) -> str:
    status = "PASS" if passed else "FAIL"
    class_name = "pass" if passed else "fail"
    rules = ", ".join(matched_rule_ids) or "negative control"
    return f"""
    <article class="verify-card">
      <div>
        <h3>{escape(_humanize(name))}</h3>
        <p>{finding_count} finding(s), {escape(rules)}</p>
      </div>
      <span class="status {class_name}">{status}</span>
    </article>
    """


def _artifact_card(label: str, path: str) -> str:
    title = _humanize(label)
    return f"""
    <a class="artifact" href="{escape(path)}">
      <b>{escape(title)}</b>
      <span>{escape(path)}</span>
    </a>
    """


def _attack_card(item: dict[str, object]) -> str:
    title = str(item.get("title", "Attack example"))
    path = str(item.get("path", "#"))
    family = _humanize(str(item.get("family", "attack")))
    severity = str(item.get("minimum_severity", "high"))
    description = _readable_snippet(str(item.get("description", "")), limit=125)
    detectors = item.get("expected_detectors", [])
    if not isinstance(detectors, list):
        detectors = []
    detector_text = ", ".join(str(detector) for detector in detectors) or "policy-driven"
    tags = item.get("tags", [])
    if not isinstance(tags, list):
        tags = []
    tag_html = "".join(f'<span class="pill">{escape(str(tag))}</span>' for tag in tags[:3])
    return f"""
    <a class="attack" href="{escape(path)}">
      <span class="badge {escape(severity)}">{escape(severity.upper())}</span>
      <h3>{escape(title)}</h3>
      <p>{escape(description)}</p>
      <div class="meta">
        <span class="pill">{escape(family)}</span>
        <span class="pill">{escape(detector_text)}</span>
      </div>
      <div class="attack-tags">{tag_html}</div>
    </a>
    """


def _friendly_location(label: str) -> str:
    parts = [part.strip() for part in label.split(":")]
    if not parts:
        return label
    filename = PurePath(parts[0]).name or parts[0]
    suffix = ": ".join(parts[1:])
    return f"{filename}: {suffix}" if suffix else filename


def _pretty_detector(detector_id: str) -> str:
    if detector_id.startswith("rule_pack:"):
        return detector_id.replace("rule_pack:", "rule pack: ")
    return detector_id.replace("_", " ")


def _humanize(value: str) -> str:
    return value.replace("_", " ").replace("-", " ").title()


def _readable_snippet(value: str, *, limit: int = 900) -> str:
    collapsed = "\n".join(line.rstrip() for line in value.strip().splitlines())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[: limit - 1].rstrip() + "..."
