"""Static project site renderer."""

from __future__ import annotations

import json
from html import escape
from pathlib import Path

from openscholarguard.benchmark.publisher import BenchmarkPublication
from openscholarguard.demo.generator import DemoArtifacts
from openscholarguard.pdf_gallery import PdfGalleryArtifacts


def render_site_index(
    *,
    demo: DemoArtifacts,
    benchmark: BenchmarkPublication,
    pdf_gallery: PdfGalleryArtifacts,
) -> str:
    """Render the GitHub Pages project entrypoint."""

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>OpenScholarGuard</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f5f7fb;
      --ink: #101828;
      --muted: #667085;
      --panel: #ffffff;
      --line: #d8e0eb;
      --dark: #0b1220;
      --green: #087f5b;
      --blue: #175cd3;
      --red: #c21f12;
      --shadow: 0 24px 70px rgba(17, 24, 39, 0.13);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      color: var(--ink);
      background:
        radial-gradient(circle at 14% 8%, rgba(8, 127, 91, 0.18), transparent 27rem),
        radial-gradient(circle at 86% 0%, rgba(23, 92, 211, 0.13), transparent 25rem),
        linear-gradient(180deg, #ffffff 0%, var(--bg) 58%, #ffffff 100%);
      font: 14px/1.55 Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }}
    a {{ color: inherit; }}
    .shell {{ width: min(1160px, calc(100vw - 36px)); margin: 0 auto; }}
    .nav {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 18px;
      padding: 18px 0;
    }}
    .brand {{ display: flex; align-items: center; gap: 11px; font-weight: 860; }}
    .mark {{
      width: 36px;
      height: 36px;
      display: grid;
      place-items: center;
      border-radius: 8px;
      background: var(--dark);
      color: #ffffff;
      font-size: 13px;
    }}
    .nav a {{
      padding: 8px 10px;
      border-radius: 8px;
      color: var(--muted);
      text-decoration: none;
      font-weight: 740;
    }}
    .nav a:hover {{ background: #ffffff; }}
    .hero {{
      display: grid;
      grid-template-columns: minmax(0, 1fr) minmax(360px, 0.72fr);
      align-items: center;
      gap: 34px;
      min-height: min(760px, calc(100vh - 74px));
      padding: 60px 0 70px;
    }}
    .eyebrow {{
      display: inline-flex;
      align-items: center;
      gap: 9px;
      margin-bottom: 18px;
      padding: 7px 10px;
      border: 1px solid rgba(8, 127, 91, 0.18);
      border-radius: 999px;
      background: rgba(223, 248, 235, 0.86);
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
      max-width: 850px;
      margin: 0;
      font-size: clamp(46px, 7vw, 86px);
      line-height: 0.96;
      letter-spacing: 0;
    }}
    .lead {{
      max-width: 760px;
      margin: 22px 0 0;
      color: var(--muted);
      font-size: clamp(17px, 2vw, 21px);
    }}
    .actions {{ display: flex; flex-wrap: wrap; gap: 12px; margin-top: 30px; }}
    .button {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 44px;
      padding: 10px 15px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #ffffff;
      text-decoration: none;
      font-weight: 800;
    }}
    .button.primary {{ border-color: var(--dark); background: var(--dark); color: #ffffff; }}
    .workflow {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 8px;
      max-width: 760px;
      margin-top: 22px;
    }}
    .step {{
      min-height: 84px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: rgba(255, 255, 255, 0.82);
      padding: 12px;
    }}
    .step strong {{ display: block; font-size: 14px; }}
    .step span {{ display: block; margin-top: 5px; color: var(--muted); font-size: 12px; font-weight: 680; }}
    .proof {{
      display: grid;
      gap: 12px;
      padding: 16px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: rgba(255, 255, 255, 0.9);
      box-shadow: var(--shadow);
    }}
    .metric {{
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #ffffff;
      padding: 14px;
    }}
    .metric span {{ display: block; color: var(--muted); font-weight: 740; }}
    .metric strong {{ display: block; margin-top: 4px; font-size: 26px; line-height: 1; }}
    main {{ padding: 12px 0 74px; }}
    .section-head {{ margin: 0 0 16px; }}
    .section-head h2 {{ margin: 0; font-size: 32px; line-height: 1.1; }}
    .section-head p {{ max-width: 780px; margin: 8px 0 0; color: var(--muted); }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 18px;
      margin-bottom: 34px;
    }}
    .card {{
      min-height: 248px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      gap: 22px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #ffffff;
      padding: 20px;
      text-decoration: none;
      box-shadow: 0 14px 40px rgba(17, 24, 39, 0.06);
      transition: transform 150ms ease, box-shadow 150ms ease, border-color 150ms ease;
    }}
    .card:hover {{
      transform: translateY(-2px);
      border-color: rgba(23, 92, 211, 0.32);
      box-shadow: 0 18px 46px rgba(17, 24, 39, 0.11);
    }}
    .card h3 {{ margin: 0; font-size: 24px; }}
    .card p {{ margin: 10px 0 0; color: var(--muted); }}
    .tagline {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }}
    .pill {{
      border: 1px solid var(--line);
      border-radius: 999px;
      background: #f8fafc;
      color: var(--muted);
      padding: 4px 9px;
      font-size: 12px;
      font-weight: 720;
    }}
    .footer {{ padding: 28px 0 44px; color: var(--muted); text-align: center; }}
    @media (max-width: 860px) {{
      .hero, .grid {{ grid-template-columns: 1fr; }}
      .hero {{ min-height: auto; }}
      .workflow {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
    }}
    @media (max-width: 560px) {{
      .workflow {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <div class="shell">
    <nav class="nav">
      <div class="brand"><span class="mark">OSG</span> OpenScholarGuard</div>
      <div>
        <a href="demo/index.html">Demo</a>
        <a href="pdf-gallery/index.html">PDF Gallery</a>
        <a href="benchmark/leaderboard.html">Leaderboard</a>
        <a href="benchmark/evaluation.html">Evaluation</a>
        <a href="https://github.com/King-play/OpenScholarGuard">GitHub</a>
      </div>
    </nav>
    <header class="hero">
      <div>
        <div class="eyebrow"><span class="pulse"></span> AI science document security preview</div>
        <h1>Trust layer for AI reviewers and document agents.</h1>
        <p class="lead">Scan, sanitize, red-team, and benchmark document-borne prompt injection before scholarly papers enter AI-assisted review or RAG pipelines.</p>
        <div class="actions">
          <a class="button primary" href="demo/index.html">Open interactive demo</a>
          <a class="button" href="benchmark/leaderboard.html">View leaderboard</a>
          <a class="button" href="benchmark/evaluation.html">Inspect evaluation</a>
        </div>
        <div class="workflow" aria-label="OpenScholarGuard workflow">
          <div class="step"><strong>Scan</strong><span>Find hidden instructions, Unicode tricks, encoded payloads, and PDF styling risks.</span></div>
          <div class="step"><strong>Sanitize</strong><span>Remove or isolate high-risk fragments before AI review or RAG ingestion.</span></div>
          <div class="step"><strong>Ingest</strong><span>Emit guarded chunks with provenance, detector metadata, and blocking policy.</span></div>
          <div class="step"><strong>Benchmark</strong><span>Publish reproducible samples, evaluation reports, and leaderboard entries.</span></div>
        </div>
      </div>
      <aside class="proof" aria-label="Generated site artifacts">
        <div class="metric"><span>Demo findings</span><strong>{escape(_count_from_json(demo.scan_json, "summary", "total_findings"))}</strong></div>
        <div class="metric"><span>PDF gallery cases</span><strong>{len(pdf_gallery.cases)}</strong></div>
        <div class="metric"><span>Benchmark samples</span><strong>{escape(_count_from_json(benchmark.evaluation_json, "metrics", "total"))}</strong></div>
        <div class="metric"><span>Leaderboard entries</span><strong>{escape(_count_entries(benchmark.leaderboard_json))}</strong></div>
      </aside>
    </header>
    <main>
      <section>
        <div class="section-head">
          <h2>Release Preview</h2>
          <p>This static site is generated from the same scanner, sanitizer, ingestion guard, rule-pack verifier, and benchmark pipeline used by the CLI.</p>
        </div>
        <div class="grid">
          <a class="card" href="demo/index.html">
            <div>
              <h3>Static Demo</h3>
              <p>Walk through suspicious paper intake, findings, sanitizer output, guarded chunks, rule verification, and ten reproducible attack examples.</p>
            </div>
            <div class="tagline">
              <span class="pill">scan</span>
              <span class="pill">sanitize</span>
              <span class="pill">RAG guard</span>
              <span class="pill">attack gallery</span>
            </div>
          </a>
          <a class="card" href="pdf-gallery/index.html">
            <div>
              <h3>PDF Attack Gallery</h3>
              <p>Inspect synthetic PDFs for white text, transparent spans, tiny text, off-page payloads, metadata injection, image-heavy pages, Unicode controls, and encoded payloads.</p>
            </div>
            <div class="tagline">
              <span class="pill">PDF</span>
              <span class="pill">screenshots</span>
              <span class="pill">scan reports</span>
              <span class="pill">deep audit</span>
            </div>
          </a>
          <a class="card" href="benchmark/leaderboard.html">
            <div>
              <h3>Benchmark Leaderboard</h3>
              <p>Review the first ScholarGuardBench-style leaderboard artifact with deterministic baseline metrics and reproducible synthetic samples.</p>
            </div>
            <div class="tagline">
              <span class="pill">ScholarGuardBench v0</span>
              <span class="pill">detector recall</span>
              <span class="pill">F1</span>
              <span class="pill">HTML/JSON/MD</span>
            </div>
          </a>
        </div>
      </section>
    </main>
    <footer class="footer">Generated by OpenScholarGuard. No external scripts, trackers, or API keys are required.</footer>
  </div>
</body>
</html>
"""


def _count_from_json(path: Path, *keys: str) -> str:
    payload: object = json.loads(Path(path).read_text(encoding="utf-8"))
    for key in keys:
        if not isinstance(payload, dict):
            return "0"
        payload = payload.get(key, 0)
    return str(payload)


def _count_entries(path: Path) -> str:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    entries = payload.get("entries", []) if isinstance(payload, dict) else []
    return str(len(entries) if isinstance(entries, list) else 0)
