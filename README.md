# OpenScholarGuard 🛡️

![CI](https://github.com/King-play/OpenScholarGuard/actions/workflows/ci.yml/badge.svg)
![Pages](https://github.com/King-play/OpenScholarGuard/actions/workflows/pages.yml/badge.svg)
![Release Check](https://github.com/King-play/OpenScholarGuard/actions/workflows/release.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**Security and trust layer for AI-assisted peer review, scholarly document ingestion, and document agents.**

OpenScholarGuard screens papers before AI review. It detects document-borne prompt
injection, hidden instructions, review manipulation, encoded payloads, invisible Unicode,
PDF text-layer tricks, suspicious metadata, and RAG/tool-boundary risks before content
reaches reviewer models or document agents.

🛡️ **Guardrail:** scan, sanitize, audit, and block risky scholarly documents.  
🧩 **Benchmark:** `ScholarGuardBench v0`, a 36-task synthetic benchmark for AI-review and document-agent safety.  
📄 **PDF depth:** gallery and audit checks for hidden spans, sparse text layers, OCR candidates, metadata, and image-heavy pages.  
🔌 **Integrations:** CLI, Python API, HTTP API, GitHub Action, LangChain-style transformers, and LlamaIndex-style postprocessors.

> Public site: <https://king-play.github.io/OpenScholarGuard/>

[![OpenScholarGuard public workflow](docs/assets/demo-preview.gif)](https://king-play.github.io/OpenScholarGuard/)

Static preview: [docs/assets/demo-preview.png](docs/assets/demo-preview.png)

## Why It Matters

AI reviewers and document agents read more than the visible page. They may ingest extracted
PDF text, metadata, OCR layers, comments, hidden markup, encoded payloads, or retrieved
chunks. That creates a new attack surface: a paper can contain content meant for a model
rather than a human reviewer.

OpenScholarGuard focuses on that boundary:

- **Screen** papers before AI-assisted review.
- **Sanitize** risky fragments before RAG or agent ingestion.
- **Preserve evidence** with structured findings, provenance, and reports.
- **Benchmark** scanners and model-review behavior with named, reproducible artifacts.

## What's Included

| Layer | What ships today |
| --- | --- |
| 🛡️ Scanner | Markdown/text/PDF scanning, hidden instruction detection, encoded payloads, Unicode controls, review manipulation, PDF metadata and styling checks |
| 🧼 Sanitizer | Risky fragment removal with provenance manifests |
| 🧩 ScholarGuardBench v0 | 36 task-style synthetic cases, 5 clean controls, 31 attack/integrity-risk tasks, manifest metadata, deterministic baseline leaderboard |
| 📄 PDF security | Deep audit skeleton, 10-case PDF attack gallery, screenshots, scan reports, OCR-candidate checks |
| 🔌 Integrations | CLI, Python API, HTTP API, GitHub Action, LangChain-style transformer, LlamaIndex-style postprocessor |
| 📊 Publication | GitHub Pages site, benchmark reports, leaderboard artifacts, model-eval protocol, arXiv paper skeleton |

## Public Artifacts

- **Project site:** <https://king-play.github.io/OpenScholarGuard/>
- **ScholarGuardBench v0 leaderboard:** <https://king-play.github.io/OpenScholarGuard/benchmark/leaderboard.html>
- **Benchmark evaluation:** <https://king-play.github.io/OpenScholarGuard/benchmark/evaluation.html>
- **PDF attack gallery:** <https://king-play.github.io/OpenScholarGuard/pdf-gallery/>
- **Dataset card:** [docs/dataset-card.md](docs/dataset-card.md)

Repository screenshots and GIF frames are reproducible with:

```bash
python scripts/capture_demo_assets.py
```

## At A Glance

- **Scan** hidden model-facing instructions in Markdown, text, and PDFs.
- **Sanitize** risky fragments before AI-assisted review or RAG ingestion.
- **Ingest** guarded chunks with provenance, detector metadata, and blocking policy.
- **Verify** custom rule packs with embedded positive and negative tests.
- **Publish** the full workflow as a static GitHub Pages site.
- **Benchmark** scanner behavior with `ScholarGuardBench v0` (`scholarguardbench-v0`), `docpibench-mini`, and leaderboard-style reports.
- **Judge** model responses with a reproducible prompt/response protocol skeleton.
- **Collect** model responses from OpenAI-compatible Chat Completions endpoints for public benchmark runs.
- **Deep-audit PDFs** for OCR candidates, image-heavy pages, hidden spans, and visual/text-layer mismatch.
- **Gallery** reproducible PDF attack cases with screenshots, scan reports, and deep-audit reports.
- **Integrate** through GitHub Actions, LangChain-style transformers, and LlamaIndex-style postprocessors.
- **Draft papers** with generated arXiv skeletons and benchmark tables.

## Install

OpenScholarGuard supports Python 3.10 and newer.

Install from this repository:

```bash
pip install -e ".[pdf]"
```

## Quick Start

Scan a document:

```bash
openscholarguard scan examples/injected_paper.md
```

Sanitize before model ingestion:

```bash
openscholarguard sanitize examples/injected_paper.md --output clean.md --manifest clean.manifest.json
```

Run ScholarGuardBench v0:

```bash
openscholarguard benchmark evaluate --dataset scholarguardbench-v0
```

Generate the public static site locally:

```bash
openscholarguard site --output-dir site-output --overwrite
```

Create guarded chunks for RAG:

```bash
openscholarguard ingest examples/injected_paper.md --allow-risk --format jsonl
```

Run the local HTTP API:

```bash
openscholarguard serve --host 127.0.0.1 --port 8765
```

Generate the synthetic PDF attack gallery:

```bash
openscholarguard pdf-gallery --output-dir pdf-gallery-output --overwrite
```

Check your local setup:

```bash
openscholarguard doctor --demo
```

Run optional LLM-assisted audit of scan findings:

```bash
$env:OPENAI_API_KEY="<your-openai-api-key>"
openscholarguard scan examples/injected_paper.md --llm-audit --format json
```

Write an HTML report:

```bash
openscholarguard scan examples/injected_paper.md --format html --output reports/scan.html
```

Generate a complete benchmark publication bundle:

```bash
openscholarguard benchmark publish --output-dir benchmark-publication
```

`ScholarGuardBench v0` is the public name for the built-in dataset
`scholarguardbench-v0`: 36 task-style synthetic cases, 5 clean controls, 31 attack or
integrity-risk tasks, stable task IDs, split metadata, difficulty labels, verifier
contracts, and expected actions. See [docs/dataset-card.md](docs/dataset-card.md).

Generate model-evaluation prompts and judge filled responses:

```bash
openscholarguard benchmark protocol --dataset scholarguardbench-v0 --output-dir model-eval
openscholarguard benchmark collect --protocol model-eval/protocol.json --model gpt-4.1-mini --output model-eval/responses.jsonl
openscholarguard benchmark judge --protocol model-eval/protocol.json --responses model-eval/responses.jsonl --format json --output model-eval/gpt-4.1-mini.judge.json
openscholarguard benchmark model-leaderboard model-eval/*.judge.json --format html --output model-eval/leaderboard.html
openscholarguard benchmark model-publish model-eval/*.judge.json --output-dir model-eval-publication --overwrite
```

Audit a directory for CI or batch ingestion:

```bash
openscholarguard audit examples --format text
openscholarguard audit . --format sarif --output openscholarguard.sarif
```

Run PDF deep audit checks:

```bash
openscholarguard pdf-audit paper.pdf --format md --output pdf.deep.md
```

Use a custom rule pack:

```bash
openscholarguard rules validate examples/rule-pack.json
openscholarguard rules verify examples/rule-pack.json --require-tests
openscholarguard scan paper.md --rule-pack examples/rule-pack.json
```

Generate benchmark samples:

```bash
openscholarguard benchmark generate --dataset scholarguardbench-v0 --output-dir benchmark-output
```

Generate an arXiv paper skeleton and experiment tables:

```bash
openscholarguard paper --output-dir paper-output --overwrite
```

The package also installs shorter aliases:

```bash
scholarguard scan paper.pdf
paperguard scan paper.pdf --profile ai-review
```

## Profiles

- `ai-review`: strict profile for peer review and AI reviewer workflows.
- `rag`: document-ingestion profile for RAG and agent systems.
- `baseline`: general scan profile with lower default sensitivity.

List profiles:

```bash
openscholarguard profiles
```

## Detectors

Current first-stage detectors include:

- Direct prompt override instructions.
- Peer-review manipulation such as forced acceptance or score inflation.
- RAG exfiltration requests for prompts, secrets, or retrieved context.
- Base64 and hex encoded payloads.
- Invisible and bidirectional Unicode controls.
- Hidden LaTeX patterns.
- Hidden HTML/CSS patterns.
- OCR-layer and image/alt-text prompt injection.
- Fake citation and AI slop quality-risk signals.
- RAG contamination and agent tool exfiltration requests.
- Mixed-script homoglyph prompt-injection attempts.
- Role-play attempts to hijack reviewer authority.
- PDF spans with tiny fonts, near-white text, transparency, or off-page placement.
- PDF metadata instructions.
- Suspicious instruction-term density.

## Python API

```python
from openscholarguard import scan_path
from openscholarguard.sanitizer import sanitize_path

scan = scan_path("paper.pdf", profile="ai-review")
print(scan.summary.risk_score)

clean = sanitize_path("paper.pdf")
print(clean.text)
```

## Output Formats

Scan output can be rendered as text, JSON, Markdown, or HTML:

```bash
openscholarguard scan paper.pdf --format json
openscholarguard scan paper.pdf --format md --output report.md
openscholarguard scan paper.pdf --format html --output report.html
```

Benchmark reports support the same output formats:

```bash
openscholarguard benchmark evaluate --format json
openscholarguard benchmark evaluate --format md --output benchmark.md
openscholarguard benchmark evaluate --format html --output benchmark.html
```

## Benchmark

OpenScholarGuard includes two built-in benchmark tracks:

- `scholarguardbench-v0`: the implementation ID for **ScholarGuardBench v0**, the formal
  v0 seed with 36 task-style synthetic cases across AI-review, RAG, multimodal document,
  citation-integrity, Unicode obfuscation, AI slop, and agent-tool safety surfaces.
- `docpibench-mini`: a compact smoke-test set with one clean control and ten attack cases
  used by the static demo gallery.

Useful commands:

```bash
openscholarguard benchmark list
openscholarguard benchmark generate --output-dir benchmark-output
openscholarguard benchmark evaluate --dataset scholarguardbench-v0 --format json --output benchmark-output/openscholarguard.eval.json
openscholarguard benchmark submit benchmark-output/openscholarguard.eval.json --system OpenScholarGuard --version 0.1.0 --output benchmark-output/entries/openscholarguard.json
openscholarguard benchmark leaderboard benchmark-output/entries --format html --output benchmark-output/leaderboard.html
openscholarguard benchmark publish --output-dir benchmark-publication
openscholarguard benchmark evaluate --manifest benchmark-output/manifest.json --format html --output benchmark.html
openscholarguard benchmark protocol --output-dir model-eval
openscholarguard benchmark collect --protocol model-eval/protocol.json --model gpt-4.1-mini --output model-eval/responses.jsonl
openscholarguard benchmark judge --protocol model-eval/protocol.json --responses model-eval/responses.jsonl --format md --output model-eval/judge.md
openscholarguard benchmark judge --protocol model-eval/protocol.json --responses model-eval/responses.jsonl --format json --output model-eval/gpt-4.1-mini.judge.json
openscholarguard benchmark model-leaderboard model-eval/*.judge.json --format html --output model-eval/leaderboard.html
openscholarguard benchmark model-publish model-eval/*.judge.json --output-dir model-eval-publication --overwrite
```

See [docs/benchmark.md](docs/benchmark.md) for details.

## PDF Deep Audit

`pdf-audit` inspects surfaces that ordinary text extraction can miss: sparse text layers,
image-heavy pages, visually nonblank pages with little extracted text, hidden PDF spans,
and optional PyMuPDF/Tesseract OCR deltas.

```bash
openscholarguard pdf-audit paper.pdf --format html --output reports/pdf.deep.html
openscholarguard pdf-audit paper.pdf --enable-ocr --format json --output reports/pdf.deep.json
```

See [docs/pdf-audit.md](docs/pdf-audit.md) for details.

## PDF Attack Gallery

Generate ten synthetic PDF cases with source PDFs, screenshots, scan reports, and deep-audit
reports:

```bash
openscholarguard pdf-gallery --output-dir pdf-gallery-output --overwrite
```

The full static project site includes the same gallery under `pdf-gallery/`. The cases are
synthetic and designed for demos, regression tests, and paper figures.

See [docs/pdf-gallery.md](docs/pdf-gallery.md) for the case list and artifact layout.

## Paper Skeleton

Generate a reproducible arXiv-style draft directory from the current benchmark:

```bash
openscholarguard paper --output-dir paper-output --overwrite
```

The generator writes `main.tex`, benchmark coverage tables, deterministic baseline tables,
and the evaluation JSON used to produce them. See [docs/paper.md](docs/paper.md).

## Local Static Bundle

Generate a polished offline workflow bundle for talks, videos, or quick project reviews:

```bash
openscholarguard demo --output-dir demo-output --overwrite
```

Open `demo-output/index.html` to inspect the dashboard. This local artifact includes scan
reports, sanitized output, ingestion chunks, and rule-pack verification artifacts. See
[docs/demo.md](docs/demo.md) for details.

The repository also includes a GitHub Pages workflow that publishes the project site,
ScholarGuardBench reports, and PDF gallery from `main`. See [docs/github.md](docs/github.md)
for setup and release-check details.

## Integrations

OpenScholarGuard ships dependency-light entry points for common adoption paths:

- `action.yml`: composite GitHub Action for SARIF-producing document audits.
- `openscholarguard.integrations.langchain.OpenScholarGuardTransformer`
- `openscholarguard.integrations.llamaindex.OpenScholarGuardNodePostprocessor`

See [docs/integrations.md](docs/integrations.md) for examples.

## Launch Readiness

The engineering MVP is already useful, but the project becomes easier to cite, star, and
adopt once the public evidence is complete:

- **Public site:** GitHub Pages URL, README GIF, project-site preview, and downloadable CI artifact.
- **Real model evaluation:** fixed prompts, model versions, response JSONL, judge output, and public leaderboard.
- **PDF attack gallery:** reproducible PDFs for white text, transparent spans, tiny text, metadata injection, OCR-layer text, image text, encoded payloads, and Unicode obfuscation.
- **Integrations:** GitHub Action, LangChain/LlamaIndex ingestion hooks, promptfoo/PyRIT adapters, and OpenReview-style workflow examples.
- **Paper track:** threat model, benchmark design, experiments, case studies, limitations, and an arXiv-ready draft.

See [docs/launch.md](docs/launch.md) for the release checklist.

## Audit Mode

Audit mode scans repositories or document folders with policy controls, suppressions, and
CI-friendly output. It supports text, JSON, Markdown, HTML, SARIF, and JUnit XML.

```bash
openscholarguard init-policy --output .openscholarguard.json
openscholarguard audit . --policy .openscholarguard.json --format sarif --output openscholarguard.sarif
openscholarguard audit submissions --format junit --output openscholarguard.junit.xml
```

See [docs/audit.md](docs/audit.md) for policy examples and CI usage.

## Guarded Ingestion

Ingest mode scans, sanitizes, and chunks documents for RAG or document agents. It blocks
high-risk documents by default and emits provenance-rich JSONL chunks when the document is
allowed.

```bash
openscholarguard ingest paper.pdf --output-dir ingest-output
openscholarguard ingest paper.md --format jsonl
openscholarguard ingest paper.md --allow-risk --chunk-size 1000 --chunk-overlap 100
```

See [docs/ingest.md](docs/ingest.md) for chunk metadata and pipeline behavior.

## HTTP API

Run OpenScholarGuard as a local service for conference systems, document gateways, or RAG
pipelines:

```bash
openscholarguard serve --host 127.0.0.1 --port 8765
curl http://127.0.0.1:8765/health
curl -X POST http://127.0.0.1:8765/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"path": "examples/injected_paper.md", "profile": "ai-review"}'
```

Export the OpenAPI schema or use the Python client:

```bash
openscholarguard openapi --output openapi.json
```

```python
from openscholarguard import OpenScholarGuardClient

client = OpenScholarGuardClient("http://127.0.0.1:8765")
scan = client.scan_path("examples/injected_paper.md")
```

See [docs/api.md](docs/api.md) for request examples and security notes.

## Optional LLM Audit

OpenScholarGuard can optionally send scanner findings to an LLM for a second-pass audit.
This is disabled by default. API keys are read from environment variables and are never
stored in project files.

```bash
$env:OPENAI_API_KEY="<your-openai-api-key>"
openscholarguard scan paper.md --llm-audit --llm-model gpt-4.1-mini --format json
```

The LLM receives only structured finding data and bounded snippets, not raw files. Treat
LLM output as an audit aid, not as a replacement for deterministic scanner findings or
human review.

## Rule Packs

Rule packs add custom regex detectors without changing OpenScholarGuard source code. They
work across scan, sanitize, ingest, audit, and the HTTP API.

```bash
openscholarguard rules list examples/rule-pack.json
openscholarguard rules fingerprint examples/rule-pack.json
openscholarguard rules verify examples/rule-pack.json --require-tests
openscholarguard rules test examples/rule-pack.json --text "private review notes"
openscholarguard audit . --rule-pack examples/rule-pack.json
```

See [docs/rule-packs.md](docs/rule-packs.md) for the JSON format, embedded tests,
fingerprints, and CI verification.

## Development

```bash
pip install -e ".[dev,pdf]"
openscholarguard doctor --demo
ruff check .
mypy src/openscholarguard
pytest
```

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the current flagship plan.

Near-term focus:

- Publish and verify the GitHub Pages demo experience.
- Record the first real model-evaluation run and render a public leaderboard.
- Build the PDF attack gallery with visual evidence and detector reports.
- Add the first ecosystem entry points: GitHub Action, LangChain, and LlamaIndex.
- Expand the generated paper skeleton into an arXiv-ready systems paper.

## Security Model

OpenScholarGuard is a defensive scanner. Findings are heuristic and should be treated as
signals for audit, not as a mathematical proof that a document is safe or malicious.
For high-stakes review and enterprise ingestion, combine it with sandboxing, least-privilege
tool access, human review, and model-side instruction hierarchy controls.

## License

MIT
