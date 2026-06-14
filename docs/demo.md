# Demo

OpenScholarGuard includes a static demo generator for repository visitors, conference
organizers, security reviewers, and RAG engineers who want to see the full workflow without
setting up external services.

The demo is offline and reproducible. It scans the synthetic injected paper, verifies the
example rule pack, sanitizes risky fragments, creates guarded ingestion chunks, and writes a
shareable HTML dashboard.

## Generate

```bash
openscholarguard demo --output-dir demo-output --overwrite
```

Open:

```bash
demo-output/index.html
```

The generated bundle includes:

- `index.html`: polished static dashboard.
- `scan.json`: structured scan result.
- `scan.html`: detailed scan report.
- `sanitized.md`: sanitized model-facing document.
- `sanitize.manifest.json`: sanitizer provenance.
- `ingest.manifest.json`: guarded ingestion manifest.
- `chunks.jsonl`: provenance-rich chunks for RAG.
- `rule-pack.verify.json`: custom rule-pack verification result.
- `attack-gallery.json`: manifest for ten reproducible synthetic attack examples.
- `attack-gallery/`: generated sample documents for the attack gallery.
- `injected_paper.md`: copied synthetic sample.

## Repository Preview

The repository README uses `docs/assets/demo-preview.png` as the first-screen demo preview.
Regenerate it after changing the demo layout:

```powershell
$chrome = "C:\Program Files\Google\Chrome\Application\chrome.exe"
$demo = [System.Uri]::new((Resolve-Path demo-output\index.html).Path).AbsoluteUri
& $chrome --headless --disable-gpu --hide-scrollbars --window-size=1440,1040 `
  --screenshot="$((Resolve-Path docs\assets).Path)\demo-preview.png" $demo
```

## Custom Inputs

```bash
openscholarguard demo \
  --sample examples/injected_paper.md \
  --rule-pack examples/rule-pack.json \
  --profile ai-review \
  --output-dir demo-output \
  --overwrite
```

The demo generator intentionally does not call external LLM providers. It is safe for CI,
documentation builds, and GitHub Pages publishing.

## GitHub Pages

You can publish the generated directory as a static site. For a project-level GitHub Pages
bundle that includes both the demo and benchmark leaderboard, run:

```bash
openscholarguard site --output-dir site-output --overwrite
```

The generated `site-output` directory contains:

- `index.html`: project entrypoint.
- `demo/`: the full static demo bundle.
- `benchmark/`: evaluation and leaderboard publication artifacts.

The page has no runtime dependencies and does not make network requests.
