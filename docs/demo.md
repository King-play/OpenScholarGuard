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

The repository README uses `docs/assets/demo-preview.png` and `docs/assets/demo-preview.gif`
as the first-screen public-site preview. Regenerate the preview, project-site preview,
leaderboard preview, and ordered animation frames after changing the public site, benchmark
pages, or local workflow bundle:

```bash
python scripts/capture_demo_assets.py
```

The script writes:

- `docs/assets/demo-preview.png`
- `docs/assets/site-preview.png`
- `docs/assets/leaderboard-preview.png`
- `docs/assets/demo-frames/*.png`

It requires a local Chrome or Chromium executable. On Windows it automatically checks
`C:\Program Files\Google\Chrome\Application\chrome.exe`; otherwise pass `--chrome`.

Optional GIF and video assembly:

```bash
magick -delay 140 -loop 0 docs/assets/demo-frames/*.png docs/assets/demo-preview.gif
ffmpeg -framerate 1 -pattern_type glob -i "docs/assets/demo-frames/*.png" -vf "fps=12,scale=1440:-1" docs/assets/demo-preview.mp4
```

Keep generated GIF/MP4 files reasonably small before committing them. The PNG frames are
the source-of-truth capture artifacts.

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

- `index.html`: public project entrypoint and primary workflow preview.
- `demo/`: local workflow bundle kept as a generated artifact, not the primary public entrypoint.
- `benchmark/`: ScholarGuardBench evaluation and leaderboard publication artifacts.
- `pdf-gallery/`: synthetic PDF attack gallery.

The page has no runtime dependencies and does not make network requests.
