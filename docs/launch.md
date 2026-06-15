# Launch Checklist

This checklist tracks the gap between a strong engineering MVP and a flagship open-source
release that people can try, cite, and integrate.

## Public Demo

- Confirm `Pages` runs successfully on `main`.
- Make the repository public when ready for the first public demo.
- Verify the public URL:

```text
https://king-play.github.io/OpenScholarGuard/
```

- Regenerate preview assets after layout changes:

```bash
python scripts/capture_demo_assets.py
```

- Confirm the README GIF, site preview, demo preview, and leaderboard preview match the
  current generated site.

## Release Preflight

Run locally before tagging:

```bash
python -m openscholarguard doctor --demo
python -m ruff check .
python -m mypy src/openscholarguard
python -m pytest
python -m build
```

Then create a release tag only after CI is green:

```bash
git tag v0.1.0
git push origin v0.1.0
```

## Benchmark Publication

Generate the deterministic baseline bundle:

```bash
openscholarguard benchmark publish --output-dir benchmark-publication
```

The public benchmark package should include:

- `evaluation.json`
- `evaluation.md`
- `evaluation.html`
- `leaderboard.json`
- `leaderboard.md`
- `leaderboard.html`
- generated samples and manifest

## First Real Model Run

For every evaluated model, record:

- provider
- model name
- model version or release date when available
- run date
- temperature
- max output tokens
- prompt protocol commit SHA
- response JSONL path
- judge version or commit SHA

Store raw responses as JSONL and never overwrite old runs. Prefer a path shaped like:

```text
model-eval/runs/2026-06-14/provider-model/responses.jsonl
```

Use the built-in OpenAI-compatible collector when the provider exposes Chat Completions:

```bash
openscholarguard benchmark collect \
  --protocol model-eval/protocol.json \
  --provider openai-compatible \
  --model provider-model-name \
  --base-url https://provider.example/v1 \
  --api-key-env PROVIDER_API_KEY \
  --run-label 2026-06-14-first-run \
  --output model-eval/runs/2026-06-14/provider-model/responses.jsonl
```

The first public leaderboard should clearly distinguish deterministic scanner baselines
from model-response evaluations.

Create the public model-response leaderboard from judge JSON files:

```bash
openscholarguard benchmark model-leaderboard \
  model-eval/runs/2026-06-14/*/*.judge.json \
  --format html \
  --output model-eval/runs/2026-06-14/leaderboard.html
```

Create the uploadable publication bundle:

```bash
openscholarguard benchmark model-publish \
  model-eval/runs/2026-06-14/*/*.judge.json \
  --output-dir model-eval-publication/2026-06-14 \
  --overwrite
```

## PDF Gallery

Each PDF gallery case should include:

- synthetic source recipe
- generated PDF
- screenshot or rendered page image
- scan report
- deep-audit report
- sanitized output when applicable
- short explanation of what is visible to humans and what is visible to extraction/OCR

Minimum gallery coverage:

- white text
- transparent text
- tiny text
- off-page text
- PDF metadata injection
- OCR-layer injection
- image text injection
- hidden LaTeX
- invisible Unicode
- encoded payload

## Integration Release Targets

Recommended order:

1. GitHub Action for audit mode.
2. LangChain loader or document transformer.
3. LlamaIndex ingestion guard.
4. promptfoo red-team example.
5. PyRIT scenario example.
6. OpenReview-style workflow example.

Each integration should have a tiny example, test coverage where practical, and a docs page
that explains the threat boundary.

## Paper Track

The arXiv-ready draft should include:

- abstract
- introduction
- threat model
- system design
- detector taxonomy
- benchmark design
- experiments
- model-evaluation results
- PDF gallery case studies
- ablations
- limitations
- ethics and responsible disclosure notes
- related work
- reproducibility appendix
