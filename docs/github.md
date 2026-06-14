# GitHub Workflows

OpenScholarGuard includes GitHub automation for quality gates, package validation, and
static demo publishing.

## CI

`.github/workflows/ci.yml` runs on pushes and pull requests to `main`.

It checks:

- Python 3.10, 3.11, 3.12, and 3.13.
- `ruff check .`
- `mypy src/openscholarguard`
- `pytest --cov=openscholarguard`
- Example rule-pack verification.
- `openscholarguard doctor --demo`
- Static demo generation.
- Source and wheel package build.

## Demo Pages

`.github/workflows/pages.yml` generates the static project site with:

```bash
python -m openscholarguard site --output-dir site-output --overwrite
```

The workflow always uploads `site-output` as a downloadable Actions artifact named
`openscholarguard-site`. This gives private repositories a shareable preview without
publishing a public site. The site includes:

- `index.html`: project entrypoint.
- `demo/`: static demo, reports, artifacts, and attack gallery.
- `benchmark/`: leaderboard, evaluation report, submission entry, and generated samples.

The GitHub Pages deployment job is skipped while the repository is private. This avoids
failing private development pushes before a public demo is intended. When you are ready to
publish the online demo:

1. Make the repository public.
2. Push to `main`, or run the `Demo Pages` workflow manually.
3. The workflow configures Pages for GitHub Actions and deploys `site-output`.

If your organization blocks workflow-managed Pages setup, open `Settings -> Pages` and set
`Build and deployment -> Source` to `GitHub Actions`, then rerun the workflow.

The default public URL will be:

```text
https://king-play.github.io/OpenScholarGuard/
```

## Release Check

`.github/workflows/release.yml` runs on `v*` tags and manual dispatch. It performs the
quality gates, verifies demo generation, builds the package, and uploads the distribution
artifacts for release review.

## Local Preflight

Before opening a pull request:

```bash
python -m openscholarguard doctor --demo
python -m ruff check .
python -m mypy src/openscholarguard
python -m pytest
python -m build
```

Do not commit generated `demo-output`, coverage output, build artifacts, caches, or local
environment files.
