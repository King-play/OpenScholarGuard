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
- `pdf-gallery/`: synthetic PDF attack cases, screenshots, scan reports, and deep-audit reports.
- `benchmark/`: leaderboard, evaluation report, submission entry, and generated samples.

The GitHub Pages deployment job is skipped while the repository is private. This avoids
failing private development pushes before a public demo is intended. When you are ready to
publish the online demo:

1. Make the repository public.
2. Push to `main`, or run the `Demo Pages` workflow manually.
3. Open `Settings -> Pages` and set `Build and deployment -> Source` to `GitHub Actions`.
4. Rerun the `Demo Pages` workflow to deploy `site-output`.

The workflow intentionally does not create or enable the Pages site through the GitHub API.
Some repositories return `Resource not accessible by integration` for that operation even
when the workflow has `pages: write`. Manual Pages setup avoids that first-run permission
edge case; after setup, the workflow handles build and deployment.

The default public URL will be:

```text
https://king-play.github.io/OpenScholarGuard/
```

## Release Check

`.github/workflows/release.yml` runs on `v*` tags and manual dispatch. It performs the
quality gates, verifies demo generation, builds the package, uploads the distribution
artifacts for release review, creates a GitHub release on tags, and publishes to PyPI when
trusted publishing is configured for the repository.

## Repository Audit Action

`.github/workflows/openscholarguard-audit.yml` demonstrates the SARIF-producing audit flow
for pull requests. The repository also ships `action.yml` as a composite action so other
projects can run:

```yaml
- uses: King-play/OpenScholarGuard@v0.1.0
  with:
    targets: "."
    profile: "ai-review"
    fail-on: "high"
```

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
