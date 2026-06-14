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

`.github/workflows/pages.yml` generates the static demo with:

```bash
python -m openscholarguard demo --output-dir demo-output --overwrite
```

It then uploads `demo-output` to GitHub Pages. Enable Pages in the repository settings and
select GitHub Actions as the source.

The workflow is skipped while the repository is private. This avoids failing private
development pushes before GitHub Pages has been enabled. When you are ready to publish the
online demo, make the repository public, enable Pages with GitHub Actions as the source,
then run the workflow again.

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
