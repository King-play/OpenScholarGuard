# Paper Skeleton

OpenScholarGuard can generate an arXiv-style paper skeleton and experiment tables from the
current benchmark.

```bash
openscholarguard paper --output-dir paper-output --overwrite
```

The output directory contains:

- `main.tex`: a structured paper draft with sections for motivation, threat model, system,
  benchmark, experiments, limitations, ethics, and conclusion.
- `tables/dataset_coverage.tex`: case counts by ScholarGuardBench attack family.
- `tables/deterministic_baseline.tex`: deterministic scanner metrics from the benchmark.
- `artifacts/evaluation.json`: the machine-readable evaluation used by the tables.
- `README.md`: local compilation notes.

## Reusing Existing Results

If CI or a release workflow already produced an evaluation JSON, reuse it:

```bash
openscholarguard paper \
  --evaluation benchmark-publication/evaluation.json \
  --output-dir paper-output \
  --overwrite
```

This keeps the paper tables tied to the exact benchmark artifact you plan to release or
cite.

## Intended Use

The generated paper is a starting point, not a finished manuscript. It intentionally marks
limitations around synthetic data, heuristic detectors, OCR availability, and the need for
external validation with publisher or conference workflows.
