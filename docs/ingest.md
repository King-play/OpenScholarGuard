# Guarded Ingestion

Guarded ingestion turns a document into sanitized, provenance-rich chunks for RAG and
document-agent systems. The pipeline scans first, sanitizes second, and only emits chunks if
the document is below the configured risk threshold unless `--allow-risk` is used.

## Quick Start

```bash
openscholarguard ingest paper.pdf --output-dir ingest-output
```

For a high-risk document, ingestion is blocked by default:

```bash
openscholarguard ingest examples/injected_paper.md
```

Allow sanitized chunks while preserving risk metadata:

```bash
openscholarguard ingest examples/injected_paper.md \
  --allow-risk \
  --output-dir ingest-output
```

## Outputs

When `--output-dir` is provided, OpenScholarGuard writes:

- `<name>.clean.md`: sanitized model-readable text.
- `<name>.chunks.jsonl`: one JSON object per chunk for vector stores.
- `<name>.manifest.json`: scan, sanitize, risk, and chunk metadata.

The JSONL chunks include:

- Stable chunk ID.
- Source path and source SHA-256.
- Character offsets.
- Chunk SHA-256.
- Risk score and maximum severity.
- Triggered detectors.

## Formats

Print manifest JSON:

```bash
openscholarguard ingest paper.md --format manifest
```

Print chunks as JSONL:

```bash
openscholarguard ingest paper.md --allow-risk --format jsonl
```

Print sanitized text:

```bash
openscholarguard ingest paper.md --allow-risk --format text
```

## Chunking Controls

```bash
openscholarguard ingest paper.md \
  --chunk-size 1000 \
  --chunk-overlap 100 \
  --min-chunk-chars 80
```

`chunk_overlap` must be smaller than `chunk_size`. The chunker prefers paragraph and line
boundaries, then falls back to sentence-like punctuation and hard splits.

## Exit Codes

- `0`: ingestion produced chunks or an allowed empty result.
- `1`: the document reached the block threshold and `--allow-risk` was not set.
- `2`: command-line usage or runtime error.
