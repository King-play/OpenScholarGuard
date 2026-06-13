# Audit Mode

Audit mode scans files and directories with a policy, suppression rules, and CI-oriented
report formats. It is designed for repositories, conference submission pipelines, RAG
ingestion folders, and document-security gates.

## Quick Start

```bash
openscholarguard audit examples --format text
```

Generate a policy file:

```bash
openscholarguard init-policy --output .openscholarguard.json
```

Run with policy:

```bash
openscholarguard audit . --policy .openscholarguard.json
```

## CI Formats

SARIF for GitHub code scanning:

```bash
openscholarguard audit . \
  --policy .openscholarguard.json \
  --format sarif \
  --output openscholarguard.sarif
```

JUnit XML for generic CI test reports:

```bash
openscholarguard audit . \
  --format junit \
  --output openscholarguard.junit.xml
```

HTML for human audit review:

```bash
openscholarguard audit submissions \
  --format html \
  --output audit.html
```

## Policy File

Policy files are JSON to avoid runtime parser dependencies.

```json
{
  "profile": "ai-review",
  "fail_on": "high",
  "include": ["**/*.pdf", "**/*.md", "**/*.tex"],
  "exclude": [
    "**/.git/**",
    "**/__pycache__/**",
    "**/dist/**",
    "**/.openscholarguard.json",
    "**/openscholarguard-policy.json"
  ],
  "max_file_bytes": 26214400,
  "suppressions": [
    {
      "detector_id": "suspicious_density",
      "path": "docs/**",
      "reason": "Accepted low-confidence documentation noise."
    }
  ]
}
```

Suppression rules can match by `detector_id`, `path`, and `finding_id`. Suppressed findings
are counted in audit summaries instead of disappearing silently.

## Exit Codes

- `0`: no files failed the configured threshold.
- `1`: at least one file has an actionable finding at or above `fail_on`, or a file failed
  to scan.
- `2`: command-line usage, policy loading, or runtime setup error.
