# Rule Packs

Rule packs let teams add local detection rules without editing OpenScholarGuard source code.
They are useful for conference-specific review policies, enterprise document-ingestion
rules, private taxonomy checks, and fast response to new document-borne attacks.

## Format

Rule packs are JSON files:

```json
{
  "name": "local-review-policy",
  "version": "0.1.0",
  "description": "Example local review rules.",
  "rules": [
    {
      "id": "forbid_private_review_request",
      "title": "Reference to private review material",
      "severity": "high",
      "patterns": ["\\bprivate\\s+review\\s+notes?\\b"],
      "confidence": 0.86,
      "remediation": "Remove private review material before ingestion.",
      "tags": ["custom-policy", "peer-review"],
      "case_sensitive": false,
      "scope": "all"
    }
  ],
  "tests": [
    {
      "name": "private-review-note-positive",
      "text": "The appendix contains confidential review comments.",
      "expected": {
        "rule_ids": ["forbid_private_review_request"],
        "min_findings": 1,
        "max_findings": 1,
        "min_severity": "high"
      }
    },
    {
      "name": "ordinary-language-negative",
      "text": "The paper asks reviewers to evaluate the evidence.",
      "expected": {
        "rule_ids": [],
        "min_findings": 0,
        "max_findings": 0
      }
    }
  ]
}
```

`scope` can be `all`, `text`, or `metadata`.

Rule packs may also include an optional `fingerprint` or `sha256` field. OpenScholarGuard
computes fingerprints from canonical JSON while ignoring those fingerprint fields, so a
pack can carry its expected SHA-256 digest without changing the digest being checked.

## Embedded Tests

The optional `tests` array turns a rule pack into a self-verifying artifact. Each test has
input `text` and an `expected` object:

- `rule_ids`: rule IDs that must be matched. Use an empty array for negative tests.
- `min_findings`: minimum number of findings expected.
- `max_findings`: maximum number of findings expected.
- `min_severity`: at least one finding must meet this severity or higher.

Use both positive and negative tests before sharing a rule pack. Positive tests prove the
rule detects the intended policy issue; negative tests reduce noisy expressions that would
flag ordinary scholarly language.

## CLI

Validate a rule pack:

```bash
openscholarguard rules validate examples/rule-pack.json
```

Print a stable fingerprint:

```bash
openscholarguard rules fingerprint examples/rule-pack.json
```

Run embedded rule-pack tests:

```bash
openscholarguard rules verify examples/rule-pack.json --require-tests
```

List rules:

```bash
openscholarguard rules list examples/rule-pack.json
```

Test against text:

```bash
openscholarguard rules test examples/rule-pack.json \
  --text "This document references private review notes."
```

Use rules during scan, sanitize, ingest, or audit:

```bash
openscholarguard scan paper.md --rule-pack examples/rule-pack.json
openscholarguard ingest paper.md --rule-pack examples/rule-pack.json --output-dir ingest-output
openscholarguard audit . --rule-pack examples/rule-pack.json
```

Policy files can also include rule packs:

```json
{
  "profile": "ai-review",
  "fail_on": "high",
  "rule_packs": ["examples/rule-pack.json"]
}
```

## API

The HTTP API accepts `rule_packs` as a list of file paths available to the server process:

```json
{
  "path": "paper.md",
  "profile": "ai-review",
  "rule_packs": ["examples/rule-pack.json"]
}
```

## Safety Notes

Rule packs use regular expressions. Keep patterns precise, test them with representative
positive and negative examples, and avoid broad expressions that flag ordinary scholarly
language.

For CI, prefer `rules verify --require-tests` over `rules validate` alone. Validation
checks structure and regular-expression syntax; verification also checks fingerprints and
the behavior promised by embedded test fixtures.
