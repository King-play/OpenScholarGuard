# Integrations

OpenScholarGuard keeps framework integrations dependency-light. The helpers accept
Document-like objects and avoid importing optional frameworks directly.

## GitHub Action

Use the composite action from this repository:

```yaml
name: Document Security Audit

on:
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: King-play/OpenScholarGuard@v0.1.0
        with:
          targets: "."
          profile: "ai-review"
          fail-on: "high"
          output: "openscholarguard.sarif"
      - uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: openscholarguard.sarif
```

When testing inside this repository before a release, set `install-spec: "."`.

## LangChain-Style Documents

```python
from openscholarguard.integrations.langchain import OpenScholarGuardTransformer

guard = OpenScholarGuardTransformer(profile="rag", block_on="high")
safe_documents = guard.transform_documents(documents)
```

The transformer expects objects with `page_content` and optional `metadata` attributes. It
returns sanitized objects of the same type when possible. Blocked documents are omitted
unless `allow_risk=True`.

For audit trails:

```python
results = guard.guard_documents(documents)
for result in results:
    print(result.blocked, result.risk_score, result.max_severity)
```

Each returned document metadata includes an `openscholarguard` object with profile,
blocked status, risk score, max severity, finding count, and removed-fragment count.

## LlamaIndex-Style Nodes

```python
from openscholarguard.integrations.llamaindex import OpenScholarGuardNodePostprocessor

guard = OpenScholarGuardNodePostprocessor(profile="rag", block_on="high")
safe_nodes = guard.postprocess_nodes(nodes)
```

The postprocessor accepts node-like objects with `get_content()`, `text`, or
`page_content`, plus optional `metadata`. Blocked nodes are omitted unless
`allow_risk=True`.

For audit trails:

```python
results = guard.guard_nodes(nodes)
for result in results:
    print(result.blocked, result.risk_score, result.finding_count)
```

## Boundary

These integrations guard document content before it enters retrieval, synthesis, or
agentic workflows. They do not replace sandboxing, least-privilege tool access,
model-side instruction hierarchy controls, or human review for high-stakes workflows.
