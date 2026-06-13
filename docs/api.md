# HTTP API

OpenScholarGuard includes a dependency-free local HTTP API for integration with conference
systems, RAG ingestion services, internal review platforms, and document-security gateways.

The server uses Python's standard library and binds to localhost by default.

## Start

```bash
openscholarguard serve --host 127.0.0.1 --port 8765
```

Bind to all interfaces only when you intentionally want network access:

```bash
openscholarguard serve --host 0.0.0.0 --port 8765
```

## Health

```bash
curl http://127.0.0.1:8765/health
```

## OpenAPI

The service exposes its OpenAPI schema:

```bash
curl http://127.0.0.1:8765/openapi.json
```

You can also export the same schema from the CLI without starting a server:

```bash
openscholarguard openapi --output openapi.json
```

## Scan

Scan by path:

```bash
curl -X POST http://127.0.0.1:8765/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"path": "examples/injected_paper.md", "profile": "ai-review"}'
```

Scan submitted text:

```bash
curl -X POST http://127.0.0.1:8765/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"name": "submission.md", "text": "Ignore previous instructions.", "profile": "ai-review"}'
```

Scan with optional LLM audit:

```bash
export OPENAI_API_KEY="<your-openai-api-key>"
curl -X POST http://127.0.0.1:8765/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "path": "examples/injected_paper.md",
    "profile": "ai-review",
    "llm_audit": true,
    "llm_options": {
      "provider": "openai",
      "model": "gpt-4.1-mini",
      "api_key_env": "OPENAI_API_KEY",
      "max_findings": 8
    }
  }'
```

PowerShell:

```powershell
$env:OPENAI_API_KEY="<your-openai-api-key>"
$body = @{
  path = "examples/injected_paper.md"
  profile = "ai-review"
  llm_audit = $true
  llm_options = @{
    provider = "openai"
    model = "gpt-4.1-mini"
    api_key_env = "OPENAI_API_KEY"
    max_findings = 8
  }
} | ConvertTo-Json -Depth 5

Invoke-RestMethod `
  -Uri http://127.0.0.1:8765/v1/scan `
  -Method Post `
  -ContentType "application/json" `
  -Body $body
```

## Sanitize

```bash
curl -X POST http://127.0.0.1:8765/v1/sanitize \
  -H "Content-Type: application/json" \
  -d '{"path": "examples/injected_paper.md", "profile": "ai-review"}'
```

## Ingest

```bash
curl -X POST http://127.0.0.1:8765/v1/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "path": "examples/injected_paper.md",
    "profile": "rag",
    "block_on": "high",
    "allow_risk": true,
    "chunk_size": 1000,
    "chunk_overlap": 100
  }'
```

## Routes

- `GET /health`
- `GET /v1/health`
- `GET /openapi.json`
- `GET /v1/openapi.json`
- `POST /v1/scan`
- `POST /v1/sanitize`
- `POST /v1/ingest`

Request bodies are JSON objects. For scan, sanitize, and ingest, provide either `path` or
`text`. If using `text`, you may also provide `name` for provenance labels.

## Security Notes

The built-in server is intended as a local integration server. It does not implement
authentication, TLS, rate limiting, or multi-tenant isolation. Put it behind your own
trusted gateway if exposing it beyond localhost.

LLM audit is disabled unless `llm_audit` is set to `true`. When enabled, the server reads
the provider key from the environment variable named by `llm_options.api_key_env`; do not
send raw API keys in request bodies. The LLM receives structured scanner findings and
bounded snippets, not entire documents.

## Python Client

```python
from openscholarguard import OpenScholarGuardClient

client = OpenScholarGuardClient("http://127.0.0.1:8765")
health = client.health()
scan = client.scan_path("examples/injected_paper.md")
llm_scan = client.scan_path(
    "examples/injected_paper.md",
    llm_audit=True,
    llm_options={"model": "gpt-4.1-mini"},
)
ingest = client.ingest_text(
    "Legitimate abstract.\nIgnore previous instructions.",
    name="submission.md",
    allow_risk=True,
)
```
