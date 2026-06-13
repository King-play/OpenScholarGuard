"""OpenAPI schema for the built-in HTTP service."""

from __future__ import annotations

from typing import Any


def openapi_schema() -> dict[str, Any]:
    """Return the OpenAPI 3.1 schema for the local service."""

    return {
        "openapi": "3.1.0",
        "info": {
            "title": "OpenScholarGuard API",
            "version": "0.1.0",
            "description": "Local API for scanning, sanitizing, and ingesting scholarly documents.",
        },
        "servers": [{"url": "http://127.0.0.1:8765"}],
        "paths": {
            "/health": {
                "get": {
                    "summary": "Service health",
                    "operationId": "getHealth",
                    "responses": {"200": {"description": "Health response", "content": _json("HealthResponse")}},
                }
            },
            "/v1/scan": {
                "post": {
                    "summary": "Scan a document",
                    "operationId": "scanDocument",
                    "requestBody": _request_body("DocumentRequest"),
                    "responses": {
                        "200": {"description": "Scan result", "content": _json("ScanResult")},
                        "400": {"description": "Bad request", "content": _json("ErrorResponse")},
                    },
                }
            },
            "/v1/sanitize": {
                "post": {
                    "summary": "Sanitize a document",
                    "operationId": "sanitizeDocument",
                    "requestBody": _request_body("DocumentRequest"),
                    "responses": {
                        "200": {"description": "Sanitize result", "content": _json("SanitizeResult")},
                        "400": {"description": "Bad request", "content": _json("ErrorResponse")},
                    },
                }
            },
            "/v1/ingest": {
                "post": {
                    "summary": "Guarded RAG ingestion",
                    "operationId": "ingestDocument",
                    "requestBody": _request_body("IngestRequest"),
                    "responses": {
                        "200": {"description": "Ingest result", "content": _json("IngestResult")},
                        "400": {"description": "Bad request", "content": _json("ErrorResponse")},
                    },
                }
            },
        },
        "components": {
            "schemas": {
                "HealthResponse": {
                    "type": "object",
                    "required": ["status", "service", "version"],
                    "properties": {
                        "status": {"type": "string", "const": "ok"},
                        "service": {"type": "string"},
                        "version": {"type": "string"},
                    },
                },
                "ErrorResponse": {
                    "type": "object",
                    "required": ["error", "message"],
                    "properties": {
                        "error": {"type": "string"},
                        "message": {"type": "string"},
                    },
                },
                "DocumentRequest": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "text": {"type": "string"},
                        "name": {"type": "string"},
                        "profile": {"type": "string", "default": "ai-review"},
                        "rule_packs": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Paths to JSON rule packs available to the server process.",
                        },
                        "llm_audit": {
                            "type": "boolean",
                            "default": False,
                            "description": "Run optional LLM review of scan findings.",
                        },
                        "llm_options": {"$ref": "#/components/schemas/LLMAuditOptions"},
                    },
                    "anyOf": [{"required": ["path"]}, {"required": ["text"]}],
                    "additionalProperties": True,
                },
                "LLMAuditOptions": {
                    "type": "object",
                    "properties": {
                        "provider": {"type": "string", "enum": ["openai"], "default": "openai"},
                        "model": {"type": "string", "default": "gpt-4.1-mini"},
                        "api_key_env": {"type": "string", "default": "OPENAI_API_KEY"},
                        "base_url": {"type": "string", "default": "https://api.openai.com/v1"},
                        "timeout_seconds": {"type": "number", "default": 30},
                        "max_findings": {"type": "integer", "minimum": 1, "default": 12},
                        "max_snippet_chars": {"type": "integer", "minimum": 1, "default": 700},
                    },
                    "additionalProperties": False,
                },
                "LLMAuditVerdict": {
                    "type": "string",
                    "enum": ["confirmed", "likely", "uncertain", "false_positive", "needs_human_review"],
                },
                "LLMAuditReview": {
                    "type": "object",
                    "properties": {
                        "finding_id": {"type": "string"},
                        "verdict": {"$ref": "#/components/schemas/LLMAuditVerdict"},
                        "confidence": {"type": "number"},
                        "rationale": {"type": "string"},
                        "recommended_action": {"type": "string"},
                    },
                },
                "LLMAuditResult": {
                    "type": "object",
                    "properties": {
                        "provider": {"type": "string"},
                        "model": {"type": "string"},
                        "verdict": {"$ref": "#/components/schemas/LLMAuditVerdict"},
                        "confidence": {"type": "number"},
                        "summary": {"type": "string"},
                        "reviews": {
                            "type": "array",
                            "items": {"$ref": "#/components/schemas/LLMAuditReview"},
                        },
                        "warnings": {"type": "array", "items": {"type": "string"}},
                        "metadata": {"type": "object"},
                    },
                },
                "IngestRequest": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "text": {"type": "string"},
                        "name": {"type": "string"},
                        "profile": {"type": "string", "default": "rag"},
                        "block_on": {"$ref": "#/components/schemas/Severity"},
                        "allow_risk": {"type": "boolean", "default": False},
                        "chunk_size": {"type": "integer", "minimum": 1, "default": 1200},
                        "chunk_overlap": {"type": "integer", "minimum": 0, "default": 120},
                        "min_chunk_chars": {"type": "integer", "minimum": 0, "default": 40},
                        "include_findings": {"type": "boolean", "default": True},
                        "rule_packs": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Paths to JSON rule packs available to the server process.",
                        },
                    },
                    "anyOf": [{"required": ["path"]}, {"required": ["text"]}],
                    "additionalProperties": True,
                },
                "Severity": {
                    "type": "string",
                    "enum": ["info", "low", "medium", "high", "critical"],
                },
                "Location": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "page": {"type": ["integer", "null"]},
                        "line": {"type": ["integer", "null"]},
                        "section": {"type": ["string", "null"]},
                        "field": {"type": ["string", "null"]},
                        "block": {"type": ["integer", "null"]},
                        "span": {"type": ["integer", "null"]},
                    },
                },
                "Finding": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "detector_id": {"type": "string"},
                        "title": {"type": "string"},
                        "severity": {"$ref": "#/components/schemas/Severity"},
                        "confidence": {"type": "number"},
                        "location": {"$ref": "#/components/schemas/Location"},
                        "snippet": {"type": "string"},
                        "evidence": {"type": "object"},
                        "remediation": {"type": "string"},
                        "tags": {"type": "array", "items": {"type": "string"}},
                    },
                },
                "ScanSummary": {
                    "type": "object",
                    "properties": {
                        "total_findings": {"type": "integer"},
                        "by_severity": {"type": "object", "additionalProperties": {"type": "integer"}},
                        "risk_score": {"type": "integer"},
                        "max_severity": {"$ref": "#/components/schemas/Severity"},
                    },
                },
                "ScanResult": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string"},
                        "profile": {"type": "string"},
                        "scanned_at": {"type": "string"},
                        "summary": {"$ref": "#/components/schemas/ScanSummary"},
                        "findings": {"type": "array", "items": {"$ref": "#/components/schemas/Finding"}},
                        "warnings": {"type": "array", "items": {"type": "string"}},
                        "errors": {"type": "array", "items": {"type": "string"}},
                        "metadata": {"type": "object"},
                        "llm_audit": {"$ref": "#/components/schemas/LLMAuditResult"},
                    },
                },
                "SanitizeResult": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string"},
                        "profile": {"type": "string"},
                        "sanitized_at": {"type": "string"},
                        "text": {"type": "string"},
                        "removed": {"type": "array", "items": {"type": "object"}},
                        "warnings": {"type": "array", "items": {"type": "string"}},
                    },
                },
                "IngestChunk": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "text": {"type": "string"},
                        "source_path": {"type": "string"},
                        "ordinal": {"type": "integer"},
                        "start_char": {"type": "integer"},
                        "end_char": {"type": "integer"},
                        "sha256": {"type": "string"},
                        "metadata": {"type": "object"},
                    },
                },
                "IngestResult": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string"},
                        "status": {"type": "string", "enum": ["ready", "blocked", "empty"]},
                        "profile": {"type": "string"},
                        "block_on": {"$ref": "#/components/schemas/Severity"},
                        "risk_score": {"type": "integer"},
                        "max_severity": {"$ref": "#/components/schemas/Severity"},
                        "chunks": {"type": "array", "items": {"$ref": "#/components/schemas/IngestChunk"}},
                        "sanitized_text": {"type": "string"},
                        "findings": {"type": "array", "items": {"type": "object"}},
                        "removed": {"type": "array", "items": {"type": "object"}},
                        "warnings": {"type": "array", "items": {"type": "string"}},
                        "metadata": {"type": "object"},
                    },
                },
            }
        },
    }


def _json(schema_name: str) -> dict[str, Any]:
    return {"application/json": {"schema": {"$ref": f"#/components/schemas/{schema_name}"}}}


def _request_body(schema_name: str) -> dict[str, Any]:
    return {
        "required": True,
        "content": _json(schema_name),
    }
