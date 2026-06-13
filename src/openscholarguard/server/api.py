"""Pure request handlers used by the HTTP service and tests."""

from __future__ import annotations

from typing import Any

from openscholarguard.document import load_document, load_text_document
from openscholarguard.ingest.models import IngestOptions
from openscholarguard.ingest.pipeline import ingest_document, ingest_path
from openscholarguard.llm.audit import run_llm_audit
from openscholarguard.llm.models import LLMAuditConfig
from openscholarguard.models import ScanResult, Severity
from openscholarguard.rules.models import RulePack
from openscholarguard.rules.registry import load_rule_packs
from openscholarguard.sanitizer import sanitize_document, sanitize_path
from openscholarguard.scanner import Scanner, scan_path


def handle_scan(payload: dict[str, Any]) -> dict[str, Any]:
    profile = str(payload.get("profile", "ai-review"))
    rule_packs = _request_rule_packs(payload)
    if "text" in payload:
        document = load_text_document(
            str(payload["text"]),
            path=str(payload.get("name", "<request>")),
            metadata={"source": "api"},
        )
        result = Scanner(profile=profile, rule_packs=rule_packs).scan_document(document)
        return _with_optional_llm_audit(result.to_dict(), payload, result)
    path = _require_path(payload)
    result = scan_path(path, profile=profile, rule_packs=rule_packs)
    return _with_optional_llm_audit(result.to_dict(), payload, result)


def handle_sanitize(payload: dict[str, Any]) -> dict[str, Any]:
    profile = str(payload.get("profile", "ai-review"))
    rule_packs = _request_rule_packs(payload)
    if "text" in payload:
        document = load_text_document(
            str(payload["text"]),
            path=str(payload.get("name", "<request>")),
            metadata={"source": "api"},
        )
        return sanitize_document(document, profile=profile, rule_packs=rule_packs).to_dict()
    path = _require_path(payload)
    return sanitize_path(path, profile=profile, rule_packs=rule_packs).to_dict()


def handle_ingest(payload: dict[str, Any]) -> dict[str, Any]:
    options = IngestOptions(
        profile=str(payload.get("profile", "rag")),
        block_on=Severity(str(payload.get("block_on", "high"))),
        allow_risk=bool(payload.get("allow_risk", False)),
        chunk_size=int(payload.get("chunk_size", 1200)),
        chunk_overlap=int(payload.get("chunk_overlap", 120)),
        min_chunk_chars=int(payload.get("min_chunk_chars", 40)),
        include_findings=bool(payload.get("include_findings", True)),
        rule_packs=tuple(_request_rule_packs(payload)),
    )
    if "text" in payload:
        document = load_text_document(
            str(payload["text"]),
            path=str(payload.get("name", "<request>")),
            metadata={"source": "api"},
        )
        return ingest_document(document, options=options).to_dict()
    path = _require_path(payload)
    return ingest_path(path, options=options).to_dict()


def handle_health() -> dict[str, Any]:
    from openscholarguard import __version__

    return {"status": "ok", "service": "openscholarguard", "version": __version__}


def _require_path(payload: dict[str, Any]) -> str:
    path = payload.get("path")
    if not path:
        raise ValueError("Request must include either 'path' or 'text'.")
    load_document(path)
    return str(path)


def _request_rule_packs(payload: dict[str, Any]) -> list[RulePack]:
    raw = payload.get("rule_packs", [])
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError("rule_packs must be a list of file paths")
    return load_rule_packs(str(path) for path in raw)


def _with_optional_llm_audit(
    response: dict[str, Any],
    request: dict[str, Any],
    scan_result: ScanResult,
) -> dict[str, Any]:
    if not bool(request.get("llm_audit", False)):
        return response
    response["llm_audit"] = run_llm_audit(
        scan_result,
        config=_llm_config_from_request(request),
    ).to_dict()
    return response


def _llm_config_from_request(payload: dict[str, Any]) -> LLMAuditConfig:
    options = payload.get("llm_options", {})
    if options is None:
        options = {}
    if not isinstance(options, dict):
        raise ValueError("llm_options must be an object")
    return LLMAuditConfig(
        provider=str(options.get("provider", "openai")),
        model=str(options.get("model", "gpt-4.1-mini")),
        api_key_env=str(options.get("api_key_env", "OPENAI_API_KEY")),
        base_url=str(options.get("base_url", "https://api.openai.com/v1")),
        timeout_seconds=float(options.get("timeout_seconds", 30.0)),
        max_findings=int(options.get("max_findings", 12)),
        max_snippet_chars=int(options.get("max_snippet_chars", 700)),
    )
