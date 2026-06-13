"""High-level LLM audit orchestration."""

from __future__ import annotations

import os

from openscholarguard.exceptions import OpenScholarGuardError
from openscholarguard.llm.models import (
    FindingReview,
    LLMAuditConfig,
    LLMAuditResult,
    LLMAuditVerdict,
)
from openscholarguard.llm.prompt import build_llm_audit_request
from openscholarguard.llm.providers import LLMAuditClient, OpenAIResponsesClient
from openscholarguard.models import ScanResult


class LLMAuditConfigurationError(OpenScholarGuardError):
    """Raised when an LLM audit is requested without valid configuration."""


def run_llm_audit(
    result: ScanResult,
    *,
    config: LLMAuditConfig | None = None,
    client: LLMAuditClient | None = None,
) -> LLMAuditResult:
    """Run optional LLM-assisted audit for a scan result."""

    config = config or LLMAuditConfig()
    if not result.findings and not config.require_findings:
        return LLMAuditResult(
            provider=config.provider,
            model=config.model,
            verdict=LLMAuditVerdict.CONFIRMED,
            confidence=1.0,
            summary="No scanner findings were present, so no LLM escalation was required.",
            reviews=[],
            warnings=[],
            metadata={"skipped": True, "reason": "no_findings"},
        )

    active_client = client or _client_from_config(config)
    request = build_llm_audit_request(result, config)
    audit = active_client.audit(request)
    review_by_id = {review.finding_id: review for review in audit.reviews}
    missing = [finding.id for finding in result.findings[: config.max_findings] if finding.id not in review_by_id]
    if missing:
        audit = _with_missing_review_warnings(audit, missing)
    return audit


def _client_from_config(config: LLMAuditConfig) -> LLMAuditClient:
    if config.provider != "openai":
        raise LLMAuditConfigurationError(f"Unsupported LLM audit provider: {config.provider}")
    api_key = os.getenv(config.api_key_env, "")
    if not api_key:
        raise LLMAuditConfigurationError(
            f"Set {config.api_key_env} to enable OpenAI-backed LLM audit, or pass a custom client."
        )
    return OpenAIResponsesClient(
        api_key=api_key,
        model=config.model,
        base_url=config.base_url,
        timeout_seconds=config.timeout_seconds,
    )


def _with_missing_review_warnings(audit: LLMAuditResult, missing: list[str]) -> LLMAuditResult:
    warnings = [
        *audit.warnings,
        f"LLM audit did not return reviews for finding IDs: {', '.join(missing)}",
    ]
    reviews = [
        *audit.reviews,
        *[
            FindingReview(
                finding_id=finding_id,
                verdict=LLMAuditVerdict.NEEDS_HUMAN_REVIEW,
                confidence=0.0,
                rationale="The LLM response omitted this scanner finding.",
                recommended_action="Review this finding manually before trusting the audit result.",
            )
            for finding_id in missing
        ],
    ]
    return LLMAuditResult(
        provider=audit.provider,
        model=audit.model,
        verdict=audit.verdict,
        confidence=audit.confidence,
        summary=audit.summary,
        reviews=reviews,
        warnings=warnings,
        metadata=audit.metadata,
    )
