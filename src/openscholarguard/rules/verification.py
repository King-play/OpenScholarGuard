"""Rule-pack verification runner."""

from __future__ import annotations

from dataclasses import dataclass, field

from openscholarguard.detectors import DetectorContext
from openscholarguard.document import load_text_document
from openscholarguard.models import SEVERITY_RANK, Finding, Severity
from openscholarguard.rules.detector import RulePackDetector
from openscholarguard.rules.fingerprint import fingerprint_mismatch
from openscholarguard.rules.models import RulePack, RulePackTestCase


@dataclass(frozen=True)
class RulePackTestResult:
    """Result for one embedded rule-pack fixture."""

    name: str
    passed: bool
    finding_count: int
    matched_rule_ids: tuple[str, ...]
    errors: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class RulePackVerification:
    """Complete verification outcome for a rule pack."""

    rule_pack: RulePack
    passed: bool
    fingerprint: str
    errors: tuple[str, ...]
    tests: tuple[RulePackTestResult, ...]


def verify_rule_pack(
    rule_pack: RulePack,
    *,
    raw_payload: dict[str, object] | None = None,
    require_tests: bool = False,
) -> RulePackVerification:
    """Run fingerprint and fixture checks for a loaded rule pack."""

    errors: list[str] = []
    if raw_payload is not None:
        mismatch = fingerprint_mismatch(raw_payload)
        if mismatch is not None:
            errors.append(mismatch)
    if require_tests and not rule_pack.tests:
        errors.append("rule pack does not define tests")

    test_results = tuple(_run_test(rule_pack, test_case) for test_case in rule_pack.tests)
    passed = not errors and all(result.passed for result in test_results)
    return RulePackVerification(
        rule_pack=rule_pack,
        passed=passed,
        fingerprint=rule_pack.fingerprint,
        errors=tuple(errors),
        tests=test_results,
    )


def _run_test(rule_pack: RulePack, test_case: RulePackTestCase) -> RulePackTestResult:
    document = load_text_document(test_case.text, path=f"<rule-test:{test_case.name}>")
    findings = RulePackDetector(rule_pack).detect(document, DetectorContext(profile="rule-pack-verify"))
    matched_rule_ids = tuple(sorted({str(finding.evidence.get("rule_id", "")) for finding in findings}))
    expected = test_case.expected
    errors: list[str] = []

    if expected.rule_ids is not None:
        missing_rule_ids = sorted(set(expected.rule_ids) - set(matched_rule_ids))
        if missing_rule_ids:
            errors.append(f"missing expected rule ids: {', '.join(missing_rule_ids)}")

    if expected.min_findings is not None and len(findings) < expected.min_findings:
        errors.append(f"expected at least {expected.min_findings} findings, got {len(findings)}")

    if expected.max_findings is not None and len(findings) > expected.max_findings:
        errors.append(f"expected at most {expected.max_findings} findings, got {len(findings)}")

    if expected.min_severity is not None and not _has_min_severity(findings, expected.min_severity):
        errors.append(f"expected at least one finding at severity {expected.min_severity.value} or higher")

    return RulePackTestResult(
        name=test_case.name,
        passed=not errors,
        finding_count=len(findings),
        matched_rule_ids=matched_rule_ids,
        errors=tuple(errors),
    )


def _has_min_severity(findings: list[Finding], minimum: Severity) -> bool:
    return any(SEVERITY_RANK[finding.severity] >= SEVERITY_RANK[minimum] for finding in findings)
