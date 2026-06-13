"""High-level scanning API."""

from __future__ import annotations

from pathlib import Path
from typing import Union

from openscholarguard.detectors import DetectorContext, get_detectors
from openscholarguard.document import Document, load_document
from openscholarguard.models import (
    Finding,
    ScanResult,
    Severity,
    build_summary,
    sort_findings,
    utc_now,
)
from openscholarguard.profiles import get_profile
from openscholarguard.rules.detector import RulePackDetector
from openscholarguard.rules.models import RulePack


class Scanner:
    """Scan documents for prompt injection and document-agent safety risks."""

    def __init__(self, *, profile: str = "ai-review", rule_packs: list[RulePack] | None = None) -> None:
        self.profile = get_profile(profile)
        self.detectors = get_detectors(sorted(self.profile.enabled_detectors))
        self.detectors.extend(RulePackDetector(rule_pack) for rule_pack in (rule_packs or []))

    def scan_document(self, document: Document) -> ScanResult:
        context = DetectorContext(profile=self.profile.name)
        findings = []
        warnings: list[str] = []
        errors: list[str] = []

        for detector in self.detectors:
            try:
                findings.extend(detector.detect(document, context))
            except Exception as exc:  # pragma: no cover - defensive isolation for plugin-like detectors.
                errors.append(f"{detector.id}: {exc}")

        unique_findings = _deduplicate_findings(sort_findings(findings))
        return ScanResult(
            target=str(document.path),
            profile=self.profile.name,
            scanned_at=utc_now(),
            summary=build_summary(unique_findings),
            findings=unique_findings,
            warnings=warnings,
            errors=errors,
            metadata={
                **document.metadata,
                "sha256": document.sha256,
                "detectors": [detector.id for detector in self.detectors],
            },
        )

    def scan_path(self, path: Union[str, Path]) -> ScanResult:
        return self.scan_document(load_document(path))


def scan_path(
    path: Union[str, Path],
    *,
    profile: str = "ai-review",
    rule_packs: list[RulePack] | None = None,
) -> ScanResult:
    return Scanner(profile=profile, rule_packs=rule_packs).scan_path(path)


def should_fail(result: ScanResult, fail_on: Union[str, Severity]) -> bool:
    severity = Severity(fail_on)
    return result.has_at_least(severity)


def _deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    unique = []
    for finding in findings:
        key = finding.id
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique
