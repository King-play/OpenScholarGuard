"""Batch audit runner for directories and document collections."""

from __future__ import annotations

import os
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional, Union

from openscholarguard.audit.policy import AuditPolicy, SuppressionRule, load_policy
from openscholarguard.exceptions import OpenScholarGuardError, UnsupportedDocumentError
from openscholarguard.models import (
    Finding,
    ScanResult,
    Severity,
    _json_ready,
    build_summary,
    utc_now,
)
from openscholarguard.rules.registry import load_rule_packs
from openscholarguard.scanner import Scanner


@dataclass(frozen=True)
class SuppressedFinding:
    """A finding intentionally suppressed by policy."""

    finding: Finding
    reason: str
    rule: SuppressionRule


@dataclass(frozen=True)
class FileAudit:
    """Audit result for one target file."""

    path: str
    scanned: bool
    result: Optional[ScanResult] = None
    suppressed: list[SuppressedFinding] = field(default_factory=list)
    error: Optional[str] = None


@dataclass(frozen=True)
class AuditSummary:
    """Aggregate view of a batch audit."""

    files_discovered: int
    files_scanned: int
    files_failed: int
    total_findings: int
    suppressed_findings: int
    actionable_findings: int
    risk_score: int
    max_severity: Severity


@dataclass(frozen=True)
class AuditResult:
    """Complete batch audit output."""

    root: str
    profile: str
    fail_on: Severity
    audited_at: str
    summary: AuditSummary
    files: list[FileAudit]
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return _json_ready(asdict(self))

    def has_failures(self) -> bool:
        threshold = self.fail_on
        return any(
            file.result is not None and file.result.has_at_least(threshold)
            for file in self.files
        ) or self.summary.files_failed > 0


def audit_paths(
    targets: Iterable[Union[str, Path]],
    *,
    policy: Optional[AuditPolicy] = None,
    policy_path: Optional[Union[str, Path]] = None,
) -> AuditResult:
    """Audit files and directories according to policy."""

    active_policy = policy or load_policy(policy_path)
    roots = [Path(target).expanduser().resolve() for target in targets]
    if not roots:
        raise OpenScholarGuardError("At least one audit target is required.")

    common_root = _common_root(roots)
    files = discover_files(roots, active_policy, common_root)
    scanner = Scanner(
        profile=active_policy.profile,
        rule_packs=load_rule_packs(active_policy.rule_packs),
    )
    audited_files: list[FileAudit] = []
    warnings: list[str] = []

    for path in files:
        if path.stat().st_size > active_policy.max_file_bytes:
            audited_files.append(
                FileAudit(
                    path=str(path),
                    scanned=False,
                    error=f"File exceeds max_file_bytes={active_policy.max_file_bytes}",
                )
            )
            continue

        try:
            raw_result = scanner.scan_path(path)
        except (OpenScholarGuardError, UnsupportedDocumentError, OSError, ValueError) as exc:
            audited_files.append(FileAudit(path=str(path), scanned=False, error=str(exc)))
            continue

        actionable, suppressed = _apply_suppressions(raw_result, active_policy, common_root)
        filtered_result = ScanResult(
            target=raw_result.target,
            profile=raw_result.profile,
            scanned_at=raw_result.scanned_at,
            summary=build_summary(actionable),
            findings=actionable,
            warnings=raw_result.warnings,
            errors=raw_result.errors,
            metadata=raw_result.metadata,
        )
        warnings.extend(raw_result.warnings)
        warnings.extend(raw_result.errors)
        audited_files.append(
            FileAudit(
                path=str(path),
                scanned=True,
                result=filtered_result,
                suppressed=suppressed,
                error=None,
            )
        )

    return AuditResult(
        root=str(common_root),
        profile=active_policy.profile,
        fail_on=active_policy.fail_on,
        audited_at=utc_now(),
        summary=_build_audit_summary(audited_files, active_policy.fail_on),
        files=audited_files,
        warnings=warnings,
    )


def discover_files(roots: Iterable[Path], policy: AuditPolicy, common_root: Path) -> list[Path]:
    discovered: set[Path] = set()
    for root in roots:
        if root.is_file():
            if policy.should_include(root, common_root):
                discovered.add(root)
            continue
        if not root.exists():
            raise FileNotFoundError(str(root))
        for path in root.rglob("*"):
            if policy.should_include(path, common_root):
                discovered.add(path)
    return sorted(discovered)


def _apply_suppressions(
    result: ScanResult,
    policy: AuditPolicy,
    root: Path,
) -> tuple[list[Finding], list[SuppressedFinding]]:
    actionable: list[Finding] = []
    suppressed: list[SuppressedFinding] = []
    for finding in result.findings:
        rule = policy.is_suppressed(finding, root)
        if rule is None:
            actionable.append(finding)
        else:
            suppressed.append(
                SuppressedFinding(
                    finding=finding,
                    reason=rule.reason,
                    rule=rule,
                )
            )
    return actionable, suppressed


def _build_audit_summary(files: list[FileAudit], fail_on: Severity) -> AuditSummary:
    scanned = [file for file in files if file.scanned and file.result is not None]
    findings: list[Finding] = []
    for file in scanned:
        if file.result is not None:
            findings.extend(file.result.findings)
    summary = build_summary(findings)
    files_failed = sum(
        1
        for file in scanned
        if file.result is not None and file.result.has_at_least(fail_on)
    ) + sum(1 for file in files if file.error)
    return AuditSummary(
        files_discovered=len(files),
        files_scanned=len(scanned),
        files_failed=files_failed,
        total_findings=sum(len(file.result.findings) for file in scanned if file.result is not None),
        suppressed_findings=sum(len(file.suppressed) for file in files),
        actionable_findings=len(findings),
        risk_score=summary.risk_score,
        max_severity=summary.max_severity,
    )


def _common_root(paths: list[Path]) -> Path:
    if len(paths) == 1:
        return paths[0].parent if paths[0].is_file() else paths[0]
    resolved = [path if path.is_dir() else path.parent for path in paths]
    common = Path(os.path.commonpath([str(path) for path in resolved]))
    return common.resolve()
