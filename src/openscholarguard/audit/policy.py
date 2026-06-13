"""Audit policy loading, path filtering, and finding suppression."""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Union

from openscholarguard.document import SUPPORTED_PDF_SUFFIXES, SUPPORTED_TEXT_SUFFIXES
from openscholarguard.models import Finding, Severity

DEFAULT_INCLUDE_PATTERNS = (
    "**/*.pdf",
    "**/*.txt",
    "**/*.md",
    "**/*.markdown",
    "**/*.tex",
    "**/*.html",
    "**/*.htm",
    "**/*.xml",
    "**/*.json",
    "**/*.csv",
)

DEFAULT_EXCLUDE_PATTERNS = (
    "**/.git/**",
    "**/.pytest_cache/**",
    "**/.ruff_cache/**",
    "**/.mypy_cache/**",
    "**/__pycache__/**",
    "**/dist/**",
    "**/build/**",
    "**/*.egg-info/**",
    "**/.openscholarguard.json",
    "**/openscholarguard-policy.json",
)

SUPPORTED_SUFFIXES = SUPPORTED_TEXT_SUFFIXES | SUPPORTED_PDF_SUFFIXES


@dataclass(frozen=True)
class SuppressionRule:
    """A policy rule that suppresses known accepted findings."""

    detector_id: Optional[str] = None
    path: Optional[str] = None
    finding_id: Optional[str] = None
    reason: str = ""

    def matches(self, finding: Finding, root: Path) -> bool:
        if self.finding_id and self.finding_id != finding.id:
            return False
        if self.detector_id and self.detector_id != finding.detector_id:
            return False
        if self.path:
            relative = _relative_posix(Path(finding.location.path), root)
            if not _matches_pattern(relative, self.path):
                return False
        return True


@dataclass(frozen=True)
class AuditPolicy:
    """Configuration for batch scans and CI gates."""

    profile: str = "ai-review"
    fail_on: Severity = Severity.HIGH
    include: tuple[str, ...] = DEFAULT_INCLUDE_PATTERNS
    exclude: tuple[str, ...] = DEFAULT_EXCLUDE_PATTERNS
    suppressions: tuple[SuppressionRule, ...] = field(default_factory=tuple)
    max_file_bytes: int = 25 * 1024 * 1024
    rule_packs: tuple[str, ...] = field(default_factory=tuple)

    def should_include(self, path: Path, root: Path) -> bool:
        if not path.is_file():
            return False
        if path.suffix.lower() not in SUPPORTED_SUFFIXES:
            return False
        relative = _relative_posix(path, root)
        return any(_matches_pattern(relative, pattern) for pattern in self.include) and not any(
            _matches_pattern(relative, pattern) for pattern in self.exclude
        )

    def is_suppressed(self, finding: Finding, root: Path) -> Optional[SuppressionRule]:
        for rule in self.suppressions:
            if rule.matches(finding, root):
                return rule
        return None


def load_policy(path: Optional[Union[str, Path]] = None) -> AuditPolicy:
    """Load an audit policy from JSON, or return the default policy."""

    if path is None:
        return AuditPolicy()
    policy_path = Path(path).expanduser()
    payload = json.loads(policy_path.read_text(encoding="utf-8"))
    return policy_from_dict(payload)


def policy_from_dict(payload: dict[str, Any]) -> AuditPolicy:
    suppressions = tuple(
        SuppressionRule(
            detector_id=item.get("detector_id"),
            path=item.get("path"),
            finding_id=item.get("finding_id"),
            reason=item.get("reason", ""),
        )
        for item in payload.get("suppressions", [])
    )
    return AuditPolicy(
        profile=payload.get("profile", "ai-review"),
        fail_on=Severity(payload.get("fail_on", "high")),
        include=tuple(payload.get("include", DEFAULT_INCLUDE_PATTERNS)),
        exclude=tuple(payload.get("exclude", DEFAULT_EXCLUDE_PATTERNS)),
        suppressions=suppressions,
        max_file_bytes=int(payload.get("max_file_bytes", 25 * 1024 * 1024)),
        rule_packs=tuple(payload.get("rule_packs", [])),
    )


def write_default_policy(path: Union[str, Path]) -> Path:
    output = Path(path).expanduser()
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "profile": "ai-review",
        "fail_on": "high",
        "include": list(DEFAULT_INCLUDE_PATTERNS),
        "exclude": list(DEFAULT_EXCLUDE_PATTERNS),
        "max_file_bytes": 25 * 1024 * 1024,
        "rule_packs": [],
        "suppressions": [
            {
                "detector_id": "suspicious_density",
                "path": "docs/**",
                "reason": "Accepted low-confidence documentation noise.",
            }
        ],
    }
    output.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return output


def _matches_pattern(relative_path: str, pattern: str) -> bool:
    normalized = pattern.replace("\\", "/")
    return fnmatch.fnmatch(relative_path, normalized) or fnmatch.fnmatch(f"/{relative_path}", normalized)


def _relative_posix(path: Path, root: Path) -> str:
    try:
        relative = path.resolve().relative_to(root.resolve())
    except ValueError:
        relative = path
    return relative.as_posix()
