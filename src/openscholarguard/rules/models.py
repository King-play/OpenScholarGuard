"""Data models for JSON rule packs."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from openscholarguard.models import Severity


@dataclass(frozen=True)
class RulePackRule:
    """A single custom detector rule."""

    id: str
    title: str
    severity: Severity
    patterns: tuple[str, ...]
    confidence: float = 0.75
    remediation: str = "Review and remove policy-matching content before model ingestion."
    tags: tuple[str, ...] = field(default_factory=tuple)
    case_sensitive: bool = False
    scope: str = "all"


@dataclass(frozen=True)
class RulePackTestExpectation:
    """Expected detector behavior for a rule-pack fixture."""

    rule_ids: Optional[tuple[str, ...]] = None
    min_findings: Optional[int] = None
    max_findings: Optional[int] = None
    min_severity: Optional[Severity] = None


@dataclass(frozen=True)
class RulePackTestCase:
    """A self-contained fixture for rule-pack verification."""

    name: str
    text: str
    expected: RulePackTestExpectation


@dataclass(frozen=True)
class RulePack:
    """A collection of custom rules."""

    name: str
    version: str
    description: str
    rules: tuple[RulePackRule, ...]
    tests: tuple[RulePackTestCase, ...] = field(default_factory=tuple)
    source: str = "<memory>"
    sha256: str = ""

    @property
    def detector_id(self) -> str:
        return f"rule_pack:{self.name}"

    @property
    def fingerprint(self) -> str:
        return f"sha256:{self.sha256}"
