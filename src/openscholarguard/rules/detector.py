"""Detector implementation for custom rule packs."""

from __future__ import annotations

import re

from openscholarguard.detectors import Detector, DetectorContext
from openscholarguard.document import Document, TextChunk
from openscholarguard.models import Finding
from openscholarguard.rules.models import RulePack, RulePackRule


class RulePackDetector(Detector):
    """Run JSON rule-pack regexes as first-class detector findings."""

    def __init__(self, rule_pack: RulePack) -> None:
        self.rule_pack = rule_pack
        self.id = rule_pack.detector_id
        self.title = f"Rule pack: {rule_pack.name}"
        self._compiled = {
            rule.id: [
                re.compile(pattern, 0 if rule.case_sensitive else re.I)
                for pattern in rule.patterns
            ]
            for rule in rule_pack.rules
        }

    def detect(self, document: Document, context: DetectorContext) -> list[Finding]:
        findings: list[Finding] = []
        for chunk in document.chunks:
            for rule in self.rule_pack.rules:
                if not _scope_matches(rule, chunk):
                    continue
                for pattern in self._compiled[rule.id]:
                    match = pattern.search(chunk.text)
                    if match is None:
                        continue
                    findings.append(
                        self.finding(
                            title=rule.title,
                            severity=rule.severity,
                            confidence=rule.confidence,
                            location=chunk.location,
                            text=chunk.text[max(0, match.start() - 120) : match.end() + 120],
                            evidence={
                                "rule_pack": self.rule_pack.name,
                                "rule_pack_version": self.rule_pack.version,
                                "rule_id": rule.id,
                                "rule_source": self.rule_pack.source,
                                "pattern": pattern.pattern,
                                "chunk_kind": chunk.kind,
                            },
                            remediation=rule.remediation,
                            tags=["custom-rule", *rule.tags],
                        )
                    )
                    break
        return findings


def _scope_matches(rule: RulePackRule, chunk: TextChunk) -> bool:
    if rule.scope == "all":
        return True
    if rule.scope == "metadata":
        return chunk.kind == "metadata"
    return chunk.kind != "metadata"
