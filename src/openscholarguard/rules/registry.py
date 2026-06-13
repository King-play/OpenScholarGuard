"""Rule-pack loading and conversion."""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Union

from openscholarguard.models import Severity
from openscholarguard.rules.fingerprint import rule_pack_sha256
from openscholarguard.rules.models import (
    RulePack,
    RulePackRule,
    RulePackTestCase,
    RulePackTestExpectation,
)
from openscholarguard.rules.validation import validate_rule_pack


def load_rule_pack(path: Union[str, Path]) -> RulePack:
    rule_path = Path(path).expanduser()
    payload = json.loads(rule_path.read_text(encoding="utf-8"))
    errors = validate_rule_pack(payload)
    if errors:
        joined = "; ".join(errors)
        raise ValueError(f"Invalid rule pack '{rule_path}': {joined}")
    return rule_pack_from_dict(payload, source=str(rule_path))


def load_rule_packs(paths: Iterable[Union[str, Path]]) -> list[RulePack]:
    return [load_rule_pack(path) for path in paths]


def rule_pack_from_dict(payload: dict[str, Any], *, source: str = "<memory>") -> RulePack:
    rules = []
    for item in payload["rules"]:
        rules.append(
            RulePackRule(
                id=str(item["id"]),
                title=str(item["title"]),
                severity=Severity(str(item["severity"])),
                patterns=tuple(str(pattern) for pattern in item["patterns"]),
                confidence=float(item.get("confidence", 0.75)),
                remediation=str(
                    item.get(
                        "remediation",
                        "Review and remove policy-matching content before model ingestion.",
                    )
                ),
                tags=tuple(str(tag) for tag in item.get("tags", [])),
                case_sensitive=bool(item.get("case_sensitive", False)),
                scope=str(item.get("scope", "all")),
            )
        )
    tests = []
    for item in payload.get("tests", []):
        expected = item["expected"]
        tests.append(
            RulePackTestCase(
                name=str(item["name"]),
                text=str(item.get("text", "")),
                expected=RulePackTestExpectation(
                    rule_ids=_optional_str_tuple(expected.get("rule_ids")),
                    min_findings=_optional_int(expected.get("min_findings")),
                    max_findings=_optional_int(expected.get("max_findings")),
                    min_severity=(
                        Severity(str(expected["min_severity"]))
                        if expected.get("min_severity") is not None
                        else None
                    ),
                ),
            )
        )
    return RulePack(
        name=str(payload["name"]),
        version=str(payload["version"]),
        description=str(payload.get("description", "")),
        rules=tuple(rules),
        tests=tuple(tests),
        source=source,
        sha256=rule_pack_sha256(payload),
    )


def _optional_str_tuple(value: object) -> tuple[str, ...] | None:
    if value is None:
        return None
    if not isinstance(value, list):
        raise ValueError("rule_ids must be a list")
    return tuple(str(item) for item in value)


def _optional_int(value: object) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int):
        raise ValueError("finding expectation must be an integer")
    return value
