"""Validation helpers for rule-pack payloads."""

from __future__ import annotations

import re
from typing import Any

from openscholarguard.models import Severity

MAX_RULES = 200
MAX_PATTERNS_PER_RULE = 20
MAX_PATTERN_LENGTH = 1000
VALID_SCOPES = {"all", "text", "metadata"}


def validate_rule_pack(payload: dict[str, Any]) -> list[str]:
    """Return validation errors for a raw rule-pack payload."""

    errors: list[str] = []
    if not isinstance(payload.get("name"), str) or not payload.get("name"):
        errors.append("name must be a non-empty string")
    if not isinstance(payload.get("version"), str) or not payload.get("version"):
        errors.append("version must be a non-empty string")
    fingerprint = payload.get("fingerprint", payload.get("sha256"))
    if fingerprint is not None:
        _validate_fingerprint(fingerprint, errors)

    rules = payload.get("rules")
    if not isinstance(rules, list) or not rules:
        errors.append("rules must be a non-empty list")
    else:
        if len(rules) > MAX_RULES:
            errors.append(f"rules must contain at most {MAX_RULES} entries")
        _validate_rules(rules, errors)

    if "tests" in payload:
        _validate_tests(payload["tests"], errors)
    return errors


def _validate_fingerprint(value: object, errors: list[str]) -> None:
    if not isinstance(value, str):
        errors.append("fingerprint must be a string")
        return
    digest = value.removeprefix("sha256:")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
        errors.append("fingerprint must be a SHA-256 hex digest")


def _validate_rules(rules: list[object], errors: list[str]) -> None:
    seen_ids: set[str] = set()
    for index, rule in enumerate(rules):
        prefix = f"rules[{index}]"
        if not isinstance(rule, dict):
            errors.append(f"{prefix} must be an object")
            continue
        rule_id = rule.get("id")
        if not isinstance(rule_id, str) or not rule_id:
            errors.append(f"{prefix}.id must be a non-empty string")
        elif rule_id in seen_ids:
            errors.append(f"{prefix}.id duplicates rule id '{rule_id}'")
        else:
            seen_ids.add(rule_id)
        if not isinstance(rule.get("title"), str) or not rule.get("title"):
            errors.append(f"{prefix}.title must be a non-empty string")
        try:
            Severity(str(rule.get("severity", "")))
        except ValueError:
            errors.append(f"{prefix}.severity must be one of info, low, medium, high, critical")
        _validate_patterns(rule.get("patterns"), prefix, errors)
        confidence = rule.get("confidence", 0.75)
        if not isinstance(confidence, (int, float)) or not 0 <= float(confidence) <= 1:
            errors.append(f"{prefix}.confidence must be a number between 0 and 1")
        scope = rule.get("scope", "all")
        if scope not in VALID_SCOPES:
            errors.append(f"{prefix}.scope must be one of all, text, metadata")


def _validate_patterns(patterns: object, prefix: str, errors: list[str]) -> None:
    if not isinstance(patterns, list) or not patterns:
        errors.append(f"{prefix}.patterns must be a non-empty list")
        return
    if len(patterns) > MAX_PATTERNS_PER_RULE:
        errors.append(f"{prefix}.patterns must contain at most {MAX_PATTERNS_PER_RULE} entries")
    for pattern_index, pattern in enumerate(patterns):
        if not isinstance(pattern, str) or not pattern:
            errors.append(f"{prefix}.patterns[{pattern_index}] must be a non-empty string")
            continue
        if len(pattern) > MAX_PATTERN_LENGTH:
            errors.append(f"{prefix}.patterns[{pattern_index}] exceeds {MAX_PATTERN_LENGTH} characters")
            continue
        try:
            re.compile(pattern)
        except re.error as exc:
            errors.append(f"{prefix}.patterns[{pattern_index}] is not valid regex: {exc}")


def _validate_tests(tests: object, errors: list[str]) -> None:
    if not isinstance(tests, list):
        errors.append("tests must be a list")
        return
    for index, test in enumerate(tests):
        prefix = f"tests[{index}]"
        if not isinstance(test, dict):
            errors.append(f"{prefix} must be an object")
            continue
        if not isinstance(test.get("name"), str) or not test.get("name"):
            errors.append(f"{prefix}.name must be a non-empty string")
        if not isinstance(test.get("text"), str):
            errors.append(f"{prefix}.text must be a string")
        expected = test.get("expected")
        if not isinstance(expected, dict):
            errors.append(f"{prefix}.expected must be an object")
            continue
        rule_ids = expected.get("rule_ids")
        if rule_ids is not None and (
            not isinstance(rule_ids, list) or not all(isinstance(rule_id, str) for rule_id in rule_ids)
        ):
            errors.append(f"{prefix}.expected.rule_ids must be a list of strings")
        for field in ("min_findings", "max_findings"):
            value = expected.get(field)
            if value is not None and (not isinstance(value, int) or value < 0):
                errors.append(f"{prefix}.expected.{field} must be a non-negative integer")
        min_severity = expected.get("min_severity")
        if min_severity is not None:
            try:
                Severity(str(min_severity))
            except ValueError:
                errors.append(f"{prefix}.expected.min_severity must be one of info, low, medium, high, critical")
