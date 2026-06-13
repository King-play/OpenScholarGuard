"""Stable fingerprints for rule-pack payloads."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_rule_pack_json(payload: dict[str, Any]) -> str:
    """Return canonical JSON used for deterministic rule-pack hashes."""

    return json.dumps(
        _drop_expected_fingerprint(payload),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def rule_pack_sha256(payload: dict[str, Any]) -> str:
    """Return a stable SHA-256 digest for a rule-pack payload."""

    canonical = canonical_rule_pack_json(payload)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def declared_rule_pack_sha256(payload: dict[str, Any]) -> str | None:
    """Return an optional SHA-256 digest declared inside a rule pack."""

    value = payload.get("fingerprint", payload.get("sha256"))
    if not isinstance(value, str):
        return None
    return value.removeprefix("sha256:").lower()


def fingerprint_mismatch(payload: dict[str, Any]) -> str | None:
    """Return a mismatch message when a declared fingerprint is stale."""

    declared = declared_rule_pack_sha256(payload)
    if declared is None:
        return None
    actual = rule_pack_sha256(payload)
    if declared != actual:
        return f"declared fingerprint sha256:{declared} does not match computed sha256:{actual}"
    return None


def _drop_expected_fingerprint(payload: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(payload)
    normalized.pop("sha256", None)
    normalized.pop("fingerprint", None)
    return normalized
