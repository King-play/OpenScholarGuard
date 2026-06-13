"""Custom JSON rule-pack support."""

from __future__ import annotations

from openscholarguard.rules.detector import RulePackDetector
from openscholarguard.rules.fingerprint import canonical_rule_pack_json, rule_pack_sha256
from openscholarguard.rules.models import (
    RulePack,
    RulePackRule,
    RulePackTestCase,
    RulePackTestExpectation,
)
from openscholarguard.rules.registry import load_rule_pack, load_rule_packs
from openscholarguard.rules.validation import validate_rule_pack
from openscholarguard.rules.verification import RulePackVerification, verify_rule_pack

__all__ = [
    "RulePack",
    "RulePackDetector",
    "RulePackTestCase",
    "RulePackTestExpectation",
    "RulePackVerification",
    "RulePackRule",
    "canonical_rule_pack_json",
    "load_rule_pack",
    "load_rule_packs",
    "rule_pack_sha256",
    "validate_rule_pack",
    "verify_rule_pack",
]
