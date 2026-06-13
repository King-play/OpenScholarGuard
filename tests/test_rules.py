from __future__ import annotations

import json
from pathlib import Path

from openscholarguard.audit.policy import AuditPolicy
from openscholarguard.audit.runner import audit_paths
from openscholarguard.document import load_text_document
from openscholarguard.ingest.models import IngestOptions
from openscholarguard.ingest.pipeline import ingest_path
from openscholarguard.models import Severity
from openscholarguard.rules.fingerprint import fingerprint_mismatch, rule_pack_sha256
from openscholarguard.rules.registry import load_rule_pack
from openscholarguard.rules.validation import validate_rule_pack
from openscholarguard.rules.verification import verify_rule_pack
from openscholarguard.scanner import Scanner, scan_path


def test_validate_rule_pack_accepts_example() -> None:
    payload = json.loads(Path("examples/rule-pack.json").read_text(encoding="utf-8"))

    assert validate_rule_pack(payload) == []


def test_validate_rule_pack_rejects_bad_regex() -> None:
    payload = {
        "name": "bad",
        "version": "0",
        "rules": [
            {
                "id": "bad_regex",
                "title": "Bad regex",
                "severity": "high",
                "patterns": ["("],
            }
        ],
    }

    errors = validate_rule_pack(payload)

    assert any("not valid regex" in error for error in errors)


def test_validate_rule_pack_rejects_null_tests() -> None:
    payload = {
        "name": "bad-tests",
        "version": "0.1.0",
        "rules": [{"id": "x", "title": "X", "severity": "low", "patterns": ["x"]}],
        "tests": None,
    }

    errors = validate_rule_pack(payload)

    assert "tests must be a list" in errors


def test_rule_pack_fingerprint_is_stable() -> None:
    payload = json.loads(Path("examples/rule-pack.json").read_text(encoding="utf-8"))
    reordered = {"version": payload["version"], **payload}

    assert rule_pack_sha256(payload) == rule_pack_sha256(reordered)
    assert len(rule_pack_sha256(payload)) == 64


def test_rule_pack_fingerprint_mismatch_is_reported() -> None:
    payload = json.loads(Path("examples/rule-pack.json").read_text(encoding="utf-8"))
    payload["fingerprint"] = "sha256:" + ("0" * 64)

    assert fingerprint_mismatch(payload) is not None


def test_verify_rule_pack_runs_embedded_tests() -> None:
    rule_pack = load_rule_pack("examples/rule-pack.json")

    verification = verify_rule_pack(rule_pack, require_tests=True)

    assert verification.passed is True
    assert len(verification.tests) == 3
    assert all(test.passed for test in verification.tests)


def test_verify_rule_pack_reports_failed_expectation() -> None:
    payload = {
        "name": "failing",
        "version": "0.1.0",
        "rules": [
            {
                "id": "private_review",
                "title": "Private review reference",
                "severity": "high",
                "patterns": ["private review"],
            }
        ],
        "tests": [
            {
                "name": "missing-match",
                "text": "ordinary text",
                "expected": {"min_findings": 1, "rule_ids": ["private_review"]},
            }
        ],
    }
    rule_pack = load_rule_pack_from_payload(payload)

    verification = verify_rule_pack(rule_pack, require_tests=True)

    assert verification.passed is False
    assert "missing expected rule ids" in verification.tests[0].errors[0]


def test_rule_pack_detector_finds_custom_policy() -> None:
    rule_pack = load_rule_pack("examples/rule-pack.json")
    document = load_text_document("This document references private review notes.", path="paper.md")

    result = Scanner(profile="baseline", rule_packs=[rule_pack]).scan_document(document)

    assert any(finding.detector_id == "rule_pack:local-review-policy" for finding in result.findings)
    assert any(finding.evidence["rule_id"] == "forbid_private_review_request" for finding in result.findings)


def test_scan_path_with_rule_pack(tmp_path: Path) -> None:
    paper = tmp_path / "paper.md"
    paper.write_text("This document promises guaranteed acceptance.", encoding="utf-8")
    rule_pack = load_rule_pack("examples/rule-pack.json")

    result = scan_path(paper, profile="baseline", rule_packs=[rule_pack])

    assert any(finding.evidence.get("rule_id") == "flag_local_acceptance_phrase" for finding in result.findings)


def test_ingest_with_rule_pack_blocks(tmp_path: Path) -> None:
    paper = tmp_path / "paper.md"
    paper.write_text("This document references private review notes.", encoding="utf-8")
    rule_pack = load_rule_pack("examples/rule-pack.json")

    result = ingest_path(
        paper,
        options=IngestOptions(rule_packs=(rule_pack,), block_on=Severity.HIGH),
    )

    assert result.status.value == "blocked"
    assert result.metadata["blocked"] is True


def test_audit_policy_loads_rule_pack(tmp_path: Path) -> None:
    paper = tmp_path / "paper.md"
    paper.write_text("This document references private review notes.", encoding="utf-8")
    policy = AuditPolicy(rule_packs=("examples/rule-pack.json",), fail_on=Severity.HIGH)

    result = audit_paths([tmp_path], policy=policy)

    assert result.summary.files_failed == 1


def load_rule_pack_from_payload(payload: dict[str, object]):
    from openscholarguard.rules.registry import rule_pack_from_dict

    return rule_pack_from_dict(payload)
