from __future__ import annotations

import json

from openscholarguard.cli import main
from openscholarguard.doctor import render_doctor_text, run_doctor


def test_run_doctor_reports_core_checks() -> None:
    report = run_doctor()
    names = {check.name for check in report.checks}

    assert report.status == "ok"
    assert {"python", "package", "pdf", "sample-scan", "rule-pack"} <= names


def test_run_doctor_can_verify_demo() -> None:
    report = run_doctor(include_demo=True)

    assert report.status == "ok"
    assert any(check.name == "demo" and check.status == "ok" for check in report.checks)


def test_render_doctor_text() -> None:
    report = run_doctor()

    rendered = render_doctor_text(report)

    assert "OpenScholarGuard doctor: ok" in rendered
    assert "[OK] python" in rendered


def test_cli_doctor_json(capsys) -> None:  # type: ignore[no-untyped-def]
    exit_code = main(["doctor", "--format", "json"])
    captured = capsys.readouterr()

    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload["status"] == "ok"
    assert payload["checks"]
