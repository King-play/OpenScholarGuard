"""Environment and project health checks."""

from __future__ import annotations

import importlib.util
import json
import platform
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from openscholarguard import __version__
from openscholarguard.demo import generate_demo
from openscholarguard.rules.registry import load_rule_pack
from openscholarguard.rules.verification import verify_rule_pack
from openscholarguard.scanner import scan_path


@dataclass(frozen=True)
class DoctorCheck:
    """One health-check result."""

    name: str
    status: str
    message: str
    details: dict[str, Any]


@dataclass(frozen=True)
class DoctorReport:
    """Complete health-check report."""

    status: str
    version: str
    checks: list[DoctorCheck]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)


def run_doctor(*, include_demo: bool = False) -> DoctorReport:
    """Run local OpenScholarGuard health checks."""

    checks = [
        _python_version_check(),
        _package_import_check(),
        _pdf_dependency_check(),
        _sample_scan_check(),
        _rule_pack_check(),
    ]
    if include_demo:
        checks.append(_demo_generation_check())
    status = "ok" if all(check.status in {"ok", "warning"} for check in checks) else "error"
    return DoctorReport(status=status, version=__version__, checks=checks)


def render_doctor_text(report: DoctorReport) -> str:
    """Render a readable doctor report."""

    lines = [
        f"OpenScholarGuard doctor: {report.status}",
        f"Version: {report.version}",
        "",
    ]
    for check in report.checks:
        lines.append(f"[{check.status.upper()}] {check.name}: {check.message}")
        for key, value in check.details.items():
            lines.append(f"  {key}: {value}")
    return "\n".join(lines).rstrip() + "\n"


def _python_version_check() -> DoctorCheck:
    version = platform.python_version()
    minimum = (3, 9)
    status = "ok" if sys.version_info >= minimum else "error"
    return DoctorCheck(
        name="python",
        status=status,
        message="Python version is supported." if status == "ok" else "Python 3.9 or newer is required.",
        details={"version": version, "implementation": platform.python_implementation()},
    )


def _package_import_check() -> DoctorCheck:
    return DoctorCheck(
        name="package",
        status="ok",
        message="OpenScholarGuard imports successfully.",
        details={"version": __version__},
    )


def _pdf_dependency_check() -> DoctorCheck:
    available = importlib.util.find_spec("fitz") is not None
    return DoctorCheck(
        name="pdf",
        status="ok" if available else "warning",
        message="PyMuPDF is installed." if available else "PDF support is optional; install with .[pdf].",
        details={"pymupdf_available": available},
    )


def _sample_scan_check() -> DoctorCheck:
    try:
        result = scan_path("examples/injected_paper.md")
    except Exception as exc:
        return DoctorCheck(
            name="sample-scan",
            status="error",
            message=str(exc),
            details={},
        )
    return DoctorCheck(
        name="sample-scan",
        status="ok" if result.summary.total_findings > 0 else "warning",
        message="Synthetic injected sample scans successfully.",
        details={
            "findings": result.summary.total_findings,
            "max_severity": result.summary.max_severity.value,
            "risk_score": result.summary.risk_score,
        },
    )


def _rule_pack_check() -> DoctorCheck:
    try:
        rule_pack = load_rule_pack("examples/rule-pack.json")
        verification = verify_rule_pack(rule_pack, require_tests=True)
    except Exception as exc:
        return DoctorCheck(
            name="rule-pack",
            status="error",
            message=str(exc),
            details={},
        )
    return DoctorCheck(
        name="rule-pack",
        status="ok" if verification.passed else "error",
        message="Example rule pack verifies successfully." if verification.passed else "Example rule pack failed verification.",
        details={
            "fingerprint": verification.fingerprint,
            "tests": len(verification.tests),
        },
    )


def _demo_generation_check() -> DoctorCheck:
    try:
        with tempfile.TemporaryDirectory(prefix="openscholarguard-demo-") as tmp:
            artifacts = generate_demo(Path(tmp) / "demo")
            exists = artifacts.index_html.exists()
    except Exception as exc:
        return DoctorCheck(
            name="demo",
            status="error",
            message=str(exc),
            details={},
        )
    return DoctorCheck(
        name="demo",
        status="ok" if exists else "error",
        message="Static demo generation works.",
        details={"index_html": exists},
    )
