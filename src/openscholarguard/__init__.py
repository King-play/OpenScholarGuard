"""OpenScholarGuard public package interface."""

from __future__ import annotations

from openscholarguard.client import OpenScholarGuardClient, OpenScholarGuardClientError
from openscholarguard.llm import LLMAuditConfig, LLMAuditResult, LLMAuditVerdict, run_llm_audit
from openscholarguard.models import Finding, ScanResult, Severity
from openscholarguard.scanner import Scanner, scan_path

__all__ = [
    "Finding",
    "LLMAuditConfig",
    "LLMAuditResult",
    "LLMAuditVerdict",
    "OpenScholarGuardClient",
    "OpenScholarGuardClientError",
    "ScanResult",
    "Scanner",
    "Severity",
    "run_llm_audit",
    "scan_path",
]

__version__ = "0.1.0"
