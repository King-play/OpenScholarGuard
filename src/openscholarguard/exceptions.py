"""Project-specific exceptions."""

from __future__ import annotations


class OpenScholarGuardError(Exception):
    """Base exception for recoverable OpenScholarGuard failures."""


class UnsupportedDocumentError(OpenScholarGuardError):
    """Raised when a file type cannot be loaded."""


class DependencyMissingError(OpenScholarGuardError):
    """Raised when an optional parser dependency is not installed."""
