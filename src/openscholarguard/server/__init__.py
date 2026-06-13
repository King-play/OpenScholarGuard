"""HTTP service entry points for OpenScholarGuard."""

from __future__ import annotations

from openscholarguard.server.app import create_server, serve

__all__ = ["create_server", "serve"]
