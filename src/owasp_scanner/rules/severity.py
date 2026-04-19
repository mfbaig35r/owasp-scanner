"""Context-sensitive severity adjustment based on file path and project context.

Test files get reduced severity (a pickle.loads in a test is low risk).
Migration files get reduced to low.
Local CLI projects (no web/MCP server) get reduced by one level.
"""

from __future__ import annotations

import re
from pathlib import Path

_SEVERITY_ORDER = ["low", "medium", "high", "critical"]

# Patterns that indicate lower-risk contexts
_REDUCE_PATTERNS = [
    re.compile(r"(?:^|/)tests?/", re.IGNORECASE),
    re.compile(r"(?:^|/)test_[^/]+\.py$", re.IGNORECASE),
    re.compile(r"_test\.py$", re.IGNORECASE),
    re.compile(r"(?:^|/)conftest\.py$", re.IGNORECASE),
    re.compile(r"(?:^|/)fixtures?/", re.IGNORECASE),
]

# Patterns that indicate migration files (reduce to low)
_MIGRATION_PATTERNS = [
    re.compile(r"(?:^|/)migrations?/", re.IGNORECASE),
    re.compile(r"(?:^|/)alembic/", re.IGNORECASE),
]

# Imports that indicate a network-facing project
_NETWORK_IMPORT_PATTERNS = [
    re.compile(
        r"^\s*(?:from|import)\s+(?:fastapi|flask|django|aiohttp\.web|tornado\.web|sanic)",
        re.MULTILINE,
    ),
    re.compile(
        r"^\s*(?:from|import)\s+(?:uvicorn|gunicorn|hypercorn|waitress)",
        re.MULTILINE,
    ),
    re.compile(
        r"^\s*(?:from|import)\s+(?:fastmcp|mcp\.server)",
        re.MULTILINE,
    ),
    re.compile(
        r"^\s*(?:from|import)\s+(?:socketserver|http\.server|xmlrpc\.server)",
        re.MULTILINE,
    ),
    re.compile(
        r"^\s*(?:from|import)\s+(?:starlette)",
        re.MULTILINE,
    ),
]

_SKIP_DIRS = {"__pycache__", ".venv", "venv", "node_modules", ".git", ".tox", ".mypy_cache"}


def detect_network_surface(project_root: Path) -> str:
    """Check if a project has network-facing components.

    Scans Python files for imports of web frameworks, MCP servers, and
    ASGI/WSGI servers. Returns early on first match.

    Returns 'local' if no network surface detected, 'network' otherwise.
    """
    for py_file in project_root.rglob("*.py"):
        if any(part in _SKIP_DIRS or part.startswith(".") for part in py_file.parts):
            continue
        try:
            content = py_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for pat in _NETWORK_IMPORT_PATTERNS:
            if pat.search(content):
                return "network"
    return "local"


def _shift_severity(severity: str, delta: int) -> str:
    """Shift severity up (+) or down (-) by delta levels."""
    idx = _SEVERITY_ORDER.index(severity)
    new_idx = max(0, min(len(_SEVERITY_ORDER) - 1, idx + delta))
    return _SEVERITY_ORDER[new_idx]


def adjust_severity(
    base_severity: str,
    file_path: str,
    *,
    project_surface: str | None = None,
) -> str:
    """Adjust finding severity based on file path and project context.

    - Test files: reduce by one level
    - Migration files: reduce to 'low'
    - Local projects (no network surface): reduce by one level
    - Reductions stack (test file in a local project = -2)
    """
    if base_severity not in _SEVERITY_ORDER:
        return base_severity

    severity = base_severity

    # Migrations → always low
    for pat in _MIGRATION_PATTERNS:
        if pat.search(file_path):
            severity = "low"
            break
    else:
        # Test files → reduce by one level
        for pat in _REDUCE_PATTERNS:
            if pat.search(file_path):
                severity = _shift_severity(severity, -1)
                break

    # Local project → reduce by one additional level
    if project_surface == "local":
        severity = _shift_severity(severity, -1)

    return severity
