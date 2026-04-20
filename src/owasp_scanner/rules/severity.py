"""Context-sensitive severity adjustment based on file path and project context.

Test files get reduced severity (a pickle.loads in a test is low risk).
Migration files get reduced to low.
Local CLI projects (no web/MCP server) get reduced by one level.
"""

from __future__ import annotations

import re

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
