"""Thread-safe error logging to JSONL, following AGI pattern."""

from __future__ import annotations

import json
import threading
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from owasp_scanner.core.config import get_settings

_write_lock = threading.Lock()


@dataclass
class ErrorRecord:
    error_id: str
    timestamp: str
    tool_name: str
    error_type: str
    message: str
    context: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "error_id": self.error_id,
            "timestamp": self.timestamp,
            "tool_name": self.tool_name,
            "error_type": self.error_type,
            "message": self.message,
            "context": self.context,
        }


def log_error(
    tool_name: str,
    exc: Exception,
    context: dict[str, Any] | None = None,
) -> str:
    """Log an error and return its UUID for reference."""
    error_id = str(uuid.uuid4())
    record = ErrorRecord(
        error_id=error_id,
        timestamp=datetime.now(UTC).isoformat(),
        tool_name=tool_name,
        error_type=type(exc).__name__,
        message=str(exc),
        context=context or {},
    )

    errors_log = get_settings().errors_log
    with _write_lock:
        # Rotate if log exceeds 1 MB
        if errors_log.exists() and errors_log.stat().st_size > 1_000_000:
            rotated = errors_log.with_suffix(".jsonl.1")
            errors_log.rename(rotated)
        with open(errors_log, "a", encoding="utf-8") as f:
            f.write(json.dumps(record.to_dict()) + "\n")

    return error_id


def get_errors(
    *,
    error_id: str | None = None,
    tool_name: str | None = None,
    limit: int = 20,
) -> list[dict[str, Any]]:
    """Read errors from the log, newest first."""
    errors_log = get_settings().errors_log
    if not errors_log.exists():
        return []

    results: list[dict[str, Any]] = []
    with open(errors_log, encoding="utf-8") as f:
        lines = f.readlines()

    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue

        if error_id and record.get("error_id") != error_id:
            continue
        if tool_name and record.get("tool_name") != tool_name:
            continue

        results.append(record)
        if len(results) >= limit:
            break

    return results
