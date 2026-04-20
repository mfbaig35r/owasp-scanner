"""SQLite database layer for findings, scans, and audit trail."""

from __future__ import annotations

import hashlib
import sqlite3
import threading
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from owasp_scanner.core.config import get_settings

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id              TEXT PRIMARY KEY,
    scan_id         TEXT,
    file_path       TEXT NOT NULL,
    line_number     INTEGER,
    rule_id         TEXT,                -- rule that triggered this finding (e.g. A05-001)
    fingerprint     TEXT UNIQUE,         -- SHA-256(file_path + line_number + rule_id) for dedup
    category_type   TEXT NOT NULL DEFAULT 'security',  -- 'security' or 'test_quality'
    owasp_category  TEXT NOT NULL,       -- A01..A10 or TQ01..TQ10
    severity        TEXT NOT NULL,       -- critical, high, medium, low
    title           TEXT NOT NULL,
    description     TEXT NOT NULL,
    code_snippet    TEXT,
    suggested_fix   TEXT,
    status          TEXT NOT NULL DEFAULT 'open',  -- open, in_progress, fixed, accepted, false_positive
    found_at        TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    fixed_at        TEXT,
    fix_commit_sha  TEXT,
    confidence      REAL,                -- 0.0-1.0 for LLM findings, NULL for regex
    notes           TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS scans (
    id              TEXT PRIMARY KEY,
    scope           TEXT NOT NULL,       -- file, directory, repo
    target_path     TEXT NOT NULL,
    started_at      TEXT NOT NULL,
    completed_at    TEXT,
    findings_count  INTEGER DEFAULT 0,
    categories      TEXT,               -- JSON array of categories scanned
    status          TEXT NOT NULL DEFAULT 'running'  -- running, completed, failed
);

CREATE TABLE IF NOT EXISTS audit_log (
    id              TEXT PRIMARY KEY,
    finding_id      TEXT NOT NULL,
    action          TEXT NOT NULL,       -- created, status_changed, note_added, verified, fix_suggested
    old_value       TEXT,
    new_value       TEXT,
    timestamp       TEXT NOT NULL,
    FOREIGN KEY (finding_id) REFERENCES findings(id)
);

CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(owasp_category);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_file ON findings(file_path);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_category_type ON findings(category_type);
CREATE INDEX IF NOT EXISTS idx_audit_finding ON audit_log(finding_id);
"""

# Migrations for existing databases
_MIGRATIONS = [
    # Migration 1: Add rule_id and fingerprint columns
    (
        "rule_id",
        [
            "ALTER TABLE findings ADD COLUMN rule_id TEXT",
            "ALTER TABLE findings ADD COLUMN fingerprint TEXT UNIQUE",
        ],
    ),
    # Migration 2: Add confidence column for LLM findings
    (
        "confidence",
        [
            "ALTER TABLE findings ADD COLUMN confidence REAL",
        ],
    ),
    # Migration 3: Add category_type for test quality findings
    (
        "category_type",
        [
            "ALTER TABLE findings ADD COLUMN category_type TEXT NOT NULL DEFAULT 'security'",
        ],
    ),
]

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    id: str
    file_path: str
    owasp_category: str
    severity: str
    title: str
    description: str
    scan_id: str | None = None
    line_number: int | None = None
    rule_id: str | None = None
    fingerprint: str | None = None
    code_snippet: str | None = None
    suggested_fix: str | None = None
    status: str = "open"
    found_at: str = ""
    updated_at: str = ""
    fixed_at: str | None = None
    fix_commit_sha: str | None = None
    confidence: float | None = None
    notes: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "rule_id": self.rule_id,
            "fingerprint": self.fingerprint,
            "owasp_category": self.owasp_category,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "code_snippet": self.code_snippet,
            "suggested_fix": self.suggested_fix,
            "status": self.status,
            "found_at": self.found_at,
            "updated_at": self.updated_at,
            "fixed_at": self.fixed_at,
            "fix_commit_sha": self.fix_commit_sha,
            "confidence": self.confidence,
            "notes": self.notes,
        }


_FINDING_FIELDS = set(Finding.__dataclass_fields__.keys())


def _finding_from_row(row: Any) -> Finding:
    """Create Finding from a DB row, ignoring columns no longer in the dataclass."""
    d = dict(row)
    return Finding(**{k: v for k, v in d.items() if k in _FINDING_FIELDS})


@dataclass
class Scan:
    id: str
    scope: str
    target_path: str
    started_at: str
    completed_at: str | None = None
    findings_count: int = 0
    categories: str | None = None
    status: str = "running"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "scope": self.scope,
            "target_path": self.target_path,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "findings_count": self.findings_count,
            "categories": self.categories,
            "status": self.status,
        }


@dataclass
class AuditEntry:
    id: str
    finding_id: str
    action: str
    timestamp: str
    old_value: str | None = None
    new_value: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "finding_id": self.finding_id,
            "action": self.action,
            "old_value": self.old_value,
            "new_value": self.new_value,
            "timestamp": self.timestamp,
        }


# ---------------------------------------------------------------------------
# Database manager
# ---------------------------------------------------------------------------


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _uuid() -> str:
    return str(uuid.uuid4())


class Database:
    """Thread-safe SQLite database for the scanner."""

    def __init__(self, db_path: Path | None = None) -> None:
        self._db_path = db_path or get_settings().db_path
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
            self._run_migrations(conn)
        # Restrict DB file — it stores code snippets that may contain secrets
        if self._db_path.exists():
            self._db_path.chmod(0o600)

    def _run_migrations(self, conn: sqlite3.Connection) -> None:
        """Apply schema migrations for existing databases."""
        existing_cols = {
            row[1] for row in conn.execute("PRAGMA table_info(findings)").fetchall()
        }
        for check_col, statements in _MIGRATIONS:
            if check_col not in existing_cols:
                for stmt in statements:
                    conn.execute(stmt)

    @contextmanager
    def _connect(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # -- Scans ---------------------------------------------------------------

    def create_scan(self, scope: str, target_path: str, categories: str | None = None) -> Scan:
        scan = Scan(
            id=_uuid(),
            scope=scope,
            target_path=target_path,
            started_at=_now(),
            categories=categories,
        )
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO scans (id, scope, target_path, started_at, categories, status)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (scan.id, scan.scope, scan.target_path, scan.started_at, scan.categories, scan.status),
            )
        return scan

    def complete_scan(self, scan_id: str, findings_count: int, status: str = "completed") -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """UPDATE scans SET completed_at = ?, findings_count = ?, status = ?
                   WHERE id = ?""",
                (_now(), findings_count, status, scan_id),
            )

    def get_scan(self, scan_id: str) -> Scan | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
            if row:
                return Scan(**dict(row))
        return None

    def list_scans(self, limit: int = 20) -> list[Scan]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,)
            ).fetchall()
            return [Scan(**dict(r)) for r in rows]

    # -- Findings ------------------------------------------------------------

    @staticmethod
    def _compute_fingerprint(
        file_path: str, line_number: int | None, rule_id: str | None,
    ) -> str | None:
        """Compute a dedup fingerprint. Returns None if rule_id is missing (manual findings)."""
        if not rule_id:
            return None
        raw = f"{file_path}:{line_number}:{rule_id}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def create_finding(
        self,
        *,
        file_path: str,
        owasp_category: str,
        severity: str,
        title: str,
        description: str,
        scan_id: str | None = None,
        line_number: int | None = None,
        rule_id: str | None = None,
        code_snippet: str | None = None,
        suggested_fix: str | None = None,
        confidence: float | None = None,
    ) -> tuple[Finding, bool]:
        """Create a finding. Returns (finding, is_new).

        If a finding with the same fingerprint already exists:
        - If status is 'open' or 'in_progress': update scan_id and updated_at, return (existing, False)
        - If status is 'fixed'/'accepted'/'false_positive': leave it alone, return (existing, False)
        If no duplicate: insert new row, return (finding, True)
        """
        now = _now()
        fingerprint = self._compute_fingerprint(file_path, line_number, rule_id)

        with self._lock, self._connect() as conn:
            # Check for existing finding with same fingerprint
            if fingerprint:
                row = conn.execute(
                    "SELECT * FROM findings WHERE fingerprint = ?", (fingerprint,)
                ).fetchone()
                if row:
                    existing = _finding_from_row(row)
                    # Update scan linkage and timestamp for open findings
                    if existing.status in ("open", "in_progress"):
                        conn.execute(
                            "UPDATE findings SET scan_id = ?, updated_at = ?, code_snippet = ? WHERE id = ?",
                            (scan_id, now, code_snippet, existing.id),
                        )
                        existing.scan_id = scan_id
                        existing.updated_at = now
                        existing.code_snippet = code_snippet
                    return existing, False

            finding = Finding(
                id=_uuid(),
                scan_id=scan_id,
                file_path=file_path,
                line_number=line_number,
                rule_id=rule_id,
                fingerprint=fingerprint,
                owasp_category=owasp_category,
                severity=severity,
                title=title,
                description=description,
                code_snippet=code_snippet,
                suggested_fix=suggested_fix,
                confidence=confidence,
                found_at=now,
                updated_at=now,
            )
            conn.execute(
                """INSERT INTO findings
                   (id, scan_id, file_path, line_number, rule_id, fingerprint,
                    owasp_category, severity, title, description,
                    code_snippet, suggested_fix, confidence, status, found_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    finding.id, finding.scan_id, finding.file_path, finding.line_number,
                    finding.rule_id, finding.fingerprint,
                    finding.owasp_category, finding.severity, finding.title, finding.description,
                    finding.code_snippet, finding.suggested_fix, finding.confidence, finding.status,
                    finding.found_at, finding.updated_at,
                ),
            )
            conn.execute(
                """INSERT INTO audit_log (id, finding_id, action, new_value, timestamp)
                   VALUES (?, ?, ?, ?, ?)""",
                (_uuid(), finding.id, "created", f"{severity}: {title}", now),
            )
        return finding, True

    def get_finding(self, finding_id: str) -> Finding | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
            if row:
                return _finding_from_row(row)
        return None

    def list_findings(
        self,
        *,
        status: str | None = None,
        severity: str | None = None,
        owasp_category: str | None = None,
        file_path: str | None = None,
        scan_id: str | None = None,
        limit: int = 100,
    ) -> list[Finding]:
        clauses: list[str] = []
        params: list[Any] = []

        if status:
            clauses.append("status = ?")
            params.append(status)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if owasp_category:
            clauses.append("owasp_category = ?")
            params.append(owasp_category)
        if file_path:
            clauses.append("file_path LIKE ?")
            params.append(f"%{file_path}%")
        if scan_id:
            clauses.append("scan_id = ?")
            params.append(scan_id)

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM findings {where} ORDER BY found_at DESC LIMIT ?",
                params,
            ).fetchall()
            return [_finding_from_row(r) for r in rows]

    def update_finding(
        self,
        finding_id: str,
        *,
        status: str | None = None,
        notes: str | None = None,
        fix_commit_sha: str | None = None,
        suggested_fix: str | None = None,
    ) -> Finding | None:
        finding = self.get_finding(finding_id)
        if not finding:
            return None

        now = _now()
        updates: list[str] = ["updated_at = ?"]
        params: list[Any] = [now]
        audit_entries: list[tuple[str, str | None, str | None]] = []

        if status and status != finding.status:
            updates.append("status = ?")
            params.append(status)
            audit_entries.append(("status_changed", finding.status, status))
            if status == "fixed":
                updates.append("fixed_at = ?")
                params.append(now)

        if notes is not None:
            updates.append("notes = ?")
            params.append(notes)
            audit_entries.append(("note_added", None, notes[:200]))

        if fix_commit_sha:
            updates.append("fix_commit_sha = ?")
            params.append(fix_commit_sha)

        if suggested_fix:
            updates.append("suggested_fix = ?")
            params.append(suggested_fix)
            audit_entries.append(("fix_suggested", None, suggested_fix[:200]))

        params.append(finding_id)

        with self._lock, self._connect() as conn:
            conn.execute(
                f"UPDATE findings SET {', '.join(updates)} WHERE id = ?",
                params,
            )
            for action, old_val, new_val in audit_entries:
                conn.execute(
                    """INSERT INTO audit_log (id, finding_id, action, old_value, new_value, timestamp)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (_uuid(), finding_id, action, old_val, new_val, now),
                )

        return self.get_finding(finding_id)

    # -- Audit ---------------------------------------------------------------

    def get_audit_trail(self, finding_id: str) -> list[AuditEntry]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_log WHERE finding_id = ? ORDER BY timestamp ASC",
                (finding_id,),
            ).fetchall()
            return [AuditEntry(**dict(r)) for r in rows]

    def delete_finding(self, finding_id: str) -> None:
        """Permanently delete a finding and its audit trail."""
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM audit_log WHERE finding_id = ?", (finding_id,))
            conn.execute("DELETE FROM findings WHERE id = ?", (finding_id,))

    # -- Summary -------------------------------------------------------------

    def get_summary(self) -> dict[str, Any]:
        with self._connect() as conn:
            # By status
            status_rows = conn.execute(
                "SELECT status, COUNT(*) as count FROM findings GROUP BY status"
            ).fetchall()
            by_status = {r["status"]: r["count"] for r in status_rows}

            # By category
            cat_rows = conn.execute(
                "SELECT owasp_category, COUNT(*) as count FROM findings WHERE status = 'open' GROUP BY owasp_category ORDER BY owasp_category"
            ).fetchall()
            by_category = {r["owasp_category"]: r["count"] for r in cat_rows}

            # By severity (open only)
            sev_rows = conn.execute(
                "SELECT severity, COUNT(*) as count FROM findings WHERE status = 'open' GROUP BY severity"
            ).fetchall()
            by_severity = {r["severity"]: r["count"] for r in sev_rows}

            # Total scans
            scan_count = conn.execute("SELECT COUNT(*) as count FROM scans").fetchone()["count"]

            # Recent scans
            recent = conn.execute(
                "SELECT * FROM scans ORDER BY started_at DESC LIMIT 5"
            ).fetchall()

            return {
                "total_findings": sum(by_status.values()),
                "by_status": by_status,
                "open_by_category": by_category,
                "open_by_severity": by_severity,
                "total_scans": scan_count,
                "recent_scans": [Scan(**dict(r)).to_dict() for r in recent],
            }


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_db: Database | None = None
_db_lock = threading.Lock()


def get_db() -> Database:
    global _db
    with _db_lock:
        if _db is None:
            _db = Database()
        return _db
