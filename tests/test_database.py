"""Tests for the SQLite database layer."""

from __future__ import annotations

from owasp_scanner.core.database import Database


class TestScans:
    def test_create_scan(self, tmp_db: Database):
        scan = tmp_db.create_scan("directory", "/test/repo")
        assert scan.id
        assert scan.scope == "directory"
        assert scan.target_path == "/test/repo"
        assert scan.status == "running"
        assert scan.started_at

    def test_complete_scan(self, tmp_db: Database):
        scan = tmp_db.create_scan("file", "/test/file.py")
        tmp_db.complete_scan(scan.id, findings_count=5)
        updated = tmp_db.get_scan(scan.id)
        assert updated.status == "completed"
        assert updated.findings_count == 5
        assert updated.completed_at

    def test_list_scans(self, tmp_db: Database):
        tmp_db.create_scan("file", "/a.py")
        tmp_db.create_scan("directory", "/b/")
        tmp_db.create_scan("file", "/c.py")
        scans = tmp_db.list_scans(limit=2)
        assert len(scans) == 2

    def test_get_scan_not_found(self, tmp_db: Database):
        assert tmp_db.get_scan("nonexistent") is None


class TestFindings:
    def _make_finding(self, db: Database, **overrides):
        defaults = {
            "file_path": "/app/views.py",
            "owasp_category": "A05",
            "severity": "critical",
            "title": "SQL injection",
            "description": "Bad query",
        }
        defaults.update(overrides)
        finding, _is_new = db.create_finding(**defaults)
        return finding

    def test_create_finding(self, tmp_db: Database):
        f = self._make_finding(tmp_db)
        assert f.id
        assert f.status == "open"
        assert f.found_at
        assert f.updated_at

    def test_create_finding_returns_is_new(self, tmp_db: Database):
        finding, is_new = tmp_db.create_finding(
            file_path="/app.py", owasp_category="A05",
            severity="high", title="Test", description="D",
        )
        assert is_new is True

    def test_get_finding(self, tmp_db: Database):
        f = self._make_finding(tmp_db)
        retrieved = tmp_db.get_finding(f.id)
        assert retrieved.title == "SQL injection"
        assert retrieved.owasp_category == "A05"

    def test_get_finding_not_found(self, tmp_db: Database):
        assert tmp_db.get_finding("nonexistent") is None

    def test_list_findings_no_filter(self, tmp_db: Database):
        self._make_finding(tmp_db, title="Finding 1")
        self._make_finding(tmp_db, title="Finding 2")
        findings = tmp_db.list_findings()
        assert len(findings) == 2

    def test_list_findings_filter_status(self, tmp_db: Database):
        f1 = self._make_finding(tmp_db)
        self._make_finding(tmp_db)
        tmp_db.update_finding(f1.id, status="fixed")
        open_findings = tmp_db.list_findings(status="open")
        assert len(open_findings) == 1
        fixed_findings = tmp_db.list_findings(status="fixed")
        assert len(fixed_findings) == 1

    def test_list_findings_filter_severity(self, tmp_db: Database):
        self._make_finding(tmp_db, severity="critical")
        self._make_finding(tmp_db, severity="low")
        critical = tmp_db.list_findings(severity="critical")
        assert len(critical) == 1

    def test_list_findings_filter_category(self, tmp_db: Database):
        self._make_finding(tmp_db, owasp_category="A01")
        self._make_finding(tmp_db, owasp_category="A05")
        a05 = tmp_db.list_findings(owasp_category="A05")
        assert len(a05) == 1

    def test_list_findings_filter_file_path(self, tmp_db: Database):
        self._make_finding(tmp_db, file_path="/app/views.py")
        self._make_finding(tmp_db, file_path="/app/models.py")
        views = tmp_db.list_findings(file_path="views")
        assert len(views) == 1

    def test_list_findings_filter_scan_id(self, tmp_db: Database):
        scan = tmp_db.create_scan("file", "/test.py")
        self._make_finding(tmp_db, scan_id=scan.id)
        self._make_finding(tmp_db)
        scan_findings = tmp_db.list_findings(scan_id=scan.id)
        assert len(scan_findings) == 1

    def test_list_findings_limit(self, tmp_db: Database):
        for i in range(10):
            self._make_finding(tmp_db, title=f"Finding {i}")
        findings = tmp_db.list_findings(limit=3)
        assert len(findings) == 3


class TestFindingUpdates:
    def _make_finding(self, db: Database):
        finding, _ = db.create_finding(
            file_path="/app/views.py",
            owasp_category="A05",
            severity="critical",
            title="SQL injection",
            description="Bad query",
        )
        return finding

    def test_update_status(self, tmp_db: Database):
        f = self._make_finding(tmp_db)
        updated = tmp_db.update_finding(f.id, status="in_progress")
        assert updated.status == "in_progress"

    def test_update_status_to_fixed_sets_fixed_at(self, tmp_db: Database):
        f = self._make_finding(tmp_db)
        updated = tmp_db.update_finding(f.id, status="fixed")
        assert updated.status == "fixed"
        assert updated.fixed_at is not None

    def test_update_notes(self, tmp_db: Database):
        f = self._make_finding(tmp_db)
        updated = tmp_db.update_finding(f.id, notes="False positive — test code")
        assert updated.notes == "False positive — test code"

    def test_update_fix_commit(self, tmp_db: Database):
        f = self._make_finding(tmp_db)
        updated = tmp_db.update_finding(f.id, fix_commit_sha="abc123")
        assert updated.fix_commit_sha == "abc123"

    def test_update_nonexistent(self, tmp_db: Database):
        assert tmp_db.update_finding("nonexistent", status="fixed") is None

    def test_update_same_status_no_audit(self, tmp_db: Database):
        f = self._make_finding(tmp_db)
        tmp_db.update_finding(f.id, status="open")  # Same as current
        audit = tmp_db.get_audit_trail(f.id)
        # Should only have the "created" entry, not a status_changed
        assert len(audit) == 1
        assert audit[0].action == "created"


class TestDeduplication:
    def test_same_fingerprint_returns_existing(self, tmp_db: Database):
        f1, is_new1 = tmp_db.create_finding(
            file_path="/app.py", line_number=10, rule_id="A05-001",
            owasp_category="A05", severity="critical",
            title="SQLi", description="D",
        )
        f2, is_new2 = tmp_db.create_finding(
            file_path="/app.py", line_number=10, rule_id="A05-001",
            owasp_category="A05", severity="critical",
            title="SQLi", description="D",
        )
        assert is_new1 is True
        assert is_new2 is False
        assert f1.id == f2.id
        # Should only be 1 finding in DB
        assert len(tmp_db.list_findings()) == 1

    def test_different_rule_id_creates_new(self, tmp_db: Database):
        tmp_db.create_finding(
            file_path="/app.py", line_number=10, rule_id="A05-001",
            owasp_category="A05", severity="critical",
            title="SQLi", description="D",
        )
        _, is_new = tmp_db.create_finding(
            file_path="/app.py", line_number=10, rule_id="A05-002",
            owasp_category="A05", severity="critical",
            title="SQL concat", description="D",
        )
        assert is_new is True
        assert len(tmp_db.list_findings()) == 2

    def test_different_line_creates_new(self, tmp_db: Database):
        tmp_db.create_finding(
            file_path="/app.py", line_number=10, rule_id="A05-001",
            owasp_category="A05", severity="critical",
            title="SQLi", description="D",
        )
        _, is_new = tmp_db.create_finding(
            file_path="/app.py", line_number=20, rule_id="A05-001",
            owasp_category="A05", severity="critical",
            title="SQLi", description="D",
        )
        assert is_new is True

    def test_fixed_finding_not_reopened(self, tmp_db: Database):
        f1, _ = tmp_db.create_finding(
            file_path="/app.py", line_number=10, rule_id="A05-001",
            owasp_category="A05", severity="critical",
            title="SQLi", description="D",
        )
        tmp_db.update_finding(f1.id, status="fixed")
        f2, is_new = tmp_db.create_finding(
            file_path="/app.py", line_number=10, rule_id="A05-001",
            owasp_category="A05", severity="critical",
            title="SQLi", description="D",
        )
        assert is_new is False
        assert f2.status == "fixed"  # Stays fixed

    def test_manual_finding_no_fingerprint(self, tmp_db: Database):
        """Manual findings (no rule_id) always create new rows."""
        f1, _ = tmp_db.create_finding(
            file_path="/app.py", owasp_category="A01",
            severity="high", title="Manual 1", description="D",
        )
        f2, is_new = tmp_db.create_finding(
            file_path="/app.py", owasp_category="A01",
            severity="high", title="Manual 2", description="D",
        )
        assert is_new is True
        assert f1.id != f2.id

    def test_dedup_updates_scan_id(self, tmp_db: Database):
        scan1 = tmp_db.create_scan("file", "/app.py")
        scan2 = tmp_db.create_scan("file", "/app.py")
        f1, _ = tmp_db.create_finding(
            scan_id=scan1.id, file_path="/app.py", line_number=10,
            rule_id="A05-001", owasp_category="A05",
            severity="critical", title="SQLi", description="D",
        )
        f2, _ = tmp_db.create_finding(
            scan_id=scan2.id, file_path="/app.py", line_number=10,
            rule_id="A05-001", owasp_category="A05",
            severity="critical", title="SQLi", description="D",
        )
        # Existing finding should now link to scan2
        refreshed = tmp_db.get_finding(f1.id)
        assert refreshed.scan_id == scan2.id


class TestAuditTrail:
    def test_create_finding_creates_audit_entry(self, tmp_db: Database):
        f, _ = tmp_db.create_finding(
            file_path="/app.py", owasp_category="A01",
            severity="high", title="Test", description="Desc",
        )
        audit = tmp_db.get_audit_trail(f.id)
        assert len(audit) == 1
        assert audit[0].action == "created"

    def test_status_change_creates_audit_entry(self, tmp_db: Database):
        f, _ = tmp_db.create_finding(
            file_path="/app.py", owasp_category="A01",
            severity="high", title="Test", description="Desc",
        )
        tmp_db.update_finding(f.id, status="fixed")
        audit = tmp_db.get_audit_trail(f.id)
        assert len(audit) == 2
        assert audit[1].action == "status_changed"
        assert audit[1].old_value == "open"
        assert audit[1].new_value == "fixed"

    def test_note_creates_audit_entry(self, tmp_db: Database):
        f, _ = tmp_db.create_finding(
            file_path="/app.py", owasp_category="A01",
            severity="high", title="Test", description="Desc",
        )
        tmp_db.update_finding(f.id, notes="Investigated, real issue")
        audit = tmp_db.get_audit_trail(f.id)
        assert any(a.action == "note_added" for a in audit)

    def test_full_lifecycle_audit(self, tmp_db: Database):
        f, _ = tmp_db.create_finding(
            file_path="/app.py", owasp_category="A05",
            severity="critical", title="SQLi", description="Desc",
        )
        tmp_db.update_finding(f.id, status="in_progress", notes="Working on fix")
        tmp_db.update_finding(f.id, status="fixed", fix_commit_sha="abc123")
        audit = tmp_db.get_audit_trail(f.id)
        actions = [a.action for a in audit]
        assert "created" in actions
        assert "status_changed" in actions
        assert "note_added" in actions


class TestSummary:
    def test_empty_summary(self, tmp_db: Database):
        summary = tmp_db.get_summary()
        assert summary["total_findings"] == 0
        assert summary["total_scans"] == 0

    def test_summary_counts(self, tmp_db: Database):
        tmp_db.create_finding(
            file_path="/a.py", owasp_category="A05",
            severity="critical", title="T1", description="D",
        )
        tmp_db.create_finding(
            file_path="/b.py", owasp_category="A02",
            severity="medium", title="T2", description="D",
        )
        tmp_db.create_scan("directory", "/repo")

        summary = tmp_db.get_summary()
        assert summary["total_findings"] == 2
        assert summary["total_scans"] == 1
        assert summary["by_status"]["open"] == 2
        assert summary["open_by_category"]["A05"] == 1
        assert summary["open_by_category"]["A02"] == 1
        assert summary["open_by_severity"]["critical"] == 1
        assert summary["open_by_severity"]["medium"] == 1


class TestToDict:
    def test_finding_to_dict(self, tmp_db: Database):
        f, _ = tmp_db.create_finding(
            file_path="/app.py", owasp_category="A01",
            severity="high", title="Test", description="Desc",
        )
        d = f.to_dict()
        assert d["id"] == f.id
        assert d["file_path"] == "/app.py"
        assert d["owasp_category"] == "A01"
        assert d["severity"] == "high"
        assert d["status"] == "open"
        assert "found_at" in d
        assert "updated_at" in d

    def test_scan_to_dict(self, tmp_db: Database):
        s = tmp_db.create_scan("directory", "/repo")
        d = s.to_dict()
        assert d["scope"] == "directory"
        assert d["target_path"] == "/repo"
        assert d["status"] == "running"
