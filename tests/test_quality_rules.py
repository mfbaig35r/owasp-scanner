"""Tests for test quality regex rules — positive + negative match."""

from __future__ import annotations

from owasp_scanner.core.scanner import scan_file_content
from owasp_scanner.rules.patterns import get_rules


def _scan(code: str, rule_id: str, filename: str = "test_example.py") -> list:
    rules = [r for r in get_rules(category_type="test_quality") if r.id == rule_id]
    assert rules, f"Rule {rule_id} not found"
    return scan_file_content(code, filename, rules=rules)


class TestPythonRules:
    def test_001_pass_only_matches(self):
        code = "def test_something():\n    pass\n"
        assert len(_scan(code, "TQ-PY-001")) > 0

    def test_001_with_assert_no_match(self):
        code = "def test_something():\n    assert True\n"
        assert len(_scan(code, "TQ-PY-001")) == 0

    def test_002_skip_no_reason_matches(self):
        code = "@pytest.mark.skip\ndef test_x(): pass\n"
        assert len(_scan(code, "TQ-PY-002")) > 0

    def test_002_skip_with_reason_no_match(self):
        code = "@pytest.mark.skip(reason='WIP')\ndef test_x(): pass\n"
        assert len(_scan(code, "TQ-PY-002")) == 0

    def test_003_sleep_in_test_matches(self):
        code = "def test_wait():\n    time.sleep(1)\n"
        assert len(_scan(code, "TQ-PY-003")) > 0

    def test_003_no_sleep_no_match(self):
        code = "def test_fast():\n    assert True\n"
        assert len(_scan(code, "TQ-PY-003")) == 0

    def test_004_except_pass_matches(self):
        code = "try:\n    do()\nexcept:\n    pass\n"
        assert len(_scan(code, "TQ-PY-004")) > 0

    def test_004_except_handled_no_match(self):
        code = "try:\n    do()\nexcept Exception as e:\n    log(e)\n"
        assert len(_scan(code, "TQ-PY-004")) == 0

    def test_005_excessive_patch_matches(self):
        code = (
            "@patch('a')\n@patch('b')\n@patch('c')\n"
            "def test_mocked():\n    pass\n"
        )
        assert len(_scan(code, "TQ-PY-005")) > 0

    def test_005_single_patch_no_match(self):
        code = "@patch('a')\ndef test_one_mock():\n    pass\n"
        assert len(_scan(code, "TQ-PY-005")) == 0


class TestRustRules:
    def test_001_unwrap_matches(self):
        code = 'let x = something.unwrap();'
        assert len(_scan(code, "TQ-RS-001", filename="lib.rs")) > 0

    def test_001_expect_no_match(self):
        code = 'let x = something.expect("msg");'
        assert len(_scan(code, "TQ-RS-001", filename="lib.rs")) == 0

    def test_002_unsafe_matches(self):
        code = "unsafe { ptr::read(p) }"
        assert len(_scan(code, "TQ-RS-002", filename="lib.rs")) > 0

    def test_003_empty_test_module_matches(self):
        code = "#[cfg(test)]\nmod tests {}"
        assert len(_scan(code, "TQ-RS-003", filename="lib.rs")) > 0

    def test_003_non_empty_no_match(self):
        code = "#[cfg(test)]\nmod tests { #[test] fn t() { assert!(true) } }"
        assert len(_scan(code, "TQ-RS-003", filename="lib.rs")) == 0

    def test_005_pub_fn_matches(self):
        code = "pub fn calculate() -> i32 { 42 }"
        assert len(_scan(code, "TQ-RS-005", filename="lib.rs")) > 0


class TestPyO3Rules:
    def test_001_pyfunction_matches(self):
        code = "#[pyfunction]\npub fn my_func() {}"
        assert len(_scan(code, "TQ-PYO3-001", filename="lib.rs")) > 0

    def test_002_pyclass_matches(self):
        code = "#[pyclass]\npub struct MyClass {}"
        assert len(_scan(code, "TQ-PYO3-002", filename="lib.rs")) > 0

    def test_003_pyerr_matches(self):
        code = "PyErr::new::<PyValueError, _>(msg)"
        assert len(_scan(code, "TQ-PYO3-003", filename="lib.rs")) > 0

    def test_004_allow_threads_matches(self):
        code = "py.allow_threads(|| { compute() })"
        assert len(_scan(code, "TQ-PYO3-004", filename="lib.rs")) > 0

    def test_python_file_no_match(self):
        """Rust rules should not fire on Python files."""
        code = "#[pyfunction]\npub fn my_func() {}"
        assert len(_scan(code, "TQ-PYO3-001", filename="test_app.py")) == 0
