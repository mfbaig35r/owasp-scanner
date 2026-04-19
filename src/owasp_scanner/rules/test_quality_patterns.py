"""Test quality rules for Python (pytest), Rust (cargo test), and PyO3 projects."""

from __future__ import annotations

import re

from owasp_scanner.rules.patterns import Rule

_FLAGS = re.IGNORECASE | re.MULTILINE

TEST_QUALITY_CATEGORIES = {
    "TQ01": "Missing Tests",
    "TQ02": "Weak Assertions",
    "TQ03": "Missing Error Paths",
    "TQ04": "Missing Edge Cases",
    "TQ05": "Excessive Mocking",
    "TQ06": "Missing Integration",
    "TQ07": "Flaky Patterns",
    "TQ08": "Unsafe Untested",
    "TQ09": "Coverage Gap",
    "TQ10": "Missing Fixture Cleanup",
}

_TEST_GLOBS = ("test_*.py", "*_test.py")


def _test_rules(**kwargs: object) -> list[Rule]:
    return [Rule(**kwargs, file_glob=g) for g in _TEST_GLOBS]  # type: ignore[arg-type]


# ── Python test quality rules ─────────────────────────────────────────

TEST_QUALITY_PYTHON_RULES: list[Rule] = []

# TQ-PY-001: Test function body is only pass
TEST_QUALITY_PYTHON_RULES.extend(_test_rules(
    id="TQ-PY-001",
    owasp_category="TQ02",
    severity="high",
    title="Test function body is only 'pass'",
    description="Test does nothing — the body is just 'pass'. Either implement the test or remove it.",
    pattern=re.compile(r"def\s+test_\w+\s*\([^)]*\)\s*:\s*\n\s+pass\s*$", _FLAGS),
    suggested_fix="Add meaningful assertions to the test body.",
))

# TQ-PY-002: @pytest.mark.skip without reason
TEST_QUALITY_PYTHON_RULES.extend(_test_rules(
    id="TQ-PY-002",
    owasp_category="TQ07",
    severity="medium",
    title="Test skipped without reason",
    description="@pytest.mark.skip without a reason string. Document why the test is skipped.",
    pattern=re.compile(r"@pytest\.mark\.skip\s*(?:\(\s*\))?$", _FLAGS),
    suggested_fix="Add reason: @pytest.mark.skip(reason='...')",
))

# TQ-PY-003: time.sleep in test
TEST_QUALITY_PYTHON_RULES.extend(_test_rules(
    id="TQ-PY-003",
    owasp_category="TQ07",
    severity="medium",
    title="time.sleep() in test (flaky pattern)",
    description="Tests with time.sleep() are timing-dependent and may be flaky in CI.",
    pattern=re.compile(r"time\.sleep\s*\(", _FLAGS),
    suggested_fix="Use polling, mocks, or event-based waiting instead of sleep.",
))

# TQ-PY-004: except: pass in test
TEST_QUALITY_PYTHON_RULES.extend(_test_rules(
    id="TQ-PY-004",
    owasp_category="TQ03",
    severity="high",
    title="Silent exception swallowing in test",
    description="Catching and ignoring exceptions in tests hides real failures.",
    pattern=re.compile(r"except\s*(?:Exception)?\s*:\s*\n\s*pass", _FLAGS),
    suggested_fix="Let exceptions propagate or use pytest.raises() to assert specific exceptions.",
))

# TQ-PY-005: Excessive @patch decorators
TEST_QUALITY_PYTHON_RULES.extend(_test_rules(
    id="TQ-PY-005",
    owasp_category="TQ05",
    severity="medium",
    title="Excessive mocking (@patch)",
    description="Multiple @patch decorators on a single test may indicate the test isn't testing real behavior.",
    pattern=re.compile(r"(?:@patch\b.*\n){3,}\s*(?:async\s+)?def\s+test_", _FLAGS),
    suggested_fix="Consider integration tests that exercise real behavior with fewer mocks.",
))

# ── Rust test quality rules ───────────────────────────────────────────

TEST_QUALITY_RUST_RULES: list[Rule] = []

# TQ-RS-001: .unwrap() in non-test code
TEST_QUALITY_RUST_RULES.append(Rule(
    id="TQ-RS-001",
    owasp_category="TQ08",
    severity="high",
    title=".unwrap() call — verify panic test exists",
    description=".unwrap() panics on None/Err. Verify there's a #[should_panic] test or proper error handling.",
    pattern=re.compile(r"\.unwrap\(\)", _FLAGS),
    file_glob="*.rs",
    suggested_fix="Use .expect('message') or handle the error with ? operator. Add #[should_panic] test.",
))

# TQ-RS-002: unsafe block
TEST_QUALITY_RUST_RULES.append(Rule(
    id="TQ-RS-002",
    owasp_category="TQ08",
    severity="critical",
    title="unsafe block — verify safety invariant tests exist",
    description="unsafe blocks require tests that verify the safety invariants are maintained.",
    pattern=re.compile(r"unsafe\s*\{", _FLAGS),
    file_glob="*.rs",
    suggested_fix="Add dedicated tests that verify the safety contract of this unsafe block.",
))

# TQ-RS-003: Empty #[cfg(test)] module
TEST_QUALITY_RUST_RULES.append(Rule(
    id="TQ-RS-003",
    owasp_category="TQ09",
    severity="high",
    title="Empty test module",
    description="#[cfg(test)] module exists but contains no tests.",
    pattern=re.compile(r"#\[cfg\(test\)\]\s*mod\s+tests\s*\{\s*\}", re.DOTALL),
    file_glob="*.rs",
    suggested_fix="Add #[test] functions to the test module.",
))

# TQ-RS-004: #[test] fn without assert
TEST_QUALITY_RUST_RULES.append(Rule(
    id="TQ-RS-004",
    owasp_category="TQ02",
    severity="high",
    title="Test function without assertion",
    description="#[test] function doesn't contain assert!, assert_eq!, or assert_ne!.",
    pattern=re.compile(r"#\[test\]\s*fn\s+\w+\s*\(\)\s*\{[^}]*\}",  re.DOTALL),
    file_glob="*.rs",
    suggested_fix="Add assert!, assert_eq!, or assert_ne! macros to verify behavior.",
))

# TQ-RS-005: pub fn (heuristic for missing test)
TEST_QUALITY_RUST_RULES.append(Rule(
    id="TQ-RS-005",
    owasp_category="TQ01",
    severity="medium",
    title="Public function — verify test coverage",
    description="Public function should have corresponding test coverage.",
    pattern=re.compile(r"pub\s+(?:async\s+)?fn\s+\w+", _FLAGS),
    file_glob="*.rs",
    suggested_fix="Add a #[test] function that exercises this public API.",
))

# ── PyO3 test quality rules ──────────────────────────────────────────

TEST_QUALITY_PYO3_RULES: list[Rule] = []

# TQ-PYO3-001: #[pyfunction] — verify Python test
TEST_QUALITY_PYO3_RULES.append(Rule(
    id="TQ-PYO3-001",
    owasp_category="TQ01",
    severity="high",
    title="#[pyfunction] — verify Python-level test exists",
    description="PyO3 function should have a pytest test exercising it from the Python side.",
    pattern=re.compile(r"#\[pyfunction\]", _FLAGS),
    file_glob="*.rs",
    suggested_fix="Add a pytest test that imports and calls this function from Python.",
))

# TQ-PYO3-002: #[pyclass] — verify Python test
TEST_QUALITY_PYO3_RULES.append(Rule(
    id="TQ-PYO3-002",
    owasp_category="TQ01",
    severity="high",
    title="#[pyclass] — verify Python-level tests exist",
    description="PyO3 class should have pytest tests exercising its methods from Python.",
    pattern=re.compile(r"#\[pyclass\]", _FLAGS),
    file_glob="*.rs",
    suggested_fix="Add pytest tests that construct and exercise this class from Python.",
))

# TQ-PYO3-003: PyErr without Python error test
TEST_QUALITY_PYO3_RULES.append(Rule(
    id="TQ-PYO3-003",
    owasp_category="TQ03",
    severity="high",
    title="PyErr conversion — verify Python-side error test",
    description="Error conversion to PyErr should be tested from Python with pytest.raises().",
    pattern=re.compile(r"PyErr", _FLAGS),
    file_glob="*.rs",
    suggested_fix="Add a pytest test: with pytest.raises(ValueError): ...",
))

# TQ-PYO3-004: py.allow_threads
TEST_QUALITY_PYO3_RULES.append(Rule(
    id="TQ-PYO3-004",
    owasp_category="TQ06",
    severity="low",
    title="GIL release — consider concurrent Python test",
    description="py.allow_threads() releases the GIL. Consider testing concurrent Python access.",
    pattern=re.compile(r"py\.allow_threads\s*\(", _FLAGS),
    file_glob="*.rs",
    suggested_fix="Add a test that calls this function from multiple Python threads.",
))
