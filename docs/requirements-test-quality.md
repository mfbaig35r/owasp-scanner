# OWASP Scanner — Test Quality Extension Requirements

## Context

The scanner currently finds security vulnerabilities. This extension finds
**test gaps** — missing tests, weak assertions, untested error paths, and
coverage blind spots. Same architecture: regex rules for obvious patterns,
LLM for semantic analysis ("this function has 4 code paths but only 2 are
tested"), findings database for tracking remediation.

Primary targets: Python (pytest) and Rust (cargo test), starting with
rustcluster as the reference project — a Rust-backed Python library with
PyO3 bindings, 167 tests across both languages.

## Why This Matters

Security scanning asks "is there something dangerous here?" Test quality
scanning asks "is there something *missing* here?" That's a harder problem
for static analysis but a natural fit for LLM reasoning. The LLM can read
a function, understand its code paths, read the corresponding test, and
tell you which paths aren't exercised.

The existing scanner infrastructure — findings persistence, dedup, triage,
reporting, SARIF export — carries over unchanged. A test gap is just a
finding with `owasp_category` replaced by a test quality category.

## Design Principle

**Extend, don't fork.** The Finding dataclass gains a `category_type` field
("security" or "test_quality") so test findings live alongside security
findings in the same database. The MCP tools, reporting, and LLM
integration all work the same way.

---

## 1. Test Quality Categories

Analogous to OWASP categories but for test coverage:

| Code | Category | Description |
|------|----------|-------------|
| `TQ01` | Missing Tests | Public function/method with no corresponding test |
| `TQ02` | Weak Assertions | Test runs code but asserts nothing meaningful |
| `TQ03` | Missing Error Paths | Function has error handling but no test triggers it |
| `TQ04` | Missing Edge Cases | No test for empty input, None, boundary values |
| `TQ05` | Excessive Mocking | Test mocks so much that it doesn't test real behavior |
| `TQ06` | Missing Integration | Unit tests exist but no integration test for the workflow |
| `TQ07` | Flaky Patterns | Time-dependent, order-dependent, or race condition tests |
| `TQ08` | Unsafe Untested | Rust `unsafe` blocks or `unwrap()` without panic tests |
| `TQ09` | Coverage Gap | Module/file with zero or near-zero test coverage |
| `TQ10` | Missing Fixture Cleanup | Resources created in test but not cleaned up |

---

## 2. Source-to-Test File Pairing

The hardest structural problem. The scanner needs to know which test file
covers which source file.

### Python conventions (pytest)

| Source | Possible test locations |
|--------|----------------------|
| `src/app/views.py` | `tests/test_views.py`, `tests/app/test_views.py`, `tests/test_app_views.py` |
| `rustcluster/__init__.py` | `tests/test_init.py`, `tests/test_rustcluster.py` |
| `lib/utils.py` | `tests/test_utils.py` |

Strategy: search for test files matching `test_{stem}.py` or `{stem}_test.py`
in `tests/` and subdirectories. Fall back to fuzzy matching on module name.
If no match found, the source file itself is a TQ09 finding.

### Rust conventions

| Source | Test location |
|--------|-------------|
| `src/kmeans.rs` | Inline `#[cfg(test)] mod tests` in same file |
| `src/lib.rs` | `tests/` directory at crate root (integration tests) |

Strategy: parse the source file for `#[cfg(test)]` modules. Check `tests/`
directory for integration tests. Rust is much easier than Python here because
the conventions are enforced by cargo.

### PyO3 boundary tests

For a project like rustcluster, there are three test layers:
1. **Rust unit tests** — `#[test]` functions testing Rust logic
2. **Python integration tests** — pytest testing the Python API
3. **Cross-boundary tests** — pytest tests that exercise Rust code via PyO3

The scanner should understand all three and identify gaps at each layer.

### Implementation

New function: `pair_source_to_tests(source_file, project_root) -> list[Path]`

```python
@dataclass
class SourceTestPair:
    source: Path
    tests: list[Path]           # matched test files
    test_functions: list[str]   # test function names that reference this module
    coverage: str               # "none", "partial", "good"
```

---

## 3. Regex Rules

### Python test quality rules

| Rule ID | Pattern | Category | Severity |
|---------|---------|----------|----------|
| `TQ-PY-001` | `def test_` function with no `assert` statement | TQ02 | high |
| `TQ-PY-002` | `def test_` function body is only `pass` | TQ02 | high |
| `TQ-PY-003` | `def test_` function that only calls the function (no assertion) | TQ02 | medium |
| `TQ-PY-004` | `@pytest.mark.skip` without reason | TQ07 | medium |
| `TQ-PY-005` | `time.sleep()` in test (flaky pattern) | TQ07 | medium |
| `TQ-PY-006` | `@patch` or `MagicMock` covering >50% of test body | TQ05 | medium |
| `TQ-PY-007` | `except: pass` or `except Exception: pass` in test | TQ03 | high |
| `TQ-PY-008` | `tmpdir` or `tmp_path` used without cleanup assertion | TQ10 | low |
| `TQ-PY-009` | Test file with fewer than 3 test functions for a complex module | TQ09 | medium |

### Rust test quality rules

| Rule ID | Pattern | Category | Severity |
|---------|---------|----------|----------|
| `TQ-RS-001` | `pub fn` without any `#[test]` referencing it | TQ01 | high |
| `TQ-RS-002` | `.unwrap()` in non-test code without `#[should_panic]` test | TQ08 | high |
| `TQ-RS-003` | `unsafe` block without dedicated test | TQ08 | critical |
| `TQ-RS-004` | `#[cfg(test)] mod tests` with empty body | TQ09 | high |
| `TQ-RS-005` | `#[test]` function with no `assert!` macro | TQ02 | high |
| `TQ-RS-006` | `enum` variant never matched in tests | TQ04 | medium |
| `TQ-RS-007` | `impl` block with untested methods | TQ01 | medium |
| `TQ-RS-008` | `async fn` without `#[tokio::test]` coverage | TQ01 | medium |
| `TQ-RS-009` | `Result<>` return type but no test exercises `Err` case | TQ03 | high |

### PyO3 boundary rules (specific to Rust+Python projects)

| Rule ID | Pattern | Category | Severity |
|---------|---------|----------|----------|
| `TQ-PYO3-001` | `#[pyfunction]` without Python-level test | TQ01 | high |
| `TQ-PYO3-002` | `#[pyclass]` with methods but no Python test exercises them | TQ01 | high |
| `TQ-PYO3-003` | dtype dispatch (f32/f64) but tests only cover one dtype | TQ04 | medium |
| `TQ-PYO3-004` | `py.allow_threads()` without concurrent Python test | TQ06 | low |
| `TQ-PYO3-005` | Error conversion (`PyErr`) without Python-side error test | TQ03 | high |

---

## 4. LLM-Powered Test Gap Analysis

This is where the real value is. Regex can find "test with no assert" but
it can't find "function has 4 code paths and only 2 are tested."

### System prompt

```
TEST_QUALITY_SYSTEM_PROMPT:

You are a test quality auditor. You will receive a source file and its
corresponding test file(s). Analyze the test coverage and identify gaps.

For each public function/method in the source file:
1. Does a corresponding test exist?
2. How many code paths does the function have? (branches, match arms, 
   error returns, early returns)
3. How many of those paths are exercised by tests?
4. What edge cases are missing? (empty input, None/null, boundary values,
   error conditions, concurrent access)
5. Is the test actually testing behavior, or just calling the function?

For Rust code specifically:
- Are unsafe blocks tested for safety invariants?
- Are unwrap() calls covered by should_panic tests?
- Are all enum variants exercised?
- Are error paths (Result::Err) tested?
- For generic functions: are both f32 and f64 tested?

For PyO3 boundary code:
- Is the Python API tested separately from the Rust logic?
- Are dtype conversions tested (f32, f64, int input)?
- Are error messages tested from the Python side?
- Is GIL release behavior tested (concurrent access)?
- Are non-contiguous array inputs tested?

Assign confidence 0.0-1.0 and severity:
- critical: public API with zero tests
- high: code path with error handling but no error test
- medium: missing edge case (empty input, boundary values)
- low: test style issue (weak assertion, excessive mocking)
```

### Key LLM capabilities

**Code path analysis:** Read a function, count branches (if/else, match,
Result handling, early returns), compare against test assertions. Report
which paths are untested.

For rustcluster specifically:
```rust
// kmeans.rs — function has 5 code paths:
// 1. Empty data → ClusterError::EmptyData
// 2. k=0 → ClusterError::InvalidK
// 3. k > n → ClusterError::InvalidK  
// 4. Single n_init → one run
// 5. Multiple n_init → best of N runs
pub fn fit<F, D>(data: &Array2<F>, k: usize, ...) -> Result<KMeansResult<F>, ClusterError>
```

The LLM reads the tests and reports: "paths 1-3 are tested via
test_empty_data, test_k_zero, test_k_greater_than_n. Path 4 is tested.
Path 5 (n_init > 1) — no test varies n_init and verifies best-of-N
selection."

**Missing edge case detection:** For a function like
`squared_euclidean(a, b)`, the LLM identifies untested inputs: empty
slices, single-element slices, mismatched lengths, NaN values, infinity,
subnormal floats.

**Integration gap detection:** "Unit tests cover K-means and DBSCAN
individually, but no test runs both on the same dataset and compares
cluster quality metrics."

---

## 5. MCP Tools

### New tools

```python
scan_test_quality(
    path: str,                  # project root
    language: str = "auto",     # "python", "rust", "auto"
    exclude: list[str] = None,
) -> dict

analyze_test_coverage(
    source_file: str,           # path to source file
    test_file: str | None,      # path to test file (auto-detected if None)
) -> dict

suggest_tests(
    source_file: str,           # path to source file
    max_suggestions: int = 5,
) -> dict
```

### scan_test_quality

Top-level scan — regex rules + LLM analysis across the project:
1. Detect language (Rust cargo project, Python pytest, or PyO3 hybrid)
2. Pair source files to test files
3. Run regex rules on test files
4. For each source-test pair, LLM evaluates coverage completeness
5. Persist findings as TQ-category findings in the database

### analyze_test_coverage

Deep dive on a single source-test pair:
1. Read source file, identify all public functions/methods
2. Read test file, identify all test functions
3. Map test functions to source functions (by name, by import, by call)
4. LLM evaluates: which code paths are tested, which are missing
5. Returns structured coverage map

### suggest_tests

Generate test skeletons for uncovered code:
1. Read source file
2. Identify untested functions/paths
3. LLM generates pytest or `#[test]` skeletons with meaningful assertions
4. Returns code strings ready to paste into test files

---

## 6. rustcluster-Specific Patterns

Using rustcluster as the reference project, these are the patterns the
scanner should understand:

### Three-layer testing

```
Layer 1 (PyO3 boundary):
  - Python tests: test dtype dispatch, error messages, array contiguity
  - Found in: tests/test_*.py

Layer 2 (Algorithm logic):
  - Rust tests: test convergence, n_init selection, cluster quality
  - Found in: src/kmeans.rs #[cfg(test)], src/dbscan.rs #[cfg(test)]

Layer 3 (Hot kernel):
  - Rust tests: test distance correctness, edge cases, NaN handling
  - Found in: src/utils.rs #[cfg(test)], src/distance.rs #[cfg(test)]
  - Criterion benchmarks: benches/benchmarks.rs
```

The scanner should verify coverage at each layer:
- Every `#[pyfunction]` has a Python test
- Every algorithm has Rust unit tests for convergence and edge cases
- Every distance kernel has correctness tests for known values

### Trait testing

When a function is generic over `D: Distance<F>` and `F: Scalar`:
- Tests should cover both `f32` and `f64`
- Tests should cover both `SquaredEuclidean` and `CosineDistance`
- Monomorphized code paths may diverge (e.g., Hamerly not available with cosine)

### Error path coverage

rustcluster has `ClusterError` with variants:
```rust
pub enum ClusterError {
    EmptyData,
    InvalidK(String),
    ConvergenceWarning(String),
    InvalidEps(String),
    InvalidMinSamples(String),
}
```

Every variant should have at least one test that triggers it from both
the Rust side (`#[test]`) and the Python side (pytest with `pytest.raises`).

### Benchmark-as-test

Criterion benchmarks (`benches/benchmarks.rs`) exercise code paths that
unit tests might miss (large n, high k, varied dimensions). The scanner
should recognize benchmark files as test coverage — they're not assertions,
but they exercise the hot path under realistic conditions.

---

## 7. Implementation Plan

### Phase 1: Source-test pairing + regex rules (zero deps)

New files:
- `rules/test_quality_patterns.py` — regex rules for Python + Rust
- `core/test_pairing.py` — `pair_source_to_tests()`, `SourceTestPair`

Modified files:
- `rules/patterns.py` — load test quality rules in `get_rules()`
- `server.py` — add `scan_test_quality` tool

This gives immediate value: finds empty tests, assertion-free tests,
skip-without-reason, flaky patterns. No LLM needed.

### Phase 2: LLM-powered gap analysis (zero deps)

New files:
- `core/test_analyzer.py` — source-test pair analysis logic

Modified files:
- `core/prompts.py` — add `TEST_QUALITY_SYSTEM_PROMPT`
- `core/llm_scanner.py` — add `analyze_test_pair_llm()`
- `server.py` — add `analyze_test_coverage` and `suggest_tests` tools

The differentiator: LLM reads source + tests together, identifies
untested code paths, missing edge cases, and generates test skeletons.

### Phase 3: Rust-specific analysis (optional)

Rust analysis requires parsing `#[test]`, `#[cfg(test)]`, `pub fn`,
`unsafe`, `unwrap()`, `Result<>`, enum variants. Options:

- **Regex-only**: catches the obvious patterns (empty test modules,
  unwrap without should_panic). Good enough for most cases.
- **tree-sitter-rust**: structural extraction of function signatures,
  test modules, unsafe blocks. Better accuracy.
- **LLM-only**: read the Rust file, reason about coverage. Best
  accuracy, cheapest to implement.

Recommendation: regex rules (Phase 1) + LLM analysis (Phase 2) cover
90% of the value. tree-sitter is Phase 3 if accuracy matters.

---

## 8. What This Catches

Using rustcluster as the example:

| Finding | How detected | Category |
|---------|-------------|----------|
| `fit()` with n_init > 1 — no test varies n_init | LLM reads code paths | TQ04 |
| `squared_euclidean` — no test for NaN input | LLM identifies edge case | TQ04 |
| `DBSCAN` — no test for all-noise result | LLM checks enum variant coverage | TQ04 |
| `KMeans.__init__` — Python test but no Rust test | Pairing + layer analysis | TQ01 |
| `validate_data_generic` — error paths tested in Rust but not from Python | Cross-layer analysis | TQ03 |
| `test_kmeans_basic` — calls `fit()` but only checks labels shape, not values | LLM reads assertion quality | TQ02 |
| `#[cfg(test)] mod tests` in `distance.rs` — only 2 test functions for 3 distance impls | Regex + LLM | TQ09 |
| `unsafe` block in hot kernel — no safety invariant test | Regex pattern | TQ08 |
| f32 dtype — Python tests exist but Rust unit tests only use f64 | LLM cross-references dtypes | TQ04 |
| silhouette score — no test for single-cluster input | LLM identifies edge case | TQ04 |
