"""Source-to-test file pairing for test quality analysis.

Implements a ranked candidate search that handles Python (pytest),
Rust (cargo test), and hybrid (PyO3) projects. Research-informed:
tested against real project layouts from FastAPI, Django, Pydantic,
SQLAlchemy, Requests, Flask, and Serde.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class TestCandidate:
    """A potential test file for a source file, ranked by confidence."""
    test_path: Path
    confidence: float       # 0.0-1.0
    match_type: str         # "basename", "mirror", "area", "inline"

    def to_dict(self) -> dict[str, Any]:
        return {
            "test_path": str(self.test_path),
            "confidence": self.confidence,
            "match_type": self.match_type,
        }


@dataclass
class SourceTestPair:
    """A source file paired with its test candidates."""
    source: Path
    language: str               # "python", "rust"
    candidates: list[TestCandidate] = field(default_factory=list)
    inline_tests: bool = False  # Rust: has #[cfg(test)] module
    status: str = "unpaired"    # "paired", "unpaired", "area_only"

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": str(self.source),
            "language": self.language,
            "candidates": [c.to_dict() for c in self.candidates],
            "inline_tests": self.inline_tests,
            "status": self.status,
        }


# ── Test framework detection ──────────────────────────────────────────


def detect_test_framework(project_root: Path) -> dict[str, Any]:
    """Detect test framework and configuration.

    Returns dict with: language, test_root, test_file_patterns, testpaths
    """
    has_python = False
    has_rust = False
    test_root: Path | None = None
    test_file_patterns = ["test_*.py", "*_test.py"]
    testpaths: list[str] = []

    # Check for Rust
    if (project_root / "Cargo.toml").is_file():
        has_rust = True

    # Check for Python + parse pytest config
    pyproject = project_root / "pyproject.toml"
    if pyproject.is_file():
        has_python = True
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
            pytest_opts = data.get("tool", {}).get("pytest", {}).get("ini_options", {})
            if "testpaths" in pytest_opts:
                tp = pytest_opts["testpaths"]
                testpaths = tp if isinstance(tp, list) else [tp]
            if "python_files" in pytest_opts:
                pf = pytest_opts["python_files"]
                test_file_patterns = pf if isinstance(pf, list) else [pf]
        except (tomllib.TOMLDecodeError, OSError):
            pass

    # Fallback Python detection
    for name in ("setup.py", "setup.cfg", "requirements.txt"):
        if (project_root / name).is_file():
            has_python = True
            break

    # Find test root
    for candidate in testpaths or ["tests", "test"]:
        p = project_root / candidate
        if p.is_dir():
            test_root = p
            break

    language = "hybrid" if has_python and has_rust else (
        "rust" if has_rust else ("python" if has_python else "unknown")
    )

    return {
        "language": language,
        "test_root": test_root,
        "test_file_patterns": test_file_patterns,
        "testpaths": testpaths,
        "has_python": has_python,
        "has_rust": has_rust,
    }


# ── Pairing algorithm ────────────────────────────────────────────────


_SKIP_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__",
    ".mypy_cache", ".ruff_cache", ".pytest_cache", "dist", "build",
    ".next", ".nuxt", "target",
}

_SOURCE_EXTENSIONS = {".py", ".rs"}


def pair_source_to_tests(
    project_root: Path,
    source_files: list[Path] | None = None,
    language: str = "auto",
) -> list[SourceTestPair]:
    """Pair source files to their test files using ranked candidate search.

    Args:
        project_root: Root directory of the project.
        source_files: Specific files to pair (None = auto-discover).
        language: 'python', 'rust', 'hybrid', or 'auto'.
    """
    config = detect_test_framework(project_root)
    if language == "auto":
        language = config["language"]

    test_root = config["test_root"]

    # Collect source files
    if source_files is None:
        source_files = _collect_source_files(project_root, language)

    pairs: list[SourceTestPair] = []
    for source in source_files:
        lang = "rust" if source.suffix == ".rs" else "python"
        pair = SourceTestPair(source=source, language=lang)

        if lang == "rust":
            # Check for inline tests
            try:
                content = source.read_text(encoding="utf-8", errors="replace")
                if re.search(r"#\[cfg\(test\)\]", content):
                    pair.inline_tests = True
                    pair.candidates.append(TestCandidate(
                        test_path=source,
                        confidence=1.0,
                        match_type="inline",
                    ))
            except OSError:
                pass

            # Check for integration tests
            crate_root = _find_crate_root(source, project_root)
            if crate_root:
                tests_dir = crate_root / "tests"
                if tests_dir.is_dir():
                    for tf in tests_dir.glob("*.rs"):
                        pair.candidates.append(TestCandidate(
                            test_path=tf,
                            confidence=0.6,
                            match_type="area",
                        ))

        elif lang == "python" and test_root:
            pair.candidates = _generate_python_candidates(
                source, test_root, project_root,
            )

        # Set status
        if pair.candidates:
            best = max(c.confidence for c in pair.candidates)
            pair.status = "paired" if best >= 0.5 else "area_only"
        else:
            pair.status = "unpaired"

        pairs.append(pair)

    return pairs


def _collect_source_files(project_root: Path, language: str) -> list[Path]:
    """Collect source files, excluding test files and skipped dirs."""
    files: list[Path] = []
    for f in sorted(project_root.rglob("*")):
        if any(part in _SKIP_DIRS for part in f.parent.parts):
            continue
        if not f.is_file():
            continue
        if f.suffix not in _SOURCE_EXTENSIONS:
            continue

        # Skip test files
        if f.name.startswith("test_") or f.name.endswith("_test.py"):
            continue
        if f.name == "conftest.py":
            continue

        # Language filter
        if language == "python" and f.suffix != ".py":
            continue
        if language == "rust" and f.suffix != ".rs":
            continue

        files.append(f)
    return files


def _generate_python_candidates(
    source: Path,
    test_root: Path,
    project_root: Path,
) -> list[TestCandidate]:
    """Generate ranked test file candidates for a Python source file."""
    candidates: list[TestCandidate] = []
    stem = source.stem

    # 1. Exact basename match in test root (confidence 0.9)
    for pattern in [f"test_{stem}.py", f"{stem}_test.py"]:
        match = test_root / pattern
        if match.is_file():
            candidates.append(TestCandidate(match, 0.9, "basename"))
        # Also search subdirectories
        for sub in test_root.rglob(pattern):
            if sub != match and sub.is_file():
                candidates.append(TestCandidate(sub, 0.85, "basename"))

    # 2. Source-root stripped mirror (confidence 0.8)
    try:
        rel = source.relative_to(project_root)
        # Strip common source roots
        parts = list(rel.parts)
        for prefix in ("src", "lib"):
            if parts and parts[0] == prefix:
                parts = parts[1:]
                break
        # Strip package root (first directory after src/)
        if len(parts) > 1:
            mirror = test_root / "/".join(parts[:-1]) / f"test_{stem}.py"
            if mirror.is_file():
                candidates.append(TestCandidate(mirror, 0.8, "mirror"))
    except ValueError:
        pass

    # 3. Package-area mirror (confidence 0.7)
    try:
        rel = source.relative_to(project_root)
        source_dir = rel.parent
        # Check if test root has matching directory
        test_area = test_root / source_dir
        if test_area.is_dir():
            for tf in test_area.glob("test_*.py"):
                if tf not in [c.test_path for c in candidates]:
                    candidates.append(TestCandidate(tf, 0.7, "area"))
    except ValueError:
        pass

    # 4. Singular/plural variant (confidence 0.5)
    for variant in [stem.rstrip("s"), stem + "s"]:
        if variant != stem:
            for pattern in [f"test_{variant}.py", f"{variant}_test.py"]:
                match = test_root / pattern
                if match.is_file() and match not in [c.test_path for c in candidates]:
                    candidates.append(TestCandidate(match, 0.5, "basename"))

    # Sort by confidence descending
    candidates.sort(key=lambda c: c.confidence, reverse=True)
    return candidates


def _find_crate_root(source: Path, project_root: Path) -> Path | None:
    """Find the nearest Cargo.toml parent for a Rust source file."""
    current = source.parent
    while current >= project_root:
        if (current / "Cargo.toml").is_file():
            return current
        current = current.parent
    return None
