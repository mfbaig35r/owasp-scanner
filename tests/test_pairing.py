"""Tests for source-to-test file pairing."""

from __future__ import annotations

from pathlib import Path

from owasp_scanner.core.test_pairing import (
    detect_test_framework,
    pair_source_to_tests,
)


class TestDetectTestFramework:
    def test_python_project(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            '[tool.pytest.ini_options]\ntestpaths = ["tests"]\n'
        )
        (tmp_path / "tests").mkdir()
        result = detect_test_framework(tmp_path)
        assert result["language"] == "python"
        assert result["test_root"] == tmp_path / "tests"

    def test_rust_project(self, tmp_path: Path):
        (tmp_path / "Cargo.toml").write_text("[package]\nname = 'test'\n")
        result = detect_test_framework(tmp_path)
        assert result["language"] == "rust"

    def test_hybrid_project(self, tmp_path: Path):
        (tmp_path / "Cargo.toml").write_text("[package]\n")
        (tmp_path / "pyproject.toml").write_text("[project]\n")
        result = detect_test_framework(tmp_path)
        assert result["language"] == "hybrid"

    def test_unknown_project(self, tmp_path: Path):
        result = detect_test_framework(tmp_path)
        assert result["language"] == "unknown"

    def test_parses_testpaths(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            '[tool.pytest.ini_options]\ntestpaths = ["test"]\n'
        )
        (tmp_path / "test").mkdir()
        result = detect_test_framework(tmp_path)
        assert result["test_root"] == tmp_path / "test"
        assert result["testpaths"] == ["test"]


class TestPairSourceToTests:
    def test_basename_match(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text("[project]\n")
        tests = tmp_path / "tests"
        tests.mkdir()
        src = tmp_path / "utils.py"
        src.write_text("def add(a, b): return a + b\n")
        (tests / "test_utils.py").write_text("def test_add(): assert add(1,2)==3\n")

        pairs = pair_source_to_tests(tmp_path, source_files=[src])
        assert len(pairs) == 1
        assert pairs[0].status == "paired"
        assert pairs[0].candidates[0].confidence == 0.9
        assert pairs[0].candidates[0].match_type == "basename"

    def test_unpaired_source(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text("[project]\n")
        (tmp_path / "tests").mkdir()
        src = tmp_path / "orphan.py"
        src.write_text("def lonely(): pass\n")

        pairs = pair_source_to_tests(tmp_path, source_files=[src])
        assert len(pairs) == 1
        assert pairs[0].status == "unpaired"
        assert len(pairs[0].candidates) == 0

    def test_rust_inline_tests(self, tmp_path: Path):
        (tmp_path / "Cargo.toml").write_text("[package]\n")
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        rs = src_dir / "lib.rs"
        rs.write_text("pub fn add() {}\n#[cfg(test)]\nmod tests { #[test] fn t() {} }\n")

        pairs = pair_source_to_tests(tmp_path, source_files=[rs])
        assert len(pairs) == 1
        assert pairs[0].inline_tests is True
        assert pairs[0].status == "paired"

    def test_suffix_test_match(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text("[project]\n")
        tests = tmp_path / "tests"
        tests.mkdir()
        src = tmp_path / "views.py"
        src.write_text("def index(): pass\n")
        (tests / "views_test.py").write_text("def test_index(): pass\n")

        pairs = pair_source_to_tests(tmp_path, source_files=[src])
        assert len(pairs) == 1
        assert pairs[0].status == "paired"

    def test_auto_discovers_source_files(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text("[project]\n")
        (tmp_path / "tests").mkdir()
        (tmp_path / "app.py").write_text("x = 1\n")
        (tmp_path / "lib.py").write_text("y = 2\n")

        pairs = pair_source_to_tests(tmp_path)
        source_names = {p.source.name for p in pairs}
        assert "app.py" in source_names
        assert "lib.py" in source_names

    def test_skips_test_files_in_source(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text("[project]\n")
        (tmp_path / "tests").mkdir()
        (tmp_path / "app.py").write_text("x = 1\n")
        (tmp_path / "test_app.py").write_text("def test_x(): pass\n")

        pairs = pair_source_to_tests(tmp_path)
        source_names = {p.source.name for p in pairs}
        assert "test_app.py" not in source_names
