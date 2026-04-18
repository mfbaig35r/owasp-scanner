"""pip-audit integration for A03 (Software Supply Chain Failures).

Wraps the pip-audit CLI to scan Python dependencies for known vulnerabilities
and converts results into scanner findings.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class VulnerabilityResult:
    package: str
    installed_version: str
    vuln_id: str
    description: str
    fix_versions: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "installed_version": self.installed_version,
            "vuln_id": self.vuln_id,
            "description": self.description,
            "fix_versions": self.fix_versions,
        }


@dataclass
class DependencySource:
    """Describes what dependency file was found and how to audit it."""
    path: Path
    source_type: str  # "requirements", "pyproject", "lockfile"

    @property
    def pip_audit_args(self) -> list[str]:
        """Return the pip-audit CLI args for this source type."""
        if self.source_type == "requirements":
            return ["--requirement", str(self.path)]
        # For pyproject.toml and lock files, pip-audit can't read them directly.
        # We use --path to audit the project directory (installs and scans).
        return ["--path", str(self.path.parent)]


def _find_dependency_source(directory: Path) -> DependencySource | None:
    """Find the best dependency source in a directory.

    Priority: requirements.txt > pyproject.toml > uv.lock > poetry.lock
    """
    # Requirements files (pip-audit reads these directly)
    for name in [
        "requirements.txt",
        "requirements/production.txt",
        "requirements/base.txt",
        "requirements/main.txt",
    ]:
        path = directory / name
        if path.is_file():
            return DependencySource(path, "requirements")

    # pyproject.toml (pip-audit uses --path to install and scan)
    pyproject = directory / "pyproject.toml"
    if pyproject.is_file():
        return DependencySource(pyproject, "pyproject")

    # Lock files (pip-audit uses --path)
    for name in ["uv.lock", "poetry.lock"]:
        path = directory / name
        if path.is_file():
            return DependencySource(path, "lockfile")

    return None


def _get_pip_audit_cmd() -> list[str]:
    """Find the best way to run pip-audit: direct, uv tool run, or uvx."""
    if shutil.which("pip-audit"):
        return ["pip-audit"]
    if shutil.which("uv"):
        return ["uv", "tool", "run", "pip-audit"]
    if shutil.which("uvx"):
        return ["uvx", "pip-audit"]
    return []


def run_pip_audit(target: Path) -> tuple[list[VulnerabilityResult], DependencySource]:
    """Run pip-audit on a Python project or requirements file.

    Supports requirements.txt, pyproject.toml, uv.lock, and poetry.lock.
    Tries pip-audit directly, then falls back to uv tool run pip-audit or uvx.

    Args:
        target: Path to a dependency file or directory containing one.

    Returns:
        Tuple of (vulnerability results, dependency source that was scanned).

    Raises:
        FileNotFoundError: If pip-audit/uv unavailable or no dependency files found.
        RuntimeError: If pip-audit fails.
    """
    base_cmd = _get_pip_audit_cmd()
    if not base_cmd:
        raise FileNotFoundError(
            "pip-audit is not installed and uv is not available for fallback. "
            "Install pip-audit (pip install pip-audit) or uv (pip install uv)."
        )

    # Determine the dependency source
    if target.is_dir():
        source = _find_dependency_source(target)
        if not source:
            raise FileNotFoundError(
                f"No dependency files found in {target}. "
                "Looked for: requirements.txt, pyproject.toml, uv.lock, poetry.lock."
            )
    elif target.name == "pyproject.toml":
        source = DependencySource(target, "pyproject")
    elif target.name in ("uv.lock", "poetry.lock"):
        source = DependencySource(target, "lockfile")
    else:
        source = DependencySource(target, "requirements")

    # Run pip-audit with source-appropriate args
    cmd = [
        *base_cmd,
        *source.pip_audit_args,
        "--format", "json",
        "--output", "-",
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=120,
    )

    # pip-audit returns exit code 1 when vulnerabilities are found (not an error)
    if result.returncode not in (0, 1):
        raise RuntimeError(
            f"pip-audit failed (exit {result.returncode}): {result.stderr.strip()}"
        )

    # Parse JSON output
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        raise RuntimeError(
            f"Failed to parse pip-audit output: {result.stdout[:500]}"
        )

    vulnerabilities: list[VulnerabilityResult] = []
    deps = data.get("dependencies", [])
    for dep in deps:
        package = dep.get("name", "")
        version = dep.get("version", "")
        for vuln in dep.get("vulns", []):
            vulnerabilities.append(VulnerabilityResult(
                package=package,
                installed_version=version,
                vuln_id=vuln.get("id", ""),
                description=vuln.get("description", vuln.get("id", "")),
                fix_versions=vuln.get("fix_versions", []),
            ))

    return vulnerabilities, source
