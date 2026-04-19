"""Next.js App Router project detection and file-type classification."""

from __future__ import annotations

import json
import re
from pathlib import Path


def detect_project_type(project_root: Path) -> str:
    """Detect project type from filesystem signals.

    Returns: 'nextjs', 'react', 'python', 'monorepo', 'unknown'
    """
    has_nextjs = False
    has_python = False

    # Next.js signals
    for name in ("next.config.js", "next.config.mjs", "next.config.ts"):
        if (project_root / name).is_file():
            has_nextjs = True
            break

    # Check package.json for next dependency
    pkg_json = project_root / "package.json"
    if pkg_json.is_file() and not has_nextjs:
        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8"))
            all_deps = {
                **data.get("dependencies", {}),
                **data.get("devDependencies", {}),
            }
            if "next" in all_deps:
                has_nextjs = True
        except (json.JSONDecodeError, OSError):
            pass

    # Python signals
    for name in ("pyproject.toml", "requirements.txt", "setup.py"):
        if (project_root / name).is_file():
            has_python = True
            break

    if has_nextjs and has_python:
        return "monorepo"
    if has_nextjs:
        return "nextjs"
    if has_python:
        return "python"

    # Generic React (package.json with react but no next)
    if pkg_json.is_file():
        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8"))
            all_deps = {
                **data.get("dependencies", {}),
                **data.get("devDependencies", {}),
            }
            if "react" in all_deps:
                return "react"
        except (json.JSONDecodeError, OSError):
            pass

    return "unknown"


def classify_nextjs_file(file_path: Path, project_root: Path) -> str:
    """Classify a file in a Next.js App Router project.

    Returns one of: 'server_component', 'client_component', 'server_action',
    'route_handler', 'middleware', 'layout', 'page', 'error_boundary',
    'config', 'lib'
    """
    name = file_path.name
    stem = file_path.stem

    # Config files
    if name.startswith("next.config"):
        return "config"

    # Middleware
    if stem == "middleware":
        return "middleware"

    # Route handlers
    if stem == "route":
        return "route_handler"

    # Error boundary (check before directives — error.tsx often has 'use client')
    if stem == "error":
        return "error_boundary"

    # Read first few lines for directives
    try:
        head = file_path.read_text(encoding="utf-8", errors="replace")[:500]
        first_lines = head.split("\n")[:5]
        for line in first_lines:
            stripped = line.strip()
            if stripped in (
                "'use client'", '"use client"',
                "'use client';", '"use client";',
            ):
                return "client_component"
            if stripped in (
                "'use server'", '"use server"',
                "'use server';", '"use server";',
            ):
                return "server_action"
    except OSError:
        pass

    # Layout
    if stem == "layout":
        return "layout"

    # Page
    if stem == "page":
        return "page"

    # Default for files in app/ directory → server component
    try:
        rel = file_path.relative_to(project_root)
        if rel.parts and rel.parts[0] == "app":
            return "server_component"
    except ValueError:
        pass

    return "lib"


# ── File-type context for LLM prompts ─────────────────────────────────

FILE_TYPE_CONTEXT: dict[str, dict[str, str]] = {
    "server_component": {
        "label": "SERVER COMPONENT (default in app/ directory)",
        "trust": "Server-side. Can access secrets, databases, internal APIs.",
        "risk": (
            "Props passed to Client Components cross the trust boundary. "
            "Data fetched here is serialized into the RSC payload and "
            "visible in the browser (self.__next_f)."
        ),
    },
    "client_component": {
        "label": "CLIENT COMPONENT ('use client' directive)",
        "trust": "Browser-side. Runs in untrusted environment.",
        "risk": (
            "Cannot safely contain secrets. All code and props are visible "
            "to users. Must not use dangerouslySetInnerHTML with user input."
        ),
    },
    "server_action": {
        "label": "SERVER ACTION ('use server' directive)",
        "trust": "Server-side, but publicly callable HTTP endpoint.",
        "risk": (
            "Callable without forms via crafted POST. Must validate auth "
            "and input at the function level. CSRF has had bypasses "
            "(CVE-2026-27978). Do not trust formData blindly."
        ),
    },
    "route_handler": {
        "label": "ROUTE HANDLER (route.ts/route.js)",
        "trust": "Server-side public HTTP endpoint.",
        "risk": (
            "Must check auth — middleware has been bypassed twice "
            "(CVE-2024-51479, CVE-2025-29927). Validate all input. "
            "Apply rate limiting."
        ),
    },
    "middleware": {
        "label": "MIDDLEWARE (middleware.ts)",
        "trust": "Edge runtime. Runs before routing.",
        "risk": (
            "Auth here is necessary but not sufficient — middleware "
            "bypasses exist. Verify matcher covers all protected routes "
            "including /api/. Re-check auth in handlers."
        ),
    },
    "layout": {
        "label": "LAYOUT (layout.tsx)",
        "trust": "Server Component by default.",
        "risk": "Wraps child pages. Data fetched here is shared across all child routes.",
    },
    "page": {
        "label": "PAGE (page.tsx)",
        "trust": "Server Component by default.",
        "risk": "Entry point for a route. Check props passed to Client Components.",
    },
    "error_boundary": {
        "label": "ERROR BOUNDARY (error.tsx — always client)",
        "trust": "Client Component. Handles runtime errors.",
        "risk": "Must not leak error details (stack traces, internal paths) to users.",
    },
    "config": {
        "label": "NEXT.JS CONFIGURATION (next.config.js)",
        "trust": "Build-time configuration.",
        "risk": (
            "Security headers, image remote patterns, rewrites, and "
            "experimental flags all have security implications."
        ),
    },
    "lib": {
        "label": "LIBRARY / UTILITY",
        "trust": "Depends on where it's imported.",
        "risk": "Check if this is imported by Client Components (secrets would leak).",
    },
}


# ── Boundary analysis ────────────────────────────────────────────────────

# Prop names that suggest sensitive data crossing the boundary
_SENSITIVE_PROP_NAMES = re.compile(
    r"(?:user|session|account|profile|token|auth|credentials|secret|"
    r"password|email|phone|ssn|credit.?card|payment|address|dob|"
    r"date.?of.?birth|salary|medical|health)",
    re.IGNORECASE,
)

# Matches JSX props: <Component propName={expression} />
_JSX_PROP_RE = re.compile(
    r"<([A-Z]\w+)\s+([^>]*?)/>|<([A-Z]\w+)\s+([^>]*?)>",
    re.DOTALL,
)

# Matches individual prop={value} pairs
_PROP_PAIR_RE = re.compile(
    r"(\w+)\s*=\s*\{([^}]*)\}",
)


def _is_client_component(file_path: Path) -> bool:
    """Check if a file is a Client Component ('use client' directive)."""
    try:
        head = file_path.read_text(encoding="utf-8", errors="replace")[:500]
        for line in head.split("\n")[:5]:
            stripped = line.strip()
            if stripped in (
                "'use client'", '"use client"',
                "'use client';", '"use client";',
            ):
                return True
    except OSError:
        pass
    return False


def _find_client_imports(
    content: str, project_root: Path, file_dir: Path,
) -> dict[str, Path | None]:
    """Find imports of Client Components from a Server Component.

    Returns dict of {ComponentName: resolved_path_or_None}.
    """
    results: dict[str, Path | None] = {}
    # Match: import ComponentName from './path'
    # Match: import { ComponentName } from './path'
    import_re = re.compile(
        r"import\s+(?:(\w+)|{([^}]+)})\s+from\s+['\"](\.[^'\"]+)['\"]",
    )
    for m in import_re.finditer(content):
        default_name = m.group(1)
        named = m.group(2)
        rel_path = m.group(3)

        names = []
        if default_name and default_name[0].isupper():
            names.append(default_name)
        if named:
            for n in named.split(","):
                n = n.strip().split(" as ")[-1].strip()
                if n and n[0].isupper():
                    names.append(n)

        if not names:
            continue

        # Resolve the import path
        resolved = None
        base = (file_dir / rel_path).resolve()
        for ext in ("", ".tsx", ".ts", ".jsx", ".js"):
            candidate = base.with_suffix(ext) if ext else base
            if candidate.is_file():
                resolved = candidate
                break
            # Check index file in directory
            idx = candidate / f"index{ext}" if ext else candidate / "index.tsx"
            if idx.is_file():
                resolved = idx
                break

        for name in names:
            if resolved and _is_client_component(resolved):
                results[name] = resolved
            elif resolved is None:
                # Can't resolve — include as potential boundary crossing
                results[name] = None

    return results


def analyze_boundary_crossings(
    project_root: Path,
    target_file: Path | None = None,
) -> list[dict]:
    """Find Server→Client Component prop crossings in a Next.js project.

    Returns a list of boundary crossing dicts with:
    - server_file, client_component, client_file
    - props: list of {name, value, line, sensitive}
    - risk_level: 'high' if sensitive props, 'medium' otherwise
    """
    crossings: list[dict] = []
    app_dir = project_root / "app"

    if target_file:
        files = [target_file]
    elif app_dir.is_dir():
        files = [
            f for f in app_dir.rglob("*")
            if f.suffix in (".tsx", ".ts", ".jsx", ".js")
            and not _is_client_component(f)
            and f.name != "middleware.ts"
        ]
    else:
        return []

    for server_file in files:
        try:
            content = server_file.read_text(
                encoding="utf-8", errors="replace",
            )
        except OSError:
            continue

        # Skip client components
        if "'use client'" in content[:200] or '"use client"' in content[:200]:
            continue

        client_imports = _find_client_imports(
            content, project_root, server_file.parent,
        )
        if not client_imports:
            continue

        # Find JSX usage: <ComponentName prop={value} />
        # Use regex to find component tags, handling multiline JSX
        for component_name, client_path in client_imports.items():
            tag_re = re.compile(
                rf"<{re.escape(component_name)}\s+(.*?)/?>",
                re.DOTALL,
            )
            for tag_m in tag_re.finditer(content):
                props_str = tag_m.group(1)
                # Calculate line number from position
                line_num = content[:tag_m.start()].count("\n") + 1

                # Extract props
                props = []
                for prop_m in _PROP_PAIR_RE.finditer(props_str):
                    prop_name = prop_m.group(1)
                    prop_value = prop_m.group(2).strip()
                    is_sensitive = bool(
                        _SENSITIVE_PROP_NAMES.search(prop_name)
                        or _SENSITIVE_PROP_NAMES.search(prop_value)
                    )
                    props.append({
                        "name": prop_name,
                        "value": prop_value,
                        "line": line_num,
                        "sensitive": is_sensitive,
                    })

                if not props:
                    continue

                has_sensitive = any(p["sensitive"] for p in props)
                crossings.append({
                    "server_file": str(server_file),
                    "client_component": component_name,
                    "client_file": str(client_path) if client_path else None,
                    "line": line_num,
                    "props": props,
                    "risk_level": "high" if has_sensitive else "medium",
                })

    return crossings
