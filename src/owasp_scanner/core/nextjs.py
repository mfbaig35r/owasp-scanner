"""Next.js App Router project detection and file-type classification."""

from __future__ import annotations

import json
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
