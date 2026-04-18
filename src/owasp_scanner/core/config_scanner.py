"""Django and FastAPI configuration security scanner.

Checks deployment settings against the OWASP Top 10 A02 (Security Misconfiguration)
checklist: HSTS, CSP, cookie flags, CSRF, debug mode, and more.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class ConfigCheck:
    setting: str
    expected: str
    actual: str
    severity: str
    title: str
    description: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "setting": self.setting,
            "expected": self.expected,
            "actual": self.actual,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
        }


def _find_setting(content: str, name: str) -> str | None:
    """Extract a Django setting value from source text."""
    m = re.search(rf"^\s*{name}\s*=\s*(.+?)$", content, re.MULTILINE)
    if m:
        return m.group(1).strip()
    return None


def _setting_is_true(content: str, name: str) -> bool:
    val = _find_setting(content, name)
    return val is not None and val.strip().rstrip(",") == "True"


def _setting_is_false(content: str, name: str) -> bool:
    val = _find_setting(content, name)
    return val is not None and val.strip().rstrip(",") == "False"


def _setting_exists(content: str, name: str) -> bool:
    return _find_setting(content, name) is not None


def scan_django_settings(content: str) -> list[ConfigCheck]:
    """Scan Django settings.py content for security misconfigurations."""
    checks: list[ConfigCheck] = []

    # DEBUG
    if _setting_is_true(content, "DEBUG"):
        checks.append(ConfigCheck(
            setting="DEBUG",
            expected="False",
            actual="True",
            severity="critical",
            title="DEBUG mode enabled",
            description="DEBUG = True exposes stack traces, SQL queries, and internal paths to users.",
        ))

    # HSTS
    val = _find_setting(content, "SECURE_HSTS_SECONDS")
    if val is None or val.strip().rstrip(",") == "0":
        checks.append(ConfigCheck(
            setting="SECURE_HSTS_SECONDS",
            expected=">= 31536000 (1 year)",
            actual=val or "not set",
            severity="high",
            title="HSTS not configured",
            description=(
                "HTTP Strict Transport Security not enabled. Browsers will allow "
                "HTTP connections, enabling downgrade attacks."
            ),
        ))

    # SSL redirect
    if not _setting_is_true(content, "SECURE_SSL_REDIRECT"):
        checks.append(ConfigCheck(
            setting="SECURE_SSL_REDIRECT",
            expected="True",
            actual=_find_setting(content, "SECURE_SSL_REDIRECT") or "not set",
            severity="high",
            title="SSL redirect not enabled",
            description="HTTP requests are not automatically redirected to HTTPS.",
        ))

    # Session cookie secure
    if not _setting_is_true(content, "SESSION_COOKIE_SECURE"):
        checks.append(ConfigCheck(
            setting="SESSION_COOKIE_SECURE",
            expected="True",
            actual=_find_setting(content, "SESSION_COOKIE_SECURE") or "not set",
            severity="high",
            title="Session cookie not marked Secure",
            description="Session cookies can be sent over HTTP, exposing them to interception.",
        ))

    # Session cookie httponly
    if _setting_is_false(content, "SESSION_COOKIE_HTTPONLY"):
        checks.append(ConfigCheck(
            setting="SESSION_COOKIE_HTTPONLY",
            expected="True (default)",
            actual="False",
            severity="high",
            title="Session cookie HttpOnly disabled",
            description="Session cookies accessible to JavaScript, enabling XSS-based session theft.",
        ))

    # CSRF cookie secure
    if not _setting_is_true(content, "CSRF_COOKIE_SECURE"):
        checks.append(ConfigCheck(
            setting="CSRF_COOKIE_SECURE",
            expected="True",
            actual=_find_setting(content, "CSRF_COOKIE_SECURE") or "not set",
            severity="medium",
            title="CSRF cookie not marked Secure",
            description="CSRF token can be sent over HTTP.",
        ))

    # X-Frame-Options
    if not _setting_exists(content, "X_FRAME_OPTIONS"):
        checks.append(ConfigCheck(
            setting="X_FRAME_OPTIONS",
            expected="'DENY' or 'SAMEORIGIN'",
            actual="not set",
            severity="medium",
            title="X-Frame-Options not configured",
            description="Page can be embedded in iframes, enabling clickjacking attacks.",
        ))

    # Content type nosniff
    if not _setting_is_true(content, "SECURE_CONTENT_TYPE_NOSNIFF"):
        checks.append(ConfigCheck(
            setting="SECURE_CONTENT_TYPE_NOSNIFF",
            expected="True",
            actual=_find_setting(content, "SECURE_CONTENT_TYPE_NOSNIFF") or "not set",
            severity="medium",
            title="Content-Type nosniff not enabled",
            description="Browsers may MIME-sniff responses, potentially executing malicious content.",
        ))

    # ALLOWED_HOSTS
    val = _find_setting(content, "ALLOWED_HOSTS")
    if val and "'*'" in val or val and '"*"' in val:
        checks.append(ConfigCheck(
            setting="ALLOWED_HOSTS",
            expected="Specific hostnames",
            actual=val,
            severity="high",
            title="ALLOWED_HOSTS accepts all hostnames",
            description="Wildcard ALLOWED_HOSTS enables host header attacks.",
        ))

    # SECRET_KEY hardcoded
    val = _find_setting(content, "SECRET_KEY")
    if val and not any(kw in val for kw in ("os.environ", "os.getenv", "config(", "env(")):
        if val.startswith(("'", '"')) and len(val) > 10:
            checks.append(ConfigCheck(
                setting="SECRET_KEY",
                expected="Loaded from environment",
                actual="Hardcoded in source",
                severity="high",
                title="SECRET_KEY hardcoded",
                description="If source is leaked, attackers can forge sessions and CSRF tokens.",
            ))

    # CSRF middleware
    if "CsrfViewMiddleware" not in content and "csrf" not in content.lower():
        checks.append(ConfigCheck(
            setting="MIDDLEWARE (CSRF)",
            expected="django.middleware.csrf.CsrfViewMiddleware in MIDDLEWARE",
            actual="Not found",
            severity="high",
            title="CSRF middleware may be missing",
            description="Without CSRF protection, attackers can forge requests on behalf of users.",
        ))

    return checks


def scan_fastapi_config(content: str) -> list[ConfigCheck]:
    """Scan FastAPI application code for security misconfigurations."""
    checks: list[ConfigCheck] = []

    # CORS allow all origins
    if re.search(r"allow_origins\s*=\s*\[.*?['\"]?\*['\"]?.*?\]", content, re.DOTALL):
        checks.append(ConfigCheck(
            setting="CORSMiddleware.allow_origins",
            expected="Specific origins",
            actual='["*"]',
            severity="high",
            title="CORS allows all origins",
            description="Any website can make authenticated requests to your API.",
        ))

    # allow_credentials with allow_origins=*
    if (
        re.search(r"allow_credentials\s*=\s*True", content)
        and re.search(r"allow_origins\s*=\s*\[.*?\*.*?\]", content, re.DOTALL)
    ):
        checks.append(ConfigCheck(
            setting="CORSMiddleware",
            expected="Credentials not allowed with wildcard origins",
            actual="allow_credentials=True with allow_origins=['*']",
            severity="critical",
            title="CORS credentials with wildcard origins",
            description=(
                "allow_credentials=True with allow_origins=['*'] allows any site "
                "to make authenticated requests with cookies."
            ),
        ))

    # No TrustedHostMiddleware
    if "TrustedHostMiddleware" not in content and "trusted_host" not in content.lower():
        if "FastAPI" in content or "app = " in content:
            checks.append(ConfigCheck(
                setting="TrustedHostMiddleware",
                expected="TrustedHostMiddleware configured",
                actual="Not found",
                severity="medium",
                title="No TrustedHostMiddleware",
                description="Without host validation, the app accepts requests for any hostname.",
            ))

    return checks


def scan_general_config(content: str) -> list[ConfigCheck]:
    """General security checks for any Python application or config file."""
    checks: list[ConfigCheck] = []

    # Debug/dev mode flags
    if re.search(r"(?:DEBUG|DEV_MODE|DEVELOPMENT)\s*=\s*True", content, re.IGNORECASE):
        checks.append(ConfigCheck(
            setting="DEBUG/DEV_MODE",
            expected="False in production",
            actual="True",
            severity="high",
            title="Debug/development mode enabled",
            description="Debug mode may expose internal details to users.",
        ))

    # Hardcoded secrets patterns
    for pattern, label in [
        (r"""(?:SECRET|KEY|TOKEN|PASSWORD|PASSWD|API_KEY)\s*=\s*['"][^'"]{8,}['"]""", "Secret value"),
        (r"""(?:mysql|postgresql|mongodb|redis)://\S+:\S+@""", "Database connection string"),
    ]:
        if re.search(pattern, content, re.IGNORECASE):
            checks.append(ConfigCheck(
                setting=label,
                expected="Loaded from environment or secrets manager",
                actual="Hardcoded in source",
                severity="high",
                title=f"Hardcoded {label.lower()} detected",
                description="Hardcoded credentials are exposed if source is leaked.",
            ))

    # Open ports without binding
    if re.search(r"""['"]?\d{4,5}:\d{4,5}['"]?""", content):
        checks.append(ConfigCheck(
            setting="Port mapping",
            expected="Bound to 127.0.0.1 or internal network",
            actual="May be exposed",
            severity="medium",
            title="Port mapping detected — verify binding",
            description="Port mappings without localhost binding may expose services to the internet.",
        ))

    return checks


def detect_framework(content: str) -> str:
    """Detect whether content is Django settings, FastAPI, Flask, or MCP server code."""
    django_signals = [
        "INSTALLED_APPS", "MIDDLEWARE", "ROOT_URLCONF",
        "DATABASES", "TEMPLATES", "STATIC_URL",
    ]
    fastapi_signals = [
        "FastAPI(", "from fastapi", "app = FastAPI",
        "@app.get", "@app.post", "APIRouter",
    ]
    flask_signals = [
        "Flask(__name__)", "from flask", "@app.route",
    ]
    mcp_signals = [
        "FastMCP(", "from mcp", "@mcp.tool()", "mcp.run()",
        "from mcp.server", "@mcp.tool",
    ]

    scores = {
        "django": sum(1 for s in django_signals if s in content),
        "fastapi": sum(1 for s in fastapi_signals if s in content),
        "flask": sum(1 for s in flask_signals if s in content),
        "mcp": sum(1 for s in mcp_signals if s in content),
    }

    best = max(scores, key=scores.get)
    if scores[best] > 0:
        return best
    return "unknown"
