"""Tests for Django and FastAPI configuration security scanner."""

from __future__ import annotations

from owasp_scanner.core.config_scanner import (
    detect_framework,
    scan_django_settings,
    scan_fastapi_config,
)

# ── Django Settings ─────────────────────────────────────────────────────


class TestDjangoSettings:
    def _settings(self, **overrides) -> str:
        """Generate a Django settings file with defaults that can be overridden."""
        defaults = {
            "DEBUG": "False",
            "SECURE_HSTS_SECONDS": "31536000",
            "SECURE_SSL_REDIRECT": "True",
            "SESSION_COOKIE_SECURE": "True",
            "SESSION_COOKIE_HTTPONLY": "True",
            "CSRF_COOKIE_SECURE": "True",
            "X_FRAME_OPTIONS": "'DENY'",
            "SECURE_CONTENT_TYPE_NOSNIFF": "True",
            "ALLOWED_HOSTS": "['example.com']",
            "SECRET_KEY": "os.environ['SECRET_KEY']",
        }
        defaults.update(overrides)
        lines = [f"{k} = {v}" for k, v in defaults.items()]
        lines.append(
            "MIDDLEWARE = ['django.middleware.csrf.CsrfViewMiddleware']"
        )
        return "\n".join(lines)

    def test_secure_settings_no_issues(self):
        checks = scan_django_settings(self._settings())
        assert len(checks) == 0

    def test_debug_true(self):
        checks = scan_django_settings(self._settings(DEBUG="True"))
        debug_checks = [c for c in checks if c.setting == "DEBUG"]
        assert len(debug_checks) == 1
        assert debug_checks[0].severity == "critical"

    def test_missing_hsts(self):
        content = self._settings()
        content = content.replace("SECURE_HSTS_SECONDS = 31536000\n", "")
        checks = scan_django_settings(content)
        hsts = [c for c in checks if c.setting == "SECURE_HSTS_SECONDS"]
        assert len(hsts) == 1

    def test_hsts_zero(self):
        checks = scan_django_settings(self._settings(SECURE_HSTS_SECONDS="0"))
        hsts = [c for c in checks if c.setting == "SECURE_HSTS_SECONDS"]
        assert len(hsts) == 1

    def test_missing_ssl_redirect(self):
        checks = scan_django_settings(
            self._settings(SECURE_SSL_REDIRECT="False")
        )
        ssl = [c for c in checks if c.setting == "SECURE_SSL_REDIRECT"]
        assert len(ssl) == 1

    def test_session_cookie_not_secure(self):
        checks = scan_django_settings(
            self._settings(SESSION_COOKIE_SECURE="False")
        )
        cookie = [c for c in checks if c.setting == "SESSION_COOKIE_SECURE"]
        assert len(cookie) == 1

    def test_session_cookie_httponly_disabled(self):
        checks = scan_django_settings(
            self._settings(SESSION_COOKIE_HTTPONLY="False")
        )
        httponly = [
            c for c in checks if c.setting == "SESSION_COOKIE_HTTPONLY"
        ]
        assert len(httponly) == 1

    def test_csrf_cookie_not_secure(self):
        checks = scan_django_settings(
            self._settings(CSRF_COOKIE_SECURE="False")
        )
        csrf = [c for c in checks if c.setting == "CSRF_COOKIE_SECURE"]
        assert len(csrf) == 1

    def test_allowed_hosts_wildcard(self):
        checks = scan_django_settings(
            self._settings(ALLOWED_HOSTS="['*']")
        )
        hosts = [c for c in checks if c.setting == "ALLOWED_HOSTS"]
        assert len(hosts) == 1

    def test_hardcoded_secret_key(self):
        checks = scan_django_settings(
            self._settings(SECRET_KEY="'django-insecure-abc123xyz'")
        )
        secret = [c for c in checks if c.setting == "SECRET_KEY"]
        assert len(secret) == 1

    def test_env_secret_key_ok(self):
        checks = scan_django_settings(
            self._settings(SECRET_KEY="os.environ['DJANGO_SECRET_KEY']")
        )
        secret = [c for c in checks if c.setting == "SECRET_KEY"]
        assert len(secret) == 0

    def test_insecure_settings_many_issues(self):
        """A completely insecure settings file should flag many issues."""
        content = """
DEBUG = True
ALLOWED_HOSTS = ['*']
SECRET_KEY = 'super-insecure-key-here'
"""
        checks = scan_django_settings(content)
        assert len(checks) >= 5  # DEBUG, HSTS, SSL, cookies, SECRET_KEY, etc.


# ── FastAPI Config ──────────────────────────────────────────────────────


class TestFastAPIConfig:
    def test_cors_allow_all(self):
        content = """
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"])
"""
        checks = scan_fastapi_config(content)
        cors = [c for c in checks if "CORS" in c.title]
        assert len(cors) >= 1

    def test_cors_specific_origins_ok(self):
        content = """
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://example.com"],
)
"""
        checks = scan_fastapi_config(content)
        cors = [c for c in checks if "CORS allows all" in c.title]
        assert len(cors) == 0

    def test_cors_credentials_with_wildcard(self):
        content = """
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
)
"""
        checks = scan_fastapi_config(content)
        cred = [c for c in checks if "credentials" in c.title.lower()]
        assert len(cred) == 1
        assert cred[0].severity == "critical"

    def test_missing_trusted_host(self):
        content = """
from fastapi import FastAPI
app = FastAPI()
"""
        checks = scan_fastapi_config(content)
        host = [c for c in checks if "TrustedHost" in c.title]
        assert len(host) == 1


# ── Framework Detection ─────────────────────────────────────────────────


class TestFrameworkDetection:
    def test_detects_django(self):
        content = """
INSTALLED_APPS = ['django.contrib.admin']
MIDDLEWARE = ['django.middleware.common.CommonMiddleware']
ROOT_URLCONF = 'myapp.urls'
DATABASES = {}
"""
        assert detect_framework(content) == "django"

    def test_detects_fastapi(self):
        content = """
from fastapi import FastAPI
app = FastAPI()

@app.get("/")
async def root():
    return {"hello": "world"}
"""
        assert detect_framework(content) == "fastapi"

    def test_unknown_framework(self):
        content = "print('hello world')"
        assert detect_framework(content) == "unknown"
