"""Tests for Next.js configuration security scanner."""

from __future__ import annotations

from owasp_scanner.core.config_scanner import detect_framework, scan_nextjs_config


class TestScanNextjsConfig:
    def _config(self, **extras: str) -> str:
        """Generate a secure next.config.js with optional overrides."""
        base = (
            "/** @type {import('next').NextConfig} */\n"
            "module.exports = {\n"
            "  reactStrictMode: true,\n"
            "  poweredByHeader: false,\n"
            "  images: {\n"
            "    remotePatterns: [{ hostname: 'cdn.example.com' }],\n"
            "  },\n"
            "  async headers() {\n"
            "    return [{ source: '/(.*)', headers: [\n"
            "      { key: 'X-Frame-Options', value: 'DENY' },\n"
            "    ]}]\n"
            "  },\n"
            "}\n"
        )
        for key, val in extras.items():
            base = base.replace(f"placeholder_{key}", val)
        return base

    def test_secure_config_minimal_issues(self):
        checks = scan_nextjs_config(self._config())
        # poweredByHeader: false is set, headers exist, etc.
        # May still flag some items depending on strictness
        severe = [c for c in checks if c.severity in ("critical", "high")]
        assert len(severe) == 0

    def test_wildcard_image_hostname(self):
        config = "module.exports = { images: { remotePatterns: [{ hostname: '**' }] } }"
        checks = scan_nextjs_config(config)
        img_checks = [
            c for c in checks
            if "image" in c.setting.lower() or "image" in c.title.lower()
        ]
        assert len(img_checks) >= 1

    def test_missing_headers(self):
        config = "module.exports = { reactStrictMode: true }"
        checks = scan_nextjs_config(config)
        header_checks = [c for c in checks if "header" in c.title.lower()]
        assert len(header_checks) >= 1

    def test_rewrite_to_internal(self):
        config = """
module.exports = {
  async rewrites() {
    return [{ source: '/api/:path*', destination: 'http://localhost:3001/:path*' }]
  }
}
"""
        checks = scan_nextjs_config(config)
        rewrite_checks = [c for c in checks if "rewrite" in c.title.lower()]
        assert len(rewrite_checks) >= 1

    def test_powered_by_header_true(self):
        config = "module.exports = { poweredByHeader: true }"
        checks = scan_nextjs_config(config)
        powered = [c for c in checks if "poweredBy" in c.setting]
        assert len(powered) >= 1

    def test_strict_mode_false(self):
        config = "module.exports = { reactStrictMode: false }"
        checks = scan_nextjs_config(config)
        strict = [c for c in checks if "reactStrictMode" in c.setting]
        assert len(strict) >= 1

    def test_rewrite_to_private_ip(self):
        config = """
module.exports = {
  async rewrites() {
    return [{ source: '/internal/:path*', destination: 'http://192.168.1.100/:path*' }]
  }
}
"""
        checks = scan_nextjs_config(config)
        rewrite_checks = [c for c in checks if "rewrite" in c.title.lower()]
        assert len(rewrite_checks) >= 1


class TestDetectNextjsFramework:
    def test_detects_nextjs_config(self):
        content = (
            "/** @type {import('next').NextConfig} */\n"
            "module.exports = { remotePatterns: [] }\n"
        )
        assert detect_framework(content) == "nextjs"

    def test_detects_nextjs_imports(self):
        content = (
            "import { NextResponse } from 'next/server'\n"
            "import { NextRequest } from 'next/server'\n"
        )
        assert detect_framework(content) == "nextjs"

    def test_does_not_detect_plain_js(self):
        content = "const x = 1;\nconsole.log(x);\n"
        assert detect_framework(content) == "unknown"
