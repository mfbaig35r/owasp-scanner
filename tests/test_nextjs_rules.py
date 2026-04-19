"""Tests for Next.js regex rules — positive + negative match for each rule."""

from __future__ import annotations

from owasp_scanner.core.scanner import scan_file_content
from owasp_scanner.rules.patterns import get_rules


def _scan(code: str, rule_id: str, filename: str = "test.tsx") -> list:
    rules = [r for r in get_rules() if r.id == rule_id]
    assert rules, f"Rule {rule_id} not found"
    return scan_file_content(code, filename, rules=rules)


# ── A01: Broken Access Control ──────────────────────────────────────────


class TestJSA01:
    def test_001_route_handler_matches(self):
        code = "export async function GET(request: Request) { return Response.json({}) }"
        assert len(_scan(code, "JS-A01-001", filename="route.ts")) > 0

    def test_001_route_handler_no_match_on_page(self):
        code = "export async function GET(request: Request) {}"
        assert len(_scan(code, "JS-A01-001", filename="page.tsx")) == 0

    def test_002_server_action_matches(self):
        code = "'use server'\nexport async function submit() {}"
        assert len(_scan(code, "JS-A01-002")) > 0

    def test_002_no_directive_no_match(self):
        code = "export async function submit() {}"
        assert len(_scan(code, "JS-A01-002")) == 0

    def test_003_mass_assignment_matches(self):
        code = "const data = Object.fromEntries(formData)"
        assert len(_scan(code, "JS-A01-003")) > 0

    def test_003_explicit_fields_no_match(self):
        code = "const name = formData.get('name')"
        assert len(_scan(code, "JS-A01-003")) == 0

    def test_004_open_redirect_matches(self):
        code = "redirect(url)"
        assert len(_scan(code, "JS-A01-004")) > 0

    def test_004_static_redirect_no_match(self):
        code = "redirect('/dashboard')"
        assert len(_scan(code, "JS-A01-004")) == 0

    def test_005_revalidate_with_var_matches(self):
        code = "revalidatePath(userPath)"
        assert len(_scan(code, "JS-A01-005")) > 0

    def test_005_revalidate_static_no_match(self):
        code = "revalidatePath('/dashboard')"
        assert len(_scan(code, "JS-A01-005")) == 0


# ── A02: Security Misconfiguration ──────────────────────────────────────


class TestJSA02:
    def test_001_next_public_secret_matches(self):
        code = "NEXT_PUBLIC_SECRET_KEY=abc123"
        assert len(_scan(code, "JS-A02-001", filename=".env")) > 0

    def test_001_next_public_normal_no_match(self):
        code = "NEXT_PUBLIC_APP_NAME=myapp"
        assert len(_scan(code, "JS-A02-001", filename=".env")) == 0

    def test_002_wildcard_hostname_matches(self):
        code = "images: { remotePatterns: [{ hostname: '**' }] }"
        assert len(_scan(code, "JS-A02-002", filename="next.config.js")) > 0

    def test_002_specific_hostname_no_match(self):
        code = "images: { remotePatterns: [{ hostname: 'cdn.example.com' }] }"
        assert len(_scan(code, "JS-A02-002", filename="next.config.js")) == 0

    def test_003_strict_mode_false_matches(self):
        code = "reactStrictMode: false"
        assert len(_scan(code, "JS-A02-003", filename="next.config.js")) > 0

    def test_003_strict_mode_true_no_match(self):
        code = "reactStrictMode: true"
        assert len(_scan(code, "JS-A02-003", filename="next.config.js")) == 0

    def test_005_internal_rewrite_matches(self):
        code = "destination: 'http://localhost:3001/api'"
        assert len(_scan(code, "JS-A02-005", filename="next.config.js")) > 0

    def test_005_external_rewrite_no_match(self):
        code = "destination: 'https://api.example.com'"
        assert len(_scan(code, "JS-A02-005", filename="next.config.js")) == 0


# ── A04: Cryptographic Failures ─────────────────────────────────────────


class TestJSA04:
    def test_001_math_random_matches(self):
        code = "const id = Math.random().toString(36)"
        assert len(_scan(code, "JS-A04-001")) > 0

    def test_001_crypto_no_match(self):
        code = "const id = crypto.randomUUID()"
        assert len(_scan(code, "JS-A04-001")) == 0

    def test_002_cookie_set_matches(self):
        code = "cookies().set('session', token)"
        assert len(_scan(code, "JS-A04-002")) > 0


# ── A05: Injection ──────────────────────────────────────────────────────


class TestJSA05:
    def test_001_dangerous_inner_html_matches(self):
        code = '<div dangerouslySetInnerHTML={{ __html: content }} />'
        assert len(_scan(code, "JS-A05-001")) > 0

    def test_001_text_content_no_match(self):
        code = "<div>{content}</div>"
        assert len(_scan(code, "JS-A05-001")) == 0

    def test_002_inner_html_assignment_matches(self):
        code = "element.innerHTML = userInput"
        assert len(_scan(code, "JS-A05-002")) > 0

    def test_003_eval_matches(self):
        code = "eval(userInput)"
        assert len(_scan(code, "JS-A05-003")) > 0

    def test_003_new_function_matches(self):
        code = "const fn = new Function('return ' + code)"
        assert len(_scan(code, "JS-A05-003")) > 0

    def test_003_json_parse_no_match(self):
        code = "JSON.parse(data)"
        assert len(_scan(code, "JS-A05-003")) == 0

    def test_004_prisma_raw_unsafe_matches(self):
        code = "prisma.$queryRawUnsafe(`SELECT * FROM ${table}`)"
        assert len(_scan(code, "JS-A05-004")) > 0

    def test_004_prisma_raw_safe_no_match(self):
        code = "prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`"
        assert len(_scan(code, "JS-A05-004")) == 0

    def test_005_prisma_raw_string_concat_matches(self):
        code = """prisma.$queryRaw('SELECT * FROM ' + table)"""
        assert len(_scan(code, "JS-A05-005")) > 0

    def test_005_prisma_raw_template_no_match(self):
        code = "prisma.$queryRaw`SELECT * FROM users`"
        assert len(_scan(code, "JS-A05-005")) == 0

    def test_006_exec_template_matches(self):
        code = "exec(`rm -rf ${path}`)"
        assert len(_scan(code, "JS-A05-006")) > 0

    def test_006_exec_file_no_match(self):
        code = "execFile('rm', ['-rf', path])"
        assert len(_scan(code, "JS-A05-006")) == 0

    def test_007_document_write_matches(self):
        code = "document.write(html)"
        assert len(_scan(code, "JS-A05-007")) > 0

    def test_008_router_push_var_matches(self):
        code = "router.push(url)"
        assert len(_scan(code, "JS-A05-008")) > 0

    def test_008_router_push_static_no_match(self):
        code = "router.push('/dashboard')"
        assert len(_scan(code, "JS-A05-008")) == 0


# ── A06: Insecure Design ───────────────────────────────────────────────


class TestJSA06:
    def test_001_middleware_missing_api_matches(self):
        code = "export const config = { matcher: ['/dashboard/:path*'] }"
        assert len(_scan(code, "JS-A06-001", filename="middleware.ts")) > 0

    def test_001_middleware_with_api_no_match(self):
        code = "export const config = { matcher: ['/dashboard/:path*', '/api/:path*'] }"
        assert len(_scan(code, "JS-A06-001", filename="middleware.ts")) == 0


# ── A07: Authentication Failures ────────────────────────────────────────


class TestJSA07:
    def test_001_db_connection_string_matches(self):
        code = 'const url = "postgresql://user:pass@localhost:5432/db"'
        assert len(_scan(code, "JS-A07-001")) > 0

    def test_001_env_var_no_match(self):
        code = "const url = process.env.DATABASE_URL"
        assert len(_scan(code, "JS-A07-001")) == 0

    def test_002_hardcoded_api_key_matches(self):
        code = 'const api_key = "sk-proj-abc123def456ghi789"'
        assert len(_scan(code, "JS-A07-002")) > 0

    def test_002_env_key_no_match(self):
        code = "const api_key = process.env.API_KEY"
        assert len(_scan(code, "JS-A07-002")) == 0


# ── A10: Exception Handling ─────────────────────────────────────────────


class TestJSA10:
    def test_001_empty_catch_matches(self):
        code = "try { doSomething() } catch (e) {}"
        assert len(_scan(code, "JS-A10-001")) > 0

    def test_001_catch_with_handling_no_match(self):
        code = "try { doSomething() } catch (e) { console.error(e) }"
        assert len(_scan(code, "JS-A10-001")) == 0

    def test_002_error_message_leaked_matches(self):
        code = "return Response.json({ error: err.message })"
        assert len(_scan(code, "JS-A10-002")) > 0

    def test_002_generic_error_no_match(self):
        code = "return Response.json({ error: 'Internal server error' })"
        assert len(_scan(code, "JS-A10-002")) == 0
