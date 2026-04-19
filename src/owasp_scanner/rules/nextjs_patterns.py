"""Next.js App Router security rules for the OWASP Top 10 (2025).

CVE-anchored rule set targeting middleware bypass, Server Action misuse,
RSC data leakage, cache poisoning, and injection patterns specific to
the React/Next.js ecosystem.
"""

from __future__ import annotations

import re

from owasp_scanner.rules.patterns import Rule

_FLAGS = re.IGNORECASE | re.MULTILINE

# file_glob helpers — two globs per rule to cover .ts/.js and .tsx/.jsx
# without matching .json (which *.[jt]s* would)
_JS_GLOBS = ("*.[jt]s", "*.[jt]sx")


def _js_rules(**kwargs: object) -> list[Rule]:
    """Create a Rule for both .ts/.js and .tsx/.jsx file globs."""
    return [Rule(**kwargs, file_glob=g) for g in _JS_GLOBS]  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

NEXTJS_RULES: list[Rule] = []

# ── A01: Broken Access Control ─────────────────────────────────────────

# JS-A01-001: Route handler without auth (CVE-2024-51479, CVE-2025-29927)
NEXTJS_RULES.append(Rule(
    id="JS-A01-001",
    owasp_category="A01",
    severity="high",
    title="Route handler without auth check",
    description=(
        "Next.js route handler exports a public HTTP endpoint. Without auth "
        "checks, any user can access it. Middleware-only auth has been bypassed "
        "twice (CVE-2024-51479, CVE-2025-29927) — re-check auth in the handler."
    ),
    pattern=re.compile(
        r"export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|DELETE|PATCH)\s*\(",
        _FLAGS,
    ),
    file_glob="route.*",
    suggested_fix="Add auth check: const session = await requireAuth(); if (!session) return new Response('Unauthorized', {status: 401})",
))

# JS-A01-002: Server Action without auth (CVE-2026-27978)
NEXTJS_RULES.extend(_js_rules(
    id="JS-A01-002",
    owasp_category="A01",
    severity="high",
    title="Server Action file detected — verify auth in each action",
    description=(
        "Files with 'use server' expose public HTTP endpoints callable without "
        "forms. CSRF protection has had bypasses (CVE-2026-27978). Every Server "
        "Action must validate auth and input at the function level."
    ),
    pattern=re.compile(r"""^['"]use server['"]""", _FLAGS),
    suggested_fix="Add auth check at the start of each exported function: const user = await requireUser()",
))

# JS-A01-003: Mass assignment via Object.fromEntries
NEXTJS_RULES.extend(_js_rules(
    id="JS-A01-003",
    owasp_category="A01",
    severity="critical",
    title="Mass assignment via Object.fromEntries(formData)",
    description=(
        "Spreading formData directly into an ORM update allows attackers to set "
        "privileged fields (role, isAdmin, teamId) by adding hidden form fields."
    ),
    pattern=re.compile(r"Object\.fromEntries\s*\(\s*(?:formData|form)", _FLAGS),
    suggested_fix="Extract specific fields: const name = formData.get('name'); await db.update({data: {name}})",
))

# JS-A01-004: Open redirect via redirect()
NEXTJS_RULES.extend(_js_rules(
    id="JS-A01-004",
    owasp_category="A01",
    severity="high",
    title="Potential open redirect via redirect()",
    description=(
        "redirect() accepts absolute external URLs. If the destination comes "
        "from user input (searchParams, formData), attackers can redirect "
        "users to malicious sites."
    ),
    pattern=re.compile(r"redirect\s*\(\s*(?!['\"\/])\w", _FLAGS),
    suggested_fix="Validate destination: const safe = normalizeLocalPath(url); redirect(safe)",
))

# JS-A01-005: Cache poisoning via revalidatePath with user input (CVE-2025-49005)
NEXTJS_RULES.extend(_js_rules(
    id="JS-A01-005",
    owasp_category="A01",
    severity="medium",
    title="revalidatePath/revalidateTag with potentially user-controlled input",
    description=(
        "Passing user-controlled values to revalidatePath or revalidateTag can "
        "poison the cache. CVE-2025-49005 showed cache confusion between HTML "
        "and RSC payloads is security-sensitive."
    ),
    pattern=re.compile(r"revalidate(?:Path|Tag)\s*\(\s*(?!['\"]\s*[/\w])[^)]+\)", _FLAGS),
    suggested_fix="Map user input to known routes: const path = mapToKnownRoute(input); revalidatePath(path)",
))

# ── A02: Security Misconfiguration ─────────────────────────────────────

# JS-A02-001: NEXT_PUBLIC_ env var with secret name (scans all files)
NEXTJS_RULES.append(Rule(
    id="JS-A02-001",
    owasp_category="A02",
    severity="critical",
    title="NEXT_PUBLIC_ environment variable may expose a secret",
    description=(
        "NEXT_PUBLIC_ variables are embedded in the client bundle and visible "
        "to all users. Variable names containing SECRET, KEY, TOKEN, or PASSWORD "
        "suggest this is a secret that should not be public."
    ),
    pattern=re.compile(r"NEXT_PUBLIC_\w*(?:SECRET|KEY|TOKEN|PASSWORD|PRIVATE|AUTH)\w*", _FLAGS),
    file_glob="*",
    suggested_fix="Remove NEXT_PUBLIC_ prefix and access server-side only, or confirm this is a publishable key.",
))

# JS-A02-002: Wildcard image hostname
NEXTJS_RULES.append(Rule(
    id="JS-A02-002",
    owasp_category="A02",
    severity="high",
    title="Wildcard image hostname enables SSRF via next/image",
    description=(
        "Setting hostname to '**' in images.remotePatterns allows next/image "
        "to fetch from any URL. Attackers can use /_next/image as an SSRF proxy."
    ),
    pattern=re.compile(r"""hostname\s*:\s*['"][*]{2}['"]"""),
    file_glob="next.config*",
    suggested_fix="Restrict to specific hostnames: hostname: 'cdn.example.com'",
))

# JS-A02-005: Rewrites to internal services
NEXTJS_RULES.append(Rule(
    id="JS-A02-005",
    owasp_category="A02",
    severity="high",
    title="Rewrite proxying to internal service",
    description=(
        "Rewrites that proxy to localhost or private IPs can expose internal "
        "services to the internet if the Next.js server is publicly accessible."
    ),
    pattern=re.compile(
        r"destination\s*:\s*['\"]https?://(?:localhost|127\.0\.0\.1|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)",
        _FLAGS,
    ),
    file_glob="next.config*",
    suggested_fix="Use API routes with auth instead of raw rewrites to internal services.",
))

# ── A04: Cryptographic Failures ────────────────────────────────────────

# JS-A04-001: Math.random for tokens
NEXTJS_RULES.extend(_js_rules(
    id="JS-A04-001",
    owasp_category="A04",
    severity="high",
    title="Math.random() used for security-sensitive value",
    description="Math.random() is not cryptographically secure. Use crypto.randomUUID() or crypto.getRandomValues().",
    pattern=re.compile(r"Math\.random\s*\(\s*\)", _FLAGS),
    suggested_fix="Use crypto.randomUUID() or crypto.getRandomValues(new Uint8Array(32))",
))

# JS-A04-002: Cookies without secure flags
NEXTJS_RULES.extend(_js_rules(
    id="JS-A04-002",
    owasp_category="A04",
    severity="high",
    title="Cookie set without security flags",
    description=(
        "cookies().set() without httpOnly, secure, and sameSite flags allows "
        "session hijacking via XSS or cross-site request forgery."
    ),
    pattern=re.compile(r"cookies\(\)\s*\.set\s*\(\s*['\"][^'\"]+['\"]", _FLAGS),
    suggested_fix="Add flags: cookies().set('name', value, {httpOnly: true, secure: true, sameSite: 'lax'})",
))

# ── A05: Injection ─────────────────────────────────────────────────────

# JS-A05-001: dangerouslySetInnerHTML
NEXTJS_RULES.extend(_js_rules(
    id="JS-A05-001",
    owasp_category="A05",
    severity="high",
    title="dangerouslySetInnerHTML usage (XSS risk)",
    description="Renders raw HTML. If the content includes user input, it enables cross-site scripting.",
    pattern=re.compile(r"dangerouslySetInnerHTML\s*=", _FLAGS),
    suggested_fix="Use React's default JSX escaping. If raw HTML is required, sanitize with DOMPurify.",
))

# JS-A05-002: innerHTML assignment
NEXTJS_RULES.extend(_js_rules(
    id="JS-A05-002",
    owasp_category="A05",
    severity="high",
    title="innerHTML assignment (XSS risk)",
    description="Direct innerHTML assignment bypasses React's XSS protections.",
    pattern=re.compile(r"\.innerHTML\s*=", _FLAGS),
    suggested_fix="Use textContent or React state instead of innerHTML.",
))

# JS-A05-003: eval / new Function
NEXTJS_RULES.extend(_js_rules(
    id="JS-A05-003",
    owasp_category="A05",
    severity="critical",
    title="eval() or new Function() (code execution risk)",
    description="Executes arbitrary code. If user input reaches eval/Function, it's game over.",
    pattern=re.compile(r"\beval\s*\(|new\s+Function\s*\(", _FLAGS),
    suggested_fix="Remove eval/Function. Use JSON.parse() for data, structured logic for dynamic behavior.",
))

# JS-A05-004: Prisma $queryRawUnsafe / $executeRawUnsafe
NEXTJS_RULES.extend(_js_rules(
    id="JS-A05-004",
    owasp_category="A05",
    severity="critical",
    title="Prisma $queryRawUnsafe / $executeRawUnsafe (SQL injection)",
    description="Raw unsafe queries pass unparameterized SQL. User input in the query string enables SQL injection.",
    pattern=re.compile(r"\$(?:queryRawUnsafe|executeRawUnsafe)\s*\(", _FLAGS),
    suggested_fix="Use $queryRaw with tagged template literals: prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`",
))

# JS-A05-005: Prisma $queryRaw with string concatenation
NEXTJS_RULES.extend(_js_rules(
    id="JS-A05-005",
    owasp_category="A05",
    severity="critical",
    title="Prisma $queryRaw with string concatenation (SQL injection)",
    description="$queryRaw with string concatenation (not tagged template) bypasses parameterization.",
    pattern=re.compile(r"\$queryRaw\s*\(\s*(?!`)['\"]", _FLAGS),
    suggested_fix="Use tagged template: prisma.$queryRaw`SELECT ... WHERE id = ${id}` (backticks, not quotes)",
))

# JS-A05-006: child_process.exec with template literal
NEXTJS_RULES.extend(_js_rules(
    id="JS-A05-006",
    owasp_category="A05",
    severity="critical",
    title="child_process.exec with template literal (command injection)",
    description="exec() runs shell commands. Template literals with user input enable command injection.",
    pattern=re.compile(r"(?:exec|execSync)\s*\(\s*`", _FLAGS),
    suggested_fix="Use execFile() with array arguments instead of exec() with shell strings.",
))

# JS-A05-008: router.push/replace with user input
NEXTJS_RULES.extend(_js_rules(
    id="JS-A05-008",
    owasp_category="A05",
    severity="high",
    title="router.push/replace with potentially user-controlled URL",
    description=(
        "router.push() and router.replace() accept javascript: URLs, enabling "
        "XSS. Unsanitized user input in navigation is dangerous."
    ),
    pattern=re.compile(r"router\.(?:push|replace)\s*\(\s*(?!['\"\/])\w", _FLAGS),
    suggested_fix="Validate URL: if (!url.startsWith('/')) throw new Error('Invalid URL')",
))

# ── A06: Insecure Design ──────────────────────────────────────────────

# JS-A06-001: Middleware matcher missing /api/
NEXTJS_RULES.append(Rule(
    id="JS-A06-001",
    owasp_category="A06",
    severity="high",
    title="Middleware matcher may not cover API routes",
    description=(
        "Middleware matcher config doesn't include /api/ routes. API endpoints "
        "may be unprotected. Auth should also be checked in route handlers."
    ),
    pattern=re.compile(r"matcher\s*[=:]\s*\[(?![^\]]*\/api)", _FLAGS),
    file_glob="middleware.*",
    suggested_fix="Add '/api/:path*' to the matcher array, or re-check auth in each route handler.",
))

# ── A07: Authentication Failures ──────────────────────────────────────

# JS-A07-001: DB connection string in app files
NEXTJS_RULES.extend(_js_rules(
    id="JS-A07-001",
    owasp_category="A07",
    severity="critical",
    title="Database connection string in source code",
    description="Database credentials in source code are exposed if the repo is leaked.",
    pattern=re.compile(r"(?:mysql|postgresql|postgres|mongodb|redis)://[^:]+:[^@]+@", _FLAGS),
    suggested_fix="Load from environment: const url = process.env.DATABASE_URL",
))

# JS-A07-002: Hardcoded API keys
NEXTJS_RULES.extend(_js_rules(
    id="JS-A07-002",
    owasp_category="A07",
    severity="critical",
    title="Hardcoded API key or secret",
    description="API keys or secrets hardcoded in source are exposed if the code is leaked or shipped to the client.",
    pattern=re.compile(
        r"""(?:api_?key|secret_?key|auth_?token|access_?token)\s*[=:]\s*['"][^'"]{8,}['"]""",
        _FLAGS,
    ),
    suggested_fix="Load from environment: const key = process.env.API_KEY",
))

# ── A10: Mishandling of Exceptional Conditions ────────────────────────

# JS-A10-001: Empty catch block
NEXTJS_RULES.extend(_js_rules(
    id="JS-A10-001",
    owasp_category="A10",
    severity="high",
    title="Empty catch block (silent error swallowing)",
    description="Catching errors without handling or logging hides bugs and security issues.",
    pattern=re.compile(r"catch\s*\([^)]*\)\s*\{\s*\}", _FLAGS),
    suggested_fix="Log the error: catch (e) { console.error('Error:', e); throw e; }",
))

# JS-A10-002: Error message/stack leaked to client
NEXTJS_RULES.extend(_js_rules(
    id="JS-A10-002",
    owasp_category="A10",
    severity="medium",
    title="Error details potentially leaked to client",
    description="Returning error.message or error.stack exposes internal details to attackers.",
    pattern=re.compile(r"(?:\.json|Response\.json)\s*\(.*?(?:\.message|\.stack)", _FLAGS),
    suggested_fix="Return generic message: Response.json({error: 'Internal server error'}, {status: 500})",
))

