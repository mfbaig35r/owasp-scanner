"""OWASP Top 10 (2025) pattern rules for Python code scanning.

Each rule is a regex pattern + metadata. The scanner runs these against
source files and reports matches as findings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Rule:
    id: str
    owasp_category: str
    severity: str
    title: str
    description: str
    pattern: re.Pattern[str]
    file_glob: str = "*.py"  # Which files this rule applies to
    suggested_fix: str = ""
    exclude_pattern: re.Pattern[str] | None = None  # If matched, suppress the finding

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "owasp_category": self.owasp_category,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "pattern": self.pattern.pattern,
            "file_glob": self.file_glob,
            "suggested_fix": self.suggested_fix,
        }


# ---------------------------------------------------------------------------
# OWASP category labels
# ---------------------------------------------------------------------------

OWASP_CATEGORIES = {
    "A01": "Broken Access Control",
    "A02": "Security Misconfiguration",
    "A03": "Software Supply Chain Failures",
    "A04": "Cryptographic Failures",
    "A05": "Injection",
    "A06": "Insecure Design",
    "A07": "Authentication Failures",
    "A08": "Software or Data Integrity Failures",
    "A09": "Security Logging and Alerting Failures",
    "A10": "Mishandling of Exceptional Conditions",
}

# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

# Flags for common pattern compilation
_FLAGS = re.IGNORECASE | re.MULTILINE

RULES: list[Rule] = [
    # ── A01: Broken Access Control ──────────────────────────────────────
    Rule(
        id="A01-001",
        owasp_category="A01",
        severity="high",
        title="@login_required without authorization check",
        description=(
            "Using @login_required checks authentication but NOT authorization. "
            "Any logged-in user can access this view. Add @permission_required or "
            "@staff_member_required for admin views."
        ),
        pattern=re.compile(
            r"@login_required\s*\n(?!.*@(?:permission_required|staff_member_required|user_passes_test))",
            _FLAGS,
        ),
        suggested_fix="Add @permission_required('app.permission') or @staff_member_required after @login_required.",
    ),
    Rule(
        id="A01-002",
        owasp_category="A01",
        severity="high",
        title="Potential path traversal in file operations",
        description=(
            "User input used in file path without validation. An attacker could "
            "use ../../etc/passwd to read arbitrary files. Resolve the path and "
            "verify it's within the allowed directory."
        ),
        pattern=re.compile(
            r"""(?:open|Path|FileResponse|send_file|send_from_directory)\s*\(.*?f['"]\s*[^'"]*\{.*?\}""",
            _FLAGS,
        ),
        suggested_fix="Resolve path with Path.resolve() and check .is_relative_to(ALLOWED_DIR) before access.",
    ),

    # ── A02: Security Misconfiguration ──────────────────────────────────
    Rule(
        id="A02-001",
        owasp_category="A02",
        severity="critical",
        title="DEBUG = True (potential production misconfiguration)",
        description=(
            "Django DEBUG mode exposes stack traces, database queries, and internal "
            "paths to end users. Must be False in production."
        ),
        pattern=re.compile(r"^\s*DEBUG\s*=\s*True", _FLAGS),
        suggested_fix="Set DEBUG = False and load from environment: DEBUG = os.environ.get('DEBUG', 'False') == 'True'",
    ),
    Rule(
        id="A02-002",
        owasp_category="A02",
        severity="high",
        title="ALLOWED_HOSTS wildcard",
        description="ALLOWED_HOSTS = ['*'] accepts requests for any hostname, enabling host header attacks.",
        pattern=re.compile(r"""ALLOWED_HOSTS\s*=\s*\[.*?['"]\*['"]""", _FLAGS),
        suggested_fix="Set ALLOWED_HOSTS to specific domains: ALLOWED_HOSTS = os.environ['ALLOWED_HOSTS'].split(',')",
    ),
    Rule(
        id="A02-003",
        owasp_category="A02",
        severity="medium",
        title="Hardcoded SECRET_KEY",
        description="Django SECRET_KEY hardcoded in source. If leaked, attackers can forge sessions and CSRF tokens.",
        pattern=re.compile(r"""SECRET_KEY\s*=\s*['"][^'"]{8,}['"]""", _FLAGS),
        suggested_fix="Load from environment: SECRET_KEY = os.environ['DJANGO_SECRET_KEY']",
    ),
    Rule(
        id="A02-004",
        owasp_category="A02",
        severity="medium",
        title="Docker port exposed without localhost binding",
        description=(
            "Docker port mapping without 127.0.0.1 binding may expose the service "
            "to the internet, bypassing UFW/firewall rules."
        ),
        pattern=re.compile(r"""['"]?\d{4,5}:\d{4,5}['"]?"""),
        file_glob="docker-compose*",
        suggested_fix="Bind to localhost: '127.0.0.1:5432:5432' or remove the ports section entirely.",
    ),
    Rule(
        id="A02-005",
        owasp_category="A02",
        severity="medium",
        title="CORS allow all origins",
        description="CORS_ALLOW_ALL_ORIGINS = True allows any website to make authenticated requests to your API.",
        pattern=re.compile(r"CORS_ALLOW_ALL_ORIGINS\s*=\s*True", _FLAGS),
        suggested_fix="Set CORS_ALLOWED_ORIGINS to specific domains.",
    ),

    # ── A04: Cryptographic Failures ─────────────────────────────────────
    Rule(
        id="A04-001",
        owasp_category="A04",
        severity="critical",
        title="MD5 used for hashing",
        description="MD5 is cryptographically broken. Rainbow tables crack MD5 hashes instantly.",
        pattern=re.compile(r"hashlib\.md5\(", _FLAGS),
        suggested_fix="Use argon2-cffi for passwords or hashlib.sha256() for non-password hashing.",
    ),
    Rule(
        id="A04-002",
        owasp_category="A04",
        severity="high",
        title="SHA-1 used for hashing",
        description="SHA-1 is deprecated and vulnerable to collision attacks.",
        pattern=re.compile(r"hashlib\.sha1\(", _FLAGS),
        suggested_fix="Use SHA-256 or SHA-3 for hashing. For passwords, use Argon2id.",
    ),
    Rule(
        id="A04-003",
        owasp_category="A04",
        severity="high",
        title="random module used for security-sensitive values",
        description=(
            "The random module is a PRNG — its output is predictable. "
            "Use the secrets module for tokens, keys, and session identifiers."
        ),
        pattern=re.compile(r"random\.(?:choice|choices|randint|random|sample|getrandbits)\(", _FLAGS),
        suggested_fix="Use secrets.token_urlsafe(), secrets.token_hex(), or secrets.choice().",
    ),
    Rule(
        id="A04-004",
        owasp_category="A04",
        severity="high",
        title="TLS certificate verification disabled",
        description="verify=False disables TLS certificate validation, enabling man-in-the-middle attacks.",
        pattern=re.compile(r"verify\s*=\s*False", _FLAGS),
        suggested_fix="Remove verify=False. If using self-signed certs, pass the CA bundle path instead.",
    ),

    # ── A05: Injection ──────────────────────────────────────────────────
    Rule(
        id="A05-001",
        owasp_category="A05",
        severity="critical",
        title="Potential SQL injection via string formatting",
        description="SQL query built with string concatenation or f-string. User input can modify the query.",
        pattern=re.compile(
            r"""(?:execute|executemany|raw|cursor\.)\s*\(\s*f['"].*?(?:SELECT|INSERT|UPDATE|DELETE|WHERE)""",
            _FLAGS,
        ),
        suggested_fix="Use parameterized queries: cursor.execute('SELECT * FROM t WHERE id = %s', (user_id,))",
    ),
    Rule(
        id="A05-002",
        owasp_category="A05",
        severity="critical",
        title="SQL query built with string concatenation",
        description="SQL query concatenated with + operator. User input can modify the query structure.",
        pattern=re.compile(
            r"""['"](?:SELECT|INSERT|UPDATE|DELETE)\s.*?['"]\s*\+""",
            _FLAGS,
        ),
        suggested_fix="Use parameterized queries or an ORM. Never concatenate user input into SQL.",
    ),
    Rule(
        id="A05-003",
        owasp_category="A05",
        severity="critical",
        title="pickle.loads() on potentially untrusted data",
        description="Deserializing untrusted data with pickle allows arbitrary code execution.",
        pattern=re.compile(r"pickle\.loads?\(", _FLAGS),
        suggested_fix="Use json.loads() for data interchange. If pickle is required, only load from trusted sources.",
    ),
    Rule(
        id="A05-004",
        owasp_category="A05",
        severity="critical",
        title="eval() or exec() usage",
        description="eval()/exec() execute arbitrary Python code. If user input reaches these, it's game over.",
        pattern=re.compile(r"\beval\s*\(|\bexec\s*\(", _FLAGS),
        suggested_fix="Use ast.literal_eval() for safe literal parsing. Avoid eval/exec entirely.",
    ),
    Rule(
        id="A05-005",
        owasp_category="A05",
        severity="critical",
        title="Unsafe YAML loading",
        description="yaml.load() without SafeLoader can execute arbitrary Python code.",
        pattern=re.compile(r"yaml\.load\s*\([^)]*\)(?!.*(?:Loader\s*=\s*(?:yaml\.)?SafeLoader|safe_load))", _FLAGS),
        suggested_fix="Use yaml.safe_load() instead of yaml.load().",
    ),
    Rule(
        id="A05-006",
        owasp_category="A05",
        severity="critical",
        title="os.system() with potential user input",
        description="os.system() executes shell commands. If user input is included, command injection is possible.",
        pattern=re.compile(r"os\.system\s*\(", _FLAGS),
        suggested_fix="Use subprocess.run() with a list of arguments and shell=False.",
    ),
    Rule(
        id="A05-007",
        owasp_category="A05",
        severity="high",
        title="subprocess with shell=True",
        description="shell=True passes the command through the shell, enabling injection via user input.",
        pattern=re.compile(r"subprocess\.\w+\([^)]*shell\s*=\s*True", _FLAGS),
        suggested_fix="Use subprocess.run(['cmd', 'arg1', 'arg2'], shell=False) with a list of arguments.",
    ),
    Rule(
        id="A05-008",
        owasp_category="A05",
        severity="high",
        title="Jinja2 template built with user input",
        description="User input used as part of the template string enables server-side template injection.",
        pattern=re.compile(r"Template\s*\(\s*f['\"]", _FLAGS),
        suggested_fix="Use a fixed template and pass user input as data: Template('Hello {{ name }}').render(name=user_input)",
    ),

    # ── A07: Authentication Failures ────────────────────────────────────
    Rule(
        id="A07-001",
        owasp_category="A07",
        severity="high",
        title="Hardcoded password or API key",
        description="Credential hardcoded in source code. If the repo is public or leaked, all systems using this key are compromised.",
        pattern=re.compile(
            r"""(?:password|passwd|api_key|apikey|secret_key|access_token|auth_token)\s*=\s*['"][^'"]{6,}['"]""",
            _FLAGS,
        ),
        suggested_fix="Load credentials from environment variables or a secret manager.",
    ),
    Rule(
        id="A07-002",
        owasp_category="A07",
        severity="medium",
        title="JWT with no algorithm restriction",
        description="jwt.decode() without explicit algorithms list may accept the 'none' algorithm, bypassing signature verification.",
        pattern=re.compile(r"jwt\.decode\s*\([^)]*(?!algorithms\s*=)", _FLAGS),
        suggested_fix="Always specify algorithms: jwt.decode(token, key, algorithms=['HS256'])",
    ),

    # ── A07: Secrets Detection (scan all file types) ─────────────────────
    Rule(
        id="A07-003",
        owasp_category="A07",
        severity="critical",
        title="AWS Access Key ID detected",
        description="AWS access key IDs start with AKIA and are 20 characters. If exposed, attackers get access to your AWS resources.",
        pattern=re.compile(r"AKIA[0-9A-Z]{16}", re.MULTILINE),
        file_glob="*",
        suggested_fix="Remove the key, rotate it in AWS IAM immediately, and use environment variables or AWS IAM roles instead.",
    ),
    Rule(
        id="A07-004",
        owasp_category="A07",
        severity="critical",
        title="AWS Secret Access Key detected",
        description="40-character base64 string following common AWS secret key variable names. If exposed, attackers get full access to your AWS account.",
        pattern=re.compile(r"""(?:aws_secret_access_key|secret_key|secretkey)\s*[=:]\s*['"]?[A-Za-z0-9/+=]{40}['"]?""", _FLAGS),
        file_glob="*",
        suggested_fix="Rotate the key in AWS IAM immediately. Use environment variables or IAM roles.",
    ),
    Rule(
        id="A07-005",
        owasp_category="A07",
        severity="critical",
        title="OpenAI API key detected",
        description="OpenAI API keys start with 'sk-proj-' or 'sk-'. If exposed, attackers can make API calls billed to your account.",
        pattern=re.compile(r"sk-proj-[A-Za-z0-9_\-]{20,}", re.MULTILINE),
        file_glob="*",
        suggested_fix="Rotate the key in the OpenAI dashboard. Load from environment variables.",
    ),
    Rule(
        id="A07-006",
        owasp_category="A07",
        severity="critical",
        title="Private key detected",
        description="PEM-encoded private key found in source. If exposed, attackers can impersonate your service or decrypt traffic.",
        pattern=re.compile(r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+)?PRIVATE\s+KEY-----", re.MULTILINE),
        file_glob="*",
        suggested_fix="Remove the key from source. Store in a secrets manager or mount as a volume.",
    ),
    Rule(
        id="A07-007",
        owasp_category="A07",
        severity="critical",
        title="Database connection string with embedded password",
        description="Connection string contains credentials in the URL. If the source is leaked, the database is compromised.",
        pattern=re.compile(r"(?:mysql|postgresql|postgres|mongodb|redis)://[^:]+:[^@]+@", _FLAGS),
        file_glob="*",
        suggested_fix="Load connection strings from environment variables or a secrets manager.",
    ),
    Rule(
        id="A07-008",
        owasp_category="A07",
        severity="critical",
        title="GitHub personal access token detected",
        description="GitHub PATs start with ghp_, gho_, ghu_, ghs_, or ghr_. If exposed, attackers get access to your repositories.",
        pattern=re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}", re.MULTILINE),
        file_glob="*",
        suggested_fix="Revoke the token on GitHub immediately. Use environment variables.",
    ),
    Rule(
        id="A07-009",
        owasp_category="A07",
        severity="critical",
        title="Slack token detected",
        description="Slack tokens start with xoxb-, xoxp-, xoxa-, or xoxs-. If exposed, attackers can read messages and impersonate bots.",
        pattern=re.compile(r"xox[bpas]-[A-Za-z0-9\-]{10,}", re.MULTILINE),
        file_glob="*",
        suggested_fix="Revoke the token in Slack workspace settings. Use environment variables.",
    ),

    # ── A01: Broken Access Control (continued) ──────────────────────────
    Rule(
        id="A01-003",
        owasp_category="A01",
        severity="high",
        title="Potential SSRF via user-controlled URL",
        description=(
            "HTTP request made with a URL that may include user input. "
            "An attacker could make the server request internal services "
            "(metadata APIs, admin panels, cloud credentials endpoints)."
        ),
        pattern=re.compile(
            r"requests\.(?:get|post|put|patch|delete|head|options)\s*\(\s*f['\"]",
            _FLAGS,
        ),
        suggested_fix="Validate URLs against an allow-list of permitted hosts. Block internal/private IP ranges.",
    ),
    Rule(
        id="A01-004",
        owasp_category="A01",
        severity="high",
        title="Potential SSRF via urllib with dynamic URL",
        description=(
            "urllib request with a dynamically constructed URL. An attacker could "
            "redirect the server to request internal resources."
        ),
        pattern=re.compile(
            r"urllib\.request\.(?:urlopen|urlretrieve)\s*\(\s*(?:f['\"]|[^'\")]*\+)",
            _FLAGS,
        ),
        suggested_fix="Validate URLs against an allow-list. Never pass raw user input to urllib.",
    ),

    # ── A02: Security Misconfiguration (continued) ─────────────────────
    Rule(
        id="A02-006",
        owasp_category="A02",
        severity="high",
        title="XML external entity (XXE) processing enabled",
        description=(
            "XML parser used without disabling external entity resolution. "
            "Attackers can read local files, perform SSRF, or cause denial of service."
        ),
        pattern=re.compile(
            r"(?:xml\.etree\.ElementTree|etree)\.(?:parse|fromstring|iterparse)\s*\(",
            _FLAGS,
        ),
        suggested_fix="Use defusedxml instead: from defusedxml.ElementTree import parse. Or disable entity resolution explicitly.",
    ),
    Rule(
        id="A02-007",
        owasp_category="A02",
        severity="high",
        title="lxml parser without safe settings",
        description=(
            "lxml.etree used to parse XML without explicitly disabling network access "
            "and entity resolution. Vulnerable to XXE attacks."
        ),
        pattern=re.compile(
            r"lxml\.etree\.(?:parse|fromstring|XML|HTML)\s*\([^)]*\)(?!.*resolve_entities\s*=\s*False)",
            _FLAGS,
        ),
        suggested_fix="Use defusedxml.lxml, or pass parser=etree.XMLParser(resolve_entities=False, no_network=True).",
    ),

    # ── A03: Software Supply Chain Failures ─────────────────────────────
    Rule(
        id="A03-001",
        owasp_category="A03",
        severity="medium",
        title="pip install without version pinning",
        description=(
            "Installing packages without pinned versions means builds are not reproducible "
            "and a compromised package version could be silently pulled."
        ),
        pattern=re.compile(
            r"pip\s+install\s+(?!-r\b|--requirement\b|-e\b|--editable\b|\.)(?:[a-zA-Z][\w-]*\s*(?!==|>=|<=|~=|!=)(?:\s|$))",
            _FLAGS,
        ),
        file_glob="*",
        suggested_fix="Pin exact versions: pip install package==1.2.3. Use lock files with hashes.",
    ),
    Rule(
        id="A03-002",
        owasp_category="A03",
        severity="high",
        title="pip install from URL or VCS",
        description=(
            "Installing packages directly from git URLs or HTTP endpoints bypasses "
            "registry integrity checks and is vulnerable to compromise."
        ),
        pattern=re.compile(
            r"pip\s+install\s+(?:--trusted-host\s+\S+\s+)?(?:git\+|https?://|svn\+)",
            _FLAGS,
        ),
        file_glob="*",
        suggested_fix="Publish packages to a private registry. If git installs are necessary, pin to a specific commit hash.",
    ),

    # ── A04: Cryptographic Failures (continued) ────────────────────────
    Rule(
        id="A04-005",
        owasp_category="A04",
        severity="high",
        title="AES in ECB mode",
        description=(
            "ECB mode encrypts identical plaintext blocks to identical ciphertext blocks, "
            "leaking patterns in the data. Never use ECB for multi-block data."
        ),
        pattern=re.compile(r"(?:AES\.new|AES\.encrypt)\s*\([^)]*MODE_ECB", _FLAGS),
        suggested_fix="Use AES-GCM (MODE_GCM) or AES-CTR (MODE_CTR) for authenticated encryption.",
    ),
    Rule(
        id="A04-006",
        owasp_category="A04",
        severity="high",
        title="DES or Triple DES usage",
        description="DES has a 56-bit key (broken). 3DES is deprecated by NIST as of 2023. Use AES-256.",
        pattern=re.compile(r"(?:DES3?|Triple_?DES)\.new\s*\(", _FLAGS),
        suggested_fix="Migrate to AES-256-GCM: from Crypto.Cipher import AES; cipher = AES.new(key, AES.MODE_GCM).",
    ),
    Rule(
        id="A04-007",
        owasp_category="A04",
        severity="high",
        title="Password hashed with fast hash (SHA/MD5)",
        description=(
            "Using hashlib directly on passwords is insecure — SHA-256 and MD5 are too fast, "
            "allowing billions of guesses per second. Use a purpose-built password hash."
        ),
        pattern=re.compile(
            r"hashlib\.(?:sha256|sha512|sha1|md5)\s*\(\s*(?:password|passwd|pwd|user_pass)",
            _FLAGS,
        ),
        suggested_fix="Use argon2-cffi, bcrypt, or passlib with Argon2id. Never hash passwords with hashlib.",
    ),

    # ── A08: Integrity Failures ─────────────────────────────────────────
    Rule(
        id="A08-001",
        owasp_category="A08",
        severity="medium",
        title="CDN script without integrity hash",
        description="Script loaded from CDN without subresource integrity (SRI) hash. If the CDN is compromised, malicious code executes.",
        pattern=re.compile(r"<script\s+src=['\"]https?://[^'\"]+['\"](?![^>]*integrity=)", _FLAGS),
        file_glob="*.html",
        suggested_fix="Add integrity='sha384-...' and crossorigin='anonymous' to all CDN script tags.",
    ),

    Rule(
        id="A08-002",
        owasp_category="A08",
        severity="critical",
        title="marshal.loads() on potentially untrusted data",
        description="marshal can execute arbitrary code on deserialization, similar to pickle.",
        pattern=re.compile(r"marshal\.loads?\(", _FLAGS),
        suggested_fix="Use json.loads() for data interchange. marshal is for Python internals only.",
    ),
    Rule(
        id="A08-003",
        owasp_category="A08",
        severity="high",
        title="shelve.open() uses pickle internally",
        description="shelve uses pickle for serialization. If the shelf file is attacker-controlled, arbitrary code execution is possible.",
        pattern=re.compile(r"shelve\.open\s*\(", _FLAGS),
        suggested_fix="Use a JSON-based store or SQLite. If shelve is required, only open trusted files.",
    ),
    Rule(
        id="A08-004",
        owasp_category="A08",
        severity="critical",
        title="Unsafe deserialization (jsonpickle/dill)",
        description="jsonpickle.decode() and dill.loads() can execute arbitrary code, just like pickle.",
        pattern=re.compile(r"(?:jsonpickle\.decode|dill\.loads?)\s*\(", _FLAGS),
        suggested_fix="Use json.loads() for data interchange. These libraries are as dangerous as pickle.",
    ),

    # ── A09: Security Logging and Alerting Failures ────────────────────
    Rule(
        id="A09-001",
        owasp_category="A09",
        severity="high",
        title="Sensitive data in log message",
        description=(
            "Logging passwords, tokens, secrets, or API keys writes them to log files "
            "where they may be accessible to operations staff, log aggregators, or attackers."
        ),
        pattern=re.compile(
            r"(?:log(?:ger|ging)?\.(?:debug|info|warning|error|critical|exception)|print)\s*\("
            r"[^)]*(?:password|passwd|secret|token|api_key|apikey|ssn|credit_card)",
            _FLAGS,
        ),
        suggested_fix="Never log sensitive data. Mask or redact credentials before logging.",
    ),
    Rule(
        id="A09-002",
        owasp_category="A09",
        severity="high",
        title="F-string in log message with user-controlled input (log injection)",
        description=(
            "F-string in a log call interpolates a variable whose name suggests "
            "user-controlled input (request, params, query, form, header, body, "
            "payload). An attacker can inject newlines to forge log entries or "
            "corrupt log analysis. Use %s placeholders and sanitize input."
        ),
        pattern=re.compile(
            r"log(?:ger|ging)?\.(?:debug|info|warning|error|critical|exception)\s*\(\s*f['\"]"
            r"[^'\"]*\{"
            r"[^}]*(?:request|req\.|params|query|form|header|body|payload|user_input|argv|stdin)"
            r"[^}]*\}",
            _FLAGS,
        ),
        suggested_fix='Sanitize input and use lazy formatting: logger.info("Request %s", sanitize(value))',
    ),
    Rule(
        id="A09-003",
        owasp_category="A09",
        severity="low",
        title="F-string in log message (bypasses lazy formatting)",
        description=(
            "Using f-strings in log calls bypasses the logging framework's lazy "
            "formatting, meaning the string is always constructed even if the log "
            "level is disabled. This is a performance/code quality issue, not a "
            "security risk unless user-controlled input is interpolated (see A09-002)."
        ),
        pattern=re.compile(
            r"log(?:ger|ging)?\.(?:debug|info|warning|error|critical|exception)\s*\(\s*f['\"]",
            _FLAGS,
        ),
        exclude_pattern=re.compile(
            r"\{[^}]*(?:request|req\.|params|query|form|header|body|payload|user_input|argv|stdin)[^}]*\}",
            _FLAGS,
        ),
        suggested_fix='Use lazy formatting: logger.info("Processed %s pages", page_count)',
    ),

    # ── A10: Mishandling of Exceptional Conditions ──────────────────────
    Rule(
        id="A10-001",
        owasp_category="A10",
        severity="high",
        title="Bare except with pass (silent error swallowing)",
        description=(
            "Catching all exceptions and doing nothing hides bugs, security issues, "
            "and data corruption. Errors should be logged and handled specifically."
        ),
        pattern=re.compile(r"except\s*:\s*\n\s*pass", _FLAGS),
        suggested_fix="Catch specific exceptions. Log all errors. Never silently swallow exceptions.",
    ),
    Rule(
        id="A10-002",
        owasp_category="A10",
        severity="medium",
        title="Broad except Exception with pass",
        description="Catching all exceptions and passing silently hides important errors.",
        pattern=re.compile(r"except\s+(?:Exception|BaseException)\s*(?:as\s+\w+)?\s*:\s*\n\s*pass", _FLAGS),
        suggested_fix="Catch specific exceptions and log them. Use except Exception only at top-level handlers.",
    ),
    Rule(
        id="A10-003",
        owasp_category="A10",
        severity="medium",
        title="Stack trace potentially exposed to user",
        description="traceback.format_exc() or traceback.print_exc() output may reach end users, leaking internals.",
        pattern=re.compile(r"traceback\.(?:format_exc|print_exc)\s*\(", _FLAGS),
        suggested_fix="Log stack traces server-side. Return generic error messages to users.",
    ),
    Rule(
        id="A10-004",
        owasp_category="A10",
        severity="medium",
        title="HTTP request without timeout",
        description=(
            "requests.get/post without a timeout will block indefinitely if the server "
            "doesn't respond, causing resource exhaustion and cascading failures."
        ),
        pattern=re.compile(
            r"requests\.(?:get|post|put|patch|delete|head|options)\s*\([^)]*\)(?<!\btimeout\b)",
            _FLAGS,
        ),
        suggested_fix="Always set a timeout: requests.get(url, timeout=30). Consider using httpx with default timeouts.",
    ),
    Rule(
        id="A10-005",
        owasp_category="A10",
        severity="high",
        title="Fail-open pattern (exception returns success)",
        description=(
            "Catching an exception and returning True/success means any error — including "
            "security check failures — will be treated as a pass. This is a fail-open vulnerability."
        ),
        pattern=re.compile(
            r"except\s*(?:\w+\s*)?(?:as\s+\w+\s*)?:\s*\n\s*return\s+True",
            _FLAGS,
        ),
        suggested_fix="Fail closed: on exception in a security check, return False/deny access. Log the error.",
    ),
]


def get_rules(
    owasp_category: str | None = None,
    severity: str | None = None,
    include_plugins: bool = True,
) -> list[Rule]:
    """Get rules, optionally filtered by category or severity.

    Args:
        owasp_category: Filter to a specific category (A01-A10).
        severity: Filter to a specific severity level.
        include_plugins: If True, also load custom rules from ~/.owasp-scanner/rules/
    """
    result = list(RULES)

    # Load Next.js rules
    from owasp_scanner.rules.nextjs_patterns import NEXTJS_RULES

    result.extend(NEXTJS_RULES)

    if include_plugins:
        from owasp_scanner.rules.loader import load_plugin_rules

        plugin_rules = load_plugin_rules()
        existing_ids = {r.id for r in result}
        for pr in plugin_rules:
            if pr.id not in existing_ids:
                result.append(pr)

    if owasp_category:
        result = [r for r in result if r.owasp_category == owasp_category]
    if severity:
        result = [r for r in result if r.severity == severity]
    return result
