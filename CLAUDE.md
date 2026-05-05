# OWASP Scanner MCP Server

Security audit workbench that scans Python and Next.js codebases against the OWASP Top 10 (2025), tracks findings, and persists everything locally. Uses regex pre-filtering + LLM reasoning for defense-in-depth vulnerability detection.

## Quick Reference

```bash
uv run python -m pytest tests/ -v --tb=short   # run tests (421 passing)
uv run ruff check src/ tests/                   # lint
uv run owasp-scanner                            # start MCP server
uv run owasp-scanner --scan /path --fail-on=high  # CLI mode
```

## Architecture

```
src/owasp_scanner/
├── server.py                 20 MCP tools, FastMCP entry point
├── core/
│   ├── config.py             Pydantic Settings (OWASP_* env vars)
│   ├── database.py           SQLite: findings, scans, audit_log (WAL mode, fingerprint dedup)
│   ├── errors.py             Thread-safe JSONL error logging
│   ├── scanner.py            Regex pattern matching + hybrid LLM orchestration
│   ├── llm_scanner.py        OpenAI SDK wrapper (optional, gpt-5.4-nano)
│   ├── prompts.py            LLM system prompts, function schemas, file-type context builders
│   ├── nextjs.py             Next.js project detection, file classification, boundary analysis
│   ├── config_scanner.py     Django/FastAPI/Next.js/general config checker
│   ├── pip_audit.py          pip-audit subprocess wrapper
│   ├── reporter.py           Markdown report generator
│   └── sarif.py              SARIF 2.1.0 export
├── data/
│   └── owasp_top10_2025.json Static OWASP Top 10 (2025) reference — all 10 categories with
│                              CWEs, stats, vulnerabilities, prevention strategies
└── rules/
    ├── patterns.py           49 Python regex rules + OWASP category labels (A01-A10)
    ├── nextjs_patterns.py    39 Next.js regex rules (22 unique, dual-glob for .ts/.tsx)
    ├── severity.py           Context-sensitive severity adjustment
    └── loader.py             YAML plugin rule loader
```

## Tools (20)

### Scanning
- `scan_directory(path, mode, exclude, git_diff_base, context_file, compact)` — main entry point. `git_diff_base` scans only changed files (replaces old scan_changes/scan_pr). `context_file` (or auto-discovered `.owasp-context.md`) prepends project invariants to LLM prompts. `compact=True` omits the inline findings list.
- `scan_file(path, mode)` — single file. `mode`: `regex` (default), `deep` (design-level checklist), `llm`, `hybrid`
- `scan_config(path, framework)` — framework config analysis
- `scan_dependencies(path)` — pip-audit for known CVEs (A03)
- `scan_boundary(path)` — Next.js Server→Client prop analysis (data leak detection)

### Findings
- `list_findings(..., compact)` — `compact=True` drops description/code_snippet/suggested_fix/notes
- `get_finding`, `create_finding`, `update_finding`, `delete_finding`, `verify_fix`

### LLM
- `llm_triage(finding_ids, auto_update, max_concurrency, per_call_timeout, context_file)` — per-finding parallel triage. Defaults: `max_concurrency=5`, `per_call_timeout=30s`, overall ceiling `min(per_call * N + 5s, 600s)`. Failed/timed-out findings get a `needs_investigation` verdict (batch continues). `context_file` (or auto-discovered `.owasp-context.md` from common ancestor of finding paths) prepends project invariants.

### Reporting
- `get_summary`, `export_report`, `export_sarif`, `get_trends`

### Utility
- `list_scans`, `health_check`, `create_baseline`, `get_errors`

## Key Patterns

- **All tools return `dict[str, Any]`** — never raise exceptions to MCP client
- **Error handling**: `try/except → errors.log_error() → return {"error": ..., "error_id": ...}`
- **Findings persistence**: `db.create_finding()` returns `tuple[Finding, bool]` (finding, is_new)
- **Dedup**: SHA-256 fingerprint of `file_path:line_number:rule_id` — re-scanning doesn't create duplicates
- **LLM is optional**: guarded with `try: import openai` / `_HAS_OPENAI`. Scanner works without it.
- **All tools are in server.py** (single file pattern)
- **File-type context**: Both Python and Next.js files get Type/Trust/Risk headers when sent to the LLM
- **Project context (`.owasp-context.md`)**: optional reviewer-supplied markdown describing auth model, tenant isolation, intentional design decisions. Auto-discovered in scan target dir; for `llm_triage` discovered by walking up from the common ancestor of the findings being triaged. Capped at 20 KB. Prepended to every LLM scan + triage prompt as authoritative context — suppresses architectural FPs in defense-in-depth codebases.
- **Triage parallelism**: `triage_findings` is async; one OpenAI call per finding via `asyncio.to_thread` under `asyncio.Semaphore(max_concurrency)`. Per-call `wait_for(per_call_timeout)`; per-finding failures yield `needs_investigation` rather than aborting. The MCP tool wraps the whole call in an overall ceiling so the transport never sees a >10-min hang.

## Scanning Modes

| Mode | What happens | Cost |
|------|-------------|------|
| `regex` | 88 regex patterns (49 Python + 39 Next.js), instant | Free |
| `deep` | Framework detection, endpoint extraction, security checklist for LLM reasoning | Free |
| `llm` | LLM scans each file with framework-specific context | ~$0.01-0.02/project |
| `hybrid` | Regex first → LLM triage (marks false positives) → LLM design review | ~$0.02-0.05/project |

Default is `regex`. Set `OWASP_LLM_ENABLED=true` + `OWASP_OPENAI_API_KEY` for LLM modes.

## OWASP 2025 Rule Coverage

| Category | Python rules | Next.js rules | LLM focus |
|----------|-------------|---------------|-----------|
| A01 Broken Access Control | 4 (auth, path traversal, SSRF) | 5 (route handler, server action, mass assignment, redirect, cache) | Missing auth, IDOR |
| A02 Security Misconfiguration | 7 (DEBUG, ALLOWED_HOSTS, SECRET_KEY, Docker, CORS, XXE) | 3 (NEXT_PUBLIC secrets, image SSRF, internal rewrites) | Config gaps |
| A03 Supply Chain | 2 (unpinned deps, git/URL installs) | — | Dep hygiene, SBOM |
| A04 Cryptographic Failures | 7 (MD5, SHA-1, random, verify=False, ECB, DES, weak pw hash) | 2 (Math.random, cookie flags) | Key management |
| A05 Injection | 8 (SQL, pickle, eval, yaml, os.system, subprocess, Jinja2) | 6 (XSS, eval, Prisma injection, command injection, router) | ORM injection |
| A06 Insecure Design | — | 1 (middleware matcher) | **Primary LLM category** |
| A07 Authentication | 9 (hardcoded creds, JWT, AWS/OpenAI/GitHub/Slack/private keys, DB strings) | 2 (DB strings, API keys) | Missing MFA, brute force |
| A08 Integrity Failures | 4 (CDN SRI, marshal, shelve, jsonpickle/dill) | — | Mass assignment |
| A09 Logging Failures | 3 (sensitive data in logs, user-input log injection [high], f-string logging [low]) | — | **Missing logging** |
| A10 Exceptional Conditions | 5 (bare except, broad except, traceback, timeout, fail-open) | 2 (empty catch, error leak) | Fail-open, transactions |

## Composability with codegraph

Cross-file structural analysis (call graphs, data flow) is handled by the codegraph MCP server, not this scanner. Claude composes both tools in conversation:

1. `owasp-scanner.scan_directory(path)` → findings
2. If a finding involves cross-file flow: `codegraph.get_edges(func)` → callers
3. `owasp-scanner.create_finding(...)` → persist with full context

## Database Schema

3 tables: `findings`, `scans`, `audit_log`. Data at `~/.owasp-scanner/scanner.db`.

- `findings` has `fingerprint TEXT UNIQUE` for dedup, `confidence REAL` for LLM findings, `rule_id TEXT` linking to the triggering rule
- `audit_log` tracks every status change with timestamps
- Migrations in `_MIGRATIONS` list — uses `PRAGMA table_info` to check before ALTER

## Known Limitations

- **Regex rules are syntax-only**: can't understand context (test file vs API handler). Use `hybrid` mode or context-sensitive severity in `rules/severity.py`.
- **LLM file scanning is sequential**: `scan_file_llm` processes files one at a time to avoid rate limits. Triage (`triage_findings`) runs in parallel — see Key Patterns.
- **scan_boundary is regex-based**: catches explicit `<Component prop={value} />` patterns but not spread props (`{...user}`) or indirect passing. The LLM catches these.

## Testing

- All LLM tests mock the OpenAI API — no real API calls
- `conftest.py` provides `tmp_db`, `patched_db`, `sample_vulnerable_py`, `sample_clean_py` fixtures
- Rule tests: each rule has positive match + negative match (safe code shouldn't trigger)
- Server tests: call tool functions directly as async functions
- Boundary tests: create temp Next.js project structures with Server/Client components

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OWASP_DATA_DIR` | `~/.owasp-scanner` | Database and logs |
| `OWASP_MAX_FILE_SIZE_KB` | `500` | Skip files larger than this |
| `OWASP_LLM_ENABLED` | `false` | Enable LLM scanning |
| `OWASP_OPENAI_API_KEY` | — | OpenAI API key |
| `OWASP_LLM_MODEL` | `gpt-5.4-nano` | Model for LLM scanning |
| `OWASP_LLM_BASE_URL` | — | Override for Ollama/Azure/vLLM |
