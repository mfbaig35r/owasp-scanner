# OWASP Scanner MCP Server

Security audit workbench that scans Python codebases against the OWASP Top 10 (2025), tracks findings, and persists everything locally.

## Quick Reference

```bash
uv run python -m pytest tests/ -v --tb=short   # run tests (283 passing)
uv run ruff check src/ tests/                   # lint
uv run owasp-scanner                            # start MCP server
uv run owasp-scanner --scan /path --fail-on=high  # CLI mode
```

## Architecture

```
src/owasp_scanner/
├── server.py                 28 MCP tools, FastMCP entry point
├── core/
│   ├── config.py             Pydantic Settings (OWASP_* env vars)
│   ├── database.py           SQLite: findings, scans, audit_log (WAL mode, fingerprint dedup)
│   ├── errors.py             Thread-safe JSONL error logging
│   ├── scanner.py            Regex pattern matching + hybrid LLM orchestration
│   ├── dataflow.py           AST-based cross-file taint analysis
│   ├── llm_scanner.py        OpenAI SDK wrapper (optional, gpt-5.4-nano)
│   ├── prompts.py            LLM system prompts and function schemas
│   ├── config_scanner.py     Django/FastAPI/general config checker
│   ├── pip_audit.py          pip-audit subprocess wrapper
│   ├── reporter.py           Markdown report generator
│   └── sarif.py              SARIF 2.1.0 export
└── rules/
    ├── patterns.py           32 regex rules + OWASP category labels
    ├── severity.py           Context-sensitive severity adjustment
    └── loader.py             YAML plugin rule loader
```

## Key Patterns

- **All tools return `dict[str, Any]`** — never raise exceptions to MCP client
- **Error handling**: `try/except → errors.log_error() → return {"error": ..., "error_id": ...}`
- **Findings persistence**: `db.create_finding()` returns `tuple[Finding, bool]` (finding, is_new)
- **Dedup**: SHA-256 fingerprint of `file_path:line_number:rule_id` — re-scanning doesn't create duplicates
- **LLM is optional**: guarded with `try: import openai` / `_HAS_OPENAI`. Scanner works without it.
- **All tools are in server.py** (single file pattern from AGI project)

## Scanning Modes

| Mode | What happens | Cost |
|------|-------------|------|
| `regex` | 32 regex patterns, instant | Free |
| `llm` | GPT-5.4-nano scans each file | ~$0.01-0.02/project |
| `hybrid` | Regex first → LLM triage (marks false positives) → LLM design review | ~$0.02-0.05/project |

Default is `regex`. Set `OWASP_LLM_ENABLED=true` + `OWASP_OPENAI_API_KEY` for LLM modes.

## Database Schema

3 tables: `findings`, `scans`, `audit_log`. Data at `~/.owasp-scanner/scanner.db`.

- `findings` has `fingerprint TEXT UNIQUE` for dedup, `confidence REAL` for LLM findings, `rule_id TEXT` linking to the triggering rule
- `audit_log` tracks every status change with timestamps
- Migrations in `_MIGRATIONS` list — uses `PRAGMA table_info` to check before ALTER

## Known Limitations

- **List-element taint propagation**: tainted value in a list literal (`[..., cmd]`) loses taint when passed to a function. This blocks detection of `subprocess.run(["sh", "-c", install_cmd])` where `install_cmd` is tainted. The LLM scanner catches these by reading the code directly.
- **Regex rules are syntax-only**: can't understand context (test file vs API handler). Use `hybrid` mode or context-sensitive severity in `rules/severity.py`.
- **Single-threaded LLM scanning**: files processed sequentially to avoid rate limits.

## Testing

- All LLM tests mock the OpenAI API — no real API calls
- `conftest.py` provides `tmp_db`, `patched_db`, `sample_vulnerable_py`, `sample_clean_py` fixtures
- Rule tests: each of 32 rules has positive match + negative match (safe code shouldn't trigger)
- Server tests: call tool functions directly as async functions

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OWASP_DATA_DIR` | `~/.owasp-scanner` | Database and logs |
| `OWASP_MAX_FILE_SIZE_KB` | `500` | Skip files larger than this |
| `OWASP_LLM_ENABLED` | `false` | Enable LLM scanning |
| `OWASP_OPENAI_API_KEY` | — | OpenAI API key |
| `OWASP_LLM_MODEL` | `gpt-5.4-nano` | Model for LLM scanning |
| `OWASP_LLM_BASE_URL` | — | Override for Ollama/Azure/vLLM |
