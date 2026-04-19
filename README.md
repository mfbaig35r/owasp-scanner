# owasp-scanner

[![CI](https://github.com/mfbaig35r/owasp-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/mfbaig35r/owasp-scanner/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

MCP server for OWASP Top 10 (2025) security scanning of Python and Next.js codebases.

Uses regex pre-filtering + optional LLM reasoning to find vulnerabilities that pattern-matching tools miss, with a persistent finding workflow that makes security knowledge accumulate instead of evaporate.

**88 rules. 20 tools. Local SQLite persistence. LLM is optional.**

## Installation

```bash
# With pip
pip install owasp-scanner

# With uv
uv tool install owasp-scanner

# With LLM support (optional)
pip install owasp-scanner[llm]
```

## MCP Setup

Add to your Claude configuration:

**Claude Desktop** (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "owasp-scanner": {
      "command": "uvx",
      "args": ["owasp-scanner"]
    }
  }
}
```

**Claude Code** (project or user settings):

```json
{
  "mcpServers": {
    "owasp-scanner": {
      "command": "uvx",
      "args": ["owasp-scanner"]
    }
  }
}
```

**With LLM scanning enabled:**

```json
{
  "mcpServers": {
    "owasp-scanner": {
      "command": "uvx",
      "args": ["owasp-scanner[llm]"],
      "env": {
        "OWASP_LLM_ENABLED": "true",
        "OWASP_OPENAI_API_KEY": "sk-..."
      }
    }
  }
}
```

## Quick Start

**CLI mode:**

```bash
# Scan a project directory
owasp-scanner --scan /path/to/project

# Fail CI if high-severity issues found
owasp-scanner --scan /path/to/project --fail-on=high
```

```
Scanned: /path/to/project
Findings: 7 (7 new)
  critical: 1
  high: 2
  medium: 4

FAIL: 3 findings at high or above.
```

**MCP mode** (via Claude):

> "Scan this project for security issues"

The scanner runs automatically when loaded as an MCP server. Claude can call any of the 20 tools directly.

## Tools

### Scanning

| Tool | Description |
|------|-------------|
| `scan_directory(path, mode, exclude, git_diff_base)` | Scan a directory. Set `git_diff_base="main"` to scan only changed files. |
| `scan_file(path, mode)` | Scan a single file. Modes: `regex`, `deep`, `llm`, `hybrid`. |
| `scan_config(path, framework)` | Scan config files (Django, FastAPI, Next.js). |
| `scan_dependencies(path)` | Check dependencies for known CVEs via pip-audit. |
| `scan_boundary(path)` | Analyze Next.js Server-to-Client Component prop crossings for data leaks. |

### Findings

| Tool | Description |
|------|-------------|
| `list_findings(status, severity, category)` | List findings with filters. |
| `get_finding(id)` | Full detail + audit trail for a finding. |
| `create_finding(...)` | Manually create a finding from review or pentesting. |
| `update_finding(id, status, notes)` | Triage: mark as fixed, accepted, or false positive. |
| `delete_finding(id)` | Remove a finding. |
| `verify_fix(id)` | Re-check if the pattern that triggered a finding is gone. |

### LLM

| Tool | Description |
|------|-------------|
| `llm_triage(finding_ids, auto_update)` | Batch LLM triage — identifies true/false positives. |

### Reporting

| Tool | Description |
|------|-------------|
| `get_summary()` | Dashboard: counts by status, category, severity. |
| `export_report(scan_id, output_path)` | Markdown report with executive summary. |
| `export_sarif(scan_id, output_path)` | SARIF 2.1.0 for GitHub/VS Code/CI integration. |
| `get_trends(days)` | Open/closed over time, mean time to remediation. |

### Utility

| Tool | Description |
|------|-------------|
| `list_scans(limit)` | Scan history. |
| `create_baseline(path)` | Snapshot current findings as the baseline. |
| `health_check()` | Server status, rule count, database info. |
| `get_errors(error_id, tool_name)` | Recent scanner errors for debugging. |

## Scanning Modes

| Mode | What happens | Cost |
|------|-------------|------|
| `regex` | 88 regex patterns, instant | Free |
| `deep` | Framework detection, endpoint extraction, security checklist for LLM reasoning | Free |
| `llm` | LLM scans each file with framework-specific context | ~$0.01-0.02/project |
| `hybrid` | Regex first, LLM triage (marks false positives), then LLM design review | ~$0.02-0.05/project |

Default is `regex`. The scanner works fully offline without an API key.

## OWASP 2025 Rule Coverage

| Category | Python | Next.js | LLM focus |
|----------|--------|---------|-----------|
| A01 Broken Access Control | 4 (auth, path traversal, SSRF) | 5 (route handler, server action, mass assignment) | Missing auth, IDOR |
| A02 Security Misconfiguration | 7 (DEBUG, ALLOWED_HOSTS, CORS, XXE) | 3 (NEXT_PUBLIC secrets, image SSRF) | Config gaps |
| A03 Supply Chain | 2 (unpinned deps, git installs) | -- | Dep hygiene, SBOM |
| A04 Cryptographic Failures | 7 (MD5, SHA-1, random, ECB, DES) | 2 (Math.random, cookies) | Key management |
| A05 Injection | 8 (SQL, pickle, eval, yaml, subprocess) | 6 (XSS, Prisma, command injection) | ORM injection |
| A06 Insecure Design | -- | 1 (middleware matcher) | **Primary LLM category** |
| A07 Authentication | 9 (secrets detection across all file types) | 2 (DB strings, API keys) | Missing MFA |
| A08 Integrity Failures | 4 (CDN SRI, marshal, shelve, jsonpickle) | -- | Mass assignment |
| A09 Logging Failures | 2 (sensitive data in logs, log injection) | -- | Missing audit logging |
| A10 Exceptional Conditions | 5 (bare except, fail-open, timeout) | 2 (empty catch, error leak) | Fail-open, transactions |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OWASP_DATA_DIR` | `~/.owasp-scanner` | Database and logs directory |
| `OWASP_MAX_FILE_SIZE_KB` | `500` | Skip files larger than this |
| `OWASP_LLM_ENABLED` | `false` | Enable LLM scanning modes |
| `OWASP_OPENAI_API_KEY` | -- | OpenAI API key for LLM modes |
| `OWASP_LLM_MODEL` | `gpt-5.4-nano` | Model for LLM scanning |
| `OWASP_LLM_BASE_URL` | -- | Override for Ollama, Azure, or vLLM |

## LLM Setup

LLM scanning is **optional**. The scanner works fully with regex mode (free, no API key needed).

To enable LLM modes (`llm`, `hybrid`, `llm_triage`):

```bash
export OWASP_LLM_ENABLED=true
export OWASP_OPENAI_API_KEY=sk-...
```

For local models via Ollama:

```bash
export OWASP_LLM_ENABLED=true
export OWASP_LLM_BASE_URL=http://localhost:11434/v1
export OWASP_OPENAI_API_KEY=ollama  # any non-empty string
export OWASP_LLM_MODEL=llama3.1
```

## Troubleshooting

**No findings on a scan:**
- Check `OWASP_MAX_FILE_SIZE_KB` (default 500 KB) — large files are skipped
- Check exclude patterns — `.owaspignore` in the project root can suppress matches
- Run `health_check()` to verify the scanner is working

**LLM mode not working:**
- Verify `OWASP_LLM_ENABLED=true` and `OWASP_OPENAI_API_KEY` are set
- Run `health_check()` — it reports whether the LLM is available
- Check `get_errors()` for API errors

**Permission errors:**
- The data directory (`~/.owasp-scanner/`) must be writable
- The database file is created with mode 0600 (owner-only read/write)

## Adding Custom Rules

Rules are regex patterns with OWASP metadata. To add a new rule:

1. Add a `Rule(...)` entry to `src/owasp_scanner/rules/patterns.py` (Python) or `nextjs_patterns.py` (Next.js)
2. Add a positive match test + negative match test to `tests/test_rules.py`
3. Run `uv run python -m pytest tests/test_rules.py -v`

For external rules without modifying source, place YAML files in `~/.owasp-scanner/rules/`:

```yaml
- id: CUSTOM-001
  owasp_category: A05
  severity: high
  title: "Custom injection pattern"
  description: "Description of the vulnerability"
  pattern: "dangerous_function\\("
  file_glob: "*.py"
  suggested_fix: "Use safe_function() instead"
```

## Development

```bash
git clone https://github.com/mfbaig35r/owasp-scanner.git
cd owasp-scanner
uv sync --all-extras
uv run python -m pytest tests/ -v --tb=short   # 370 tests
uv run ruff check src/ tests/                   # lint
```

## License

MIT
