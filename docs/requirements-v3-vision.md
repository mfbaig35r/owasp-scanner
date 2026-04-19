# Security Scanner v3 — Vision Document

## What we learned building v1 and v2

We built a 12,750-line scanner with 31 tools, 97 rules, an AST dataflow
engine, Next.js boundary analysis, and test quality detection. It works.
But it tries to be three things at once, and the AST engine duplicates
what codegraph already does better.

The things that actually mattered:
1. The LLM hybrid mode found issues no other tool finds
2. The finding workflow (persist, triage, verify, report) is the real product
3. Next.js boundary analysis is genuinely differentiated
4. Regex rules are a good free pre-filter but not the value proposition
5. The AST dataflow engine was educational but the LLM makes it redundant
6. Test quality is a different product for a different user

## The product in one sentence

A security scanner MCP that uses LLM reasoning to find vulnerabilities
that pattern-matching tools miss, with a persistent finding workflow
that makes security knowledge accumulate instead of evaporate.

---

## Architecture: Two tools, not one

### Tool 1: codegraph (already exists)

Parses Python repositories into queryable code relationship graphs.
Nodes (functions, classes, methods), edges (calls, imports, inherits),
LLM enrichment (summaries, clusters, semantic similarity).

**Role in security scanning:** structural understanding. "What calls
this function?" "What does this module import?" "Show me the call graph
from the API endpoint to the database query." The scanner doesn't need
to build its own call graph — codegraph already does this.

### Tool 2: security scanner (what we're building)

Finds security vulnerabilities using regex pre-filtering + LLM reasoning,
with a persistent finding workflow. Does NOT try to parse code structure —
delegates that to codegraph when structural understanding is needed.

**The scanner's job:**
1. Scan files for known vulnerability patterns (regex, free, instant)
2. Send files to the LLM with framework-specific context for design-level analysis
3. Persist findings with dedup, audit trail, and triage workflow
4. Export in standard formats (SARIF, markdown)

**NOT the scanner's job:**
- Building call graphs (codegraph does this)
- Tracing data flow through AST (the LLM reads the code)
- Detecting test quality (different product)
- Being a linter (ruff/eslint do this)

### How they compose

Claude (the LLM in the conversation) orchestrates both tools:

```
User: "Scan this project for security issues"

Claude:
  1. owasp-scanner.scan_directory(path, mode="hybrid")
     → regex findings + LLM design-level findings

  2. If a finding involves cross-file data flow:
     codegraph.index_repo(path)
     codegraph.get_edges("executor.execute", direction="callers")
     → structural context for the finding

  3. owasp-scanner.create_finding(...)
     → persist the cross-file finding with full context

  4. owasp-scanner.export_report()
     → markdown report with all findings
```

The scanner doesn't need to understand call graphs. Claude does that
by composing the two tools. This is what MCP is designed for.

---

## What the scanner contains

### Core: The finding workflow

This is the product. Everything else is a means to populate it.

```
scan → findings → triage → fix → verify → report
         ↑                           |
         └── persist with dedup ─────┘
```

**Finding lifecycle:**
- `open` → initial detection (regex or LLM)
- `in_progress` → developer is working on it
- `fixed` → `verify_fix` confirms the pattern is gone
- `accepted` → risk accepted with documented rationale
- `false_positive` → not a real issue (with reasoning)

**Persistence:**
- SQLite with WAL mode
- Fingerprint dedup (SHA-256 of file:line:rule_id)
- Full audit trail (who changed what, when, why)
- Findings accumulate across scans — re-scanning doesn't create duplicates

**Reporting:**
- Markdown with executive summary, severity tables, remediation priority
- SARIF 2.1.0 for GitHub/VS Code/CI integration
- Timestamps on everything

### Layer 1: Regex pre-filter (free, instant)

~50-60 focused rules. Not trying to be comprehensive — just catching
the obvious patterns before the LLM runs.

**Python rules (~30):**
- Injection: SQL f-strings, pickle, eval, yaml.load, os.system, subprocess shell=True
- Crypto: MD5, SHA-1, random for security, verify=False, hardcoded keys
- Config: DEBUG=True, ALLOWED_HOSTS=*, hardcoded SECRET_KEY
- Access control: @login_required without @permission_required, path traversal
- Error handling: bare except:pass, traceback leaked to users
- Secrets: AWS keys, OpenAI keys, GitHub tokens, DB connection strings, private keys

**Next.js rules (~25):**
- Injection: dangerouslySetInnerHTML, innerHTML, eval, Prisma rawUnsafe
- Access control: route handler without auth, server action without auth, mass assignment
- Config: NEXT_PUBLIC_ secrets, wildcard image hostname, internal rewrites
- Design: middleware matcher gaps, open redirect via redirect()
- Crypto: Math.random for tokens, cookies without secure flags

Rules are the cheapest layer. They run on every scan regardless of mode.
They produce findings that the LLM can triage in hybrid mode.

### Layer 2: LLM analysis (the differentiator)

The LLM does what regex cannot: understand intent, evaluate design
decisions, and find what's missing.

**Framework-specific prompts:**

The system prompt changes based on the detected project type. This is
the single most important design decision — priming the LLM with the
right security model makes the difference between generic findings
and framework-specific insights.

**Python prompt focus:**
- Authorization checks on every endpoint
- Input validation with allow-lists
- Error handling (fail closed, log details, generic user messages)
- Database access (parameterized queries, least-privilege accounts)
- Secret management (environment variables, not hardcoded)

**Next.js prompt focus (the differentiator):**
- Server/Client boundary: props crossing from Server Components to
  Client Components are serialized into the RSC payload. Full objects
  exposed, not just rendered fields.
- Server Actions: public HTTP endpoints, CSRF has had bypasses.
  Must validate auth AND input at the function level.
- Middleware: bypassed twice (CVE-2024-51479, CVE-2025-29927).
  Auth only in middleware is a critical finding.
- The 10 high-priority patterns: over-fetching, mass assignment,
  route handler auth, matcher gaps, NEXT_PUBLIC_ secrets, Prisma
  injection, open redirect, cache poisoning, image SSRF, cookie flags.

**File-type context block:**

Every file sent to the LLM includes a context header:

```
File: app/api/users/route.ts
Type: ROUTE HANDLER (always server-side)
Trust: Public HTTP endpoint. Must validate auth and input.
Risk: Middleware has been bypassed twice. Re-check auth in handler.
```

This primes the LLM to evaluate the file through the right security lens.

**What the LLM finds that nothing else does:**
- "This Server Component fetches the full user record and passes it
   to a Client Component — SSN and credit card are in the RSC payload"
- "This Server Action accepts Object.fromEntries(formData) and spreads
   it into a Prisma update — mass assignment vulnerability"
- "Every MCP tool accepts run_id without ownership checks — IDOR on
   all 17 endpoints"
- "This route handler has no auth check — middleware matcher doesn't
   cover /api/admin"

### Layer 3: Codegraph integration (structural context)

When the scanner or the user needs structural understanding — "what
calls this function?" "where does this data flow?" — codegraph provides
it. The scanner doesn't import codegraph directly. Claude composes them
in the conversation.

**When codegraph helps:**
- A finding says "command injection in executor.py" → codegraph shows
  which API endpoints call executor.execute() and what parameters they pass
- A finding says "missing auth on helper function" → codegraph shows
  whether the function is called from authenticated or unauthenticated contexts
- The user asks "what's the blast radius if this function is compromised?"
  → codegraph traces the call graph downstream

**When codegraph isn't needed:**
- Single-file analysis (most findings)
- Config scanning (next.config.js, settings.py)
- Secrets detection (pattern matching)
- Most LLM findings (the LLM reads the file and reasons about it)

The key insight: 90% of security findings are single-file. The 10% that
need cross-file understanding are exactly the ones where codegraph shines.
Building cross-file analysis into the scanner was solving the 10% case
at the cost of 775 lines of AST code. Delegating to codegraph solves it
with zero lines in the scanner.

---

## Tools (target: ~18)

### Scanning
- `scan_directory(path, mode, exclude)` — the main entry point
- `scan_file(path, mode)` — single file
- `scan_config(path, framework)` — framework config analysis

### Findings
- `list_findings(status, severity, category, file_path, category_type)`
- `get_finding(id)` — full detail + audit trail
- `create_finding(...)` — manual findings from review/pentesting
- `update_finding(id, status, notes, fix_commit)` — triage
- `delete_finding(id)` — remove mistakes
- `verify_fix(id)` — re-check if pattern is gone

### Reporting
- `get_summary(category_type)` — dashboard
- `export_report(scan_id, output_path)` — markdown
- `export_sarif(scan_id, output_path)` — CI integration
- `get_trends(days)` — open/closed over time, MTTR

### LLM
- `llm_triage(finding_ids, auto_update)` — batch LLM triage
- `scan_boundary(path)` — Next.js Server→Client prop analysis

### Utility
- `list_scans(limit)` — scan history
- `health_check()` — status
- `create_baseline(path)` — snapshot current findings

### Removed (vs current)
- `trace_dataflow` → use codegraph instead
- `llm_evaluate_dataflows` → use codegraph + LLM conversation
- `deep_analyze` → folded into scan_file with mode="llm"
- `scan_changes` → folded into scan_directory with git awareness
- `scan_pr` → composition of scan_directory + scan_dependencies
- `scan_dependencies` → keep or fold into scan_directory
- `analyze_code` → folded into scan_file
- `list_rules` → rarely used, remove or make it a --verbose flag
- `get_owasp_reference` → the guide document is better
- `get_errors` → keep for debugging
- `get_scan` → rarely used separately from list_scans
- `scan_test_quality` → separate product
- `analyze_test_coverage` → separate product
- `suggest_tests` → separate product

---

## What makes this different from existing tools

| Existing tool | What it does well | What it can't do |
|---------------|------------------|-----------------|
| **Semgrep** | Pattern matching with dataflow | Can't reason about design intent |
| **CodeQL** | Semantic queries with type info | Requires query authoring, no design reasoning |
| **Bandit** | Python-specific patterns | No framework awareness, no LLM |
| **ESLint** | JS/TS code quality | Not security-focused, no cross-file |
| **SonarQube** | Broad language coverage | No Next.js boundary model |
| **Snyk** | Dependencies + broad code | No framework-specific design analysis |

**What we do that nobody else does:**

1. **LLM finds what's missing** — "this endpoint has no auth check" is
   not a pattern match. It's the absence of a pattern. Only an LLM can
   find something that should exist but doesn't.

2. **Framework-specific security models** — the Next.js prompt knows that
   Server Action auth was bypassed via CVE-2026-27978. It knows middleware
   was bypassed twice. It knows props cross the RSC serialization boundary.
   No other scanner encodes this knowledge.

3. **Persistent triage workflow** — scan once, triage findings, track fixes,
   verify remediation, export reports. Security knowledge accumulates over
   time instead of starting from zero on every scan.

4. **Composable with codegraph** — when cross-file understanding is needed,
   the user has codegraph in the same MCP session. Two focused tools
   composed by Claude, not one monolithic tool trying to do everything.

---

## What success looks like

A developer opens Claude Code, points it at their Next.js project, and says
"scan this for security issues." Five minutes later they have:

- A list of findings ranked by severity with confidence scores
- The critical one: "Your dashboard Server Component passes the full user
  record to a Client Component — email, phone, and SSN are in the RSC
  payload visible to any browser user"
- A triage workflow where they mark the false positives with rationale
- A markdown report they can paste into a PR or share with their team
- Findings that persist — next week when they scan again, only new issues
  appear, and fixed issues are automatically closed

That's the product. Everything else is implementation detail.
