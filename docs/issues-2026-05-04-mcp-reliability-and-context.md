# MCP server reliability + per-file context — three issues from a real audit

Three issues encountered while running owasp-scanner against
[`mfbaig35r/sourcing-kernel`](https://github.com/mfbaig35r/sourcing-kernel)
on 2026-05-04. Each has a concrete reproducer, a root-cause file
reference, and a suggested fix sized for a single PR.

**The repro target:** ~16k LOC Python, 94 source files, multi-tenant
FastAPI + FastMCP service. A `hybrid` scan against the production
code path (excluding tests + migrations) produced 120 findings: 3
critical, 31 high, ~50 medium, ~36 low.

| # | Title | Severity | Category |
|---|---|---|---|
| 1 | `llm_triage` batch hangs and crashes the MCP server | high | reliability |
| 2 | Per-file LLM analysis can't see cross-module invariants | medium-high | precision |
| 3 | Findings responses blow past the inline tool-output cap | low | UX |

Fix in numeric order — issue 1 is the only one that actually blocks
audits; 2 and 3 are tax on every scan.

---

## Issue 1 — `llm_triage` batch hangs ~7 min, then crashes the MCP server

The crash takes down all 28 MCP tools in the session. Recovery
requires a `/mcp` reconnect (or restarting Claude Code).

### Symptom

Single-finding triage works fine — ~1 second, ~$0.0001 (664 input
tokens, 112 output, `gpt-5.4-nano`, function-calling). Batch triage
of 31 findings:

| t | event |
|---|---|
| 0:00 | `llm_triage(finding_ids=[<31 UUIDs>], auto_update=True)` issued |
| 7:00 | still no response; user interrupts |
| 7:01 | next call to *any* owasp-scanner tool: `MCP error -32000: Connection closed` |
| 7:01 | `system-reminder` enumerates every tool as "no longer available" |
| —   | `/mcp` reconnects cleanly; in-progress triage results are lost |

The `try/except → errors.log_error` wrapper at `server.py:893` would
catch a Python exception, but a transport-layer disconnect (the
client gave up before the LLM replied) bypasses it.

### Root cause — `src/owasp_scanner/core/llm_scanner.py:238`

`triage_findings` packs every finding's full code context into a
single prompt and makes one synchronous OpenAI call:

```python
def triage_findings(
    findings_with_context: list[dict[str, Any]],
) -> tuple[list[TriageResult], LLMUsage]:
    user_content = "Triage these security findings:\n\n"
    for f in findings_with_context:
        user_content += (
            f"Finding ID: {f['id']}\n"
            f"Title: {f['title']}\n"
            ...
            f"Code context:\n```\n{f.get('code_context', ...)}\n```\n\n"
        )
    response = client.chat.completions.create(
        model=model,
        messages=[...],
        functions=[TRIAGE_FUNCTION_SCHEMA],
        function_call={"name": "report_triage"},
        temperature=0.1,
    )
```

For 31 findings: ~22 KB of input + a function-calling response that
has to emit 31 structured assessments serially. No streaming, no
progress, no per-finding timeout, no transport-level ceiling. The
most likely failure mode is the model just took longer than the
client's read timeout (the OpenAI SDK has its own retries that are
silent to FastMCP), and when the connection eventually died the
server didn't recover.

### Suggested fix

Replace the single-call shape with **per-finding parallelism +
progress + bounded concurrency**:

```python
# core/llm_scanner.py
async def triage_findings(
    findings: list[dict[str, Any]],
    *,
    max_concurrency: int = 5,
    per_finding_timeout: float = 30.0,
    progress_cb: Callable[[int, int], None] | None = None,
) -> tuple[list[TriageResult], LLMUsage]:
    sem = asyncio.Semaphore(max_concurrency)
    done = 0

    async def one(f: dict[str, Any]) -> TriageResult | None:
        nonlocal done
        async with sem:
            try:
                tr = await asyncio.wait_for(
                    _triage_single(f), timeout=per_finding_timeout
                )
            except (asyncio.TimeoutError, Exception) as e:
                tr = _timeout_result(f, e)
            done += 1
            if progress_cb:
                progress_cb(done, len(findings))
            return tr

    results = await asyncio.gather(*(one(f) for f in findings))
    ...
```

And expose the knobs at the tool layer:

```python
# server.py
async def llm_triage(
    finding_ids: list[str],
    auto_update: bool = False,
    max_concurrency: int = 5,
) -> dict[str, Any]:
    ...
    # Hard ceiling so the MCP transport never sees a multi-minute hang.
    ceiling = min(600.0, 30.0 * len(findings))
    return await asyncio.wait_for(_do_triage(...), timeout=ceiling)
```

Plus a `logger.info("triaged %d/%d", done, total)` callback so an
operator (or the MCP client, when FastMCP grows progress
notifications) can see the call is making progress.

Net behavior change: 31 calls instead of 1 (linear cost), but
gpt-5.4-nano makes a 100-finding triage still under $0.01. Single-
finding precision is unchanged — same system prompt, same schema.

### Workaround used in the repro

Hand-classify via per-finding `update_finding` calls. That path is
reliable, fast, and doesn't go through the LLM at all.

---

## Issue 2 — Per-file LLM analysis can't see cross-module auth invariants

The 31-high finding set in the repro included **13 false positives**
of the same shape — "missing tenant authorization" flagged on every
internal helper that takes an ID. Examples (all flagged high, A01):

- `core/runtime/runs.py` — state-machine helpers (`start_run`,
  `complete_stage`, ...) "missing tenant authorization checks on run_id"
- `clustering/assign.py:78` — `load_run_centroids(run_id)` "missing
  tenant isolation"
- `orchestration/jobs.py:74` — `run_pipeline_task` "missing
  authorization for run_id"
- `core/runtime/repository.py:1` — Arrow ↔ SQL adapter "missing
  object-level authorization"

Every one of these is gated upstream at the API/MCP boundary
(`Run.tenant_id == ctx.tenant_id` checked before the helper is ever
called). The codebase explicitly documents the pattern in
`docs/backlog.md`'s "Confirmed not-bugs" section, and verifies it
with a 10-case integration test (commit
[`2665533`](https://github.com/mfbaig35r/sourcing-kernel/commit/2665533)).
The LLM, looking at one file at a time, can't see any of that.

### Why this matters

Every defense-in-depth Python web codebase will hit this. The
reviewer ends up either ignoring all A01 findings (dangerous) or
hand-marking each one (slow). The scanner does the right thing
per-file — it just can't see the project-level shape.

### Suggested fix — opt-in project context

Add an **optional project-context file** prepended to every LLM
analysis prompt:

1. **Auto-discover** `.owasp-context.md` in the scan target (same
   pattern as `.owaspignore` already supports).
2. **CLI flag** `--context-file path/to/context.md` to override.
3. **MCP tool arg** `context_file: str | None = None` on
   `scan_directory` and `llm_triage`.

The contents go in as a separate system-prompt block with explicit
framing — *this is how the project is structured; treat it as
authoritative when judging individual files*. For the repro project
the file would be ~10 lines:

```markdown
# OWASP scan context

Auth model: every API route + MCP tool gates with
`Run.tenant_id == ctx.tenant_id` (or equivalent for the resource
type) BEFORE invoking internal helpers. Functions in
`core/runtime/`, `orchestration/`, `pipelines/`, and `clustering/`
are worker-internal — they receive trusted IDs from validated
callers. Cross-tenant isolation is verified by
`tests/integration/test_multi_tenant_isolation_pg.py`.

Known limitations (deferred): no DB-level RLS; MCP transport is
one-tenant-per-process via SK_API_KEY (no per-call auth by design).
```

Estimated impact on the repro: would have cut high-severity FPs
from ~13 to ~0 without losing the 6 real findings (which are about
prompt injection, file-path containment, audit error sanitization,
etc. — orthogonal to the auth-gating pattern).

This isn't a substitute for triage — the LLM should still flag a
specific code path that obviously contradicts the context — but it
fixes the precision problem for architectural patterns that are
correct by design.

---

## Issue 3 — `list_findings` and `scan_directory` outputs blow past the inline cap

UX issue, workaround exists. Worth fixing for quality of life.

### Symptom

Two MCP tool responses exceeded the inline cap and auto-spilled to
disk:

| Tool call | Response size | Findings |
|---|---|---|
| `scan_directory(... mode="hybrid")` | 71 KB | 120 |
| `list_findings(severity="high", limit=50)` | 51 KB | 31 |

When that happens, the caller has to read + parse the persisted file,
turning "scan → look at findings" into 2-3 round trips instead of
one.

### Root cause

Each finding's response payload is ~1.5-2 KB:

| Field | Typical size |
|---|---|
| `description` | 300-800 chars (often multi-paragraph) |
| `suggested_fix` | 200-400 chars |
| `code_snippet` | 3-5 lines, ~150 chars |
| `notes` | variable (from triage history) |
| structural fields | id, file_path, severity, status — ~150 chars |

Information density is fine; the inline cap just wasn't designed
for 50-finding payloads.

### Suggested fix — `compact=True` flag

Add a `compact: bool = False` flag to `list_findings` and
`scan_directory`:

```python
async def list_findings(
    ...,
    limit: int = 50,
    compact: bool = False,
) -> dict[str, Any]:
    """...
    Args:
        compact: When True, omit description, code_snippet,
            suggested_fix, and notes from each finding. Use to fit
            larger result sets in a single response; call
            get_finding(id) for the full record.
    """
```

A compact finding shrinks to ~250 chars (id, file_path, line_number,
severity, title, status). A 50-finding compact list fits well under
any reasonable cap. The caller follows up with `get_finding(id)` for
full detail on the specific findings they care about.

For `scan_directory` the natural compact mode is "return scan_id +
counts only, no findings inline" — the caller pages through with
`list_findings(scan_id=..., compact=True)`.

---

## Notes for whoever picks this up

- **Issue 1 first.** Until it's fixed, anyone running a non-trivial
  scan can't use `llm_triage` at all — the workaround (hand-classify
  via `update_finding`) doesn't scale past ~10 findings.
- **Issue 2 has the largest precision payoff** — cuts FP rates
  dramatically for a class of codebase that's mainstream Python web.
  Worth pairing with `llm_triage` so triage gets the same context.
- **Issue 3 is pure UX.** Easy PR (one new arg, ~10 lines). Defer if
  the others are bigger.

The full triage of the 31 high findings landed in the
sourcing-kernel commit history as
[`8a4bb45`](https://github.com/mfbaig35r/sourcing-kernel/commit/8a4bb45)
(real fixes) and the per-finding `update_finding` calls during the
audit. The OWASP scanner database (`~/.owasp-scanner/scanner.db`)
holds the verdict + reasoning for every finding if you want to
inspect what a real triage pass looks like.
