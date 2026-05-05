# MCP server reliability + per-file context — issues from a real audit

Three issues encountered while running owasp-scanner against
[`mfbaig35r/sourcing-kernel`](https://github.com/mfbaig35r/sourcing-kernel)
on 2026-05-04. Documented here so they don't get lost; each has a
suggested fix sized for a single PR.

**Audit context for the repro:** ~16k LOC Python codebase, 94 source
files, multi-tenant FastAPI + FastMCP service. Hybrid scan against the
production code path (excluding tests + migrations) produced 120
findings: 3 critical, 31 high, ~50 medium, ~36 low.

---

## Issue 1 — `llm_triage` batched call hangs, then crashes the MCP server

**Severity:** high. The crash takes down all 28 MCP tools in the
session; recovery requires reconnecting (or restarting Claude Code).

### Symptom

Calling `llm_triage(finding_ids=[<31 UUIDs>], auto_update=True)` from
Claude Code:

1. The call returns no response for **~7 minutes**.
2. The user (rightly) interrupts.
3. The next call to *any* owasp-scanner tool returns
   `MCP error -32000: Connection closed`.
4. A `system-reminder` enumerates every tool as "no longer available"
   — the entire FastMCP server has dropped the connection.
5. `/mcp` reconnects the server cleanly but the in-progress triage
   results are gone.

For comparison, a single-finding triage during the same session
returned in **~1 second** at $0.0001 (`gpt-5.4-nano`, 664 input
tokens, 112 output tokens).

### Root cause (`src/owasp_scanner/core/llm_scanner.py:238`)

`triage_findings` packs every finding's full context into a single
prompt and makes one OpenAI call:

```python
def triage_findings(
    findings_with_context: list[dict[str, Any]],
) -> tuple[list[TriageResult], LLMUsage]:
    user_content = "Triage these security findings:\n\n"
    for f in findings_with_context:
        user_content += (
            f"Finding ID: {f['id']}\n"
            f"Title: {f['title']}\n"
            f"Description: {f['description']}\n"
            f"File: {f['file_path']}:{f.get('line_number', '?')}\n"
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

For the 31-finding batch in the repro:

- ~700 tokens × 31 findings ≈ 22k input tokens (well under the model's
  context window, but the `code_context` adds ~20 lines per finding)
- The model has to emit 31 structured assessments via function
  calling, each with `verdict + confidence + reasoning + adjusted_severity`
- Everything happens in one synchronous `chat.completions.create` —
  no progress output, no per-finding timeout, no streaming

Plausible failure modes that match the 7-minute symptom:

1. **Slow generation, no progress feedback** — the MCP transport's
   read timeout (or Claude Code's wait threshold) elapsed before the
   call returned, the client disconnected, and the FastMCP server
   crashed when it later tried to reply down the dead connection.
2. **OpenAI rate limit / 5xx with internal SDK retry** — the OpenAI
   client backed off through several attempts, each silent to the
   MCP layer, until something timed out.
3. **Memory pressure** — assembling the 22k-token prompt + buffering
   the streaming response under FastMCP's stdio transport tipped over.

The `try/except → errors.log_error` wrapper at the call site
(`server.py:893`) would have caught a Python-level exception, but a
transport-layer disconnect bypasses it.

### Reproducer

```python
# Against any project where a hybrid scan produces 25+ findings.
scan = scan_directory("/path/to/project", mode="hybrid")
high_ids = [f["id"] for f in list_findings(severity="high", limit=50)["findings"]]
# This call is the one that hangs:
llm_triage(finding_ids=high_ids, auto_update=True)
```

Single-ID calls (`llm_triage([one_id])`) work reliably.

### Suggested fix

Replace the single-prompt batch with **per-finding parallelism +
progress + bounded concurrency**:

1. **Process findings in parallel batches** (e.g.
   `asyncio.Semaphore(default=5)`), one LLM call per finding, not
   one for all 31.
2. **Per-finding timeout** (e.g. `asyncio.wait_for(timeout=30s)`),
   so a single slow call doesn't take down the batch.
3. **Stream progress** via `logger.info("triaged %d/%d", done, total)`
   on a fixed cadence so an operator (or the MCP client) can see the
   call is making progress.
4. **Add a `max_concurrency` arg to the tool** (default 5) so callers
   on tier-3 OpenAI keys can crank it up.
5. **Wrap the whole tool body in `asyncio.wait_for` with a hard
   ceiling** (e.g. `30s × len(findings)` or 600s, whichever is
   smaller) so the MCP transport never sees a >10-min hang.

Single-finding precision wouldn't change — the system prompt is the
same. Cost goes up linearly (31 calls instead of 1) but at
gpt-5.4-nano prices a 100-finding triage is still under $0.01.

### Workaround for the user today

Triage in batches of 5 manually. Or just call `update_finding` per
finding with a hand-classified status — that path is single-call,
fast, and doesn't crash the MCP server.

---

## Issue 2 — Per-file LLM analysis can't see cross-module auth invariants

**Severity:** medium-high. Generates persistent false positives in
any defense-in-depth architecture where the auth boundary is at one
layer and the helpers below it trust their callers.

### Symptom

The 31-high finding set in the repro included **13 false positives**
of the same shape — "missing tenant authorization" flagged on
internal worker / repository / state-machine helpers like
`runners/items/classify.py`, `core/runtime/runs.py`,
`clustering/assign.py`, `orchestration/jobs.py`. Example:

> **Missing tenant/object-level authorization checks when operating
> on run_id** (high, A01)
> All stage runners accept (run_id, tenant_id) and then perform
> reads/writes scoped only by run_id (e.g., RunItems.run_id ==
> run_id, RunClassification.run_id == run_id, ...). The code relies
> on load_run_context(...) to enforce that the provided tenant_id is
> authorized for the given run_id, but subsequent queries use run_id
> without re-checking tenant ownership. If load_run_context is
> imperfect or bypassable, this becomes an object-level access
> control gap (IDOR)...

The codebase actually has a robust API-layer auth gate (every route
filters `Run.tenant_id == ctx.tenant_id` before any of these
helpers run), explicitly documented in `docs/backlog.md`'s
`Confirmed not-bugs` section, and verified by an integration test
matrix (commit `2665533`). But the LLM, looking at one file at a
time, can't see any of that.

### Why this matters

Every project with this architecture (and there are many — defense
in depth + thin internal helpers is mainstream Python web design)
will hit the same noise. The reviewer ends up either ignoring all
A01 findings (dangerous) or hand-marking each one (slow). The
scanner does the right thing per-file; it's just blind to the
project-level shape.

### Suggested fix

Add an **optional project-context file** that gets prepended to
every LLM analysis prompt:

1. **CLI flag**: `--context-file path/to/.owasp-context.md`
2. **MCP tool arg**: `context_file: str | None = None` on
   `scan_directory`
3. **Auto-discover** `.owasp-context.md` in the target directory
   (same pattern as `.owaspignore`)

The contents would be a short paragraph the LLM reads as
authoritative context. For the repro project it would look like:

```markdown
# OWASP scan context

Auth model: every API route + MCP tool gates with
`Run.tenant_id == ctx.tenant_id` (or equivalent for the resource
type) BEFORE invoking internal helpers. Functions in
`core/runtime/`, `orchestration/`, `pipelines/`, and `clustering/`
are worker-internal — they receive trusted IDs from validated
callers. Cross-tenant isolation is verified by
`tests/integration/test_multi_tenant_isolation_pg.py` (10-case
matrix).

Known limitations: no DB-level RLS yet (deferred); MCP transport
is one-tenant-per-process via `SK_API_KEY` (no per-call auth by
design — see `docs/backlog.md`).
```

Estimated impact on the repro scan: would have cut high-severity
false positives from ~13 to ~0 without losing the 6 real findings.

This isn't a substitute for proper triage — the LLM can still
disagree if a specific code path obviously contradicts the context
— but it fixes the precision problem for architectural patterns
that are correct-by-design.

### Adjacent: triage could use the same context

If implemented, `llm_triage` should also accept the context file
(or read it from the same auto-discovered location). Today triage
runs per-finding without project context, so the same flagged
helper gets the same false-positive verdict on retry.

---

## Issue 3 — `list_findings` and `scan_directory` outputs blow past the inline cap

**Severity:** low UX issue (workaround exists; caller falls back to a
persisted file). Worth fixing for quality of life.

### Symptom

In Claude Code, two MCP tool responses exceeded the inline tool-output
cap and auto-spilled to a file:

- `scan_directory(... mode="hybrid")` → 71,326 chars
- `list_findings(severity="high", limit=50)` → 51 KB / 31 findings

When that happens, the MCP layer writes the response to a temp file
and the caller has to read + parse it, which is fine for an LLM
agent but means the conversational flow "scan → look at findings"
takes 2-3 round trips instead of one.

### Root cause

Each finding's response payload includes:

- `title` (~50-150 chars)
- `description` (300-800 chars, often multi-paragraph)
- `code_snippet` (3-5 lines, ~150 chars)
- `suggested_fix` (200-400 chars)
- `notes`, `code_context`, etc.

At ~1.5-2 KB per finding, 30 findings = ~50 KB. The information
density is fine; the inline cap just wasn't designed for this volume.

### Suggested fix

Add a `compact=True` flag to `list_findings` and `scan_directory`
that drops the verbose fields from the response (still in the DB,
still recoverable via `get_finding(id)`):

```python
async def list_findings(..., compact: bool = False) -> dict[str, Any]:
    """Args:
        compact: When True, omit description, code_snippet,
            suggested_fix, and notes from each finding. Use to fit
            larger result sets in a single response; call
            get_finding(id) for the full record.
    """
```

Compact response per finding shrinks to ~250 chars: id, file_path,
line_number, severity, title, status. A 50-finding compact list
fits well under the inline cap. Caller asks for full detail on the
specific findings they care about.

For `scan_directory`, the natural compact mode is "return the scan
ID + counts only, no findings" — let the caller follow up with
`list_findings(scan_id=...)` if they want the details.

---

## What I did instead during the audit

For the record, none of these issues blocked the actual security
review. After hitting issue 1 twice, I:

1. Read the persisted findings file directly (~50 KB JSON).
2. Manually classified all 31 high findings using `update_finding`
   (single-call, fast, didn't crash the MCP).
3. Filed a triage summary back to the user with the 6 real items
   surfaced and the 13 architectural false positives marked
   `false_positive` with reasoning.

`update_finding` was the workhorse — single-finding calls are
reliable and the response is always small.

---

## Priority for fixing

If pickup order matters: **issue 1 first** (the crash is a real
operational problem), **issue 2 second** (cuts noise dramatically
for a whole class of codebase), **issue 3 third** (UX polish).
Issue 1 should land first in any case so future audits aren't
blocked by it.
