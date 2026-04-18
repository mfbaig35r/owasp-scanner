# OWASP Scanner v2 — Status

Three features built: cross-file data flow analysis, CI-integrated scanning,
and report timestamp labeling. 261 tests, 26 tools, 32 rules.

---

## 1. Cross-File Data Flow Analysis ✅ (with known limitations)

### What was built

- **`core/dataflow.py`** — AST-based taint analysis engine
- **`trace_dataflow` MCP tool** — traces tainted data from MCP tools / API
  endpoints through function calls to dangerous sinks
- **`deep_analyze` integration** — 1-hop cross-file taint analysis runs
  automatically when the file imports other project modules

### Capabilities

| Capability | Status |
|------------|--------|
| Taint source detection (MCP `@mcp.tool()`, FastAPI routes) | ✅ |
| Cross-file import resolution (`from .module import Class`) | ✅ |
| Instance method resolution (`executor = Foo(); executor.method()`) | ✅ |
| `self.method()` intra-class call tracing | ✅ |
| Keyword argument mapping (`execute(packages=packages)`) | ✅ |
| Ternary expression propagation (`x if cond else None`) | ✅ |
| Assignment-based taint expansion (`cmd = ' '.join(packages)`) | ✅ |
| `ast.Starred` / `ast.Subscript` name extraction | ✅ |
| Configurable hop limit (`max_hops`, default 3) | ✅ |
| Sanitizer detection (regex, isinstance, validate patterns) | ✅ |

### Sink types

| Sink type | Pattern |
|-----------|---------|
| `shell_injection` | `os.system`, `os.popen`, `subprocess` with `shell=True` |
| `code_execution` | `eval()`, `exec()`, `compile()` |
| `sql_injection` | `cursor.execute()`, `conn.execute()`, `db.execute()`, `session.execute()` |
| `path_traversal` | `open()` with user-controlled paths |
| `deserialization` | `pickle.loads()`, `yaml.load()` |
| `ssrf` | `urllib.request.urlopen`, `requests.get/post`, `socket.connect` |

### Verified findings

The tracer correctly identifies:
- **SSRF via `port` parameter**: `open_notebook(port)` → `_impl_open_notebook`
  → `_server_is_healthy` → `urllib.request.urlopen(f"http://127.0.0.1:{port}/health")`
  — classified as `ssrf`, unsanitized.

### Known limitation: list/tuple element taint propagation

The tracer does **not** propagate taint through list or tuple elements. When a
tainted value is placed inside a list literal and the list is passed as an
argument, the taint is lost.

**Example (not detected):**

```python
# executor.py — the actual marimo-sandbox pattern
install_cmd = f"pip install {' '.join(packages)}"   # ← tainted via assignment ✅
cmd = [
    "docker", "run", ...,
    "--entrypoint", "sh",
    self.docker_image,
    "-c", install_cmd,    # ← tainted value inside list literal ❌ lost here
]
subprocess.run(cmd, ...)  # ← sink, but cmd appears untainted
```

The taint correctly propagates through:
1. `packages` parameter (taint source) ✅
2. `' '.join(packages)` in f-string → `install_cmd` (assignment expansion) ✅
3. `install_cmd` placed in a `[...]` list literal → taint lost ❌
4. List passed to `subprocess.run(cmd)` → not flagged

**Why this is hard:** Lists are ubiquitous in Python. Tainting every list that
contains a tainted element would produce many false positives (e.g.,
`[run_id, "success"]` is a list with tainted data but isn't dangerous).
A useful fix would need to be context-aware — only propagate list-element taint
when the list is passed to a known sink like `subprocess.run` or `os.execv`.

**Workaround:** This specific flow (command injection via package names) was
caught by the v1 regex scan + manual review and is logged as a persistent
finding in the scanner database. The recommended workflow is: automated
scanning catches common patterns, `trace_dataflow` catches cross-file design
issues, and `create_finding` captures what manual review uncovers.

### Future work (v3)

- **Context-aware list taint**: when a tainted element enters a list/tuple and
  that list is passed to `subprocess.run`, `os.execv`, or similar, flag it.
- **Return value taint**: track tainted data flowing back through return values
  to callers.
- **f-string sink detection**: when an f-string contains tainted data and is
  used in a shell/SQL context (assigned to a variable named `cmd`, `query`,
  `sql`, etc.), flag it directly as a sink regardless of what happens next.

---

## 2. CI Integration ✅

### What was built

- **`scan_changes(deep=True)`** — runs regex scan + `deep_analyze` on git-
  changed Python files
- **`scan_pr` MCP tool** — combines `scan_changes(deep=True)` +
  `scan_dependencies` into a single pre-PR security check
- **CLI mode** with `--scan` and `--fail-on` exit codes

### `scan_pr` tool

```
scan_pr(
    path: str,
    base_branch: str = "main",
    output_format: str = "summary",  # "summary" | "sarif" | "markdown"
) -> dict
```

Returns:
```json
{
  "changed_files": 3,
  "regex_findings": 2,
  "new_findings": 1,
  "dependency_vulnerabilities": 0,
  "severity_counts": {"high": 1, "medium": 1},
  "pass": false,
  "findings": [...],
  "deep_analysis": [...]
}
```

- `pass: true/false` — verdict for CI (fails on any critical/high finding)
- SARIF output mode for GitHub code scanning annotations
- Markdown output mode for PR comments

### Verified behavior

- Clean branch (no changes vs main) → `pass: true`, 0 findings
- Non-git directory → clear error message

---

## 3. Report Timestamps ✅

### What was built

- **Report metadata header**: `Generated:` timestamp, `Scan history:` summary
- **Finding timestamps**: `Found:` on each finding detail
- **Triage timestamps**: `Triaged:` on each false positive / accepted finding
- **`_fmt_ts()` helper**: ISO → `2026-04-18 06:17 UTC` formatting

### Example output

```markdown
**Generated:** 2026-04-18 06:17 UTC
**Scan history:** 3 scans, first: 2026-04-18, latest: 2026-04-18

### 1. [HIGH] Command injection via package names
- **Found:** 2026-04-18 00:58 UTC

## Triaged Findings
- **[False Positive]** eval() usage (test_analyzer.py)
  - *Triaged:* 2026-04-18 00:59 UTC
```
