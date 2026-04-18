"""Cross-file data flow analysis using Python AST.

Traces tainted data (from MCP tools, API endpoints, user input) through
function calls across files to dangerous sinks (subprocess, eval, SQL, etc).
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ── Data structures ────────────────────────────────────────────────────────


@dataclass
class Assignment:
    """A variable assignment within a function body."""
    target: str       # variable being assigned to
    sources: list[str]  # variables used in the right-hand side
    line: int


@dataclass
class FunctionInfo:
    """Information about a function extracted from AST."""
    name: str
    file: str
    line: int
    params: list[str]
    class_name: str | None = None  # set if this is a method
    callees: list[CallSite] = field(default_factory=list)
    assignments: list[Assignment] = field(default_factory=list)
    decorators: list[str] = field(default_factory=list)
    is_taint_source: bool = False

    def qualified_name(self) -> str:
        if self.class_name:
            return f"{self.file}:{self.class_name}.{self.name}"
        return f"{self.file}:{self.name}"


@dataclass
class CallSite:
    """A function call within a function body."""
    callee: str           # e.g. "executor.execute" or "os.system"
    line: int
    args_passed: list[str]  # variable names used in arguments (positional)
    kwargs_passed: dict[str, list[str]] = field(default_factory=dict)  # kw_name → var names
    is_sink: bool = False
    sink_type: str = ""


@dataclass
class TaintFlow:
    """A traced path from taint source to sink."""
    source_file: str
    source_function: str
    source_param: str
    source_line: int
    path: list[dict[str, Any]]
    sink_file: str
    sink_line: int
    sink_type: str
    sanitized: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": {
                "file": self.source_file,
                "function": self.source_function,
                "param": self.source_param,
                "line": self.source_line,
            },
            "path": self.path,
            "sink": {
                "file": self.sink_file,
                "line": self.sink_line,
                "type": self.sink_type,
            },
            "sanitized": self.sanitized,
        }


# ── Taint source / sink patterns ──────────────────────────────────────────

# Decorators that mark functions as receiving untrusted input
_TAINT_SOURCE_DECORATORS = {
    "mcp.tool",
    "app.get", "app.post", "app.put", "app.delete", "app.patch",
    "route", "api_view",
}

# Dangerous function calls (sinks)
# Order matters — more specific patterns before general ones
_SINK_PATTERNS: list[tuple[str, str]] = [
    # Command injection
    (r"os\.system", "command_injection"),
    (r"subprocess\.(?:run|call|Popen|check_output)", "command_injection"),
    # Code execution
    (r"\beval$", "code_execution"),
    (r"\bexec$", "code_execution"),
    # Deserialization
    (r"pickle\.loads?", "deserialization"),
    (r"yaml\.load", "deserialization"),
    # SQL injection — only database-context .execute()
    (r"(?:cursor|conn|connection|db|session)\.execute(?:many)?$", "sql_injection"),
    (r"\.raw$", "sql_injection"),
    # Network / SSRF — urlopen, requests, socket with user-controlled input
    (r"urllib\.request\.urlopen", "ssrf"),
    (r"requests\.(?:get|post|put|delete|patch|head)", "ssrf"),
    (r"httpx\.(?:get|post|put|delete|patch|head)", "ssrf"),
    (r"socket\.connect", "ssrf"),
    (r"urlopen", "ssrf"),
    # Path traversal — file operations (but not urlopen which is SSRF)
    (r"\bopen$", "path_traversal"),
    (r"shutil\.(?:copy|move|rmtree)", "path_traversal"),
    (r"Path\.\w+", "path_traversal"),
]

# Patterns suggesting sanitization/validation
_SANITIZER_PATTERNS = [
    r"isinstance\(",
    r"re\.match\(",
    r"re\.search\(",
    r"validate",
    r"sanitize",
    r"escape",
    r"quote\(",
    r"shlex\.quote",
    r"parameterize",
    r"\.resolve\(\).*\.is_relative_to\(",
]


# ── AST Analysis ──────────────────────────────────────────────────────────


class FunctionAnalyzer(ast.NodeVisitor):
    """Extract function info from an AST."""

    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        self.functions: list[FunctionInfo] = []
        self._current_func: FunctionInfo | None = None
        self._current_class: str | None = None
        # Module-level instance assignments: var_name → ClassName
        self.instance_types: dict[str, str] = {}

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        prev_class = self._current_class
        self._current_class = node.name
        self.generic_visit(node)
        self._current_class = prev_class

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        decorators = []
        is_source = False
        for dec in node.decorator_list:
            dec_name = _get_decorator_name(dec)
            decorators.append(dec_name)
            if any(s in dec_name for s in _TAINT_SOURCE_DECORATORS):
                is_source = True

        params = [
            arg.arg for arg in node.args.args
            if arg.arg != "self"
        ]

        func = FunctionInfo(
            name=node.name,
            file=self.file_path,
            line=node.lineno,
            params=params,
            class_name=self._current_class,
            decorators=decorators,
            is_taint_source=is_source,
        )

        # Analyze function body for calls and sinks
        prev = self._current_func
        self._current_func = func
        self.generic_visit(node)
        self._current_func = prev

        self.functions.append(func)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node: ast.Assign) -> None:
        """Track variable assignments for taint propagation and instance types."""
        # Module-level: track instance assignments like executor = NotebookExecutor(...)
        if self._current_func is None and self._current_class is None:
            if isinstance(node.value, ast.Call):
                class_name = _get_call_name(node.value)
                for target in node.targets:
                    if isinstance(target, ast.Name) and class_name:
                        self.instance_types[target.id] = class_name
            self.generic_visit(node)
            return

        if self._current_func is None:
            self.generic_visit(node)
            return

        sources = _extract_names(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name) and sources:
                self._current_func.assignments.append(Assignment(
                    target=target.id,
                    sources=sources,
                    line=node.lineno,
                ))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if self._current_func is None:
            self.generic_visit(node)
            return

        callee_name = _get_call_name(node)
        if not callee_name:
            self.generic_visit(node)
            return

        # Extract argument names (for taint tracking)
        # Handles direct names, f-strings containing names, and nested exprs
        args_passed: list[str] = []
        kwargs_passed: dict[str, list[str]] = {}
        for arg in node.args:
            args_passed.extend(_extract_names(arg))
        for kw in node.keywords:
            names = _extract_names(kw.value)
            if kw.arg:
                kwargs_passed[kw.arg] = names
            args_passed.extend(names)  # Also add to flat list for sink detection

        # Check if this is a known sink
        is_sink = False
        sink_type = ""
        for pattern, stype in _SINK_PATTERNS:
            if re.search(pattern, callee_name):
                is_sink = True
                sink_type = stype
                break

        self._current_func.callees.append(CallSite(
            callee=callee_name,
            line=node.lineno,
            args_passed=args_passed,
            kwargs_passed=kwargs_passed,
            is_sink=is_sink,
            sink_type=sink_type,
        ))

        self.generic_visit(node)


def _extract_names(node: ast.expr) -> list[str]:
    """Extract all Name references from an expression.

    Handles: plain names, f-strings, function calls, binary ops,
    ternary expressions (x if cond else y), subscripts, starred args.
    """
    names: list[str] = []
    if isinstance(node, ast.Name):
        names.append(node.id)
    elif isinstance(node, ast.JoinedStr):
        # f-string: extract names from format values
        for value in node.values:
            if isinstance(value, ast.FormattedValue):
                names.extend(_extract_names(value.value))
    elif isinstance(node, ast.Call):
        for arg in node.args:
            names.extend(_extract_names(arg))
    elif isinstance(node, ast.BinOp):
        names.extend(_extract_names(node.left))
        names.extend(_extract_names(node.right))
    elif isinstance(node, ast.IfExp):
        # Ternary: x if cond else y — taint flows through both branches
        names.extend(_extract_names(node.body))
        names.extend(_extract_names(node.orelse))
    elif isinstance(node, ast.Starred):
        names.extend(_extract_names(node.value))
    elif isinstance(node, ast.Subscript):
        names.extend(_extract_names(node.value))
    return names


def _get_decorator_name(node: ast.expr) -> str:
    """Extract decorator name from AST node."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        value = _get_decorator_name(node.value)
        return f"{value}.{node.attr}" if value else node.attr
    if isinstance(node, ast.Call):
        return _get_decorator_name(node.func)
    return ""


def _get_call_name(node: ast.Call) -> str:
    """Extract function call name from AST node."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        value = ""
        if isinstance(node.func.value, ast.Name):
            value = node.func.value.id
        elif isinstance(node.func.value, ast.Attribute):
            value = _get_call_name(
                ast.Call(func=node.func.value, args=[], keywords=[])
            )
        return f"{value}.{node.func.attr}" if value else node.func.attr
    return ""


# ── Module Resolution ─────────────────────────────────────────────────────


def resolve_module(
    import_name: str,
    current_file: Path,
    project_root: Path,
) -> Path | None:
    """Resolve an import name to a file path within the project.

    Handles:
    - Relative imports: from .executor import X
    - Absolute imports: from mypackage.executor import X
    - Simple imports: import executor
    """
    # Try relative to current file's package
    current_dir = current_file.parent
    parts = import_name.lstrip(".").split(".")

    # Count leading dots for relative imports
    dots = len(import_name) - len(import_name.lstrip("."))
    if dots > 0:
        base = current_dir
        for _ in range(dots - 1):
            base = base.parent
        candidate = base / "/".join(parts)
    else:
        candidate = project_root / "/".join(parts)

    # Try as module file
    if (candidate.with_suffix(".py")).is_file():
        return candidate.with_suffix(".py")

    # Try as package
    if (candidate / "__init__.py").is_file():
        return candidate / "__init__.py"

    return None


# ── Import Extraction ─────────────────────────────────────────────────────


@dataclass
class ImportInfo:
    module: str          # "from X" part
    names: list[str]     # "import A, B" part
    alias: str | None    # "as Y" part
    line: int


class ImportExtractor(ast.NodeVisitor):
    """Extract import statements from AST."""

    def __init__(self) -> None:
        self.imports: list[ImportInfo] = []

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports.append(ImportInfo(
                module=alias.name,
                names=[alias.name.split(".")[-1]],
                alias=alias.asname,
                line=node.lineno,
            ))

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = ("." * (node.level or 0)) + (node.module or "")
        names = [alias.name for alias in node.names]
        self.imports.append(ImportInfo(
            module=module,
            names=names,
            alias=None,
            line=node.lineno,
        ))


# ── Main Analysis ─────────────────────────────────────────────────────────


@dataclass
class FileAnalysis:
    """Complete analysis results for a file."""
    functions: list[FunctionInfo]
    imports: list[ImportInfo]
    instance_types: dict[str, str]  # var_name → ClassName


def analyze_file(
    file_path: Path,
) -> tuple[list[FunctionInfo], list[ImportInfo]]:
    """Parse a Python file and extract function info + imports."""
    result = analyze_file_full(file_path)
    return result.functions, result.imports


def analyze_file_full(file_path: Path) -> FileAnalysis:
    """Parse a Python file and extract functions, imports, and instance types."""
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(file_path))
    except SyntaxError:
        return FileAnalysis([], [], {})

    func_analyzer = FunctionAnalyzer(str(file_path))
    func_analyzer.visit(tree)

    import_extractor = ImportExtractor()
    import_extractor.visit(tree)

    return FileAnalysis(
        functions=func_analyzer.functions,
        imports=import_extractor.imports,
        instance_types=func_analyzer.instance_types,
    )


def _check_sanitization(source_lines: list[str], start_line: int, end_line: int) -> bool:
    """Check if there's any sanitization between two lines in the source."""
    for i in range(start_line - 1, min(end_line, len(source_lines))):
        line = source_lines[i]
        for pattern in _SANITIZER_PATTERNS:
            if re.search(pattern, line):
                return True
    return False


def trace_dataflows(
    project_root: Path,
    target_file: Path | None = None,
    max_hops: int = 3,
) -> list[TaintFlow]:
    """Trace tainted data from sources to sinks across files.

    Args:
        project_root: Root directory of the project.
        target_file: If specified, only analyze flows starting from this file.
        max_hops: Maximum call depth to trace (default 3).

    Returns:
        List of taint flows found.
    """
    # Step 1: Collect all Python files
    py_files: list[Path] = []
    if target_file and target_file.is_file():
        py_files = [target_file]
        # Also include files imported by the target
    else:
        for f in project_root.rglob("*.py"):
            if any(skip in f.parts for skip in (
                ".venv", "venv", "node_modules", "__pycache__",
                ".git", "dist", "build",
            )):
                continue
            py_files.append(f)

    # Step 2: Build function index across all files
    all_functions: dict[str, FunctionInfo] = {}  # qualified_name -> FunctionInfo
    all_imports: dict[str, list[ImportInfo]] = {}  # file_path -> imports
    all_instances: dict[str, dict[str, str]] = {}  # file -> {var: ClassName}
    source_cache: dict[str, list[str]] = {}  # file_path -> source lines

    def _index_file(f: Path) -> None:
        analysis = analyze_file_full(f)
        all_imports[str(f)] = analysis.imports
        all_instances[str(f)] = analysis.instance_types
        try:
            source_cache[str(f)] = f.read_text(
                encoding="utf-8", errors="replace"
            ).split("\n")
        except OSError:
            source_cache[str(f)] = []
        for func in analysis.functions:
            all_functions[func.qualified_name()] = func

    for f in py_files:
        _index_file(f)

    # If we started from a target file, recursively discover imported files
    if target_file and target_file.is_file():
        discovery_queue = [target_file]
        discovered: set[str] = {str(target_file)}
        for _ in range(max_hops + 1):
            next_queue: list[Path] = []
            for source_file in discovery_queue:
                for imp in all_imports.get(str(source_file), []):
                    resolved = resolve_module(imp.module, source_file, project_root)
                    if resolved and str(resolved) not in discovered:
                        discovered.add(str(resolved))
                        _index_file(resolved)
                        next_queue.append(resolved)
            discovery_queue = next_queue
            if not discovery_queue:
                break

    # Step 3: Find taint sources
    taint_sources: list[tuple[FunctionInfo, str]] = []  # (func, param)
    for func in all_functions.values():
        if func.is_taint_source:
            for param in func.params:
                taint_sources.append((func, param))

    # Step 4: Trace each taint source through calls
    flows: list[TaintFlow] = []

    for source_func, source_param in taint_sources:
        _trace_param(
            source_func=source_func,
            param_name=source_param,
            current_func=source_func,
            path=[],
            all_functions=all_functions,
            all_imports=all_imports,
            all_instances=all_instances,
            source_cache=source_cache,
            project_root=project_root,
            flows=flows,
            depth=0,
            max_hops=max_hops,
            visited=set(),
        )

    return flows


def _trace_param(
    *,
    source_func: FunctionInfo,
    param_name: str,
    current_func: FunctionInfo,
    path: list[dict[str, Any]],
    all_functions: dict[str, FunctionInfo],
    all_imports: dict[str, list[ImportInfo]],
    all_instances: dict[str, dict[str, str]],
    source_cache: dict[str, list[str]],
    project_root: Path,
    flows: list[TaintFlow],
    depth: int,
    max_hops: int,
    visited: set[str],
) -> None:
    """Recursively trace a tainted parameter through function calls."""
    if depth > max_hops:
        return

    visit_key = f"{current_func.qualified_name()}:{param_name}:{depth}"
    if visit_key in visited:
        return
    visited.add(visit_key)

    # Expand taint through variable assignments
    # e.g., cmd = ' '.join(packages) → cmd is now tainted
    tainted: set[str] = {param_name}
    changed = True
    while changed:
        changed = False
        for assign in current_func.assignments:
            if assign.target not in tainted:
                if any(src in tainted for src in assign.sources):
                    tainted.add(assign.target)
                    changed = True

    for call in current_func.callees:
        # Check if any tainted variable is passed to this call
        if not any(t in call.args_passed for t in tainted):
            continue

        step = {
            "file": current_func.file,
            "line": call.line,
            "call": call.callee,
            "param": param_name,
        }

        # Check if this call is a sink
        if call.is_sink:
            # Check for sanitization between function start and sink
            lines = source_cache.get(current_func.file, [])
            sanitized = _check_sanitization(
                lines, current_func.line, call.line,
            )

            flows.append(TaintFlow(
                source_file=source_func.file,
                source_function=source_func.name,
                source_param=param_name if depth == 0 else path[0].get("param", param_name),
                source_line=source_func.line,
                path=[*path, step],
                sink_file=current_func.file,
                sink_line=call.line,
                sink_type=call.sink_type,
                sanitized=sanitized,
            ))
            continue

        # Try to resolve the callee to a known function and trace further
        resolved_func = _resolve_callee(
            call.callee,
            current_func,
            all_functions,
            all_imports,
            all_instances,
            project_root,
        )
        if resolved_func:
            # Map the tainted arg to the callee's parameter
            # First check keyword args (name-based mapping)
            callee_params: list[str] = []
            for kw_name, kw_vars in call.kwargs_passed.items():
                if any(t in kw_vars for t in tainted) and kw_name in resolved_func.params:
                    callee_params.append(kw_name)

            # Fall back to positional mapping
            if not callee_params:
                positional_args = [
                    a for a in call.args_passed
                    if not any(a in vs for vs in call.kwargs_passed.values())
                ]
                for t in tainted:
                    if t in positional_args:
                        arg_idx = positional_args.index(t)
                        if arg_idx < len(resolved_func.params):
                            p = resolved_func.params[arg_idx]
                            if p not in callee_params:
                                callee_params.append(p)

            for callee_param in callee_params:
                _trace_param(
                    source_func=source_func,
                    param_name=callee_param,
                    current_func=resolved_func,
                    path=[*path, step],
                    all_functions=all_functions,
                    all_imports=all_imports,
                    all_instances=all_instances,
                    source_cache=source_cache,
                    project_root=project_root,
                    flows=flows,
                    depth=depth + 1,
                    max_hops=max_hops,
                    visited=visited,
                )


def _resolve_callee(
    callee: str,
    current_func: FunctionInfo,
    all_functions: dict[str, FunctionInfo],
    all_imports: dict[str, list[ImportInfo]],
    all_instances: dict[str, dict[str, str]],
    project_root: Path,
) -> FunctionInfo | None:
    """Try to resolve a callee name to a FunctionInfo.

    Handles:
    - Local function calls: helper(x)
    - Imported function calls: from .b import step2; step2(x)
    - Module.function calls: executor.run(x)
    - Instance.method calls: executor.execute(x) where executor = NotebookExecutor()
    - self.method calls: self._run_docker(x) within a class
    """
    caller_file = current_func.file
    parts = callee.split(".")

    if len(parts) < 2:
        # Simple name — local function or imported name
        key = f"{caller_file}:{callee}"
        local = all_functions.get(key)
        if local:
            return local

        # Check if it's within the same class
        if current_func.class_name:
            key = f"{caller_file}:{current_func.class_name}.{callee}"
            method = all_functions.get(key)
            if method:
                return method

        # Check imported names
        imports = all_imports.get(caller_file, [])
        for imp in imports:
            if callee in imp.names:
                resolved = resolve_module(
                    imp.module, Path(caller_file), project_root,
                )
                if resolved:
                    key = f"{resolved}:{callee}"
                    found = all_functions.get(key)
                    if found:
                        return found
        return None

    # X.method() pattern
    obj_name = parts[0]
    method_name = parts[-1]

    # Case 1: self.method() — resolve within the same class
    if obj_name == "self" and current_func.class_name:
        key = f"{caller_file}:{current_func.class_name}.{method_name}"
        return all_functions.get(key)

    # Case 2: instance.method() — look up instance type from module-level assignments
    instances = all_instances.get(caller_file, {})
    if obj_name in instances:
        class_name = instances[obj_name]
        # The class might be in the same file or imported
        # Try same file first
        key = f"{caller_file}:{class_name}.{method_name}"
        found = all_functions.get(key)
        if found:
            return found

        # Try imported module
        imports = all_imports.get(caller_file, [])
        for imp in imports:
            if class_name in imp.names:
                resolved = resolve_module(
                    imp.module, Path(caller_file), project_root,
                )
                if resolved:
                    key = f"{resolved}:{class_name}.{method_name}"
                    found = all_functions.get(key)
                    if found:
                        return found

    # Case 3: module.function() — import-based resolution
    imports = all_imports.get(caller_file, [])
    for imp in imports:
        if imp.alias == obj_name or obj_name in imp.names:
            resolved = resolve_module(
                imp.module, Path(caller_file), project_root,
            )
            if resolved:
                # Try as plain function
                key = f"{resolved}:{method_name}"
                found = all_functions.get(key)
                if found:
                    return found
                # Try as class.method (if obj is actually a class imported directly)
                for qn, func in all_functions.items():
                    if qn.startswith(str(resolved) + ":") and func.name == method_name:
                        return func

        # "from mypackage import executor" → executor.func()
        if obj_name in imp.names:
            sub_module = f"{imp.module}.{obj_name}"
            resolved = resolve_module(
                sub_module, Path(caller_file), project_root,
            )
            if resolved:
                key = f"{resolved}:{method_name}"
                found = all_functions.get(key)
                if found:
                    return found

    return None
