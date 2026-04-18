"""Tests for cross-file data flow analysis."""

from __future__ import annotations

from pathlib import Path

from owasp_scanner.core.dataflow import (
    analyze_file,
    resolve_module,
    trace_dataflows,
)


class TestAnalyzeFile:
    def test_extracts_functions(self, tmp_path: Path):
        f = tmp_path / "app.py"
        f.write_text("""
def hello(name: str):
    print(name)

async def greet(user):
    return f"Hello {user}"
""")
        functions, imports = analyze_file(f)
        names = [fn.name for fn in functions]
        assert "hello" in names
        assert "greet" in names

    def test_detects_mcp_taint_source(self, tmp_path: Path):
        f = tmp_path / "server.py"
        f.write_text("""
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("test")

@mcp.tool()
async def run_code(code: str, packages: list):
    execute(code)
""")
        functions, _ = analyze_file(f)
        run_code = [fn for fn in functions if fn.name == "run_code"][0]
        assert run_code.is_taint_source
        assert "code" in run_code.params

    def test_detects_fastapi_taint_source(self, tmp_path: Path):
        f = tmp_path / "api.py"
        f.write_text("""
from fastapi import FastAPI
app = FastAPI()

@app.post("/execute")
async def execute_code(body: dict):
    eval(body["code"])
""")
        functions, _ = analyze_file(f)
        execute = [fn for fn in functions if fn.name == "execute_code"][0]
        assert execute.is_taint_source

    def test_detects_sinks(self, tmp_path: Path):
        f = tmp_path / "runner.py"
        f.write_text("""
import os
import subprocess

def run_cmd(cmd):
    os.system(cmd)

def run_safe(args):
    subprocess.run(args)
""")
        functions, _ = analyze_file(f)
        run_cmd = [fn for fn in functions if fn.name == "run_cmd"][0]
        sinks = [c for c in run_cmd.callees if c.is_sink]
        assert len(sinks) == 1
        assert sinks[0].sink_type == "command_injection"

    def test_extracts_imports(self, tmp_path: Path):
        f = tmp_path / "app.py"
        f.write_text("""
import os
from pathlib import Path
from .executor import run
""")
        _, imports = analyze_file(f)
        modules = [i.module for i in imports]
        assert "os" in modules
        assert "pathlib" in modules
        assert ".executor" in modules

    def test_syntax_error_returns_empty(self, tmp_path: Path):
        f = tmp_path / "bad.py"
        f.write_text("def broken(\n")
        functions, imports = analyze_file(f)
        assert functions == []
        assert imports == []

    def test_extracts_call_args(self, tmp_path: Path):
        f = tmp_path / "app.py"
        f.write_text("""
def process(user_input):
    helper(user_input, "static")
""")
        functions, _ = analyze_file(f)
        process = [fn for fn in functions if fn.name == "process"][0]
        assert len(process.callees) == 1
        assert "user_input" in process.callees[0].args_passed


class TestResolveModule:
    def test_resolve_relative_import(self, tmp_path: Path):
        pkg = tmp_path / "mypackage"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "server.py").write_text("")
        (pkg / "executor.py").write_text("")

        result = resolve_module(
            ".executor",
            pkg / "server.py",
            tmp_path,
        )
        assert result == pkg / "executor.py"

    def test_resolve_absolute_import(self, tmp_path: Path):
        pkg = tmp_path / "mypackage"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "utils.py").write_text("")

        result = resolve_module(
            "mypackage.utils",
            pkg / "server.py",
            tmp_path,
        )
        assert result == pkg / "utils.py"

    def test_resolve_nonexistent(self, tmp_path: Path):
        result = resolve_module(
            "nonexistent",
            tmp_path / "app.py",
            tmp_path,
        )
        assert result is None


class TestTraceDataflows:
    def test_direct_sink_in_same_file(self, tmp_path: Path):
        f = tmp_path / "server.py"
        f.write_text("""
import os

@app.post("/run")
async def run_cmd(command: str):
    os.system(command)
""")
        flows = trace_dataflows(tmp_path, target_file=f)
        assert len(flows) >= 1
        assert flows[0].sink_type == "command_injection"
        assert not flows[0].sanitized

    def test_sanitized_flow_detected(self, tmp_path: Path):
        f = tmp_path / "server.py"
        f.write_text("""
import os
import re

@app.post("/run")
async def run_cmd(hostname: str):
    if not re.match(r'^[a-z.]+$', hostname):
        raise ValueError("bad")
    os.system(f"ping {hostname}")
""")
        flows = trace_dataflows(tmp_path, target_file=f)
        assert len(flows) >= 1
        assert flows[0].sanitized  # re.match detected

    def test_cross_file_flow(self, tmp_path: Path):
        pkg = tmp_path / "myapp"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")

        (pkg / "server.py").write_text("""
from .executor import execute

@app.post("/run")
async def run_code(code: str):
    execute(code)
""")
        (pkg / "executor.py").write_text("""
def execute(code):
    eval(code)
""")
        flows = trace_dataflows(tmp_path, target_file=pkg / "server.py")
        # Should find: run_code(code) → execute(code) → eval(code)
        eval_flows = [f for f in flows if f.sink_type == "code_execution"]
        assert len(eval_flows) >= 1
        assert eval_flows[0].source_function == "run_code"
        assert eval_flows[0].source_param == "code"

    def test_no_taint_sources_no_flows(self, tmp_path: Path):
        f = tmp_path / "utils.py"
        f.write_text("""
import os

def cleanup(path):
    os.system(f"rm -rf {path}")
""")
        flows = trace_dataflows(tmp_path, target_file=f)
        assert len(flows) == 0  # No @app.post or @mcp.tool

    def test_max_hops_respected(self, tmp_path: Path):
        pkg = tmp_path / "deep"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")

        (pkg / "a.py").write_text("""
from .b import step2

@app.post("/start")
async def start(data: str):
    step2(data)
""")
        (pkg / "b.py").write_text("""
from .c import step3

def step2(data):
    step3(data)
""")
        (pkg / "c.py").write_text("""
from .d import step4

def step3(data):
    step4(data)
""")
        (pkg / "d.py").write_text("""
def step4(data):
    eval(data)
""")
        # With max_hops=2, should NOT reach d.py (3 hops needed)
        flows_short = trace_dataflows(tmp_path, pkg / "a.py", max_hops=2)
        eval_flows = [f for f in flows_short if f.sink_type == "code_execution"]
        assert len(eval_flows) == 0

        # With max_hops=3, should reach d.py
        flows_deep = trace_dataflows(tmp_path, pkg / "a.py", max_hops=3)
        eval_flows = [f for f in flows_deep if f.sink_type == "code_execution"]
        assert len(eval_flows) >= 1

    def test_taint_flow_to_dict(self, tmp_path: Path):
        f = tmp_path / "server.py"
        f.write_text("""
import os

@app.post("/cmd")
async def run(cmd: str):
    os.system(cmd)
""")
        flows = trace_dataflows(tmp_path, target_file=f)
        assert len(flows) >= 1
        d = flows[0].to_dict()
        assert "source" in d
        assert "sink" in d
        assert "path" in d
        assert d["source"]["param"] == "cmd"
        assert d["sink"]["type"] == "command_injection"

    def test_keyword_arg_cross_file_to_intra_file_sink(self, tmp_path: Path):
        """The packages flow: kwarg crosses files, then intra-file call to sink.

        server.py: run_python(packages) → executor.execute(packages=packages)
        executor.py: execute(packages) → _install(packages) → os.system(f"pip install {packages}")
        """
        pkg = tmp_path / "myapp"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")

        (pkg / "server.py").write_text("""
from .executor import execute

@mcp.tool()
async def run_python(code: str, packages: list):
    execute(packages=packages)
""")
        (pkg / "executor.py").write_text("""
import os

def execute(packages=None):
    if packages:
        _install_packages(packages)

def _install_packages(packages):
    cmd = ' '.join(packages)
    os.system(f"pip install {cmd}")
""")
        flows = trace_dataflows(tmp_path, pkg / "server.py", max_hops=3)
        pkg_flows = [
            f for f in flows
            if f.source_param == "packages"
            and f.sink_type == "command_injection"
        ]
        assert len(pkg_flows) >= 1, (
            f"Expected packages→shell flow, got {len(pkg_flows)} flows. "
            f"All flows: {[(f.source_param, f.sink_type) for f in flows]}"
        )

    def test_ternary_expression_propagates_taint(self, tmp_path: Path):
        """packages if sandbox else None should propagate taint through packages."""
        pkg = tmp_path / "myapp"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")

        (pkg / "server.py").write_text("""
from .executor import execute

@mcp.tool()
async def run_python(code: str, packages: list, sandbox: bool = True):
    execute(packages=packages if sandbox else None)
""")
        (pkg / "executor.py").write_text("""
import os

def execute(packages=None):
    if packages:
        _install(packages)

def _install(packages):
    cmd = ' '.join(packages)
    os.system(f"pip install {cmd}")
""")
        flows = trace_dataflows(tmp_path, pkg / "server.py", max_hops=3)
        pkg_flows = [
            f for f in flows
            if f.source_param == "packages"
            and f.sink_type == "command_injection"
        ]
        assert len(pkg_flows) >= 1, (
            f"Expected packages→command_injection, got: "
            f"{[(f.source_param, f.sink_type) for f in flows]}"
        )

    def test_executor_execute_not_sql_sink(self, tmp_path: Path):
        """executor.execute() should NOT be classified as SQL injection."""
        f = tmp_path / "app.py"
        f.write_text("""
from executor import execute

@app.post("/run")
async def run(code: str):
    execute(code)
""")
        flows = trace_dataflows(tmp_path, target_file=f)
        sql_flows = [fl for fl in flows if fl.sink_type == "sql_injection"]
        assert len(sql_flows) == 0, (
            f"executor.execute should not match SQL sink, got: "
            f"{[(fl.source_param, fl.sink_type) for fl in flows]}"
        )

    def test_instance_method_resolution(self, tmp_path: Path):
        """executor = Executor(); executor.run(data) should resolve to Executor.run."""
        pkg = tmp_path / "myapp"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")

        (pkg / "server.py").write_text("""
from .executor import NotebookExecutor

executor = NotebookExecutor()

@mcp.tool()
async def run_python(packages: list):
    executor.execute(packages=packages)
""")
        (pkg / "executor.py").write_text("""
import os

class NotebookExecutor:
    def execute(self, packages=None):
        if packages:
            self._install(packages)

    def _install(self, packages):
        cmd = ' '.join(packages)
        os.system(f"pip install {cmd}")
""")
        flows = trace_dataflows(tmp_path, pkg / "server.py", max_hops=3)
        pkg_flows = [
            f for f in flows
            if f.source_param == "packages"
            and f.sink_type == "command_injection"
        ]
        assert len(pkg_flows) >= 1, (
            f"Expected instance method flow, got: "
            f"{[(f.source_param, f.sink_type) for f in flows]}"
        )

    def test_self_method_call(self, tmp_path: Path):
        """self._helper(data) should trace within the class."""
        f = tmp_path / "app.py"
        f.write_text("""
import os

class Handler:
    @app.post("/run")
    async def handle(self, cmd: str):
        self._execute(cmd)

    def _execute(self, cmd):
        os.system(cmd)
""")
        flows = trace_dataflows(tmp_path, target_file=f)
        cmd_flows = [fl for fl in flows if fl.sink_type == "command_injection"]
        assert len(cmd_flows) >= 1

    def test_cursor_execute_is_sql_sink(self, tmp_path: Path):
        """cursor.execute() SHOULD be classified as SQL injection."""
        f = tmp_path / "app.py"
        f.write_text("""
@app.post("/query")
async def query(sql: str):
    cursor.execute(sql)
""")
        flows = trace_dataflows(tmp_path, target_file=f)
        sql_flows = [fl for fl in flows if fl.sink_type == "sql_injection"]
        assert len(sql_flows) >= 1

    def test_source_filter(self, tmp_path: Path):
        f = tmp_path / "server.py"
        f.write_text("""
import os

@app.post("/a")
async def func_a(cmd: str):
    os.system(cmd)

@app.post("/b")
async def func_b(data: str):
    eval(data)
""")
        all_flows = trace_dataflows(tmp_path, target_file=f)
        assert len(all_flows) >= 2

        # Filter to just func_a
        filtered = [f for f in all_flows if f.source_function == "func_a"]
        assert all(f.sink_type == "command_injection" for f in filtered)
