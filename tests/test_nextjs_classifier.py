"""Tests for Next.js file-type classifier and project detection."""

from __future__ import annotations

from pathlib import Path

from owasp_scanner.core.nextjs import (
    FILE_TYPE_CONTEXT,
    classify_nextjs_file,
    detect_project_type,
)


class TestClassifyNextjsFile:
    def test_server_component_default_in_app(self, tmp_path: Path):
        app = tmp_path / "app" / "dashboard"
        app.mkdir(parents=True)
        f = app / "utils.ts"
        f.write_text("export function helper() {}")
        assert classify_nextjs_file(f, tmp_path) == "server_component"

    def test_page(self, tmp_path: Path):
        app = tmp_path / "app"
        app.mkdir()
        f = app / "page.tsx"
        f.write_text("export default function Home() {}")
        assert classify_nextjs_file(f, tmp_path) == "page"

    def test_layout(self, tmp_path: Path):
        app = tmp_path / "app"
        app.mkdir()
        f = app / "layout.tsx"
        f.write_text("export default function Layout({children}) {}")
        assert classify_nextjs_file(f, tmp_path) == "layout"

    def test_client_component(self, tmp_path: Path):
        comp = tmp_path / "components"
        comp.mkdir()
        f = comp / "Counter.tsx"
        f.write_text("'use client'\nexport default function Counter() {}")
        assert classify_nextjs_file(f, tmp_path) == "client_component"

    def test_client_with_double_quotes(self, tmp_path: Path):
        f = tmp_path / "Widget.tsx"
        f.write_text('"use client"\nexport function Widget() {}')
        assert classify_nextjs_file(f, tmp_path) == "client_component"

    def test_server_action(self, tmp_path: Path):
        app = tmp_path / "app"
        app.mkdir()
        f = app / "actions.ts"
        f.write_text("'use server'\nexport async function submit() {}")
        assert classify_nextjs_file(f, tmp_path) == "server_action"

    def test_route_handler(self, tmp_path: Path):
        api = tmp_path / "app" / "api" / "users"
        api.mkdir(parents=True)
        f = api / "route.ts"
        f.write_text("export async function GET() {}")
        assert classify_nextjs_file(f, tmp_path) == "route_handler"

    def test_middleware(self, tmp_path: Path):
        f = tmp_path / "middleware.ts"
        f.write_text("export function middleware() {}")
        assert classify_nextjs_file(f, tmp_path) == "middleware"

    def test_error_boundary(self, tmp_path: Path):
        app = tmp_path / "app"
        app.mkdir()
        f = app / "error.tsx"
        f.write_text("'use client'\nexport default function Error() {}")
        assert classify_nextjs_file(f, tmp_path) == "error_boundary"

    def test_config(self, tmp_path: Path):
        f = tmp_path / "next.config.js"
        f.write_text("module.exports = {}")
        assert classify_nextjs_file(f, tmp_path) == "config"

    def test_config_mjs(self, tmp_path: Path):
        f = tmp_path / "next.config.mjs"
        f.write_text("export default {}")
        assert classify_nextjs_file(f, tmp_path) == "config"

    def test_lib_file(self, tmp_path: Path):
        lib = tmp_path / "lib"
        lib.mkdir()
        f = lib / "utils.ts"
        f.write_text("export function cn() {}")
        assert classify_nextjs_file(f, tmp_path) == "lib"

    def test_file_type_context_complete(self):
        expected_types = {
            "server_component", "client_component", "server_action",
            "route_handler", "middleware", "layout", "page",
            "error_boundary", "config", "lib",
        }
        assert set(FILE_TYPE_CONTEXT.keys()) == expected_types


class TestDetectProjectType:
    def test_nextjs_with_config(self, tmp_path: Path):
        (tmp_path / "next.config.js").write_text("{}")
        assert detect_project_type(tmp_path) == "nextjs"

    def test_nextjs_with_mjs_config(self, tmp_path: Path):
        (tmp_path / "next.config.mjs").write_text("export default {}")
        assert detect_project_type(tmp_path) == "nextjs"

    def test_nextjs_from_package_json(self, tmp_path: Path):
        (tmp_path / "package.json").write_text(
            '{"dependencies": {"next": "15.0.0"}}'
        )
        assert detect_project_type(tmp_path) == "nextjs"

    def test_python_project(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text("[project]")
        assert detect_project_type(tmp_path) == "python"

    def test_monorepo(self, tmp_path: Path):
        (tmp_path / "next.config.js").write_text("{}")
        (tmp_path / "pyproject.toml").write_text("[project]")
        assert detect_project_type(tmp_path) == "monorepo"

    def test_react_generic(self, tmp_path: Path):
        (tmp_path / "package.json").write_text(
            '{"dependencies": {"react": "19.0.0"}}'
        )
        assert detect_project_type(tmp_path) == "react"

    def test_unknown(self, tmp_path: Path):
        assert detect_project_type(tmp_path) == "unknown"

    def test_invalid_package_json(self, tmp_path: Path):
        (tmp_path / "package.json").write_text("not json")
        assert detect_project_type(tmp_path) == "unknown"
