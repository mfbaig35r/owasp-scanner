"""Shared fixtures for OWASP Scanner tests."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from owasp_scanner.core.config import ScannerSettings
from owasp_scanner.core.database import Database


@pytest.fixture
def tmp_settings(tmp_path: Path) -> ScannerSettings:
    """Settings pointing at a temporary data directory."""
    settings = ScannerSettings(data_dir=tmp_path / "owasp-test")
    settings.ensure_dirs()
    return settings


@pytest.fixture
def tmp_db(tmp_path: Path) -> Database:
    """Fresh database in a temp directory."""
    return Database(db_path=tmp_path / "test.db")


@pytest.fixture
def patched_db(tmp_db: Database):
    """Patches get_db() to return the temp database."""
    with patch("owasp_scanner.core.database.get_db", return_value=tmp_db):
        yield tmp_db


@pytest.fixture
def sample_vulnerable_py(tmp_path: Path) -> Path:
    """A Python file with known security issues."""
    code = '''\
import os
import hashlib
import pickle
import yaml

DEBUG = True
ALLOWED_HOSTS = ["*"]
SECRET_KEY = "django-insecure-super-secret-key-12345"

def get_user(username):
    query = f"SELECT * FROM users WHERE name = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

def load_data(data):
    return pickle.loads(data)

def run_cmd(hostname):
    os.system(f"ping {hostname}")

config = yaml.load(open("config.yml"))

try:
    do_something()
except:
    pass
'''
    f = tmp_path / "vulnerable.py"
    f.write_text(code)
    return f


@pytest.fixture
def sample_clean_py(tmp_path: Path) -> Path:
    """A Python file with no security issues."""
    code = '''\
import json
import secrets
import subprocess
from argon2 import PasswordHasher
import yaml

DEBUG = False
ALLOWED_HOSTS = ["example.com"]

ph = PasswordHasher()

def get_user(username: str):
    cursor.execute("SELECT * FROM users WHERE name = %s", (username,))
    return cursor.fetchone()

def hash_password(password: str) -> str:
    return ph.hash(password)

def load_data(data: str):
    return json.loads(data)

def run_cmd(hostname: str):
    subprocess.run(["ping", "-c", "1", hostname], capture_output=True)

config = yaml.safe_load(open("config.yml"))

def generate_token():
    return secrets.token_urlsafe(32)

try:
    do_something()
except ValueError:
    handle_error()
'''
    f = tmp_path / "clean.py"
    f.write_text(code)
    return f


@pytest.fixture
def sample_nextjs_app(tmp_path: Path) -> Path:
    """Create a minimal Next.js App Router project with known vulnerabilities."""
    root = tmp_path / "nextjs-app"
    root.mkdir()

    (root / "package.json").write_text(
        '{"dependencies": {"next": "15.0.0", "react": "19.0.0"}}'
    )

    (root / "next.config.js").write_text(
        "/** @type {import('next').NextConfig} */\n"
        "module.exports = {\n"
        "  images: { remotePatterns: [{ hostname: '**' }] },\n"
        "  poweredByHeader: true,\n"
        "  reactStrictMode: false,\n"
        "}\n"
    )

    (root / "middleware.ts").write_text(
        "import { NextResponse } from 'next/server'\n"
        "export const config = { matcher: ['/dashboard/:path*'] }\n"
        "export function middleware(request) {\n"
        "  return NextResponse.next()\n"
        "}\n"
    )

    (root / ".env").write_text(
        "DATABASE_URL=postgresql://user:pass@localhost/db\n"
        "NEXT_PUBLIC_SECRET_KEY=sk-proj-abc123def456\n"
    )

    app = root / "app"
    app.mkdir()
    (app / "page.tsx").write_text(
        "export default function Home() { return <div>Hello</div> }\n"
    )

    dash = app / "dashboard"
    dash.mkdir()
    (dash / "page.tsx").write_text(
        "import { ClientDashboard } from '@/components/Dashboard'\n"
        "export default async function DashboardPage() {\n"
        "  const user = await prisma.user.findUnique({ where: { id: userId } })\n"
        "  return <ClientDashboard user={user} />\n"
        "}\n"
    )

    api = app / "api" / "users"
    api.mkdir(parents=True)
    (api / "route.ts").write_text(
        "import { prisma } from '@/lib/db'\n"
        "export async function GET(request: Request) {\n"
        "  const role = request.headers.get('role')\n"
        "  const users = await prisma.$queryRawUnsafe("
        "`SELECT * FROM users WHERE role = ${role}`)\n"
        "  return Response.json(users)\n"
        "}\n"
    )

    (app / "actions.ts").write_text(
        "'use server'\n"
        "export async function updateProfile(formData: FormData) {\n"
        "  const data = Object.fromEntries(formData)\n"
        "  await prisma.user.update({ where: { id: session.user.id }, data })\n"
        "}\n"
    )

    comp = root / "components"
    comp.mkdir()
    (comp / "Dashboard.tsx").write_text(
        "'use client'\n"
        "export function ClientDashboard({ user }) {\n"
        "  return <div>{user.name}</div>\n"
        "}\n"
    )

    lib = root / "lib"
    lib.mkdir()
    (lib / "db.ts").write_text(
        "import { PrismaClient } from '@prisma/client'\n"
        "export const prisma = new PrismaClient()\n"
    )

    return root
