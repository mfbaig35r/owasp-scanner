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
