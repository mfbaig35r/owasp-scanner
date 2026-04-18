"""Configuration management using Pydantic Settings."""

from __future__ import annotations

import threading
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class ScannerSettings(BaseSettings):
    """Scanner configuration.

    Priority: env vars (OWASP_*) > defaults.
    """

    model_config = SettingsConfigDict(
        env_prefix="OWASP_",
        case_sensitive=False,
        extra="ignore",
    )

    # Data directory
    data_dir: Path = Path.home() / ".owasp-scanner"

    # Database
    db_name: str = "scanner.db"

    # Scanning defaults
    default_severity_threshold: str = "low"  # low, medium, high, critical
    max_file_size_kb: int = 500  # Skip files larger than this

    # LLM scanning (opt-in)
    llm_model: str = "gpt-5.4-nano"
    openai_api_key: str = ""
    llm_base_url: str = ""  # Override for Ollama, Azure, vLLM, etc.
    llm_enabled: bool = False

    @property
    def db_path(self) -> Path:
        return self.data_dir / self.db_name

    @property
    def errors_log(self) -> Path:
        return self.data_dir / "errors.jsonl"

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)


_settings: ScannerSettings | None = None
_settings_lock = threading.Lock()


def get_settings() -> ScannerSettings:
    global _settings
    with _settings_lock:
        if _settings is None:
            _settings = ScannerSettings()
            _settings.ensure_dirs()
        return _settings
