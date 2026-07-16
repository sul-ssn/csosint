"""Единая конфигурация сервисов (pydantic-settings).

Читается из окружения / .env. Опциональные ключи источников по умолчанию пусты —
их отсутствие означает graceful degradation, а не ошибку.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- Инфраструктура ---
    database_url: str = Field(
        default="postgresql+asyncpg://csosint:csosint@localhost:5432/csosint",
        description="Async DSN PostgreSQL (asyncpg-драйвер).",
    )
    redis_url: str = Field(default="redis://localhost:6379/0")
    # CORS для фронта (self-host): `*` в dev или CSV-список origin'ов.
    cors_origins: str = Field(default="*")
    # Rate-limit на эндпоинты gateway (запросов на клиента в минуту).
    rate_limit_per_minute: int = Field(default=60)

    # --- Core-источники ---
    nvd_api_key: str | None = None

    # --- Optional enrichment — пусто => источник пропускается ---
    shodan_api_key: str | None = None
    censys_api_id: str | None = None
    censys_api_secret: str | None = None
    securitytrails_api_key: str | None = None
    virustotal_api_key: str | None = None

    # --- AI-анализ сценариев атак. Опционально: нет ключа → 501 ---
    anthropic_api_key: str | None = None
    anthropic_model: str = "claude-opus-4-8"

    # --- Поведение синка NVD (design-nvd-sync) ---
    nvd_sync_min_delay_seconds: float = 6.0
    nvd_sync_page_size: int = 2000


@lru_cache
def get_settings() -> Settings:
    """Кэшированный доступ к настройкам (один инстанс на процесс)."""
    return Settings()
