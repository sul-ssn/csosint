"""Контракт прогресс-событий сбора (ТЗ §7).

Прогресс идёт `Celery-воркер → Redis pub/sub → gateway WS → браузер`. Общий канал
и схема события живут здесь, чтобы collector (издатель) и gateway (подписчик)
не расходились.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel


def scan_channel(job_id: int) -> str:
    """Redis pub/sub-канал прогресса конкретного скана."""
    return f"scan:{job_id}"


class ProgressEvent(BaseModel):
    """Одно событие прогресса скана."""

    job_id: int
    # started — задача взята; source — источник отработал/пропущен/упал;
    # persisted — активы записаны; matching — матчинг поставлен; done/failed — терминальные.
    event: Literal["started", "source", "persisted", "matching", "done", "failed"]
    source: str | None = None
    status: str | None = None  # ok | skipped | failed | running
    message: str | None = None
    counts: dict | None = None

    @property
    def terminal(self) -> bool:
        return self.event in ("done", "failed")
