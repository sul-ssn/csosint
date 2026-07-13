"""Постановка задач в очередь Celery из gateway (ТЗ §7).

Gateway не импортирует код воркеров — шлёт таску по имени через общий Redis-брокер.
"""

from __future__ import annotations

from celery import Celery

from csosint_common.config import get_settings

_app: Celery | None = None


def _celery() -> Celery:
    global _app
    if _app is None:
        settings = get_settings()
        _app = Celery("gateway", broker=settings.redis_url, backend=settings.redis_url)
    return _app


def enqueue_scan(job_id: int) -> str:
    """Поставить сбор по scan_job в collector-service. Возвращает id таски."""
    result = _celery().send_task("collector_service.run_scan", args=[job_id])
    return result.id
