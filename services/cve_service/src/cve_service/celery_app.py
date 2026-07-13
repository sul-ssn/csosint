"""Celery-приложение cve-service.

Единый брокер — Redis (ТЗ §2, RabbitMQ убран). Этап 0: каркас + ping-таска и
заглушки синка NVD, которые наполнятся на Этапе 1 (design-nvd-sync).
"""

from __future__ import annotations

from celery import Celery

from csosint_common.config import get_settings

settings = get_settings()

celery_app = Celery(
    "cve_service",
    broker=settings.redis_url,
    backend=settings.redis_url,
)
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    # Этап 1: раскомментировать суточный инкремент синка NVD.
    # beat_schedule={
    #     "nvd-incremental-daily": {
    #         "task": "cve_service.tasks.nvd_incremental_sync",
    #         "schedule": 24 * 60 * 60,
    #     },
    # },
)


@celery_app.task(name="cve_service.ping")
def ping() -> str:
    """Проверка живости воркера/брокера."""
    return "pong"


@celery_app.task(name="cve_service.nvd_incremental_sync")
def nvd_incremental_sync() -> dict[str, str]:
    # TODO(Этап 1): инкрементальный синк NVD (design-nvd-sync §2, §10).
    return {"status": "not_implemented", "stage": "1"}
