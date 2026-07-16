"""Celery-приложение cve-service (design-nvd-sync §9).

Единый брокер — Redis. Таски синхронные, внутри гоняют async-пайплайны
через `asyncio.run` с ОДНОРАЗОВЫМ engine на вызов: asyncpg-движок нельзя делить
между event-loop'ами разных `asyncio.run`, поэтому создаём и закрываем его тут.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

from celery import Celery
from redis import Redis
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

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
    # cve-worker слушает свою очередь "cve" (сюда collector шлёт match_service, а
    # gateway — run_scan в дефолтную "celery" для collector-worker). Иначе воркеры
    # делят одну очередь и cve-worker крадёт run_scan → скан висит в pending.
    task_default_queue="cve",
    beat_schedule={
        "nvd-sync-daily": {
            "task": "cve_service.nvd_incremental_sync",
            "schedule": 24 * 60 * 60,
        },
        "threat-intel-sync-daily": {
            "task": "cve_service.threat_intel_sync",
            "schedule": 24 * 60 * 60,
        },
    },
)


def _run_async(make_coro: Callable[[async_sessionmaker], Awaitable[Any]]) -> Any:
    """Запустить async-пайплайн с изолированным engine/sessionmaker на этот вызов."""

    async def runner() -> Any:
        engine = create_async_engine(get_settings().database_url, pool_pre_ping=True)
        sessionmaker = async_sessionmaker(engine, expire_on_commit=False, autoflush=False)
        try:
            return await make_coro(sessionmaker)
        finally:
            await engine.dispose()

    return asyncio.run(runner())


def _with_nvd_lock(fn: Callable[[], Any]) -> Any:
    """Redis-lock на источник — два синка NVD не пересекаются (bootstrap длинный)."""
    client = Redis.from_url(get_settings().redis_url)
    lock = client.lock("nvd_cve:sync", timeout=6 * 60 * 60, blocking=False)
    if not lock.acquire(blocking=False):
        return {"status": "skipped", "reason": "sync already running"}
    try:
        return fn()
    finally:
        try:
            lock.release()
        except Exception:
            pass


@celery_app.task(name="cve_service.ping")
def ping() -> str:
    """Проверка живости воркера/брокера."""
    return "pong"


@celery_app.task(name="cve_service.nvd_sync")
def nvd_sync() -> dict:
    """Синк NVD: bootstrap при пустом состоянии, иначе инкремент (авто-выбор)."""
    from .nvd.client import NvdClient
    from .nvd.repository import SqlSyncRepo
    from .nvd.sync import NvdSyncer

    async def _do(sessionmaker: async_sessionmaker) -> dict:
        st = get_settings()
        repo = SqlSyncRepo(sessionmaker)
        async with NvdClient(
            api_key=st.nvd_api_key, min_delay=st.nvd_sync_min_delay_seconds
        ) as client:
            syncer = NvdSyncer(client, repo, page_size=st.nvd_sync_page_size)
            return await syncer.run()

    return _with_nvd_lock(lambda: _run_async(_do))


# Имя для beat/совместимости: инкремент — тот же авто-синк.
@celery_app.task(name="cve_service.nvd_incremental_sync")
def nvd_incremental_sync() -> dict:
    return nvd_sync()


@celery_app.task(name="cve_service.threat_intel_sync")
def threat_intel_sync() -> dict:
    """Обновить EPSS и authoritative CISA KEV для CVE в локальной базе."""
    from .threat_intel import sync_threat_intel

    return _run_async(sync_threat_intel)


@celery_app.task(name="cve_service.match_service")
def match_service_task(service_id: int) -> dict:
    """Сматчить один сервис с CVE и сохранить в service_cve."""
    from csosint_common.models import Service

    from .matching.repository import match_service_row

    async def _do(sessionmaker: async_sessionmaker) -> dict:
        async with sessionmaker() as session, session.begin():
            svc = await session.get(Service, service_id)
            if svc is None:
                return {"status": "not_found", "service_id": service_id}
            matches = await match_service_row(
                session, svc.id, svc.product, svc.version, svc.cpe_uri
            )
            return {"service_id": service_id, "matched": len(matches)}

    return _run_async(_do)
