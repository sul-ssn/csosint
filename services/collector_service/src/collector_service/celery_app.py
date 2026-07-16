"""Celery-приложение collector-service.

Таск `run_scan` собирает данные по цели, пишет их в БД и ставит матчинг найденных
сервисов в cve-service (через общий Redis-брокер, по имени таски). async-пайплайн
гоняется через isolated engine на вызов — как в cve-service."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

from celery import Celery
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from csosint_common.config import get_settings

settings = get_settings()

celery_app = Celery(
    "collector_service",
    broker=settings.redis_url,
    backend=settings.redis_url,
)
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
)


def _run_async(make_coro: Callable[[async_sessionmaker], Awaitable[Any]]) -> Any:
    async def runner() -> Any:
        engine = create_async_engine(get_settings().database_url, pool_pre_ping=True)
        sessionmaker = async_sessionmaker(engine, expire_on_commit=False, autoflush=False)
        try:
            return await make_coro(sessionmaker)
        finally:
            await engine.dispose()

    return asyncio.run(runner())


@celery_app.task(name="collector_service.ping")
def ping() -> str:
    return "pong"


@celery_app.task(name="collector_service.run_scan")
def run_scan(job_id: int) -> dict:
    """Собрать цель scan_job'а, записать активы, зачейнить матчинг сервисов."""
    from csosint_common.models import ScanJob

    from .persistence import persist
    from .pipeline import collect
    from .progress import RedisProgress

    async def _do(sessionmaker: async_sessionmaker) -> dict:
        st = get_settings()
        prog = RedisProgress(st.redis_url, job_id)
        async with sessionmaker() as session:
            job = await session.get(ScanJob, job_id)
            if job is None:
                await prog.aclose()
                return {"status": "not_found", "job_id": job_id}
            target, target_type = job.target, job.type
            # session.get выше уже автостартовал транзакцию — просто коммитим,
            # без session.begin() (иначе «transaction is already begun»).
            job.status = "running"
            await session.commit()

        try:
            await prog.emit({"event": "started", "status": "running"})
            result = await collect(target, target_type, st, progress=prog.emit)
            async with sessionmaker() as session, session.begin():
                counts = await persist(session, result, job_id=job_id)
                job = await session.get(ScanJob, job_id)
                job.status = "done"
                job.finished_at = datetime.now(UTC)
                job.degraded_sources = result.degraded or None
            service_ids = counts.pop("service_ids", [])
            await prog.emit({"event": "persisted", "counts": counts})
            # Зачейнить матчинг product+version→CVE по новым сервисам.
            # Отдельная очередь `cve` — чтобы матчинг разбирал cve-воркер, а не collector.
            for sid in service_ids:
                celery_app.send_task("cve_service.match_service", args=[sid], queue="cve")
            await prog.emit({"event": "matching", "counts": {"services": len(service_ids)}})
            await prog.emit({"event": "done", "status": "done", "counts": counts})
            return {"status": "done", "job_id": job_id, **counts}
        except Exception as exc:
            async with sessionmaker() as session, session.begin():
                job = await session.get(ScanJob, job_id)
                if job is not None:
                    job.status = "failed"
                    job.finished_at = datetime.now(UTC)
                    job.error = f"{type(exc).__name__}: {exc}"
            await prog.emit({"event": "failed", "status": "failed", "message": str(exc)})
            raise
        finally:
            await prog.aclose()

    return _run_async(_do)
