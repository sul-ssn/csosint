"""cve-service HTTP-фасад.

Этап 1: health + управление синком NVD и матчингом. Внутренний сервис —
публичный вход остаётся у gateway; сюда gateway ходит по очереди/HTTP.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from csosint_common.db import get_session
from csosint_common.health import make_health_router
from csosint_common.models import CveRecord, ServiceCve, SyncState

# Аннотированная зависимость сессии — без вызова Depends() в дефолтах аргументов.
SessionDep = Annotated[AsyncSession, Depends(get_session)]

app = FastAPI(
    title="CSOSINT cve-service",
    version="0.1.0",
    summary="Синк NVD и матчинг product+version→CVE",
)

app.include_router(make_health_router("cve-service", check_db=True, check_redis=True))


class SyncStatus(BaseModel):
    source: str
    phase: str | None = None
    status: str | None = None
    bootstrap_index: int | None = None
    last_mod_cursor: datetime | None = None
    last_run_at: datetime | None = None
    last_error: str | None = None


class TaskQueued(BaseModel):
    task_id: str
    task: str


class CveDetail(BaseModel):
    cve_id: str
    description: str | None = None
    published: datetime | None = None
    modified: datetime | None = None
    cvss_version: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    severity: str | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    kev: bool = False
    kev_required_action: str | None = None


class ServiceCveOut(BaseModel):
    cve_id: str
    match_confidence: str
    matched_cpe: str | None = None
    matched_at: datetime


@app.get("/sync/status", response_model=SyncStatus)
async def sync_status(session: SessionDep) -> SyncStatus:
    row = await session.get(SyncState, "nvd_cve")
    if row is None:
        return SyncStatus(source="nvd_cve", status="never_run")
    return SyncStatus.model_validate(row, from_attributes=True)


@app.post("/sync/run", response_model=TaskQueued, status_code=status.HTTP_202_ACCEPTED)
async def trigger_sync() -> TaskQueued:
    """Поставить синк NVD в очередь (bootstrap при пустом состоянии, иначе инкремент)."""
    from .celery_app import nvd_sync

    result = nvd_sync.delay()
    return TaskQueued(task_id=result.id, task="cve_service.nvd_sync")


@app.post("/intel/sync", response_model=TaskQueued, status_code=status.HTTP_202_ACCEPTED)
async def trigger_intel_sync() -> TaskQueued:
    """Поставить ежедневное обогащение FIRST EPSS + CISA KEV в очередь."""
    from .celery_app import threat_intel_sync

    result = threat_intel_sync.delay()
    return TaskQueued(task_id=result.id, task="cve_service.threat_intel_sync")


@app.get("/cve/{cve_id}", response_model=CveDetail)
async def get_cve(cve_id: str, session: SessionDep) -> CveDetail:
    # PK таблицы — id, поэтому ищем по уникальному cve_id, а не session.get.
    row = (
        await session.execute(select(CveRecord).where(CveRecord.cve_id == cve_id))
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"CVE {cve_id} нет в локальной базе")
    return CveDetail.model_validate(row, from_attributes=True)


@app.post("/match/{service_id}", response_model=TaskQueued, status_code=status.HTTP_202_ACCEPTED)
async def trigger_match(service_id: int) -> TaskQueued:
    """Поставить матчинг сервиса → CVE в очередь."""
    from .celery_app import match_service_task

    result = match_service_task.delay(service_id)
    return TaskQueued(task_id=result.id, task="cve_service.match_service")


@app.get("/match/{service_id}", response_model=list[ServiceCveOut])
async def get_matches(service_id: int, session: SessionDep) -> list[ServiceCveOut]:
    rows = (
        await session.execute(select(ServiceCve).where(ServiceCve.service_id == service_id))
    ).scalars()
    return [ServiceCveOut.model_validate(r, from_attributes=True) for r in rows]


@app.get("/")
async def root() -> dict[str, str]:
    return {"service": "cve-service", "docs": "/docs"}
