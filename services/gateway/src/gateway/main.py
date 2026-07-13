"""API Gateway — единая точка входа (ТЗ §7).

Этап 2: оркестрация сбора — POST /scan создаёт scan_job и ставит его в очередь
collector-service; GET /scan/{job_id} отдаёт статус (+ degraded_sources).
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, FastAPI, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from csosint_common.db import get_session
from csosint_common.health import make_health_router
from csosint_common.models import ScanJob
from csosint_common.schemas import ScanJobCreated, ScanRequest

from .graph import build_graph
from .queue import enqueue_scan

app = FastAPI(
    title="CSOSINT API Gateway",
    version="0.1.0",
    summary="CVE Intelligence Platform — пассивная OSINT-аналитика (self-host)",
)

app.include_router(make_health_router("gateway", check_db=True, check_redis=True))

SessionDep = Annotated[AsyncSession, Depends(get_session)]
api = APIRouter(prefix="/api/v1")


class ScanJobStatus(BaseModel):
    id: int
    target: str
    type: str
    status: str
    created_at: datetime
    finished_at: datetime | None = None
    error: str | None = None
    degraded_sources: dict | None = None


@api.post("/scan", response_model=ScanJobCreated, status_code=status.HTTP_202_ACCEPTED)
async def create_scan(req: ScanRequest, session: SessionDep) -> ScanJobCreated:
    job = ScanJob(target=req.target, type=req.type.value, status="pending")
    session.add(job)
    await session.commit()
    await session.refresh(job)
    enqueue_scan(job.id)
    return ScanJobCreated(job_id=job.id, status=job.status)


@api.get("/scan/{job_id}", response_model=ScanJobStatus)
async def get_scan(job_id: int, session: SessionDep) -> ScanJobStatus:
    job = await session.get(ScanJob, job_id)
    if job is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"scan job {job_id} не найден")
    return ScanJobStatus.model_validate(job, from_attributes=True)


@api.get("/graph/domain/{fqdn}")
async def graph_by_domain(fqdn: str, session: SessionDep) -> dict:
    """Граф связей от домена: domain→ip→service→cve (+ shared-host домены)."""
    return await build_graph(session, domain=fqdn)


@api.get("/graph/ip/{address}")
async def graph_by_ip(address: str, session: SessionDep) -> dict:
    return await build_graph(session, ip=address)


@api.get("/graph/scan/{job_id}")
async def graph_by_scan(job_id: int, session: SessionDep) -> dict:
    """Граф того, что обнаружил конкретный скан (по его цели)."""
    job = await session.get(ScanJob, job_id)
    if job is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"scan job {job_id} не найден")
    if job.type == "domain":
        return await build_graph(session, domain=job.target)
    if job.type == "ip":
        return await build_graph(session, ip=job.target)
    # org-цели вне скоупа сбора v1 → пустой граф.
    return {"nodes": [], "edges": []}


app.include_router(api)


@app.get("/")
async def root() -> dict[str, str]:
    return {"service": "gateway", "docs": "/docs"}
