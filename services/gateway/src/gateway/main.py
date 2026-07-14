"""API Gateway — единая точка входа (ТЗ §7).

Этап 2: оркестрация сбора — POST /scan создаёт scan_job и ставит его в очередь
collector-service; GET /scan/{job_id} отдаёт статус (+ degraded_sources).
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    FastAPI,
    HTTPException,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from csosint_common.config import get_settings
from csosint_common.db import get_session
from csosint_common.health import make_health_router
from csosint_common.models import ScanJob
from csosint_common.schemas import ScanJobCreated, ScanRequest

from .analyze import analyze_report
from .graph import build_graph
from .queue import enqueue_scan
from .ratelimit import rate_limit
from .report import build_report
from .ws import scan_stream

app = FastAPI(
    title="CSOSINT API Gateway",
    version="0.1.0",
    summary="CVE Intelligence Platform — пассивная OSINT-аналитика (self-host)",
)

app.include_router(make_health_router("gateway", check_db=True, check_redis=True))

# Self-host: фронт ходит с другого origin (Next.js). CORS_ORIGINS — CSV или * (dev).
_origins = get_settings().cors_origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if _origins == "*" else [o.strip() for o in _origins.split(",")],
    allow_methods=["*"],
    allow_headers=["*"],
)

SessionDep = Annotated[AsyncSession, Depends(get_session)]
# Rate-limit на все эндпоинты API (ТЗ §7).
api = APIRouter(prefix="/api/v1", dependencies=[Depends(rate_limit)])


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


@api.get("/report/{job_id}")
async def get_report(job_id: int, session: SessionDep) -> dict:
    """Итоговый отчёт по скану: активы + «потенциальные» CVE (+ дисклеймер)."""
    job = await session.get(ScanJob, job_id)
    if job is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"scan job {job_id} не найден")
    return await build_report(session, job)


@api.post("/analyze/{job_id}")
async def analyze(job_id: int, session: SessionDep) -> dict:
    """AI-сценарии атак поверх отчёта (Этап 6). Оборонительно, «potential» (ТЗ §6).

    Опционально: без ANTHROPIC_API_KEY — 501 (self-host приносит свой ключ).
    """
    if not get_settings().anthropic_api_key:
        raise HTTPException(
            status.HTTP_501_NOT_IMPLEMENTED,
            "AI-анализ не сконфигурирован: задайте ANTHROPIC_API_KEY",
        )
    job = await session.get(ScanJob, job_id)
    if job is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"scan job {job_id} не найден")
    report = await build_report(session, job)
    return await analyze_report(report)


@api.get("/sources")
async def list_sources() -> dict:
    """Статус источников: core (всегда) + опциональные (включены при наличии ключа)."""
    s = get_settings()
    return {
        "core": ["internetdb", "crtsh", "dns", "rdap"],
        "optional": [
            {"name": "shodan", "enabled": bool(s.shodan_api_key)},
            {"name": "censys", "enabled": bool(s.censys_api_id and s.censys_api_secret)},
            {"name": "securitytrails", "enabled": bool(s.securitytrails_api_key)},
            {"name": "virustotal", "enabled": bool(s.virustotal_api_key)},
        ],
    }


app.include_router(api)


@app.websocket("/ws/scan/{job_id}")
async def ws_scan(websocket: WebSocket, job_id: int) -> None:
    """Прогресс сбора в реальном времени: снапшот статуса + живые события."""
    await websocket.accept()
    redis = Redis.from_url(get_settings().redis_url)
    try:
        async for data in scan_stream(job_id, redis):
            await websocket.send_text(data)
    except WebSocketDisconnect:
        pass
    finally:
        await redis.aclose()


@app.get("/")
async def root() -> dict[str, str]:
    return {"service": "gateway", "docs": "/docs"}
