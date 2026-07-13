"""API Gateway — единая точка входа (ТЗ §7).

Этап 0: живой каркас — health + заглушки API-эндпоинтов (501, реализуются на
Этапах 1–4). Оркестрация сбора и WS-прогресс появятся позже.
"""

from __future__ import annotations

from fastapi import APIRouter, FastAPI, HTTPException, status

from csosint_common.health import make_health_router
from csosint_common.schemas import ScanRequest

app = FastAPI(
    title="CSOSINT API Gateway",
    version="0.1.0",
    summary="CVE Intelligence Platform — пассивная OSINT-аналитика (self-host)",
)

app.include_router(make_health_router("gateway", check_db=True, check_redis=True))

api = APIRouter(prefix="/api/v1")


@api.post("/scan", status_code=status.HTTP_501_NOT_IMPLEMENTED)
async def create_scan(req: ScanRequest) -> None:
    # TODO(Этап 2): поставить задачу сбора в очередь, вернуть job_id.
    raise HTTPException(status.HTTP_501_NOT_IMPLEMENTED, "scan оркестрация — Этап 2")


app.include_router(api)


@app.get("/")
async def root() -> dict[str, str]:
    return {"service": "gateway", "docs": "/docs"}
