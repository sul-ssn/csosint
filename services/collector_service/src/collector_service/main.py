"""collector-service HTTP-фасад.

Внутренний сервис: сбор идёт в Celery-воркере, публичный вход — у gateway.
Здесь — health для оркестрации Docker Compose."""

from __future__ import annotations

from fastapi import FastAPI

from csosint_common.health import make_health_router

app = FastAPI(
    title="CSOSINT collector-service",
    version="0.1.0",
    summary="Пассивный сбор активов: InternetDB, CT (crt.sh), DNS/RDAP + опц. обогащение",
)

app.include_router(make_health_router("collector-service", check_db=True, check_redis=True))


@app.get("/")
async def root() -> dict[str, str]:
    return {"service": "collector-service", "docs": "/docs"}
