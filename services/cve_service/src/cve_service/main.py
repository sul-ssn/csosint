"""cve-service HTTP-фасад.

Этап 0: health-эндпоинты. Матчинг и статус синка NVD появятся на Этапе 1.
"""

from __future__ import annotations

from fastapi import FastAPI

from csosint_common.health import make_health_router

app = FastAPI(
    title="CSOSINT cve-service",
    version="0.1.0",
    summary="Синк NVD и матчинг product+version→CVE",
)

app.include_router(make_health_router("cve-service", check_db=True, check_redis=True))


@app.get("/")
async def root() -> dict[str, str]:
    return {"service": "cve-service", "docs": "/docs"}
