"""Общий health-роутер для всех сервисов (ТЗ Этап 0).

- GET /health        — liveness: процесс жив (без внешних зависимостей).
- GET /health/ready  — readiness: пингует БД/Redis, 503 если что-то недоступно.
"""

from __future__ import annotations

from fastapi import APIRouter, Response, status

from .db import ping_db
from .schemas import DependencyStatus, HealthStatus, ReadinessStatus


async def _ping_redis() -> bool:
    from redis.asyncio import Redis

    from .config import get_settings

    client: Redis | None = None
    try:
        client = Redis.from_url(get_settings().redis_url)
        return bool(await client.ping())
    except Exception:
        return False
    finally:
        if client is not None:
            await client.aclose()


def make_health_router(
    service_name: str, *, check_db: bool = False, check_redis: bool = False
) -> APIRouter:
    router = APIRouter(tags=["health"])

    @router.get("/health", response_model=HealthStatus)
    async def health() -> HealthStatus:
        return HealthStatus(service=service_name)

    @router.get("/health/ready", response_model=ReadinessStatus)
    async def ready(response: Response) -> ReadinessStatus:
        deps: list[DependencyStatus] = []
        if check_db:
            deps.append(DependencyStatus(name="postgres", ok=await ping_db()))
        if check_redis:
            deps.append(DependencyStatus(name="redis", ok=await _ping_redis()))

        all_ok = all(d.ok for d in deps)
        if not all_ok:
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return ReadinessStatus(service=service_name, ready=all_ok, dependencies=deps)

    return router
