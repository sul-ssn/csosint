"""Публикация прогресса сбора в Redis pub/sub (ТЗ §7).

Издатель — Celery-воркер; подписчик — gateway WS. Прогресс best-effort: сбой
публикации не должен ронять скан.
"""

from __future__ import annotations

from redis.asyncio import Redis

from csosint_common.events import ProgressEvent, scan_channel


class RedisProgress:
    def __init__(self, redis_url: str, job_id: int) -> None:
        self._redis = Redis.from_url(redis_url)
        self._job_id = job_id
        self._channel = scan_channel(job_id)

    async def emit(self, event: dict) -> None:
        try:
            payload = ProgressEvent(job_id=self._job_id, **event).model_dump_json()
            await self._redis.publish(self._channel, payload)
        except Exception:
            pass  # прогресс — best-effort

    async def aclose(self) -> None:
        try:
            await self._redis.aclose()
        except Exception:
            pass
