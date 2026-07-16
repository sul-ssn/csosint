"""WS-стрим прогресса скана.

Gateway подписывается на Redis-канал `scan:{job_id}` и проксирует события в
браузер. На подключении отдаёт снапшот текущего статуса из БД (если скан уже
завершился до подписки — сразу терминальное событие).
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from csosint_common.db import get_sessionmaker
from csosint_common.events import ProgressEvent, scan_channel
from csosint_common.models import ScanJob

_TERMINAL_STATUS = {"done": "done", "failed": "failed"}


async def subscribe_scan(redis, job_id: int) -> AsyncIterator[str]:
    """Живые события из Redis pub/sub; завершается на терминальном событии."""
    pubsub = redis.pubsub()
    await pubsub.subscribe(scan_channel(job_id))
    try:
        async for message in pubsub.listen():
            if message.get("type") != "message":
                continue
            data = message["data"]
            if isinstance(data, bytes | bytearray):
                data = data.decode()
            yield data
            try:
                if ProgressEvent.model_validate_json(data).terminal:
                    break
            except Exception:
                pass
    finally:
        await pubsub.unsubscribe(scan_channel(job_id))
        await pubsub.aclose()


async def _snapshot(job_id: int) -> tuple[str, bool]:
    async with get_sessionmaker()() as session:
        job = await session.get(ScanJob, job_id)
    if job is None:
        ev = ProgressEvent(job_id=job_id, event="failed", message="job not found")
        return ev.model_dump_json(), True
    event = _TERMINAL_STATUS.get(job.status, "started")
    ev = ProgressEvent(job_id=job_id, event=event, status=job.status)
    return ev.model_dump_json(), event in ("done", "failed")


async def scan_stream(job_id: int, redis) -> AsyncIterator[str]:
    """Снапшот статуса из БД + живые события до терминального."""
    snapshot, terminal = await _snapshot(job_id)
    yield snapshot
    if terminal:
        return
    async for data in subscribe_scan(redis, job_id):
        yield data
