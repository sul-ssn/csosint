"""WS-подписка на прогресс через Redis pub/sub (ТЗ §7). Redis — fakeredis."""

from __future__ import annotations

import asyncio

import fakeredis.aioredis

from csosint_common.events import ProgressEvent, scan_channel
from gateway.ws import subscribe_scan


async def test_subscribe_scan_forwards_until_terminal() -> None:
    server = fakeredis.aioredis.FakeServer()
    sub = fakeredis.aioredis.FakeRedis(server=server)
    pub = fakeredis.aioredis.FakeRedis(server=server)

    events: list[str] = []

    async def consume() -> None:
        async for data in subscribe_scan(sub, 1):
            events.append(data)

    task = asyncio.create_task(consume())
    await asyncio.sleep(0.1)  # дать подписке зарегистрироваться

    ch = scan_channel(1)
    await pub.publish(
        ch, ProgressEvent(job_id=1, event="source", source="crtsh", status="ok").model_dump_json()
    )
    await pub.publish(ch, ProgressEvent(job_id=1, event="done", status="done").model_dump_json())
    # Событие после терминального не должно быть доставлено (подписка закрылась).
    await pub.publish(ch, ProgressEvent(job_id=1, event="source", source="late").model_dump_json())

    await asyncio.wait_for(task, timeout=3)
    assert len(events) == 2
    assert ProgressEvent.model_validate_json(events[0]).source == "crtsh"
    assert ProgressEvent.model_validate_json(events[-1]).terminal

    await sub.aclose()
    await pub.aclose()
