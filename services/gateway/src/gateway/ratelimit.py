"""Rate-limiting эндпоинтов gateway (ТЗ §7).

Простой sliding-window счётчик на клиента (in-memory — self-host, один инстанс).
Без внешней зависимости и детерминированно тестируется через инъекцию часов.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from collections.abc import Callable

from fastapi import HTTPException, Request, status

from csosint_common.config import get_settings


class SlidingWindowLimiter:
    def __init__(self, limit: int, window: float, clock: Callable[[], float] = time.monotonic):
        self.limit = limit
        self.window = window
        self._clock = clock
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = self._clock()
        q = self._hits[key]
        while q and q[0] <= now - self.window:
            q.popleft()
        if len(q) >= self.limit:
            return False
        q.append(now)
        return True


_limiter = SlidingWindowLimiter(get_settings().rate_limit_per_minute, window=60.0)


async def rate_limit(request: Request) -> None:
    """FastAPI-зависимость: 429, если клиент превысил лимит запросов/мин."""
    key = request.client.host if request.client else "anon"
    if not _limiter.allow(key):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "rate limit exceeded — слишком много запросов",
        )
