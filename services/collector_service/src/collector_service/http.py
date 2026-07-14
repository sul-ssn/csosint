"""Общий async-HTTP с таймаутом и ретраями (ТЗ §3, §4).

Внешние API флакают (crt.sh 502, NVD 503, RDAP-таймауты) — единое требование:
timeout + экспоненциальный retry с jitter (`tenacity`). 4xx (кроме 429) не
ретраим — это не транзиентные ошибки.
"""

from __future__ import annotations

import httpx
from tenacity import (
    AsyncRetrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_random_exponential,
)

_RETRY_STATUS = {429, 500, 502, 503, 504}
DEFAULT_TIMEOUT = 15.0


class SourceError(Exception):
    """Источник недоступен/ответил ошибкой после ретраев."""


class _RetryableStatus(SourceError):
    """Транзиентный HTTP-статус — повторяем."""


def build_client(timeout: float = DEFAULT_TIMEOUT, **kwargs) -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=timeout, follow_redirects=True, **kwargs)


async def get_json(
    client: httpx.AsyncClient,
    url: str,
    *,
    params: dict | None = None,
    headers: dict | None = None,
    max_attempts: int = 4,
):
    """GET → JSON с ретраями. Бросает SourceError, если не удалось."""
    async for attempt in AsyncRetrying(
        stop=stop_after_attempt(max_attempts),
        wait=wait_random_exponential(multiplier=1, max=30),
        retry=retry_if_exception_type(
            (httpx.TransportError, httpx.TimeoutException, _RetryableStatus)
        ),
        reraise=True,
    ):
        with attempt:
            resp = await client.get(url, params=params, headers=headers)
            if resp.status_code in _RETRY_STATUS:
                raise _RetryableStatus(f"{url} -> {resp.status_code}")
            if resp.status_code >= 400:
                # 4xx (кроме 429) — не транзиентно (нет ключа/нет данных): не ретраим.
                raise SourceError(f"{url} -> {resp.status_code}")
            return resp.json()
    raise SourceError(f"{url}: ретраи исчерпаны")  # pragma: no cover
