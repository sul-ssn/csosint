"""Асинхронный клиент NVD API 2.0 (design-nvd-sync §1, §4).

Отвечает за одно: устойчиво достать страницу CVE/CPE, уважая лимиты и флакость
NVD (частые 503/timeout). Rate-limit (min_delay между запросами) + экспоненциальный
ретрай с jitter, уважение `Retry-After`. 403/404 — конфиг-ошибки, не ретраим.
"""

from __future__ import annotations

import asyncio
import random
from datetime import datetime

import httpx

_BASE_URL = "https://services.nvd.nist.gov/rest/json"
_CVE_PATH = "/cves/2.0"
_CPE_PATH = "/cpes/2.0"
_RETRY_STATUS = {429, 500, 502, 503, 504}


class NvdError(Exception):
    """Ретраи исчерпаны или неожиданный ответ."""


class NvdAuthError(NvdError):
    """403 — плохой/просроченный ключ. Падаем громко, не ретраим."""


class NvdNotFound(NvdError):
    """404 — неверный эндпоинт/параметры."""


def _fmt(dt: datetime) -> str:
    """ISO-8601 с offset и миллисекундами — как требует NVD."""
    return dt.isoformat(timespec="milliseconds")


class _MinDelayLimiter:
    """Не чаще одного запроса в `min_delay` секунд (консервативно под лимит NVD).

    С бесплатным ключом лимит 50/30с (0.6с/запрос) — дефолтные 6с с большим
    запасом внутри окна, поэтому отдельный токен-бакет не нужен.
    """

    def __init__(self, min_delay: float) -> None:
        self._min_delay = min_delay
        self._next_at = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = asyncio.get_event_loop().time()
            wait = self._next_at - now
            if wait > 0:
                await asyncio.sleep(wait)
                now = asyncio.get_event_loop().time()
            self._next_at = now + self._min_delay


class NvdClient:
    def __init__(
        self,
        *,
        api_key: str | None = None,
        min_delay: float = 6.0,
        timeout: float = 30.0,
        max_attempts: int = 5,
        base_url: str = _BASE_URL,
    ) -> None:
        self._api_key = api_key
        self._max_attempts = max_attempts
        self._base_url = base_url
        self._limiter = _MinDelayLimiter(min_delay)
        headers = {"apiKey": api_key} if api_key else {}
        self._client = httpx.AsyncClient(base_url=base_url, timeout=timeout, headers=headers)

    async def __aenter__(self) -> NvdClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def fetch_cves(
        self,
        *,
        start_index: int = 0,
        results_per_page: int = 2000,
        last_mod_start: datetime | None = None,
        last_mod_end: datetime | None = None,
    ) -> dict:
        """Одна страница `cves/2.0`. Возвращает распарсенную обёртку JSON."""
        params: dict[str, str | int] = {
            "startIndex": start_index,
            "resultsPerPage": results_per_page,
        }
        if last_mod_start and last_mod_end:
            params["lastModStartDate"] = _fmt(last_mod_start)
            params["lastModEndDate"] = _fmt(last_mod_end)
        return await self._get(_CVE_PATH, params)

    async def fetch_cpes(self, *, start_index: int = 0, results_per_page: int = 10000) -> dict:
        """Одна страница `cpes/2.0` (CPE Dictionary, design-nvd-sync §7)."""
        return await self._get(
            _CPE_PATH, {"startIndex": start_index, "resultsPerPage": results_per_page}
        )

    async def _backoff(self, attempt: int, retry_after: float | None) -> None:
        # Экспоненциальный бэкофф с полным jitter; уважаем Retry-After, если он больше.
        base = min(2.0**attempt, 60.0)
        delay = random.uniform(0, base)
        if retry_after is not None:
            delay = max(delay, retry_after)
        await asyncio.sleep(delay)

    @staticmethod
    def _retry_after(resp: httpx.Response) -> float | None:
        value = resp.headers.get("Retry-After")
        if value is None:
            return None
        try:
            return float(value)
        except ValueError:
            return None

    async def _get(self, path: str, params: dict) -> dict:
        last_exc: Exception | None = None
        for attempt in range(1, self._max_attempts + 1):
            await self._limiter.acquire()
            try:
                resp = await self._client.get(path, params=params)
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_exc = exc
                if attempt >= self._max_attempts:
                    break
                await self._backoff(attempt, None)
                continue

            if resp.status_code == 200:
                return resp.json()
            if resp.status_code == 403:
                raise NvdAuthError("NVD 403 — проверь NVD_API_KEY")
            if resp.status_code == 404:
                raise NvdNotFound(f"NVD 404 для {path}")
            if resp.status_code in _RETRY_STATUS:
                last_exc = NvdError(f"NVD {resp.status_code}")
                if attempt >= self._max_attempts:
                    break
                await self._backoff(attempt, self._retry_after(resp))
                continue
            raise NvdError(f"NVD неожиданный статус {resp.status_code}")

        raise NvdError(f"NVD: исчерпаны {self._max_attempts} попыток") from last_exc
