"""Клиент NVD: ретраи/лимиты (design-nvd-sync §4, §12). Сеть не трогаем — respx."""

from __future__ import annotations

import httpx
import pytest
import respx

from cve_service.nvd.client import NvdAuthError, NvdClient, NvdError

_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@pytest.fixture(autouse=True)
def _no_backoff_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    # Бэкофф без реальных пауз — тесты быстрые.
    monkeypatch.setattr("cve_service.nvd.client.random.uniform", lambda a, b: 0.0)


@respx.mock
async def test_retries_503_then_succeeds() -> None:
    route = respx.get(_URL).mock(
        side_effect=[
            httpx.Response(503),
            httpx.Response(503),
            httpx.Response(
                200, json={"totalResults": 0, "resultsPerPage": 0, "vulnerabilities": []}
            ),
        ]
    )
    async with NvdClient(min_delay=0, max_attempts=5) as client:
        data = await client.fetch_cves(start_index=0, results_per_page=1)
    assert data["totalResults"] == 0
    assert route.call_count == 3


@respx.mock
async def test_403_is_not_retried() -> None:
    route = respx.get(_URL).mock(return_value=httpx.Response(403))
    async with NvdClient(min_delay=0, max_attempts=5) as client:
        with pytest.raises(NvdAuthError):
            await client.fetch_cves()
    assert route.call_count == 1  # 403 — конфиг-ошибка, повторов нет


@respx.mock
async def test_exhausted_retries_raise() -> None:
    respx.get(_URL).mock(return_value=httpx.Response(503))
    async with NvdClient(min_delay=0, max_attempts=3) as client:
        with pytest.raises(NvdError):
            await client.fetch_cves()


@respx.mock
async def test_incremental_params_are_sent() -> None:
    from datetime import UTC, datetime

    route = respx.get(_URL).mock(
        return_value=httpx.Response(
            200, json={"totalResults": 0, "resultsPerPage": 0, "vulnerabilities": []}
        )
    )
    async with NvdClient(min_delay=0) as client:
        await client.fetch_cves(
            last_mod_start=datetime(2026, 1, 1, tzinfo=UTC),
            last_mod_end=datetime(2026, 2, 1, tzinfo=UTC),
        )
    params = route.calls.last.request.url.params
    assert "lastModStartDate" in params
    assert "lastModEndDate" in params
