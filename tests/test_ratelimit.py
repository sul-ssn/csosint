"""Rate-limiting эндпоинтов gateway (ТЗ §7)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from gateway import ratelimit
from gateway.main import app
from gateway.ratelimit import SlidingWindowLimiter


def test_sliding_window_allows_then_blocks() -> None:
    now = [0.0]
    lim = SlidingWindowLimiter(limit=2, window=60.0, clock=lambda: now[0])
    assert lim.allow("k") is True
    assert lim.allow("k") is True
    assert lim.allow("k") is False  # 3-й в окне — блок
    now[0] = 61.0  # окно прошло → снова можно
    assert lim.allow("k") is True


def test_limiter_is_per_client_key() -> None:
    lim = SlidingWindowLimiter(limit=1, window=60.0)
    assert lim.allow("a") is True
    assert lim.allow("b") is True  # другой клиент — свой бюджет
    assert lim.allow("a") is False


def test_endpoint_returns_429_over_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ratelimit, "_limiter", SlidingWindowLimiter(limit=2, window=60.0))
    with TestClient(app) as client:
        assert client.get("/api/v1/sources").status_code == 200
        assert client.get("/api/v1/sources").status_code == 200
        assert client.get("/api/v1/sources").status_code == 429
