"""Прогресс сбора: события источников через progress-callback."""

from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest
import respx
import tenacity
from collector_service.pipeline import collect

from csosint_common.events import ProgressEvent

_NO_KEYS = SimpleNamespace(
    shodan_api_key=None,
    censys_api_id=None,
    censys_api_secret=None,
    securitytrails_api_key=None,
    virustotal_api_key=None,
)


@pytest.fixture(autouse=True)
def _no_retry_wait(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "collector_service.http.wait_random_exponential", lambda **kw: tenacity.wait_none()
    )


@respx.mock
async def test_ip_scan_emits_source_progress() -> None:
    respx.get("https://internetdb.shodan.io/1.2.3.4").mock(
        return_value=httpx.Response(200, json={"ports": [443], "cpes": [], "hostnames": []})
    )
    respx.get("https://rdap.org/ip/1.2.3.4").mock(
        return_value=httpx.Response(200, json={"name": "NET", "country": "US"})
    )

    events: list[dict] = []

    async def prog(e: dict) -> None:
        events.append(e)

    await collect("1.2.3.4", "ip", _NO_KEYS, progress=prog)

    seen = {(e["source"], e["status"]) for e in events if e["event"] == "source"}
    assert ("internetdb", "ok") in seen
    assert ("rdap", "ok") in seen
    # Опциональные без ключей → skipped-события.
    assert ("shodan", "skipped") in seen
    assert ("censys", "skipped") in seen


@respx.mock
async def test_failed_source_emits_failed_event() -> None:
    respx.get("https://internetdb.shodan.io/9.9.9.9").mock(return_value=httpx.Response(404))
    respx.get("https://rdap.org/ip/9.9.9.9").mock(
        return_value=httpx.Response(200, json={"name": "Q"})
    )
    events: list[dict] = []
    await collect("9.9.9.9", "ip", _NO_KEYS, progress=lambda e: _append(events, e))
    seen = {(e["source"], e["status"]) for e in events if e["event"] == "source"}
    assert ("internetdb", "failed") in seen


async def _append(bucket: list, e: dict) -> None:
    bucket.append(e)


def test_progress_event_terminal_flag() -> None:
    assert ProgressEvent(job_id=1, event="done").terminal is True
    assert ProgressEvent(job_id=1, event="failed").terminal is True
    assert ProgressEvent(job_id=1, event="source", source="dns").terminal is False
