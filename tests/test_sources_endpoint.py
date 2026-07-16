"""Эндпоинт статуса источников."""

from __future__ import annotations

from fastapi.testclient import TestClient

from gateway.main import app


def test_sources_lists_core_and_optional() -> None:
    with TestClient(app) as client:
        resp = client.get("/api/v1/sources")
    assert resp.status_code == 200
    body = resp.json()
    assert set(body["core"]) == {"internetdb", "crtsh", "dns", "rdap"}
    names = {o["name"] for o in body["optional"]}
    assert names == {"shodan", "censys", "securitytrails", "virustotal"}
    # В тестовой среде ключей нет → все опциональные выключены.
    assert all(o["enabled"] is False for o in body["optional"])
