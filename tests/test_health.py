"""Каркасные тесты Этапа 0: liveness сервисов и целостность схемы."""

from __future__ import annotations

from fastapi.testclient import TestClient

from cve_service.main import app as cve_app
from gateway.main import app as gateway_app


def test_gateway_liveness() -> None:
    with TestClient(gateway_app) as client:
        resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"service": "gateway", "status": "ok"}


def test_cve_service_liveness() -> None:
    with TestClient(cve_app) as client:
        resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["service"] == "cve-service"


def test_scan_endpoint_is_stub() -> None:
    # Оркестрация сбора — Этап 2; пока честный 501.
    with TestClient(gateway_app) as client:
        resp = client.post("/api/v1/scan", json={"target": "example.com", "type": "domain"})
    assert resp.status_code == 501


def test_schema_has_core_tables() -> None:
    from csosint_common.models import Base

    tables = set(Base.metadata.tables)
    assert {"cve_records", "cve_cpe_match", "services", "sync_state", "service_cve"} <= tables
