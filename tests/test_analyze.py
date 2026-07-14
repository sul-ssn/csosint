"""Тесты AI-слоя сценариев атак (gateway.analyze) — без сети и без ключа."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from gateway import analyze
from gateway.main import app as gateway_app

SAMPLE_REPORT = {
    "job": {"target": "example.com", "type": "domain"},
    "summary": {
        "services": 2,
        "vulnerabilities": 2,
        "by_severity": {"critical": 1, "high": 1, "medium": 0, "low": 0, "unknown": 0},
        "risk_posture": "critical",
    },
    "vulnerabilities": [
        {
            "cve_id": "CVE-2021-44228",
            "product": "Apache Log4j",
            "version": "2.14.1",
            "ip": "203.0.113.5",
            "port": 8080,
            "cvss_score": 10.0,
            "severity": "CRITICAL",
            "match_confidence": "high",
            "priority": "critical",
        },
        {
            "cve_id": "CVE-2014-0160",
            "product": "OpenSSL",
            "version": "1.0.1",
            "ip": "203.0.113.5",
            "port": 443,
            "cvss_score": 7.5,
            "severity": "HIGH",
            "match_confidence": "high",
            "priority": "high",
        },
    ],
}

CANNED_MODEL_JSON = json.dumps(
    {
        "overall_assessment": "Критический риск из-за Log4Shell на 8080.",
        "scenarios": [
            {
                "title": "RCE через Log4Shell",
                "likelihood": "high",
                "based_on": ["CVE-2021-44228"],
                "attack_path": [
                    "Внешний доступ к сервису на 8080",
                    "JNDI-инъекция в логируемое поле",
                ],
                "impact": "Удалённое выполнение кода на хосте.",
                "remediation": ["Обновить Log4j до 2.17+", "Ограничить исходящий трафик"],
            }
        ],
    },
    ensure_ascii=False,
)


def test_build_model_input_shape() -> None:
    payload = analyze.build_model_input(SAMPLE_REPORT)
    assert payload["target"] == "example.com"
    assert payload["findings_total"] == 2
    assert len(payload["findings"]) == 2
    assert payload["findings"][0]["host"] == "203.0.113.5:8080"
    assert payload["summary"]["risk_posture"] == "critical"


def test_build_model_input_caps_findings() -> None:
    many = {**SAMPLE_REPORT, "vulnerabilities": SAMPLE_REPORT["vulnerabilities"] * 20}
    payload = analyze.build_model_input(many, max_findings=15)
    assert len(payload["findings"]) == 15
    assert payload["findings_total"] == 40


def test_output_schema_is_strict() -> None:
    assert analyze.OUTPUT_SCHEMA["additionalProperties"] is False
    assert "scenarios" in analyze.OUTPUT_SCHEMA["required"]
    item = analyze.OUTPUT_SCHEMA["properties"]["scenarios"]["items"]
    assert item["additionalProperties"] is False
    assert set(item["required"]) == {
        "title",
        "likelihood",
        "based_on",
        "attack_path",
        "impact",
        "remediation",
    }


def test_attack_analysis_validates_canned() -> None:
    parsed = analyze.AttackAnalysis.model_validate_json(CANNED_MODEL_JSON)
    assert parsed.scenarios[0].title == "RCE через Log4Shell"
    assert parsed.scenarios[0].likelihood == "high"


async def test_analyze_report_with_mocked_model(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_call(payload: dict) -> str:
        assert payload["target"] == "example.com"  # получает наш вход
        return CANNED_MODEL_JSON

    monkeypatch.setattr(analyze, "_call_model", fake_call)
    result = await analyze.analyze_report(SAMPLE_REPORT)
    assert result["findings_analyzed"] == 2
    assert result["analysis"]["scenarios"][0]["title"] == "RCE через Log4Shell"
    assert "гипотет" in result["disclaimer"].lower()


async def test_analyze_report_empty_skips_model(monkeypatch: pytest.MonkeyPatch) -> None:
    async def boom(payload: dict) -> str:
        raise AssertionError("модель не должна вызываться при отсутствии находок")

    monkeypatch.setattr(analyze, "_call_model", boom)
    empty = {**SAMPLE_REPORT, "vulnerabilities": [], "summary": {"vulnerabilities": 0}}
    result = await analyze.analyze_report(empty)
    assert result["analysis"] is None
    assert "нечего" in result["note"]


def test_analyze_endpoint_501_without_key(monkeypatch: pytest.MonkeyPatch) -> None:
    # Self-host: нет ANTHROPIC_API_KEY → честный 501 до похода в БД/модель.
    # Явно гасим ключ, чтобы тест не зависел от локального .env разработчика.
    from csosint_common.config import get_settings

    monkeypatch.setattr(get_settings(), "anthropic_api_key", None)
    with TestClient(gateway_app) as client:
        resp = client.post("/api/v1/analyze/1")
    assert resp.status_code == 501
