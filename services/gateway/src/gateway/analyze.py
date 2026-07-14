"""AI-слой: гипотетические сценарии атак поверх отчёта (Этап 6).

Оборонительный анализ для СВОЕЙ/авторизованной инфраструктуры: берём
приоритизированные «потенциальные» находки из отчёта (risk-модель §1) и просим
Claude построить концептуальные сценарии атак + remediation. НЕ генерируем
рабочих эксплойтов — только пути атаки и меры защиты (см. системный промпт).

Модель — `claude-opus-4-8` (настраивается `ANTHROPIC_MODEL`). Структурированный
вывод через `output_config.format`. Нет ключа → эндпоинт отдаёт 501 (см. main).
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel

from csosint_common.config import get_settings

# Дисклеймер задаём сервером (не доверяем модели) — гарантируем «potential/гипотеза».
DISCLAIMER = (
    "Сценарии — ГИПОТЕТИЧЕСКИЕ и оборонительные: они исходят из допущения, что "
    "«потенциальные» CVE реальны и не закрыты. Наличие версии с известной CVE не "
    "значит, что хост уязвим (возможен бэкпорт-патч, ложное срабатывание). Это "
    "оценка риска для приоритизации устранения, не подтверждение и не руководство "
    "к эксплуатации."
)

SYSTEM_PROMPT = """\
Ты — ассистент оборонительного анализа платформы OSPC (self-host). Пользователь \
анализирует СВОЮ или авторизованную инфраструктуру. На вход — JSON с обнаруженными \
сервисами и «потенциальными» CVE (оценка вероятности, НЕ подтверждение: возможны \
бэкпорт-патчи и ложные срабатывания).

Задача: построить приоритизированные ГИПОТЕТИЧЕСКИЕ сценарии атак, которые \
злоумышленник мог бы реализовать, ЕСЛИ уязвимости реальны и не закрыты, — чтобы \
защитник понял риск и очередь устранения.

Строго:
- Это ОБОРОНИТЕЛЬНЫЙ анализ. НЕ давай рабочих эксплойтов, пейлоадов, команд, \
PoC-кода или пошаговых инструкций эксплуатации. Пути атаки описывай концептуально: \
какая слабость → к чему ведёт → почему опасно.
- Для каждого сценария дай приоритизированные меры устранения (remediation).
- likelihood оценивай реалистично по эксплуатируемости и экспозиции; помни, что \
находки «потенциальные».
- НЕ выдумывай CVE или сервисы, которых нет во входных данных; based_on ссылается \
только на переданные CVE/сервисы.
- Отвечай на русском. Верни строго JSON по заданной схеме, без markdown."""

# JSON-схема структурированного вывода. Ограничения structured outputs: у объектов
# additionalProperties=false + required; без min/maxLength; enum допустим.
OUTPUT_SCHEMA: dict = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "overall_assessment": {"type": "string"},
        "scenarios": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "title": {"type": "string"},
                    "likelihood": {"type": "string", "enum": ["high", "medium", "low"]},
                    "based_on": {"type": "array", "items": {"type": "string"}},
                    "attack_path": {"type": "array", "items": {"type": "string"}},
                    "impact": {"type": "string"},
                    "remediation": {"type": "array", "items": {"type": "string"}},
                },
                "required": [
                    "title",
                    "likelihood",
                    "based_on",
                    "attack_path",
                    "impact",
                    "remediation",
                ],
            },
        },
    },
    "required": ["overall_assessment", "scenarios"],
}


class AttackScenario(BaseModel):
    title: str
    likelihood: Literal["high", "medium", "low"]
    based_on: list[str]
    attack_path: list[str]
    impact: str
    remediation: list[str]


class AttackAnalysis(BaseModel):
    overall_assessment: str
    scenarios: list[AttackScenario]


def build_model_input(report: dict, max_findings: int = 15) -> dict:
    """Компактный, ограниченный по объёму вход для модели из отчёта (§1)."""
    job = report.get("job", {})
    summary = report.get("summary", {})
    vulns = report.get("vulnerabilities", [])
    findings = [
        {
            "cve_id": v.get("cve_id"),
            "product": v.get("product"),
            "version": v.get("version"),
            "host": f"{v.get('ip')}:{v.get('port')}",
            "cvss": v.get("cvss_score"),
            "severity": v.get("severity"),
            "match_confidence": v.get("match_confidence"),
            "priority": v.get("priority"),
        }
        for v in vulns[:max_findings]
    ]
    return {
        "target": job.get("target"),
        "target_type": job.get("type"),
        "summary": {
            "services": summary.get("services"),
            "vulnerabilities": summary.get("vulnerabilities"),
            "by_severity": summary.get("by_severity"),
            "risk_posture": summary.get("risk_posture"),
        },
        "findings": findings,
        "findings_total": len(vulns),
    }


async def _call_model(payload: dict) -> str:
    """Изолированный вызов Claude (мокается в тестах). Возвращает JSON-строку."""
    import json

    from anthropic import AsyncAnthropic

    settings = get_settings()
    client = AsyncAnthropic(api_key=settings.anthropic_api_key)
    resp = await client.messages.create(
        model=settings.anthropic_model,
        max_tokens=6000,
        thinking={"type": "adaptive"},
        system=SYSTEM_PROMPT,
        output_config={
            "format": {"type": "json_schema", "schema": OUTPUT_SCHEMA},
            "effort": "medium",
        },
        messages=[{"role": "user", "content": json.dumps(payload, ensure_ascii=False)}],
    )
    # output_config.format гарантирует: первый text-блок — валидный JSON по схеме.
    return next(b.text for b in resp.content if b.type == "text")


async def analyze_report(report: dict) -> dict:
    """Оркестрация: отчёт → вход модели → структурированные сценарии атак."""
    payload = build_model_input(report)
    base = {
        "target": payload["target"],
        "model": get_settings().anthropic_model,
        "findings_analyzed": len(payload["findings"]),
        "disclaimer": DISCLAIMER,
    }
    if not payload["findings"]:
        return {
            **base,
            "analysis": None,
            "note": "Потенциальных уязвимостей нет — анализировать нечего.",
        }

    raw = await _call_model(payload)
    analysis = AttackAnalysis.model_validate_json(raw)
    return {**base, "analysis": analysis.model_dump()}
