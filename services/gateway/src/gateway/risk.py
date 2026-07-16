"""Модель риска и агрегация отчёта (чистые функции — тестируются без БД).

Риск = базовый CVSS, **дисконтированный на достоверность матчинга**: low-confidence
совпадение может не применяться к хосту, поэтому его вклад в риск ниже. Это оценка
приоритета для триажа, а НЕ подтверждение уязвимости.

Шкала risk_score — 0..100: CVSS × confidence + EPSS/KEV exploitation signals.
"""

from __future__ import annotations

CONFIDENCE_WEIGHT = {"high": 1.0, "medium": 0.75, "low": 0.5}
_UNKNOWN_CVSS = 5.0  # CVSS неизвестен → консервативная середина, не завышаем
_CONF_RANK = {"high": 3, "medium": 2, "low": 1}
_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


def risk_score(
    cvss_score: float | None,
    match_confidence: str,
    epss_score: float | None = None,
    kev: bool = False,
    ransomware_use: str | None = None,
) -> float:
    """0..100. CVSS×confidence + максимум 15 EPSS + 20 KEV + 5 ransomware."""
    base = cvss_score if cvss_score is not None else _UNKNOWN_CVSS
    weight = CONFIDENCE_WEIGHT.get(match_confidence, 0.5)
    score = base * weight * 10.0
    score += max(0.0, min(1.0, epss_score or 0.0)) * 15.0
    if kev:
        score += 20.0
    if (ransomware_use or "").lower() == "known":
        score += 5.0
    return round(min(100.0, score), 1)


def risk_factors(vuln: dict) -> list[dict]:
    """Машиночитаемое объяснение результата для UI/API."""
    cvss = vuln.get("cvss_score")
    conf = vuln.get("match_confidence", "low")
    cvss_label = cvss if cvss is not None else "неизвестна"
    factors = [
        {
            "factor": "cvss",
            "impact": round((cvss if cvss is not None else _UNKNOWN_CVSS) * 10, 1),
            "detail": f"Базовая техническая тяжесть CVSS {cvss_label}",
        },
        {
            "factor": "confidence",
            "impact": CONFIDENCE_WEIGHT.get(conf, 0.5),
            "detail": f"Достоверность сопоставления: {conf}",
        },
    ]
    epss = vuln.get("epss_score")
    if epss is not None:
        factors.append(
            {
                "factor": "epss",
                "impact": round(epss * 15.0, 1),
                "detail": f"EPSS: {epss * 100:.1f}% вероятности эксплуатации в ближайшие 30 дней",
            }
        )
    if vuln.get("kev"):
        factors.append(
            {
                "factor": "kev",
                "impact": 20.0,
                "detail": "CISA подтверждает эксплуатацию уязвимости в реальных атаках",
            }
        )
    if (vuln.get("kev_ransomware_use") or "").lower() == "known":
        factors.append(
            {
                "factor": "ransomware",
                "impact": 5.0,
                "detail": "CISA связывает уязвимость с ransomware-кампаниями",
            }
        )
    return factors


def priority(score: float) -> str:
    """Корзина приоритета триажа по risk_score."""
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def severity_bucket(severity: str | None) -> str:
    """Нормализует CVSS-severity к корзине; неизвестное → 'unknown'."""
    s = (severity or "").upper()
    return s.lower() if s in _SEVERITIES else "unknown"


def rank_findings(vulns: list[dict]) -> list[dict]:
    """Проставляет risk_score/priority и сортирует по убыванию риска (мутирует и возвращает)."""
    for v in vulns:
        v["risk_score"] = risk_score(
            v.get("cvss_score"),
            v.get("match_confidence", "low"),
            v.get("epss_score"),
            bool(v.get("kev")),
            v.get("kev_ransomware_use"),
        )
        v["priority"] = priority(v["risk_score"])
        v["risk_factors"] = risk_factors(v)
    vulns.sort(
        key=lambda v: (
            v["risk_score"],
            v.get("cvss_score") or 0.0,
            _CONF_RANK.get(v.get("match_confidence"), 0),
        ),
        reverse=True,
    )
    return vulns


def summarize(domains: int, ips: int, services: int, vulns: list[dict]) -> dict:
    """Сводка: распределения по severity / достоверности / приоритету + общая постура."""
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    by_confidence = {"high": 0, "medium": 0, "low": 0}
    by_priority = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for v in vulns:
        by_severity[severity_bucket(v.get("severity"))] += 1
        conf = v.get("match_confidence")
        if conf in by_confidence:
            by_confidence[conf] += 1
        by_priority[v.get("priority", "low")] += 1
    max_score = max((v.get("risk_score", 0.0) for v in vulns), default=0.0)
    return {
        "domains": domains,
        "ips": ips,
        "services": services,
        "vulnerabilities": len(vulns),
        "by_severity": by_severity,
        "by_confidence": by_confidence,
        "by_priority": by_priority,
        "max_risk_score": max_score,
        "risk_posture": priority(max_score) if vulns else "none",
        "known_exploited": sum(1 for v in vulns if v.get("kev")),
        "high_epss": sum(1 for v in vulns if (v.get("epss_score") or 0) >= 0.1),
    }


def top_risks(vulns: list[dict], n: int = 5) -> list[dict]:
    """Первые n находок (список уже отсортирован rank_findings)."""
    return vulns[:n]


def build_exec_summary(
    target: str, ips: int, services: int, vulns: list[dict], summary: dict
) -> str:
    """Детерминированный текст-резюме (не AI). Держим формулировку «потенциальные»."""
    if not vulns:
        return (
            f"По цели {target}: обнаружено {services} сервисов на {ips} IP. "
            "Потенциальных уязвимостей по локальной базе NVD не выявлено. "
            "Это не гарантия защищённости — см. дисклеймер."
        )
    sev = summary["by_severity"]
    top = vulns[0]
    host = f"{top.get('ip')}:{top.get('port')}"
    product = top.get("product") or "сервис"
    version = f" {top['version']}" if top.get("version") else ""
    cvss = top.get("cvss_score")
    cvss_txt = f"CVSS {cvss}" if cvss is not None else "CVSS н/д"
    sev_label = f" {top['severity']}" if top.get("severity") else ""
    exploited = " Входит в CISA KEV." if top.get("kev") else ""
    return (
        f"По цели {target}: {services} сервисов на {ips} IP, "
        f"{len(vulns)} потенциальных уязвимостей "
        f"(критич. {sev['critical']}, высок. {sev['high']}, средн. {sev['medium']}). "
        f"Наибольший риск — {top['cve_id']} ({cvss_txt}{sev_label}, "
        f"достоверность {top.get('match_confidence')}) на {product}{version} ({host})."
        f"{exploited} "
        "Начните триаж с блока «Наибольшие риски»."
    )
