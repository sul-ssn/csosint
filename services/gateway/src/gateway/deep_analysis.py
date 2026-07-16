"""Детерминированный анализ экспозиции и построение объяснимых attack paths.

Правила не подтверждают эксплуатацию или misconfiguration: они приоритизируют
наблюдаемую извне поверхность и всегда возвращают evidence + remediation.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

SENSITIVE_PORTS: dict[int, dict] = {
    22: {
        "severity": "medium",
        "title": "SSH доступен из интернета",
        "kind": "remote_access",
        "remediation": "Ограничьте SSH allowlist/VPN и отключите password authentication.",
    },
    2375: {
        "severity": "critical",
        "title": "Docker API доступен без TLS-порта",
        "kind": "admin_interface",
        "remediation": "Закройте TCP/2375; используйте локальный socket или TLS-аутентификацию.",
    },
    3306: {
        "severity": "high",
        "title": "MySQL наблюдается на публичном адресе",
        "kind": "database",
        "remediation": "Уберите СУБД из внешнего периметра и разрешите доступ только приложению.",
    },
    5432: {
        "severity": "high",
        "title": "PostgreSQL наблюдается на публичном адресе",
        "kind": "database",
        "remediation": "Закройте публичный доступ и ограничьте pg_hba.conf доверенными сетями.",
    },
    5900: {
        "severity": "high",
        "title": "VNC доступен из интернета",
        "kind": "remote_access",
        "remediation": "Поместите VNC за VPN/bastion и примените сетевой allowlist.",
    },
    6379: {
        "severity": "critical",
        "title": "Redis наблюдается на публичном адресе",
        "kind": "database",
        "remediation": "Отключите public bind, включите ACL/TLS и ограничьте доступ firewall.",
    },
    6443: {
        "severity": "high",
        "title": "Kubernetes API доступен из интернета",
        "kind": "admin_interface",
        "remediation": "Ограничьте API server корпоративными сетями/VPN и проверьте RBAC.",
    },
    9200: {
        "severity": "high",
        "title": "Elasticsearch наблюдается на публичном адресе",
        "kind": "database",
        "remediation": "Закройте внешний доступ и включите authentication/TLS.",
    },
    11211: {
        "severity": "critical",
        "title": "Memcached наблюдается на публичном адресе",
        "kind": "database",
        "remediation": "Привяжите Memcached к private interface и заблокируйте UDP/TCP извне.",
    },
    27017: {
        "severity": "high",
        "title": "MongoDB наблюдается на публичном адресе",
        "kind": "database",
        "remediation": "Ограничьте bindIp/private network и включите обязательную аутентификацию.",
    },
    3389: {
        "severity": "high",
        "title": "RDP доступен из интернета",
        "kind": "remote_access",
        "remediation": "Поместите RDP за VPN/RD Gateway, включите NLA и MFA.",
    },
}

_ENV_TOKEN = re.compile(r"(^|[.-])(dev|test|stage|staging|qa|uat|demo|sandbox)([.-]|$)", re.I)
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def analyze_exposure(domains: list[dict], services: list[dict]) -> list[dict]:
    findings: list[dict] = []
    for service in services:
        ip, port = service.get("ip"), service.get("port")
        if port in SENSITIVE_PORTS:
            rule = SENSITIVE_PORTS[port]
            findings.append(
                {
                    "id": f"exposure:{ip}:{port}",
                    "category": "exposure",
                    "kind": rule["kind"],
                    "severity": rule["severity"],
                    "title": rule["title"],
                    "asset": f"{ip}:{port}",
                    "confidence": "high",
                    "evidence": [
                        f"Порт {port} получен из пассивного источника "
                        f"{service.get('source') or 'unknown'}",
                        f"Продукт: {service.get('product') or 'не определён'}",
                    ],
                    "remediation": rule["remediation"],
                }
            )
        if service.get("product") and not service.get("version") and port != 0:
            findings.append(
                {
                    "id": f"hygiene:version:{service.get('id')}",
                    "category": "hygiene",
                    "kind": "unknown_version",
                    "severity": "low",
                    "title": "Версия публичного сервиса не определена",
                    "asset": f"{ip}:{port}",
                    "confidence": "medium",
                    "evidence": [f"Определён продукт {service['product']}, но отсутствует версия"],
                    "remediation": (
                        "Проверьте версию вручную и добавьте актив в управляемый inventory."
                    ),
                }
            )
    for domain in domains:
        fqdn = domain["fqdn"]
        if _ENV_TOKEN.search(fqdn):
            findings.append(
                {
                    "id": f"exposure:environment:{fqdn}",
                    "category": "exposure",
                    "kind": "non_production",
                    "severity": "medium",
                    "title": "Непроизводственная среда видна во внешнем периметре",
                    "asset": fqdn,
                    "confidence": "medium",
                    "evidence": [f"Имя {fqdn} содержит маркер dev/test/stage/qa"],
                    "remediation": (
                        "Проверьте необходимость публикации и эквивалентность production-защите."
                    ),
                }
            )
    findings.sort(key=lambda item: (_SEVERITY_RANK[item["severity"]], item["title"]), reverse=True)
    return findings


def analyze_infrastructure(certificates: list[dict], ips: list[dict]) -> list[dict]:
    """Сроки сертификатов и инфраструктурная концентрация без active probing."""
    findings: list[dict] = []
    now = datetime.now(UTC)
    for cert in certificates:
        expiry = cert.get("not_after")
        if isinstance(expiry, str):
            try:
                expiry = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
            except ValueError:
                expiry = None
        if expiry and expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=UTC)
        if expiry and expiry < now + timedelta(days=30):
            expired = expiry < now
            findings.append(
                {
                    "id": f"certificate:expiry:{cert['fingerprint']}",
                    "category": "hygiene",
                    "kind": "certificate_expiry",
                    "severity": "high" if expired else "medium",
                    "title": "Сертификат истёк" if expired else "Сертификат скоро истекает",
                    "asset": cert["fingerprint"],
                    "confidence": "high",
                    "evidence": [f"notAfter: {expiry.date().isoformat()}"],
                    "remediation": "Обновите сертификат и проверьте автоматическое продление.",
                }
            )
        if len(cert.get("domains", [])) >= 5:
            findings.append(
                {
                    "id": f"infrastructure:shared-cert:{cert['fingerprint']}",
                    "category": "hygiene",
                    "kind": "shared_certificate",
                    "severity": "low",
                    "title": "Сертификат связывает много внешних имён",
                    "asset": cert["fingerprint"],
                    "confidence": "high",
                    "evidence": [f"Связанных доменов: {len(cert['domains'])}"],
                    "remediation": (
                        "Проверьте список SAN и удалите неиспользуемые имена при перевыпуске."
                    ),
                }
            )
    networks: dict[str, list[str]] = {}
    for ip in ips:
        if cidr := ip.get("network_cidr"):
            networks.setdefault(cidr, []).append(ip["address"])
    for cidr, addresses in networks.items():
        if len(addresses) >= 3:
            findings.append(
                {
                    "id": f"infrastructure:netblock:{cidr}",
                    "category": "hygiene",
                    "kind": "infrastructure_cluster",
                    "severity": "low",
                    "title": "Несколько активов сосредоточены в одном netblock",
                    "asset": cidr,
                    "confidence": "high",
                    "evidence": [f"Наблюдаемые IP: {', '.join(sorted(addresses))}"],
                    "remediation": "Учитывайте общий blast radius провайдера при оценке рисков.",
                }
            )
    findings.sort(key=lambda item: (_SEVERITY_RANK[item["severity"]], item["title"]), reverse=True)
    return findings


def build_attack_paths(
    target: str, target_type: str, domains: list[dict], services: list[dict], vulns: list[dict]
) -> list[dict]:
    paths: list[dict] = []
    entry = target if target_type == "domain" else "Internet"
    for vuln in vulns[:10]:
        epss = vuln.get("epss_score") or 0.0
        if vuln.get("priority") not in {"critical", "high"} and not vuln.get("kev"):
            continue
        likelihood = "high" if vuln.get("kev") or epss >= 0.1 else "medium"
        host = f"{vuln.get('ip')}:{vuln.get('port')}"
        product = vuln.get("product") or "Публичный сервис"
        paths.append(
            {
                "id": f"path:cve:{vuln['service_id']}:{vuln['cve_id']}",
                "title": f"Публичный сервис → {vuln['cve_id']}",
                "likelihood": likelihood,
                "risk_score": vuln["risk_score"],
                "confidence": vuln.get("match_confidence", "low"),
                "nodes": [
                    {"type": "entry", "label": entry},
                    {"type": "ip", "label": host},
                    {"type": "service", "label": product},
                    {"type": "cve", "label": vuln["cve_id"]},
                ],
                "evidence": [factor["detail"] for factor in vuln.get("risk_factors", [])],
                "impact": vuln.get("description") or "Возможна компрометация публичного сервиса.",
                "remediation": vuln.get("kev_required_action")
                or (
                    "Проверьте применимость CVE, установите исправление "
                    "и ограничьте экспозицию сервиса."
                ),
            }
        )
    paths.sort(key=lambda item: item["risk_score"], reverse=True)
    return paths


def deep_summary(findings: list[dict], paths: list[dict]) -> dict:
    return {
        "findings": len(findings),
        "critical_findings": sum(1 for item in findings if item["severity"] == "critical"),
        "high_findings": sum(1 for item in findings if item["severity"] == "high"),
        "attack_paths": len(paths),
        "high_likelihood_paths": sum(1 for item in paths if item["likelihood"] == "high"),
    }
