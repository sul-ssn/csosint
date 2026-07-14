"""Парсинг ответа NVD API 2.0 (design-nvd-sync §5, §6).

Чистые функции: JSON одного элемента `vulnerabilities[].cve` → плоские
структуры данных (`ParsedCve`), которые слой синка кладёт в `cve_records` и
`cve_cpe_match`. Ничего не знают про БД → полностью юнит-тестируемы на фикстурах.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from cve_service.cpe import parse_cpe

# Приоритет метрик CVSS: новее — выше. V4.0 — задел на будущее (design-nvd-sync §5).
_CVSS_PRIORITY = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


@dataclass(slots=True)
class CveRecordData:
    cve_id: str
    description: str | None
    published: datetime | None
    modified: datetime | None
    cvss_version: str | None
    cvss_score: float | None
    cvss_vector: str | None
    severity: str | None
    raw: dict


@dataclass(slots=True)
class CpeMatchData:
    cpe_uri: str
    vendor: str | None
    product: str | None
    part: str | None
    vulnerable_bool: bool
    config_idx: int
    node_idx: int
    config_operator: str | None
    node_operator: str | None
    version_start: str | None = None
    version_start_type: str | None = None
    version_end: str | None = None
    version_end_type: str | None = None


@dataclass(slots=True)
class ParsedCve:
    record: CveRecordData
    matches: list[CpeMatchData] = field(default_factory=list)


def _parse_dt(value: str | None) -> datetime | None:
    """NVD-таймстемпы вида `2021-12-10T10:15:09.143` (UTC, часто без offset)."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt


def _english_description(cve: dict) -> str | None:
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value")
    return None


def _extract_cvss(cve: dict) -> tuple[str | None, float | None, str | None, str | None]:
    """Первая доступная метрика по приоритету; тип Primary важнее Secondary."""
    metrics = cve.get("metrics", {})
    for key in _CVSS_PRIORITY:
        entries = metrics.get(key)
        if not entries:
            continue
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = entry.get("cvssData", {})
        version = data.get("version")
        score = data.get("baseScore")
        vector = data.get("vectorString")
        # V3.x кладёт baseSeverity в cvssData, V2 — на уровне метрики.
        severity = data.get("baseSeverity") or entry.get("baseSeverity")
        return version, score, vector, severity
    return None, None, None, None


_START_TYPES = {
    "versionStartIncluding": "including",
    "versionStartExcluding": "excluding",
}
_END_TYPES = {
    "versionEndIncluding": "including",
    "versionEndExcluding": "excluding",
}


def _unpack_cpe_match(m: dict, *, config_idx, node_idx, config_operator, node_operator):
    cpe_uri = m.get("criteria", "")
    parsed = parse_cpe(cpe_uri)
    row = CpeMatchData(
        cpe_uri=cpe_uri,
        vendor=parsed.vendor if parsed else None,
        product=parsed.product if parsed else None,
        part=parsed.part if parsed else None,
        vulnerable_bool=bool(m.get("vulnerable", False)),
        config_idx=config_idx,
        node_idx=node_idx,
        config_operator=config_operator,
        node_operator=node_operator,
    )
    for src, kind in _START_TYPES.items():
        if src in m:
            row.version_start, row.version_start_type = m[src], kind
    for src, kind in _END_TYPES.items():
        if src in m:
            row.version_end, row.version_end_type = m[src], kind
    return row


def parse_configurations(cve: dict) -> list[CpeMatchData]:
    """Развернуть `configurations[].nodes[].cpeMatch[]` в плоские строки,
    сохранив группировку (config/node-операторы) для AND-логики матчинга."""
    rows: list[CpeMatchData] = []
    for config_idx, config in enumerate(cve.get("configurations", [])):
        config_operator = config.get("operator")  # AND между nodes («running on»)
        for node_idx, node in enumerate(config.get("nodes", [])):
            node_operator = node.get("operator")
            for m in node.get("cpeMatch", []):
                rows.append(
                    _unpack_cpe_match(
                        m,
                        config_idx=config_idx,
                        node_idx=node_idx,
                        config_operator=config_operator,
                        node_operator=node_operator,
                    )
                )
    return rows


def parse_cve(item: dict) -> ParsedCve:
    """Один элемент `vulnerabilities[]` → запись + строки применимости.

    Устойчив к неполным CVE (REJECTED/AWAITING без configurations/CVSS):
    поля просто NULL, не падаем (design-nvd-sync §11).
    """
    cve = item["cve"] if "cve" in item else item
    version, score, vector, severity = _extract_cvss(cve)
    record = CveRecordData(
        cve_id=cve["id"],
        description=_english_description(cve),
        published=_parse_dt(cve.get("published")),
        modified=_parse_dt(cve.get("lastModified")),
        cvss_version=version,
        cvss_score=score,
        cvss_vector=vector,
        severity=severity or ("UNKNOWN" if version is None else None),
        raw=cve,
    )
    return ParsedCve(record=record, matches=parse_configurations(cve))
