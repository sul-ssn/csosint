"""Ядро матчинга «сервис → CVE» (design-cpe-matching §7–§10).

Чистая логика без БД: кандидаты применимости (`cve_cpe_match`) отдаёт
инъектируемый `CandidateProvider`, чтобы юнит-тесты гоняли золотые кейсы
в памяти, без сети и Postgres.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from univers.versions import GenericVersion

from cve_service.cpe import parse_cpe

from .product_map import ProductMatch, map_product_to_cpe
from .version import extract_core, in_range, normalize, ver_eq


@dataclass(frozen=True, slots=True)
class Candidate:
    """Строка `cve_cpe_match` — то, что нужно для теста применимости."""

    cve_id: str
    cpe_uri: str
    version_start: str | None = None
    version_start_type: str | None = None
    version_end: str | None = None
    version_end_type: str | None = None
    config_operator: str | None = None
    node_operator: str | None = None


@dataclass(frozen=True, slots=True)
class Match:
    cve_id: str
    confidence: str  # high | medium | low
    matched_cpe: str


# (part, vendor, product) → строки-кандидаты. Реальный провайдер ходит в БД.
CandidateProvider = Callable[[str, str, str], list[Candidate]]

_CONF_RANK = {"low": 1, "medium": 2, "high": 3}


def evaluate_version(observed: GenericVersion | None, cand: Candidate) -> tuple[bool, str] | None:
    """Тест «версия ∈ диапазон» (§7). Возвращает (применимо, вид совпадения)
    либо None — «сравнивать нечем, пропустить» (versionless → REJECT выше)."""
    has_range = cand.version_start is not None or cand.version_end is not None
    crit = parse_cpe(cand.cpe_uri)
    exact_in_cpe = crit is not None and crit.has_exact_version and not has_range

    if observed is None:
        return None  # только продукт без версии → шумно, не матчим (§11)
    if exact_in_cpe:
        return ver_eq(observed, crit.version), "exact"  # type: ignore[union-attr]
    if has_range:
        return (
            in_range(
                observed,
                cand.version_start,
                cand.version_start_type,
                cand.version_end,
                cand.version_end_type,
            ),
            "range",
        )
    return True, "all"  # wildcard-версия без границ → «все версии»


def _version_points(core: str | None) -> int:
    if not core:
        return 0
    # Специфичная версия (>=3 компонента или буквенный суффикс) весомее «2.4».
    specific = core.count(".") >= 2 or any(c.isalpha() for c in core)
    return 2 if specific else 1


def _is_and_node(cand: Candidate) -> bool:
    """AND «running on»: применимость требует ещё одну ветку, которую мы не проверяли."""
    return cand.config_operator == "AND" or cand.node_operator == "AND"


def confidence_score(
    method: str, version_core: str | None, match_kind: str, cand: Candidate
) -> int:
    """Очки достоверности (§9). Затем to_bucket превращает их в корзину."""
    score = 0
    # Маппинг продукта.
    if method in ("from_internetdb", "alias", "dict_exact"):
        score += 2
    elif method == "dict_fuzzy":
        score += 1
    # Версия.
    score += _version_points(version_core)
    # Тип совпадения.
    score += {"exact": 2, "range": 1, "all": 0}[match_kind]
    # Узел.
    score += -1 if _is_and_node(cand) else 1
    return score


def to_bucket(score: int) -> str | None:
    if score >= 5:
        return "high"
    if score >= 3:
        return "medium"
    if score >= 1:
        return "low"
    return None  # REJECT


def resolve_products(
    product: str | None, cpe_uri: str | None, dictionary=None
) -> list[ProductMatch]:
    """Стадия A/B: кандидатные `vendor:product`. Готовый CPE от InternetDB
    (стадия A) короткозамыкает фаззи-маппинг."""
    if cpe_uri:
        parsed = parse_cpe(cpe_uri)
        if parsed is None:
            return []
        return [ProductMatch(parsed.vendor, parsed.product, "from_internetdb")]
    return map_product_to_cpe(product, dictionary)


def match_service(
    product: str | None,
    version: str | None,
    cpe_uri: str | None,
    get_candidates: CandidateProvider,
    *,
    dictionary=None,
) -> list[Match]:
    """Полный пайплайн для одного сервиса → список Match с дедупом по CVE."""
    products = resolve_products(product, cpe_uri, dictionary)
    if not products:
        return []

    # (C) версия.
    version_core = extract_core(version)
    observed = normalize(version)

    best: dict[str, Match] = {}
    for pm in products:
        part = "a"  # приложения — основной кейс; part берём из candidate-запроса
        for cand in get_candidates(part, pm.vendor, pm.product):
            result = evaluate_version(observed, cand)
            if result is None:
                continue
            applies, kind = result
            if not applies:
                continue
            bucket = to_bucket(confidence_score(pm.method, version_core, kind, cand))
            if bucket is None:
                continue
            prev = best.get(cand.cve_id)
            if prev is None or _CONF_RANK[bucket] > _CONF_RANK[prev.confidence]:
                best[cand.cve_id] = Match(cand.cve_id, bucket, cand.cpe_uri)
    return list(best.values())
