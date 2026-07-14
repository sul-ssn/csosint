"""Стадия B матчинга: `product` (свободный текст) → `vendor:product`
(design-cpe-matching §4).

Порядок от точного к рискованному, «сработало — стоп»:
1. alias_map (ручная, приоритетная);
2. cpe_dictionary — точное совпадение нормализованного имени;
3. cpe_dictionary — фаззи (token Jaccard) с порогом; ниже порога — не матчим
   (пустой результат лучше ложного).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from .aliases import ALIAS_MAP, normalize_product_name


@dataclass(frozen=True, slots=True)
class DictEntry:
    """Строка cpe_dictionary для маппинга (или производного product_index)."""

    vendor: str
    product: str
    title: str | None = None


@dataclass(frozen=True, slots=True)
class ProductMatch:
    vendor: str
    product: str
    method: str  # alias | dict_exact | dict_fuzzy | from_internetdb


def _tokens(name: str) -> set[str]:
    return set(name.split())


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    inter = len(a & b)
    return inter / len(a | b)


def map_product_to_cpe(
    product: str | None,
    dictionary: Sequence[DictEntry] | None = None,
    *,
    fuzzy_threshold: float = 0.6,
) -> list[ProductMatch]:
    """Кандидатные `vendor:product` для имени продукта. Может дать 0..N."""
    norm = normalize_product_name(product)
    if not norm:
        return []

    # 1) alias_map — точный ключ.
    if norm in ALIAS_MAP:
        return [ProductMatch(v, p, "alias") for v, p in ALIAS_MAP[norm]]

    if not dictionary:
        return []

    # 2) точное совпадение с product/title словаря.
    query_tokens = _tokens(norm)
    exact = {
        (e.vendor, e.product)
        for e in dictionary
        if normalize_product_name(e.product) == norm
        or (e.title and normalize_product_name(e.title) == norm)
    }
    if exact:
        return [ProductMatch(v, p, "dict_exact") for v, p in sorted(exact)]

    # 3) фаззи по токенам; берём только лучшую группу выше порога.
    scored: list[tuple[float, str, str]] = []
    for e in dictionary:
        cand_names = [normalize_product_name(e.product)]
        if e.title:
            cand_names.append(normalize_product_name(e.title))
        score = max((_jaccard(query_tokens, _tokens(n)) for n in cand_names if n), default=0.0)
        if score >= fuzzy_threshold:
            scored.append((score, e.vendor, e.product))
    if not scored:
        return []
    best = max(s for s, _, _ in scored)
    top = {(v, p) for s, v, p in scored if s == best}
    return [ProductMatch(v, p, "dict_fuzzy") for v, p in sorted(top)]
