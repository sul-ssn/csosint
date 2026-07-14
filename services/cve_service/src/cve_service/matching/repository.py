"""Матчинг поверх БД: выборка кандидатов из `cve_cpe_match`, запись `service_cve`
(design-cpe-matching §6, §1).

Матчер синхронный, а БД асинхронная: заранее (по разрешённым `vendor:product`)
выбираем всех кандидатов одним запросом и отдаём матчеру sync-провайдером над
предзагруженным словарём. Это держит ядро тестируемым и без сети.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from csosint_common.models import CveCpeMatch, ServiceCve

from .matcher import Candidate, Match, match_service, resolve_products
from .product_map import DictEntry


async def load_product_index(session: AsyncSession) -> list[DictEntry]:
    """Производный набор продуктов из `cve_cpe_match` (design-nvd-sync §7):
    ровно те `vendor:product`, у которых ВООБЩЕ есть уязвимость."""
    stmt = (
        select(CveCpeMatch.vendor, CveCpeMatch.product)
        .where(CveCpeMatch.vulnerable_bool.is_(True))
        .where(CveCpeMatch.part == "a")
        .distinct()
    )
    rows = await session.execute(stmt)
    return [
        DictEntry(vendor=v, product=p, title=p)
        for v, p in rows.all()
        if v is not None and p is not None
    ]


async def _fetch_candidates(
    session: AsyncSession, pairs: set[tuple[str, str]]
) -> dict[tuple[str, str], list[Candidate]]:
    result: dict[tuple[str, str], list[Candidate]] = {(v, p): [] for v, p in pairs}
    if not pairs:
        return result
    stmt = select(CveCpeMatch).where(
        CveCpeMatch.vulnerable_bool.is_(True),
        CveCpeMatch.part == "a",
    )
    for row in (await session.execute(stmt)).scalars():
        key = (row.vendor, row.product)
        if key not in result:
            continue
        result[key].append(
            Candidate(
                cve_id=row.cve_id,
                cpe_uri=row.cpe_uri,
                version_start=row.version_start,
                version_start_type=row.version_start_type,
                version_end=row.version_end,
                version_end_type=row.version_end_type,
                config_operator=row.config_operator,
                node_operator=row.node_operator,
            )
        )
    return result


async def match_service_row(
    session: AsyncSession,
    service_id: int,
    product: str | None,
    version: str | None,
    cpe_uri: str | None,
) -> list[Match]:
    """Сматчить один сервис и сохранить результат в `service_cve`."""
    # Словарь для фаззи грузим лениво — только если alias/CPE не дали продукта.
    dictionary: list[DictEntry] | None = None
    products = resolve_products(product, cpe_uri, dictionary)
    if not products and product and not cpe_uri:
        dictionary = await load_product_index(session)
        products = resolve_products(product, cpe_uri, dictionary)
    if not products:
        return []

    pairs = {(pm.vendor, pm.product) for pm in products}
    cand_map = await _fetch_candidates(session, pairs)

    def provider(part: str, vendor: str, prod: str) -> list[Candidate]:
        return cand_map.get((vendor, prod), [])

    matches = match_service(product, version, cpe_uri, provider, dictionary=dictionary)
    await _store(session, service_id, matches)
    return matches


async def _store(session: AsyncSession, service_id: int, matches: list[Match]) -> None:
    if not matches:
        return
    stmt = pg_insert(ServiceCve).values(
        [
            {
                "service_id": service_id,
                "cve_id": m.cve_id,
                "match_confidence": m.confidence,
                "matched_cpe": m.matched_cpe,
            }
            for m in matches
        ]
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=[ServiceCve.service_id, ServiceCve.cve_id],
        set_={
            "match_confidence": stmt.excluded.match_confidence,
            "matched_cpe": stmt.excluded.matched_cpe,
        },
    )
    await session.execute(stmt)
