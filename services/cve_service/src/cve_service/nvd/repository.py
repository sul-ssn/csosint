"""SQL-реализация SyncRepo поверх async SQLAlchemy (design-nvd-sync §8).

Идемпотентность: cve_records — upsert `ON CONFLICT (cve_id)`; cve_cpe_match —
полная пересборка на CVE (`DELETE ... ; INSERT ...`) в одной транзакции, чтобы
изменённая конфигурация не оставляла «залипших» старых строк.
"""

from __future__ import annotations

from sqlalchemy import delete, insert
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from csosint_common.models import CveCpeMatch, CveRecord, SyncState

from .parser import ParsedCve
from .sync import SOURCE, SyncStateData

_RECORD_UPDATE_COLS = (
    "description",
    "published",
    "modified",
    "cvss_version",
    "cvss_score",
    "cvss_vector",
    "severity",
    "raw",
)


class SqlSyncRepo:
    def __init__(self, sessionmaker: async_sessionmaker[AsyncSession]) -> None:
        self._sm = sessionmaker

    async def load_state(self) -> SyncStateData | None:
        async with self._sm() as session:
            row = await session.get(SyncState, SOURCE)
            if row is None:
                return None
            return SyncStateData(
                phase=row.phase,
                last_mod_cursor=row.last_mod_cursor,
                bootstrap_index=row.bootstrap_index,
                status=row.status,
                last_run_at=row.last_run_at,
                last_error=row.last_error,
            )

    async def apply_page(self, parsed: list[ParsedCve], state_updates: dict) -> None:
        async with self._sm() as session, session.begin():
            await self._upsert_records(session, parsed)
            for pc in parsed:
                await self._replace_matches(session, pc)
            await self._upsert_state(session, state_updates)

    async def save_state(self, state_updates: dict) -> None:
        async with self._sm() as session, session.begin():
            await self._upsert_state(session, state_updates)

    async def _upsert_records(self, session: AsyncSession, parsed: list[ParsedCve]) -> None:
        if not parsed:
            return
        values = [
            {
                "cve_id": pc.record.cve_id,
                "description": pc.record.description,
                "published": pc.record.published,
                "modified": pc.record.modified,
                "cvss_version": pc.record.cvss_version,
                "cvss_score": pc.record.cvss_score,
                "cvss_vector": pc.record.cvss_vector,
                "severity": pc.record.severity,
                "raw": pc.record.raw,
            }
            for pc in parsed
        ]
        stmt = pg_insert(CveRecord).values(values)
        stmt = stmt.on_conflict_do_update(
            index_elements=[CveRecord.cve_id],
            set_={col: getattr(stmt.excluded, col) for col in _RECORD_UPDATE_COLS},
        )
        await session.execute(stmt)

    async def _replace_matches(self, session: AsyncSession, pc: ParsedCve) -> None:
        await session.execute(delete(CveCpeMatch).where(CveCpeMatch.cve_id == pc.record.cve_id))
        if not pc.matches:
            return
        await session.execute(
            insert(CveCpeMatch),
            [
                {
                    "cve_id": pc.record.cve_id,
                    "cpe_uri": m.cpe_uri,
                    "vendor": m.vendor,
                    "product": m.product,
                    "part": m.part,
                    "vulnerable_bool": m.vulnerable_bool,
                    "config_idx": m.config_idx,
                    "node_idx": m.node_idx,
                    "config_operator": m.config_operator,
                    "node_operator": m.node_operator,
                    "version_start": m.version_start,
                    "version_start_type": m.version_start_type,
                    "version_end": m.version_end,
                    "version_end_type": m.version_end_type,
                }
                for m in pc.matches
            ],
        )

    async def _upsert_state(self, session: AsyncSession, updates: dict) -> None:
        stmt = pg_insert(SyncState).values(source=SOURCE, **updates)
        stmt = stmt.on_conflict_do_update(index_elements=[SyncState.source], set_=dict(updates))
        await session.execute(stmt)
