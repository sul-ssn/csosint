"""Оркестрация синка NVD: bootstrap + инкремент (design-nvd-sync §2, §8, §10).

Чистая логика пагинации, резюмируемости и продвижения курсора вынесена за
интерфейс `SyncRepo`, поэтому тестируется на фейковом репозитории/клиенте —
без сети и Postgres. SQL-реализация репозитория — в `repository.py`.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol

from .parser import ParsedCve, parse_cve

SOURCE = "nvd_cve"
# Запас назад от прошлого курсора — защита от гонки «CVE изменилась между
# чтением и записью» (design-nvd-sync §3). Дубликаты гасит идемпотентный upsert.
OVERLAP = timedelta(minutes=5)
# NVD ограничивает окно lastMod диапазоном 120 дней (§1) — бьём инкремент на под-окна.
MAX_WINDOW = timedelta(days=120)


@dataclass(slots=True)
class SyncStateData:
    phase: str | None = None
    last_mod_cursor: datetime | None = None
    bootstrap_index: int | None = None
    status: str | None = None
    last_run_at: datetime | None = None
    last_error: str | None = None


class SyncRepo(Protocol):
    async def load_state(self) -> SyncStateData | None: ...

    async def apply_page(self, parsed: list[ParsedCve], state_updates: dict) -> None:
        """Одной транзакцией: upsert cve_records + пересборка cve_cpe_match +
        обновление sync_state. Гранулярность коммита — страница (§8)."""

    async def save_state(self, state_updates: dict) -> None:
        """Отдельный апдейт sync_state (финализация окна/фаз)."""


class NvdSyncer:
    def __init__(
        self,
        client,
        repo: SyncRepo,
        *,
        page_size: int = 2000,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._client = client
        self._repo = repo
        self._page_size = page_size
        self._now = now or (lambda: datetime.now(UTC))

    async def run(self) -> dict:
        state = await self._repo.load_state()
        if state is None or state.phase == "bootstrap":
            return await self._bootstrap(state)
        return await self._incremental(state)

    async def _drain(
        self,
        fetch: Callable[[int], Awaitable[dict]],
        on_page: Callable[[list[ParsedCve], int], Awaitable[None]],
    ) -> int:
        """Пройти пагинацию до конца. `fetch(start_index)` → страница;
        `on_page(parsed, next_index)` персистит её. Возвращает число CVE."""
        idx = 0
        total: int | None = None
        seen = 0
        while total is None or idx < total:
            page = await fetch(idx)
            total = page["totalResults"]
            items = page.get("vulnerabilities", [])
            returned = len(items)
            if returned == 0:
                break
            parsed = [parse_cve(item) for item in items]
            idx += returned
            seen += returned
            await on_page(parsed, idx)
        return seen

    async def _bootstrap(self, state: SyncStateData | None) -> dict:
        start_idx = (state.bootstrap_index if state else None) or 0

        async def fetch(idx: int) -> dict:
            return await self._client.fetch_cves(
                start_index=start_idx + idx, results_per_page=self._page_size
            )

        async def on_page(parsed: list[ParsedCve], next_index: int) -> None:
            await self._repo.apply_page(
                parsed,
                {
                    "phase": "bootstrap",
                    "status": "running",
                    "bootstrap_index": start_idx + next_index,
                    "last_run_at": self._now(),
                },
            )

        seen = await self._drain(fetch, on_page)
        # Bootstrap завершён → переходим в инкрементальную фазу, курсор = now.
        await self._repo.save_state(
            {
                "phase": "incremental",
                "status": "idle",
                "bootstrap_index": None,
                "last_mod_cursor": self._now(),
                "last_run_at": self._now(),
            }
        )
        return {"phase": "bootstrap", "processed": seen}

    def _windows(self, start: datetime, end: datetime) -> list[tuple[datetime, datetime]]:
        out: list[tuple[datetime, datetime]] = []
        cur = start
        while cur < end:
            nxt = min(cur + MAX_WINDOW, end)
            out.append((cur, nxt))
            cur = nxt
        return out

    async def _incremental(self, state: SyncStateData) -> dict:
        cursor = state.last_mod_cursor or self._now()
        start = cursor - OVERLAP
        end = self._now()
        seen = 0
        for win_start, win_end in self._windows(start, end):

            async def fetch(idx: int, _s=win_start, _e=win_end) -> dict:
                return await self._client.fetch_cves(
                    start_index=idx,
                    results_per_page=self._page_size,
                    last_mod_start=_s,
                    last_mod_end=_e,
                )

            async def on_page(parsed: list[ParsedCve], next_index: int) -> None:
                # Курсор НЕ двигаем здесь — только после полного успеха всех окон.
                await self._repo.apply_page(
                    parsed, {"status": "running", "last_run_at": self._now()}
                )

            seen += await self._drain(fetch, on_page)

        # Курсор продвигаем ТОЛЬКО в самом конце — иначе сбой посреди окна даст дыру.
        await self._repo.save_state(
            {
                "phase": "incremental",
                "status": "idle",
                "last_mod_cursor": end,
                "last_run_at": self._now(),
            }
        )
        return {"phase": "incremental", "processed": seen}
