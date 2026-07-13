"""Оркестрация синка: пагинация, резюмируемость, дисциплина курсора
(design-nvd-sync §3, §8, §10, §12). Без сети и Postgres — фейковые клиент/репо.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cve_service.nvd.sync import MAX_WINDOW, NvdSyncer, SyncStateData

_NOW = datetime(2026, 7, 13, tzinfo=UTC)


class FakeClient:
    """Отдаёт `total` синтетических CVE постранично; пишет историю вызовов."""

    def __init__(self, total: int, page_size: int) -> None:
        self.total = total
        self.page_size = page_size
        self.calls: list[dict] = []

    async def fetch_cves(
        self, *, start_index=0, results_per_page=2000, last_mod_start=None, last_mod_end=None
    ) -> dict:
        self.calls.append(
            {"start_index": start_index, "start": last_mod_start, "end": last_mod_end}
        )
        items = [
            {"cve": {"id": f"CVE-{i:04d}", "descriptions": []}}
            for i in range(start_index, min(start_index + self.page_size, self.total))
        ]
        return {
            "totalResults": self.total,
            "resultsPerPage": len(items),
            "vulnerabilities": items,
        }


class FakeRepo:
    def __init__(self, state: SyncStateData | None = None) -> None:
        self.state = state
        self.applied: list[str] = []  # cve_id в порядке обработки
        self.page_updates: list[dict] = []
        self.saved: list[dict] = []

    async def load_state(self) -> SyncStateData | None:
        return self.state

    async def apply_page(self, parsed, state_updates: dict) -> None:
        self.applied.extend(pc.record.cve_id for pc in parsed)
        self.page_updates.append(state_updates)
        self._merge(state_updates)

    async def save_state(self, state_updates: dict) -> None:
        self.saved.append(state_updates)
        self._merge(state_updates)

    def _merge(self, updates: dict) -> None:
        if self.state is None:
            self.state = SyncStateData()
        for k, v in updates.items():
            setattr(self.state, k, v)


async def test_bootstrap_paginates_all_and_finalizes() -> None:
    client = FakeClient(total=5, page_size=2)
    repo = FakeRepo(state=None)
    syncer = NvdSyncer(client, repo, page_size=2, now=lambda: _NOW)

    result = await syncer.run()

    assert result == {"phase": "bootstrap", "processed": 5}
    assert repo.applied == [f"CVE-{i:04d}" for i in range(5)]
    # bootstrap_index рос по мере коммита страниц.
    assert [u["bootstrap_index"] for u in repo.page_updates] == [2, 4, 5]
    # Финализация: перешли в инкремент, курсор выставлен, индекс сброшен.
    assert repo.saved[-1]["phase"] == "incremental"
    assert repo.saved[-1]["bootstrap_index"] is None
    assert repo.saved[-1]["last_mod_cursor"] == _NOW


async def test_bootstrap_resumes_from_index() -> None:
    client = FakeClient(total=5, page_size=2)
    repo = FakeRepo(state=SyncStateData(phase="bootstrap", bootstrap_index=2))
    syncer = NvdSyncer(client, repo, page_size=2, now=lambda: _NOW)

    result = await syncer.run()

    # Продолжили с индекса 2 → обработаны только CVE-0002..0004.
    assert result["processed"] == 3
    assert repo.applied == ["CVE-0002", "CVE-0003", "CVE-0004"]
    assert client.calls[0]["start_index"] == 2


async def test_incremental_advances_cursor_only_at_end() -> None:
    client = FakeClient(total=3, page_size=2)
    cursor = _NOW - timedelta(days=1)
    repo = FakeRepo(state=SyncStateData(phase="incremental", last_mod_cursor=cursor))
    syncer = NvdSyncer(client, repo, page_size=2, now=lambda: _NOW)

    result = await syncer.run()

    assert result["phase"] == "incremental"
    # Курсор НЕ двигали на страницах — только финальным save_state.
    assert all("last_mod_cursor" not in u for u in repo.page_updates)
    assert repo.saved[-1]["last_mod_cursor"] == _NOW


async def test_incremental_splits_windows_over_120_days() -> None:
    client = FakeClient(total=0, page_size=2000)
    cursor = _NOW - timedelta(days=200)  # шире 120-дневного лимита NVD
    repo = FakeRepo(state=SyncStateData(phase="incremental", last_mod_cursor=cursor))
    syncer = NvdSyncer(client, repo, page_size=2000, now=lambda: _NOW)

    await syncer.run()

    windows = {(c["start"], c["end"]) for c in client.calls}
    assert len(windows) == 2  # 200 дней → два под-окна (<=120 каждое)
    for start, end in windows:
        assert end - start <= MAX_WINDOW
