"""Обогащение локальных CVE сигналами эксплуатации FIRST EPSS и CISA KEV."""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import async_sessionmaker
from tenacity import AsyncRetrying, retry_if_exception_type, stop_after_attempt, wait_exponential

from csosint_common.models import CveRecord

EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# FIRST ограничивает cve-параметр 2000 символами; 80 современных CVE помещаются с запасом.
EPSS_BATCH_SIZE = 80


async def _get_json(client: httpx.AsyncClient, url: str, **kwargs) -> dict:
    async for attempt in AsyncRetrying(
        stop=stop_after_attempt(4),
        wait=wait_exponential(multiplier=1, max=20),
        retry=retry_if_exception_type((httpx.TransportError, httpx.HTTPStatusError)),
        reraise=True,
    ):
        with attempt:
            response = await client.get(url, **kwargs)
            response.raise_for_status()
            return response.json()
    raise RuntimeError(f"failed to fetch {url}")  # pragma: no cover


def _date(value: str | None) -> datetime | None:
    return datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=UTC) if value else None


def parse_epss(payload: dict) -> list[dict]:
    return [
        {
            "cve_id": item["cve"],
            "epss_score": float(item["epss"]),
            "epss_percentile": float(item["percentile"]),
            "epss_date": _date(item.get("date")),
        }
        for item in payload.get("data", [])
        if item.get("cve") and item.get("epss") is not None
    ]


def parse_kev(payload: dict) -> list[dict]:
    return [
        {
            "cve_id": item["cveID"],
            "kev": True,
            "kev_date_added": _date(item.get("dateAdded")),
            "kev_due_date": _date(item.get("dueDate")),
            "kev_required_action": item.get("requiredAction"),
            "kev_ransomware_use": item.get("knownRansomwareCampaignUse"),
        }
        for item in payload.get("vulnerabilities", [])
        if item.get("cveID")
    ]


async def sync_threat_intel(sessionmaker: async_sessionmaker, *, client=None) -> dict:
    owns_client = client is None
    client = client or httpx.AsyncClient(timeout=30, follow_redirects=True)
    try:
        async with sessionmaker() as session:
            cve_ids = list((await session.scalars(select(CveRecord.cve_id))).all())

        epss_rows: list[dict] = []
        for start in range(0, len(cve_ids), EPSS_BATCH_SIZE):
            batch = cve_ids[start : start + EPSS_BATCH_SIZE]
            payload = await _get_json(
                client, EPSS_URL, params={"cve": ",".join(batch), "limit": 100}
            )
            epss_rows.extend(parse_epss(payload))

        kev_rows = parse_kev(await _get_json(client, KEV_URL))

        async with sessionmaker() as session, session.begin():
            # KEV — полный authoritative feed: сначала снимаем старые флаги.
            await session.execute(
                update(CveRecord).values(
                    kev=False,
                    kev_date_added=None,
                    kev_due_date=None,
                    kev_required_action=None,
                    kev_ransomware_use=None,
                )
            )
            for row in epss_rows:
                cve_id = row.pop("cve_id")
                await session.execute(
                    update(CveRecord).where(CveRecord.cve_id == cve_id).values(**row)
                )
            for row in kev_rows:
                cve_id = row.pop("cve_id")
                await session.execute(
                    update(CveRecord).where(CveRecord.cve_id == cve_id).values(**row)
                )
        return {"status": "done", "epss_updated": len(epss_rows), "kev_feed": len(kev_rows)}
    finally:
        if owns_client:
            await client.aclose()
