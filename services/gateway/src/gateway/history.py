"""История поверхности атаки: сравнение immutable snapshots последовательных сканов."""

from __future__ import annotations

from collections import Counter

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from csosint_common.models import ScanJob, ScanSnapshot


def compare_snapshots(current: list, previous: list) -> dict:
    """Сравнить два набора snapshot-строк. Работает с ORM и простыми объектами."""
    cur = {(row.entity_type, row.entity_key): row for row in current}
    prev = {(row.entity_type, row.entity_key): row for row in previous}
    added_keys = sorted(cur.keys() - prev.keys())
    removed_keys = sorted(prev.keys() - cur.keys())
    shared = cur.keys() & prev.keys()
    changed_keys = sorted(key for key in shared if cur[key].fingerprint != prev[key].fingerprint)

    changes: list[dict] = []
    for status, keys, source in (
        ("added", added_keys, cur),
        ("removed", removed_keys, prev),
    ):
        changes.extend(
            {
                "status": status,
                "entity_type": key[0],
                "entity_key": key[1],
                "before": source[key].details if status == "removed" else None,
                "after": source[key].details if status == "added" else None,
                "changed_fields": [],
            }
            for key in keys
        )
    for key in changed_keys:
        before, after = prev[key].details, cur[key].details
        fields = sorted(
            field for field in before.keys() | after.keys() if before.get(field) != after.get(field)
        )
        changes.append(
            {
                "status": "changed",
                "entity_type": key[0],
                "entity_key": key[1],
                "before": before,
                "after": after,
                "changed_fields": fields,
            }
        )
    order = {"added": 0, "changed": 1, "removed": 2}
    changes.sort(key=lambda item: (order[item["status"]], item["entity_type"], item["entity_key"]))
    by_type = Counter(item["entity_type"] for item in changes)
    return {
        "summary": {
            "added": len(added_keys),
            "changed": len(changed_keys),
            "removed": len(removed_keys),
            "total": len(changes),
            "by_type": dict(sorted(by_type.items())),
        },
        "changes": changes,
    }


async def build_history(session: AsyncSession, job: ScanJob) -> dict:
    current = (
        await session.execute(
            select(ScanSnapshot).where(ScanSnapshot.job_id == job.id)
        )
    ).scalars().all()
    previous_job = (
        await session.execute(
            select(ScanJob)
            .where(
                ScanJob.target == job.target,
                ScanJob.type == job.type,
                ScanJob.status == "done",
                ScanJob.id < job.id,
            )
            .order_by(ScanJob.id.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if previous_job is None:
        return {
            "baseline": False,
            "reliable": True,
            "suppressed_removed": 0,
            "previous_job": None,
            "summary": {"added": 0, "changed": 0, "removed": 0, "total": 0, "by_type": {}},
            "changes": [],
        }
    previous = (
        await session.execute(
            select(ScanSnapshot).where(ScanSnapshot.job_id == previous_job.id)
        )
    ).scalars().all()
    comparison = compare_snapshots(list(current), list(previous))
    unreliable_sources = {
        source: reason
        for source, reason in (job.degraded_sources or {}).items()
        if not str(reason).startswith("skipped:")
    }
    suppressed_removed = 0
    if unreliable_sources:
        suppressed_removed = comparison["summary"]["removed"]
        comparison["changes"] = [
            item for item in comparison["changes"] if item["status"] != "removed"
        ]
        counts = Counter(item["entity_type"] for item in comparison["changes"])
        comparison["summary"]["removed"] = 0
        comparison["summary"]["total"] = len(comparison["changes"])
        comparison["summary"]["by_type"] = dict(sorted(counts.items()))
    return {
        "baseline": True,
        "reliable": not unreliable_sources,
        "suppressed_removed": suppressed_removed,
        "previous_job": {
            "id": previous_job.id,
            "created_at": previous_job.created_at,
            "finished_at": previous_job.finished_at,
        },
        **comparison,
    }
