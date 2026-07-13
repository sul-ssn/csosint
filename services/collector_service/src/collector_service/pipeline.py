"""Оркестрация пассивного сбора (ТЗ §4, §7).

Собирает по цели (домен/IP/организация) нормализованный `CollectResult`.
Каждый источник обёрнут в guard: падение или отсутствие ключа помечается в
`degraded` и НЕ роняет всю задачу — частичный результат лучше провала (§4).
Прогресс по источникам эмитится через опциональный `progress`-callback (§7).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from .http import SourceError, build_client
from .sources import (
    censys,
    crtsh,
    dns_records,
    internetdb,
    rdap,
    securitytrails,
    shodan,
    virustotal,
)
from .types import CollectResult

# Пределы фанаута, чтобы пассивный сбор оставался ограниченным.
SUBDOMAIN_RESOLVE_CAP = 50
IP_RECON_CAP = 100

ProgressFn = Callable[[dict], Awaitable[None]]


class _Collector:
    def __init__(self, settings, client, resolve, progress: ProgressFn | None) -> None:
        self.settings = settings
        self.client = client
        self.resolve = resolve
        self.progress = progress
        self.result = CollectResult()

    async def _emit(self, **event) -> None:
        if self.progress:
            await self.progress(event)

    async def _guard(self, name: str, coro: Awaitable) -> None:
        try:
            await coro
        except SourceError as exc:
            self.result.mark_degraded(name, f"failed: {exc}")
            await self._emit(event="source", source=name, status="failed", message=str(exc))
        except Exception as exc:  # неожиданное — фиксируем, но не роняем задачу
            self.result.mark_degraded(name, f"error: {type(exc).__name__}: {exc}")
            await self._emit(event="source", source=name, status="failed", message=str(exc))
        else:
            await self._emit(event="source", source=name, status="ok")

    async def _optional(self, module, make_coro: Callable[[], Awaitable]) -> None:
        if not module.is_enabled(self.settings):
            self.result.mark_degraded(module.SOURCE, "skipped: no api key")
            await self._emit(event="source", source=module.SOURCE, status="skipped")
            return
        await self._guard(module.SOURCE, make_coro())

    async def _collect_ip_sources(self, ip: str) -> None:
        await self._guard(internetdb.SOURCE, internetdb.collect(self.result, ip, self.client))
        await self._guard(rdap.SOURCE, rdap.collect_ip(self.result, ip, self.client))
        await self._optional(
            shodan, lambda: shodan.collect(self.result, ip, self.client, self.settings)
        )
        await self._optional(
            censys, lambda: censys.collect(self.result, ip, self.client, self.settings)
        )

    async def _collect_domain(self, domain: str) -> None:
        domain = domain.lower().rstrip(".")
        self.result.add_subdomain(domain, "seed")

        # Поддомены: CT (core) + опциональный пассивный DNS.
        await self._guard(crtsh.SOURCE, crtsh.collect(self.result, domain, self.client))
        await self._optional(
            securitytrails,
            lambda: securitytrails.collect(self.result, domain, self.client, self.settings),
        )
        await self._optional(
            virustotal,
            lambda: virustotal.collect(self.result, domain, self.client, self.settings),
        )

        # Резолвим найденные имена (с ограничением фанаута) → рёбра домен→IP.
        try:
            for name in sorted(self.result.subdomains)[:SUBDOMAIN_RESOLVE_CAP]:
                await dns_records.collect(self.result, name, resolve=self.resolve)
            await self._emit(event="source", source=dns_records.SOURCE, status="ok")
        except Exception as exc:
            self.result.mark_degraded(dns_records.SOURCE, f"error: {exc}")
            await self._emit(event="source", source=dns_records.SOURCE, status="failed")

        # Recon по обнаруженным IP.
        for ip in sorted(self.result.ips)[:IP_RECON_CAP]:
            await self._collect_ip_sources(ip)

    async def run(self, target: str, target_type: str) -> CollectResult:
        if target_type == "domain":
            await self._collect_domain(target)
        elif target_type == "ip":
            await self._collect_ip_sources(target)
        else:  # org: пассивный маппинг «организация → домены» вне скоупа v1
            self.result.mark_degraded("org", "skipped: org→domain discovery out of v1 scope")
            await self._emit(event="source", source="org", status="skipped")
        return self.result


async def collect(
    target: str,
    target_type: str,
    settings,
    *,
    client=None,
    resolve=None,
    progress: ProgressFn | None = None,
) -> CollectResult:
    owns_client = client is None
    client = client or build_client()
    try:
        return await _Collector(settings, client, resolve, progress).run(target, target_type)
    finally:
        if owns_client:
            await client.aclose()
