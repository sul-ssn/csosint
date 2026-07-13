"""Оркестрация пассивного сбора (ТЗ §4, §7).

Собирает по цели (домен/IP/организация) нормализованный `CollectResult`.
Каждый источник обёрнут в guard: падение или отсутствие ключа помечается в
`degraded` и НЕ роняет всю задачу — частичный результат лучше провала (§4).
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


async def _guard(result: CollectResult, name: str, coro: Awaitable) -> None:
    try:
        await coro
    except SourceError as exc:
        result.mark_degraded(name, f"failed: {exc}")
    except Exception as exc:  # неожиданное — фиксируем, но не роняем задачу
        result.mark_degraded(name, f"error: {type(exc).__name__}: {exc}")


async def _optional(
    result: CollectResult, module, settings, make_coro: Callable[[], Awaitable]
) -> None:
    if not module.is_enabled(settings):
        result.mark_degraded(module.SOURCE, "skipped: no api key")
        return
    await _guard(result, module.SOURCE, make_coro())


async def _collect_ip_sources(result: CollectResult, ip: str, settings, client) -> None:
    await _guard(result, internetdb.SOURCE, internetdb.collect(result, ip, client))
    await _guard(result, rdap.SOURCE, rdap.collect_ip(result, ip, client))
    await _optional(result, shodan, settings, lambda: shodan.collect(result, ip, client, settings))
    await _optional(result, censys, settings, lambda: censys.collect(result, ip, client, settings))


async def _collect_domain(result, domain, settings, client, resolve) -> None:
    domain = domain.lower().rstrip(".")
    result.add_subdomain(domain, "seed")

    # Поддомены: CT (core) + опциональный пассивный DNS.
    await _guard(result, crtsh.SOURCE, crtsh.collect(result, domain, client))
    await _optional(
        result,
        securitytrails,
        settings,
        lambda: securitytrails.collect(result, domain, client, settings),
    )
    await _optional(
        result,
        virustotal,
        settings,
        lambda: virustotal.collect(result, domain, client, settings),
    )

    # Резолвим найденные имена (с ограничением фанаута) → рёбра домен→IP.
    for name in sorted(result.subdomains)[:SUBDOMAIN_RESOLVE_CAP]:
        await _guard(result, dns_records.SOURCE, dns_records.collect(result, name, resolve=resolve))

    # Recon по обнаруженным IP.
    for ip in sorted(result.ips)[:IP_RECON_CAP]:
        await _collect_ip_sources(result, ip, settings, client)


async def collect(
    target: str,
    target_type: str,
    settings,
    *,
    client=None,
    resolve=None,
) -> CollectResult:
    result = CollectResult()
    owns_client = client is None
    client = client or build_client()
    try:
        if target_type == "domain":
            await _collect_domain(result, target, settings, client, resolve)
        elif target_type == "ip":
            await _collect_ip_sources(result, target, settings, client)
        else:  # org
            # Пассивный маппинг «организация → домены» вне скоупа v1 (нет core-источника).
            result.mark_degraded("org", "skipped: org→domain discovery out of v1 scope")
    finally:
        if owns_client:
            await client.aclose()
    return result
