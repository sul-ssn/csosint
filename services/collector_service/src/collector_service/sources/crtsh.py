"""Certificate Transparency — пассивный поиск поддоменов (ТЗ §4.3).

crt.sh (primary) — один Postgres от Sectigo, регулярно отдаёт 502/таймауты →
обязателен фолбэк на certspotter. Результаты дедуплицируются.
"""

from __future__ import annotations

from ..http import SourceError, get_json
from ..types import CollectResult

_CRTSH = "https://crt.sh/"
_CERTSPOTTER = "https://api.certspotter.com/v1/issuances"
SOURCE = "crtsh"


def _clean(name: str, domain: str) -> str | None:
    """Нормализовать имя из сертификата и отфильтровать чужие домены/wildcard."""
    n = name.strip().lower().rstrip(".")
    if n.startswith("*."):
        n = n[2:]
    if not n or n == domain:
        return n or None
    return n if n.endswith("." + domain) else None


def parse_crtsh(domain: str, data: list[dict]) -> set[str]:
    out: set[str] = set()
    for entry in data:
        # name_value может содержать несколько имён через \n.
        for raw in str(entry.get("name_value", "")).splitlines():
            cleaned = _clean(raw, domain)
            if cleaned:
                out.add(cleaned)
        cn = entry.get("common_name")
        if cn and (cleaned := _clean(str(cn), domain)):
            out.add(cleaned)
    return out


def parse_certspotter(domain: str, data: list[dict]) -> set[str]:
    out: set[str] = set()
    for entry in data:
        for raw in entry.get("dns_names", []):
            cleaned = _clean(str(raw), domain)
            if cleaned:
                out.add(cleaned)
    return out


async def collect(result: CollectResult, domain: str, client) -> None:
    """crt.sh → фолбэк certspotter. Наполняет result поддоменами.

    Помечаем деградацию, только если ОБА источника недоступны."""
    domain = domain.lower().rstrip(".")
    try:
        data = await get_json(client, _CRTSH, params={"q": f"%.{domain}", "output": "json"})
        subs = parse_crtsh(domain, data)
        used = SOURCE
    except SourceError:
        data = await get_json(
            client,
            _CERTSPOTTER,
            params={
                "domain": domain,
                "include_subdomains": "true",
                "expand": "dns_names",
            },
        )
        subs = parse_certspotter(domain, data)
        used = "certspotter"
    for sub in subs:
        result.add_subdomain(sub, used)
