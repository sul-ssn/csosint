"""Certificate Transparency — пассивный поиск поддоменов.

crt.sh (primary) — один Postgres от Sectigo, регулярно отдаёт 502/таймауты →
обязателен фолбэк на certspotter. Результаты дедуплицируются.
"""

from __future__ import annotations

from ..http import SourceError, get_json
from ..types import CertificateObservation, CollectResult

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


def parse_crtsh_certificates(domain: str, data: list[dict]) -> list[CertificateObservation]:
    certs: dict[str, CertificateObservation] = {}
    for entry in data:
        names = {
            cleaned
            for raw in str(entry.get("name_value", "")).splitlines()
            if (cleaned := _clean(raw, domain))
        }
        if cn := entry.get("common_name"):
            if cleaned := _clean(str(cn), domain):
                names.add(cleaned)
        identity = entry.get("serial_number") or entry.get("id")
        if not identity or not names:
            continue
        fingerprint = f"crtsh:{identity}"
        certs[fingerprint] = CertificateObservation(
            fingerprint=fingerprint,
            names=sorted(names),
            source=SOURCE,
            issuer=entry.get("issuer_name"),
            not_before=entry.get("not_before"),
            not_after=entry.get("not_after"),
        )
    return list(certs.values())


def parse_certspotter_certificates(
    domain: str, data: list[dict]
) -> list[CertificateObservation]:
    certs: list[CertificateObservation] = []
    for entry in data:
        names = sorted(
            {
                cleaned
                for raw in entry.get("dns_names", [])
                if (cleaned := _clean(str(raw), domain))
            }
        )
        identity = entry.get("id") or entry.get("tbs_sha256")
        if identity and names:
            certs.append(
                CertificateObservation(
                    fingerprint=f"certspotter:{identity}",
                    names=names,
                    source="certspotter",
                    issuer=(entry.get("issuer") or {}).get("name")
                    if isinstance(entry.get("issuer"), dict)
                    else None,
                    not_before=entry.get("not_before"),
                    not_after=entry.get("not_after"),
                )
            )
    return certs


async def collect(result: CollectResult, domain: str, client) -> None:
    """crt.sh → фолбэк certspotter. Наполняет result поддоменами.

    Помечаем деградацию, только если ОБА источника недоступны."""
    domain = domain.lower().rstrip(".")
    try:
        data = await get_json(client, _CRTSH, params={"q": f"%.{domain}", "output": "json"})
        subs = parse_crtsh(domain, data)
        certs = parse_crtsh_certificates(domain, data)
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
        certs = parse_certspotter_certificates(domain, data)
        used = "certspotter"
    for sub in subs:
        result.add_subdomain(sub, used)
    for cert in certs:
        result.add_certificate(cert)
