"""SSRF-guard и валидация ввода (ТЗ §11).

Инструмент принимает произвольный `target` от пользователя — это делает его самого
мишенью. Блокируем приватные/служебные адреса (в т.ч. cloud-metadata 169.254.169.254)
и валидируем формат домена. Проверка IP — на ФАКТИЧЕСКОМ адресе после DNS-резолва
(защита от DNS rebinding, §11.1).
"""

from __future__ import annotations

import ipaddress
import re

# Домен: 1..253 символа, метки 1..63 из [A-Za-z0-9-] без ведущего/хвостового дефиса,
# минимум два уровня (есть точка).
_DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")


def is_valid_domain(value: str) -> bool:
    v = value.strip().rstrip(".")
    return 1 <= len(v) <= 253 and bool(_DOMAIN_RE.match(v))


def is_public_ip(value: str) -> bool:
    """True только для публичного маршрутизируемого IP. Блокируем loopback,
    RFC1918, link-local (169.254/16, fe80::/10, cloud-metadata), ULA (fc00::/7),
    multicast, reserved и unspecified (§11.1)."""
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )
