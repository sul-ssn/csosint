"""Мини-конвертер CPE 2.2 URI → 2.3 formatted-string.

InternetDB отдаёт CPE в старом формате `cpe:/a:vendor:product:version`, а матчинг
cve-service ждёт `cpe:2.3:...`. Приводим здесь при сборе, чтобы в БД лёг 2.3.
"""

from __future__ import annotations

# 2.3 имеет 11 полей; 2.2 URI — до 7 (part..language). Остальное добиваем `*`.
_TOTAL_23_FIELDS = 11


def cpe22_to_23(uri: str) -> str | None:
    """`cpe:/a:apache:http_server:2.4.41` → `cpe:2.3:a:apache:http_server:2.4.41:*:...`.
    Уже-2.3 возвращаем как есть; мусор → None."""
    if not uri:
        return None
    if uri.startswith("cpe:2.3:"):
        return uri
    if not uri.startswith("cpe:/"):
        return None
    fields = uri[len("cpe:/") :].split(":")
    # Пустые компоненты 2.2 означают ANY → `*`; добиваем до 11 полей.
    vals = [f or "*" for f in fields]
    vals += ["*"] * (_TOTAL_23_FIELDS - len(vals))
    return "cpe:2.3:" + ":".join(vals[:_TOTAL_23_FIELDS])
