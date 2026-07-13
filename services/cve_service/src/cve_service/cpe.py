"""Разбор CPE 2.3-строк — общий для синка NVD и матчинга (design-cpe-matching §2).

Формат formatted-string (11 полей после `cpe:2.3:`):

    cpe:2.3: part : vendor : product : version : update : edition : language
           : sw_edition : target_sw : target_hw : other

Спецсимволы внутри компонента экранируются бэкслэшем (`\\:`, `\\.`), поэтому
наивный `split(":")` неверен — режем только по неэкранированным двоеточиям.
"""

from __future__ import annotations

from dataclasses import dataclass

_FIELDS = (
    "part",
    "vendor",
    "product",
    "version",
    "update",
    "edition",
    "language",
    "sw_edition",
    "target_sw",
    "target_hw",
    "other",
)


@dataclass(frozen=True, slots=True)
class Cpe:
    """Разобранный CPE 2.3. `*` = ANY, `-` = N/A (сохраняем как есть)."""

    part: str
    vendor: str
    product: str
    version: str
    update: str
    edition: str
    language: str
    sw_edition: str
    target_sw: str
    target_hw: str
    other: str
    raw: str

    @property
    def has_exact_version(self) -> bool:
        """Версия зашита в самом CPE (не wildcard)."""
        return self.version not in ("*", "-", "")


def _split_unescaped(text: str) -> list[str]:
    """Split по `:`, игнорируя экранированные `\\:`."""
    parts: list[str] = []
    buf: list[str] = []
    escaped = False
    for ch in text:
        if escaped:
            buf.append(ch)
            escaped = False
        elif ch == "\\":
            buf.append(ch)
            escaped = True
        elif ch == ":":
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    parts.append("".join(buf))
    return parts


def _unescape(value: str) -> str:
    """Снять CPE-экранирование (`\\.` → `.`), не трогая `*`/`-`."""
    out: list[str] = []
    escaped = False
    for ch in value:
        if escaped:
            out.append(ch)
            escaped = False
        elif ch == "\\":
            escaped = True
        else:
            out.append(ch)
    if escaped:  # висячий бэкслэш — сохраняем буквально
        out.append("\\")
    return "".join(out)


def parse_cpe(uri: str) -> Cpe | None:
    """Разобрать `cpe:2.3:...`. Вернуть None, если это не валидный CPE 2.3."""
    if not uri or not uri.startswith("cpe:2.3:"):
        return None
    comps = _split_unescaped(uri)
    # cpe : 2.3 : + 11 полей = 13 компонентов
    if len(comps) != 13:
        return None
    values = [_unescape(c) for c in comps[2:]]
    return Cpe(**dict(zip(_FIELDS, values, strict=True)), raw=uri)
