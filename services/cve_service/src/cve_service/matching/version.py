"""Извлечение и сравнение версий (design-cpe-matching §5, §7).

`version` от источников замусорен (`2.4.41 (Ubuntu)`, `1.0.2k-fips`,
`OpenSSH_8.2p1`). Достаём ядро версии, сохраняя значимый суффикс (`p1`, `k`),
и сравниваем библиотекой `univers.GenericVersion` — НЕ int-tuple и НЕ PEP 440,
которые ломаются на не-Python версиях.
"""

from __future__ import annotations

import re

from univers.versions import GenericVersion

# Ядро версии: числа с точками + опциональный буквенный суффикс (`k`, `p1`, `rc1`).
# Дистро-хвосты (`-fips`, `+deb10u1`, ` (Ubuntu)`) остаются за границей совпадения.
_VERSION_RE = re.compile(r"\d+(?:\.\d+)*(?:[a-z]+\d*)?", re.IGNORECASE)


def extract_core(raw: str | None) -> str | None:
    """Выдрать ядро версии из свободного текста. None, если версии нет."""
    if not raw:
        return None
    # Отбрасываем дистро-скобки до поиска: "2.4.41 (Ubuntu)" → "2.4.41 ".
    cleaned = raw.split("(", 1)[0]
    m = _VERSION_RE.search(cleaned)
    return m.group(0) if m else None


def _to_generic(value: str | None) -> GenericVersion | None:
    if not value:
        return None
    try:
        return GenericVersion(value)
    except Exception:
        return None


def normalize(raw: str | None) -> GenericVersion | None:
    """Свободный текст → GenericVersion. None, если распарсить не удалось."""
    return _to_generic(extract_core(raw))


def ver_eq(observed: GenericVersion, criteria_version: str) -> bool:
    """Точное равенство наблюдаемой версии и версии, зашитой в CPE."""
    other = _to_generic(criteria_version)
    if other is None:
        return False
    try:
        return observed == other
    except Exception:
        return False


def in_range(
    observed: GenericVersion,
    version_start: str | None,
    version_start_type: str | None,
    version_end: str | None,
    version_end_type: str | None,
) -> bool:
    """Попадает ли `observed` в интервал границ (including|excluding).

    Отсутствующая граница не ограничивает. Неразбираемая граница трактуется
    консервативно как «не подтверждено» → False (точность важнее полноты, §13).
    """
    if version_start is not None:
        start = _to_generic(version_start)
        if start is None:
            return False
        try:
            ok = observed >= start if version_start_type == "including" else observed > start
        except Exception:
            return False
        if not ok:
            return False
    if version_end is not None:
        end = _to_generic(version_end)
        if end is None:
            return False
        try:
            ok = observed <= end if version_end_type == "including" else observed < end
        except Exception:
            return False
        if not ok:
            return False
    return True
