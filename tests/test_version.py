"""Извлечение и сравнение версий (design-cpe-matching §5, §7, §11)."""

from __future__ import annotations

import pytest

from cve_service.matching.version import extract_core, in_range, normalize, ver_eq


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("2.4.41 (Ubuntu)", "2.4.41"),  # дистро-скобки отбрасываем
        ("1.0.2k-fips", "1.0.2k"),  # значимый буквенный суффикс сохраняем
        ("OpenSSH_8.2p1", "8.2p1"),  # версия из баннера + суффикс p1
        ("1.4.6+deb10u1", "1.4.6"),  # build-метаданные отбрасываем
        ("nginx/1.20.0", "1.20.0"),
        ("2.4.41", "2.4.41"),
        ("no version here", None),
    ],
)
def test_extract_core(raw: str, expected: str | None) -> None:
    assert extract_core(raw) == expected


def test_extract_core_none() -> None:
    assert extract_core(None) is None
    assert extract_core("") is None


def test_letter_versions_order() -> None:
    # Буквенные версии OpenSSL — обязателен univers, не int-tuple.
    assert normalize("1.0.2k") < normalize("1.0.2l")


def test_ver_eq() -> None:
    assert ver_eq(normalize("1.0.1"), "1.0.1") is True
    assert ver_eq(normalize("1.0.1"), "1.0.2") is False


def test_in_range_boundaries() -> None:
    v = normalize("1.0.1f")
    # >=1.0.1 including .. <=1.0.1f including → включительно верхняя граница
    assert in_range(v, "1.0.1", "including", "1.0.1f", "including") is True
    # <1.0.1f excluding → сам 1.0.1f уже вне
    assert in_range(v, "1.0.1", "including", "1.0.1f", "excluding") is False


def test_in_range_start_excluding() -> None:
    v = normalize("1.0.1")
    assert in_range(v, "1.0.1", "excluding", None, None) is False
    assert in_range(v, "1.0.1", "including", None, None) is True


def test_in_range_unbounded_sides() -> None:
    v = normalize("2.4.41")
    assert in_range(v, None, None, "2.4.52", "excluding") is True
    assert in_range(v, "2.4.0", "including", None, None) is True


def test_in_range_unparseable_bound_is_conservative() -> None:
    # Заданная, но нераспознаваемая граница → консервативно не подтверждаем (False),
    # а не «пропускаем» — точность важнее полноты (§13).
    v = normalize("2.4.41")
    assert in_range(v, None, None, "", "excluding") is False
