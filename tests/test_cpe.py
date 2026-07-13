"""Разбор CPE 2.3 (design-cpe-matching §2)."""

from __future__ import annotations

from cve_service.cpe import parse_cpe


def test_parses_all_fields() -> None:
    cpe = parse_cpe("cpe:2.3:a:openssl:openssl:1.0.1:*:*:*:*:*:*:*")
    assert cpe is not None
    assert (cpe.part, cpe.vendor, cpe.product, cpe.version) == ("a", "openssl", "openssl", "1.0.1")
    assert cpe.has_exact_version is True


def test_wildcard_version_is_not_exact() -> None:
    cpe = parse_cpe("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*")
    assert cpe is not None
    assert cpe.has_exact_version is False


def test_respects_escaped_colon() -> None:
    # Экранированное двоеточие внутри компонента не должно порождать лишнее поле.
    cpe = parse_cpe(r"cpe:2.3:a:vendor:pro\:duct:1.0:*:*:*:*:*:*:*")
    assert cpe is not None
    assert cpe.product == "pro:duct"
    assert cpe.version == "1.0"


def test_rejects_non_cpe() -> None:
    assert parse_cpe("not-a-cpe") is None
    assert parse_cpe("cpe:2.3:a:only:three") is None
    assert parse_cpe("") is None
