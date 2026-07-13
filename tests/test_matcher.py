"""Золотые кейсы матчинга сервис→CVE (design-cpe-matching §7–§12)."""

from __future__ import annotations

from cve_service.matching.matcher import Candidate, match_service
from cve_service.matching.product_map import DictEntry, map_product_to_cpe


def _provider(rows_by_vp: dict[tuple[str, str], list[Candidate]]):
    def provider(part: str, vendor: str, product: str) -> list[Candidate]:
        return rows_by_vp.get((vendor, product), [])

    return provider


HEARTBLEED = Candidate(
    cve_id="CVE-2014-0160",
    cpe_uri="cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
    version_start="1.0.1",
    version_start_type="including",
    version_end="1.0.1f",
    version_end_type="including",
    node_operator="OR",
)


def test_heartbleed_in_range_high_confidence() -> None:
    prov = _provider({("openssl", "openssl"): [HEARTBLEED]})
    for ver in ("1.0.1", "1.0.1f"):
        matches = match_service("OpenSSL", ver, None, prov)
        assert [m.cve_id for m in matches] == ["CVE-2014-0160"]
        assert matches[0].confidence == "high"


def test_heartbleed_patched_version_excluded() -> None:
    prov = _provider({("openssl", "openssl"): [HEARTBLEED]})
    # 1.0.1g пропатчен (верхняя граница including 1.0.1f) → не матчим.
    assert match_service("OpenSSL", "1.0.1g", None, prov) == []
    assert match_service("OpenSSL", "1.0.0", None, prov) == []


def test_versionless_is_rejected() -> None:
    prov = _provider({("openssl", "openssl"): [HEARTBLEED]})
    assert match_service("OpenSSL", None, None, prov) == []


def test_exact_enumerated_version() -> None:
    exact = Candidate(
        cve_id="CVE-EXACT",
        cpe_uri="cpe:2.3:a:openssl:openssl:1.0.1:*:*:*:*:*:*:*",
        node_operator="OR",
    )
    prov = _provider({("openssl", "openssl"): [exact]})
    assert [m.cve_id for m in match_service("OpenSSL", "1.0.1", None, prov)] == ["CVE-EXACT"]
    assert match_service("OpenSSL", "1.0.2", None, prov) == []


def test_nginx_multi_vendor() -> None:
    f5 = Candidate(
        "CVE-F5",
        "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
        version_start="1.20.0",
        version_start_type="including",
        version_end="1.21.0",
        version_end_type="excluding",
        node_operator="OR",
    )
    old = Candidate(
        "CVE-NG",
        "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
        version_end="1.21.0",
        version_end_type="excluding",
        node_operator="OR",
    )
    prov = _provider({("f5", "nginx"): [f5], ("nginx", "nginx"): [old]})
    got = sorted(m.cve_id for m in match_service("nginx", "1.20.0", None, prov))
    assert got == ["CVE-F5", "CVE-NG"]


def test_and_node_lowers_confidence() -> None:
    plain = Candidate(
        "CVE-X",
        "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
        version_start="2.0",
        version_start_type="including",
        version_end="2.15.0",
        version_end_type="excluding",
        node_operator="OR",
    )
    conditioned = Candidate(
        "CVE-Y",
        "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
        version_start="2.0",
        version_start_type="including",
        version_end="2.15.0",
        version_end_type="excluding",
        config_operator="AND",
        node_operator="OR",
    )
    prov = _provider({("apache", "log4j"): [plain, conditioned]})
    matches = {m.cve_id: m.confidence for m in match_service("log4j", "2.14.0", None, prov)}
    # AND «running on» непроверен → штраф понижает корзину.
    assert matches["CVE-X"] == "high"
    assert matches["CVE-Y"] == "medium"


def test_from_internetdb_cpe_shortcuts_mapping() -> None:
    cand = Candidate(
        "CVE-IDB",
        "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
        version_end="2.4.52",
        version_end_type="excluding",
        node_operator="OR",
    )
    prov = _provider({("apache", "http_server"): [cand]})
    matches = match_service(
        product=None,
        version="2.4.41",
        cpe_uri="cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*",
        get_candidates=prov,
    )
    assert [m.cve_id for m in matches] == ["CVE-IDB"]


def test_dedupe_keeps_best_confidence() -> None:
    strong = Candidate(
        "CVE-DUP",
        "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
        version_start="1.0.1",
        version_start_type="including",
        version_end="1.0.2",
        version_end_type="excluding",
        node_operator="OR",
    )
    weak = Candidate(  # тот же CVE, но AND-штраф
        "CVE-DUP",
        "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
        version_start="1.0.1",
        version_start_type="including",
        version_end="1.0.2",
        version_end_type="excluding",
        config_operator="AND",
        node_operator="OR",
    )
    prov = _provider({("openssl", "openssl"): [weak, strong]})
    matches = match_service("OpenSSL", "1.0.1f", None, prov)
    assert len(matches) == 1
    assert matches[0].confidence == "high"  # лучший из двух


# --- Стадия B: product → vendor:product ----------------------------------- #
def test_alias_mapping() -> None:
    assert map_product_to_cpe("Apache httpd") == map_product_to_cpe("apache")
    # nginx — мульти-вендор: старые CVE под nginx:nginx, новые под f5:nginx.
    nginx = {(m.vendor, m.product) for m in map_product_to_cpe("nginx")}
    assert nginx == {("f5", "nginx"), ("nginx", "nginx")}
    assert all(m.method == "alias" for m in map_product_to_cpe("nginx"))


def test_dict_exact_mapping() -> None:
    dictionary = [DictEntry(vendor="foovendor", product="foo_bar")]
    got = map_product_to_cpe("Foo Bar", dictionary)
    assert [(m.vendor, m.product, m.method) for m in got] == [
        ("foovendor", "foo_bar", "dict_exact")
    ]


def test_dict_fuzzy_above_threshold() -> None:
    dictionary = [DictEntry(vendor="v", product="foo_bar_extra")]
    got = map_product_to_cpe("Foo Bar", dictionary, fuzzy_threshold=0.6)
    assert [(m.vendor, m.product, m.method) for m in got] == [("v", "foo_bar_extra", "dict_fuzzy")]


def test_fuzzy_below_threshold_is_empty() -> None:
    # Ниже порога — пустой результат лучше ложной CVE (§13).
    dictionary = [DictEntry(vendor="v", product="foo_bar_baz")]
    assert map_product_to_cpe("foo", dictionary, fuzzy_threshold=0.6) == []


def test_unknown_product_no_dict_is_empty() -> None:
    assert map_product_to_cpe("totally-unknown-thing", None) == []
