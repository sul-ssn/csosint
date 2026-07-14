"""Сборка графа связей в формат Cytoscape (ТЗ §2.3, §5.2)."""

from __future__ import annotations

from gateway.graph import GraphData, to_cytoscape


def _index(cyto: dict) -> tuple[dict[str, dict], dict[str, dict]]:
    nodes = {n["data"]["id"]: n["data"] for n in cyto["nodes"]}
    edges = {e["data"]["id"]: e["data"] for e in cyto["edges"]}
    return nodes, edges


def test_full_graph_shape() -> None:
    g = GraphData(
        domains=[(1, "example.com"), (2, "www.example.com")],
        ips=[(10, "1.2.3.4", "TESTNET", "US")],
        edges_domain_ip=[(1, 10), (2, 10)],
        services=[(100, 10, 443, "OpenSSL", "1.0.1", "internetdb")],
        service_cves=[(100, "CVE-2014-0160", "high")],
        cves=[("CVE-2014-0160", "HIGH", 7.5)],
    )
    nodes, edges = _index(to_cytoscape(g))

    assert set(nodes) == {
        "domain:1",
        "domain:2",
        "ip:10",
        "service:100",
        "cve:CVE-2014-0160",
        "country:US",
        "org:TESTNET",
    }
    assert nodes["ip:10"]["org_name"] == "TESTNET"
    assert nodes["service:100"]["label"] == "OpenSSL 1.0.1:443"
    assert nodes["cve:CVE-2014-0160"]["label"] == "CVE-2014-0160 (7.5)"
    # Гео/организация как отдельные узлы (как у CVEG).
    assert edges["ip:10->country:US"]["type"] == "geo"
    assert edges["ip:10->org:TESTNET"]["type"] == "hosted"
    # Shared-host: оба домена связаны с одним IP.
    assert "domain:1->ip:10" in edges and "domain:2->ip:10" in edges
    assert edges["ip:10->service:100"]["type"] == "runs"
    assert edges["service:100->cve:CVE-2014-0160"]["type"] == "vulnerable"
    assert edges["service:100->cve:CVE-2014-0160"]["confidence"] == "high"


def test_empty_graph() -> None:
    assert to_cytoscape(GraphData()) == {"nodes": [], "edges": []}


def test_dangling_edges_are_skipped() -> None:
    # Рёбра на отсутствующие узлы не попадают в граф.
    g = GraphData(
        domains=[(1, "example.com")],
        edges_domain_ip=[(1, 99)],  # ip:99 нет в узлах
        service_cves=[(500, "CVE-X", "low")],  # service:500 нет
    )
    nodes, edges = _index(to_cytoscape(g))
    assert set(nodes) == {"domain:1"}
    assert edges == {}


def test_service_label_without_product() -> None:
    g = GraphData(
        ips=[(10, "1.2.3.4", None, None)],
        services=[(100, 10, 22, None, None, "internetdb")],
    )
    nodes, _ = _index(to_cytoscape(g))
    assert nodes["service:100"]["label"] == "service:22"
