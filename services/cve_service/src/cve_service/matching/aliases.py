"""Ручная карта высокочастотных product → canonical `vendor:product`
(design-cpe-matching §4).

Канонические CPE-имена неинтуитивны: `nginx → f5:nginx` (вендор f5!),
`OpenSSH → openbsd:openssh`, `MySQL → oracle:mysql`. Строкой не вывести —
эта выверенная по NVD карта закрывает ~80% попаданий и снимает злые ловушки.

Значение — СПИСОК пар `(vendor, product)`: одно имя может маппиться в несколько
canonical (nginx: старые CVE под `nginx:nginx`, новые под `f5:nginx`).
"""

from __future__ import annotations

import re

# Ключи — уже нормализованные имена (см. normalize_product_name).
ALIAS_MAP: dict[str, list[tuple[str, str]]] = {
    "apache": [("apache", "http_server")],
    "apache http server": [("apache", "http_server")],
    "httpd": [("apache", "http_server")],
    "nginx": [("f5", "nginx"), ("nginx", "nginx")],
    "openssh": [("openbsd", "openssh")],
    "openssl": [("openssl", "openssl")],
    "mysql": [("oracle", "mysql")],
    "mariadb": [("mariadb", "mariadb")],
    "postgresql": [("postgresql", "postgresql")],
    "postgres": [("postgresql", "postgresql")],
    "exim": [("exim", "exim")],
    "microsoft iis": [("microsoft", "internet_information_services")],
    "iis": [("microsoft", "internet_information_services")],
    "lighttpd": [("lighttpd", "lighttpd")],
    "proftpd": [("proftpd", "proftpd")],
    "vsftpd": [("vsftpd", "vsftpd")],
    "dovecot": [("dovecot", "dovecot")],
    "postfix": [("postfix", "postfix")],
    "bind": [("isc", "bind")],
    "redis": [("redis", "redis")],
    "mongodb": [("mongodb", "mongodb")],
    "elasticsearch": [("elastic", "elasticsearch")],
    "tomcat": [("apache", "tomcat")],
    "apache tomcat": [("apache", "tomcat")],
    "haproxy": [("haproxy", "haproxy")],
    "log4j": [("apache", "log4j")],
}

# Шумовые слова, которые убираем при нормализации имени продукта.
_NOISE = re.compile(r"\b(httpd|server|daemon|service|software)\b", re.IGNORECASE)
_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def normalize_product_name(product: str | None) -> str | None:
    """Нормализовать свободное имя продукта под ключ карты/словаря:
    lower-case, убрать шум (`server`/`daemon`), схлопнуть разделители в пробел."""
    if not product:
        return None
    text = product.lower().strip()
    text = _NOISE.sub(" ", text)
    text = _NON_ALNUM.sub(" ", text)
    text = " ".join(text.split())
    return text or None
