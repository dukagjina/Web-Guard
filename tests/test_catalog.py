import json
import sqlite3

import pytest

from web_guard.catalog import CATEGORY_BITS, ThreatCatalog


def make_database(path):
    connection = sqlite3.connect(path)
    connection.executescript("""
        CREATE TABLE domains(domain TEXT PRIMARY KEY, flags INTEGER NOT NULL) WITHOUT ROWID;
        CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
    """)
    connection.executemany("INSERT INTO domains VALUES(?, ?)", [
        ("bad-example.com", CATEGORY_BITS["malware"]),
        ("mixed-example.com", CATEGORY_BITS["phishing"] | CATEGORY_BITS["scams"]),
        ("sec-tunnel.com", CATEGORY_BITS["malware"]),
    ])
    connection.execute("INSERT INTO metadata VALUES(?, ?)", ("unique_domains", json.dumps(2)))
    connection.commit()
    connection.close()


def test_catalog_matches_subdomains_and_category_mask(tmp_path):
    path = tmp_path / "test.db"
    make_database(path)
    catalog = ThreatCatalog(str(path))
    try:
        match = catalog.match("deep.bad-example.com", CATEGORY_BITS["malware"])
        assert match.blocked and match.matched_domain == "bad-example.com"
        assert not catalog.match("bad-example.com", CATEGORY_BITS["phishing"]).blocked
    finally:
        catalog.close()


def test_allowlist_precedes_downloaded_and_custom_rules(tmp_path):
    path = tmp_path / "test.db"
    make_database(path)
    catalog = ThreatCatalog(str(path))
    try:
        result = catalog.match(
            "sub.bad-example.com", CATEGORY_BITS["malware"],
            frozenset({"bad-example.com"}), frozenset({"bad-example.com"}),
        )
        assert not result.blocked and result.source == "allowlist"
    finally:
        catalog.close()


def test_browser_compatibility_override_only_precedes_bundled_rule(tmp_path):
    path = tmp_path / "test.db"
    make_database(path)
    catalog = ThreatCatalog(str(path))
    try:
        allowed = catalog.match(
            "api.sec-tunnel.com", CATEGORY_BITS["malware"]
        )
        assert not allowed.blocked and allowed.source == "compatibility"
        custom = catalog.match(
            "api.sec-tunnel.com", CATEGORY_BITS["malware"],
            custom_blocklist=frozenset({"sec-tunnel.com"}),
        )
        assert custom.blocked and custom.source == "custom"
    finally:
        catalog.close()


def test_catalog_rejects_a_database_without_the_required_schema(tmp_path):
    path = tmp_path / "broken.db"
    sqlite3.connect(path).close()
    with pytest.raises(sqlite3.OperationalError):
        ThreatCatalog(str(path))
