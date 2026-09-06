"""Threat-category definitions and bundled-database access."""

from __future__ import annotations

import functools
import json
import os
import sqlite3
import sys
from dataclasses import dataclass

from .domain_utils import domain_matches, normalize_domain, suffixes


CATEGORY_BITS = {
    "malware": 1,
    "phishing": 2,
    "scams": 4,
    "abuse": 8,
    "redirects": 16,
    "crypto": 32,
}
DEFAULT_CATEGORIES = {name: True for name in CATEGORY_BITS}
# These are required by legitimate browser privacy features but are present in
# an upstream malware feed. User-added block rules still take precedence.
BUNDLED_COMPATIBILITY_ALLOWLIST = frozenset({
    "sec-tunnel.com",
    "myip.surfeasy.com",
})


def resource_root() -> str:
    if getattr(sys, "frozen", False):
        return getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def database_path() -> str:
    primary = os.path.join(resource_root(), "data", "guard.db")
    if os.path.isfile(primary):
        return primary
    if getattr(sys, "frozen", False):
        shared = os.path.join(
            os.path.dirname(sys.executable), "service", "_internal",
            "data", "guard.db",
        )
        if os.path.isfile(shared):
            return shared
    return primary


def metadata_path() -> str:
    return os.path.join(resource_root(), "data", "guard-metadata.json")


@functools.lru_cache(maxsize=1)
def bundled_metadata() -> dict:
    """Load the tiny build manifest without opening the 75 MB SQLite catalog."""
    with open(metadata_path(), "r", encoding="utf-8") as handle:
        return json.load(handle)


@dataclass(frozen=True)
class Match:
    blocked: bool
    category: str | None = None
    matched_domain: str | None = None
    source: str | None = None


class ThreatCatalog:
    """Read-only indexed threat lookup with a bounded process-local cache."""

    def __init__(self, path: str | None = None):
        self.path = path or database_path()
        uri = "file:" + self.path.replace("\\", "/") + "?mode=ro&immutable=1"
        self.connection = sqlite3.connect(uri, uri=True, check_same_thread=False)
        try:
            self.connection.execute("PRAGMA query_only=ON")
            self.connection.execute("PRAGMA cache_size=-32768")
            self.connection.execute("PRAGMA mmap_size=268435456")
            # Fail before Windows DNS is changed if the bundled catalog is
            # corrupt or does not contain the table the resolver requires.
            self.connection.execute(
                "SELECT domain, flags FROM domains LIMIT 1"
            ).fetchone()
        except Exception:
            self.connection.close()
            raise

    def close(self):
        self._flags_for_candidates.cache_clear()
        self.connection.close()

    @functools.lru_cache(maxsize=32768)
    def _flags_for_candidates(self, candidates: tuple[str, ...]):
        placeholders = ",".join("?" for _ in candidates)
        rows = self.connection.execute(
            f"SELECT domain, flags FROM domains WHERE domain IN ({placeholders})",
            candidates,
        ).fetchall()
        if not rows:
            return None, 0
        by_domain = dict(rows)
        for candidate in candidates:
            if candidate in by_domain:
                return candidate, int(by_domain[candidate])
        return None, 0

    def match(
        self,
        value: str,
        enabled_mask: int,
        allowlist: frozenset[str] = frozenset(),
        custom_blocklist: frozenset[str] = frozenset(),
    ) -> Match:
        try:
            domain = normalize_domain(value)
        except ValueError:
            return Match(False)
        if domain_matches(domain, allowlist):
            return Match(False, source="allowlist")
        if domain_matches(domain, custom_blocklist):
            return Match(True, "custom", domain, "custom")
        if domain_matches(domain, BUNDLED_COMPATIBILITY_ALLOWLIST):
            return Match(False, source="compatibility")
        matched, flags = self._flags_for_candidates(suffixes(domain))
        active = flags & enabled_mask
        if not active:
            return Match(False)
        category = next(
            name for name, bit in CATEGORY_BITS.items() if active & bit
        )
        return Match(True, category, matched, "bundled")

    def metadata(self) -> dict:
        rows = self.connection.execute(
            "SELECT key, value FROM metadata ORDER BY key"
        ).fetchall()
        result = {}
        for key, value in rows:
            try:
                result[key] = json.loads(value)
            except (TypeError, json.JSONDecodeError):
                result[key] = value
        return result


def category_mask(categories: dict[str, bool]) -> int:
    return sum(
        bit for name, bit in CATEGORY_BITS.items() if categories.get(name, False)
    )
