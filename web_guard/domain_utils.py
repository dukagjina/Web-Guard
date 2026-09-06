"""Strict domain parsing shared by the compiler, UI, and DNS service."""

from __future__ import annotations

import ipaddress
import functools
import os
import re
import sys
from urllib.parse import urlsplit


_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _resource_root() -> str:
    if getattr(sys, "frozen", False):
        return getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@functools.lru_cache(maxsize=1)
def delegated_tlds() -> frozenset[str]:
    """Return the bundled IANA root-zone TLD snapshot in ASCII form."""
    path = os.path.join(_resource_root(), "data", "iana-tlds.txt")
    with open(path, "r", encoding="ascii") as handle:
        values = {
            line.strip().lower()
            for line in handle
            if line.strip() and not line.startswith("#")
        }
    if not values:
        raise RuntimeError("The bundled IANA top-level-domain list is empty")
    return frozenset(values)


def normalize_domain(value: str) -> str:
    """Return a canonical ASCII hostname, or raise ValueError.

    User input may be a hostname or an http(s) URL. Paths, ports, credentials,
    wildcards, and IP addresses never become block-list entries.
    """
    if not isinstance(value, str):
        raise ValueError("Enter a website domain")
    text = value.strip().lower().rstrip(".")
    if not text:
        raise ValueError("Enter a website domain")
    if "://" in text:
        parsed = urlsplit(text)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Enter a valid website address")
        text = parsed.hostname.rstrip(".")
    elif any(character in text for character in "/?#@"):
        raise ValueError("Enter only a domain, such as example.com")
    elif ":" in text:
        # Bracket-free IPv6 and hostname:port are both rejected deliberately.
        raise ValueError("Ports and IP addresses are not supported")

    try:
        ipaddress.ip_address(text)
    except ValueError:
        pass
    else:
        raise ValueError("IP addresses are not supported")

    try:
        ascii_name = text.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("This domain name is not valid") from exc
    if len(ascii_name) > 253 or "." not in ascii_name:
        raise ValueError("Enter a complete domain, such as example.com")
    labels = ascii_name.split(".")
    if any(not _LABEL_RE.fullmatch(label) for label in labels):
        raise ValueError("This domain name is not valid")
    if labels[-1] not in delegated_tlds():
        raise ValueError("Use a real domain ending, such as .com, .org, or a country code")
    return ascii_name


def suffixes(domain: str) -> tuple[str, ...]:
    """Return domain and registrable-looking parents for suffix blocking."""
    parts = domain.split(".")
    return tuple(".".join(parts[index:]) for index in range(max(1, len(parts) - 1)))


def domain_matches(domain: str, candidates: set[str] | frozenset[str]) -> bool:
    return any(candidate in candidates for candidate in suffixes(domain))
