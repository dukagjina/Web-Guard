"""Persistent service settings with atomic writes and conservative limits."""

from __future__ import annotations

import json
import ipaddress
import os
import threading

import win32security

from .catalog import DEFAULT_CATEGORIES
from .domain_utils import normalize_domain


APP_NAME = "Web Guard"
PROGRAM_DATA = os.path.join(
    os.environ.get("PROGRAMDATA", r"C:\ProgramData"), APP_NAME
)
SETTINGS_PATH = os.path.join(PROGRAM_DATA, "settings.json")
MAX_EXCEPTIONS = 2_000
_PROTECTED_DACL = (
    win32security.DACL_SECURITY_INFORMATION
    | win32security.PROTECTED_DACL_SECURITY_INFORMATION
)
_PROGRAM_DATA_SDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)"
_BROWSER_POLICY_VALUES = {
    "chrome": {"DnsOverHttpsMode"},
    "edge": {"DnsOverHttpsMode"},
    "brave": {"DnsOverHttpsMode"},
    "firefox": {"Enabled", "Locked"},
}


def defaults() -> dict:
    return {
        "schema": 2,
        "protection_enabled": False,
        "dns_provider": "cloudflare",
        "browser_dns_protection": False,
        "browser_policy_backup": {},
        "categories": dict(DEFAULT_CATEGORIES),
        "allowlist": [],
        "custom_blocklist": [],
        "dns_snapshot": [],
    }


def _clean_policy_backup(value) -> dict:
    clean = {}
    if not isinstance(value, dict):
        return clean
    for browser, allowed_names in _BROWSER_POLICY_VALUES.items():
        supplied = value.get(browser)
        if not isinstance(supplied, dict):
            continue
        browser_values = {}
        for name in allowed_names:
            item = supplied.get(name)
            if not isinstance(item, dict):
                continue
            exists = bool(item.get("exists"))
            try:
                value_type = int(item.get("type", 0)) if exists else 0
            except (TypeError, ValueError):
                continue
            saved = item.get("value") if exists else None
            if exists and value_type not in (1, 4):  # REG_SZ or REG_DWORD
                continue
            if value_type == 1 and not isinstance(saved, str):
                continue
            if value_type == 4 and (not isinstance(saved, int) or isinstance(saved, bool)):
                continue
            browser_values[name] = {
                "exists": exists,
                "type": value_type,
                "value": saved,
            }
        if browser_values:
            clean[browser] = browser_values
    return clean


def _clean_domain_list(values) -> list[str]:
    clean = set()
    for value in values if isinstance(values, list) else []:
        try:
            clean.add(normalize_domain(value))
        except ValueError:
            continue
        if len(clean) >= MAX_EXCEPTIONS:
            break
    return sorted(clean)


def _clean_addresses(values, version: int) -> list[str]:
    if isinstance(values, str):
        values = [values]
    clean = []
    for value in values if isinstance(values, list) else []:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        if address.version != version or address.is_loopback or address.is_unspecified:
            continue
        text = str(address)
        if text not in clean:
            clean.append(text)
    return clean[:8]


def _clean_snapshot(values) -> list[dict]:
    clean = []
    for row in values if isinstance(values, list) else []:
        if not isinstance(row, dict):
            continue
        try:
            index = int(row["interface_index"])
        except (KeyError, TypeError, ValueError):
            continue
        if not 0 < index <= 2_147_483_647:
            continue
        clean.append({
            "interface_index": index,
            "alias": str(row.get("alias", "Network adapter"))[:200],
            "ipv4_automatic": bool(row.get("ipv4_automatic", True)),
            "ipv6_automatic": bool(row.get("ipv6_automatic", True)),
            "ipv4_active": bool(row.get("ipv4_active", True)),
            "ipv6_active": bool(row.get("ipv6_active", False)),
            "ipv4_servers": _clean_addresses(row.get("ipv4_servers", []), 4),
            "ipv6_servers": _clean_addresses(row.get("ipv6_servers", []), 6),
        })
        if len(clean) >= 32:
            break
    return clean


def _secure_program_data(path: str):
    """Keep recovery settings readable but writable only by the service/admins."""
    descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        _PROGRAM_DATA_SDDL, win32security.SDDL_REVISION_1
    )
    win32security.SetFileSecurity(path, _PROTECTED_DACL, descriptor)


def sanitize(value) -> dict:
    base = defaults()
    if not isinstance(value, dict):
        return base
    base["protection_enabled"] = bool(value.get("protection_enabled", False))
    provider = str(value.get("dns_provider", "cloudflare")).lower()
    base["dns_provider"] = provider if provider in ("cloudflare", "system") else "cloudflare"
    base["browser_dns_protection"] = bool(value.get("browser_dns_protection", False))
    base["browser_policy_backup"] = _clean_policy_backup(
        value.get("browser_policy_backup", {})
    )
    supplied_categories = value.get("categories", {})
    if isinstance(supplied_categories, dict):
        base["categories"] = {
            name: bool(supplied_categories.get(name, enabled))
            for name, enabled in base["categories"].items()
        }
    base["allowlist"] = _clean_domain_list(value.get("allowlist", []))
    base["custom_blocklist"] = _clean_domain_list(
        value.get("custom_blocklist", [])
    )
    base["dns_snapshot"] = _clean_snapshot(value.get("dns_snapshot", []))
    return base


class SettingsStore:
    def __init__(self, path: str = SETTINGS_PATH):
        self.path = path
        self._lock = threading.RLock()
        self._protected_storage = (
            os.path.normcase(os.path.abspath(path))
            == os.path.normcase(os.path.abspath(SETTINGS_PATH))
        )
        directory = os.path.dirname(self.path)
        if self._protected_storage and os.path.isdir(directory):
            _secure_program_data(directory)

    def load(self) -> dict:
        with self._lock:
            try:
                with open(self.path, "r", encoding="utf-8") as handle:
                    return sanitize(json.load(handle))
            except (OSError, ValueError, json.JSONDecodeError):
                return defaults()

    def save(self, value: dict) -> dict:
        clean = sanitize(value)
        with self._lock:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            if self._protected_storage:
                _secure_program_data(os.path.dirname(self.path))
            temporary = self.path + ".tmp"
            with open(temporary, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(clean, handle, indent=2, sort_keys=True)
                handle.write("\n")
            os.replace(temporary, self.path)
        return clean

    def update(self, **changes) -> dict:
        current = self.load()
        current.update(changes)
        return self.save(current)
