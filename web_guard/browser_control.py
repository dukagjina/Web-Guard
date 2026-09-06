"""Reversible browser DNS-over-HTTPS policy management for Windows."""

from __future__ import annotations

import json
import os
import winreg


POLICIES = {
    "chrome": {
        "label": "Google Chrome",
        "path": r"SOFTWARE\Policies\Google\Chrome",
        "values": {"DnsOverHttpsMode": (winreg.REG_SZ, "off")},
    },
    "edge": {
        "label": "Microsoft Edge",
        "path": r"SOFTWARE\Policies\Microsoft\Edge",
        "values": {"DnsOverHttpsMode": (winreg.REG_SZ, "off")},
    },
    "brave": {
        "label": "Brave",
        "path": r"SOFTWARE\Policies\BraveSoftware\Brave",
        "values": {"DnsOverHttpsMode": (winreg.REG_SZ, "off")},
    },
    "firefox": {
        "label": "Mozilla Firefox",
        "path": r"SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS",
        "values": {
            "Enabled": (winreg.REG_DWORD, 0),
            "Locked": (winreg.REG_DWORD, 1),
        },
    },
}


def _read_value(path, name):
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ) as key:
            value, value_type = winreg.QueryValueEx(key, name)
            return {"exists": True, "type": int(value_type), "value": value}
    except OSError:
        return {"exists": False, "type": 0, "value": None}


def capture_backup():
    return {
        browser: {
            name: _read_value(spec["path"], name)
            for name in spec["values"]
        }
        for browser, spec in POLICIES.items()
    }


def _write_value(path, name, value_type, value):
    with winreg.CreateKeyEx(
        winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_SET_VALUE
    ) as key:
        winreg.SetValueEx(key, name, 0, value_type, value)


def _delete_value(path, name):
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_SET_VALUE
        ) as key:
            winreg.DeleteValue(key, name)
    except FileNotFoundError:
        pass


def conflicting_policies(backup):
    conflicts = []
    for browser, spec in POLICIES.items():
        saved = backup.get(browser, {}) if isinstance(backup, dict) else {}
        for name, (desired_type, desired_value) in spec["values"].items():
            item = saved.get(name, {}) if isinstance(saved, dict) else {}
            if item.get("exists") and (
                item.get("type") != desired_type or item.get("value") != desired_value
            ):
                conflicts.append(spec["label"])
                break
    return conflicts


def apply_policies():
    changed = []
    for browser, spec in POLICIES.items():
        for name, (value_type, value) in spec["values"].items():
            _write_value(spec["path"], name, value_type, value)
        changed.append(browser)
    return changed


def _delete_key_if_empty(path):
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, path, 0,
            winreg.KEY_READ | winreg.KEY_SET_VALUE,
        ) as key:
            if winreg.QueryInfoKey(key)[:2] != (0, 0):
                return
        winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, path)
    except (FileNotFoundError, OSError):
        pass


def restore_policies(backup):
    """Restore only values that still contain Web Guard's applied value.

    If an administrator changed a policy after Web Guard applied it, that new
    value wins and is reported instead of being overwritten.
    """
    skipped = []
    for browser, spec in POLICIES.items():
        saved = backup.get(browser, {}) if isinstance(backup, dict) else {}
        for name, (desired_type, desired_value) in spec["values"].items():
            current = _read_value(spec["path"], name)
            if not current.get("exists"):
                continue
            if current.get("type") != desired_type or current.get("value") != desired_value:
                skipped.append(spec["label"])
                continue
            item = saved.get(name, {}) if isinstance(saved, dict) else {}
            if item.get("exists"):
                _write_value(
                    spec["path"], name, int(item.get("type")), item.get("value")
                )
            else:
                _delete_value(spec["path"], name)
        _delete_key_if_empty(spec["path"])
    return sorted(set(skipped))


def policy_status():
    browsers = []
    for browser, spec in POLICIES.items():
        values = {
            name: _read_value(spec["path"], name)
            for name in spec["values"]
        }
        secured = all(
            values[name].get("exists")
            and values[name].get("type") == desired_type
            and values[name].get("value") == desired_value
            for name, (desired_type, desired_value) in spec["values"].items()
        )
        browsers.append({
            "id": browser,
            "label": spec["label"],
            "supported": True,
            "secured": secured,
        })
    return browsers


def _candidate_paths():
    program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
    program_files_x86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    local = os.environ.get("LOCALAPPDATA", "")
    return {
        "chrome": [
            os.path.join(program_files, "Google", "Chrome", "Application", "chrome.exe"),
            os.path.join(program_files_x86, "Google", "Chrome", "Application", "chrome.exe"),
            os.path.join(local, "Google", "Chrome", "Application", "chrome.exe"),
        ],
        "edge": [
            os.path.join(program_files_x86, "Microsoft", "Edge", "Application", "msedge.exe"),
            os.path.join(program_files, "Microsoft", "Edge", "Application", "msedge.exe"),
        ],
        "brave": [
            os.path.join(program_files, "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
            os.path.join(program_files_x86, "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
            os.path.join(local, "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
        ],
        "firefox": [
            os.path.join(program_files, "Mozilla Firefox", "firefox.exe"),
            os.path.join(program_files_x86, "Mozilla Firefox", "firefox.exe"),
        ],
        "opera": [
            os.path.join(local, "Programs", "Opera", "launcher.exe"),
            os.path.join(local, "Programs", "Opera", "opera.exe"),
            os.path.join(local, "Programs", "Opera GX", "launcher.exe"),
            os.path.join(local, "Programs", "Opera GX", "opera.exe"),
        ],
        "vivaldi": [
            os.path.join(local, "Vivaldi", "Application", "vivaldi.exe"),
            os.path.join(program_files, "Vivaldi", "Application", "vivaldi.exe"),
        ],
    }


def _opera_profile_paths():
    roaming = os.environ.get("APPDATA", "")
    return [
        os.path.join(roaming, "Opera Software", name, "Default", "Preferences")
        for name in ("Opera Stable", "Opera GX Stable")
    ]


def opera_vpn_enabled():
    """Read Opera's own VPN preference without changing browser data."""
    for path in _opera_profile_paths():
        try:
            if os.path.getsize(path) > 32 * 1024 * 1024:
                continue
            with open(path, "r", encoding="utf-8") as handle:
                preferences = json.load(handle)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        proxy = preferences.get("proxy_switcher", {})
        if isinstance(proxy, dict) and bool(proxy.get("enabled")):
            return True
    return False


def detected_browsers():
    labels = {
        **{key: value["label"] for key, value in POLICIES.items()},
        "opera": "Opera",
        "vivaldi": "Vivaldi",
    }
    result = []
    opera_vpn = opera_vpn_enabled()
    for browser, paths in _candidate_paths().items():
        if any(path and os.path.isfile(path) for path in paths):
            item = {
                "id": browser,
                "label": labels[browser],
                "supported": browser in POLICIES,
            }
            if browser == "opera":
                item["vpn_active"] = opera_vpn
            result.append(item)
    return result
