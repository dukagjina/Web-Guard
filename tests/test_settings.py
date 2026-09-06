from web_guard.settings import SettingsStore, sanitize


def test_settings_are_sanitized_and_saved_atomically(tmp_path):
    path = tmp_path / "settings.json"
    store = SettingsStore(str(path))
    value = store.save({
        "protection_enabled": 1,
        "categories": {"malware": False},
        "allowlist": ["EXAMPLE.com", "bad value", "example.com"],
        "custom_blocklist": ["blocked-example.com"],
    })
    assert value["protection_enabled"] is True
    assert value["allowlist"] == ["example.com"]
    assert store.load() == value


def test_invalid_settings_return_safe_defaults():
    value = sanitize("broken")
    assert value["protection_enabled"] is False
    assert value["dns_provider"] == "cloudflare"
    assert value["browser_dns_protection"] is False
    assert all(value["categories"].values())


def test_dns_and_browser_recovery_settings_are_sanitized():
    value = sanitize({
        "dns_provider": "not-a-provider",
        "browser_dns_protection": 1,
        "browser_policy_backup": {
            "chrome": {
                "DnsOverHttpsMode": {"exists": True, "type": 1, "value": "secure"},
                "Unrelated": {"exists": True, "type": 1, "value": "keep"},
            },
            "unknown": {"Value": {"exists": True, "type": 1, "value": "bad"}},
        },
    })
    assert value["dns_provider"] == "cloudflare"
    assert value["browser_dns_protection"] is True
    assert value["browser_policy_backup"] == {
        "chrome": {
            "DnsOverHttpsMode": {"exists": True, "type": 1, "value": "secure"}
        }
    }


def test_dns_recovery_snapshot_is_strictly_sanitized():
    value = sanitize({
        "dns_snapshot": [
            {
                "interface_index": "17",
                "alias": "Wi-Fi",
                "ipv4_active": True,
                "ipv6_active": False,
                "ipv4_servers": ["192.168.1.1", "127.0.0.1", "bad"],
                "ipv6_servers": ["::1"],
            },
            {"interface_index": -1, "ipv4_servers": ["8.8.8.8"]},
            {"interface_index": "not-a-number"},
            "not a row",
        ]
    })
    assert value["dns_snapshot"] == [{
        "interface_index": 17,
        "alias": "Wi-Fi",
        "ipv4_automatic": True,
        "ipv6_automatic": True,
        "ipv4_active": True,
        "ipv6_active": False,
        "ipv4_servers": ["192.168.1.1"],
        "ipv6_servers": [],
    }]
