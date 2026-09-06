from web_guard import network_config


def test_apply_and_restore_touch_only_active_address_families(monkeypatch):
    calls = []
    monkeypatch.setattr(network_config, "_run", lambda args, timeout=30: calls.append(args) or "")
    monkeypatch.setattr(network_config, "flush_dns", lambda: None)
    snapshot = [{
        "interface_index": 17,
        "alias": "Wi-Fi",
        "ipv4_active": True,
        "ipv6_active": False,
        "ipv4_automatic": True,
        "ipv6_automatic": True,
        "ipv4_servers": ["192.168.1.1"],
        "ipv6_servers": [],
    }]
    network_config.apply_local_dns(snapshot)
    assert len(calls) == 1 and calls[0][2] == "ipv4"
    calls.clear()
    network_config.restore_dns(snapshot)
    assert len(calls) == 1 and calls[0][2] == "ipv4"
    assert "source=dhcp" in calls[0]


def test_upstreams_keep_only_the_original_usable_resolver():
    result = network_config.upstreams([{
        "ipv4_servers": ["192.168.1.1", "127.0.0.1"],
        "ipv6_servers": ["fec0:0:0:ffff::1"],
    }])
    assert result == ["192.168.1.1"]


def test_compatibility_summary_detects_adapter_and_nrpt_bypass():
    environment = {
        "vpn_names": ["Work VPN"],
        "nrpt_rules": 1,
        "scan_error": False,
        "adapters": [{
            "alias": "Wi-Fi", "default_route": True,
            "dns_servers": ["8.8.8.8"],
        }],
    }
    result = network_config.compatibility_summary(environment, True)
    assert result["vpn_active"] is True
    assert result["dns_bypass"] is True
    assert result["bypass_adapters"] == ["Wi-Fi"]


def test_compatibility_summary_accepts_local_dns_and_ignores_when_off():
    environment = {
        "vpn_names": [], "nrpt_rules": 0, "scan_error": False,
        "adapters": [{
            "alias": "Wi-Fi", "default_route": True,
            "dns_servers": ["127.0.0.1", "::1"],
        }],
    }
    assert network_config.compatibility_summary(environment, True)["dns_bypass"] is False
    environment["adapters"][0]["dns_servers"] = ["1.1.1.1"]
    assert network_config.compatibility_summary(environment, False)["dns_bypass"] is False
