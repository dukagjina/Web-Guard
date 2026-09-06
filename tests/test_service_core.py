from web_guard import service
from web_guard.settings import SettingsStore


class FakeStats:
    def snapshot(self):
        return {"queries": 0, "blocked": 0, "categories": {}, "started": 1}


class FakeProxy:
    def __init__(self, settings, resolvers, catalog_path):
        self.settings = settings
        self.resolvers = resolvers
        self.started = False
        self.stopped = False
        self.stats = FakeStats()

    def start(self):
        self.started = True

    def stop(self):
        self.stopped = True

    def update(self, settings):
        self.settings = settings

    def upstream_status(self):
        return {
            "provider": "cloudflare", "label": "Cloudflare",
            "encrypted": True, "last_success": 1, "last_error": "",
        }


def test_activation_saves_recovery_data_and_disable_restores(monkeypatch, tmp_path):
    events = []
    snapshot = [{
        "interface_index": 7, "alias": "Wi-Fi",
        "ipv4_automatic": True, "ipv6_automatic": True,
        "ipv4_active": True, "ipv6_active": False,
        "ipv4_servers": ["192.168.1.1"], "ipv6_servers": [],
    }]
    monkeypatch.setattr(service, "DNSProxy", FakeProxy)
    monkeypatch.setattr(service, "capture_active_dns", lambda: snapshot)
    monkeypatch.setattr(service, "upstreams", lambda value: ["192.168.1.1"])
    monkeypatch.setattr(service, "apply_local_dns", lambda value: events.append(("apply", value)))
    monkeypatch.setattr(service, "restore_dns", lambda value: events.append(("restore", value)))
    monkeypatch.setattr(service.browser_control, "capture_backup", lambda: {})
    monkeypatch.setattr(service.browser_control, "conflicting_policies", lambda value: [])
    monkeypatch.setattr(service.browser_control, "apply_policies", lambda: None)
    monkeypatch.setattr(service.browser_control, "restore_policies", lambda value: [])
    monkeypatch.setattr(service.browser_control, "policy_status", lambda: [])

    store = SettingsStore(str(tmp_path / "settings.json"))
    core = service.GuardCore(store=store, catalog_path="unused")
    enabled = core._set_protection(True)
    assert enabled["ok"] and enabled["filter_running"]
    assert enabled["settings"]["browser_dns_protection"] is True
    assert store.load()["dns_snapshot"] == snapshot
    assert events == [("apply", snapshot)]

    disabled = core._set_protection(False)
    assert disabled["ok"] and not disabled["filter_running"]
    assert store.load()["dns_snapshot"] == []
    assert events[-1] == ("restore", snapshot)


def test_failed_restore_keeps_filter_alive(monkeypatch, tmp_path):
    store = SettingsStore(str(tmp_path / "settings.json"))
    settings = store.load()
    settings["protection_enabled"] = True
    settings["dns_snapshot"] = [{"interface_index": 7, "ipv4_active": True}]
    store.save(settings)
    core = service.GuardCore(store=store, catalog_path="unused")
    core._proxy = FakeProxy(settings, [], "unused")
    monkeypatch.setattr(service, "restore_dns", lambda value: (_ for _ in ()).throw(RuntimeError("restore failed")))
    result = core._set_protection(False)
    assert not result["ok"]
    assert result["filter_running"]
    assert store.load()["protection_enabled"] is True


def test_failed_start_restores_dns_and_disables_protection(monkeypatch, tmp_path):
    restored = []
    snapshot = [{"interface_index": 7, "ipv4_active": True}]
    store = SettingsStore(str(tmp_path / "settings.json"))
    settings = store.load()
    settings["protection_enabled"] = True
    settings["dns_snapshot"] = snapshot
    store.save(settings)
    saved_snapshot = store.load()["dns_snapshot"]
    core = service.GuardCore(store=store, catalog_path="unused")
    monkeypatch.setattr(service, "restore_dns", lambda value: restored.append(value))

    core._recover_failed_start(RuntimeError("catalog failed"))

    assert restored == [saved_snapshot]
    assert store.load()["protection_enabled"] is False
    assert store.load()["dns_snapshot"] == []


def test_dns_provider_changes_only_while_filter_is_off(monkeypatch, tmp_path):
    monkeypatch.setattr(service.browser_control, "policy_status", lambda: [])
    store = SettingsStore(str(tmp_path / "settings.json"))
    core = service.GuardCore(store=store, catalog_path="unused")
    changed = core._set_dns_provider("system")
    assert changed["ok"] and store.load()["dns_provider"] == "system"
    core._proxy = FakeProxy(store.load(), [], "unused")
    refused = core._set_dns_provider("cloudflare")
    assert not refused["ok"]
    assert store.load()["dns_provider"] == "system"


def test_browser_dns_policies_are_backed_up_and_restored(monkeypatch, tmp_path):
    events = []
    backup = {"chrome": {"DnsOverHttpsMode": {
        "exists": False, "type": 0, "value": None,
    }}}
    monkeypatch.setattr(service.browser_control, "capture_backup", lambda: backup)
    monkeypatch.setattr(service.browser_control, "conflicting_policies", lambda value: [])
    monkeypatch.setattr(service.browser_control, "apply_policies", lambda: events.append("apply"))
    monkeypatch.setattr(service.browser_control, "restore_policies", lambda value: events.append(("restore", value)) or [])
    monkeypatch.setattr(service.browser_control, "policy_status", lambda: [])
    store = SettingsStore(str(tmp_path / "settings.json"))
    core = service.GuardCore(store=store, catalog_path="unused")
    core._proxy = FakeProxy(store.load(), [], "unused")

    enabled = core._set_browser_dns_protection(True)
    assert enabled["ok"] and store.load()["browser_dns_protection"] is True
    assert events == ["apply"]

    disabled = core._set_browser_dns_protection(False)
    assert disabled["ok"] and store.load()["browser_dns_protection"] is False
    assert events[-1] == ("restore", backup)


def test_failed_browser_policy_restore_keeps_recovery_backup(monkeypatch, tmp_path):
    backup = {"chrome": {"DnsOverHttpsMode": {
        "exists": False, "type": 0, "value": None,
    }}}
    monkeypatch.setattr(
        service.browser_control, "restore_policies",
        lambda value: (_ for _ in ()).throw(OSError("registry unavailable")),
    )
    monkeypatch.setattr(service.browser_control, "policy_status", lambda: [])
    store = SettingsStore(str(tmp_path / "settings.json"))
    settings = store.load()
    settings["browser_dns_protection"] = True
    settings["browser_policy_backup"] = backup
    store.save(settings)
    core = service.GuardCore(store=store, catalog_path="unused")

    result = core._set_browser_dns_protection(False)

    assert not result["ok"]
    saved = store.load()
    assert saved["browser_dns_protection"] is True
    assert saved["browser_policy_backup"] == backup
