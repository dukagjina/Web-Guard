import win32service

from web_guard import app


def test_missing_service_returns_immediately_without_pipe(monkeypatch):
    monkeypatch.setattr(app, "_service_state", lambda: (False, None))
    monkeypatch.setattr(
        app.service_ipc, "request",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("pipe should not be opened")),
    )
    result = app.Api._service()
    assert not result["ok"]
    assert result["service"] == "unavailable"


def test_running_service_uses_pipe(monkeypatch):
    monkeypatch.setattr(
        app, "_service_state",
        lambda: (True, win32service.SERVICE_RUNNING),
    )
    monkeypatch.setattr(
        app.service_ipc, "request",
        lambda *args, **kwargs: {"ok": True, "service": "running"},
    )
    assert app.Api._service()["ok"]


def test_bootstrap_does_not_open_threat_database(monkeypatch):
    monkeypatch.setattr(app, "bundled_metadata", lambda: {"unique_domains": 123})
    monkeypatch.setattr(app, "_startup_service_status", lambda: {
        "ok": True, "service": "starting", "filter_running": False,
    })
    monkeypatch.setattr(
        app.Api, "_service",
        staticmethod(lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("bootstrap must not wait for service IPC")
        )),
    )
    monkeypatch.setattr(
        app.Api, "_catalog",
        lambda self: (_ for _ in ()).throw(AssertionError("database opened during startup")),
    )
    api = app.Api()
    result = api.bootstrap()
    assert result["metadata"]["unique_domains"] == 123
    assert result["status"]["service"] == "starting"
    assert api._catalog_instance is None


def test_js_api_keeps_native_objects_private():
    api = app.Api()
    assert not hasattr(api, "window")
    assert not hasattr(api, "catalog")


def test_startup_status_does_not_open_pipe(monkeypatch):
    monkeypatch.setattr(
        app, "_service_state",
        lambda: (True, win32service.SERVICE_RUNNING),
    )
    monkeypatch.setattr(
        app.service_ipc, "request",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("startup status must not open the pipe")
        ),
    )
    result = app._startup_service_status()
    assert result["ok"]
    assert result["service"] == "starting"


def test_status_decoration_combines_network_and_detected_browsers(monkeypatch):
    api = app.Api()
    monkeypatch.setattr(api, "_schedule_network_refresh", lambda force=False: None)
    api._network_environment = {
        "vpn_names": ["Test VPN"], "nrpt_rules": 0, "scan_error": False,
        "adapters": [{
            "alias": "Wi-Fi", "default_route": True,
            "dns_servers": ["8.8.8.8"],
        }],
    }
    api._browser_inventory = [
        {"id": "chrome", "label": "Google Chrome", "supported": True},
        {"id": "opera", "label": "Opera", "supported": False, "vpn_active": True},
    ]
    result = api._decorate_status({
        "filter_running": True,
        "browser_dns": {"enabled": True, "policies": [
            {"id": "chrome", "label": "Google Chrome", "supported": True, "secured": True},
        ]},
    })
    assert result["compatibility"]["dns_bypass"] is True
    assert result["compatibility"]["vpn_active"] is True
    assert result["browser_dns"]["browsers"][0]["secured"] is True
    assert result["browser_dns"]["unsupported"] == ["Opera"]
    assert result["browser_dns"]["vpn_browsers"] == ["Opera"]
