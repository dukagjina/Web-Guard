import winreg

from web_guard import browser_control


def _fake_registry(monkeypatch, initial=None):
    values = dict(initial or {})

    def read(path, name):
        if (path, name) not in values:
            return {"exists": False, "type": 0, "value": None}
        value_type, value = values[(path, name)]
        return {"exists": True, "type": value_type, "value": value}

    monkeypatch.setattr(browser_control, "_read_value", read)
    monkeypatch.setattr(
        browser_control, "_write_value",
        lambda path, name, value_type, value: values.__setitem__(
            (path, name), (value_type, value)
        ),
    )
    monkeypatch.setattr(
        browser_control, "_delete_value",
        lambda path, name: values.pop((path, name), None),
    )
    monkeypatch.setattr(browser_control, "_delete_key_if_empty", lambda path: None)
    return values


def test_apply_and_restore_browser_policies(monkeypatch):
    values = _fake_registry(monkeypatch)
    backup = browser_control.capture_backup()
    assert browser_control.conflicting_policies(backup) == []

    browser_control.apply_policies()
    assert values[(browser_control.POLICIES["chrome"]["path"], "DnsOverHttpsMode")] == (
        winreg.REG_SZ, "off"
    )
    assert all(item["secured"] for item in browser_control.policy_status())

    browser_control.restore_policies(backup)
    assert values == {}


def test_restore_does_not_overwrite_later_administrator_change(monkeypatch):
    values = _fake_registry(monkeypatch)
    backup = browser_control.capture_backup()
    browser_control.apply_policies()
    path = browser_control.POLICIES["edge"]["path"]
    values[(path, "DnsOverHttpsMode")] = (winreg.REG_SZ, "secure")

    skipped = browser_control.restore_policies(backup)

    assert skipped == ["Microsoft Edge"]
    assert values[(path, "DnsOverHttpsMode")] == (winreg.REG_SZ, "secure")


def test_conflicting_existing_policy_is_reported(monkeypatch):
    path = browser_control.POLICIES["brave"]["path"]
    _fake_registry(monkeypatch, {
        (path, "DnsOverHttpsMode"): (winreg.REG_SZ, "secure")
    })
    assert browser_control.conflicting_policies(
        browser_control.capture_backup()
    ) == ["Brave"]


def test_detected_browsers_identifies_supported_and_manual(monkeypatch):
    monkeypatch.setattr(browser_control, "_candidate_paths", lambda: {
        "chrome": [r"C:\Chrome\chrome.exe"],
        "opera": [r"C:\Opera\launcher.exe"],
        "firefox": [r"C:\Firefox\firefox.exe"],
    })
    monkeypatch.setattr(
        browser_control.os.path, "isfile",
        lambda path: "Chrome" in path or "Opera" in path,
    )
    monkeypatch.setattr(browser_control, "opera_vpn_enabled", lambda: False)
    result = {item["id"]: item for item in browser_control.detected_browsers()}
    assert result["chrome"]["supported"] is True
    assert result["opera"]["supported"] is False
    assert "firefox" not in result


def test_opera_vpn_preference_is_detected(monkeypatch, tmp_path):
    preferences = tmp_path / "Preferences"
    preferences.write_text(
        '{"proxy_switcher":{"enabled":true,"forbidden":false}}',
        encoding="utf-8",
    )
    monkeypatch.setattr(
        browser_control, "_opera_profile_paths", lambda: [str(preferences)]
    )
    assert browser_control.opera_vpn_enabled() is True

    preferences.write_text(
        '{"proxy_switcher":{"enabled":false}}', encoding="utf-8"
    )
    assert browser_control.opera_vpn_enabled() is False
