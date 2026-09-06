"""Web Guard desktop UI bridge."""

from __future__ import annotations

import ctypes
import os
import threading
import time
from ctypes import wintypes

import pywintypes
import webview
import win32service

from . import __version__
from .catalog import ThreatCatalog, bundled_metadata, category_mask
from .domain_utils import normalize_domain
from . import browser_control, network_config, service_ipc
from .windows_chrome import configure_process, configure_window, minimize_window, move_window


APP_NAME = "Web Guard"
SERVICE_NAME = "WebGuardService"
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UI_DIR = os.path.join(ROOT_DIR, "ui")
_MUTEX_NAME = r"Local\Web.Guard.UI"
_ERROR_ALREADY_EXISTS = 183
_SW_RESTORE = 9
_mutex_handle = None

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_user32 = ctypes.WinDLL("user32", use_last_error=True)
_kernel32.CreateMutexW.argtypes = (ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR)
_kernel32.CreateMutexW.restype = wintypes.HANDLE
_kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
_kernel32.CloseHandle.restype = wintypes.BOOL
_user32.FindWindowW.argtypes = (wintypes.LPCWSTR, wintypes.LPCWSTR)
_user32.FindWindowW.restype = wintypes.HWND
_user32.ShowWindow.argtypes = (wintypes.HWND, ctypes.c_int)
_user32.ShowWindow.restype = wintypes.BOOL
_user32.SetForegroundWindow.argtypes = (wintypes.HWND,)
_user32.SetForegroundWindow.restype = wintypes.BOOL


def _acquire_single_instance() -> bool:
    """Keep one UI/WebView process per signed-in Windows session."""
    global _mutex_handle
    ctypes.set_last_error(0)
    handle = _kernel32.CreateMutexW(None, False, _MUTEX_NAME)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    if ctypes.get_last_error() == _ERROR_ALREADY_EXISTS:
        existing = _user32.FindWindowW(None, APP_NAME)
        if existing:
            _user32.ShowWindow(existing, _SW_RESTORE)
            _user32.SetForegroundWindow(existing)
        _kernel32.CloseHandle(handle)
        return False
    _mutex_handle = handle
    return True


def _release_single_instance():
    global _mutex_handle
    if _mutex_handle:
        _kernel32.CloseHandle(_mutex_handle)
        _mutex_handle = None


def _service_state():
    """Return the SCM state without waiting on a pipe that may not exist."""
    manager = None
    service = None
    try:
        manager = win32service.OpenSCManager(
            None, None, win32service.SC_MANAGER_CONNECT
        )
        service = win32service.OpenService(
            manager, SERVICE_NAME, win32service.SERVICE_QUERY_STATUS
        )
        return True, win32service.QueryServiceStatus(service)[1]
    except pywintypes.error as exc:
        if exc.winerror == 1060:  # ERROR_SERVICE_DOES_NOT_EXIST
            return False, None
        return False, None
    finally:
        if service is not None:
            win32service.CloseServiceHandle(service)
        if manager is not None:
            win32service.CloseServiceHandle(manager)


def _startup_service_status():
    """Describe SCM state without waiting for the service IPC endpoint.

    The WebView must be allowed to finish painting even when Windows is still
    starting the service. The normal status poll performs the bounded IPC
    handshake immediately after the interface has initialized.
    """
    installed, status = _service_state()
    if not installed:
        return {
            "ok": False,
            "service": "unavailable",
            "filter_running": False,
            "error": "Install Web Guard to enable its protection service",
        }
    if status != win32service.SERVICE_RUNNING:
        return {
            "ok": False,
            "service": "stopped",
            "filter_running": False,
            "error": "Web Guard Service is not running",
        }
    return {
        "ok": True,
        "service": "starting",
        "filter_running": False,
    }


class Api:
    def __init__(self):
        # pywebview exposes public attributes on js_api objects. These must be
        # private or it recursively walks the native WinForms/WebView2 window,
        # which can deadlock startup and hit Python's recursion limit.
        self._window = None
        self._catalog_instance = None
        self._compatibility_lock = threading.Lock()
        self._network_environment = None
        self._network_checked_at = 0.0
        self._network_refreshing = False
        self._browser_inventory = browser_control.detected_browsers()

    def attach(self, window):
        self._window = window

    def _catalog(self):
        if self._catalog_instance is None:
            self._catalog_instance = ThreatCatalog()
        return self._catalog_instance

    def _refresh_network_worker(self):
        try:
            environment = network_config.network_environment()
            browsers = browser_control.detected_browsers()
            with self._compatibility_lock:
                self._network_environment = environment
                self._browser_inventory = browsers
                self._network_checked_at = time.monotonic()
        except Exception:
            with self._compatibility_lock:
                self._network_environment = {
                    "vpn_names": [], "nrpt_rules": 0,
                    "adapters": [], "scan_error": True,
                }
                self._network_checked_at = time.monotonic()
        finally:
            with self._compatibility_lock:
                self._network_refreshing = False

    def _schedule_network_refresh(self, force=False):
        with self._compatibility_lock:
            stale = time.monotonic() - self._network_checked_at > 30
            if self._network_refreshing or (not force and not stale):
                return
            self._network_refreshing = True
        threading.Thread(
            target=self._refresh_network_worker,
            name="WebGuardNetworkCheck",
            daemon=True,
        ).start()

    def _decorate_status(self, status, force_refresh=False):
        result = dict(status or {})
        self._schedule_network_refresh(force=force_refresh)
        with self._compatibility_lock:
            environment = self._network_environment
            refreshing = self._network_refreshing
            inventory = [dict(item) for item in self._browser_inventory]
        compatibility = network_config.compatibility_summary(
            environment or {}, bool(result.get("filter_running"))
        )
        compatibility["scanning"] = bool(refreshing and environment is None)
        result["compatibility"] = compatibility

        browser_dns = dict(result.get("browser_dns") or {})
        policies = {
            item.get("id"): item
            for item in browser_dns.get("policies", [])
            if isinstance(item, dict)
        }
        browsers = []
        for detected in inventory:
            item = dict(detected)
            policy = policies.get(item.get("id"), {})
            item["secured"] = bool(policy.get("secured")) if item.get("supported") else False
            browsers.append(item)
        browser_dns["browsers"] = browsers
        browser_dns["unsupported"] = [
            item["label"] for item in browsers if not item.get("supported")
        ]
        browser_dns["vpn_browsers"] = [
            item["label"] for item in browsers if item.get("vpn_active")
        ]
        result["browser_dns"] = browser_dns
        return result

    @staticmethod
    def _service(command="status", payload=None, timeout_ms=1500):
        installed, status = _service_state()
        if not installed:
            return {
                "ok": False,
                "service": "unavailable",
                "filter_running": False,
                "error": "Install Web Guard to enable its protection service",
            }
        if status != win32service.SERVICE_RUNNING:
            return {
                "ok": False,
                "service": "stopped",
                "filter_running": False,
                "error": "Web Guard Service is not running",
            }
        try:
            return service_ipc.request(command, payload, timeout_ms=timeout_ms)
        except service_ipc.ServiceUnavailable as exc:
            return {
                "ok": False,
                "service": "unavailable",
                "filter_running": False,
                "error": str(exc),
            }

    def bootstrap(self):
        try:
            metadata = bundled_metadata()
        except Exception as exc:
            metadata = {"error": str(exc), "unique_domains": 0, "category_counts": {}}
        return {
            "ok": True,
            "version": __version__,
            "metadata": metadata,
            # Never make initial WebView rendering depend on a service reply.
            "status": self._decorate_status(_startup_service_status()),
        }

    def status(self):
        return self._decorate_status(self._service(timeout_ms=1500))

    def set_protection(self, enabled):
        return self._decorate_status(
            self._service(
                "set_protection", {"enabled": bool(enabled)}, timeout_ms=8000
            ),
            force_refresh=True,
        )

    def set_dns_provider(self, provider):
        return self._decorate_status(self._service(
            "set_dns_provider", {"provider": str(provider)}, timeout_ms=2500
        ))

    def set_browser_dns_protection(self, enabled):
        return self._decorate_status(self._service(
            "set_browser_dns_protection", {"enabled": bool(enabled)}, timeout_ms=8000
        ))

    def set_categories(self, categories):
        return self._decorate_status(self._service(
            "set_categories", {"categories": categories}, timeout_ms=8000
        ))

    def set_exceptions(self, allowlist, custom_blocklist):
        return self._decorate_status(self._service("set_exceptions", {
            "allowlist": allowlist,
            "custom_blocklist": custom_blocklist,
        }, timeout_ms=8000))

    def check_domain(self, value, settings):
        try:
            domain = normalize_domain(value)
            categories = settings.get("categories", {}) if isinstance(settings, dict) else {}
            allowlist = frozenset(settings.get("allowlist", [])) if isinstance(settings, dict) else frozenset()
            custom = frozenset(settings.get("custom_blocklist", [])) if isinstance(settings, dict) else frozenset()
            match = self._catalog().match(
                domain, category_mask(categories), allowlist, custom
            )
            return {
                "ok": True,
                "domain": domain,
                "blocked": match.blocked,
                "category": match.category,
                "matched_domain": match.matched_domain,
                "source": match.source,
            }
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        except Exception as exc:
            return {"ok": False, "error": f"Could not check this domain: {exc}"}

    def window_minimize(self):
        return minimize_window(self._window) if self._window else False

    def window_close(self):
        if self._window:
            self._window.destroy()
        return True

    def window_move(self, x, y):
        return move_window(self._window, x, y) if self._window else False

    def window_restored(self):
        return configure_window(self._window) if self._window else False


def run():
    configure_process()
    if not _acquire_single_instance():
        return
    api = Api()
    try:
        window = webview.create_window(
            APP_NAME,
            os.path.join(UI_DIR, "index.html"),
            js_api=api,
            width=1180,
            height=820,
            min_size=(940, 660),
            background_color="#0f0f0f",
            frameless=True,
            easy_drag=False,
        )
        api.attach(window)
        window.events.shown += lambda: configure_window(window)
        window.events.restored += api.window_restored
        webview.start(debug=bool(os.environ.get("WEB_GUARD_DEBUG")))
    finally:
        if api._catalog_instance:
            api._catalog_instance.close()
        _release_single_instance()


if __name__ == "__main__":
    run()
