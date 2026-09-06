"""Privileged Windows service that owns local DNS filtering and restoration."""

from __future__ import annotations

import argparse
import logging
import os
import subprocess
import sys
import threading

import pywintypes
import servicemanager
import win32event
import win32service
import win32serviceutil

from .catalog import CATEGORY_BITS
from . import browser_control
from .dns_proxy import DNSProxy
from .domain_utils import normalize_domain
from .network_config import (
    apply_local_dns, capture_active_dns, flush_dns, restore_dns, upstreams,
)
from .service_ipc import PipeServer
from .settings import MAX_EXCEPTIONS, PROGRAM_DATA, SettingsStore
from . import service_ipc


SERVICE_NAME = "WebGuardService"
SERVICE_DISPLAY_NAME = "Web Guard Service"
SERVICE_DESCRIPTION = (
    "Filters known malicious domains locally and restores Windows DNS settings when stopped."
)
LOG_FILE = os.path.join(PROGRAM_DATA, "service.log")


def _configure_logging():
    try:
        os.makedirs(PROGRAM_DATA, exist_ok=True)
        logging.basicConfig(
            filename=LOG_FILE,
            level=logging.INFO,
            format="%(asctime)s %(levelname)s %(message)s",
        )
    except OSError:
        logging.basicConfig(level=logging.INFO)


def _public_settings(settings: dict) -> dict:
    return {
        "protection_enabled": bool(settings.get("protection_enabled")),
        "dns_provider": str(settings.get("dns_provider", "cloudflare")),
        "browser_dns_protection": bool(settings.get("browser_dns_protection")),
        "categories": dict(settings.get("categories", {})),
        "allowlist": list(settings.get("allowlist", [])),
        "custom_blocklist": list(settings.get("custom_blocklist", [])),
    }


class GuardCore:
    def __init__(self, store=None, catalog_path=None):
        self.store = store or SettingsStore()
        self.catalog_path = catalog_path
        self.stop_event = threading.Event()
        self.pipe = PipeServer()
        self._lock = threading.RLock()
        self._proxy = None
        self._last_error = ""

    def _status(self):
        settings = self.store.load()
        return {
            "ok": True,
            "service": "running",
            "filter_running": self._proxy is not None,
            "settings": _public_settings(settings),
            "stats": self._proxy.stats.snapshot() if self._proxy else {
                "queries": 0, "blocked": 0, "categories": {}, "started": None,
            },
            "upstream": self._proxy.upstream_status() if self._proxy else {
                "provider": settings.get("dns_provider", "cloudflare"),
                "label": "Cloudflare" if settings.get("dns_provider", "cloudflare") == "cloudflare" else "System DNS",
                "encrypted": settings.get("dns_provider", "cloudflare") != "system",
                "last_success": None,
                "last_error": "",
            },
            "browser_dns": {
                "enabled": bool(settings.get("browser_dns_protection")),
                "policies": browser_control.policy_status(),
            },
            "last_error": self._last_error,
        }

    def _restore_browser_policies(self, settings):
        if not settings.get("browser_dns_protection"):
            return settings
        try:
            skipped = browser_control.restore_policies(
                settings.get("browser_policy_backup", {})
            )
            if skipped:
                self._last_error = (
                    "Browser policies changed outside Web Guard and were left untouched: "
                    + ", ".join(skipped)
                )
        except Exception as exc:
            self._last_error = f"Browser DNS settings could not be restored: {exc}"
            logging.exception("Browser DNS policy restoration failed")
            # Retain the backup and active marker so restoration can be
            # retried. Never discard recovery data after a partial failure.
            return self.store.save(settings)
        settings["browser_dns_protection"] = False
        settings["browser_policy_backup"] = {}
        return self.store.save(settings)

    def _start_filter(self):
        with self._lock:
            settings = self.store.load()
            if self._proxy:
                self._proxy.update(settings)
                return
            snapshot = settings.get("dns_snapshot") or capture_active_dns()
            if not snapshot:
                raise RuntimeError("Windows did not report an active network adapter")
            if not settings.get("dns_snapshot"):
                settings["dns_snapshot"] = snapshot
                self.store.save(settings)  # Save recovery data before changing DNS.
            proxy = DNSProxy(settings, upstreams(snapshot), self.catalog_path)
            proxy_started = False
            try:
                proxy.start()
                proxy_started = True
                apply_local_dns(snapshot)
            except Exception:
                if proxy_started:
                    # Keep a working resolver alive until a deliberate disable
                    # can confirm that every touched adapter was restored.
                    self._proxy = proxy
                else:
                    proxy.stop()
                raise
            self._proxy = proxy
            self._last_error = ""
            logging.info("Protection enabled on %d adapter(s)", len(snapshot))

    def _recover_failed_start(self, error):
        """Restore Windows DNS when filtering could not start safely."""
        self._last_error = str(error)
        if self._proxy is not None:
            return
        settings = self.store.load()
        snapshot = settings.get("dns_snapshot") or []
        try:
            if snapshot:
                restore_dns(snapshot)
        except Exception as restore_error:
            self._last_error = (
                f"{error}; Windows DNS could not be restored: {restore_error}"
            )
            logging.exception("Protection failed and DNS restoration also failed")
            return
        settings["protection_enabled"] = False
        settings["dns_snapshot"] = []
        self.store.save(settings)

    def _stop_filter(self, preserve_enabled=False):
        with self._lock:
            settings = self.store.load()
            snapshot = settings.get("dns_snapshot") or []
            # Keep the proxy alive until Windows no longer points at it.
            if snapshot:
                restore_dns(snapshot)
            proxy = self._proxy
            self._proxy = None
            if not preserve_enabled:
                settings["protection_enabled"] = False
                settings["dns_snapshot"] = []
                settings = self._restore_browser_policies(settings)
                settings = self.store.save(settings)
            if proxy:
                proxy.stop()
            logging.info("Protection disabled")
            if not preserve_enabled and settings.get("browser_dns_protection"):
                raise RuntimeError(self._last_error or "Browser DNS settings were not restored")

    def _set_protection(self, enabled):
        if not isinstance(enabled, bool):
            return {"ok": False, "error": "Protection state is invalid"}
        settings = self.store.load()
        if enabled:
            settings["protection_enabled"] = True
            self.store.save(settings)
            try:
                self._start_filter()
            except Exception as exc:
                self._recover_failed_start(exc)
                logging.exception("Protection activation failed")
                response = self._status()
                response.update(ok=False, error=str(exc))
                return response
            settings = self.store.load()
            if not settings.get("browser_dns_protection"):
                browser_result = self._set_browser_dns_protection(True)
                if not browser_result.get("ok"):
                    response = self._status()
                    response["warning"] = browser_result.get(
                        "error", "Supported browser DNS protection could not be enabled"
                    )
                    return response
        else:
            try:
                self._stop_filter(preserve_enabled=False)
            except Exception as exc:
                self._last_error = str(exc)
                logging.exception("Protection deactivation failed")
                response = self._status()
                response.update(ok=False, error=str(exc))
                return response
        return self._status()

    def _set_dns_provider(self, provider):
        provider = str(provider).lower()
        if provider not in ("cloudflare", "system"):
            return {"ok": False, "error": "Encrypted DNS selection is invalid"}
        if self._proxy:
            response = self._status()
            response.update(
                ok=False,
                error="Turn protection off before changing encrypted DNS",
            )
            return response
        settings = self.store.load()
        settings["dns_provider"] = provider
        self.store.save(settings)
        return self._status()

    def _set_browser_dns_protection(self, enabled):
        if not isinstance(enabled, bool):
            return {"ok": False, "error": "Browser protection state is invalid"}
        settings = self.store.load()
        if enabled:
            if not self._proxy:
                response = self._status()
                response.update(ok=False, error="Turn Web Guard on before protecting browser DNS")
                return response
            if settings.get("browser_dns_protection"):
                return self._status()
            backup = browser_control.capture_backup()
            conflicts = browser_control.conflicting_policies(backup)
            if conflicts:
                response = self._status()
                response.update(
                    ok=False,
                    error=(
                        "Existing administrator browser policies were not replaced: "
                        + ", ".join(conflicts)
                    ),
                )
                return response
            # Persist recovery data before changing machine-wide policy.
            settings["browser_policy_backup"] = backup
            settings["browser_dns_protection"] = True
            self.store.save(settings)
            try:
                browser_control.apply_policies()
            except Exception as exc:
                rollback_error = None
                try:
                    browser_control.restore_policies(backup)
                except Exception as restore_exc:
                    rollback_error = restore_exc
                    logging.exception("Browser DNS policy rollback failed")
                if rollback_error is None:
                    settings["browser_dns_protection"] = False
                    settings["browser_policy_backup"] = {}
                self.store.save(settings)
                response = self._status()
                error = f"Browser DNS protection failed: {exc}"
                if rollback_error is not None:
                    error += f"; restoration must be retried: {rollback_error}"
                response.update(ok=False, error=error)
                return response
        else:
            settings = self._restore_browser_policies(settings)
            if settings.get("browser_dns_protection"):
                response = self._status()
                response.update(ok=False, error=self._last_error)
                return response
        return self._status()

    def _set_categories(self, supplied):
        if not isinstance(supplied, dict):
            return {"ok": False, "error": "Protection categories are invalid"}
        if set(supplied) != set(CATEGORY_BITS):
            return {"ok": False, "error": "Every protection category is required"}
        settings = self.store.load()
        settings["categories"] = {name: bool(supplied[name]) for name in CATEGORY_BITS}
        if not any(settings["categories"].values()):
            return {"ok": False, "error": "Keep at least one protection category enabled"}
        settings = self.store.save(settings)
        if self._proxy:
            self._proxy.update(settings)
            flush_dns()
        return self._status()

    @staticmethod
    def _validated_list(values):
        if not isinstance(values, list) or len(values) > MAX_EXCEPTIONS:
            raise ValueError(f"A list may contain at most {MAX_EXCEPTIONS:,} domains")
        return sorted({normalize_domain(value) for value in values})

    def _set_exceptions(self, payload):
        try:
            allowlist = self._validated_list(payload.get("allowlist", []))
            blocklist = self._validated_list(payload.get("custom_blocklist", []))
        except (ValueError, TypeError) as exc:
            return {"ok": False, "error": str(exc)}
        overlap = set(allowlist) & set(blocklist)
        if overlap:
            return {"ok": False, "error": "A domain cannot be in both lists"}
        settings = self.store.load()
        settings["allowlist"] = allowlist
        settings["custom_blocklist"] = blocklist
        settings = self.store.save(settings)
        if self._proxy:
            self._proxy.update(settings)
            flush_dns()
        return self._status()

    def _handle(self, command, payload):
        with self._lock:
            if command == "ping" or command == "status":
                response = self._status()
                response["protocol"] = service_ipc.PROTOCOL_VERSION
                return response
            if command == "set_protection":
                return self._set_protection(payload.get("enabled"))
            if command == "set_categories":
                return self._set_categories(payload.get("categories"))
            if command == "set_exceptions":
                return self._set_exceptions(payload)
            if command == "set_dns_provider":
                return self._set_dns_provider(payload.get("provider"))
            if command == "set_browser_dns_protection":
                return self._set_browser_dns_protection(payload.get("enabled"))
            if command == "prepare_uninstall":
                result = self._set_protection(False)
                if result.get("ok"):
                    result["prepared"] = True
                return result
            return {"ok": False, "error": "Unsupported service command"}

    def run(self):
        _configure_logging()
        settings = self.store.load()
        if settings.get("protection_enabled"):
            try:
                self._start_filter()
            except Exception as exc:
                self._recover_failed_start(exc)
                logging.exception("Could not resume protection")
            else:
                if settings.get("browser_dns_protection"):
                    try:
                        browser_control.apply_policies()
                    except Exception as exc:
                        self._last_error = (
                            f"Browser DNS protection could not be restored: {exc}"
                        )
                        logging.exception("Could not restore browser DNS policies")
                else:
                    result = self._set_browser_dns_protection(True)
                    if not result.get("ok"):
                        self._last_error = result.get("error", "")
        try:
            self.pipe.serve(self.stop_event, self._handle)
        finally:
            if self._proxy:
                try:
                    self._stop_filter(preserve_enabled=True)
                except Exception:
                    logging.exception("Could not restore DNS while stopping service")

    def stop(self):
        self.stop_event.set()
        self.pipe.wake()


class GuardService(win32serviceutil.ServiceFramework):
    _svc_name_ = SERVICE_NAME
    _svc_display_name_ = SERVICE_DISPLAY_NAME
    _svc_description_ = SERVICE_DESCRIPTION

    def __init__(self, args):
        super().__init__(args)
        self._core = GuardCore()
        self._stop_handle = win32event.CreateEvent(None, 0, 0, None)

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self._core.stop()
        win32event.SetEvent(self._stop_handle)

    def SvcDoRun(self):
        servicemanager.LogInfoMsg(SERVICE_DISPLAY_NAME + " started")
        self._core.run()


def _run_sc(*arguments):
    completed = subprocess.run(
        [os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "sc.exe"), *arguments],
        check=False, capture_output=True, text=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if completed.returncode:
        raise RuntimeError((completed.stderr or completed.stdout or "Service command failed").strip())
    return completed.stdout


def _service_handle(access):
    manager = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ALL_ACCESS)
    try:
        service = win32service.OpenService(manager, SERVICE_NAME, access)
        return manager, service
    except Exception:
        win32service.CloseServiceHandle(manager)
        raise


def install_service():
    if not getattr(sys, "frozen", False):
        raise RuntimeError("Build Web Guard before installing its service")
    command = f'"{os.path.abspath(sys.executable)}"'
    manager = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ALL_ACCESS)
    service = None
    try:
        try:
            service = win32service.OpenService(manager, SERVICE_NAME, win32service.SERVICE_ALL_ACCESS)
            win32service.ChangeServiceConfig(
                service, win32service.SERVICE_NO_CHANGE, win32service.SERVICE_AUTO_START,
                win32service.SERVICE_NO_CHANGE, command, None, 0, None, None, None,
                SERVICE_DISPLAY_NAME,
            )
        except pywintypes.error as exc:
            if exc.winerror != 1060:
                raise
            service = win32service.CreateService(
                manager, SERVICE_NAME, SERVICE_DISPLAY_NAME, win32service.SERVICE_ALL_ACCESS,
                win32service.SERVICE_WIN32_OWN_PROCESS, win32service.SERVICE_AUTO_START,
                win32service.SERVICE_ERROR_NORMAL, command, None, 0, None, None, None,
            )
        try:
            win32service.ChangeServiceConfig2(
                service, win32service.SERVICE_CONFIG_DESCRIPTION, SERVICE_DESCRIPTION
            )
        except pywintypes.error:
            pass
        try:
            win32service.StartService(service, None)
        except pywintypes.error as exc:
            if exc.winerror != 1056:
                raise
    finally:
        if service is not None:
            win32service.CloseServiceHandle(service)
        win32service.CloseServiceHandle(manager)
    _run_sc("failure", SERVICE_NAME, "reset=", "86400", "actions=", "restart/1000/restart/5000/restart/15000")


def uninstall_service():
    disabled = False
    try:
        response = service_ipc.request("prepare_uninstall", timeout_ms=15_000)
        disabled = bool(response.get("ok"))
    except service_ipc.ServiceUnavailable:
        disabled = False
    if not disabled:
        # A crashed, stopped, or unhealthy service may have left Windows
        # pointing at the local resolver. The elevated uninstaller can still
        # restore the saved adapter configuration before removing it.
        store = SettingsStore()
        settings = store.load()
        snapshot = settings.get("dns_snapshot") or []
        if snapshot:
            restore_dns(snapshot)
        if settings.get("browser_dns_protection"):
            browser_control.restore_policies(
                settings.get("browser_policy_backup", {})
            )
        settings["protection_enabled"] = False
        settings["dns_snapshot"] = []
        settings["browser_dns_protection"] = False
        settings["browser_policy_backup"] = {}
        store.save(settings)
    try:
        manager, service = _service_handle(
            win32service.SERVICE_STOP | win32service.DELETE | win32service.SERVICE_QUERY_STATUS
        )
    except pywintypes.error as exc:
        if exc.winerror == 1060:
            return
        raise
    try:
        try:
            win32service.ControlService(service, win32service.SERVICE_CONTROL_STOP)
        except pywintypes.error as exc:
            if exc.winerror != 1062:
                raise
        win32service.DeleteService(service)
    finally:
        win32service.CloseServiceHandle(service)
        win32service.CloseServiceHandle(manager)


def main(argv=None):
    parser = argparse.ArgumentParser(description=SERVICE_DISPLAY_NAME)
    parser.add_argument("--install", action="store_true")
    parser.add_argument("--uninstall", action="store_true")
    parser.add_argument("--console", action="store_true")
    args = parser.parse_args(argv)
    if args.install:
        install_service()
        return 0
    if args.uninstall:
        uninstall_service()
        return 0
    if args.console:
        core = GuardCore()
        try:
            core.run()
        except KeyboardInterrupt:
            core.stop()
        return 0
    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(GuardService)
    servicemanager.StartServiceCtrlDispatcher()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
