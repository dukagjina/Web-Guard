"""Local-only IPC between Web Guard and its privileged Windows service."""

from __future__ import annotations

import json
import time

import pywintypes
import win32con
import win32event
import win32file
import win32pipe
import win32security


PIPE_NAME = r"\\.\pipe\Web Guard Service"
PROTOCOL_VERSION = 1
MAX_MESSAGE = 512 * 1024
ERROR_IO_PENDING = 997


class ServiceUnavailable(RuntimeError):
    pass


def _remaining_ms(deadline):
    return max(1, int((deadline - time.monotonic()) * 1000))


def _wait_for_io(handle, overlapped, deadline, timeout_message):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        try:
            win32file.CancelIo(handle)
        except pywintypes.error:
            pass
        raise ServiceUnavailable(timeout_message)
    result = win32event.WaitForSingleObject(
        overlapped.hEvent, max(1, int(remaining * 1000))
    )
    if result == win32event.WAIT_TIMEOUT:
        try:
            win32file.CancelIo(handle)
        except pywintypes.error:
            pass
        raise ServiceUnavailable(timeout_message)
    if result != win32event.WAIT_OBJECT_0:
        raise ServiceUnavailable("Web Guard Service communication failed")
    return win32file.GetOverlappedResult(handle, overlapped, False)


def _write_with_deadline(handle, value, deadline):
    overlapped = pywintypes.OVERLAPPED()
    event = win32event.CreateEvent(None, True, False, None)
    overlapped.hEvent = event
    try:
        result, _ = win32file.WriteFile(handle, value, overlapped)
        if result not in (0, ERROR_IO_PENDING):
            raise ServiceUnavailable("Web Guard Service could not receive the request")
        _wait_for_io(
            handle, overlapped, deadline,
            "Web Guard Service timed out while receiving the request",
        )
    finally:
        win32file.CloseHandle(event)


def _read_with_deadline(handle, deadline):
    overlapped = pywintypes.OVERLAPPED()
    event = win32event.CreateEvent(None, True, False, None)
    overlapped.hEvent = event
    try:
        result, buffer = win32file.ReadFile(handle, MAX_MESSAGE, overlapped)
        if result not in (0, ERROR_IO_PENDING):
            raise ServiceUnavailable("Web Guard Service did not answer correctly")
        received = _wait_for_io(
            handle, overlapped, deadline,
            "Web Guard Service did not answer in time",
        )
        return bytes(buffer[:received])
    finally:
        win32file.CloseHandle(event)


def _security_attributes():
    descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)",
        win32security.SDDL_REVISION_1,
    )
    attributes = pywintypes.SECURITY_ATTRIBUTES()
    attributes.SECURITY_DESCRIPTOR = descriptor
    return attributes


def request(command, payload=None, timeout_ms=5000):
    encoded = json.dumps({
        "version": PROTOCOL_VERSION,
        "command": command,
        "payload": payload or {},
    }, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(encoded) > MAX_MESSAGE:
        raise ValueError("Service request is too large")
    deadline = time.monotonic() + max(timeout_ms, 1) / 1000
    handle = None
    last_error = None
    while time.monotonic() < deadline:
        try:
            win32pipe.WaitNamedPipe(PIPE_NAME, min(250, _remaining_ms(deadline)))
            handle = win32file.CreateFile(
                PIPE_NAME, win32con.GENERIC_READ | win32con.GENERIC_WRITE,
                0, None, win32con.OPEN_EXISTING,
                win32file.FILE_FLAG_OVERLAPPED, None,
            )
            break
        except pywintypes.error as exc:
            last_error = exc
            if exc.winerror not in (2, 231):
                break
            time.sleep(0.025)
    if handle is None:
        raise ServiceUnavailable("Web Guard Service is not running") from last_error
    try:
        win32pipe.SetNamedPipeHandleState(handle, win32pipe.PIPE_READMODE_MESSAGE, None, None)
        _write_with_deadline(handle, encoded, deadline)
        raw = _read_with_deadline(handle, deadline)
        response = json.loads(raw.decode("utf-8"))
        if not isinstance(response, dict):
            raise ValueError("Invalid service response")
        return response
    except (pywintypes.error, ValueError, json.JSONDecodeError) as exc:
        raise ServiceUnavailable("Web Guard Service did not answer correctly") from exc
    finally:
        win32file.CloseHandle(handle)


class PipeServer:
    def __init__(self):
        self._pipe = None

    def _create(self):
        return win32pipe.CreateNamedPipe(
            PIPE_NAME,
            win32pipe.PIPE_ACCESS_DUPLEX,
            win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE |
            win32pipe.PIPE_WAIT | getattr(win32pipe, "PIPE_REJECT_REMOTE_CLIENTS", 0x8),
            win32pipe.PIPE_UNLIMITED_INSTANCES,
            MAX_MESSAGE, MAX_MESSAGE, 1000, _security_attributes(),
        )

    @staticmethod
    def _serve(pipe, handler):
        try:
            _, raw = win32file.ReadFile(pipe, MAX_MESSAGE)
            value = json.loads(raw.decode("utf-8"))
            if not isinstance(value, dict) or value.get("version") != PROTOCOL_VERSION:
                response = {"ok": False, "error": "Unsupported service request"}
            else:
                response = handler(value.get("command"), value.get("payload") or {})
            output = json.dumps(response, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            win32file.WriteFile(pipe, output[:MAX_MESSAGE])
            win32file.FlushFileBuffers(pipe)
        except (pywintypes.error, ValueError, json.JSONDecodeError):
            pass
        finally:
            try:
                win32pipe.DisconnectNamedPipe(pipe)
            except pywintypes.error:
                pass
            win32file.CloseHandle(pipe)

    def serve(self, stop_event, handler):
        import threading
        while not stop_event.is_set():
            pipe = self._create()
            self._pipe = pipe
            try:
                try:
                    win32pipe.ConnectNamedPipe(pipe, None)
                except pywintypes.error as exc:
                    if exc.winerror != 535:
                        raise
                if stop_event.is_set():
                    win32file.CloseHandle(pipe)
                    break
                threading.Thread(target=self._serve, args=(pipe, handler), daemon=True).start()
            except pywintypes.error:
                try:
                    win32file.CloseHandle(pipe)
                except pywintypes.error:
                    pass
            finally:
                self._pipe = None

    def wake(self):
        try:
            request("ping", timeout_ms=200)
        except ServiceUnavailable:
            pass
