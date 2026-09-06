"""Native Windows behavior for Web Guard's custom frameless window."""

from __future__ import annotations

import ctypes
from ctypes import wintypes


GWL_STYLE = -16
WS_CAPTION = 0x00C00000
WS_SYSMENU = 0x00080000
WS_THICKFRAME = 0x00040000
WS_MINIMIZEBOX = 0x00020000
WS_MAXIMIZEBOX = 0x00010000
WM_SYSCOMMAND = 0x0112
SC_MINIMIZE = 0xF020
DWMWA_TRANSITIONS_FORCEDISABLED = 3
APP_USER_MODEL_ID = "Zuyis.WebGuard"

SWP_NOSIZE = 0x0001
SWP_NOMOVE = 0x0002
SWP_NOZORDER = 0x0004
SWP_NOACTIVATE = 0x0010
SWP_FRAMECHANGED = 0x0020
SWP_SHOWWINDOW = 0x0040
FRAME_REFRESH_FLAGS = SWP_NOSIZE | SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED
MOVE_FLAGS = SWP_NOSIZE | SWP_NOZORDER | SWP_SHOWWINDOW
RDW_INVALIDATE = 0x0001
RDW_ERASE = 0x0004
RDW_ALLCHILDREN = 0x0080
RDW_UPDATENOW = 0x0100
REDRAW_FLAGS = RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN | RDW_UPDATENOW
REQUIRED_STYLES = WS_SYSMENU | WS_MINIMIZEBOX

_user32 = ctypes.windll.user32
_dwmapi = ctypes.windll.dwmapi
_shell32 = ctypes.windll.shell32

_get_window_long = _user32.GetWindowLongPtrW
_get_window_long.argtypes = [wintypes.HWND, ctypes.c_int]
_get_window_long.restype = ctypes.c_ssize_t
_set_window_long = _user32.SetWindowLongPtrW
_set_window_long.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_ssize_t]
_set_window_long.restype = ctypes.c_ssize_t
_post_message = _user32.PostMessageW
_post_message.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
_post_message.restype = wintypes.BOOL
_set_window_pos = _user32.SetWindowPos
_set_window_pos.argtypes = [wintypes.HWND, wintypes.HWND, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, wintypes.UINT]
_set_window_pos.restype = wintypes.BOOL
_redraw_window = _user32.RedrawWindow
_redraw_window.argtypes = [wintypes.HWND, ctypes.c_void_p, ctypes.c_void_p, wintypes.UINT]
_redraw_window.restype = wintypes.BOOL
_dwm_set_window_attribute = _dwmapi.DwmSetWindowAttribute
_dwm_set_window_attribute.argtypes = [wintypes.HWND, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD]
_dwm_set_window_attribute.restype = ctypes.c_long
_set_process_app_id = _shell32.SetCurrentProcessExplicitAppUserModelID
_set_process_app_id.argtypes = [wintypes.LPCWSTR]
_set_process_app_id.restype = ctypes.c_long


def configure_process():
    try:
        return int(_set_process_app_id(APP_USER_MODEL_ID)) == 0
    except (AttributeError, OSError, TypeError, ValueError):
        return False


def _window_handle(window):
    handle = getattr(getattr(window, "native", None), "Handle", None)
    if handle is None:
        return 0
    try:
        if hasattr(handle, "ToInt64"):
            return int(handle.ToInt64())
        if hasattr(handle, "ToInt32"):
            return int(handle.ToInt32())
        return int(handle)
    except (TypeError, ValueError, OverflowError):
        return 0


def native_style(style):
    return ((int(style) | REQUIRED_STYLES) & ~WS_CAPTION &
            ~WS_MAXIMIZEBOX & ~WS_THICKFRAME)


def configure_window(window):
    hwnd = _window_handle(window)
    if not hwnd:
        return False
    try:
        current = int(_get_window_long(hwnd, GWL_STYLE))
        desired = native_style(current)
        if desired != current:
            ctypes.set_last_error(0)
            previous = int(_set_window_long(hwnd, GWL_STYLE, desired))
            if previous == 0 and ctypes.get_last_error():
                return False
        if not _set_window_pos(hwnd, 0, 0, 0, 0, 0, FRAME_REFRESH_FLAGS):
            return False
        _redraw_window(hwnd, None, None, REDRAW_FLAGS)
        disabled = wintypes.BOOL(False)
        _dwm_set_window_attribute(
            hwnd, DWMWA_TRANSITIONS_FORCEDISABLED,
            ctypes.byref(disabled), ctypes.sizeof(disabled),
        )
        applied = int(_get_window_long(hwnd, GWL_STYLE))
        return (applied & REQUIRED_STYLES) == REQUIRED_STYLES
    except (AttributeError, OSError, TypeError, ValueError):
        return False


def minimize_window(window):
    hwnd = _window_handle(window)
    if not hwnd:
        return False
    try:
        return bool(_post_message(hwnd, WM_SYSCOMMAND, SC_MINIMIZE, 0))
    except (AttributeError, OSError, TypeError, ValueError):
        return False


def move_window(window, x, y):
    hwnd = _window_handle(window)
    if not hwnd:
        return False
    try:
        scale = float(getattr(getattr(window, "native", None), "_scale", 1) or 1)
        return bool(_set_window_pos(
            hwnd, 0, round(float(x) * scale), round(float(y) * scale),
            0, 0, MOVE_FLAGS,
        ))
    except (AttributeError, OSError, TypeError, ValueError, OverflowError):
        return False
