from web_guard.windows_chrome import (
    REQUIRED_STYLES, WS_CAPTION, WS_MAXIMIZEBOX, WS_THICKFRAME, native_style,
)


def test_custom_window_keeps_shell_behavior_without_native_frame():
    style = native_style(WS_CAPTION | WS_MAXIMIZEBOX | WS_THICKFRAME)
    assert style & REQUIRED_STYLES == REQUIRED_STYLES
    assert not style & WS_CAPTION
    assert not style & WS_MAXIMIZEBOX
    assert not style & WS_THICKFRAME
