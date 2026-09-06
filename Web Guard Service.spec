# Build the privileged, windowless Web Guard DNS filtering service.

from pathlib import Path


root = Path(SPECPATH)

a = Analysis(
    [str(root / "web_guard_service_launcher.py")],
    pathex=[str(root)],
    binaries=[],
    datas=[
        (str(root / "data" / "guard.db"), "data"),
        (str(root / "data" / "iana-tlds.txt"), "data"),
    ],
    hiddenimports=[
        "pywintypes", "servicemanager", "win32event", "win32file",
        "win32pipe", "win32security", "win32service", "win32serviceutil",
        "win32timezone", "dnslib",
    ],
    hookspath=[], hooksconfig={}, runtime_hooks=[], excludes=[],
    noarchive=False, optimize=1,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz, a.scripts, [], exclude_binaries=True,
    name="Web Guard Service", debug=False, bootloader_ignore_signals=False,
    strip=False, upx=True, console=False, disable_windowed_traceback=False,
    argv_emulation=False, target_arch=None, codesign_identity=None,
    entitlements_file=None,
    icon=str(root / "assets" / "web-guard.ico"),
    version=str(root / "assets" / "web-guard-service-version.txt"),
    uac_admin=False,
)

coll = COLLECT(
    exe, a.binaries, a.datas, strip=False, upx=True,
    upx_exclude=[], name="Web Guard Service",
)
