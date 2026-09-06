import re
import struct
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ReleaseConfigurationTests(unittest.TestCase):
    def test_release_versions_stay_aligned(self):
        package = (ROOT / "web_guard" / "__init__.py").read_text(encoding="utf-8")
        installer = (ROOT / "installer.iss").read_text(encoding="utf-8")
        app_version = (ROOT / "assets" / "web-guard-version.txt").read_text(encoding="utf-8")
        service_version = (ROOT / "assets" / "web-guard-service-version.txt").read_text(encoding="utf-8")

        version = re.search(
            r'__version__ = "([0-9]+\.[0-9]+\.[0-9]+)"', package,
        ).group(1)
        self.assertIn(f'#define MyAppVersion "{version}"', installer)
        self.assertIn(f"StringStruct('ProductVersion', '{version}')", app_version)
        self.assertIn(f"StringStruct('ProductVersion', '{version}')", service_version)

    def test_legal_documents_are_complete_and_packaged(self):
        installer = (ROOT / "installer.iss").read_text(encoding="utf-8")
        build = (ROOT / "build.ps1").read_text(encoding="utf-8")
        license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")

        self.assertIn("LicenseFile=LICENSE", installer)
        self.assertIn("# PolyForm Noncommercial License 1.0.0", license_text)
        self.assertIn("Required Notice: Copyright © 2026 Zuyis.", license_text)
        for document in (
            "README.md", "LICENSE", "COMMERCIAL_USE.md", "TRADEMARKS.md",
            "THIRD_PARTY_NOTICES.md", "SECURITY.md",
        ):
            self.assertIn(f'"{document}"', build)

    def test_shortcuts_use_a_versioned_icon_path(self):
        installer = (ROOT / "installer.iss").read_text(encoding="utf-8")

        self.assertIn(
            '#define MyAppIconName "web-guard-" + MyAppVersion + ".ico"',
            installer,
        )
        self.assertIn('DestName: "{#MyAppIconName}"', installer)
        self.assertEqual(
            installer.count('IconFilename: "{app}\\{#MyAppIconName}"'),
            2,
        )
        self.assertIn('UninstallDisplayIcon={app}\\{#MyAppIconName}', installer)
        self.assertIn('Type: files; Name: "{app}\\web-guard-*.ico"', installer)

    def test_official_icon_contains_all_windows_sizes(self):
        data = (ROOT / "assets" / "web-guard.ico").read_bytes()
        reserved, kind, count = struct.unpack_from("<HHH", data)
        self.assertEqual((reserved, kind), (0, 1))
        sizes = set()
        for index in range(count):
            width, height = struct.unpack_from("BB", data, 6 + index * 16)
            sizes.add((width or 256, height or 256))
        self.assertEqual(
            sizes,
            {(16, 16), (20, 20), (24, 24), (32, 32), (40, 40),
             (48, 48), (64, 64), (128, 128), (256, 256)},
        )

    def test_upgrade_removes_retired_license_history(self):
        installer = (ROOT / "installer.iss").read_text(encoding="utf-8")

        self.assertIn('Type: files; Name: "{app}\\LICENSE_HISTORY.md"', installer)
        self.assertNotIn(
            '"LICENSE_HISTORY.md"',
            (ROOT / "build.ps1").read_text(encoding="utf-8"),
        )

    def test_vpn_warning_and_page_cards_use_shared_design(self):
        html = (ROOT / "ui" / "index.html").read_text(encoding="utf-8")
        script = (ROOT / "ui" / "app.js").read_text(encoding="utf-8")
        styles = (ROOT / "ui" / "style.css").read_text(encoding="utf-8")

        self.assertIn('id="vpnWarning"', html)
        self.assertIn("vpnWarning.hidden = !vpnDetected", script)
        self.assertIn(
            ".threat-card, .exception-card, .about-grid article, .source-card",
            styles,
        )


if __name__ == "__main__":
    unittest.main()
