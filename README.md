# Web Guard

<p align="center">
  <img src="./assets/web-guard.png?raw=1" alt="Web Guard" width="96" height="96">
</p>

Web Guard is a focused Windows application that blocks known dangerous domains locally. It covers malware and ransomware, phishing, scams and fraud, deceptive or abusive sites, redirect threats, and cryptojacking or cryptocurrency scams.

## Set up Web Guard from GitHub's source ZIP

This repository distributes source code only. It does not provide a prebuilt
application, installer download, or direct download link.

1. On the repository page, select **Code**, then **Download ZIP**.
2. In File Explorer, right-click the ZIP, select **Extract All**, and open the
   extracted `Web-Guard` folder.
3. Install these prerequisites if they are not already available:
   - 64-bit Windows 10 or Windows 11;
   - 64-bit Python 3.12; and
   - Microsoft Edge WebView2 Runtime.
4. Open the extracted folder in Windows Terminal or PowerShell and run:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m web_guard
```

That starts Web Guard directly from source. Source mode can inspect the bundled
database and interface, but system-wide protection requires its packaged
Windows service.

For the complete installed application, build the service and installer
locally from the same extracted folder:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
winget install --id JRSoftware.InnoSetup --exact
powershell -ExecutionPolicy Bypass -File .\build.ps1
.\dist\Web-Guard-Setup.exe
```

Approve the one-time Windows administrator prompt from the locally built
installer. It installs Web Guard and its protection service under Program
Files. Because the local build is unsigned, Windows may display an
unknown-publisher warning.

## What this first version does

- Runs a small local DNS filtering service with administrator permission.
- Checks domains against a bundled, indexed database of more than three million unique entries.
- Stores no browsing history. Only aggregate counters for the current service session are kept in memory.
- Lets the user turn individual protection categories on or off.
- Supports explicit allow rules and user-added block rules.
- Forwards allowed requests through certificate-verified Cloudflare DNS over HTTPS by default, with the original Windows resolver available as an explicit alternative.
- Automatically disables and locks separate browser Secure DNS while protection is active for Google Chrome, Microsoft Edge, Brave, and Mozilla Firefox so those browsers cannot silently bypass the local filter. The original policies are restored when protection turns off.
- Detects active VPNs, Windows DNS policy rules (NRPT), and default-route adapters whose DNS no longer points at Web Guard, then reports the limitation instead of claiming full coverage.
- Shows a prominent Protection-page warning when a detected system or browser VPN may bypass website blocking.
- Captures the active Windows DNS configuration before activation and restores it when protection is disabled, the service stops, or the app is uninstalled.
- Backs up browser policies before changing them and restores only values that Web Guard still owns. Existing administrator policies are never overwritten.
- Makes no network request to download a threat list while the user browses.

The raw source snapshots are in `data/blocklists/raw`. `tools/build_blocklist_db.py` validates, normalizes, de-duplicates and compiles them into `data/guard.db`. The installer ships the compiled database; the raw files remain in the source project for inspection.

## Important limitations

Block lists reduce exposure; they do not prove that an unlisted website is safe. Web Guard is not antivirus software and does not guarantee that a website, download, message, or device is safe. A newly created malicious domain may not be listed yet. VPN clients with their own DNS, unsupported browser-level secure DNS, Windows DNS policy rules, direct IP connections, and already-open or cached connections can bypass a Windows DNS filter. Web Guard detects common VPN and DNS-routing conflicts, but detection cannot prove that every third-party network client is compatible. Opera and Vivaldi are identified when installed but require a manual Secure DNS check because Web Guard does not write undocumented browser policies. Opera's built-in browser VPN carries its browsing and DNS inside Opera's tunnel; Web Guard reports that bypass and does not disable the VPN. Redirect-category blocking may occasionally affect legitimate redirect or proxy services; the allow list exists for that reason.

## DNS privacy and browser control

Encrypted DNS protects allowed DNS questions between the PC and Cloudflare from plain-text inspection on the local network. It does not make Web Guard a VPN: the router or internet provider can still observe connection metadata and destination IP addresses, and websites still see the connection. Cloudflare receives allowed DNS questions when its encrypted resolver is selected. Choosing **Original system DNS** sends allowed questions to the resolver Windows was using before protection started.

When protection is enabled, browser control writes documented machine policies for Chrome, Edge, Brave, and Firefox. Web Guard records the previous values before writing anything, refuses to replace a conflicting administrator policy, and restores the saved values when the control or protection is disabled or the app is uninstalled. Browsers should be restarted after changing the control.

The bundled compatibility override permits `sec-tunnel.com` and `myip.surfeasy.com` because those legitimate Opera VPN endpoints are present in an upstream malware snapshot. This prevents Web Guard from breaking Opera's VPN connection. A user-added custom block rule still takes precedence over the compatibility override.

## Development

Requires Windows 10 or 11 and Python 3.12.

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest -q
$env:WEB_GUARD_DEBUG='1'
.\.venv\Scripts\python.exe -m web_guard
```

Build the installer with:

```powershell
.\build.ps1
```

The local build output is `dist\Web-Guard-Setup.exe`. The unpacked
PyInstaller staging directory is removed automatically so it cannot be mistaken
for an installed, service-enabled application.

Installing the app requires one UAC approval because the DNS service and application are installed under Program Files. Protection starts off and remains the user's choice. After installation, open Web Guard from its desktop or Start-menu shortcut rather than from the source project.

## Data source

The bundled threat feeds are downloaded from [The Block List Project](https://github.com/blocklistproject/Lists). Each downloaded file identifies its list, snapshot date and MIT license in its header. User-entered domain endings are checked against a bundled snapshot of IANA's authoritative TLD list. See `THIRD_PARTY_NOTICES.md`.

## License

Copyright © 2026 Zuyis. Web Guard 0.1.0 and later are provided under the
[PolyForm Noncommercial License 1.0.0](LICENSE).

You may download, use, inspect, modify, and share Web Guard for personal and
other noncommercial purposes permitted by that license. You may not sell it,
charge for access to it, include it in a paid product or subscription, offer
it as part of a paid service, or otherwise use it commercially without
separate written permission from Zuyis.

The [commercial-use policy](COMMERCIAL_USE.md) gives concrete prohibited and
permitted examples. The [trademark policy](TRADEMARKS.md) reserves Zuyis™,
Web Guard™, the globe logo, and the project's visual identity; modified forks
must use a different name and logo and must not imply Zuyis endorsement.

Web Guard is therefore **free and source-available, not OSI open source**.
This summary is explanatory; the [LICENSE](LICENSE) text controls.

Third-party data and dependency notices are listed in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Security issues should be
reported through the process in [SECURITY.md](SECURITY.md).
