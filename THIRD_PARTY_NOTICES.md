# Third-party notices

## The Block List Project lists

Web Guard contains downloaded snapshots of the Abuse, Crypto, Fraud, Malware, Phishing, Ransomware, Redirect and Scam domain lists from The Block List Project.

- Project: https://github.com/blocklistproject/Lists
- Download format: `https://blocklistproject.github.io/Lists/alt-version/{list}-nl.txt`
- License declared by each bundled snapshot: MIT
- Copyright: the respective list maintainers and contributors

The original headers are preserved in `data/blocklists/raw/*.txt`. The compiled `data/guard.db` is a normalized and de-duplicated representation of those snapshots.

MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## IANA root-zone TLD list

Web Guard bundles `data/iana-tlds.txt`, a snapshot of the ASCII top-level-domain list published by the Internet Assigned Numbers Authority. It is used only to reject user input whose final domain label is not delegated in the DNS root zone.

- Registry: https://www.iana.org/domains/root/db
- Snapshot: https://data.iana.org/TLD/tlds-alpha-by-domain.txt
- The upstream version and update time are preserved in the file's first line.

## Optional external DNS service

Cloudflare DNS over HTTPS is the default upstream for allowed DNS requests.
This is an external network service, not bundled code or data. Users can select
the original Windows DNS resolver in Web Guard before enabling protection.
Cloudflare's own service terms and privacy commitments govern requests sent to
that resolver.

## Python dependencies

The distributable also includes dnslib (BSD), pywebview (BSD-3-Clause), pywin32 (PSF), CPython (PSF), pythonnet (MIT), clr-loader (MIT), cffi (MIT-0), pycparser (BSD-3-Clause), setuptools (MIT), tomli (MIT), Microsoft WebView2 components, and a PyInstaller bootloader built under PyInstaller's GPL license exception. Their respective upstream license terms remain controlling for those components.
