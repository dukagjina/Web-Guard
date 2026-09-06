"""Download and validate an authoritative IANA top-level-domain snapshot."""

from __future__ import annotations

import os
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
URL = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
OUTPUT = ROOT / "data" / "iana-tlds.txt"


def main() -> int:
    request = urllib.request.Request(URL, headers={"User-Agent": "Web-Guard-build/0.1"})
    with urllib.request.urlopen(request, timeout=30) as response:
        content = response.read().decode("ascii")
    lines = content.splitlines()
    delegated = {line for line in lines if line and not line.startswith("#")}
    if not lines or not lines[0].startswith("# Version "):
        raise RuntimeError("IANA TLD response did not contain a version header")
    if len(delegated) < 1000 or not {"COM", "NET", "ORG", "UK"}.issubset(delegated):
        raise RuntimeError("IANA TLD response failed its integrity checks")
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    temporary = OUTPUT.with_suffix(OUTPUT.suffix + ".tmp")
    temporary.write_text(content.rstrip() + "\n", encoding="ascii", newline="\n")
    os.replace(temporary, OUTPUT)
    print(f"Saved {len(delegated):,} delegated TLDs to {OUTPUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
