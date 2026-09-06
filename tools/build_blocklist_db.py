"""Compile downloaded Block List Project text feeds into one indexed database."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import sqlite3
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from web_guard.catalog import CATEGORY_BITS  # noqa: E402
from web_guard.domain_utils import normalize_domain  # noqa: E402


SOURCES = {
    "abuse": "abuse",
    "crypto": "crypto",
    "fraud": "scams",
    "malware": "malware",
    "phishing": "phishing",
    "ransomware": "malware",
    "redirect": "redirects",
    "scam": "scams",
}
HEADER_RE = re.compile(r"^#\s*([^:]+):\s*(.*)$")


def metadata_from_header(path: Path) -> dict[str, str]:
    result = {}
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if not line.startswith("#"):
                break
            match = HEADER_RE.match(line.strip())
            if match:
                result[match.group(1).strip().lower()] = match.group(2).strip()
    return result


def iter_domains(path: Path):
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            value = raw.strip()
            if not value or value.startswith("#"):
                continue
            try:
                yield normalize_domain(value)
            except ValueError:
                continue


def compile_database(raw_dir: Path, output: Path):
    missing = [name for name in SOURCES if not (raw_dir / f"{name}.txt").is_file()]
    if missing:
        raise SystemExit("Missing raw feeds: " + ", ".join(missing))
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    if temporary.exists():
        temporary.unlink()

    connection = sqlite3.connect(temporary)
    connection.executescript("""
        PRAGMA journal_mode=OFF;
        PRAGMA synchronous=OFF;
        PRAGMA temp_store=MEMORY;
        PRAGMA page_size=4096;
        CREATE TABLE domains (
            domain TEXT PRIMARY KEY,
            flags INTEGER NOT NULL
        ) WITHOUT ROWID;
        CREATE TABLE metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        ) WITHOUT ROWID;
    """)
    source_metadata = {}
    source_counts = {}
    try:
        for source_name, category in SOURCES.items():
            path = raw_dir / f"{source_name}.txt"
            bit = CATEGORY_BITS[category]
            count = 0
            batch = []
            for domain in iter_domains(path):
                batch.append((domain, bit))
                count += 1
                if len(batch) >= 10_000:
                    connection.executemany(
                        "INSERT INTO domains(domain, flags) VALUES(?, ?) "
                        "ON CONFLICT(domain) DO UPDATE SET flags=flags|excluded.flags",
                        batch,
                    )
                    batch.clear()
            if batch:
                connection.executemany(
                    "INSERT INTO domains(domain, flags) VALUES(?, ?) "
                    "ON CONFLICT(domain) DO UPDATE SET flags=flags|excluded.flags",
                    batch,
                )
            connection.commit()
            header = metadata_from_header(path)
            source_metadata[source_name] = {
                "file": path.name,
                "title": header.get("title", source_name.title()),
                "description": header.get("description", ""),
                "license": header.get("license", "MIT"),
                "last_modified": header.get("last modified", ""),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
            source_counts[source_name] = count
            print(f"{source_name}: {count:,}")

        unique_total = connection.execute("SELECT COUNT(*) FROM domains").fetchone()[0]
        category_counts = {}
        for name, bit in CATEGORY_BITS.items():
            category_counts[name] = connection.execute(
                "SELECT COUNT(*) FROM domains WHERE flags & ? != 0", (bit,)
            ).fetchone()[0]
        metadata = {
            "schema": 1,
            "built_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
            "unique_domains": unique_total,
            "category_counts": category_counts,
            "source_counts": source_counts,
            "sources": source_metadata,
        }
        connection.executemany(
            "INSERT INTO metadata(key, value) VALUES(?, ?)",
            [(key, json.dumps(value, separators=(",", ":"))) for key, value in metadata.items()],
        )
        connection.commit()
        connection.execute("VACUUM")
        connection.execute("PRAGMA optimize")
    finally:
        connection.close()
    os.replace(temporary, output)
    metadata_output = output.with_name(output.stem + "-metadata.json")
    metadata_temporary = metadata_output.with_suffix(metadata_output.suffix + ".tmp")
    metadata_temporary.write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    os.replace(metadata_temporary, metadata_output)
    print(f"Compiled {unique_total:,} unique domains -> {output}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw", type=Path, default=ROOT / "data" / "blocklists" / "raw")
    parser.add_argument("--output", type=Path, default=ROOT / "data" / "guard.db")
    args = parser.parse_args()
    compile_database(args.raw, args.output)
