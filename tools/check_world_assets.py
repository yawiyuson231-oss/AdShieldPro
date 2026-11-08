#!/usr/bin/env python3
"""Verify actual APKs contain the complete, byte-identical shared World Monitor runtime."""
from pathlib import Path
from zipfile import ZipFile, BadZipFile
import sys

ROOT = Path(__file__).resolve().parents[1]
PREFIX = "assets/world-monitor/"
FIXED = [
    "ui/dom.js", "ui/icons.js", "ui/theme.css", "ui/world.css",
    "security/storage.js", "security/sha256.js", "assets/world-land.svg",
    "assets/country-boundaries.json", "assets/country-data-license.txt",
]
EXPECTED = sorted(FIXED + [str(p.relative_to(ROOT)) for p in (ROOT / "world").rglob("*") if p.is_file()])


def check(path: str) -> None:
    with ZipFile(path) as apk:
        actual = {name[len(PREFIX):] for name in apk.namelist() if name.startswith(PREFIX) and not name.endswith("/")}
        missing = set(EXPECTED) - actual
        extra = actual - set(EXPECTED)
        if missing or extra:
            raise ValueError(f"World Monitor asset mismatch: missing={sorted(missing)}, extra={sorted(extra)}")
        total = 0
        for name in EXPECTED:
            expected = (ROOT / name).read_bytes()
            if apk.read(PREFIX + name) != expected:
                raise ValueError(f"Packaged {name} differs from the tested shared runtime")
            total += len(expected)
        print(f"{Path(path).name}: {len(EXPECTED)} World Monitor assets, {total:,} bytes, all identical to reviewed source; no test fixtures")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("Usage: python3 tools/check_world_assets.py path/to/debug.apk [path/to/release.apk]")
    try:
        for path in sys.argv[1:]:
            check(path)
    except (OSError, BadZipFile, ValueError, KeyError) as error:
        sys.exit(f"World Monitor packaging failed: {error}")
