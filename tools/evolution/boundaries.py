"""Verify frozen DNS/VPN/UI files against the audited starting revision."""
import argparse
import hashlib
import json
from pathlib import Path

from .artifacts import load_json

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = 'tools/evolution/boundaries.json'
BASE = '4fbc131ca4f4d0bd4e93eca2f73013e9cd867452'
DIRECTORIES = (
    'app/src/main/java/com/adshield/pro/engine/dns',
    'app/src/main/java/com/adshield/pro/engine/filter',
    'app/src/main/java/com/adshield/pro/service',
    'app/src/main/java/com/adshield/pro/ui/screens',
    'app/src/main/java/com/adshield/pro/ui/components',
    'app/src/main/java/com/adshield/pro/ui/theme',
    'app/src/main/res', 'dns', 'ui',
)
FILES = ('app/src/main/AndroidManifest.xml', 'app/src/main/java/com/adshield/pro/MainActivity.kt',
         'app.js', 'engine.js', 'index.html')


def check(root=ROOT):
    root = Path(root)
    manifest = load_json(root / MANIFEST)
    if (manifest.get('base_commit') != BASE or type(manifest.get('schema')) is not int
            or manifest.get('schema') != 1):
        raise ValueError('unexpected boundary baseline')
    paths = set(FILES)
    for directory in DIRECTORIES:
        paths.update(path.relative_to(root).as_posix() for path in (root / directory).rglob('*') if path.is_file())
    expected = manifest['files']
    if set(expected) != paths:
        raise ValueError('protected file inventory changed')
    for path in sorted(paths):
        if hashlib.sha256((root / path).read_bytes()).hexdigest() != expected[path]:
            raise ValueError(f'DNS/VPN/UI boundary changed: {path}')
    return dict(unchanged=True, files_checked=len(paths), base_commit=BASE,
                limitations='Static byte equality in declared boundaries, not end-to-end DNS proof.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    try:
        print(json.dumps(check(), indent=2))
    except (ValueError, KeyError, TypeError, OSError) as error:
        parser.exit(1, f'Protected boundary gate rejected: {error}\n')
