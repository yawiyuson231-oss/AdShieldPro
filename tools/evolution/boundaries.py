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


# User-authorized additive consent control. Original SettingsScreen bytes stay pinned;
# this exact insertion is the only exception, never a blanket UI rebaseline.
SETTINGS_PATH = 'app/src/main/java/com/adshield/pro/ui/screens/SettingsScreen.kt'
SETTINGS_EXTENSION = b'''        // BEGIN reviewed evolution settings extension
        item { com.adshield.pro.ui.evolution.EvolutionSettingsCard() }
        // END reviewed evolution settings extension

'''


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
    extensions = []
    for path in sorted(paths):
        content = (root / path).read_bytes()
        if path == SETTINGS_PATH and content.count(SETTINGS_EXTENSION) == 1:
            content = content.replace(SETTINGS_EXTENSION, b'', 1)
            extensions.append('explicit-consent-settings-card')
        if hashlib.sha256(content).hexdigest() != expected[path]:
            raise ValueError(f'DNS/VPN/UI boundary changed: {path}')
    return dict(unchanged=True, files_checked=len(paths), base_commit=BASE,
                reviewed_additive_extensions=extensions,
                limitations='Original boundary bytes pinned; exact disclosed consent insertion allowed. Not end-to-end DNS proof.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    try:
        print(json.dumps(check(), indent=2))
    except (ValueError, KeyError, TypeError, OSError) as error:
        parser.exit(1, f'Protected boundary gate rejected: {error}\n')
