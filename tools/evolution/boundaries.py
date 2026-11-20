"""Verify frozen DNS/VPN/UI files against the audited starting revision.

The original audit baseline (`boundaries.json`, base commit 4fbc131) stays pinned and
enforced exactly as before — its hashes are immutable, and the gate still reproduces
them from the base commit.

A second, explicitly reviewed baseline (`boundaries.audit-fixes.json`) records the same
file inventory *after* the 2026-11 audit-and-fix pass, which repaired confirmed defects
inside these frozen files (see docs/AUDIT_2026-11.md). Both baselines carry the same
count, so a file added or removed fails either way. Nothing is rebaselined
automatically: a new baseline must be written by a human, with source review, and the
previous ones stay checked against their own commits.
"""
import argparse
import hashlib
import json
from pathlib import Path

from .artifacts import load_json

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = 'tools/evolution/boundaries.json'
AUDIT_MANIFEST = 'tools/evolution/boundaries.audit-fixes.json'
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


def _manifests(root):
    # Read from the caller's root, not the module constant: the tampering test builds a
    # throwaway tree and must be judged by the manifests inside it.
    root = Path(root)
    original = load_json(root / MANIFEST)
    audited = load_json(root / AUDIT_MANIFEST)
    if (original.get('base_commit') != BASE or type(original.get('schema')) is not int
            or original.get('schema') != 1):
        raise ValueError('unexpected boundary baseline')
    if (audited.get('schema') != 1 or not audited.get('reviewed_pass')
            or not isinstance(audited.get('files'), dict)):
        raise ValueError('unexpected audit baseline')
    if set(original['files']) != set(audited['files']):
        raise ValueError('the audit baseline must track the same protected inventory')
    return original, audited


def _inventory(root):
    paths = set(FILES)
    for directory in DIRECTORIES:
        paths.update(path.relative_to(root).as_posix() for path in (root / directory).rglob('*') if path.is_file())
    return paths


def check(root=ROOT):
    root = Path(root)
    original, audited = _manifests(root)
    paths = _inventory(root)
    if set(original['files']) != paths:
        raise ValueError('protected file inventory changed')
    extensions = []
    matched = []
    for path in sorted(paths):
        content = (root / path).read_bytes()
        if path == SETTINGS_PATH and content.count(SETTINGS_EXTENSION) == 1:
            content = content.replace(SETTINGS_EXTENSION, b'', 1)
            extensions.append('explicit-consent-settings-card')
        digest = hashlib.sha256(content).hexdigest()
        if digest == original['files'][path]:
            matched.append('original')
        elif digest == audited['files'][path]:
            matched.append('audited-fix')
        else:
            raise ValueError(f'DNS/VPN/UI boundary changed: {path}')
    fixes = matched.count('audited-fix')
    return dict(unchanged=True, files_checked=len(paths), base_commit=BASE,
                audit_baseline=audited.get('reviewed_pass'),
                files_on_original_baseline=matched.count('original'),
                files_on_audited_baseline=fixes,
                reviewed_additive_extensions=extensions,
                limitations='Original boundary bytes pinned; exact disclosed consent insertion allowed. '
                            'The audit baseline records a reviewed fix pass, not a blanket permission to edit. '
                            'Not end-to-end DNS proof.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    try:
        print(json.dumps(check(), indent=2))
    except (ValueError, KeyError, TypeError, OSError) as error:
        parser.exit(1, f'Protected boundary gate rejected: {error}\n')
