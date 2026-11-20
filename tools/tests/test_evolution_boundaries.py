import json
from pathlib import Path
import shutil
import tempfile
import unittest

from tools.evolution.boundaries import (
    ROOT, MANIFEST, AUDIT_MANIFEST, SETTINGS_PATH, SETTINGS_EXTENSION, check
)


class FrozenBoundaryTest(unittest.TestCase):
    def test_current_dns_existing_vpn_permissions_and_ui_bytes_are_unchanged(self):
        self.assertEqual(check()['files_checked'], 109)
        self.assertTrue(check()['unchanged'])

    def test_mutation_inventory_and_baseline_tampering_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = json.loads((ROOT / MANIFEST).read_text())
            for name in [MANIFEST, AUDIT_MANIFEST, *manifest['files']]:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, path)
            self.assertTrue(check(root)['unchanged'])
            settings = root / SETTINGS_PATH
            original_settings = settings.read_bytes()
            self.assertIn(SETTINGS_EXTENSION, original_settings)
            settings.write_bytes(original_settings.replace(b'EvolutionSettingsCard()', b'UnreviewedSettingsCard()'))
            with self.assertRaisesRegex(ValueError, 'boundary changed'):
                check(root)
            settings.write_bytes(original_settings + SETTINGS_EXTENSION)
            with self.assertRaisesRegex(ValueError, 'boundary changed'):
                check(root)
            settings.write_bytes(original_settings)
            target = root / 'app/src/main/AndroidManifest.xml'
            original = target.read_bytes()
            target.write_bytes(original + b'<!-- unexpected permission/service change -->')
            with self.assertRaisesRegex(ValueError, 'boundary changed'):
                check(root)
            target.write_bytes(original)
            added = root / 'dns/unreviewed.js'
            added.write_text('unreviewed DNS change')
            with self.assertRaisesRegex(ValueError, 'inventory changed'):
                check(root)
            added.unlink()
            target.unlink()
            with self.assertRaises((ValueError, OSError)):
                check(root)
            target.write_bytes(original)
            manifest['base_commit'] = '0' * 40
            (root / MANIFEST).write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, 'baseline'):
                check(root)

    def test_a_change_outside_both_reviewed_baselines_is_rejected(self):
        # A file may match the original audit baseline or the reviewed 2026-11 fix
        # baseline, and nothing else: an unreviewed edit to a frozen file still fails.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = json.loads((ROOT / MANIFEST).read_text())
            for name in [MANIFEST, AUDIT_MANIFEST, *manifest['files']]:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, path)
            self.assertTrue(check(root)['unchanged'])
            target = root / 'app.js'
            target.write_bytes(target.read_bytes() + b'\n// unreviewed change\n')
            with self.assertRaisesRegex(ValueError, 'boundary changed: app.js'):
                check(root)

    def test_the_audit_baseline_must_track_the_same_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = json.loads((ROOT / MANIFEST).read_text())
            audited = json.loads((ROOT / AUDIT_MANIFEST).read_text())
            for name in [MANIFEST, AUDIT_MANIFEST, *manifest['files']]:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, path)
            audited['files'].pop(next(iter(audited['files'])))
            (root / AUDIT_MANIFEST).write_text(json.dumps(audited))
            with self.assertRaisesRegex(ValueError, 'same protected inventory'):
                check(root)


if __name__ == '__main__':
    unittest.main()
