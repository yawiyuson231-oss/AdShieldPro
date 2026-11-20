import json
from pathlib import Path
import shutil
import tempfile
import unittest

from tools.evolution.boundaries import ROOT, MANIFEST, check


class FrozenBoundaryTest(unittest.TestCase):
    def test_current_dns_existing_vpn_permissions_and_ui_bytes_are_unchanged(self):
        self.assertEqual(check()['files_checked'], 109)
        self.assertTrue(check()['unchanged'])

    def test_mutation_inventory_and_baseline_tampering_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = json.loads((ROOT / MANIFEST).read_text())
            for name in [MANIFEST, *manifest['files']]:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, path)
            self.assertTrue(check(root)['unchanged'])
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


if __name__ == '__main__':
    unittest.main()
