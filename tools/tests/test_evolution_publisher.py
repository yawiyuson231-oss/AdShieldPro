"""Harmless ephemeral test keys only; these are never publisher credentials."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from tools.evolution.publisher import payload, sign, verified_sequence


@unittest.skipUnless(shutil.which('openssl'), 'OpenSSL required for signing tests')
class EvolutionPublisherTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        cls.private = cls.root / 'test-only.pem'
        cls.public = cls.root / 'test-only-public.pem'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048',
                        '-out', str(cls.private)], check=True, capture_output=True)
        subprocess.run(['openssl', 'pkey', '-in', str(cls.private), '-pubout', '-out', str(cls.public)],
                       check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def manifest(self):
        return dict(keyId='test-only', sequence=1, issuedAt=100, expiresAt=200,
                    minAppVersion=1, maxAppVersion=100,
                    indicators=[dict(sha256='a' * 64, category='malware')])

    def test_round_trip_signed_sequence(self):
        packet = sign(self.manifest(), self.private, self.public, 150)
        self.assertEqual(1, verified_sequence(packet, self.public))

    def test_rejects_replay_and_accepts_later_sequence(self):
        manifest = self.manifest()
        previous = sign(manifest, self.private, self.public, 150)
        with self.assertRaises(ValueError):
            sign(manifest, self.private, self.public, 150, previous)
        manifest['sequence'] = 2
        packet = sign(manifest, self.private, self.public, 150, previous)
        self.assertEqual(2, verified_sequence(packet, self.public))

    def test_rejects_tampered_previous(self):
        packet = bytearray(sign(self.manifest(), self.private, self.public, 150))
        packet[-1] ^= 1
        with self.assertRaises(subprocess.CalledProcessError):
            verified_sequence(bytes(packet), self.public)

    def test_rejects_expired_future_and_unbounded_validity(self):
        for update in (dict(expiresAt=150), dict(issuedAt=151), dict(expiresAt=700000)):
            with self.subTest(update=update), self.assertRaises(ValueError):
                payload(self.manifest() | update, 150)

    def test_rejects_executable_unknown_duplicate_and_invalid_data(self):
        for entries in ([dict(sha256='a' * 64, category='execute')],
                        [dict(sha256='invalid', category='malware')],
                        self.manifest()['indicators'] * 2, []):
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                payload(self.manifest() | dict(indicators=entries), 150)
        with self.assertRaises(ValueError):
            payload(self.manifest() | dict(script='anything'), 150)

    def test_strict_integer_and_compatibility_checks(self):
        for update in (dict(sequence=True), dict(sequence=0), dict(minAppVersion=101),
                       dict(maxAppVersion=2**63), dict(issuedAt=-1)):
            with self.subTest(update=update), self.assertRaises(ValueError):
                payload(self.manifest() | update, 150)

    def test_truncated_or_trailing_packet_is_not_verified(self):
        packet = sign(self.manifest(), self.private, self.public, 150)
        for invalid in (b'', packet[:4], packet[:-1], packet + b'x'):
            with self.subTest(length=len(invalid)), self.assertRaises((ValueError, subprocess.CalledProcessError)):
                verified_sequence(invalid, self.public)


if __name__ == '__main__':
    unittest.main()
