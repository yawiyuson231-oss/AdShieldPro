"""Offline EVO1 signing tool. Private keys are file inputs, never generated or printed.

This validates packaging, not indicator truth. Use only after independent review.
"""
import argparse
import base64
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import time

PURPOSE = 'adshield-reviewed-apk-reputation-v1'
ENDPOINT = 'https://github.com/yawiyuson231-oss/AdShieldPro/releases/download/evolution-data/reputation.evo'
MAX_BYTES = 256 * 1024


def utf(text):
    # All schema strings are ASCII, identical to Java modified UTF-8 for these inputs.
    value = text.encode('ascii')
    if len(value) > 65535:
        raise ValueError('String too long')
    return struct.pack('>H', len(value)) + value


def payload(manifest, now):
    fields = {'keyId', 'sequence', 'issuedAt', 'expiresAt', 'minAppVersion', 'maxAppVersion', 'indicators'}
    if set(manifest) != fields or not re.fullmatch(r'[a-zA-Z0-9_-]{1,64}', manifest['keyId']):
        raise ValueError('Invalid manifest schema or key ID')
    numbers = [manifest[k] for k in ('sequence', 'issuedAt', 'expiresAt', 'minAppVersion', 'maxAppVersion')]
    if any(type(n) is not int or not 0 <= n < 2**63 for n in numbers):
        raise ValueError('Invalid integer field')
    sequence, issued, expires, minimum, maximum = numbers
    if not (sequence > 0 and issued <= now < expires and 0 < expires - issued <= 604800
            and 0 < minimum <= maximum):
        raise ValueError('Invalid sequence, validity or compatibility')
    entries = manifest['indicators']
    if not isinstance(entries, list) or not 1 <= len(entries) <= 1000:
        raise ValueError('Invalid indicator count')
    seen = set()
    result = struct.pack('>I', 0x45564F31) + utf(PURPOSE) + utf(manifest['keyId'])
    result += struct.pack('>qqqqqI', *numbers, len(entries))
    for entry in entries:
        if (set(entry) != {'sha256', 'category'} or not re.fullmatch('[0-9a-f]{64}', entry['sha256'])
                or entry['category'] not in {'malware', 'phishing', 'unwanted'} or entry['sha256'] in seen):
            raise ValueError('Invalid or duplicate indicator')
        seen.add(entry['sha256'])
        result += utf(entry['sha256']) + utf(entry['category'])
    if len(result) > MAX_BYTES - 1024:
        raise ValueError('Payload too large')
    return result


def openssl(*args):
    return subprocess.run(['openssl', *map(str, args)], check=True, capture_output=True).stdout


def verified_sequence(envelope, public_key):
    if not 8 <= len(envelope) <= MAX_BYTES:
        raise ValueError('Invalid envelope size')
    size, = struct.unpack_from('>I', envelope)
    if not 1 <= size <= MAX_BYTES - 1024 or size + 8 > len(envelope):
        raise ValueError('Invalid payload length')
    data = envelope[4:4 + size]
    signature_size, = struct.unpack_from('>I', envelope, 4 + size)
    signature = envelope[8 + size:]
    if signature_size != len(signature) or not 256 <= signature_size <= 512:
        raise ValueError('Invalid signature length')
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory)
        (path / 'payload').write_bytes(data)
        (path / 'signature').write_bytes(signature)
        openssl('dgst', '-sha256', '-verify', public_key, '-signature', path / 'signature', path / 'payload')
    magic, = struct.unpack_from('>I', data)
    if magic != 0x45564F31:
        raise ValueError('Wrong format')
    cursor = 4
    texts = []
    for _ in range(2):
        length, = struct.unpack_from('>H', data, cursor)
        cursor += 2
        texts.append(data[cursor:cursor + length].decode('ascii'))
        cursor += length
    if texts[0] != PURPOSE:
        raise ValueError('Wrong purpose')
    sequence, = struct.unpack_from('>q', data, cursor)
    if sequence <= 0:
        raise ValueError('Invalid stored sequence')
    return sequence


def sign(manifest, private_key, public_key, now, previous=None):
    data = payload(manifest, now)
    if previous is not None and manifest['sequence'] <= verified_sequence(previous, public_key):
        raise ValueError('Sequence must increase over the published signed package')
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory)
        (path / 'payload').write_bytes(data)
        signature = openssl('dgst', '-sha256', '-sign', private_key, path / 'payload')
    if not 256 <= len(signature) <= 512:
        raise ValueError('Expected a 2048–4096-bit RSA key')
    envelope = struct.pack('>I', len(data)) + data + struct.pack('>I', len(signature)) + signature
    verified_sequence(envelope, public_key)  # Independently pinned public key must match signer.
    return envelope


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--private-key', type=Path, required=True)
    parser.add_argument('--public-key', type=Path, required=True)
    parser.add_argument('--previous', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--public-config-output', type=Path)
    args = parser.parse_args()
    if args.manifest.stat().st_size > MAX_BYTES:
        raise ValueError('Manifest too large')
    manifest = json.loads(args.manifest.read_text())
    if args.previous and args.previous.stat().st_size > MAX_BYTES:
        raise ValueError('Previous package too large')
    previous = args.previous.read_bytes() if args.previous else None
    packet = sign(manifest, args.private_key, args.public_key, int(time.time()), previous)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(packet)
    if args.public_config_output:
        public_der = openssl('pkey', '-pubin', '-in', args.public_key, '-outform', 'DER')
        args.public_config_output.parent.mkdir(parents=True, exist_ok=True)
        args.public_config_output.write_text(
            f'endpoint={ENDPOINT}\nkeyId={manifest["keyId"]}\n'
            f'publicKeySpkiBase64={base64.b64encode(public_der).decode()}\n')


if __name__ == '__main__':
    main()
