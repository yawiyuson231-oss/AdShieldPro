"""Validate JVM detector artifacts and compare two runs. No artifact executes code.

Hashes bind data to bytes, not to an authenticated builder or trustworthy labels.
"""
import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re

from .core import digest, evaluate
from .fixtures import DATASET

ADAPTER = 'android-pure-detectors-v1'
SCOPE = 'public-synthetic-regression-not-independent-holdout'
HASH = re.compile(r'[0-9a-f]{64}')
EXTRA_SOURCES = (
    'app/src/test/java/com/adshield/pro/EvolutionDetectorEvidenceTest.kt',
    'app/build.gradle.kts', 'build.gradle.kts', 'settings.gradle.kts',
    'gradle/libs.versions.toml',
)


def sha_file(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_paths(root):
    return sorted([p.relative_to(root).as_posix()
                   for p in (root / 'app/src/main').rglob('*.kt')] + list(EXTRA_SOURCES))


def load_json(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f'duplicate JSON key: {key}')
            result[key] = value
        return result
    with Path(path).open(encoding='utf-8') as stream:
        return json.load(stream, object_pairs_hook=unique,
                         parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def validate(artifact, root, *, current=False):
    root = Path(root)
    if (type(artifact.get('schema')) is not int or artifact['schema'] != 1
            or artifact.get('adapter') != ADAPTER or artifact.get('scope') != SCOPE):
        raise ValueError('unsupported artifact schema, adapter or scope')
    timestamp = datetime.fromisoformat(artifact['created_at'].replace('Z', '+00:00'))
    if timestamp.utcoffset() is None:
        raise ValueError('timestamp must include timezone')
    dataset = root / DATASET
    if artifact.get('dataset_file_sha256') != sha_file(dataset):
        raise ValueError('dataset bytes do not match artifact')
    manifest = artifact.get('source_manifest')
    # Baseline may legitimately contain different/removed sources. Never open any
    # artifact-supplied source path. Current source paths come only from local inventory.
    if not isinstance(manifest, dict) or not manifest:
        raise ValueError('source manifest missing')
    for path, hashed in manifest.items():
        if (not isinstance(path, str) or path.startswith('/') or '\\' in path
                or any(part in ('', '.', '..') for part in path.split('/'))
                or not isinstance(hashed, str) or not HASH.fullmatch(hashed)):
            raise ValueError('invalid source manifest entry')
    if current:
        if set(manifest) != set(source_paths(root)):
            raise ValueError('current source inventory mismatch')
        for path in source_paths(root):
            if manifest[path] != sha_file(root / path):
                raise ValueError(f'current source bytes changed: {path}')
    samples = load_json(dataset)
    # Self-comparison validates the complete prediction contract. It deliberately
    # cannot establish improvement; unchanged predictions are a failed evolution.
    evaluate(samples, artifact['predictions'], artifact['predictions'])
    return samples


def compare(baseline, candidate, root):
    samples = validate(baseline, root)
    validate(candidate, root, current=True)
    if baseline['adapter'] != candidate['adapter']:
        raise ValueError('evaluation policy changed; rebaseline with the same adapter')
    adapter_path = EXTRA_SOURCES[0]
    if baseline['source_manifest'].get(adapter_path) != candidate['source_manifest'][adapter_path]:
        raise ValueError('adapter bytes changed; rebaseline before comparison')
    report = evaluate(samples, baseline['predictions'], candidate['predictions'])
    report.update(baseline_artifact_sha256=digest(baseline),
                  candidate_artifact_sha256=digest(candidate),
                  baseline_sources_sha256=digest(baseline['source_manifest']),
                  candidate_sources_sha256=digest(candidate['source_manifest']),
                  independent_holdout=False, release_eligible=False)
    report['limitations'] = ('Public synthetic risk/policy regression cases, not confirmed malware or an '
                             'independent holdout. Builder/signature authentication and runtime tests '
                             'remain required. No shipping detection improvement is implied.')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[2])
    sub = parser.add_subparsers(dest='command', required=True)
    check = sub.add_parser('validate')
    check.add_argument('artifact')
    comparison = sub.add_parser('compare')
    comparison.add_argument('baseline')
    comparison.add_argument('candidate')
    args = parser.parse_args()
    try:
        if args.command == 'validate':
            samples = validate(load_json(args.artifact), args.root, current=True)
            print(json.dumps({'valid': True, 'samples': len(samples), 'release_eligible': False}))
            return 0
        report = compare(load_json(args.baseline), load_json(args.candidate), args.root)
        print(json.dumps(report, indent=2, allow_nan=False))
        return 0 if report['eligible'] else 1
    except (ValueError, KeyError, TypeError, AttributeError, OSError) as error:
        parser.exit(2, f'Invalid detector evidence: {error}\n')


if __name__ == '__main__':
    raise SystemExit(main())
