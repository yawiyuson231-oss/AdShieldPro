"""python3 -m tools.evolution samples.json baseline.json candidate.json"""
import argparse
import json
from .core import evaluate

parser = argparse.ArgumentParser(description='Offline detection comparison; never deploys code')
parser.add_argument('samples')
parser.add_argument('baseline')
parser.add_argument('candidate')
args = parser.parse_args()
try:
    values = []
    for path in (args.samples, args.baseline, args.candidate):
        with open(path, encoding='utf-8') as stream:
            values.append(json.load(stream))
    report = evaluate(*values)
    print(json.dumps(report, indent=2, allow_nan=False))
    raise SystemExit(0 if report['eligible'] else 1)
except (ValueError, KeyError, TypeError, OSError) as error:
    parser.exit(2, f'Invalid evidence: {error}\n')
