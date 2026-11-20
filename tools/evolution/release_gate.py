"""Production release evidence gate. Aggregate attestations from a protected environment.

Does not sign, publish, install or establish independent ground truth. Missing evidence blocks release.
"""
import json
import os
import re

from .core import CATEGORIES, digest, gate
from .knowledge import text


def authorize(envelope, source_commit):
    if (not isinstance(envelope, dict) or set(envelope) != {'schema', 'source_commit', 'report', 'checks', 'approval'}
            or type(envelope['schema']) is not int or envelope['schema'] != 1):
        raise ValueError('invalid release evidence envelope')
    if (not isinstance(source_commit, str) or not re.fullmatch(r'[a-f0-9]{40}', source_commit)
            or envelope['source_commit'] != source_commit):
        raise ValueError('release evidence does not approve this exact source commit')
    report, checks, approval = envelope['report'], envelope['checks'], envelope['approval']
    if report.get('independent_holdout') is not True or not gate(report, checks)['eligible']:
        raise ValueError('release comparison/holdout/review gates rejected')
    for key in ('dataset_sha256', 'baseline_sha256', 'candidate_sha256'):
        if not isinstance(report.get(key), str) or not re.fullmatch(r'[0-9a-f]{64}', report[key]):
            raise ValueError('dataset and prediction digests required')
    if set(report['slices']) != CATEGORIES:
        raise ValueError('missing security-category coverage')
    totals = {name: dict(tp=0, fn=0, fp=0, tn=0) for name in ('baseline', 'candidate')}
    improved = False
    for category in sorted(CATEGORIES):
        old, new = report['slices'][category]['baseline'], report['slices'][category]['candidate']
        for name, values in (('baseline', old), ('candidate', new)):
            for key in ('tp', 'fn', 'fp', 'tn'):
                value = values[key]
                if type(value) is not int or not 0 <= value <= 10000000:
                    raise ValueError('invalid measured confusion counts')
                totals[name][key] += value
            if values['tp'] + values['fn'] < 20 or values['fp'] + values['tn'] < 20:
                raise ValueError('insufficient reviewed holdout class coverage')
        if (old['tp'] + old['fn'] != new['tp'] + new['fn']
                or old['fp'] + old['tn'] != new['fp'] + new['tn']):
            raise ValueError('baseline and candidate did not use matched class counts')
        if new['fn'] > old['fn'] or new['fp'] > old['fp']:
            raise ValueError('per-category security regression')
        improved |= new['fn'] < old['fn'] or new['fp'] < old['fp']
    for name in totals:
        for key, value in totals[name].items():
            if type(report[name][key]) is not int or report[name][key] != value:
                raise ValueError('aggregate counts do not match slices')
    if not improved or report['baseline_sha256'] == report['candidate_sha256']:
        raise ValueError('no measured detection improvement')
    text(approval['reviewer'], 128)
    bound = {'source_commit': source_commit, 'report': report, 'checks': checks}
    if approval.get('evidence_sha256') != digest(bound):
        raise ValueError('reviewer approval is not bound to this evidence')
    return dict(authorized_source_commit=source_commit, evidence_sha256=digest(bound),
                approval_record_valid=True, apk_signature_verified_by_this_gate=False,
                publication_performed=False)


def main():
    raw = os.environ.get('ADSHIELD_EVOLUTION_APPROVAL_JSON', '')
    try:
        if not raw or len(raw) > 65536:
            raise ValueError('protected environment evolution approval is missing or oversized')
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError('duplicate evidence JSON key')
                result[key] = value
            return result
        evidence = json.loads(raw, object_pairs_hook=unique,
                              parse_constant=lambda value: (_ for _ in ()).throw(ValueError('nonfinite evidence')))
        result = authorize(evidence, os.environ.get('GITHUB_SHA'))
        print(json.dumps(result, indent=2))
    except (ValueError, KeyError, TypeError, AttributeError) as error:
        # Never echo the supplied envelope, raw labels, or private holdout data.
        raise SystemExit(f'Release blocked: {error}') from None


if __name__ == '__main__':
    main()
