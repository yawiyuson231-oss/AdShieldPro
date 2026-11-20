"""Offline evolution evidence gates. No networking, code execution or app mutation."""
import hashlib
import json
import sqlite3
from datetime import datetime, timezone

CATEGORIES = frozenset({'domain', 'phishing', 'apk_metadata', 'dns_filter', 'configuration'})
STAGES = ('DISCOVER', 'EXPERIMENT', 'VERIFY', 'DEPLOY')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def evaluate(samples, baseline, candidate):
    """Evaluate predictions supplied by isolated adapters, never inferred from labels."""
    if not samples:
        raise ValueError('empty dataset')
    ids = [s['id'] for s in samples]
    if any(not isinstance(i, str) or not i for i in ids) or len(set(ids)) != len(ids):
        raise ValueError('sample IDs must be unique nonempty strings')
    for predictions in (baseline, candidate):
        if set(predictions) != set(ids) or any(type(v) is not bool for v in predictions.values()):
            raise ValueError('predictions must cover exactly the dataset with boolean labels')
    for s in samples:
        if (s['category'] not in CATEGORIES or type(s['malicious']) is not bool
                or s.get('verification') != 'verified' or not s.get('source')):
            raise ValueError('only sourced, verified boolean labels in known categories are accepted')
    def metrics(rows, predictions):
        tp = sum(s['malicious'] and predictions[s['id']] for s in rows)
        fn = sum(s['malicious'] and not predictions[s['id']] for s in rows)
        fp = sum(not s['malicious'] and predictions[s['id']] for s in rows)
        tn = sum(not s['malicious'] and not predictions[s['id']] for s in rows)
        return dict(tp=tp, fn=fn, fp=fp, tn=tn,
                    recall=tp / (tp + fn) if tp + fn else None,
                    false_positive_rate=fp / (fp + tn) if fp + tn else None)
    reasons = []
    slices = {}
    for category in sorted(CATEGORIES):
        rows = [s for s in samples if s['category'] == category]
        old, new = metrics(rows, baseline), metrics(rows, candidate)
        slices[category] = {'baseline': old, 'candidate': new}
        if old['recall'] is None or old['false_positive_rate'] is None:
            reasons.append(f'{category}: missing positive or negative coverage')
        if new['fn'] > old['fn'] or new['fp'] > old['fp']:
            reasons.append(f'{category}: security regression')
    old, new = metrics(samples, baseline), metrics(samples, candidate)
    if not (new['fn'] < old['fn'] or new['fp'] < old['fp']):
        reasons.append('no measured detection improvement')
    incorrect = {
        name: [{'id': s['id'], 'category': s['category'], 'expected': s['malicious'],
                'predicted': predictions[s['id']]} for s in samples
               if predictions[s['id']] != s['malicious']]
        for name, predictions in (('baseline', baseline), ('candidate', candidate))
    }
    return {'dataset_sha256': digest(samples), 'baseline_sha256': digest(baseline),
            'candidate_sha256': digest(candidate), 'baseline': old, 'candidate': new,
            'incorrect_classifications': incorrect,
            'slices': slices, 'reasons': reasons, 'eligible': not reasons,
            'limitations': 'Synthetic/offline evidence only; not proof of real-world protection.'}


def gate(report, checks):
    """Fail closed. These are reviewer attestations, not automatic APK verification."""
    required = ('regression_tests', 'dns_unchanged', 'ui_unchanged', 'privacy_review',
                'performance_budget', 'dependency_integrity', 'signing_verified',
                'rollback_tested', 'independent_holdout')
    reasons = list(report['reasons'])
    if report.get('eligible') is not True:
        reasons.append('comparison is not eligible')
    if report.get('independent_holdout') is False:
        reasons.append('public regression corpus is not an independent holdout')
    for key in required:
        if checks.get(key) is not True:
            reasons.append(f'{key}: missing or failed evidence')
    return {'eligible': not reasons, 'reasons': reasons}


class Journal:
    """SQLite transactions + SHA-256 chain; not secure against whole-file replacement.

    Keep the returned tip in a separately controlled artifact to detect truncation.
    Single local engineering writer; no device/user telemetry belongs here.
    """
    def __init__(self, path):
        self.db = sqlite3.connect(path)
        self.db.execute('CREATE TABLE IF NOT EXISTS events '
                        '(seq INTEGER PRIMARY KEY, payload TEXT NOT NULL, '
                        'previous TEXT NOT NULL, hash TEXT NOT NULL)')

    def close(self):
        self.db.close()

    def verify(self, expected_tip=None):
        if self.db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise ValueError('database integrity failure')
        previous = '0' * 64
        events = []
        for seq, payload, prior, hashed in self.db.execute('SELECT * FROM events ORDER BY seq'):
            if seq != len(events) + 1 or prior != previous or digest([seq, payload, prior]) != hashed:
                raise ValueError('journal integrity failure')
            events.append(json.loads(payload))
            previous = hashed
        if expected_tip is not None and expected_tip != previous:
            raise ValueError('journal tip mismatch')
        return events, previous

    def append(self, cycle, stage, evidence, approval=None):
        if not isinstance(cycle, str) or not cycle.strip() or stage not in STAGES:
            raise ValueError('invalid cycle or stage')
        # Lock before verification to avoid check/append races with other writers.
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            events, previous = self.verify()
            history = [e for e in events if e['cycle'] == cycle]
            index = len(history)
            if index >= len(STAGES) or stage != STAGES[index]:
                raise ValueError('invalid stage transition')
            if stage == 'VERIFY':
                if (evidence['report'] != history[-1]['evidence'].get('report')
                        or gate(evidence['report'], evidence['checks'])['eligible'] is not True):
                    raise ValueError('verification rejected or experiment report changed')
            if stage == 'DEPLOY':
                # Bind approval to the exact verified evidence; DEPLOY records approval only.
                verified = history[-1]['evidence']
                if (not isinstance(approval, dict) or not approval.get('reviewer')
                        or approval.get('evidence_sha256') != digest(verified)):
                    raise ValueError('explicit approval bound to verified evidence required')
                if evidence != verified:
                    raise ValueError('deployment evidence differs from verified evidence')
            event = {'cycle': cycle, 'stage': stage, 'evidence': evidence,
                     'approval': approval, 'timestamp': datetime.now(timezone.utc).isoformat()}
            payload = canonical(event)
            seq = len(events) + 1
            tip = digest([seq, payload, previous])
            self.db.execute('INSERT INTO events VALUES (?, ?, ?, ?)', (seq, payload, previous, tip))
        return tip


def priorities(reports):
    """Summarize unsuccessful cycles instead of assuming every candidate helped."""
    counts = {}
    for report in reports:
        for reason in report['reasons']:
            counts[reason] = counts.get(reason, 0) + 1
    return [{'issue': key, 'cycles': value} for key, value in
            sorted(counts.items(), key=lambda pair: (-pair[1], pair[0]))]
