"""Verified feedback and model-selection metadata; never trains or loads executables."""
from datetime import datetime, timezone
import json
import sqlite3

from .core import CATEGORIES, canonical, digest, evaluate, gate
from .knowledge import identifier, text


def drift(reference, observed, *, min_samples=100, threshold=0.15):
    """Total variation of reviewed fixed-bin counts. Advisory only, not model drift proof."""
    if (type(min_samples) is not int or min_samples < 1 or type(threshold) not in (float, int)
            or not 0 < threshold <= 1):
        raise ValueError('invalid drift policy')
    if (not isinstance(reference, list) or not isinstance(observed, list)
            or len(reference) != len(observed) or len(reference) < 2):
        raise ValueError('matched fixed bins required')
    if any(type(v) is not int or v < 0 for v in reference + observed):
        raise ValueError('bin counts must be nonnegative integers')
    a, b = sum(reference), sum(observed)
    if min(a, b) < min_samples:
        return dict(status='insufficient_evidence', distance=None, protection_changed=False)
    distance = sum(abs(x / a - y / b) for x, y in zip(reference, observed)) / 2
    return dict(status='review_distribution_shift' if distance >= threshold else 'no_shift_detected',
                distance=distance, threshold=threshold, protection_changed=False)


class LearningRegistry:
    """Local reviewer-controlled metadata. Selection is NOT a shipping app model switch."""
    def __init__(self, path):
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA foreign_keys=ON')
        try:
            version = self.db.execute('PRAGMA user_version').fetchone()[0]
            if version not in (0, 1):
                raise ValueError('unsupported learning schema')
            if version == 0:
                if self.db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchone():
                    raise ValueError('refusing nonempty unversioned database')
                self.db.executescript('''
                    BEGIN IMMEDIATE;
                    CREATE TABLE samples (id TEXT PRIMARY KEY, category TEXT NOT NULL,
                        split TEXT NOT NULL, features TEXT NOT NULL);
                    CREATE TABLE feedback (id TEXT PRIMARY KEY, sample TEXT NOT NULL REFERENCES samples(id),
                        body TEXT NOT NULL);
                    CREATE TABLE decisions (seq INTEGER PRIMARY KEY, feedback TEXT NOT NULL REFERENCES feedback(id),
                        body TEXT NOT NULL);
                    CREATE TABLE versions (id TEXT PRIMARY KEY, body TEXT NOT NULL);
                    CREATE TABLE selections (seq INTEGER PRIMARY KEY, version TEXT NOT NULL REFERENCES versions(id),
                        body TEXT NOT NULL);
                    PRAGMA user_version=1;
                    COMMIT;
                ''')
            expected = {'samples': {'id', 'category', 'split', 'features'},
                        'feedback': {'id', 'sample', 'body'}, 'decisions': {'seq', 'feedback', 'body'},
                        'versions': {'id', 'body'}, 'selections': {'seq', 'version', 'body'}}
            for table, columns in expected.items():
                if {r['name'] for r in self.db.execute(f'PRAGMA table_info({table})')} != columns:
                    raise ValueError('incompatible learning schema')
            self.verify()
        except Exception:
            self.db.close()
            raise

    def close(self):
        self.db.close()

    def verify(self):
        if (self.db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok'
                or self.db.execute('PRAGMA foreign_key_check').fetchone()):
            raise ValueError('learning database integrity failure')

    @staticmethod
    def _now():
        return datetime.now(timezone.utc).isoformat()

    def _capacity(self, table, limit):
        if self.db.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0] >= limit:
            raise ValueError('learning store capacity reached; archive required')

    def add_sample(self, category, features, split):
        if category not in CATEGORIES or split not in ('train', 'holdout', 'regression'):
            raise ValueError('unknown category or split')
        if not isinstance(features, dict) or not features or len(canonical(features)) > 16384:
            raise ValueError('bounded feature object required')
        # Feature identity ignores split/category to prevent exact-content leakage.
        identity = digest(features)
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            prior = self.db.execute('SELECT * FROM samples WHERE id=?', (identity,)).fetchone()
            if prior:
                if prior['split'] != split or prior['category'] != category:
                    raise ValueError('duplicate features across splits/categories')
            else:
                self._capacity('samples', 50000)
                self.db.execute('INSERT INTO samples VALUES (?,?,?,?)',
                                (identity, category, split, canonical(features)))
        return identity

    def submit_feedback(self, sample, label, source, rationale):
        if type(label) is not bool:
            raise ValueError('boolean label required')
        text(source)
        text(rationale)
        body = dict(sample=sample, malicious=label, source=source, rationale=rationale)
        identity = digest(body)
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            if not self.db.execute('SELECT 1 FROM samples WHERE id=?', (sample,)).fetchone():
                raise ValueError('unknown sample')
            if not self.db.execute('SELECT 1 FROM feedback WHERE id=?', (identity,)).fetchone():
                self._capacity('feedback', 100000)
                self.db.execute('INSERT INTO feedback VALUES (?,?,?)', (identity, sample, canonical(body)))
        return identity

    def review_feedback(self, feedback_id, reviewer, rationale, accepted):
        text(reviewer, 128)
        text(rationale)
        if type(accepted) is not bool:
            raise ValueError('explicit boolean review decision required')
        body = dict(reviewer=reviewer, rationale=rationale, accepted=accepted, timestamp=self._now())
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            if not self.db.execute('SELECT 1 FROM feedback WHERE id=?', (feedback_id,)).fetchone():
                raise ValueError('unknown feedback')
            self._capacity('decisions', 200000)
            self.db.execute('INSERT INTO decisions(feedback,body) VALUES (?,?)', (feedback_id, canonical(body)))

    def dataset(self, split):
        if split not in ('train', 'holdout', 'regression'):
            raise ValueError('unknown split')
        rows = []
        for sample in self.db.execute('SELECT * FROM samples WHERE split=? ORDER BY id', (split,)):
            # Latest decision for each feedback; contradictory accepted labels are excluded,
            # not silently resolved by arrival order. Reviewers must reject obsolete feedback.
            accepted = []
            for feedback in self.db.execute('SELECT * FROM feedback WHERE sample=? ORDER BY id', (sample['id'],)):
                decision = self.db.execute('SELECT body FROM decisions WHERE feedback=? ORDER BY seq DESC LIMIT 1',
                                           (feedback['id'],)).fetchone()
                if decision and json.loads(decision['body'])['accepted'] is True:
                    accepted.append((feedback['id'], json.loads(feedback['body']), json.loads(decision['body'])))
            if not accepted or len({f[1]['malicious'] for f in accepted}) != 1:
                continue
            rows.append(dict(id=sample['id'], category=sample['category'], split=split,
                             features=json.loads(sample['features']), malicious=accepted[0][1]['malicious'],
                             source=canonical([f[1]['source'] for f in accepted]), verification='verified',
                             feedback_evidence=[{'id': f[0], 'review': f[2]} for f in accepted]))
        return rows

    def register_version(self, version, model_sha256, training_dataset_sha256):
        identifier(version)
        for hashed in (model_sha256, training_dataset_sha256):
            if not isinstance(hashed, str) or len(hashed) != 64 or any(c not in '0123456789abcdef' for c in hashed):
                raise ValueError('SHA-256 digest required')
        body = dict(version=version, model_sha256=model_sha256, training_dataset_sha256=training_dataset_sha256,
                    artifact_kind='metadata-only-no-executable-loading')
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            prior = self.db.execute('SELECT body FROM versions WHERE id=?', (version,)).fetchone()
            if prior and prior['body'] != canonical(body):
                raise ValueError('immutable version conflict')
            if not prior:
                self._capacity('versions', 10000)
                self.db.execute('INSERT INTO versions VALUES (?,?)', (version, canonical(body)))

    def select(self, version, report, checks, reviewer, rationale):
        text(reviewer, 128)
        text(rationale)
        if not gate(report, checks)['eligible']:
            raise ValueError('version selection rejected by evolution gates')
        # Reports must bind the registered candidate and a held-out dataset. Merely
        # supplying a model name must not transfer approval to unrelated bytes.
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            row = self.db.execute('SELECT body FROM versions WHERE id=?', (version,)).fetchone()
            if not row:
                raise ValueError('unknown version')
            manifest = json.loads(row['body'])
            heldout = self.dataset('holdout')
            if (report.get('candidate_model_sha256') != manifest['model_sha256']
                    or report.get('dataset_sha256') != digest(heldout)
                    or report.get('independent_holdout') is not True):
                raise ValueError('model/holdout evidence mismatch')
            recomputed = evaluate(heldout, report['baseline_predictions'], report['candidate_predictions'])
            if any(report.get(key) != value for key, value in recomputed.items()):
                raise ValueError('reported metrics do not match reviewed holdout predictions')
            for category in CATEGORIES:
                for label in (False, True):
                    if sum(s['category'] == category and s['malicious'] is label for s in heldout) < 20:
                        raise ValueError('at least 20 reviewed examples per class/category required')
            body = dict(action='select', version=version, report=report, checks=checks,
                        reviewer=reviewer, rationale=rationale, timestamp=self._now(), protection_changed=False)
            self._capacity('selections', 50000)
            self.db.execute('INSERT INTO selections(version,body) VALUES (?,?)', (version, canonical(body)))
        return body

    def rollback(self, reviewer, rationale):
        text(reviewer, 128)
        text(rationale)
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            current = self.current()
            prior = self.db.execute('SELECT version FROM selections WHERE version != ? ORDER BY seq DESC LIMIT 1',
                                    (current['version'] if current else '',)).fetchone()
            if not prior:
                raise ValueError('no previously selected version')
            body = dict(action='rollback', version=prior['version'], reviewer=reviewer, rationale=rationale,
                        timestamp=self._now(), protection_changed=False)
            self._capacity('selections', 50000)
            self.db.execute('INSERT INTO selections(version,body) VALUES (?,?)', (prior['version'], canonical(body)))
        return body

    def current(self):
        row = self.db.execute('SELECT body FROM selections ORDER BY seq DESC LIMIT 1').fetchone()
        return json.loads(row['body']) if row else None
