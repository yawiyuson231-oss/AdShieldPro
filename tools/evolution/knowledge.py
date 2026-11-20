"""Offline research knowledge graph. Review-only; never changes app protection."""
import argparse
from datetime import datetime, timedelta, timezone
import math
from pathlib import Path
import re
import sqlite3
from urllib.parse import urlsplit

from .artifacts import load_json
from .core import canonical, digest
import json

NODE_TYPES = frozenset({'vulnerability', 'malware_indicator', 'domain', 'application_signature',
                        'dependency', 'network_indicator', 'advisory', 'incident'})
RELATIONS = frozenset({'affects', 'indicates', 'depends_on', 'reported_in', 'observed_in',
                       'related_to', 'mitigates'})
STATUSES = frozenset({'unverified', 'verified', 'disputed', 'retracted'})
LIMITS = {'sources': 2000, 'nodes': 10000, 'edges': 50000, 'reviews': 100000, 'proposals': 10000}
ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}')


def text(value, maximum=2048):
    if (not isinstance(value, str) or not value.strip() or len(value) > maximum
            or any(ord(char) < 32 for char in value)):
        raise ValueError('invalid or overlong text')
    return value


def identifier(value):
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise ValueError('invalid identifier')
    return value


def confidence(value):
    if type(value) not in (float, int) or not 0 <= value <= 1 or not math.isfinite(value):
        raise ValueError('confidence/reliability must be a finite number in [0, 1]')
    return value


def timestamp(value):
    parsed = datetime.fromisoformat(text(value, 64).replace('Z', '+00:00'))
    if parsed.utcoffset() is None:
        raise ValueError('timezone is required')
    return parsed.astimezone(timezone.utc)


def fields(row, expected):
    if not isinstance(row, dict) or set(row) != set(expected.split()):
        raise ValueError('missing or unexpected fields')


class KnowledgeGraph:
    """Versioned SQLite graph with immutable imports and append-only local reviews.

    The local engineering user is trusted; reviewer names are attestations, not
    authenticated identities. This store is not connected to Android Room.
    """
    def __init__(self, path, clock=None):
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA foreign_keys = ON')
        try:
            version = self.db.execute('PRAGMA user_version').fetchone()[0]
            if version not in (0, 1):
                raise ValueError('unsupported knowledge schema version')
            if version == 0:
                if self.db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall():
                    raise ValueError('refusing to initialize a nonempty unversioned database')
                self.db.executescript('''
                    BEGIN IMMEDIATE;
                    CREATE TABLE sources (id TEXT PRIMARY KEY, body TEXT NOT NULL);
                    CREATE TABLE nodes (id TEXT PRIMARY KEY, body TEXT NOT NULL);
                    CREATE TABLE edges (id TEXT PRIMARY KEY, subject TEXT NOT NULL REFERENCES nodes(id),
                        object TEXT NOT NULL REFERENCES nodes(id), source TEXT NOT NULL REFERENCES sources(id),
                        body TEXT NOT NULL);
                    CREATE TABLE reviews (seq INTEGER PRIMARY KEY, kind TEXT NOT NULL, target TEXT NOT NULL,
                        body TEXT NOT NULL);
                    CREATE INDEX reviews_target ON reviews(kind, target, seq);
                    CREATE TABLE proposals (id TEXT PRIMARY KEY, edge TEXT NOT NULL REFERENCES edges(id),
                        body TEXT NOT NULL);
                    PRAGMA user_version = 1;
                    COMMIT;
                ''')
            self.verify()
        except Exception:
            self.db.close()
            raise

    def close(self):
        self.db.close()

    def verify(self):
        expected = {
            'sources': {'id', 'body'}, 'nodes': {'id', 'body'},
            'edges': {'id', 'subject', 'object', 'source', 'body'},
            'reviews': {'seq', 'kind', 'target', 'body'},
            'proposals': {'id', 'edge', 'body'},
        }
        for table, columns in expected.items():
            actual = {row['name'] for row in self.db.execute(f'PRAGMA table_info({table})')}
            if actual != columns:
                raise ValueError('knowledge schema is incomplete or incompatible')
        if (self.db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok'
                or self.db.execute('PRAGMA foreign_key_check').fetchone() is not None):
            raise ValueError('knowledge database integrity failure')

    def _now(self):
        value = self.clock()
        if value.utcoffset() is None:
            raise ValueError('clock must be timezone aware')
        return value.astimezone(timezone.utc)

    def _time_range(self, row):
        observed, expires = timestamp(row['observed_at']), timestamp(row['expires_at'])
        if observed > self._now() or expires <= observed or expires - observed > timedelta(days=366):
            raise ValueError('future observation, invalid expiry or lifetime exceeding 366 days')

    def _capacity(self, table):
        if self.db.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0] >= LIMITS[table]:
            raise ValueError(f'{table} capacity reached; archive before adding data')

    def _get(self, table, identity):
        identifier(identity)
        row = self.db.execute(f'SELECT body FROM {table} WHERE id=?', (identity,)).fetchone()
        if row is None:
            raise ValueError(f'unknown {table} identifier')
        return json.loads(row['body'])

    def _insert(self, table, row):
        prior = self.db.execute(f'SELECT body FROM {table} WHERE id=?', (row['id'],)).fetchone()
        body = canonical(row)
        if prior:
            if prior['body'] != body:
                raise ValueError('immutable identifier conflict; use a new versioned ID')
            return
        self._capacity(table)
        if table == 'edges':
            self.db.execute('INSERT INTO edges VALUES (?, ?, ?, ?, ?)',
                            (row['id'], row['subject'], row['object'], row['source'], body))
        else:
            self.db.execute(f'INSERT INTO {table} VALUES (?, ?)', (row['id'], body))

    def import_bundle(self, bundle):
        """Atomic local JSON intake; imports can never provide trusted reviews."""
        fields(bundle, 'sources nodes edges')
        for values in bundle.values():
            if not isinstance(values, list) or len(values) > 1000:
                raise ValueError('bundle lists are limited to 1000 records each')
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            for row in bundle['sources']:
                fields(row, 'id url license observed_at expires_at')
                identifier(row['id'])
                uri = urlsplit(text(row['url']))
                if uri.scheme != 'https' or not uri.hostname or uri.username or uri.password or uri.fragment:
                    raise ValueError('source reference must be HTTPS without credentials/fragment')
                text(row['license'], 128)  # declaration only; a review is still mandatory
                self._time_range(row)
                self._insert('sources', row)
            for row in bundle['nodes']:
                fields(row, 'id type value')
                identifier(row['id'])
                if row['type'] not in NODE_TYPES:
                    raise ValueError('unknown node type')
                text(row['value'])
                self._insert('nodes', row)
            for row in bundle['edges']:
                fields(row, 'id subject relation object source observed_at expires_at confidence verification')
                for key in ('id', 'subject', 'object', 'source'):
                    identifier(row[key])
                if row['relation'] not in RELATIONS or row['verification'] != 'unverified':
                    raise ValueError('unknown relation or attempted verification through import')
                confidence(row['confidence'])
                self._time_range(row)
                self._get('nodes', row['subject'])
                self._get('nodes', row['object'])
                self._get('sources', row['source'])
                self._insert('edges', row)

    def review(self, kind, target, reviewer, rationale, status, *, reliability=None, license_allowed=None,
               assessed_confidence=None):
        if kind not in ('source', 'edge') or status not in STATUSES:
            raise ValueError('invalid review kind/status')
        self._get('sources' if kind == 'source' else 'edges', target)
        text(reviewer, 128)
        text(rationale)
        if kind == 'source':
            confidence(reliability)
            if type(license_allowed) is not bool or assessed_confidence is not None:
                raise ValueError('explicit license decision required; confidence assessment is edge-only')
        elif reliability is not None or license_allowed is not None:
            raise ValueError('source-only fields supplied to edge review')
        if assessed_confidence is not None:
            confidence(assessed_confidence)
        row = dict(kind=kind, target=target, reviewer=reviewer, rationale=rationale, status=status,
                   reliability=reliability, license_allowed=license_allowed, assessed_confidence=assessed_confidence,
                   reviewed_at=self._now().isoformat())
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            self._capacity('reviews')
            self.db.execute('INSERT INTO reviews(kind, target, body) VALUES (?, ?, ?)',
                            (kind, target, canonical(row)))
        return row

    def _review(self, kind, target):
        row = self.db.execute('SELECT body FROM reviews WHERE kind=? AND target=? ORDER BY seq DESC LIMIT 1',
                              (kind, target)).fetchone()
        return json.loads(row['body']) if row else None

    def relationship(self, identity):
        edge = self._get('edges', identity)
        source = self._get('sources', edge['source'])
        sr, er = self._review('source', source['id']), self._review('edge', identity)
        reasons = []
        now = self._now()
        if now < max(timestamp(edge['observed_at']), timestamp(source['observed_at'])):
            reasons.append('observation is in the future relative to current clock')
        if any(review and timestamp(review['reviewed_at']) > now for review in (sr, er)):
            reasons.append('review is in the future relative to current clock')
        if now >= min(timestamp(edge['expires_at']), timestamp(source['expires_at'])):
            reasons.append('expired evidence')
        if not sr or sr['status'] != 'verified':
            reasons.append('source not verified')
        if not sr or sr['license_allowed'] is not True:
            reasons.append('license not approved')
        if not sr or sr['reliability'] < 0.8:
            reasons.append('source reliability below 0.8')
        if not er or er['status'] != 'verified':
            reasons.append('relationship not verified')
        assessed = er.get('assessed_confidence') if er else None
        effective_confidence = assessed if assessed is not None else edge['confidence']
        if effective_confidence < 0.8:
            reasons.append('relationship confidence below 0.8')
        return dict(edge=edge, source=source, source_review=sr, edge_review=er,
                    confidence=effective_confidence, verification=er['status'] if er else 'unverified',
                    proposal_eligible=not reasons, reasons=reasons, protection_eligible=False)

    def propose(self, edge_id, title):
        """Snapshot reviewed research as DISCOVER-only engineering evidence."""
        text(title, 256)
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            snapshot = self.relationship(edge_id)
            if not snapshot['proposal_eligible']:
                raise ValueError('research proposal rejected: ' + '; '.join(snapshot['reasons']))
            body = dict(stage='DISCOVER', title=title, evidence=snapshot,
                        created_at=self._now().isoformat(), protection_eligible=False)
            identity = digest(body)
            if not self.db.execute('SELECT 1 FROM proposals WHERE id=?', (identity,)).fetchone():
                self._capacity('proposals')
                self.db.execute('INSERT INTO proposals VALUES (?, ?, ?)', (identity, edge_id, canonical(body)))
        return dict(id=identity, **body)

    def proposal(self, identity):
        stored = self._get('proposals', identity)
        current = self.relationship(stored['evidence']['edge']['id'])
        return dict(snapshot=stored, current_evidence=current,
                    currently_eligible=current['proposal_eligible'], protection_eligible=False)

    def record_discovery(self, journal, cycle, proposal_id):
        evidence = self.proposal(proposal_id)
        if not evidence['currently_eligible']:
            raise ValueError('proposal evidence is no longer eligible')
        return journal.append(cycle, 'DISCOVER',
                              {'research_proposal_id': proposal_id, 'research': evidence})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('database', type=Path)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('init')
    intake = sub.add_parser('import')
    intake.add_argument('bundle', type=Path)
    inspect = sub.add_parser('inspect')
    inspect.add_argument('edge')
    args = parser.parse_args()
    graph = None
    try:
        if args.command == 'import' and args.bundle.stat().st_size > 4 * 1024 * 1024:
            raise ValueError('bundle file exceeds 4 MiB')
        graph = KnowledgeGraph(args.database)
        if args.command == 'import':
            graph.import_bundle(load_json(args.bundle))
        result = graph.relationship(args.edge) if args.command == 'inspect' else {'ok': True}
        print(json.dumps(result, indent=2, allow_nan=False))
    except (ValueError, KeyError, TypeError, AttributeError, OSError, sqlite3.Error) as error:
        parser.exit(2, f'Knowledge intake rejected: {error}\n')
    finally:
        if graph:
            graph.close()


if __name__ == '__main__':
    main()
