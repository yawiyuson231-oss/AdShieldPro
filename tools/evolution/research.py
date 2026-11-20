"""Bounded GitHub Maven-advisory intake. Research only; no dependency or protection updates."""
import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import sqlite3
import subprocess
import tempfile
import tomllib

from .artifacts import load_json
from .core import digest
from .knowledge import KnowledgeGraph

ROOT = Path(__file__).resolve().parents[2]
ENDPOINT = '/advisories?ecosystem=maven&per_page=100&sort=updated&direction=desc'
GHSA = re.compile(r'GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}')


def dependency_coordinates(catalog):
    data = tomllib.loads(Path(catalog).read_text())
    coordinates = set()
    for value in data.get('libraries', {}).values():
        if isinstance(value, dict):
            coordinate = value.get('module') or f"{value.get('group', '')}:{value.get('name', '')}"
            if re.fullmatch(r'[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+', coordinate):
                coordinates.add(coordinate)
    return coordinates


def collect_bundle(advisories, coordinates, now=None):
    now = now or datetime.now(timezone.utc)
    if now.utcoffset() is None or not isinstance(advisories, list) or len(advisories) > 100:
        raise ValueError('timezone-aware clock and at most 100 advisories required')
    # Daily observation IDs make reruns idempotent while preserving historical refreshes.
    observed = now.astimezone(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    expires = observed + timedelta(days=8)
    sources, nodes, edges, opportunities, withdrawn = {}, {}, {}, [], []
    for advisory in advisories:
        identity = advisory['ghsa_id']
        if not isinstance(identity, str) or not GHSA.fullmatch(identity):
            raise ValueError('invalid GHSA identifier')
        url = f'https://github.com/advisories/{identity}'
        if advisory.get('html_url') != url:
            raise ValueError('unexpected advisory source URL')
        vulnerabilities = advisory.get('vulnerabilities')
        if not isinstance(vulnerabilities, list) or len(vulnerabilities) > 100:
            raise ValueError('bounded vulnerability metadata required')
        packages = set()
        for vulnerability in vulnerabilities:
            package = vulnerability['package']
            # One advisory can span multiple ecosystems even when the API query is Maven-filtered.
            # Ignore non-Maven entries; never interpret their names as Maven coordinates.
            if package.get('ecosystem') != 'maven':
                continue
            name = package['name']
            if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+', name):
                raise ValueError('invalid Maven package metadata')
            packages.add(name)
        if advisory.get('withdrawn_at'):
            withdrawn.append(identity)
            continue
        relevant = sorted(packages & coordinates)
        # The first page is not an exhaustive dependency audit. Preserve only exact
        # coordinate matches to avoid polluting a local Android research queue.
        if not relevant:
            continue
        source_id = 'gh-' + digest([advisory, observed.isoformat()])
        sources[source_id] = dict(id=source_id, url=url, license='NOASSERTION',
                                  observed_at=observed.isoformat(), expires_at=expires.isoformat())
        advisory_id = 'adv-' + identity
        nodes[advisory_id] = dict(id=advisory_id, type='advisory', value=identity)
        cve = advisory.get('cve_id')
        if cve:
            if not isinstance(cve, str) or not re.fullmatch(r'CVE-\d{4}-\d{4,}', cve):
                raise ValueError('invalid CVE identifier')
            nodes[cve] = dict(id=cve, type='vulnerability', value=cve)
            edge_id = 'rel-' + digest([source_id, cve, advisory_id])
            edges[edge_id] = dict(id=edge_id, subject=cve, relation='reported_in', object=advisory_id,
                                  source=source_id, observed_at=observed.isoformat(), expires_at=expires.isoformat(),
                                  confidence=0.5, verification='unverified')
        for coordinate in relevant:
            dependency_id = 'dep-' + digest(coordinate)
            nodes[dependency_id] = dict(id=dependency_id, type='dependency', value=coordinate)
            edge_id = 'rel-' + digest([source_id, advisory_id, dependency_id])
            edges[edge_id] = dict(id=edge_id, subject=advisory_id, relation='related_to', object=dependency_id,
                                  source=source_id, observed_at=observed.isoformat(), expires_at=expires.isoformat(),
                                  confidence=0.5, verification='unverified')
            opportunities.append(dict(advisory=identity, coordinate=coordinate, edge=edge_id,
                status='needs_source_license_version_and_relevance_review', affected_version_verified=False))
    bundle = dict(sources=list(sources.values()), nodes=list(nodes.values()), edges=list(edges.values()))
    summary = dict(observed_at=observed.isoformat(), examined=len(advisories),
                   exact_coordinate_matches=opportunities, withdrawn_advisories=withdrawn,
                   exhaustive=False, protection_changed=False, release_eligible=False,
                   limitations='Latest 100 Maven advisories only; no transitive/OS coverage or version-range verification.')
    return bundle, summary


def fetch_github(destination):
    # No caller-controlled host/endpoint, shell interpolation, credentials in argv or executable downloads.
    with Path(destination).open('wb') as stream:
        result = subprocess.run(['gh', 'api', ENDPOINT], stdout=stream, stderr=subprocess.PIPE, timeout=60)
    if result.returncode != 0:
        raise ValueError('GitHub advisory fetch failed; check connection/rate limits')
    if Path(destination).stat().st_size > 4 * 1024 * 1024:
        raise ValueError('advisory response exceeds 4 MiB')
    return load_json(destination)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('database', type=Path)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--input', type=Path, help='Previously downloaded JSON, no network')
    source.add_argument('--fetch-github', action='store_true', help='Explicit public advisory API read')
    parser.add_argument('--catalog', type=Path, default=ROOT / 'gradle/libs.versions.toml')
    parser.add_argument('--report', type=Path, default=ROOT / '.cache/evolution/research-report.json')
    args = parser.parse_args()
    graph = None
    try:
        with tempfile.TemporaryDirectory() as directory:
            if args.input:
                if args.input.stat().st_size > 4 * 1024 * 1024:
                    raise ValueError('advisory input exceeds 4 MiB')
                advisories = load_json(args.input)
            else:
                advisories = fetch_github(Path(directory) / 'advisories.json')
            bundle, report = collect_bundle(advisories, dependency_coordinates(args.catalog))
            graph = KnowledgeGraph(args.database)
            graph.import_bundle(bundle)
            report['bundle_sha256'] = digest(bundle)
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + '\n')
            print(json.dumps(report, indent=2))
    except (ValueError, KeyError, TypeError, OSError, sqlite3.Error, subprocess.SubprocessError) as error:
        parser.exit(2, f'Research intake rejected: {error}\n')
    finally:
        if graph:
            graph.close()


if __name__ == '__main__':
    main()
