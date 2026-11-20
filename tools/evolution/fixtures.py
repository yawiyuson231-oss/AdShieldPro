"""Deterministic, metadata-only synthetic regression corpus. Never resolves a host.

Labels describe intended fixture risk/policy, not confirmed malware. This corpus is
public development data, NOT an independent holdout and NOT training data.
"""
import argparse
import json
from pathlib import Path

DATASET = 'tools/evolution/fixtures/synthetic-v1.json'


def generate():
    rows = []

    def add(category, name, positive, payload, rationale):
        rows.append(dict(id=f'{category}:{name}', category=category, malicious=positive,
                         source='repository-authored synthetic regression specification v1',
                         verification='verified', observed_at='2026-11-20T00:00:00Z',
                         license='CC0-1.0', label_scope='synthetic-risk-or-policy-only',
                         rationale=rationale, input=payload))

    for name, host, positive, why in (
        ('lookalike', 'paypal-billing.attacker.test', True, 'Brand imitation with billing lure'),
        ('deep-lookalike', 'a.b.c.google.attacker.test', True, 'Brand imitation in deep subdomains'),
        ('punycode', 'xn--fixture.test', True, 'Synthetic IDN risk signal; not verified malware'),
        ('ordinary', 'docs.publisher.test', False, 'Ordinary reserved documentation host'),
        ('hyphen-negative', 'team-notes.publisher.test', False, 'A hyphen alone is not abuse'),
    ):
        add('domain', name, positive, {'target': host}, why)
    for name, target, positive, why in (
        ('brand-credentials', 'https://paypal.attacker.test/login', True, 'Brand impersonation and credential lure'),
        ('plain-credentials', 'http://gcash.attacker.test/verify', True, 'Brand impersonation on cleartext transport'),
        ('generic-lure', 'https://portal.attacker.test/signin', True, 'Generic synthetic credential lure without brand; blind-spot probe'),
        ('article', 'https://docs.publisher.test/article', False, 'Ordinary documentation'),
        ('legitimate-login', 'https://portal.publisher.test/login', False, 'A login path alone is not phishing'),
    ):
        add('phishing', name, positive, {'target': target}, why)

    for name, permissions, bindings, installer, sdk, positive, why in (
        ('accessibility-sms', ['RECEIVE_SMS'], ['BIND_ACCESSIBILITY_SERVICE'], None, 36, True,
         'Declared accessibility plus SMS and unknown origin; not observed interception'),
        ('surveillance', ['RECORD_AUDIO', 'CAMERA', 'ACCESS_BACKGROUND_LOCATION'], [], None, 36, True,
         'Stacked requested permissions and unknown origin'),
        ('old-dropper', ['REQUEST_INSTALL_PACKAGES'], [], None, 28, True,
         'Installation request without Internet, old SDK and unknown origin'),
        ('store-basic', ['INTERNET'], [], 'com.android.vending', 36, False,
         'Minimal store-installed metadata'),
        ('unknown-source-only', ['INTERNET'], [], None, 36, False,
         'Unknown origin alone must not imply elevated metadata risk'),
        ('binding-in-request-list', ['BIND_ACCESSIBILITY_SERVICE'], [], 'com.android.vending', 36, False,
         'Requested binding string is not a declared component binding'),
    ):
        add('apk_metadata', name, positive,
            dict(permissions=permissions, bindings=bindings, installer=installer, target_sdk=sdk), why)

    for name, host, allowed, positive, why in (
        ('blocked', 'blocked.fixture.test', False, True, 'Exact synthetic feed block'),
        ('subdomain', 'cdn.blocked.fixture.test', False, True, 'Subdomain synthetic feed block'),
        ('allow-override', 'blocked.fixture.test', True, False, 'Explicit user allow overrides feed'),
        ('suffix-boundary', 'notblocked.fixture.test', False, False, 'Non-child suffix must not match'),
        ('ordinary', 'docs.fixture.test', False, False, 'No matching rule'),
        ('case-dot', 'BLOCKED.FIXTURE.TEST.', False, True, 'Normalization retains block semantics'),
    ):
        add('dns_filter', name, positive, dict(target=host, allow=allowed), why)

    for name, alias, restricted, positive, why in (
        ('alias-off', False, False, True, 'Saved alias inspection disabled'),
        ('network-gap', True, True, True, 'Saved cellular/ethernet/other filtering gap'),
        ('combined', False, True, True, 'Both saved coverage gaps'),
        ('covered', True, False, False, 'All fixture transports covered with alias inspection enabled'),
    ):
        add('configuration', name, positive, dict(alias_shield=alias, wifi_only=restricted), why)
    return rows


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    path = Path(DATASET)
    text = json.dumps(generate(), indent=2, ensure_ascii=True) + '\n'
    if args.check:
        if not path.is_file() or path.read_text() != text:
            parser.exit(1, 'Synthetic corpus is stale; run python3 -m tools.evolution.fixtures\n')
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
