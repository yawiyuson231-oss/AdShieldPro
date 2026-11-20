# Phase 3 — provenance graph and reviewed research intake

Status: **offline engineering foundation implemented and tested**. Not connected to Android Room or protection decisions. Later phases added bounded public Maven-advisory collection, and Phase 2 Android execution has passed; see [the current system guide](EVOLUTION_SYSTEM.md) and [validation record](EVOLUTION_VALIDATION.md). The sections below describe the Phase 3 checkpoint.

## Existing architecture and reuse boundary

Android already has `ThreatIndicatorEntity` in `ConnectorEntities.kt`, `IntelligenceEventEntity`, connector parsers, and the intelligence map vocabulary. These remain unchanged. The new `tools/evolution/knowledge.py` is a local engineering research store, not a replacement device database or a second threat detector. Event/indicator export adapters and a Room migration require a separately tested future change; existing app events are not silently imported as verified intelligence.

## Implemented behavior

- SQLite schema v1: immutable, versioned sources/nodes/edges; append-only reviewer decisions; immutable research proposal snapshots.
- Eight entity types: vulnerability, malware indicator, domain, application signature, dependency, network indicator, advisory, incident.
- Seven relationship types: affects, indicates, depends_on, reported_in, observed_in, related_to, mitigates.
- Each edge requires a source reference, timezone-aware observation/expiry timestamps, finite confidence in [0,1], and verification state. Source references include declared license and their own observation/expiry timestamps.
- Imports always start **unverified**. Imported review records or claimed verified edges are rejected. Unknown fields, missing references, nonfinite confidence, future observations and invalid lifetimes are rejected atomically.
- Source reliability and license decisions require explicit local review. A verified edge alone is insufficient.
- Proposal eligibility requires verified source and edge reviews, permitted license, source reliability ≥0.8, edge confidence ≥0.8, and both source/edge evidence unexpired. These thresholds are research-queue policy, not detection confidence calibration.
- Evidence lifetimes are positive and at most 366 days. Later source observations must use new IDs; refreshes do not rewrite history. Expiry and clock rollback are checked at use time, not just import time.
- Retractions/disputes remain in review history and immediately prevent new eligible proposals. Retrieval of an older proposal returns its original snapshot **and** the current evidence/eligibility, so old approval cannot hide a later retraction.
- `record_discovery` rechecks a proposal before recording only DISCOVER evidence in the Phase 1 hash-chained cycle journal. It cannot advance to VERIFY/DEPLOY or change protection.
- Referential integrity, schema-version/column checks, and SQLite integrity checks. Unknown, incomplete, or nonempty unversioned databases are rejected rather than destructively migrated.

No source was fetched or evaluated as current security intelligence during this phase. The system does not invent real incidents, CVEs, confirmed malware, source reliability, or license permissions.

## Storage contract

A bundle is an object with exactly `sources`, `nodes`, and `edges` arrays. Maximum 1000 records per array and 4 MiB per CLI import file. Node values are bounded plain text, not executable objects. Type tags describe vocabulary, not semantic validation of a CVE/hash/address. A reviewer must check real identifier correctness and relevance.

```json
{
  "sources": [{
    "id": "research-source-v1",
    "url": "https://research.example.test/advisory",
    "license": "unknown",
    "observed_at": "2026-11-20T00:00:00Z",
    "expires_at": "2026-12-20T00:00:00Z"
  }],
  "nodes": [
    {"id": "advisory-fixture", "type": "advisory", "value": "Synthetic advisory, not a real security finding"},
    {"id": "dependency-fixture", "type": "dependency", "value": "Synthetic dependency fixture"}
  ],
  "edges": [{
    "id": "relationship-v1",
    "subject": "advisory-fixture",
    "relation": "affects",
    "object": "dependency-fixture",
    "source": "research-source-v1",
    "observed_at": "2026-11-20T00:00:00Z",
    "expires_at": "2026-12-20T00:00:00Z",
    "confidence": 0.9,
    "verification": "unverified"
  }]
}
```

This example uses a reserved `.test` host, not a source of real intelligence. Its fixed timestamps deliberately expire; do not automatically extend timestamps to conceal stale evidence. An HTTPS URL is only a reference: intake does not resolve, request, authenticate, or assess the referenced host. No arbitrary URL-fetching or executable content loading is implemented.

## Running

Keep local databases and user information out of Git:

```sh
mkdir -p .cache/evolution
python3 -m tools.evolution.knowledge .cache/evolution/research.sqlite init
python3 -m tools.evolution.knowledge .cache/evolution/research.sqlite import /path/to/bundle.json
python3 -m tools.evolution.knowledge .cache/evolution/research.sqlite inspect relationship-v1
python3 -m unittest discover -s tools/tests -v
```

Exit codes: 0 for a successful import/inspection/init; 2 for invalid input/database. Inspection success is **not** verification or deployment approval. Duplicate JSON keys and nonfinite values are rejected using the existing strict artifact loader.

Explicit review is an API operation for a trusted local engineering user, not a feed field. For a *real, independently reviewed* source and edge:

```python
from tools.evolution.knowledge import KnowledgeGraph
from tools.evolution.core import Journal

graph = KnowledgeGraph('.cache/evolution/research.sqlite')
journal = Journal('.cache/evolution/cycles.sqlite')
try:
    # Values here must come from actual review, not the imported source's claims.
    graph.review('source', source_id, reviewer, license_and_source_review_reason,
                 'verified', reliability=reviewed_reliability, license_allowed=license_permitted)
    graph.review('edge', edge_id, reviewer, independent_verification_reason, 'verified',
                 assessed_confidence=reviewed_relationship_confidence)
    proposal = graph.propose(edge_id, 'Investigate applicability to the existing Android app')
    tip = graph.record_discovery(journal, cycle_id, proposal['id'])
    # Store tip separately. EXPERIMENT, VERIFY, approval and release remain separate.
finally:
    journal.close()
    graph.close()
```

The API checks reviewer/rationale presence, not reviewer authentication or legal correctness. It never infers that a declared license permits use. Unknown/uncertain licenses should remain unapproved. No automatic trust is assigned merely because a URL names a familiar organization.

## Privacy, retention and trust limits

- Store public research only. No private device/package inventories, browsing history, user incidents, secrets or personal telemetry. Input validation bounds strings but does not detect/redact all personal information.
- Use restrictive host filesystem permissions. This database is not encrypted and graph/review records are not tamper-evident against an attacker with local database-write access. The separate evolution journal is hash-chained; its independently stored head is still required to detect truncation.
- Capacity limits: 2000 sources, 10000 nodes, 50000 edges, 100000 reviews, 10000 proposals. Writes fail closed at capacity. Expired evidence stays available as history but is ineligible; there is no automatic history deletion. Archive/export to an access-controlled location before starting a fresh database. Secure deletion, backup key custody and device retention policies are not implemented here.
- SQLite atomic imports prevent partial feed replacement. Identical IDs/content are idempotent; conflicting IDs roll back the entire bundle. No overwrite or automatic trust upgrade.
- Proposals always carry `protection_eligible: false`. Even a fully reviewed proposal is only an engineering opportunity. Fresh relevance/privacy/license checks and measured experiments are still required. Graph and cycle databases are separate; recording DISCOVER is not a cross-database release transaction and must not be treated as one.
- There is no continuous background collector, live advisory monitoring, authenticated review service, source reliability model or Android graph UI in this phase. Existing connectors remain the app's feed mechanisms.

## Measured validation

17 new tests exercise real temporary SQLite stores and CLI commands: all entity categories, required edge provenance, unverified imports, idempotency, atomic rollback, conflicts, retractions, disputed/low-confidence evidence, expiry/clock rollback, license/reliability gates, immutable proposal snapshots, DISCOVER journal integration, bounds, persistence, foreign keys, malformed bundles and incompatible schemas.

The next integration gate is a reviewed mapping from existing Android indicators/events to this provenance contract, with device-side privacy/retention requirements and Room migration tests. Do not migrate or label existing data as verified merely because this offline foundation passed tests.
