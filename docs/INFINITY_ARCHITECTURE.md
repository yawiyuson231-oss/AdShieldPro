# OMNISHIELD X INFINITY — implementation and deployment architecture

This document describes the Infinity upgrade on this branch. It distinguishes code that ships in the
Android app from infrastructure an operator must actually deploy. No server, account, capacity, scan,
or transfer is simulated.

## 1. Existing application preserved

The original Android cyber-console, DNS/VPN engine, filter lists, Security Center, optimizer, battery
screens, statistics, settings, and status matrix remain in place. The existing Ad Blocker → Browser
screen now contains private-search controls. Three destinations were added to the existing lazy,
scrollable bottom navigation:

- **Files** — Android Storage Access Framework (SAF) file manager and bounded folder scanning.
- **Cloud** — Nextcloud/WebDAV storage and the Infinity verified-capacity dashboard.
- **Downloads** — direct HTTPS media inspection and Android DownloadManager queue/history.

The static OmniShield X web application and browser extension are separate existing deliverables;
their runtime was not replaced.

## 2. Selected backend architecture

The baseline deployment is deliberately one coherent open-source stack rather than several
unnecessarily overlapping storage systems:

| Layer | Selected component | Responsibility |
| --- | --- | --- |
| Android interface | Existing Compose cyber-console | User consent, SAF pickers, file/cloud/download views, progress and evidence |
| Android metadata | Room v3 | Persistent security reports, provider health/quota and download history |
| Credential boundary | AndroidKeyStore + AES-GCM | Encrypt WebDAV passwords; ciphertext only in app-private preferences |
| Remote protocol | Authenticated HTTPS WebDAV | PROPFIND, MKCOL, PUT, GET, MOVE, DELETE and DAV quota |
| Sharing | Nextcloud OCS Share API | Real public links on Nextcloud only; generic WebDAV has no standard share API |
| Accounts/files/versions | Nextcloud Community | Users, app passwords, shares, metadata, trash/version facilities supplied by the server |
| Metadata database | PostgreSQL | Nextcloud's authoritative account/file/share metadata |
| HTTPS edge | Caddy | Public TLS endpoint and reverse proxy |
| Physical capacity | Operator-mounted persistent volumes | Actual disks, quotas and backups; never an assumed allowance |

SeaweedFS, S3-compatible storage, Syncthing, and Ceph are **not** installed by the baseline compose
file. Adding them without infrastructure and an interoperability test would create unused services
and misleading capability claims. A future adapter can connect Nextcloud External Storage to an
operator-supplied S3-compatible service, but that path is not verified on this branch.

## 3. Deploy the baseline server

### Requirements

- A Linux server you own or are authorized to administer.
- Docker Engine with the Compose plugin.
- A public DNS name pointing to that server, inbound TCP/UDP 443 and TCP 80 for certificate issuance.
- Persistent disks with measured free space, plus a separate backup destination.
- Strong unique PostgreSQL and Nextcloud credentials.

### Installation

```bash
cd infra
cp .env.example .env
# Replace DOMAIN, ACME_EMAIL and every database value. Use a random password, for example:
openssl rand -hex 32
chmod 600 .env
docker compose --env-file .env pull
docker compose --env-file .env up -d
docker compose --env-file .env ps
docker compose --env-file .env logs --tail=100 caddy nextcloud postgres
```

Complete the Nextcloud setup in its HTTPS web interface, apply updates, create a non-admin user for
the phone, and create an **app password** for that user. Configure a quota supported by the actual
volume and operational policy. Do not enter 1 TB/5 TB/10 TB merely because those capacities are
desired.

The Android WebDAV root for a standard Nextcloud installation is:

```text
https://DOMAIN/remote.php/dav/files/NEXTCLOUD_USERNAME/
```

In **Cloud → Connect**, select Nextcloud, enter this URL and the app password, then tap **Verify &
connect**. Registration performs a real PROPFIND request. An authentication, DNS, TLS, network, or
permission failure leaves the provider offline. A successful server that does not report DAV quota is
online for file operations but contributes zero to the capacity totals.

### Verify outside the app

Use a non-production test folder and an app password. Do not paste real credentials into shell history
or logs. `curl` can prompt for the password:

```bash
curl -u 'NEXTCLOUD_USERNAME' \
  -X PROPFIND -H 'Depth: 0' \
  -H 'Content-Type: application/xml' \
  --data '<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop><d:quota-available-bytes/><d:quota-used-bytes/></d:prop></d:propfind>' \
  'https://DOMAIN/remote.php/dav/files/NEXTCLOUD_USERNAME/'
```

Confirm HTTP 207 and inspect the actual quota values. Then create a small test folder/file in the
Android app and verify it appears in Nextcloud. Test upload, download, rename, delete, preview, and
public sharing with non-sensitive data before using the deployment for real files.

## 4. Infinity capacity semantics

A provider contributes to **Verified capacity** only when all of these conditions hold:

1. The user explicitly registered the endpoint and supplied its authorization.
2. The most recent health operation succeeded over authenticated HTTPS.
3. Its DAV response contains non-negative `quota-available-bytes` and `quota-used-bytes`.
4. `total = available + used` can therefore be derived.

Offline, checking, failed, disconnected, unregistered, and quota-unreported endpoints are excluded.
Last-known quota can be shown on a provider card for troubleshooting but is not counted while offline.
The aggregate is not a reservation, guarantee, RAID set, or distributed filesystem.

### Current distributed-storage boundary

The app supports multiple independent authorized connections, health checks, measured aggregation,
and connection removal. It does **not** yet shard, stripe, erasure-code, replicate, or automatically
recover objects across those connections. Those operations require a coordinated backend and are
listed as PLANNED, not as working buttons.

## 5. Data flows

### Cloud upload

SAF OpenDocument grant → app reads the user-selected stream → WebDavClient PUT with Basic
authentication → streamed 128 KiB chunks → real progress callback → remote PROPFIND refresh. Failures
are shown; no success message is inferred from starting a request.

### Cloud download/preview

Remote GET → streamed destination → measured byte count and SHA-256. Downloads go to an SAF destination
chosen by the user. Previews go to a 24-hour app-cache directory (maximum 256 MiB), receive a
FileProvider URI, and open only if an installed viewer supports the type. A local SHA-256 is evidence
of the bytes received, not publisher authenticity.

### SAF file operations

OpenDocumentTree grant → DocumentsContract listing/mutations. Imports create a destination first and
attempt to remove it if copying fails. Preview/share use URI-granted Android intents. Delete/rename
always require provider support; destructive actions require confirmation.

### Folder security scan

Explicit tree grant → recursive DocumentsContract traversal → existing local file/APK scanners → Room
scan history. The current bounds are 250 files per run and 512 MiB per individual file; skipped and
error counts are reported. No all-files permission is requested. Periodic/background folder scanning
is not scheduled by this implementation.

### Direct media download

HTTPS URL → HEAD inspection (or one-byte Range fallback) → supported MIME validation → SAF destination
→ Android DownloadManager. HTML and unsupported responses are refused. Redirects cannot downgrade to
HTTP. Android controls background scheduling and pause reasons. Manual pause/resume and website stream
extraction are not claimed.

Integrity checks compare a publisher-supplied SHA-256 when the user provides one. Otherwise the app can
verify declared size and calculate a local digest, explicitly labelled as lacking a publisher reference.

## 6. Private-search boundary

DuckDuckGo and Google queries use HTTPS inside the existing filtered WebView. Search suggestions are
**off by default** because enabling them sends typed text to the selected provider. Search history is
search text only, kept locally in DataStore, with clear and automatic-deletion controls. Private mode
disables history, cookies, DOM storage and cache for the app WebView and clears WebView session data on
exit. It does not make Google, DuckDuckGo, websites, ISPs, or networks unable to observe their own
requests/metadata.

## 7. Backup and recovery requirements

Room migration 2→3 preserves existing DNS/rule/statistics data and adds security/provider/download
tables. Existing configuration backup behavior is unchanged. Provider passwords are not exported.

Nextcloud file versions/trash are server facilities, not a substitute for backups. An operator must
implement and test all of the following:

1. PostgreSQL consistent dumps (`pg_dump` through the compose service).
2. Snapshots/copies of `nextcloud_data` coordinated with database state and maintenance mode.
3. Caddy/configuration and `.env` secret backup in a restricted secret store.
4. Off-server immutable backup copies and monitored schedules.
5. Documented restore drills on a separate host, including file ownership and database credentials.

This repository does not claim automatic backup scheduling or a completed recovery test. Those require
the operator's infrastructure and recovery destination.

## 8. Performance and security controls

- Streaming 128 KiB transfer/hash buffers instead of whole-file in-memory payloads.
- Lazy keyed Compose lists; progress polling only while Downloads is visible.
- No continuous provider-health service or battery-draining storage poll loop.
- Bounded recursive scans and preview size; user-initiated large work.
- HTTPS-only remote endpoints and no HTTPS→HTTP redirect downgrade.
- Rejection of embedded URL credentials, traversal paths, DTD-based XML, unsupported custom schemes,
  embedded media URL passwords, and unbounded filename/path input.
- No private server credentials in BuildConfig, the web app, or public deployment files.
- AETHER report explanations use persisted evidence and cannot independently mutate device/server state.

See `docs/INFINITY_VERIFICATION.md` for exact tests performed and remaining external requirements.
