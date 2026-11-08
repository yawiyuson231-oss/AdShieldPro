# World Monitor v2 — OmniShield X 5.1

World Monitor is an evidence-first addition to the existing Android and browser platforms. It is
not an infinite-feed claim, a prediction engine, an emergency dispatch service, or an indication
that all existing planned Android capabilities have become implemented.

## What is implemented

- **250 country and territory profiles**, searchable by name, code and region, with saved countries,
  capital/language/currency/area metadata and links to the actual received records.
- **237 approximate geographic boundaries** (Natural Earth). Thirteen territory entries have no
  separate bundled polygon and explicitly show that geographic counts are unavailable. Headlines
  mentioning a country are shown separately from geolocated events. Zero received records does not
  mean there are no hazards. Listings do not imply a position on sovereignty.
- **12 built-in public source adapters**, **8 event layers**, **up to 100 configured sources**
  (12 built-in + 88 user-added keyless HTTPS endpoints). These are distinct endpoints, not 100
  providers claimed to be verified. A custom endpoint must implement a supported JSON schema and
  permit browser requests; validation and errors are visible.
- Offline SVG world map with pan, wheel/pinch/keyboard zoom, clustering, map focus, region boundaries,
  accessible event buttons and a paginated text alternative. No external map tiles or GPS permission.
- Search (all words), region, time window, priority, source, layer and ordering controls.
- Source-qualified event IDs, deduplication **within each source**, per-source freshness, bounded
  storage, single-flight requests, three-source concurrency, cancel, timeouts, size caps, backoff,
  rate-limit handling and last-good-data retention. Reports from two providers may describe the same
  physical event; counters say **records**, not unique incidents.
- Local bookmarks, up to 30 keyword/region/layer/priority watches, a 300-match acknowledgement inbox,
  JSON watchlist transfer and confirmation-gated cache clearing. Alerts cover received records from
  the past seven days; they are not OS push or emergency notifications.
- Deterministic Markdown situation briefings, attributed JSON and formula-escaped CSV exports.
  Exports contain the current filtered records (or saved snapshots) and source-health metadata.
- Explicit five-day Open-Meteo forecasts and CAMS/US-AQI estimates at a chosen city or manually entered
  coordinates, including partial-provider failure, cached timestamps and source attribution. These
  are **modelled conditions**, not device sensors. No location tracking.
- Explicit World Bank population and GDP-per-capita lookups. The actual **publication year** is
  displayed. An older published indicator is never described as a current census.
- Responsive sidebar/navigation, light/dark theme, keyboard command finder (Ctrl/Cmd+K), focus-aware
  dialogs, URL/back navigation and readable empty/error states. Existing DNS, AETHER, firewall,
  backup, privacy and extension workflows remain available.

## Daily updates: what “every day” means

Daily refresh is **opt-in** under **Sources → Daily updates**.

| Surface | Behaviour |
|---|---|
| Browser | Checks once per day while the World Monitor page is open, visible and online. A closed tab cannot guarantee a background job. |
| Browser five-minute mode | Separate session-only control; refreshes due sources every five minutes while the World Monitor page is visible. Provider TTLs/backoff still apply. |
| Android | WorkManager requests a 24-hour periodic job, first scheduled after 24 hours, requiring connected networking and battery-not-low. Android power saving, force-stop and scheduling may delay it. No exact alarm or foreground service is used. |
| Android custom feeds | Browser-side only; refresh when the view is open. Arbitrary custom URLs are not silently added to the native background network allowlist. |
| On opening Android World | The shared parser revalidates the most recent native snapshot. It is labelled cached/background-received, not a new live WebView response. Newer interactive results win. |

Turning daily updates off cancels the native job. No daily schedule is created merely by opening the
screen. Failed requests retain the previous payload and their error text; a failed day is not turned
into a fabricated success. The existing Android connector worker is independent and is not replaced.

## Built-in feeds

Five feeds are initially selected, but **none are requested until Refresh (or an explicitly enabled
schedule)**. Enabling a checkbox alone does not fetch anything.

| Source | Data | Default selected | Cadence / scope |
|---|---|---:|---|
| USGS | Magnitude 2.5+ earthquakes | Yes | 5 min; past 24 hours |
| NASA EONET | Open natural events | Yes | 30 min; up to 200 upstream records |
| GDACS | Earthquake impact alerts | Yes | 15 min; provider alert colours; upstream browser bot protection can block requests |
| US NWS | Active weather alerts | No | 10 min; United States only |
| CISA KEV | Known-exploited CVEs, official GitHub mirror | Yes | 6 hours; latest 800 entries |
| GitHub Advisories | Latest reviewed advisories | Yes | 1 hour; 50 upstream records |
| NOAA SWPC | Space-weather bulletins | No | 15 min; no inferred local impact |
| GeoNet | New Zealand earthquakes | No | 10 min; upstream intensity selection |
| EMSC | Latest seismic reports | No | 10 min; 100 upstream records |
| GitHub Status | Official service incidents | No | 10 min; resolved incidents labelled |
| Cloudflare Status | Official service incidents | No | 10 min; no invented coordinates |
| GDELT | World news headlines | No | 15 min; 75 headlines over 24 hours, not independently verified |

URLs, attribution, terms and cache TTLs are in [`world/catalog.js`](../world/catalog.js). The generated
[`world/providers.json`](../world/providers.json) is the exact native daily-worker allowlist; CI checks
it against the JavaScript catalogue. Public availability is not a guarantee: CORS, rate limits,
changes in terms and outages can make a source unavailable. Read the individual source card.

### Priority rules

- USGS, GeoNet, EMSC: local magnitude bands (7+ critical, 6+ high, 4.5+ moderate). Not damage forecasts.
- GDACS: provider red → critical; orange → high; green/unknown → informational.
- NWS and GitHub advisories: explicit provider ratings mapped to the displayed scale.
- CISA: high as a local triage policy because exploitation is documented, **not** a CVSS probability
  or proof the user's device is affected.
- EONET, news and NOAA: informational when no comparable rating is supplied. Informational is not
  a verdict of safety.
- Status-page incidents: use provider impact; resolved records are informational.

The detail dialog names the basis for every priority. Missing coordinates are never turned into
zero/zero, a publisher's country, a random dot, or a guessed location.

## Custom feed contract

Supported formats: documented GeoJSON, USGS, EONET, NWS, GDACS, CISA KEV, GitHub advisory arrays and
GDELT-compatible JSON. Custom feeds are explicitly labelled user-added and unverified.

```json
{
  "type": "FeatureCollection",
  "features": [{
    "type": "Feature",
    "id": "publisher-record-123",
    "properties": {
      "title": "Publisher event title",
      "occurredAt": "2026-11-08T10:00:00Z",
      "category": "disaster",
      "severity": "info",
      "summary": "Plain text only",
      "url": "https://example.org/original-report"
    },
    "geometry": { "type": "Point", "coordinates": [121, 15] }
  }]
}
```

`geometry` can be null. Categories: `seismic`, `wildfire`, `weather`, `disaster`, `cyber`, `space`,
`infrastructure`, `news`. Priority values: `info`, `moderate`, `high`, `critical`. Nonempty feeds with
no valid dated records fail instead of being marked live. A schema-valid empty array is a valid
zero-result response. Refresh intervals are 1–168 hours for custom feeds. Private/literal local
addresses, credentials in URLs and secret-like query parameters are rejected. There is no open proxy.

## Architecture and security

```
world/catalog.js + custom.js        reviewed registry / explicit custom subscriptions
world/network.js                   bounded, credential-free HTTPS, timeout and rate-limit handling
world/parsers.js                    per-provider validation / normalization
world/model.js                     filters, watches, clustering, histogram, exports
world/store.js + storage.js        bounded snapshots, IndexedDB, cache health, concurrency, inbox
world/countries*.js                 directory, geographic lookup, dated country indicators
world/weather.js                   explicit forecast + air requests with independent failure handling
world/map.js + view.js              shared DOM/SVG interface; no remote scripts or HTML sinks
world/embed.html + embed.js         packaged Android entry point
WorldMonitorScreen.kt               WebViewAssetLoader + exact-origin WebMessage channels + SAF
WorldMonitorWorker.kt               opt-in WorkManager, fixed provider allowlist, AtomicFile snapshot
WorldMonitorPolicy.kt               pure URL/origin/export/response policy with JVM tests
```

- API requests omit cookies and referrers. Providers receive the IP address and, for explicit
  weather lookups, the chosen rounded coordinates. No DNS history, app inventory, accounts or keys
  are attached. Keyword filtering and watches run locally.
- Event text uses safe DOM construction. Provider HTML is never interpreted. Links are HTTPS-only,
  opened with `noopener noreferrer`; no arbitrary HTML report rendering or script evaluation.
- The Android screen loads **packaged files**, not a remote website. Native message listeners are
  restricted to the exact `https://appassets.androidplatform.net` origin and the main frame.
  There is no unrestricted `addJavascriptInterface`. Navigation does not load arbitrary websites
  into the privileged WebView. Mixed content, file access, location and automatic windows are off.
- Native export validates filename, MIME and UTF-8 byte length, then prompts with
  `ACTION_CREATE_DOCUMENT`. It never writes an arbitrary filesystem path. Watchlist import uses a
  user-selected document. A recent Android System WebView is required for secure host channels.
- At most 800 records/source, 200 bookmarks, 30 watches, 300 inbox entries, 6 MB/provider response,
  15-second browser timeout and 3 concurrent source requests. Export cap: 8 MB. Native cache cap:
  30 MB. Quota failures are visible and in-memory results remain usable.
- World records use IndexedDB so larger feed caches do not consume the small localStorage quota
  used by existing DNS/security settings. Legacy world records migrate only after a confirmed write.
  If IndexedDB is unavailable, the previous adapter remains available; quota failures stay visible.
  Offline snapshots have a 12 MB UTF-8 budget and retain newest records fairly across providers.
  Reduction is disclosed after reload; watches/bookmarks are never silently discarded. In-memory
  records remain available for filtered exports.
- Local browser/webview storage is not encrypted; a person with access to the device/profile can
  read it. Browser and Android workspaces are separate; use explicit exports to transfer watches.
- SW caches only the local shell/assets. API responses are never silently served from the SW.
  Activating a new release deletes only this app's older cache namespaces. A server error cannot
  overwrite the last good offline navigation shell. An incomplete update cannot activate; embedded-page
  navigation cannot poison the main shell; even same-origin custom feeds bypass the worker.

## Data licences

- Natural Earth land/boundary geometry: **public domain**, retrieved from
  `nvkelso/natural-earth-vector`. Boundary rings are rounded and simplified (0.012° tolerance), so
  coastline/border inclusion is approximate. This is not a legal, territorial or navigation tool.
- Country directory: derived from `mledoze/countries`, **ODbL-1.0**. The derived directory is
  distributed under that licence; full text is in [`assets/country-data-license.txt`](../assets/country-data-license.txt).
- Open-Meteo / CAMS and World Bank: attribution shown alongside results. Provider API fair-use and
  non-commercial restrictions apply where stated. Other feed terms are shown per source.

## Validation and release boundaries

`npm run test:browser` runs 12 real-Chromium acceptance checks, including phone-width panes, pointer/keyboard map controls, document downloads, file import, persisted watches/theme and actual offline reload.

`npm run ci` exercises the existing app and the new monitor; `npm run stage` verifies the staged
runtime and every offline asset. New tests are in `tests/unit/world.test.mjs`,
`tests/integration/world.test.mjs`, `tests/integration/world-embed.test.mjs`, `tests/unit/sw.test.mjs`, `tests/browser/world-smoke.mjs`, and
`WorldMonitorTestSuite.kt`. They use labelled synthetic fixtures only at the fetch boundary; fixture
files are not bundled into the website/APK. The running UI has no demo-event injection.

The `World Monitor daily source health` workflow probes all 12 public event endpoints and the actual weather/air and country-indicator clients using a fixed Manila/Philippines sample, and parses actual responses. It reports HTTP, record counts, CORS permission and failures in a dated artifact; its daily cron starts only after merge to the default branch. A green audit means the audit ran, not that every provider is reachable. `npm run probe:world` performs the same optional network check.

Android compilation, JVM tests, R8 packaging and lint are run by the Android workflow. `tools/check_world_assets.py` compares every shared runtime asset inside both real APKs byte-for-byte with the tested source and rejects missing/extra files. A physical
Android device is still required to verify document-picker providers, touch/pinch gestures,
background scheduling after reboot/doze and upgrade installation. Exact daily timing, zero public
provider outages, unlimited sources and “every planned feature works” are **not** claims of this build.

Versioning: the parent app/browser are **5.1.0** (`versionCode 50100`); this new workspace is called
**World Monitor v2**. The higher Android code preserves upgrade ordering over the previous 2.10.2.
A source-branch upgrade is not a published release APK; publishing still uses the existing release
workflow after review and device checks.
