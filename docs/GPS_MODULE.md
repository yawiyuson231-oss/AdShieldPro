# GPS, maps, navigation and community traffic

A complete, **zero-cost** GPS module inside the existing AdShield Pro APK. It is a new package
(`com.adshield.pro.gps.**`) with its own Room database, its own Hilt module and its own navigation
tab. The DNS/VPN engine is untouched and the two modules never share state.

Everything the module claims is either measured or explicitly marked unavailable. There is no
simulated position anywhere in the source, and the traffic layer is designed so that **the honest
answer — UNKNOWN — is the default**.

---

## 1. What runs on the device

| Section | What it does | Implementation |
|---|---|---|
| **GPS Map** | Full-screen MapLibre vector map, live marker, camera follow, traffic overlay, style switch | `gps/map/MapLibreEngine.kt`, `gps/ui/screens/GpsMapScreen.kt` |
| **Navigate** | Open geocoding search, OSRM/Valhalla/offline routing, turn-by-turn, rerouting, TTS | `gps/nav/NavigationSession.kt`, `gps/ui/screens/NavigationScreen.kt` |
| **Live Traffic** | Community speed observations, congestion colours, incident reports, UNKNOWN when empty | `gps/traffic/TrafficRepository.kt`, `gps/ui/screens/TrafficScreen.kt` |
| **GPS Radar** | Real satellite sky plot from `GnssStatus`, per-satellite table, integrity findings | `gps/engine/RadarGeometry.kt`, `gps/ui/screens/GpsRadarScreen.kt` |
| **Telemetry** | Speed gauge, compass, accuracy bar, every raw receiver reading, encrypted trip log | `gps/engine/GpsEngine.kt`, `gps/ui/screens/TelemetryScreen.kt` |
| **Location Security** | Permission audit, mock/anomaly findings, privacy switches, kill switch, delete-all | `gps/security/LocationSecurity.kt`, `gps/ui/screens/LocationSecurityScreen.kt` |
| **Offline Maps** | Region planner within the free tile budget, pack list, graph import, storage facts | `gps/offline/OfflinePlanner.kt`, `gps/ui/screens/OfflineMapsScreen.kt` |

Entry point: `GpsHubScreen()` in `gps/ui/GpsHubScreen.kt`, reachable from the bottom navigation as
**GPS** (`MainNavDestination.GPS`).

## 2. The free stack

| Concern | Provider | Cost | Notes |
|---|---|---|---|
| Map rendering | MapLibre Native 13.7.1 (OpenGL backend) | BSD-2, free | Arm64/armv7/x86/x86_64 native libs ship in the AAR |
| Map data | OpenStreetMap via OpenFreeMap styles | free, MIT-style terms | `liberty`, `dark`, `bright`, `positron` |
| Geocoding | Nominatim | free, fair-use | identifying User-Agent, ≥1.2 s between calls |
| Routing | OSRM demo / Valhalla demo / offline graph | free, fair-use | the app reports rate limits instead of hiding them |
| Voice | Android TextToSpeech | free, on-device | reports `LANGUAGE_MISSING` rather than speaking wrong phonemes |
| Traffic | this device's own observations + optionally one self-hosted server | free | no commercial feed exists in the code |
| Storage | Room + DataStore + Keystore | free | separate database from the DNS module |

Nothing in the dependency graph requires an API key, an account or a payment method.

Fair-use ceilings are enforced in code, not in a README: `GpsPreferences.Companion` caps an offline
pack at **3 000 tiles / 50 MB**, parallel tile requests at **4**, geocoding and traffic calls at
**40/min**, routing at **30/min**, and `OfflinePlanner` refuses a download that would exceed them
*before* the first network request.

## 3. Honesty rules (these are the interesting part)

1. **No fabricated positions.** `GnssFix` is only ever constructed from a real `android.location.Location`.
   A field the receiver does not report stays `null` and the UI prints "not reported".
2. **UNKNOWN traffic is the default.** A segment has a colour only if it has observations younger
   than 30 minutes *and* a confidence score of at least 0.35. Otherwise it renders grey with the
   reason. There is no "typical speed for this hour" fallback.
3. **Integrity verdicts are heuristics and are labelled as such.** The UI says plainly that a rooted
   device can defeat app-side spoofing detection.
4. **Offline routing fails loudly.** With no imported graph the router returns
   `NO_OFFLINE_GRAPH`; it never draws a straight line to the destination.
5. **TTS never invents.** A missing voice language is reported, not replaced with an English
   approximation of another language.
6. **Mock-flagged positions are quarantined**: excluded from trip history, traffic samples and
   incident reports (`IntegrityReport.shouldRejectObservation`).

## 4. Privacy defaults

Every sharing path starts **off**:

| Switch | Default | What it controls |
|---|---|---|
| Contribute traffic | off | one average speed per road segment, no coordinates |
| Report incidents | off | user-submitted accident/hazard reports |
| Trip history | off | encrypted local trips (AES-256-GCM, Keystore key) |
| Coarse history only | **on** | coordinates rounded to ~1 km |
| Emergency sharing | off | generates text the user copies; the app never uploads it |
| Kill switch | off (when engaged, blocks everything incl. emergency) | hard stop for every sharing path |

Background location is deliberately **not** requested. Location is read while a GPS screen is open
or navigation is running in a foreground service, and stops otherwise.

## 5. Offline

Two independent artefacts, because they fail independently:

**Map tiles** — `MapLibreEngine.downloadRegion()` creates an `OfflineRegion` through
`OfflineManager`, records it in Room, and streams progress into the pack row. Sizes are estimated
from tile count (`OfflinePlanner.AVERAGE_VECTOR_TILE_BYTES`), because MapLibre does not expose the
required byte count; the UI labels it an estimate.

**Routing graph** — build one from any OSM extract:

```bash
python3 tools/osm_graph_builder.py region.osm --output region.adg.gz   # or .pbf with osmium
```

Then **Offline maps → Routing graph → Import**. The import validates the file with
`OfflineRoadGraph.readFile()` *before* accepting it, so a corrupt graph fails at import time rather
than mid-journey.

Graph format (`ADG1`, little-endian, gzip container, documented in `OfflineRoadGraph.kt`):

```
magic "ADG1" | version | nodeCount | edgeCount | nameCount
south, west, north, east : double
nodeLat[nodeCount], nodeLon[nodeCount] : double
edgeFrom[edges], edgeTo[edges] : int
edgeLengthM[edges] : double | edgeSpeedKmh[edges] : float
edgeNameIndex[edges] : int (-1 = unnamed) | edgeClass[edges] : byte
names: nameCount × (uint16 length + UTF-8)
```

Routing is A* over that graph with the great-circle distance as an admissible heuristic; turn
instructions are generated from the geometry and the road names in the graph.

## 6. Optional community traffic server

`gps-backend/` is a ~600-line Node 20 service (zero runtime dependencies in memory mode,
`pg` only for Postgres) with:

* `postgres/migrations/0001_init.sql` — PostGIS schema: segments, observations, incidents,
  permanent hourly aggregates, rate limiting, and a `live_segment_traffic` view that matches the
  client's 30-minute window.
* `api/server.mjs` — the four endpoints the app calls (`/v1/traffic/observations`,
  `/v1/traffic/incidents`, `/v1/traffic/segments`, `/v1/health`), plus an in-memory store for
  local testing.
* `tests/api.test.mjs` — 10 contract tests, including "a segment with no observations is absent,
  not green" and "one sample is not enough evidence".

```bash
cd gps-backend
npm run dev                       # in-memory, no database, no cost
npm test                          # 10 tests, no external services
# production:
npm run migrate                   # applies the PostGIS schema
DATABASE_URL=postgres://… npm start
```

Then set the URL in **Live traffic → Backend URL**. The app refuses cleartext HTTP except on
loopback/emulator hosts, so a deployment needs TLS (Caddy + a free certificate is enough).

**If you never run this**, the module works completely — traffic simply shows UNKNOWN for roads you
have not driven. That is the intended default, not a degraded mode.

## 7. Module layout

```
com/adshield/pro/gps/
├── geo/        Geodesy.kt, MapProjection, GeoBounds          (pure maths)
├── engine/     GnssLocationSource, GpsEngine, HeadingSensor,
│               PositionModels (fix/integrity/movement), RadarGeometry
├── security/   SecureLocationStore (AES-GCM), LocationSecurity
│               (policy, permission audit, mock detector, telemetry gate,
│                emergency share, history guard, incident validator)
├── data/       GpsEntities, GpsDatabase (adshield_gps.db), GpsPreferences,
│               GpsNetworkClients (Nominatim/OSRM/Valhalla/traffic)
├── map/        MapLibreEngine, AdShieldMapView (Compose host)
├── routing/    RouteModels, RouteCodec (OSRM/Valhalla/GeoJSON decoding)
├── nav/        NavigationSession, TripRecorder, VoiceGuidance, TtsVoiceGuidance
├── offline/    OfflinePlanner, OfflineRoadGraph (+ A* router)
├── traffic/    TrafficEngine (aggregation/matching/dedupe), TrafficRepository
├── ui/         GpsViewModel, GpsComponents (HUD kit), GpsHubScreen, screens/
├── worker/     TrafficSyncWorker, GpsMaintenanceWorker
└── di/         GpsModule
service/GpsConsoleService.kt   foreground location service
```

Screens collect their own slices from one `GpsViewModel`; the DNS/home tabs never touch location and
never recompose on a satellite tick.

## 8. Permissions

```xml
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
<uses-permission android:name="android.permission.ACCESS_COARSE_LOCATION" />
<uses-permission android:name="android.permission.FOREGROUND_SERVICE_LOCATION" />
<uses-permission android:name="android.permission.WAKE_LOCK" />
<uses-feature android:name="android.hardware.location.gps" android:required="false" />
<uses-feature android:name="android.hardware.sensor.compass" android:required="false" />
```

`INTERNET` is already declared by the app. `ACCESS_BACKGROUND_LOCATION` is **not** declared.
minSdk 29 (Android 10) as before.

## 9. Testing status

**Verified in this repository (JVM, no device):**

* `GpsEngineTest` — 35 tests: geodesy, accuracy bands, nullable readings, integrity (mock/jump/
  clock/spoofed-speed in both directions), movement classification, ETA fallbacks, radar projection
  and ring geometry, sky score, satellite quality notes, segment projection, severity ordering.
* `GpsTrafficSecurityTest` — 33 tests: UNKNOWN-by-default, confidence thresholds, window and
  segment filtering, free-flow derivation, rate limiting, incident dedupe, telemetry gate, privacy
  defaults, kill switch, emergency share gating, history rounding/retention, permission findings,
  incident validation, offline tile budget and auto-fit.
* `GpsOfflineGraphTest` — 17 tests: `ADG1` write/read round-trip (raw, gzipped, on disk), foreign
  magic, wrong version and truncated/corrupt headers all rejected with a reason, A* over a two-leg
  network, direction-aware one-way traversal, offline turn-by-turn plan synthesis, refusal to route
  outside the downloaded pack, nearest-node and on-segment snapping, snap radius, coverage
  distance, and the pack description string.
* `GpsSecureStoreTest` — 11 tests on the `ADSE1` container: exact-byte round-trip, plaintext never
  present in the ciphertext, a fresh IV per write, documented header layout, wrong key rejected,
  bit-flipped ciphertext and IV failing GCM authentication, plaintext and truncated files refused,
  empty payload, and decryption with a reloaded key.
* `gps-backend/tests/api.test.mjs` — 10 tests against the real HTTP handler.
* `tools/osm_graph_builder.py` — graph output verified byte-for-byte against
  `OfflineRoadGraph.readFrom`'s layout (magic, header, arrays, names, no trailing bytes).

**Requires a physical device (not claimed as verified here):** actual GNSS acquisition, sky-plot
population, MapLibre rendering/3D buildings, camera smoothness, TTS pronunciation, offline pack
download against OpenFreeMap's limits, battery/memory under a long drive, and behaviour when the OS
restricts background work. The Android Keystore-backed `SecureLocationStore` (the `ADSE1` container
itself is covered above, the Keystore key lifecycle is not) and the MapLibre tile cache also need a
device. `docs/TESTING.md` describes the manual passes.
