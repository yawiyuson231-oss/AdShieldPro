# OMNISHIELD X INFINITY — WORLD MONITOR 2035 Architecture & Source Ledger

World Monitor 2035 is an additive, offline-resilient **3D Digital Earth & Multi-Domain Global Intelligence Platform** embedded inside the existing AdShield Pro Android APK (`com.adshield.pro`).

## 1. Non-Destructive Integration Guarantees
- **Navigation & Shell Preserved**: All 13 existing `MainNavDestination` tabs, `CyberBottomNav`, and isolated `*Destination` composables in `MainActivity.kt` remain intact. World Monitor 2035 opens additively via a dedicated `worldMonitorOpen` full-screen overlay (matching `ConnectorRegistryScreen`), accessible from the **Intel Command Panel**, **Home Dashboard**, and **Watchtower Notification** deep links.
- **Database Isolation**: World Monitor persists cached entities, kinematic trails, provider sync metadata, Watchtower geofences, and alert history in an isolated Room database (`world_monitor_2035.db`), leaving `AdShieldDatabase` v6 (`adshield_pro_v2.db`) untouched with zero WAL contention against `AdShieldVpnService`.
- **No Mandatory VPN or Cloud Backend**: All 26 default-enabled providers connect directly over HTTPS from the user's device without requiring the local DNS VPN to be active, without proprietary proxy servers, and without any paid or cloud AI service.

## 2. 3D Digital Earth & WebView Security Architecture
- **Bundled Open-Source Runtime (`app/src/main/assets/worldmonitor/vendor/`)**:
  - `cesium@1.147.0` (`Apache-2.0`) — WebGL 3D globe, Columbus 2.5D, and 2D Mercator projections; `Cesium.Ion.defaultAccessToken = ""` (zero Cesium Ion dependency).
  - `satellite.js@6.0.1` (`MIT`) — Client-side SGP4/SDP4 orbital propagation, ground tracks, and 24-hour overhead pass predictions.
  - `topojson-client@3.1.0` (`ISC`) + `world-atlas@2.0.2` (`ISC` / Natural Earth Public Domain) — Offline sovereign country borders.
- **Keyless 3D Terrain & Imagery**:
  - **Terrain**: Custom heightmap provider decoding public AWS Open Data Mapzen Terrarium elevation PNG tiles (`(R * 256 + G + B / 256) - 32768` meters MSL).
  - **Basemaps & Overlays**: Esri World Imagery, OpenStreetMap Standard, CARTO Dark Matter, NASA GIBS Blue Marble / VIIRS True Color (including dual-date split-screen historical comparison), NASA GIBS MODIS Cloud Top Temperature, and RainViewer animated global precipitation radar.
  - **120 MB Persistent Tile Cache**: `WorldMonitorAssetAndTileServer` proxies allowlisted HTTPS tile hosts through an OkHttp disk cache (`worldmonitor_tiles_v1`) so visited 3D terrain and satellite imagery render offline.
- **Hardened JS <-> Kotlin Bridge (`WorldMonitorJsBridge`)**:
  - `WebSettings`: `allowFileAccess = false`, `allowContentAccess = false`, `mixedContentMode = MIXED_CONTENT_NEVER_ALLOW`, `setSupportMultipleWindows(false)`, strict CSP in `index.html`.
  - Inbound `@JavascriptInterface` payloads enforce a 16 KB ceiling, strict JSON object parsing, finite WGS84 bounds (`[-90, 90]`, `[-180, 180]`), identifier regex whitelisting, and HTTPS-only external source URLs.
  - Outbound Kotlin -> JS commands are UTF-8 Base64 encoded (`window.WorldMonitorApp.receiveBase64(...)`) to eliminate script injection vectors.

## 3. Multi-Domain Provider Ledger (Categories A–H)

| ID | Category | Provider | Auth | Default | Refresh / Gap | License & Attribution |
|---|---|---|---|---|---|---|
| `wm.aviation.opensky` | Aviation | OpenSky Network ADS-B | Keyless (Optional `wm.cred.opensky`) | On | 60s / 30s | OpenSky Terms (Non-commercial OSINT) |
| `wm.aviation.adsblol` | Aviation | ADSB.lol Community Emergency Squawks | Keyless | On | 60s / 30s | ODbL / ADSB.lol Community |
| `wm.aviation.ourairports` | Aviation | OurAirports Global Hub Catalog | Keyless | On | 7d / 1h | Public Domain (CC0) |
| `wm.maritime.digitraffic` | Maritime | Fintraffic Digitraffic Live AIS | Keyless | On | 2m / 60s | CC BY 4.0 · Fintraffic |
| `wm.maritime.ndbc` | Maritime | NOAA NDBC Global Ocean Buoys & Ships | Keyless | On | 15m / 5m | US Public Domain (NOAA) |
| `wm.maritime.aisstream` | Maritime | AISStream Global AIS (WebSocket) | Required Key (`wm.cred.aisstream`) | Off | External | Requires user key & WebSocket stream proxy |
| `wm.space.iss` | Space | WhereTheISS.at Live ISS Telemetry | Keyless | On | 20s / 10s | Open API (WTIA) |
| `wm.space.celestrak.stations` | Space | CelesTrak Space Stations (3LE) | Keyless | On | 6h / **2h min** | CelesTrak Public GP Policy |
| `wm.space.celestrak.weather` | Space | CelesTrak Weather & Earth Obs (3LE) | Keyless | On | 6h / **2h min** | CelesTrak Public GP Policy |
| `wm.space.celestrak.gnss` | Space | CelesTrak Navigation Satellites (3LE) | Keyless | On | 12h / **2h min** | CelesTrak Public GP Policy |
| `wm.space.launches` | Space | The Space Devs — Upcoming Launches | Keyless | On | 30m / 10m | CC BY-NC-SA 4.0 (Free Tier) |
| `wm.space.swpc.kp` | Space | NOAA SWPC Planetary K-Index | Keyless | On | 15m / 5m | US Public Domain (NOAA SWPC) |
| `wm.space.swpc.alerts` | Space | NOAA SWPC Solar & Geomagnetic Alerts | Keyless | On | 15m / 5m | US Public Domain (NOAA SWPC) |
| `wm.disaster.usgs.day` | Disaster | USGS Global Earthquakes (24h M2.5+) | Keyless | On | 5m / 1m | US Public Domain (USGS) |
| `wm.disaster.emsc` | Disaster | SeismicPortal / EMSC Global Quakes | Keyless | On | 5m / 2m | EMSC Open Access |
| `wm.disaster.eonet` | Disaster | NASA EONET Active Natural Events | Keyless | On | 15m / 5m | US Public Domain (NASA) |
| `wm.disaster.gdacs` | Disaster | UN/EC GDACS Global Disaster Alerts | Keyless | On | 15m / 5m | GDACS Open Humanitarian |
| `wm.disaster.firms` | Disaster | NASA FIRMS VIIRS Thermal Hotspots | Required Key (`wm.cred.nasa_firms`) | Off | 30m / 10m | US Public Domain (Free NASA `MAP_KEY`) |
| `wm.weather.openmeteo` | Weather | Open-Meteo Global Hub Synoptic Grid | Keyless | On | 20m / 5m | CC BY 4.0 (Open-Meteo) |
| `wm.weather.airquality` | Weather | Open-Meteo CAMS Global Air Quality | Keyless | On | 30m / 10m | CC BY 4.0 (Copernicus CAMS) |
| `wm.weather.marine` | Weather | Open-Meteo GloFAS River Discharge | Keyless | On | 1h / 15m | CC BY 4.0 (Copernicus GloFAS) |
| `wm.weather.nws` | Weather | NOAA NWS Active Severe Alerts | Keyless | On | 10m / 2m | US Public Domain (NOAA NWS) |
| `wm.weather.rainviewer` | Weather | RainViewer Global Radar Composite | Keyless | On | 10m / 3m | RainViewer Public Radar API |
| `wm.cyber.cisa.kev` | Cyber | CISA Known Exploited Vulnerabilities | Keyless | On | 6h / 30m | US Public Domain (CISA) |
| `wm.cyber.feodo` | Cyber | Abuse.ch Feodo Botnet C2 Tracker | Keyless | On | 30m / 10m | CC0 / Abuse.ch |
| `wm.cyber.ioda` | Cyber | IODA Internet Outage Detection | Keyless | On | 15m / 5m | Georgia Tech / CAIDA IODA |
| `wm.cyber.ripestat` | Cyber | RIPEstat Global BGP Routing Status | Keyless | On | 15m / 5m | RIPE NCC Open Data |
| `wm.news.gdelt` | News | GDELT Project 2.0 Global Geo-Events | Keyless | On | 15m / 5m | GDELT Open Data |
| `wm.news.un` | News | United Nations Global News Feed | Keyless | On | 30m / 10m | UN News Public RSS |
| `wm.infra.baseline` | Infrastructure | Bundled Global Critical Infra Reference | Offline Asset | On | Bundled | CC0 / Public Domain / CC BY 4.0 |
| `wm.infra.overpass` | Infrastructure | OpenStreetMap Overpass 3D Buildings & Infra | Keyless | On (Zoomed) | 10m / 30s | ODbL © OpenStreetMap contributors |

## 4. Epistemic Honesty & Known Limitations
- **Dynamic Staleness Decay**: Cached `LIVE` records automatically decay to `NEAR_REAL_TIME` (>5 min), `DELAYED` (>30 min), and `HISTORICAL` (>6 hours) when read offline so stale aircraft or ship positions are never presented as real-time.
- **Coarse Cyber & News Geolocation**: Cyber advisories (`wm.cyber.cisa.kev`, `wm.cyber.ioda`, `wm.cyber.ripestat`) and country-matched UN bulletins carry `ASN_COUNTRY_LEVEL` or `ADMIN_CENTROID` accuracy tags rather than street-level coordinates.
- **Commercial Global AIS & Live Satellite Video**: Keyless open AIS (`wm.maritime.digitraffic`) covers Baltic/Nordic waters while `wm.maritime.ndbc` covers global ocean buoys/SHIP reports; global satellite AIS requires commercial licensing or a user-configured AISStream WebSocket proxy. Real-time live video from Earth-observation satellites or private CCTV networks is not publicly available and is never fabricated.
