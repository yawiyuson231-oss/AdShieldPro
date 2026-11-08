package com.adshield.pro.engine.worldmonitor

import com.adshield.pro.domain.worldmonitor.ProviderAuthRequirement
import com.adshield.pro.domain.worldmonitor.WorldIntelCategory
import com.adshield.pro.domain.worldmonitor.WorldProviderSpec

/**
 * Modular Provider Registry for OMNISHIELD X INFINITY — WORLD MONITOR 2035 (Section 6).
 *
 * Every provider explicitly declares:
 *  - unique providerId & category
 *  - HTTPS endpoint (with `{south}`, `{north}`, `{west}`, `{east}`, `{lat}`, `{lon}` templates where supported)
 *  - authentication requirements (no paid service is mandatory; no private keys are embedded)
 *  - refresh interval, minimum request gap, rate-limit policy & retry cap
 *  - normalizer identifier, mandatory attribution & license terms
 */
object WorldMonitorProviderRegistry {

    private const val MIN = 60_000L
    private const val HOUR = 60L * MIN
    private const val DAY = 24L * HOUR

    val providers: List<WorldProviderSpec> = listOf(
        // ==================== A. AVIATION INTELLIGENCE ====================
        WorldProviderSpec(
            providerId = "wm.aviation.opensky",
            name = "OpenSky Network Live ADS-B",
            category = WorldIntelCategory.AVIATION,
            endpoint = "https://opensky-network.org/api/states/all?lamin={south}&lomin={west}&lamax={north}&lomax={east}",
            authRequirement = ProviderAuthRequirement.OPTIONAL_USER_KEY,
            credentialSlot = "wm.cred.opensky",
            refreshIntervalMs = 2 * MIN,
            minRequestGapMs = 30_000L,
            rateLimitPolicy = "Anonymous: 400 API credits/day (viewport bbox queries use 1-4 credits); higher quota with free OpenSky account.",
            maxRetries = 1,
            normalizerId = "opensky-states",
            attribution = "The OpenSky Network (https://opensky-network.org)",
            licenseInfo = "OpenSky Terms of Use — free non-commercial/research access; commercial redistribution requires OpenSky permission.",
            docsUrl = "https://openskynetwork.github.io/opensky-api/rest.html",
            supportsViewportBbox = true,
            defaultEnabled = true
        ),
        WorldProviderSpec(
            providerId = "wm.aviation.adsblol",
            name = "ADSB.lol Community Point-Radius ADS-B",
            category = WorldIntelCategory.AVIATION,
            endpoint = "https://api.adsb.lol/v2/point/{lat}/{lon}/250",
            authRequirement = ProviderAuthRequirement.NONE_PUBLIC,
            refreshIntervalMs = 90_000L,
            minRequestGapMs = 20_000L,
            rateLimitPolicy = "Community ADS-B API; viewport radius capped to 250 NM and polled politely.",
            maxRetries = 2,
            normalizerId = "adsblol-v2",
            attribution = "ADSB.lol Open Community ADS-B Contributors",
            licenseInfo = "ODbL / Public Domain community feeder network.",
            docsUrl = "https://api.adsb.lol/docs",
            supportsViewportBbox = true,
            defaultEnabled = true
        ),
        WorldProviderSpec(
            providerId = "wm.aviation.ourairports",
            name = "OurAirports Global Hub Directory",
            category = WorldIntelCategory.AVIATION,
            endpoint = "https://davidmegginson.github.io/ourairports-data/airports.csv",
            authRequirement = ProviderAuthRequirement.NONE_PUBLIC,
            refreshIntervalMs = 7 * DAY,
            minRequestGapMs = HOUR,
            rateLimitPolicy = "Static GitHub Pages CSV; cached locally for 7 days with bundled hub baseline.",
            maxRetries = 1,
            normalizerId = "ourairports-csv",
            attribution = "OurAirports (David Megginson & contributors)",
            licenseInfo = "Public Domain (CC0 1.0 Universal).",
            docsUrl = "https://ourairports.com/data/",
            defaultEnabled = false,
            notes = "Bundled major international airports load immediately; enable to fetch full CSV update."
        ),

        // ==================== B. MARITIME INTELLIGENCE ====================
        WorldProviderSpec(
            providerId = "wm.maritime.digitraffic",
            name = "Fintraffic Digitraffic Live Open AIS",
            category = WorldIntelCategory.MARITIME,
            endpoint = "https://meri.digitraffic.fi/api/ais/v1/locations",
            authRequirement = ProviderAuthRequirement.NONE_PUBLIC,
            refreshIntervalMs = 3 * MIN,
            minRequestGapMs = 45_000L,
            rateLimitPolicy = "Public open-data endpoint; gzipped GeoJSON, max ~1 request/min recommended.",
            maxRetries = 2,
            normalizerId = "digitraffic-ais",
            attribution = "Fintraffic Vessel Traffic Services (meri.digitraffic.fi)",
            licenseInfo = "Creative Commons Attribution 4.0 International (CC BY 4.0). Coverage: Baltic Sea & European Northern waters.",
            docsUrl = "https://www.digitraffic.fi/en/marine-traffic/",
            defaultEnabled = true
        ),
        WorldProviderSpec(
            providerId = "wm.maritime.ndbc",
            name = "NOAA NDBC Global Marine Buoys & Ship Reports",
            category = WorldIntelCategory.MARITIME,
            endpoint = "https://www.ndbc.noaa.gov/data/latest_obs/latest_obs.txt",
            authRequirement = ProviderAuthRequirement.NONE_PUBLIC,
            refreshIntervalMs = 15 * MIN,
            minRequestGapMs = 5 * MIN,
            rateLimitPolicy = "Updated every 5-15 minutes by NOAA; cached 15 minutes.",
            maxRetries = 2,
            normalizerId = "ndbc-latest-obs",
            attribution = "NOAA National Data Buoy Center (NDBC)",
            licenseInfo = "US Government Public Domain (17 U.S.C. § 105).",
            docsUrl = "https://www.ndbc.noaa.gov/",
            defaultEnabled = true
        ),
        WorldProviderSpec(
            providerId = "wm.maritime.aisstream",
            name = "AISStream.io Global Terrestrial AIS",
            category = WorldIntelCategory.MARITIME,
            endpoint = "https://stream.aisstream.io/v0/stream",
            authRequirement = ProviderAuthRequirement.REQUIRED_USER_KEY,
            credentialSlot = "wm.cred.aisstream",
            refreshIntervalMs = 5 * MIN,
            minRequestGapMs = MIN,
            rateLimitPolicy = "Requires free AISStream API key and WebSocket relay; never faked when key is absent.",
            maxRetries = 0,
            normalizerId = "none",
            attribution = "AISStream.io",
            licenseInfo = "Free developer tier with mandatory API key; worldwide commercial satellite AIS requires licensed backend.",
            docsUrl = "https://aisstream.io/documentation",
            defaultEnabled = false,
            implemented = false,
            notes = "Global terrestrial/satellite AIS has no unlimited keyless REST dump. Fintraffic AIS + NOAA NDBC run keyless."
        ),

        // ==================== C. SATELLITE & SPACE INTELLIGENCE ====================
        WorldProviderSpec(
            providerId = "wm.space.iss",
            name = "WhereTheISS.at Live ISS Ephemeris",
            category = WorldIntelCategory.SPACE,
            endpoint = "https://api.wheretheiss.at/v1/satellites/25544",
            authRequirement = ProviderAuthRequirement.NONE_PUBLIC,
            refreshIntervalMs = 2 * MIN,
            minRequestGapMs = 15_000L,
            rateLimitPolicy = "Max 1 request/second documented; polled at 2-minute intervals.",
            maxRetries = 2,
            normalizerId = "wheretheiss-json",
            attribution = "WhereTheISS.at API",
            licenseInfo = "Free public API with attribution.",
            docsUrl = "https://wheretheiss.at/w/developer",
            defaultEnabled = true
        ),
        WorldProviderSpec(
            providerId = "wm.space.celestrak.stations",
            name = "CelesTrak Space Stations & Crewed Vehicles (TLE)",
            category = WorldIntelCategory.SPACE,
            endpoint = "https://celestrak.org/NORAD/elements/gp.php?GROUP=stations&FORMAT=tle",
            authRequirement = ProviderAuthRequirement.NONE_PUBLIC,
            refreshIntervalMs = 6 * HOUR,
            minRequestGapMs = 2 * HOUR,
            rateLimitPolicy = "CRITICAL: CelesTrak blocks IPs polling GP TLEs more than once every 2 hours. Strictly cached 6h.",
            maxRetries = 1,
            normalizerId = "celestrak-tle",
            attribution = "CelesTrak (Dr. T.S. Kelso) / 18 SDS GP Elements",
            licenseInfo = "Public GP orbital elements via CelesTrak; propagated on-device via satellite.js (MIT).",
            docsUrl = "https://celestrak.org/NORAD/documentation/gp-data-formats.php",
            defaultEnabled = true
        ),
        WorldProviderSpec(
            providerId = "wm.space.celestrak.weather",
            name = "CelesTrak Weather & Earth Observation Satellites (TLE)",
            category = WorldIntelCategory.SPACE,
            endpoint = "https://celestrak.org/NORAD/elements/gp.php?GROUP=weather&FORMAT=tle",
            authRequirement = ProviderAuthRequirement.NONE_PUBLIC,
            refreshIntervalMs = 6 * HOUR,
            minRequestGapMs = 2 * HOUR,
            rateLimitPolicy = "Strictly cached 6 hours per CelesTrak GP rate-limit policy.",
            maxRetries = 1,
            normalizerId = "celestrak-tle",
            attribution = "CelesTrak / NOAA / EUMETSAT GP Elements",
            licenseInfo = "Public GP orbital elements; propagated via satellite.js.",
            docsUrl = "https://celestrak.org/NORAD/elements/",
            defaultEnabled = true
        ),
        WorldProviderSpec(
            providerId = "wm.space.celestrak.gnss",
            name = "CelesTrak GPS Operational Constellation (TLE)",
            category = WorldIntelCategory.SPACE,
            endpoint = "https://celestrak.org/NORAD/elements/gp.php?GROUP=gps-ops&FORMAT=tle",
            authRequirement = ProviderAuthRequirement.NONE_PUBLIC,
            refreshIntervalMs = 12 * HOUR,
            minRequestGapMs = 2 * HOUR,
            rateLimitPolicy = "Strictly cached 12 hours per CelesTrak GP rate-limit policy.",
            maxRetries = 1,
            normalizerId = "celestrak-tle",
            attribution = "CelesTrak / US Space Force GPS GP Elements",
            licenseInfo = "Public GP orbital elements; propagated via satellite.js.",
            docsUrl = "https://celestrak.org/NORAD/elements/",
            defaultEnabled = false
        ),
        WorldProviderSpec(
            providerId = "wm.space.launches",
            name = "Launch Library 2 Upcoming Orbital Launches",
            category = WorldIntelCategory.SPACE,
            endpoint = "https://ll.thespacedevs.com/2.2.0/launch/upcoming/?limit=15&mode=detailed",
            authRequirement = ProviderAuthRequirement.NONE_PUBLIC,
            refreshIntervalMs = HOUR,
            minRequestGapMs = 15 * MIN,
            rateLimitPolicy = "Free tier: 15 requests/hour per IP; cached 1 hour.",
            maxRetries = 1,
            normalizerId = "spacedevs-launches",
            attribution = "The Space Devs — Launch Library 2",
            licenseInfo = "Free non-commercial tier (15 req/hr) with attribution.",
            docsUrl = "https://thespacedevs.com/llapi",
            defaultEnabled = true
        ),
        WorldProviderSpec(
            providerId = "wm.space.swpc.kp",
            name = "NOAA SWPC Planetary K-Index & Geomagnetic Storms",
            category = WorldIntelCategory.SPACE,
            endpoint = "https://services.swpc.noaa.gov/products/noaa-planetary-k-index.json",
            authRequirement = ProviderAuthRequirement.NONE_PUBLIC,
            refreshIntervalMs = 30 * MIN,
            minRequestGapMs = 5 * MIN,
            rateLimitPolicy = "Public NOAA feed updated every 3 hours / real-time cadence; cached 30 min.",
            maxRetries = 2,
            normalizerId = "swpc-kp",
            attribution = "NOAA Space Weather Prediction Center (SWPC)",
            licenseInfo = "US Government Public Domain.",
            docsUrl = "https://www.swpc.noaa.gov/products/planetary-k-index",
            defaultEnabled = true
        ),
        WorldProviderSpec(
            providerId = "wm.space.swpc.alerts",
            name = "NOAA SWPC Solar & Space-Weather Alerts",
            category = WorldIntelCategory.SPACE,
            endpoint = "https://services.swpc.noaa.gov/products/alerts.json",
            authRequirement = ProviderAuthRequirement.NONE_PUBLIC,
            refreshIntervalMs = 30 * MIN,
            minRequestGapMs = 5 * MIN,
            rateLimitPolicy = "Public NOAA bulletin JSON; cached 30 min.",
            maxRetries = 2,
            normalizerId = "swpc-alerts",
            attribution = "NOAA Space Weather Prediction Center (SWPC)",
            licenseInfo = "US Government Public Domain.",
            docsUrl = "https://www.swpc.noaa.gov/",
            defaultEnabled = true
        ),

        // ==================== D. EARTH & DISASTER INTELLIGENCE ====================
        WorldProviderSpec(
            providerId = "wm.disaster.usgs.day",
            name = "USGS Global Earthquakes (Past 24 Hours)",
            category = WorldIntelCategory.DISASTER,
            endpoint = "https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/2.5_day.geojson",
            authRequirement = ProviderAuthRequirement.NONE_PUBLIC,
            refreshIntervalMs = 10 * MIN,
            minRequestGapMs = MIN,
            rateLimitPolicy = "Static CDN GeoJSON updated every minute; cached 10 min.",
            maxRetries = 2,
            normalizerId = "usgs-geojson",
            attribution = "U.S. Geological Survey (USGS) Earthquake Hazards Program",
            licenseInfo = "US Government Public Domain.",
            docsUrl = "https://earthquake.usgs.gov/earthquakes/feed/v1.0/geojson.php",
            defaultEnabled = true
        ),
        WorldProviderSpec(
            providerId = "wm.disaster.emsc",
            name = "EMSC SeismicPortal Global/Euro-Med Quakes",
            category = WorldIntelCategory.DISASTER,
            endpoint = "https://www.seismicportal.eu/fdsnws/event/1/query?format=json&limit=50&orderby=time",
            authRequirement = ProviderAuthRequirement.NONE_PUBLIC,
            refreshIntervalMs = 20 * MIN,
            minRequestGapMs = 3 * MIN,
            rateLimitPolicy = "Public FDSN webservice; cached 20 min.",
            maxRetries = 2,
            normalizerId = "emsc-json",
            attribution = "European-Mediterranean Seismological Centre (EMSC)",
            licenseInfo = "EMSC Open FDSNWS attribution terms.",
            docsUrl = "https://www.seismicportal.eu/fdsn-wsevent.html",
            defaultEnabled = true
        ),
        WorldProviderSpec(
            providerId = "wm.disaster.eonet",
            name = "NASA EONET v3 Natural Hazard Events",
            category = WorldIntelCategory.DISASTER,
            endpoint = "https://eonet.gsfc.nasa.gov/api/v3/events?status=open&limit=80",
            authRequirement = ProviderAuthRequirement.NONE_PUBLIC,
            refreshIntervalMs = 30 * MIN,
            minRequestGapMs = 5 * MIN,
            rateLimitPolicy = "Open NASA Earth Observatory API; cached 30 min.",
            maxRetries = 2,
            normalizerId = "nasa-eonet",
            attribution = "NASA Earth Observatory Natural Event Tracker (EONET)",
            licenseInfo = "US Government Public Domain / NASA Open Data.",
            docsUrl = "https://eonet.gsfc.nasa.gov/docs/v3",
            defaultEnabled = true
        ),
        WorldProviderSpec(
            providerId = "wm.disaster.gdacs",
            name = "GDACS UN/EU Global Multi-Hazard Alerts",
            category = WorldIntelCategory.DISASTER,
            endpoint = "https://www.gdacs.org/gdacsapi/api/events/geteventlist/SEARCH?eventlist=EQ,TC,FL,VO,WF,DR,TS&limit=60",
            authRequirement = ProviderAuthRequirement.NONE_PUBLIC,
            refreshIntervalMs = 30 * MIN,
            minRequestGapMs = 5 * MIN,
            rateLimitPolicy = "Public GDACS GeoJSON service; cached 30 min.",
            maxRetries = 2,
            normalizerId = "gdacs-geojson",
            attribution = "Global Disaster Alert and Coordination System (GDACS — UN OCHA & European Commission JRC)",
            licenseInfo = "GDACS public humanitarian information service with attribution.",
            docsUrl = "https://www.gdacs.org/",
            defaultEnabled = true
        ),
        WorldProviderSpec(
            providerId = "wm.disaster.firms",
            name = "NASA FIRMS VIIRS Thermal Fire Hotspots",
            category = WorldIntelCategory.DISASTER,
            endpoint = "https://firms.modaps.eosdis.nasa.gov/api/area/csv/{apiKey}/VIIRS_SNPP_NRT/{west},{south},{east},{north}/1",
            authRequirement = ProviderAuthRequirement.REQUIRED_USER_KEY,
            credentialSlot = "wm.cred.nasa_firms",
            refreshIntervalMs = HOUR,
            minRequestGapMs = 10 * MIN,
            rateLimitPolicy = "Requires free personal NASA FIRMS MAP_KEY; key-bound transaction quota.",
            maxRetries = 1,
            normalizerId = "nasa-firms-csv",
            attribution = "NASA Fire Information for Resource Management System (FIRMS)",
            licenseInfo = "NASA Earthdata Open Data (free personal MAP_KEY required for CSV API).",
            docsUrl = "https://firms.modaps.eosdis.nasa.gov/api/area/",
            supportsViewportBbox = true,
            defaultEnabled = true,
            notes = "Active wildfires are already tracked keyless via NASA EONET & GDACS; add a free FIRMS MAP_KEY to unlock raw VIIRS thermal hotspots."
        ),

        // ==================== E. GLOBAL WEATHER INTELLIGENCE ====================
        WorldProviderSpec(
            providerId = "wm.weather.openmeteo",
            name = "Open-Meteo Global Synoptic & Viewport Weather",
            category = WorldIntelCategory.WEATHER,
            endpoint = "https://api.open-meteo.com/v1/forecast?latitude={lat}&longitude={lon}&current=temperature_2m,precipitation,rain,cloud_cover,surface_pressure,wind_speed_10m,wind_direction_10m,weather_code",
            authRequirement = ProviderAuthRequirement.NONE_PUBLIC,
            refreshIntervalMs = 15 * MIN,
            minRequestGapMs = 15_000L,
            rateLimitPolicy = "Free non-commercial quota: 10,000 calls/day; multi-coordinate batching & 15m caching used.",
            maxRetries = 2,
            normalizerId = "openmeteo-current",
            attribution = "Weather data by Open-Meteo.com",
            licenseInfo = "CC BY 4.0 (Non-commercial free API; commercial use requires Open-Meteo subscription).",
            docsUrl = "https://open-meteo.com/en/docs",
            supportsViewportBbox = true,
            defaultEnabled = true
        ),
        WorldProviderSpec(
            providerId = "wm.weather.airquality",
            name = "Open-Meteo Air Quality & Atmospheric Particulates",
            category = WorldIntelCategory.WEATHER,
            endpoint = "https://air-quality-api.open-meteo.com/v1/air-quality?latitude={lat}&longitude={lon}&current=pm2_5,pm10,us_aqi,uv_index",
            authRequirement = ProviderAuthRequirement.NONE_PUBLIC,
            refreshIntervalMs = 30 * MIN,
            minRequestGapMs = 20_000L,
            rateLimitPolicy = "Free non-commercial API; cached 30 min.",
            maxRetries = 2,
            normalizerId = "openmeteo-air",
            attribution = "Open-Meteo Air Quality API / CAMS",
            licenseInfo = "CC BY 4.0.",
            docsUrl = "https://open-meteo.com/en/docs/air-quality-api",
            supportsViewportBbox = true,
            defaultEnabled = true
        ),
        WorldProviderSpec(
            providerId = "wm.weather.marine",
            name = "Open-Meteo Ocean Waves, Swell & GloFAS Flood",
            category = WorldIntelCategory.WEATHER,
            endpoint = "https://flood-api.open-meteo.com/v1/flood?latitude={lat}&longitude={lon}&daily=river_discharge,river_discharge_mean,river_discharge_max&forecast_days=3",
            authRequirement = ProviderAuthRequirement.NONE_PUBLIC,
            refreshIntervalMs = HOUR,
            minRequestGapMs = 30_000L,
            rateLimitPolicy = "Free non-commercial GloFAS v4 river discharge feed; cached 1h.",
            maxRetries = 2,
            normalizerId = "openmeteo-flood",
            attribution = "Open-Meteo Flood API / Copernicus GloFAS",
            licenseInfo = "CC BY 4.0.",
            docsUrl = "https://open-meteo.com/en/docs/flood-api",
            supportsViewportBbox = true,
            defaultEnabled = true
        ),
        WorldProviderSpec(
            providerId = "wm.weather.nws",
            name = "NOAA NWS Active Severe Weather Warnings",
            category = WorldIntelCategory.WEATHER,
            endpoint = "https://api.weather.gov/alerts/active?status=actual&severity=Extreme,Severe",
            authRequirement = ProviderAuthRequirement.NONE_PUBLIC,
            refreshIntervalMs = 15 * MIN,
            minRequestGapMs = 2 * MIN,
            rateLimitPolicy = "Public API requiring descriptive User-Agent header (sent by OkHttpConnectorTransport).",
            maxRetries = 2,
            normalizerId = "nws-alerts-geojson",
            attribution = "NOAA National Weather Service (NWS)",
            licenseInfo = "US Government Public Domain (US & Pacific/Atlantic territories).",
            docsUrl = "https://www.weather.gov/documentation/services-web-api",
            defaultEnabled = true
        ),
        WorldProviderSpec(
            providerId = "wm.weather.rainviewer",
            name = "RainViewer Global Radar Animation Manifest",
            category = WorldIntelCategory.WEATHER,
            endpoint = "https://api.rainviewer.com/public/weather-maps.json",
            authRequirement = ProviderAuthRequirement.NONE_PUBLIC,
            refreshIntervalMs = 10 * MIN,
            minRequestGapMs = 2 * MIN,
            rateLimitPolicy = "Public radar tile manifest updated every 10 minutes.",
            maxRetries = 2,
            normalizerId = "rainviewer-manifest",
            attribution = "RainViewer Global Weather Radar (rainviewer.com)",
            licenseInfo = "Free public API tier (max zoom 7 radar tiles with attribution).",
            docsUrl = "https://www.rainviewer.com/api.html",
            defaultEnabled = true
        ),

        // ==================== F. GLOBAL CYBER INTELLIGENCE ====================
        WorldProviderSpec(
            providerId = "wm.cyber.cisa.kev",
            name = "CISA Known Exploited Vulnerabilities (KEV)",
            category = WorldIntelCategory.CYBER,
            endpoint = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            authRequirement = ProviderAuthRequirement.NONE_PUBLIC,
            refreshIntervalMs = 12 * HOUR,
            minRequestGapMs = HOUR,
            rateLimitPolicy = "Static US Government JSON catalog; cached 12h.",
            maxRetries = 2,
            normalizerId = "cisa-kev-world",
            attribution = "U.S. Cybersecurity and Infrastructure Security Agency (CISA)",
            licenseInfo = "US Government Public Domain. Passive defensive advisory only.",
            docsUrl = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            defaultEnabled = true
        ),
        WorldProviderSpec(
            providerId = "wm.cyber.feodo",
            name = "abuse.ch Feodo Tracker Botnet C2 Infrastructure",
            category = WorldIntelCategory.CYBER,
            endpoint = "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
            authRequirement = ProviderAuthRequirement.NONE_PUBLIC,
            refreshIntervalMs = 6 * HOUR,
            minRequestGapMs = 30 * MIN,
            rateLimitPolicy = "Public JSON blocklist updated every 5-15m; cached 6h politely.",
            maxRetries = 2,
            normalizerId = "feodo-json-world",
            attribution = "abuse.ch Feodo Tracker",
            licenseInfo = "CC0 / Public defensive threat intelligence. Mapped at ASN/country centroid level only.",
            docsUrl = "https://feodotracker.abuse.ch/",
            defaultEnabled = true
        ),
        WorldProviderSpec(
            providerId = "wm.cyber.ioda",
            name = "IODA Public Internet Outages & BGP Incidents",
            category = WorldIntelCategory.CYBER,
            endpoint = "https://api.ioda.inetintel.cc.gatech.edu/v2/outages/events?limit=40",
            authRequirement = ProviderAuthRequirement.NONE_PUBLIC,
            refreshIntervalMs = 30 * MIN,
            minRequestGapMs = 5 * MIN,
            rateLimitPolicy = "Public academic BGP/probing outage telemetry; cached 30 min.",
            maxRetries = 1,
            normalizerId = "ioda-outages",
            attribution = "IODA — Internet Intelligence Lab, Georgia Tech",
            licenseInfo = "Academic/public internet measurement telemetry with attribution. Passive observation only.",
            docsUrl = "https://ioda.inetintel.cc.gatech.edu/",
            defaultEnabled = true
        ),
        WorldProviderSpec(
            providerId = "wm.cyber.ripestat",
            name = "RIPEstat Country BGP & ASN Routing State",
            category = WorldIntelCategory.CYBER,
            endpoint = "https://stat.ripe.net/data/country-resource-stats/data.json?resource=PH",
            authRequirement = ProviderAuthRequirement.NONE_PUBLIC,
            refreshIntervalMs = 6 * HOUR,
            minRequestGapMs = 5 * MIN,
            rateLimitPolicy = "Public RIPE NCC API; low concurrent request rate respected.",
            maxRetries = 2,
            normalizerId = "ripestat-country",
            attribution = "RIPE NCC RIPEstat",
            licenseInfo = "RIPE NCC Terms & Conditions — free public routing statistics.",
            docsUrl = "https://stat.ripe.net/docs/02.data-api/",
            defaultEnabled = true
        ),

        // ==================== G. GLOBAL NEWS INTELLIGENCE ====================
        WorldProviderSpec(
            providerId = "wm.news.gdelt",
            name = "GDELT 2.0 Geolocated Global Event Stream",
            category = WorldIntelCategory.NEWS,
            endpoint = "https://api.gdeltproject.org/api/v2/geo/geo?query=(earthquake%20OR%20cyclone%20OR%20flood%20OR%20volcano%20OR%20outage%20OR%20emergency%20OR%20summit)&format=geojson&timespan=24h",
            authRequirement = ProviderAuthRequirement.NONE_PUBLIC,
            refreshIntervalMs = 20 * MIN,
            minRequestGapMs = 3 * MIN,
            rateLimitPolicy = "Open GDELT 2.0 GeoJSON API; cached 20 min.",
            maxRetries = 2,
            normalizerId = "gdelt-geojson",
            attribution = "The GDELT Project (https://www.gdeltproject.org)",
            licenseInfo = "Open data for public analysis with citation to The GDELT Project.",
            docsUrl = "https://blog.gdeltproject.org/gdelt-geo-2-0-api-debuts/",
            defaultEnabled = true
        ),
        WorldProviderSpec(
            providerId = "wm.news.un",
            name = "United Nations Global Emergency & Diplomatic Feed",
            category = WorldIntelCategory.NEWS,
            endpoint = "https://news.un.org/feed/subscribe/en/news/all/rss.xml",
            authRequirement = ProviderAuthRequirement.NONE_PUBLIC,
            refreshIntervalMs = 45 * MIN,
            minRequestGapMs = 10 * MIN,
            rateLimitPolicy = "Public UN RSS feed; cached 45 min.",
            maxRetries = 2,
            normalizerId = "un-news-rss",
            attribution = "UN News (news.un.org)",
            licenseInfo = "United Nations public news terms with source link attribution.",
            docsUrl = "https://news.un.org/en/rss-feeds",
            defaultEnabled = true
        ),

        // ==================== H. GLOBAL INFRASTRUCTURE ====================
        WorldProviderSpec(
            providerId = "wm.infra.baseline",
            name = "Bundled Global Airports, Seaports, Submarine Cables & Grid",
            category = WorldIntelCategory.INFRASTRUCTURE,
            endpoint = "https://appassets.androidplatform.net/assets/worldmonitor/baseline/global_reference.json",
            authRequirement = ProviderAuthRequirement.NONE_PUBLIC,
            refreshIntervalMs = 30 * DAY,
            minRequestGapMs = MINUTE_FLOOR,
            rateLimitPolicy = "Local APK asset — zero network traffic.",
            maxRetries = 0,
            normalizerId = "bundled-infra",
            attribution = "OurAirports (CC0), NGA World Port Index (Public Domain), TeleGeography (CC BY-SA 4.0), WRI GPPD (CC BY 4.0)",
            licenseInfo = "CC0 / Public Domain / CC BY 4.0 / CC BY-SA 4.0 open reference datasets.",
            docsUrl = "https://ourairports.com/data/",
            defaultEnabled = true
        ),
        WorldProviderSpec(
            providerId = "wm.infra.overpass",
            name = "OpenStreetMap Overpass Live Viewport Infrastructure & 3D Buildings",
            category = WorldIntelCategory.INFRASTRUCTURE,
            endpoint = "https://overpass-api.de/api/interpreter",
            authRequirement = ProviderAuthRequirement.NONE_PUBLIC,
            refreshIntervalMs = 30 * MIN,
            minRequestGapMs = 25_000L,
            rateLimitPolicy = "Overpass public commons: strictly viewport-bounded (<0.6 deg span), 18s query timeout, cached in Room.",
            maxRetries = 1,
            normalizerId = "overpass-infra",
            attribution = "© OpenStreetMap contributors (Overpass API)",
            licenseInfo = "Open Data Commons Open Database License (ODbL).",
            docsUrl = "https://wiki.openstreetmap.org/wiki/Overpass_API",
            supportsViewportBbox = true,
            defaultEnabled = true
        )
    )

    private const val MINUTE_FLOOR = 5_000L

    val byId: Map<String, WorldProviderSpec> by lazy {
        providers.associateBy { it.providerId }
    }

    fun forCategory(category: WorldIntelCategory): List<WorldProviderSpec> =
        providers.filter { it.category == category }

    fun find(providerId: String): WorldProviderSpec? = byId[providerId]
}
