package com.adshield.pro

import com.adshield.pro.data.worldmonitor.WorldEntityRecord
import com.adshield.pro.domain.worldmonitor.FreshnessClass
import com.adshield.pro.domain.worldmonitor.GeoAccuracy
import com.adshield.pro.domain.worldmonitor.ProviderAuthRequirement
import com.adshield.pro.domain.worldmonitor.ProviderSyncStatus
import com.adshield.pro.domain.worldmonitor.SatellitePassPrediction
import com.adshield.pro.domain.worldmonitor.SimulationKind
import com.adshield.pro.domain.worldmonitor.VerificationStatus
import com.adshield.pro.domain.worldmonitor.WatchtowerRegion
import com.adshield.pro.domain.worldmonitor.WorldEntity
import com.adshield.pro.domain.worldmonitor.WorldIntelCategory
import com.adshield.pro.domain.worldmonitor.WorldProviderRuntimeState
import com.adshield.pro.domain.worldmonitor.WorldSeverity
import com.adshield.pro.domain.worldmonitor.WorldViewport
import com.adshield.pro.engine.worldmonitor.BaselineReferenceStore
import com.adshield.pro.engine.worldmonitor.CzmlAndGeoJsonBuilder
import com.adshield.pro.engine.worldmonitor.DigitalTwinEngine
import com.adshield.pro.engine.worldmonitor.EventCorrelationEngine
import com.adshield.pro.engine.worldmonitor.GeoSpatialIndex
import com.adshield.pro.engine.worldmonitor.SimulationLabEngine
import com.adshield.pro.engine.worldmonitor.WatchtowerManager
import com.adshield.pro.engine.worldmonitor.WorldMonitorAiAnalyst
import com.adshield.pro.engine.worldmonitor.WorldMonitorAssetAndTileServer
import com.adshield.pro.engine.worldmonitor.WorldMonitorJsBridge
import com.adshield.pro.engine.worldmonitor.WorldMonitorNormalizers
import com.adshield.pro.engine.worldmonitor.WorldMonitorProviderRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Comprehensive JVM Verification Suite for OMNISHIELD X INFINITY — WORLD MONITOR 2035.
 */
class WorldMonitorTestSuite {

    private val fixedNowMs = 1_794_144_000_000L // 2026-11-08 UTC

    private fun spec(id: String) = requireNotNull(WorldMonitorProviderRegistry.find(id)) { "Missing spec $id" }

    @Test
    fun testProviderRegistryAndEpistemicContracts() {
        val all = WorldMonitorProviderRegistry.providers
        assertTrue("Expected at least 26 registered global providers", all.size >= 26)
        assertEquals("Provider IDs must be globally unique", all.size, all.map { it.providerId }.toSet().size)

        WorldIntelCategory.entries.forEach { cat ->
            assertTrue("Category $cat must have providers", WorldMonitorProviderRegistry.forCategory(cat).isNotEmpty())
        }

        all.forEach { s ->
            assertTrue("${s.providerId}: attribution required", s.attribution.isNotBlank())
            assertTrue("${s.providerId}: license required", s.licenseInfo.isNotBlank())
            assertTrue("${s.providerId}: docs URL must be HTTPS", s.docsUrl.startsWith("https://"))
            assertTrue("${s.providerId}: endpoint must be HTTPS", s.endpoint.startsWith("https://"))
        }

        val aisStream = WorldMonitorProviderRegistry.find("wm.maritime.aisstream")
        assertNotNull(aisStream)
        assertFalse("AISStream WebSocket requires external key/proxy", aisStream!!.implemented)
        assertEquals(ProviderAuthRequirement.REQUIRED_USER_KEY, aisStream.authRequirement)

        val firms = WorldMonitorProviderRegistry.find("wm.disaster.firms")
        assertNotNull(firms)
        assertEquals(ProviderAuthRequirement.REQUIRED_USER_KEY, firms!!.authRequirement)

        WorldMonitorProviderRegistry.providers.filter { it.providerId.startsWith("wm.space.celestrak.") }.forEach { ct ->
            assertTrue("${ct.providerId} must enforce >= 2h minimum poll gap", ct.minRequestGapMs >= 2 * 3_600_000L)
        }
    }

    @Test
    fun testNormalizersAcrossAllEightIntelligenceDomains() {
        // A. Aviation: OpenSky + ADSB.lol + OurAirports CSV
        val openSkyJson = """{"time":1794143990,"states":[["4b1814","SWR100  ","Switzerland",1794143988,1794143989,8.5492,47.4582,10668.0,false,245.5,282.0,0.0,null,10800.0,"1000",false,0]]}"""
        val openSky = WorldMonitorNormalizers.normalize(spec("wm.aviation.opensky"), openSkyJson, fixedNowMs)
        assertEquals(1, openSky.size)
        assertEquals(WorldIntelCategory.AVIATION, openSky[0].category)
        assertEquals(FreshnessClass.LIVE, openSky[0].freshness)

        val adsbJson = """{"ac":[{"hex":"a00001","flight":"UAL1    ","lat":37.62,"lon":-122.37,"alt_baro":32000,"gs":470.0,"track":295.0,"t":"B789"}]}"""
        val adsb = WorldMonitorNormalizers.normalize(spec("wm.aviation.adsblol"), adsbJson, fixedNowMs)
        assertEquals(1, adsb.size)
        assertTrue(adsb[0].altitudeMeters!! > 9_000.0)

        val airportsCsv = "id,ident,type,name,latitude_deg,longitude_deg,elevation_ft,continent,iso_country,iso_region,municipality,scheduled_service,icao_code,iata_code\n" +
            "1,\"RPLL\",\"large_airport\",\"Ninoy Aquino International Airport\",14.5086,121.0194,75,\"AS\",\"PH\",\"PH-00\",\"Manila\",\"yes\",\"RPLL\",\"MNL\""
        val airports = WorldMonitorNormalizers.normalize(spec("wm.aviation.ourairports"), airportsCsv, fixedNowMs)
        assertEquals(1, airports.size)
        assertEquals(FreshnessClass.HISTORICAL, airports[0].freshness)

        // B. Maritime: Digitraffic AIS + NOAA NDBC buoys
        val aisJson = """{"features":[{"mmsi":230999111,"geometry":{"type":"Point","coordinates":[24.95,60.15]},"properties":{"sog":14.2,"cog":185.0,"heading":184,"navStat":0,"timestampExternal":1794143950000}}]}"""
        val vessels = WorldMonitorNormalizers.normalize(spec("wm.maritime.digitraffic"), aisJson, fixedNowMs)
        assertEquals(1, vessels.size)
        assertEquals(WorldIntelCategory.MARITIME, vessels[0].category)

        val ndbcTxt = "#STN LAT LON YYYY MM DD hh mm WDIR WSPD GST WVHT DPD APD MWD PRES PTDY ATMP WTMP\n" +
            "#deg deg yr mo dy hr mn degT m/s m/s m sec sec degT hPa hPa degC degC\n" +
            "46001 56.300 -147.900 2026 11 08 12 00 240 16.5 20.1 6.4 12 9 245 996.2 -1.5 7.2 8.1"
        val buoys = WorldMonitorNormalizers.normalize(spec("wm.maritime.ndbc"), ndbcTxt, fixedNowMs)
        assertEquals(1, buoys.size)

        // C. Space: ISS + CelesTrak 3LE + SWPC Kp
        val issJson = """{"name":"iss","id":25544,"latitude":14.60,"longitude":120.98,"altitude":418.5,"velocity":27580.2,"visibility":"daylight","timestamp":1794143995}"""
        val iss = WorldMonitorNormalizers.normalize(spec("wm.space.iss"), issJson, fixedNowMs)
        assertEquals(1, iss.size)
        assertEquals(GeoAccuracy.SATELLITE_FOOTPRINT, iss[0].geoAccuracy)

        val tle3le = """
            ISS (ZARYA)
            1 25544U 98067A   26312.50000000  .00016717  00000+0  10270-3 0  9993
            2 25544  51.6416 247.4627 0006703 130.5360 325.0288 15.50103472421535
        """.trimIndent()
        val sats = WorldMonitorNormalizers.normalize(spec("wm.space.celestrak.stations"), tle3le, fixedNowMs)
        assertEquals(1, sats.size)
        assertNotNull(sats[0].tleLine1)
        assertNotNull(sats[0].tleLine2)

        val swpcKp = """[["time_tag","Kp","a_running","station_count"],["2026-11-08 12:00:00.000","7.33","132","8"]]"""
        val kp = WorldMonitorNormalizers.normalize(spec("wm.space.swpc.kp"), swpcKp, fixedNowMs)
        assertEquals(1, kp.size)

        // D. Disaster: USGS + EONET + FIRMS
        val usgsJson = """{"features":[{"id":"us7000test","properties":{"mag":6.8,"place":"45 km E of Davao, Philippines","time":1794142000000,"url":"https://earthquake.usgs.gov/earthquakes/eventpage/us7000test","tsunami":1},"geometry":{"type":"Point","coordinates":[126.05,7.07,28.5]}}]}"""
        val quakes = WorldMonitorNormalizers.normalize(spec("wm.disaster.usgs.day"), usgsJson, fixedNowMs)
        assertEquals(1, quakes.size)
        assertEquals(VerificationStatus.OFFICIAL_AGENCY, quakes[0].verificationStatus)

        val eonetJson = """{"events":[{"id":"EONET_99","title":"Wildfire - Luzon","link":"https://eonet.gsfc.nasa.gov/api/v3/events/EONET_99","categories":[{"title":"Wildfires"}],"geometry":[{"date":"2026-11-08T10:00:00Z","type":"Point","coordinates":[121.10,15.40]}]}]}"""
        val eonet = WorldMonitorNormalizers.normalize(spec("wm.disaster.eonet"), eonetJson, fixedNowMs)
        assertEquals(1, eonet.size)

        val firmsCsv = "latitude,longitude,bright_ti4,scan,track,acq_date,acq_time,satellite,instrument,confidence,version,bright_ti5,frp,daynight\n" +
            "15.42,121.12,345.6,0.4,0.4,2026-11-08,0430,N20,VIIRS,h,2.0NRT,298.1,68.4,D"
        val firms = WorldMonitorNormalizers.normalize(spec("wm.disaster.firms"), firmsCsv, fixedNowMs)
        assertEquals(1, firms.size)

        // E. Weather: Open-Meteo + RainViewer
        val openMeteoJson = """{"latitude":14.6,"longitude":120.98,"current":{"temperature_2m":31.4,"precipitation":0.0,"wind_speed_10m":26.0,"wind_direction_10m":270,"surface_pressure":1007.2,"cloud_cover":45,"weather_code":1}}"""
        val wx = WorldMonitorNormalizers.normalize(spec("wm.weather.openmeteo"), openMeteoJson, fixedNowMs)
        assertEquals(1, wx.size)

        val rvFrames = WorldMonitorNormalizers.parseRainViewerFrames("""{"radar":{"past":[{"time":1794143000,"path":"/v2/radar/1794143000"}]}}""")
        assertEquals(1, rvFrames.size)

        // F. Cyber: CISA KEV + IODA Outage
        val kevJson = """{"vulnerabilities":[{"cveID":"CVE-2026-9999","vendorProject":"Acme","product":"EdgeGateway","vulnerabilityName":"Auth Bypass","dateAdded":"2026-11-07","shortDescription":"Actively exploited","knownRansomwareCampaignUse":"Known"}]}"""
        val kev = WorldMonitorNormalizers.normalize(spec("wm.cyber.cisa.kev"), kevJson, fixedNowMs)
        assertEquals(1, kev.size)

        // G. News: GDELT GeoJSON
        val gdeltJson = """{"features":[{"geometry":{"type":"Point","coordinates":[126.02,7.10]},"properties":{"name":"Davao Region, Philippines","count":5,"html":"<a href=\"https://example.org/news1\">Quake shakes Mindanao</a>"}}]}"""
        val news = WorldMonitorNormalizers.normalize(spec("wm.news.gdelt"), gdeltJson, fixedNowMs)
        assertEquals(1, news.size)

        // H. Infrastructure: Baseline + Overpass 3D Buildings
        val baseline = BaselineReferenceStore.buildBaselineEntities(fixedNowMs)
        assertTrue("Offline baseline should provide global airports, ports, power, cables, and TLEs", baseline.size >= 70)

        val overpassJson = """{"elements":[
            {"type":"way","id":101,"tags":{"building":"commercial","name":"Tower One","building:levels":"32"},"geometry":[{"lat":14.554,"lon":121.024},{"lat":14.555,"lon":121.024},{"lat":14.555,"lon":121.025},{"lat":14.554,"lon":121.025}]},
            {"type":"node","id":202,"lat":14.556,"lon":121.022,"tags":{"railway":"station","name":"Ayala Station"}}
        ]}"""
        val overpass = WorldMonitorNormalizers.parseOverpass(spec("wm.infra.overpass"), overpassJson, fixedNowMs)
        assertEquals(1, overpass.buildings3D.size)
        assertTrue(overpass.buildings3D[0].heightMeters > 80.0)
        assertEquals(1, overpass.infrastructureEntities.size)
    }

    @Test
    fun testGeoSpatialIndexCzmlAndGeoJsonExport() {
        val distKm = GeoSpatialIndex.haversineKm(14.5995, 120.9842, 35.6762, 139.6503)
        assertTrue("Expected Manila-Tokyo distance near 3000 km, got $distKm", distKm in 2950.0..3050.0)

        val datelineVp = WorldViewport(west = 175.0, south = -20.0, east = -175.0, north = 20.0)
        assertTrue(GeoSpatialIndex.inViewport(10.0, 179.0, datelineVp, padDeg = 0.0))
        assertTrue(GeoSpatialIndex.inViewport(10.0, -178.0, datelineVp, padDeg = 0.0))
        assertFalse(GeoSpatialIndex.inViewport(10.0, 120.0, datelineVp, padDeg = 0.0))

        val hash = GeoSpatialIndex.encodeGeohash(14.5995, 120.9842, 5)
        assertEquals(5, hash.length)

        val sample = BaselineReferenceStore.buildBaselineEntities(fixedNowMs).take(5)
        val geoJson = CzmlAndGeoJsonBuilder.buildGeoJsonFeatureCollection(sample)
        assertTrue(geoJson.contains("\"FeatureCollection\""))
        assertTrue(geoJson.contains("\"freshness\""))

        val czml = CzmlAndGeoJsonBuilder.buildCzmlDocument(sample)
        assertTrue(czml.contains("\"id\":\"document\""))
        assertTrue(czml.contains("\"cartographicDegrees\""))
    }

    @Test
    fun testEventCorrelationEngineNeverInventsSelfLinks() {
        val usgsQuake = WorldEntity(
            id = "usgs:1",
            providerId = "wm.disaster.usgs.day",
            providerName = "USGS",
            category = WorldIntelCategory.DISASTER,
            subType = "Earthquake",
            title = "M 7.1 — Offshore Mindanao",
            summary = "Depth 25 km",
            latitude = 7.10,
            longitude = 126.20,
            severity = WorldSeverity.CRITICAL,
            freshness = FreshnessClass.NEAR_REAL_TIME,
            geoAccuracy = GeoAccuracy.SEISMIC_EPICENTER,
            confidence = 98,
            verificationStatus = VerificationStatus.OFFICIAL_AGENCY,
            eventTimeEpochMs = fixedNowMs - 600_000L,
            retrievedAtEpochMs = fixedNowMs,
            expiresAtEpochMs = fixedNowMs + 3_600_000L,
            sourceUrl = "https://earthquake.usgs.gov/1",
            attribution = "USGS",
            licenseInfo = "Public Domain"
        )
        val sameProviderQuake = usgsQuake.copy(id = "usgs:2", latitude = 7.15)
        val gdacsTsunami = usgsQuake.copy(
            id = "gdacs:1",
            subType = "Tsunami Advisory",
            title = "Red Tsunami Alert Mindanao",
            providerId = "wm.disaster.gdacs",
            providerName = "GDACS",
            sourceUrl = "https://www.gdacs.org/1"
        )
        val simulatedItem = gdacsTsunami.copy(
            id = "sim:1",
            providerId = "wm.sim",
            freshness = FreshnessClass.SIMULATED,
            verificationStatus = VerificationStatus.EXPERIMENTAL_SIMULATION
        )

        assertEquals(0, EventCorrelationEngine.correlate(listOf(usgsQuake, sameProviderQuake, simulatedItem)).size)

        val correlated = EventCorrelationEngine.correlate(listOf(usgsQuake, gdacsTsunami, simulatedItem))
        assertEquals(1, correlated.size)
        assertTrue(correlated[0].caveat.isNotBlank())
        assertEquals(2, correlated[0].sourceLinks.size)
    }

    @Test
    fun testDigitalTwinAndAiAnalystEpistemicSeparation() {
        val entities = BaselineReferenceStore.buildBaselineEntities(fixedNowMs).toMutableList()
        entities += WorldEntity(
            id = "sim:fake",
            providerId = "sim",
            providerName = "SimLab",
            category = WorldIntelCategory.DISASTER,
            subType = "Simulated Surge",
            title = "Experimental Surge",
            summary = "Not real",
            latitude = 14.59,
            longitude = 120.98,
            severity = WorldSeverity.CRITICAL,
            freshness = FreshnessClass.SIMULATED,
            geoAccuracy = GeoAccuracy.ADMIN_CENTROID,
            confidence = 10,
            verificationStatus = VerificationStatus.EXPERIMENTAL_SIMULATION,
            eventTimeEpochMs = fixedNowMs,
            retrievedAtEpochMs = fixedNowMs,
            expiresAtEpochMs = fixedNowMs + 60_000L,
            sourceUrl = "https://example.org",
            attribution = "Local",
            licenseInfo = "Local"
        )

        val twin = DigitalTwinEngine.buildRegionalTwin(
            latitude = 14.5995,
            longitude = 120.9842,
            elevationMeters = 16,
            allEntities = entities,
            compareCountryIso = "JP",
            nowEpochMs = fixedNowMs
        )
        assertTrue(twin.regionName.contains("Philippines"))
        assertTrue(twin.datasetComparison.isNotEmpty())
        assertEquals(0, twin.activeHazardCounts.values.sum())

        val ai = WorldMonitorAiAnalyst.analyze(
            userQuery = "What infrastructure and hazards exist near Manila?",
            allEntities = entities,
            correlations = emptyList(),
            providerStates = listOf(
                WorldProviderRuntimeState(providerId = "wm.disaster.usgs.day", enabled = true, status = ProviderSyncStatus.OFFLINE)
            ),
            focusLat = 14.5995,
            focusLon = 120.9842,
            nowEpochMs = fixedNowMs
        )
        assertTrue(ai.verifiedObservations.none { it.freshness == FreshnessClass.SIMULATED })
        assertTrue(ai.uncertaintiesAndGaps.any { it.contains("offline", ignoreCase = true) })
        assertTrue(ai.markdownReport.contains("## 1. Verified Observations"))
        assertTrue(ai.markdownReport.contains("## 2. Uncertainties & Coverage Gaps"))
        assertTrue(ai.markdownReport.contains("## 3. Analytical Inferences & Hypotheses"))
    }

    @Test
    fun testSimulationLabStampsExperimentalMetadata() {
        val baseline = BaselineReferenceStore.buildBaselineEntities(fixedNowMs)
        SimulationKind.entries.forEach { kind ->
            val result = SimulationLabEngine.runScenario(
                kind = kind,
                centerLat = 14.5995,
                centerLon = 120.9842,
                intensityOrRadiusParameter = if (kind == SimulationKind.FLOOD_SURGE) 4.0 else 200.0,
                referenceEntities = baseline
            )
            assertTrue(result.active)
            assertEquals(FreshnessClass.SIMULATED, result.freshness)
            assertEquals(VerificationStatus.EXPERIMENTAL_SIMULATION, result.verificationStatus)
            assertTrue(result.findings.isNotEmpty())
        }
    }

    @Test
    fun testWatchtowerGeofenceMatchingAndDeduplication() {
        val region = WatchtowerRegion(
            id = "w1",
            name = "Manila Watch",
            centerLat = 14.5995,
            centerLon = 120.9842,
            radiusKm = 250.0,
            categories = setOf(WorldIntelCategory.DISASTER),
            minSeverity = WorldSeverity.HIGH,
            createdAtEpochMs = fixedNowMs
        )
        val matchingQuake = WorldEntity(
            id = "q1",
            providerId = "wm.disaster.usgs.day",
            providerName = "USGS",
            category = WorldIntelCategory.DISASTER,
            subType = "Earthquake",
            title = "M 6.2 Batangas",
            summary = "Strong shaking",
            latitude = 13.90,
            longitude = 120.90,
            severity = WorldSeverity.HIGH,
            freshness = FreshnessClass.LIVE,
            geoAccuracy = GeoAccuracy.SEISMIC_EPICENTER,
            confidence = 96,
            verificationStatus = VerificationStatus.OFFICIAL_AGENCY,
            eventTimeEpochMs = fixedNowMs,
            retrievedAtEpochMs = fixedNowMs,
            expiresAtEpochMs = fixedNowMs + 3_600_000L,
            sourceUrl = "https://earthquake.usgs.gov",
            attribution = "USGS",
            licenseInfo = "Public Domain"
        )
        val distantQuake = matchingQuake.copy(id = "q2", latitude = 35.6, longitude = 139.6)
        val simulatedQuake = matchingQuake.copy(id = "q3", freshness = FreshnessClass.SIMULATED)

        val firstPass = WatchtowerManager.findMatchingAlerts(
            regions = listOf(region),
            entities = listOf(matchingQuake, distantQuake, simulatedQuake),
            nowEpochMs = fixedNowMs
        )
        assertEquals(1, firstPass.size)
        assertEquals("w1", firstPass[0].regionId)
        assertEquals("q1", firstPass[0].entityId)

        val secondPass = WatchtowerManager.findMatchingAlerts(
            regions = listOf(region),
            entities = listOf(matchingQuake),
            alreadySeenPairs = setOf("w1:q1"),
            nowEpochMs = fixedNowMs
        )
        assertTrue(secondPass.isEmpty())
    }

    @Test
    fun testJsBridgeAndTileServerSecurityValidation() {
        var capturedViewport: WorldViewport? = null
        var capturedEntityId: String? = null
        val bridge = WorldMonitorJsBridge(object : WorldMonitorJsBridge.Listener {
            override fun onGlobeReady(webglSupported: Boolean, cesiumVersion: String) {}
            override fun onGlobeError(errorMessage: String) {}
            override fun onViewportChanged(viewport: WorldViewport) { capturedViewport = viewport }
            override fun onEntitySelected(entityId: String) { capturedEntityId = entityId }
            override fun onBuildingSelected(id: String, name: String, heightMeters: Double, heightEstimated: Boolean, lat: Double, lon: Double) {}
            override fun onLocationSelected(lat: Double, lon: Double, terrainElevationMeters: Int, countryHint: String) {}
            override fun onSatellitePassesComputed(entityId: String, passes: List<SatellitePassPrediction>) {}
        })

        bridge.onViewportChanged("""{"centerLat":145.0,"centerLon":120.0,"cameraAltitudeMeters":1000}""")
        assertEquals(null, capturedViewport)

        bridge.onViewportChanged("""{"centerLat":14.5995,"centerLon":120.9842,"cameraAltitudeMeters":250000}""")
        assertNotNull(capturedViewport)

        bridge.onEntitySelected("""{"entityId":"<script>alert(1)</script>"}""")
        assertEquals(null, capturedEntityId)

        bridge.onEntitySelected("""{"entityId":"usgs:us7000test"}""")
        assertEquals("usgs:us7000test", capturedEntityId)

        assertTrue(WorldMonitorJsBridge.isAllowedHttpsSourceUrl("https://earthquake.usgs.gov/event"))
        assertFalse(WorldMonitorJsBridge.isAllowedHttpsSourceUrl("javascript:alert(1)"))
        assertFalse(WorldMonitorJsBridge.isAllowedHttpsSourceUrl("http://insecure.example.com"))

        assertTrue(WorldMonitorAssetAndTileServer.isAllowedTileHost("services.arcgisonline.com"))
        assertTrue(WorldMonitorAssetAndTileServer.isAllowedTileHost("gibs.earthdata.nasa.gov"))
        assertFalse(WorldMonitorAssetAndTileServer.isAllowedTileHost("evil-tracker.example.com"))
        assertEquals("application/wasm", WorldMonitorAssetAndTileServer.resolveMimeType("/vendor/cesium/ThirdParty/draco.wasm", null))
        assertEquals("text/javascript", WorldMonitorAssetAndTileServer.resolveMimeType("/assets/worldmonitor/worldmonitor.js", null))
    }

    @Test
    fun testDynamicFreshnessDecayOnCachedEntities() {
        val liveAircraft = WorldEntity(
            id = "opensky:test",
            providerId = "wm.aviation.opensky",
            providerName = "OpenSky",
            category = WorldIntelCategory.AVIATION,
            subType = "Aircraft",
            title = "TEST01",
            summary = "Airborne",
            latitude = 14.5,
            longitude = 121.0,
            severity = WorldSeverity.INFO,
            freshness = FreshnessClass.LIVE,
            geoAccuracy = GeoAccuracy.RADAR_TRANSPONDER,
            confidence = 88,
            verificationStatus = VerificationStatus.PUBLIC_TRANSPONDER_FEED,
            eventTimeEpochMs = fixedNowMs,
            retrievedAtEpochMs = fixedNowMs,
            expiresAtEpochMs = fixedNowMs + 3_600_000L,
            sourceUrl = "https://opensky-network.org",
            attribution = "OpenSky",
            licenseInfo = "OpenSky Terms"
        )
        val record = WorldEntityRecord.fromDomain(liveAircraft, "wdw4")

        assertEquals(FreshnessClass.LIVE, record.toDomain(fixedNowMs + 60_000L).freshness)
        assertEquals(FreshnessClass.NEAR_REAL_TIME, record.toDomain(fixedNowMs + 10 * 60_000L).freshness)
        assertEquals(FreshnessClass.DELAYED, record.toDomain(fixedNowMs + 90 * 60_000L).freshness)
        assertEquals(FreshnessClass.HISTORICAL, record.toDomain(fixedNowMs + 26 * 3_600_000L).freshness)
    }
}
