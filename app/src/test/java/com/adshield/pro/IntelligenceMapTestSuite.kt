package com.adshield.pro

import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import com.adshield.pro.data.local.db.IntelligenceEventDao
import com.adshield.pro.data.local.db.IntelligenceEventEntity
import com.adshield.pro.data.repository.IntelligenceLimits
import com.adshield.pro.data.repository.IntelligenceRecorder
import com.adshield.pro.data.repository.IntelligenceRepository
import com.adshield.pro.domain.intelligence.IntelligenceAction
import com.adshield.pro.domain.intelligence.IntelligenceEvent
import com.adshield.pro.domain.intelligence.IntelligenceEventType
import com.adshield.pro.domain.intelligence.IntelligenceFilters
import com.adshield.pro.domain.intelligence.IntelligenceInputs
import com.adshield.pro.domain.intelligence.IntelligenceMetric
import com.adshield.pro.domain.intelligence.IntelligenceMetricSource
import com.adshield.pro.domain.intelligence.IntelligenceModule
import com.adshield.pro.domain.intelligence.IntelligenceModuleState
import com.adshield.pro.domain.intelligence.IntelligenceSeverity
import com.adshield.pro.domain.intelligence.IntelligenceTimeRange
import com.adshield.pro.domain.intelligence.NodePosition
import com.adshield.pro.domain.model.ProtectionMode
import com.adshield.pro.domain.model.RuleCategory
import com.adshield.pro.domain.model.VpnStatus
import com.adshield.pro.engine.battery.BatteryHealthStatus
import com.adshield.pro.engine.battery.BatteryReading
import com.adshield.pro.engine.battery.BatteryTelemetry
import com.adshield.pro.engine.battery.HistoryCoverage
import com.adshield.pro.engine.intelligence.FinancialTargetClassifier
import com.adshield.pro.engine.intelligence.IntelligenceAggregator
import com.adshield.pro.engine.intelligence.IntelligenceEventFactory
import com.adshield.pro.engine.intelligence.IntelligenceEventSanitizer
import com.adshield.pro.engine.intelligence.IntelligenceRecommendations
import com.adshield.pro.engine.security.ScanKind
import com.adshield.pro.engine.security.ScanSource
import com.adshield.pro.engine.security.SecurityLevel
import com.adshield.pro.engine.security.SecurityScanRecord
import com.adshield.pro.ui.screens.intelligence.MapCamera
import com.adshield.pro.ui.screens.intelligence.MapGeometry
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.math.abs

/**
 * OMNISHIELD X — Live Intelligence Map test suite.
 *
 * The suite is deliberately adversarial about the two failure modes that matter for this feature:
 *  1. **Invented activity** — an empty device must render an empty map, and an event without real
 *     evidence must be rejected.
 *  2. **Map/UI truth drift** — every state shown by the UI must be derivable from the inputs and
 *     the stored events the tests feed in; there is no hidden data source.
 *
 * It also fixes the interaction contracts (hit-testing, pinch focal stability, tap-versus-drag) and
 * publishes a real measured performance budget for aggregation and filtering on the JVM.
 */
class IntelligenceMapTestSuite {

    private val now = 1_800_000_000_000L

    // ------------------------------------------------------------------ sanitizer / honesty

    @Test
    fun testSanitizerRejectsEventWithoutEvidence() {
        val draft = IntelligenceEvent(
            module = IntelligenceModule.NETWORK_DEFENSE,
            type = IntelligenceEventType.NETWORK_THREAT_BLOCKED,
            severity = IntelligenceSeverity.WARNING,
            timestampEpochMs = now,
            title = "Blocked something",
            description = "No evidence attached",
            evidence = "   "
        )
        val result = IntelligenceEventSanitizer.sanitize(draft, now)
        assertNull("an event with blank evidence must be rejected", result.event)
        assertNotNull(result.rejectionReason)
    }

    @Test
    fun testSanitizerMasksSecretsAndPersonalData() {
        val raw = "token=abc123secret user@example.com 4111111111111111 " +
            "http://user:password@evil.test/path 5551234567 " +
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        val cleaned = IntelligenceEventSanitizer.sanitizeText(raw, 400)
        assertFalse(cleaned.contains("abc123secret"))
        assertFalse(cleaned.contains("user:password@"))
        assertFalse(cleaned.contains("4111111111111111"))
        assertFalse(cleaned.contains("5551234567"))
        assertFalse(cleaned.contains("user@example.com"))
        assertTrue(cleaned.contains("[redacted]"))
    }

    @Test
    fun testSanitizerCannotDowngradeCatalogueSeverity() {
        val draft = IntelligenceEvent(
            module = IntelligenceModule.NETWORK_DEFENSE,
            type = IntelligenceEventType.NETWORK_RESOLVER_ERROR,
            severity = IntelligenceSeverity.INFO,
            timestampEpochMs = now,
            title = "Resolver error",
            description = "Reported by the tunnel",
            evidence = "Tunnel reported failure while resolving"
        )
        val sanitized = IntelligenceEventSanitizer.sanitize(draft, now).event
        assertNotNull(sanitized)
        assertEquals(IntelligenceSeverity.CRITICAL, sanitized!!.severity)

        val escalated = draft.copy(severity = IntelligenceSeverity.CRITICAL)
        assertEquals(
            IntelligenceSeverity.CRITICAL,
            IntelligenceEventSanitizer.normalisedSeverity(escalated.type, escalated.severity)
        )
    }

    @Test
    fun testSanitizerRejectsModuleTypeMismatchAndFutureTimestamps() {
        val mismatch = IntelligenceEvent(
            module = IntelligenceModule.PRIVACY_DEFENSE,
            type = IntelligenceEventType.NETWORK_THREAT_BLOCKED,
            severity = IntelligenceSeverity.WARNING,
            timestampEpochMs = now,
            title = "Wrong module",
            description = "Never stored",
            evidence = "Real evidence"
        )
        assertNull(IntelligenceEventSanitizer.sanitize(mismatch, now).event)

        val future = mismatch.copy(
            module = IntelligenceModule.NETWORK_DEFENSE,
            timestampEpochMs = now + 60 * 60_000L
        )
        assertNull(IntelligenceEventSanitizer.sanitize(future, now).event)

        val stale = future.copy(timestampEpochMs = now - IntelligenceEventSanitizer.MAX_AGE_MS - 1L)
        assertNull(IntelligenceEventSanitizer.sanitize(stale, now).event)
    }

    @Test
    fun testEventSanitizerBoundsAndMetricLimits() {
        val metrics = (1..20).map { IntelligenceMetric("m$it", "v$it", IntelligenceMetricSource.MEASURED) }
        val actions = listOf(
            IntelligenceAction.STOP_PROTECTION,
            IntelligenceAction.TOGGLE_LOCKDOWN,
            IntelligenceAction.RUN_APP_AUDIT,
            IntelligenceAction.OPEN_MODULE
        )
        val draft = IntelligenceEvent(
            module = IntelligenceModule.CYBER_DEFENSE,
            type = IntelligenceEventType.CYBER_SCAN_CLEAN,
            severity = IntelligenceSeverity.INFO,
            timestampEpochMs = now,
            title = "x".repeat(500),
            description = "y".repeat(900),
            evidence = "z".repeat(2000),
            metrics = metrics,
            actions = actions,
            relatedObjectIds = (1..20).map { "id$it" }
        )
        val sanitized = IntelligenceEventSanitizer.sanitize(draft, now).event!!
        assertTrue(sanitized.title.length <= IntelligenceEventSanitizer.MAX_TITLE)
        assertTrue(sanitized.evidence.length <= IntelligenceEventSanitizer.MAX_EVIDENCE)
        assertEquals(IntelligenceEventSanitizer.MAX_METRICS, sanitized.metrics.size)
        assertEquals(IntelligenceEventSanitizer.MAX_RELATED_IDS, sanitized.relatedObjectIds.size)
        // Only controls the Cyber module really exposes may survive.
        assertTrue(sanitized.actions.all { it in IntelligenceAction.forModule(IntelligenceModule.CYBER_DEFENSE) })
        assertFalse(sanitized.actions.contains(IntelligenceAction.STOP_PROTECTION))
    }

    // ------------------------------------------------------------------ classification / factory

    @Test
    fun testFinancialClassifierAttributesPaymentLinksOnly() {
        assertTrue(FinancialTargetClassifier.isFinancialTarget("https://paypal.com.login-verify.tk/checkout"))
        assertTrue(FinancialTargetClassifier.isFinancialTarget("https://gcash-ph.example/verify-account"))
        assertFalse(FinancialTargetClassifier.isFinancialTarget("https://developer.android.com/studio"))

        val paymentRecord = scanRecord(
            kind = ScanKind.URL,
            target = "http://secure-paypal.com.login-verify.tk/account/update-payment",
            level = SecurityLevel.DANGEROUS,
            risk = 80
        )
        val paymentEvent = IntelligenceEventFactory.scanRecord(paymentRecord, now)
        assertNotNull(paymentEvent)
        assertEquals(IntelligenceModule.FINANCIAL_DEFENSE, paymentEvent!!.module)
        assertEquals(IntelligenceEventType.FINANCIAL_PAYMENT_RISK, paymentEvent.type)
        assertEquals(IntelligenceSeverity.CRITICAL, paymentEvent.severity)

        val docsRecord = scanRecord(kind = ScanKind.URL, target = "https://developer.android.com/studio")
        val cyberEvent = IntelligenceEventFactory.scanRecord(docsRecord, now)!!
        assertEquals(IntelligenceModule.CYBER_DEFENSE, cyberEvent.module)
    }

    @Test
    fun testScanRecordRoutesToCyberFinancialAndPrivacy() {
        val apk = IntelligenceEventFactory.scanRecord(
            scanRecord(kind = ScanKind.APK, target = "downloaded.apk", level = SecurityLevel.SUSPICIOUS, risk = 55),
            now
        )!!
        assertEquals(IntelligenceModule.CYBER_DEFENSE, apk.module)
        assertEquals(IntelligenceSeverity.WARNING, apk.severity)
        assertTrue(apk.evidence.contains("downloaded.apk"))

        val audit = IntelligenceEventFactory.scanRecord(
            scanRecord(
                kind = ScanKind.APP_AUDIT,
                target = "Flashlight Pro (com.example.flash)",
                level = SecurityLevel.DANGEROUS,
                risk = 88
            ),
            now
        )!!
        assertEquals(IntelligenceModule.PRIVACY_DEFENSE, audit.module)
        assertEquals(IntelligenceEventType.PRIVACY_PERMISSION_FINDING, audit.type)

        // A record with neither findings, threat name nor risk cannot become an event.
        assertNull(
            IntelligenceEventFactory.scanRecord(
                scanRecord(
                    kind = ScanKind.FILE,
                    target = "notes.txt",
                    level = SecurityLevel.CLEAN,
                    risk = 0,
                    findings = emptyList()
                ),
                now
            )
        )
    }

    @Test
    fun testFactoryNeverEmitsWithoutRealEvidence() {
        assertNull(
            IntelligenceEventFactory.dnsThreatBlocked(
                domain = "not a domain",
                category = RuleCategory.MALWARE,
                matchedRule = null,
                sourceList = "list",
                protocolUsed = "DOH",
                appName = null,
                timestampEpochMs = now
            )
        )
        assertNull(
            IntelligenceEventFactory.vpnTransition(
                previous = VpnStatus.CONNECTED,
                current = VpnStatus.CONNECTED,
                error = null,
                ruleCount = 10,
                timestampEpochMs = now
            )
        )
        assertNull(
            IntelligenceEventFactory.thermalWarning(
                batteryTelemetry(temperature = null),
                thresholdCelsius = 41f,
                timestampEpochMs = now
            )
        )
        val blocked = IntelligenceEventFactory.dnsThreatBlocked(
            domain = "malware.example",
            category = RuleCategory.MALWARE,
            matchedRule = "||malware.example^",
            sourceList = "HaGeZi Multi Pro",
            protocolUsed = "DOH",
            appName = "Browser",
            timestampEpochMs = now
        )
        assertNotNull(blocked)
        assertTrue(blocked!!.evidence.contains("malware.example"))
        assertTrue(blocked.isMitigated)
        assertFalse("mitigated blocks must not count as open alerts", blocked.countsTowardAlerts)
    }

    // ------------------------------------------------------------------ aggregation

    @Test
    fun testAggregatorBuildsOnlyFromRealInputs() {
        val inputs = healthyInputs()
        val state = IntelligenceAggregator.buildState(inputs, emptyList(), IntelligenceFilters.DEFAULT, 3L)
        assertEquals(8, state.modules.size)
        assertEquals(0, state.storedEventCount)
        assertTrue(state.filteredEvents.isEmpty())
        assertTrue("no stored or derived incident may appear on a healthy idle device", state.incidents.isEmpty())
        assertEquals(IntelligenceModuleState.MONITORING, state.snapshotFor(IntelligenceModule.NETWORK_DEFENSE)?.state)
        assertEquals(100, state.healthPercent)
        assertEquals(3L, state.buildDurationMs)
    }

    @Test
    fun testAggregatorEscalatesThermalThresholdAndRecovers() {
        val cool = healthyInputs().copy(batteryTelemetry = batteryTelemetry(temperature = 38f))
        assertEquals(
            IntelligenceModuleState.MONITORING,
            IntelligenceAggregator.buildState(cool, emptyList(), IntelligenceFilters.DEFAULT, 0)
                .snapshotFor(IntelligenceModule.DEVICE_INTELLIGENCE)?.state
        )

        val warm = healthyInputs().copy(batteryTelemetry = batteryTelemetry(temperature = 42f))
        val warmState = IntelligenceAggregator.buildState(warm, emptyList(), IntelligenceFilters.DEFAULT, 0)
        assertEquals(
            IntelligenceModuleState.WARNING,
            warmState.snapshotFor(IntelligenceModule.DEVICE_INTELLIGENCE)?.state
        )
        assertTrue(warmState.incidents.any { it.module == IntelligenceModule.DEVICE_INTELLIGENCE })

        val hot = healthyInputs().copy(batteryTelemetry = batteryTelemetry(temperature = 46f))
        assertEquals(
            IntelligenceModuleState.CRITICAL,
            IntelligenceAggregator.buildState(hot, emptyList(), IntelligenceFilters.DEFAULT, 0)
                .snapshotFor(IntelligenceModule.DEVICE_INTELLIGENCE)?.state
        )
    }

    @Test
    fun testAggregatorReportsOfflineModuleWithoutInventingData() {
        val unsupported = healthyInputs().copy(
            batteryTelemetry = batteryTelemetry(temperature = null, temperatureSupported = false)
        )
        val snapshot = IntelligenceAggregator.buildState(
            unsupported,
            emptyList(),
            IntelligenceFilters.DEFAULT,
            0
        ).snapshotFor(IntelligenceModule.DEVICE_INTELLIGENCE)!!
        assertEquals(IntelligenceModuleState.OFFLINE, snapshot.state)
        assertNotNull(snapshot.unavailableReason)
        assertTrue(snapshot.metrics.any { it.label == "Temperature" && it.value == "unavailable" })
        assertTrue(snapshot.metrics.none { it.label == "Temperature" && it.value.contains("°C") })
    }

    @Test
    fun testMitigatedBlocksDoNotRaiseModuleAlerts() {
        val block = IntelligenceEventFactory.dnsThreatBlocked(
            domain = "tracker.malware.example",
            category = RuleCategory.MALWARE,
            matchedRule = "||tracker.malware.example^",
            sourceList = "UnitTestList",
            protocolUsed = "DOH",
            appName = null,
            timestampEpochMs = now - 60_000L
        )!!
        val state = IntelligenceAggregator.buildState(
            healthyInputs().copy(nowEpochMs = now),
            listOf(block.copy(id = 1L)),
            IntelligenceFilters.DEFAULT,
            0
        )
        assertEquals(1, state.storedEventCount)
        assertEquals(1, state.filteredEvents.size)
        assertTrue(state.incidents.none { it.module == IntelligenceModule.NETWORK_DEFENSE })
        assertEquals(
            IntelligenceModuleState.MONITORING,
            state.snapshotFor(IntelligenceModule.NETWORK_DEFENSE)?.state
        )
        assertEquals(0, state.snapshotFor(IntelligenceModule.NETWORK_DEFENSE)?.activeAlerts)
    }

    @Test
    fun testAutomationFailuresRaiseAlerts() {
        val failure = IntelligenceEventFactory.automationJob(
            jobLabel = "Filter list sync",
            success = false,
            detail = "HTTP 503",
            durationMs = 1240,
            timestampEpochMs = now - 30_000L
        ).copy(id = 7L)
        val state = IntelligenceAggregator.buildState(
            healthyInputs().copy(nowEpochMs = now),
            listOf(failure),
            IntelligenceFilters.DEFAULT,
            0
        )
        assertEquals(
            IntelligenceModuleState.WARNING,
            state.snapshotFor(IntelligenceModule.AUTOMATION_CORE)?.state
        )
        assertTrue(state.incidents.any { it.module == IntelligenceModule.AUTOMATION_CORE })
    }

    @Test
    fun testNetworkStateFollowsRealTunnelState() {
        val paused = IntelligenceAggregator.buildState(
            healthyInputs().copy(vpnStatus = VpnStatus.PAUSED, nowEpochMs = now),
            emptyList(),
            IntelligenceFilters.DEFAULT,
            0
        )
        assertEquals(
            IntelligenceModuleState.WARNING,
            paused.snapshotFor(IntelligenceModule.NETWORK_DEFENSE)?.state
        )

        val disabled = IntelligenceAggregator.buildState(
            healthyInputs().copy(
                vpnStatus = VpnStatus.DISCONNECTED,
                protectionExpected = false,
                nowEpochMs = now
            ),
            emptyList(),
            IntelligenceFilters.DEFAULT,
            0
        )
        assertEquals(
            IntelligenceModuleState.DISABLED,
            disabled.snapshotFor(IntelligenceModule.NETWORK_DEFENSE)?.state
        )

        val error = IntelligenceAggregator.buildState(
            healthyInputs().copy(
                vpnStatus = VpnStatus.ERROR,
                vpnLastError = "tun open failed",
                nowEpochMs = now
            ),
            emptyList(),
            IntelligenceFilters.DEFAULT,
            0
        )
        assertEquals(
            IntelligenceModuleState.CRITICAL,
            error.snapshotFor(IntelligenceModule.NETWORK_DEFENSE)?.state
        )
        assertTrue(error.incidents.any { it.module == IntelligenceModule.NETWORK_DEFENSE })
    }

    @Test
    fun testEmergencyLockdownIsReportedAsVerifiedConfiguration() {
        val inputs = healthyInputs().copy(emergencyAllowlistOnly = true, nowEpochMs = now)
        val state = IntelligenceAggregator.buildState(inputs, emptyList(), IntelligenceFilters.DEFAULT, 0)
        val snapshot = state.snapshotFor(IntelligenceModule.EMERGENCY_INTELLIGENCE)!!
        assertEquals(IntelligenceModuleState.WARNING, snapshot.state)
        assertTrue(snapshot.metrics.any { it.label == "Lockdown" && it.value == "ACTIVE" })
        assertTrue(state.incidents.any { it.module == IntelligenceModule.EMERGENCY_INTELLIGENCE })
    }

    // ------------------------------------------------------------------ filters

    @Test
    fun testFiltersMatchModuleSeverityRangeAndQuery() {
        val old = sampleEvent(id = 1L, module = IntelligenceModule.CYBER_DEFENSE, timestamp = now - 2 * 24 * 3600_000L)
        val recent = sampleEvent(id = 2L, module = IntelligenceModule.PRIVACY_DEFENSE, timestamp = now - 30_000L)
        val all = listOf(recent, old)

        val moduleFiltered = IntelligenceFilters(module = IntelligenceModule.PRIVACY_DEFENSE, range = IntelligenceTimeRange.ALL)
        assertEquals(listOf(2L), all.filter { moduleFiltered.matches(it, now) }.map { it.id })

        val severityFiltered = IntelligenceFilters(severity = IntelligenceSeverity.WARNING, range = IntelligenceTimeRange.ALL)
        assertTrue(all.filter { severityFiltered.matches(it, now) }.all { it.severity == IntelligenceSeverity.WARNING })

        val hourFiltered = IntelligenceFilters(range = IntelligenceTimeRange.HOUR_1)
        assertEquals(listOf(2L), all.filter { hourFiltered.matches(it, now) }.map { it.id })

        val searched = IntelligenceFilters(range = IntelligenceTimeRange.ALL, query = "privacy")
        assertEquals(listOf(2L), all.filter { searched.matches(it, now) }.map { it.id })
        assertTrue(searched.isActive)
        assertFalse(IntelligenceFilters.DEFAULT.isActive)
    }

    // ------------------------------------------------------------------ dedupe / persistence

    @Test
    fun testDedupePolicyThrottlesRepeatedObservations() = runTest {
        val repository = IntelligenceRepository(FakeIntelligenceDao())
        val recorder = IntelligenceRecorder(repository)
        val draft = IntelligenceEventFactory.dnsThreatBlocked(
            domain = "repeat.example",
            category = RuleCategory.MALWARE,
            matchedRule = null,
            sourceList = "list",
            protocolUsed = "DOH",
            appName = null,
            timestampEpochMs = now
        )!!

        assertNotNull(recorder.emit(draft, now))
        assertNull("identical observation inside the cooldown must be suppressed", recorder.emit(draft, now + 1_000L))
        val other = draft.copy(evidenceRef = "dns:other.example", relatedObjectIds = listOf("other.example"))
        assertNotNull(recorder.emit(other, now + 1_000L))
        assertEquals(2, repository.events.first().size)
    }

    @Test
    fun testRepositoryRoundTripPersistsSanitizedEvents() = runTest {
        val dao = FakeIntelligenceDao()
        val repository = IntelligenceRepository(dao)
        val event = sampleEvent(id = 0L, module = IntelligenceModule.DEVICE_INTELLIGENCE, timestamp = now)
            .copy(
                metrics = listOf(IntelligenceMetric("Temperature", "42 °C", IntelligenceMetricSource.MEASURED)),
                actions = IntelligenceAction.forModule(IntelligenceModule.DEVICE_INTELLIGENCE)
            )
        val stored = repository.record(event, now)
        assertNotNull(stored)
        val loaded = repository.events.first().single()
        assertEquals(stored!!.id, loaded.id)
        assertEquals(IntelligenceModule.DEVICE_INTELLIGENCE, loaded.module)
        assertEquals(1, loaded.metrics.size)
        assertEquals("42 °C", loaded.metrics.first().value)
        assertTrue(loaded.actions.contains(IntelligenceAction.OPEN_MODULE))
    }

    @Test
    fun testRepositoryDropsCorruptRowsOnRead() = runTest {
        val dao = FakeIntelligenceDao()
        dao.seed(
            IntelligenceEventEntity(
                id = 99,
                module = "network",
                typeCode = "type.that.does.not.exist",
                severity = "WARNING",
                timestampEpochMs = now,
                title = "corrupt",
                description = "corrupt",
                evidence = "corrupt",
                evidenceRef = null,
                relatedIdsJson = "[]",
                metricsJson = "[]",
                actionsCsv = ""
            )
        )
        val repository = IntelligenceRepository(dao)
        assertTrue(repository.events.first().isEmpty())
    }

    @Test
    fun testRepositoryPrunesByAgeAndCount() = runTest {
        val dao = FakeIntelligenceDao()
        val repository = IntelligenceRepository(dao)
        val ancient = sampleEvent(
            id = 0L,
            module = IntelligenceModule.CYBER_DEFENSE,
            timestamp = now - (IntelligenceLimits.RETENTION_DAYS + 1) * 24L * 60L * 60L * 1_000L
        )
        val fresh = sampleEvent(id = 0L, module = IntelligenceModule.CYBER_DEFENSE, timestamp = now - 1_000L)
        repository.record(ancient, now)
        repository.record(fresh, now)
        val removed = repository.prune(now)
        assertTrue(removed >= 1)
        assertEquals(1, repository.events.first().size)
        assertEquals(IntelligenceLimits.RETENTION_DAYS * 24L * 60L * 60L * 1_000L, IntelligenceLimits.RETENTION_MS)
    }

    // ------------------------------------------------------------------ geometry / interaction

    @Test
    fun testGeometryFitContainsAllNodesInPortraitAndLandscape() {
        val positions = MapGeometry.defaultPositions()
        assertEquals(7, positions.size)
        positions.values.forEach {
            assertTrue(it.x in 0f..1f && it.y in 0f..1f)
        }
        val viewports = listOf(Size(1080f, 2200f), Size(2200f, 1080f), Size(1600f, 1600f))
        viewports.forEach { viewport ->
            val camera = MapCamera().fit(viewport)
            positions.values.forEach { position ->
                val screen = camera.worldToScreen(MapGeometry.worldPosition(position))
                assertTrue("node must be inside viewport $viewport", screen.x in 0f..viewport.width)
                assertTrue("node must be inside viewport $viewport", screen.y in 0f..viewport.height)
            }
            val core = camera.worldToScreen(MapGeometry.coreWorldPosition)
            assertTrue(abs(core.x - viewport.width / 2f) < 1f)
            assertTrue(abs(core.y - viewport.height / 2f) < 1f)
        }
    }

    @Test
    fun testGeometryPinchZoomKeepsFocalPointStable() {
        val viewport = Size(1080f, 2000f)
        val camera = MapCamera().fit(viewport)
        val focal = Offset(320f, 780f)
        val worldBefore = camera.screenToWorld(focal)
        val zoomed = camera.zoomAround(focal, factor = 2f, viewport = viewport)
        val worldAfter = zoomed.screenToWorld(focal)
        assertTrue(abs(worldBefore.x - worldAfter.x) < 0.5f)
        assertTrue(abs(worldBefore.y - worldAfter.y) < 0.5f)
        assertTrue(zoomed.scale > camera.scale)

        val clamped = camera.zoomAround(focal, factor = 1_000f, viewport = viewport)
        assertClose(MapGeometry.MAX_SCALE_ABS, clamped.scale, 0.0001f)
        val tooSmall = camera.zoomAround(focal, factor = 0.00001f, viewport = viewport)
        assertClose(MapGeometry.MIN_SCALE_ABS, tooSmall.scale, 0.0001f)
    }

    @Test
    fun testGeometryHitTestSelectsNearestNodeAndCore() {
        val viewport = Size(1200f, 2000f)
        val camera = MapCamera().fit(viewport)
        val positions = MapGeometry.defaultPositions()
        val network = positions.getValue(IntelligenceModule.NETWORK_DEFENSE)
        val nodeScreen = camera.worldToScreen(MapGeometry.worldPosition(network))
        assertEquals(
            IntelligenceModule.NETWORK_DEFENSE,
            MapGeometry.hitTest(camera, viewport, positions, nodeScreen)
        )
        val coreScreen = camera.worldToScreen(MapGeometry.coreWorldPosition)
        assertEquals(IntelligenceModule.CORE, MapGeometry.hitTest(camera, viewport, positions, coreScreen))
        assertNull(MapGeometry.hitTest(camera, viewport, positions, Offset(2f, 2f)))
    }

    @Test
    fun testGeometryTapSlopCancelsSelectionWhileDragging() {
        val start = Offset(100f, 100f)
        assertFalse(MapGeometry.hasDragged(start, Offset(105f, 104f)))
        assertTrue(MapGeometry.hasDragged(start, Offset(140f, 190f)))

        val requested = listOf(
            IntelligenceModule.CYBER_DEFENSE,
            IntelligenceModule.FINANCIAL_DEFENSE,
            IntelligenceModule.PRIVACY_DEFENSE,
            IntelligenceModule.NETWORK_DEFENSE,
            IntelligenceModule.DEVICE_INTELLIGENCE,
            IntelligenceModule.EMERGENCY_INTELLIGENCE,
            IntelligenceModule.AUTOMATION_CORE
        )
        assertEquals(IntelligenceModule.nodes, requested)
        requested.forEach { module ->
            assertTrue(IntelligenceAction.forModule(module).contains(IntelligenceAction.OPEN_MODULE))
        }
    }

    @Test
    fun testGeometryPulseProgressAlphaAndMarkerPlacement() {
        assertClose(0f, MapGeometry.progress(1_000L, 1_000L, 1_000L))
        assertClose(1f, MapGeometry.progress(2_000L, 1_000L, 1_000L))
        assertClose(0f, MapGeometry.pulseAlpha(0f), 0.0001f)
        assertClose(0f, MapGeometry.pulseAlpha(1f), 0.0001f)
        assertTrue(MapGeometry.pulseAlpha(0.25f) > 0.9f)

        val from = Offset(100f, 100f)
        val to = Offset(500f, 100f)
        val mid = MapGeometry.pulsePoint(from, to, 0.5f, arc = 0f)
        assertClose(300f, mid.x, 0.5f)
        assertClose(100f, mid.y, 0.5f)

        val modulePosition = MapGeometry.defaultPositions().getValue(IntelligenceModule.PRIVACY_DEFENSE)
        val marker = MapGeometry.eventMarkerWorld(modulePosition, 0, 1)
        val fromWorld = MapGeometry.worldPosition(modulePosition)
        val core = MapGeometry.coreWorldPosition
        val distance = MapGeometry.screenDistance(marker, fromWorld)
        val total = MapGeometry.screenDistance(core, fromWorld)
        assertTrue(distance > 0f && distance < total)

        assertClose(0f, MapGeometry.labelAlpha(0.1f, 1f), 0.0001f)
        assertClose(1f, MapGeometry.labelAlpha(1f, 1f), 0.0001f)
        assertClose(50f, MapGeometry.gridSpacingWorld(1.0f), 0.001f)
    }

    @Test
    fun testCameraLerpAndCentredOn() {
        val viewport = Size(1080f, 1920f)
        val from = MapCamera().fit(viewport)
        val target = from.centredOn(MapGeometry.coreWorldPosition, viewport, targetScale = 0.8f)
        val half = from.lerpTo(target, 0.5f)
        assertClose((from.scale + target.scale) / 2f, half.scale, 0.0001f)
        val full = from.lerpTo(target, 1f)
        assertClose(target.scale, full.scale, 0.0001f)
        assertClose(target.offsetX, full.offsetX, 0.0001f)

        val centred = MapCamera().fit(viewport).centredOn(
            MapGeometry.coreWorldPosition,
            viewport,
            targetScale = MapGeometry.MAX_SCALE_ABS
        )
        val screenCore = centred.worldToScreen(MapGeometry.coreWorldPosition)
        assertTrue(abs(screenCore.x - viewport.width / 2f) < 2f)
        assertTrue(abs(screenCore.y - viewport.height / 2f) < 2f)
    }

    @Test
    fun testNodePositionsClampIntoTheWorld() {
        val clamped = NodePosition.fromRaw(5f, -3f)
        assertNotNull(clamped)
        assertClose(1f, clamped!!.x, 0.0001f)
        assertClose(0f, clamped.y, 0.0001f)
        assertNull(NodePosition.fromRaw(Float.NaN, 0.5f))
        assertTrue(MapGeometry.resolvedPositions(emptyMap()).containsKey(IntelligenceModule.CORE) == false)
    }

    @Test
    fun testRecommendationsCoverEveryModule() {
        val state = IntelligenceAggregator.buildState(
            healthyInputs().copy(batteryTelemetry = batteryTelemetry(temperature = 44f)),
            emptyList(),
            IntelligenceFilters.DEFAULT,
            0
        )
        IntelligenceModule.entries.forEach { module ->
            val snapshot = state.snapshotFor(module)
            assertNotNull(snapshot)
            val recommendations = IntelligenceRecommendations.forSnapshot(snapshot!!)
            assertTrue("module $module needs at least one recommendation", recommendations.isNotEmpty())
        }
    }

    // ------------------------------------------------------------------ measured performance

    @Test
    fun testAggregatorPerformanceBudget() {
        val events = (1..IntelligenceLimits.LOADED_EVENTS).map { index ->
            sampleEvent(
                id = index.toLong(),
                module = IntelligenceModule.nodes[index % IntelligenceModule.nodes.size],
                timestamp = now - index * 1_000L
            )
        }
        val inputs = healthyInputs().copy(
            nowEpochMs = now,
            scans = (1..40).map { index ->
                scanRecord(
                    kind = if (index % 5 == 0) ScanKind.APP_AUDIT else ScanKind.FILE,
                    target = "file-$index.bin",
                    level = if (index % 7 == 0) SecurityLevel.SUSPICIOUS else SecurityLevel.CLEAN,
                    risk = index % 40
                )
            }
        )
        val filters = IntelligenceFilters(range = IntelligenceTimeRange.HOURS_24, query = "temperature")

        // Warm-up so JIT compilation is not counted as steady-state cost.
        repeat(20) { IntelligenceAggregator.buildState(inputs, events, filters, 0L) }

        val iterations = 120
        val samples = LongArray(iterations)
        repeat(iterations) { index ->
            val started = System.nanoTime()
            IntelligenceAggregator.buildState(inputs, events, filters, 0L)
            samples[index] = System.nanoTime() - started
        }
        samples.sort()
        val averageMs = samples.average() / 1_000_000.0
        val p95Ms = samples[(iterations * 95) / 100] / 1_000_000.0
        println(
            "IntelligenceAggregator: ${eventCount(events)} events, 8 nodes, filters=on → " +
                "avg=${"%.3f".format(averageMs)} ms p95=${"%.3f".format(p95Ms)} ms " +
                "(budget 25 ms avg / 40 ms p95, measured on the CI JVM)"
        )

        val filterStarted = System.nanoTime()
        repeat(200) {
            events.count { filters.matches(it, now) }
        }
        val filterMs = (System.nanoTime() - filterStarted) / 1_000_000.0 / 200.0
        println("Event feed filter (800 events, query+range): avg=${"%.3f".format(filterMs)} ms per pass")
        assertTrue("aggregation average exceeded the frame-safe budget", averageMs < 25.0)
        assertTrue("aggregation p95 exceeded the frame-safe budget", p95Ms < 40.0)
        assertTrue("feed filtering exceeded the frame-safe budget", filterMs < 5.0)
    }

    // ------------------------------------------------------------------ helpers

    private fun eventCount(events: List<IntelligenceEvent>): Int = events.size

    private fun assertClose(expected: Float, actual: Float, delta: Float = 1e-4f) {
        assertEquals(expected.toDouble(), actual.toDouble(), delta.toDouble())
    }

    private fun healthyInputs(): IntelligenceInputs = IntelligenceInputs(
        nowEpochMs = now,
        vpnStatus = VpnStatus.CONNECTED,
        protectionExpected = true,
        connectedSinceEpochMs = now - 3_600_000L,
        protectionMode = ProtectionMode.STANDARD,
        loadedRuleCount = 120_000,
        sessionTotalQueries = 2_000,
        sessionBlockedQueries = 145,
        averageLatencyMs = 24,
        resolverLabel = "Cloudflare (1.1.1.1)",
        dnsProtocolLabel = "DNS-over-HTTPS (DoH)",
        emergencyAllowlistOnly = false,
        autoUpdateFiltersEnabled = true,
        lastFilterUpdateEpochMs = now - 7_200_000L,
        scheduledScanEnabled = true,
        scheduledScanIntervalHours = 24,
        smartAutoOptimizeEnabled = true,
        browserCosmeticFilteringEnabled = true,
        browserBlockThirdPartyCookies = true,
        perAppDnsRuleCount = 1,
        trackerBlocksRecent = 12,
        filterSourceCount = 4,
        scans = emptyList(),
        quarantine = emptyList(),
        batteryTelemetry = batteryTelemetry(temperature = 33f)
    )

    private fun sampleEvent(id: Long, module: IntelligenceModule, timestamp: Long): IntelligenceEvent {
        val type = IntelligenceEventType.entries.first { it.module == module }
        return IntelligenceEvent(
            id = id,
            module = module,
            type = type,
            severity = IntelligenceSeverity.WARNING,
            timestampEpochMs = timestamp,
            title = "${module.shortLabel} sample event",
            description = "Test fixture representing a stored event",
            evidence = "Recorded evidence for ${module.displayName}",
            evidenceRef = "test:$id"
        )
    }

    private fun scanRecord(
        kind: ScanKind = ScanKind.FILE,
        target: String = "sample.bin",
        level: SecurityLevel = SecurityLevel.SUSPICIOUS,
        risk: Int = 50,
        findings: List<String> = listOf("Suspicious permission stack detected"),
        timestamp: Long = now - 60_000L
    ): SecurityScanRecord = SecurityScanRecord(
        id = 42L,
        kind = kind,
        target = target,
        threatLevel = level,
        riskScore = risk,
        threatName = findings.firstOrNull(),
        findings = findings,
        recommendation = "Review the finding in Security",
        timestampEpochMs = timestamp,
        scanSource = ScanSource.MANUAL,
        durationMs = 120L
    )

    private fun batteryTelemetry(
        temperature: Float?,
        temperatureSupported: Boolean = true
    ): BatteryTelemetry = BatteryTelemetry(
        timestampEpochMs = now,
        levelPercent = BatteryReading.measured(72, "%"),
        statusLabel = "Discharging",
        isCharging = false,
        isFull = false,
        pluggedLabel = "Unplugged",
        pluggedRaw = 0,
        temperatureCelsius = if (temperatureSupported && temperature != null) {
            BatteryReading.measured(temperature, "°C")
        } else if (temperatureSupported) {
            BatteryReading.unavailable("°C")
        } else {
            BatteryReading.unsupported<Float>("°C")
        },
        voltageVolts = BatteryReading.measured(4.1f, "V"),
        currentMilliAmps = BatteryReading.measured(-420, "mA"),
        currentAverageMilliAmps = BatteryReading.measured(-400, "mA"),
        chargeCounterMicroAmpHours = BatteryReading.measured(3_000_000L, "µAh"),
        powerWatts = BatteryReading.computed(1.7f, "W"),
        healthLabel = "Good",
        health = BatteryHealthStatus.GOOD,
        technology = "Li-ion",
        chargeTimeRemainingMinutes = BatteryReading.unavailable("min"),
        runtimeRemainingMinutes = BatteryReading.estimated(420, "min"),
        manufacturer = "Test",
        model = "JVM",
        cycleCount = BatteryReading.unavailable("cycles"),
        chargeFullDesignMicroAmpHours = BatteryReading.measured(4_000_000L, "µAh"),
        chargeFullMicroAmpHours = BatteryReading.measured(3_900_000L, "µAh"),
        currentSignKnown = true,
        historyCoverage = HistoryCoverage.APP_FOREGROUND_ONLY
    )

    private class FakeIntelligenceDao : IntelligenceEventDao {
        private val state = MutableStateFlow<List<IntelligenceEventEntity>>(emptyList())

        fun seed(vararg rows: IntelligenceEventEntity) {
            state.value = rows.toList()
        }

        override suspend fun insert(event: IntelligenceEventEntity): Long {
            val nextId = (state.value.maxOfOrNull { it.id } ?: 0L) + 1L
            state.value = state.value + event.copy(id = nextId)
            return nextId
        }

        override fun observeRecent(limit: Int): Flow<List<IntelligenceEventEntity>> =
            state.map { rows ->
                rows.sortedWith(
                    compareByDescending<IntelligenceEventEntity> { it.timestampEpochMs }.thenByDescending { it.id }
                ).take(limit)
            }

        override fun observeForModule(module: String, limit: Int): Flow<List<IntelligenceEventEntity>> =
            state.map { rows ->
                rows.filter { it.module == module }
                    .sortedByDescending { it.timestampEpochMs }
                    .take(limit)
            }

        override suspend fun count(): Int = state.value.size

        override suspend fun countForModule(module: String): Int =
            state.value.count { it.module == module }

        override suspend fun pruneBefore(cutoffEpochMs: Long): Int {
            val before = state.value.size
            state.value = state.value.filterNot { it.timestampEpochMs < cutoffEpochMs }
            return before - state.value.size
        }

        override suspend fun trimToLimit(maxRows: Int): Int {
            val before = state.value.size
            state.value = state.value
                .sortedByDescending { it.timestampEpochMs }
                .take(maxRows)
            return before - state.value.size
        }

        override suspend fun clearAll() {
            state.value = emptyList()
        }
    }
}
