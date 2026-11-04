package com.adshield.pro

import com.adshield.pro.engine.battery.BatteryAlertPolicy
import com.adshield.pro.engine.battery.BatteryDiagnostic
import com.adshield.pro.engine.battery.BatteryDiagnosticSeverity
import com.adshield.pro.engine.platform.DiagnosticReport
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Battery alert policy — the half of "High-temperature and charging-complete alerts" that used
 * to be missing. These cases pin the properties that make the notifications trustworthy:
 * no spam, no alert without a real reading, and a real re-arm.
 */
class BatteryAlertPolicyTest {

    private val idle = BatteryAlertPolicy.State()

    @Test
    fun testOverheatAlertFiresOnceAndLatchesUntilItActuallyCools() {
        val hot = BatteryAlertPolicy.evaluate(50, 45.5f, false, false, idle)
        assertEquals("exactly one alert for a hot reading", 1, hot.alerts.size)
        assertEquals(BatteryAlertPolicy.AlertKind.OVERHEAT, hot.alerts.first().kind)
        assertTrue("a hot battery is not a low-priority notice", hot.alerts.first().priorityHigh)
        assertTrue(hot.state.overheatLatched)

        // Still above the clear threshold: no repeat, and the reason says why.
        val stillHot = BatteryAlertPolicy.evaluate(50, 42.5f, false, false, hot.state)
        assertTrue("must not re-notify while latched", stillHot.alerts.isEmpty())
        assertTrue(stillHot.reasons.any { it.contains("latched") })

        // Between the bands: still latched (hysteresis, not a timer).
        val wobble = BatteryAlertPolicy.evaluate(50, 41.9f, false, false, stillHot.state)
        assertTrue(wobble.alerts.isEmpty())
        assertTrue(wobble.state.overheatLatched)

        // Below the clear threshold: re-armed, still no notification.
        val cooled = BatteryAlertPolicy.evaluate(50, 39f, false, false, wobble.state)
        assertTrue(cooled.alerts.isEmpty())
        assertFalse(cooled.state.overheatLatched)

        // A new episode alerts again.
        val again = BatteryAlertPolicy.evaluate(50, 46f, false, false, cooled.state)
        assertEquals(1, again.alerts.size)
    }

    @Test
    fun testMissingOrStubTemperatureNeverProducesAnAlert() {
        val missing = BatteryAlertPolicy.evaluate(50, null, true, false, idle)
        assertTrue(missing.alerts.isEmpty())
        assertTrue("must state that the sensor is missing instead of assuming cold",
            missing.reasons.any { it.contains("temperature unavailable") })
        assertEquals("a missing sensor must not latch", idle, missing.state)

        val stub = BatteryAlertPolicy.evaluate(50, 0f, true, false, idle)
        assertTrue("0 °C is a driver stub, not a reading", stub.alerts.isEmpty())
        assertFalse(BatteryAlertPolicy.isPlausibleTemperature(0f))
        assertFalse(BatteryAlertPolicy.isPlausibleTemperature(Float.NaN))
    }

    @Test
    fun testChargedAlertFiresOnceAndRearmsWhenUnplugged() {
        val full = BatteryAlertPolicy.evaluate(100, 31f, true, true, idle)
        assertEquals(1, full.alerts.size)
        assertEquals(BatteryAlertPolicy.AlertKind.CHARGED, full.alerts.first().kind)
        assertTrue(full.state.chargedLatched)

        val repeat = BatteryAlertPolicy.evaluate(100, 31f, true, true, full.state)
        assertTrue(repeat.alerts.isEmpty())

        val unplugged = BatteryAlertPolicy.evaluate(99, 30f, false, false, repeat.state)
        assertFalse("unplugging must re-arm the alert", unplugged.state.chargedLatched)
        assertTrue(unplugged.alerts.isEmpty())
    }

    @Test
    fun testFullLevelWithoutTheChargerDoesNotClaimChargingIsComplete() {
        // 100 % but not charging: no "charging complete" notification, because nothing is charging.
        val outcome = BatteryAlertPolicy.evaluate(100, 30f, false, true, idle)
        assertTrue(outcome.alerts.none { it.kind == BatteryAlertPolicy.AlertKind.CHARGED })
    }

    @Test
    fun testCriticalLevelAlertsOnceAndRearmsAboveTheThreshold() {
        val low = BatteryAlertPolicy.evaluate(12, 30f, false, false, idle)
        assertEquals(1, low.alerts.size)
        assertEquals(BatteryAlertPolicy.AlertKind.CRITICAL_LEVEL, low.alerts.first().kind)
        assertTrue(low.state.criticalLatched)

        val stillLow = BatteryAlertPolicy.evaluate(11, 30f, false, false, low.state)
        assertTrue(stillLow.alerts.isEmpty())

        val recovered = BatteryAlertPolicy.evaluate(25, 30f, true, false, stillLow.state)
        assertFalse(recovered.state.criticalLatched)
        assertTrue(recovered.alerts.isEmpty())
    }

    @Test
    fun testDisabledAlertsKeepTheLatchSoReEnablingDoesNotSpam() {
        val outcome = BatteryAlertPolicy.evaluate(50, 47f, false, false, idle, alertsEnabled = false)
        assertTrue("no notification while disabled", outcome.alerts.isEmpty())
        assertTrue("but the condition is remembered", outcome.state.overheatLatched)
        assertTrue(outcome.reasons.any { it.contains("disabled") })

        val reEnabled = BatteryAlertPolicy.evaluate(50, 47f, false, false, outcome.state, alertsEnabled = true)
        assertTrue("re-enabling must not immediately notify about an old episode", reEnabled.alerts.isEmpty())
    }

    @Test
    fun testEveryAlertCarriesAStableKeyAndHumanCopy() {
        val kinds = setOf(
            BatteryAlertPolicy.evaluate(50, 46f, true, false, idle).alerts.map { it.key },
            BatteryAlertPolicy.evaluate(100, 30f, true, true, idle).alerts.map { it.key },
            BatteryAlertPolicy.evaluate(10, 30f, false, false, idle).alerts.map { it.key }
        ).flatten()
        assertEquals("three distinct alert keys", 3, kinds.toSet().size)
        for (alert in BatteryAlertPolicy.evaluate(50, 46f, true, false, idle).alerts) {
            assertTrue(alert.title.isNotBlank())
            assertTrue("the body must explain the measured value", alert.body.contains("°C"))
            assertTrue(alert.kind.channelId.startsWith("adshield_"))
        }
    }

    @Test
    fun testCriticalDiagnosticBecomesANotificationAndLowerSeveritiesDoNot() {
        val critical = BatteryDiagnostic(
            title = "Battery is critically hot",
            explanation = "48 °C while charging",
            recommendation = "Unplug the charger and let it cool.",
            severity = BatteryDiagnosticSeverity.CRITICAL,
            confidencePercent = 90,
            evidence = listOf("temperature=48.0°C")
        )
        val alert = BatteryAlertPolicy.forCriticalDiagnostic(critical)
        assertNotNull(alert)
        assertEquals("Battery is critically hot", alert!!.title)
        assertEquals("Unplug the charger and let it cool.", alert.body)

        val warning = critical.copy(severity = BatteryDiagnosticSeverity.WARNING)
        assertNull("a warning is not a notification", BatteryAlertPolicy.forCriticalDiagnostic(warning))
    }
}

/**
 * Diagnostic report export — previously PLANNED because it had to be scrubbed first.
 * These cases assert both the content and the absence of identifiers.
 */
class DiagnosticReportTest {

    private val fixedClock = 1_700_000_000_000L

    private fun sample(overrides: DiagnosticReport.Counters = counters()) = DiagnosticReport.build(
        clockMillis = fixedClock,
        build = DiagnosticReport.BuildInfo("2.7.0", 20700, "com.adshield.pro"),
        environment = DiagnosticReport.Environment(
            sdkInt = 34,
            manufacturer = "Google",
            model = "Pixel 8",
            isLowRamDevice = false,
            totalRamBytes = 8_000_000_000,
            availableStorageBytes = 12_000_000_000,
            thermalStatus = 2,
            powerSaveMode = false
        ),
        counters = overrides
    )

    private fun counters() = DiagnosticReport.Counters(
        protectionActive = true,
        protectionMode = "STANDARD",
        totalRules = 367_000,
        blockRules = 300_000,
        allowRules = 67_000,
        userRules = 12,
        lookupsToday = 4_312,
        blockedToday = 611,
        errorsToday = 2,
        upstreamTransport = "DoH (RFC 8484)",
        resolversConfigured = 3,
        lastFeedSyncAgeHours = 6,
        lastErrorCategory = "SERVFAIL"
    )

    @Test
    fun testJsonIsWellFormedForTheFieldsItClaims() {
        val json = DiagnosticReport.toJson(sample())
        assertTrue(json.startsWith("{\n"))
        assertTrue(json.endsWith("}\n"))
        assertEquals("braces must balance", json.count { it == '{' }, json.count { it == '}' })
        assertEquals("brackets must balance", json.count { it == '[' }, json.count { it == ']' })
        assertTrue(json.contains("\"formatVersion\": 1"))
        assertTrue(json.contains("\"protectionActive\": true"))
        assertTrue(json.contains("\"lookupsToday\": 4312"))
        assertTrue(json.contains("\"lastFeedSyncAgeHours\": 6"))
        // No trailing commas in objects or arrays.
        assertFalse(Regex(",\\s*[}\\]]").containsMatchIn(json))
    }

    @Test
    fun testReportCarriesNoIdentifiers() {
        val json = DiagnosticReport.toJson(sample())
        // Nothing that could single out a person, a domain or an app.
        assertFalse("no email addresses", Regex("""[\w.+-]+@[\w-]+\.[\w.]+""").containsMatchIn(json))
        assertFalse("no IPv4 addresses", Regex("""\b(?:\d{1,3}\.){3}\d{1,3}\b""").containsMatchIn(json))
        assertFalse("no MAC addresses", Regex("""\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b""").containsMatchIn(json))
        assertFalse("no domain names in the payload", json.contains("doubleclick"))
        assertFalse("no file paths", json.contains("/data/"))
        assertFalse("no rule text", json.contains("||"))
    }

    @Test
    fun testRedactorCatchesEveryIdentifierShapeItClaims() {
        assertEquals("[redacted]", DiagnosticReport.redact("user@example.com"))
        assertEquals("[redacted]", DiagnosticReport.redact("192.168.1.20"))
        assertEquals("[redacted]", DiagnosticReport.redact("aa:bb:cc:dd:ee:ff"))
        assertTrue(DiagnosticReport.redact("2606:4700:4700::1111").contains("[redacted]"))
        assertEquals("Pixel 8", DiagnosticReport.redact("Pixel 8"))
    }

    @Test
    fun testNotesStateWhatTheReportDoesNotContain() {
        val report = sample()
        assertTrue(report.notes.any { it.contains("no DNS history") })
        assertTrue(report.notes.any { it.contains("not an antivirus verdict") })
        assertTrue(report.notes.any { it.contains("aggregate counters", ignoreCase = true) })
    }

    @Test
    fun testNullSyncAndErrorCategoriesRenderAsJsonNull() {
        val report = sample(counters().copy(lastFeedSyncAgeHours = null, lastErrorCategory = null))
        val json = DiagnosticReport.toJson(report)
        assertTrue(json.contains("\"lastFeedSyncAgeHours\": null"))
        assertTrue(json.contains("\"lastErrorCategory\": null"))
        assertTrue("the absence is explained in the notes",
            report.notes.any { it.contains("No remote list sync") })
    }

    @Test
    fun testQuotingEscapesEverythingThatWouldBreakTheDocument() {
        assertEquals("\"a\\\"b\"", DiagnosticReport.quote("a\"b"))
        assertEquals("\"a\\\\b\"", DiagnosticReport.quote("a\\b"))
        assertEquals("\"a\\nb\"", DiagnosticReport.quote("a\nb"))
        assertTrue(DiagnosticReport.quote("\u0001").contains("\\u0001"))
    }

    @Test
    fun testTimestampIsUtcIso8601() {
        assertEquals("2023-11-14T22:13:20Z", DiagnosticReport.formatTimestamp(fixedClock))
    }
}
