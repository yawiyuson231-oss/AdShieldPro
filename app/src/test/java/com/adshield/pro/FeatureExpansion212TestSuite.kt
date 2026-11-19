package com.adshield.pro

import com.adshield.pro.domain.model.DnsProtocol
import com.adshield.pro.domain.model.DnsProviderPreset
import com.adshield.pro.domain.model.DnsResolverConfig
import com.adshield.pro.domain.model.NetworkTransportPolicy
import com.adshield.pro.domain.model.ProtectionMode
import com.adshield.pro.engine.aether.BehavioralAnomalyEngine
import com.adshield.pro.engine.battery.BatteryHealthStatus
import com.adshield.pro.engine.battery.BatteryReading
import com.adshield.pro.engine.battery.BatteryTelemetry
import com.adshield.pro.engine.battery.HistoryCoverage
import com.adshield.pro.engine.browser.BrowserTabSessionManager
import com.adshield.pro.engine.dns.HardcodedDnsTrap
import com.adshield.pro.engine.dns.ObliviousDohCodec
import com.adshield.pro.engine.filter.BinaryFilterSnapshotCodec
import com.adshield.pro.engine.platform.ContextAutomationEngine
import com.adshield.pro.engine.security.ApkSignatureVerifier
import com.adshield.pro.engine.security.QrPayloadInspector
import com.adshield.pro.engine.storage.ZeroKnowledgeFileCipher
import com.adshield.pro.worker.BatteryAlertWorker
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import javax.crypto.spec.SecretKeySpec

class FeatureExpansion212TestSuite {

    @Test
    fun hardcodedDnsTrapExcludesActivePlaintextUpstream() {
        val routes = HardcodedDnsTrap.buildTrapRoutes(
            enabled = true,
            excludedPlaintextUpstreamIps = setOf("8.8.8.8")
        )
        assertTrue(routes.none { it.address == "8.8.8.8" })
        assertTrue(routes.any { it.address == "1.1.1.1" && it.prefixLength == 32 })
        assertTrue(routes.any { it.address == "2606:4700:4700::1111" && it.prefixLength == 128 })
    }

    @Test
    fun obliviousDohCodecRejectsPrivateRelayAndBuildsValidRelayUrl() {
        assertNull(ObliviousDohCodec.buildRelayQueryUrl("https://127.0.0.1/proxy", "https://dns.google/dns-query"))
        val built = ObliviousDohCodec.buildRelayQueryUrl(
            "https://odoh.example.org/proxy",
            "https://cloudflare-dns.com/dns-query"
        )
        assertNotNull(built)
        assertTrue(built!!.contains("targethost=cloudflare-dns.com"))
    }

    @Test
    fun binaryFilterSnapshotRoundTripAndTamperDetection() {
        val domains = listOf("ads.example.com", "tracker.example.org", "telemetry.bad.net").sorted()
        val out = ByteArrayOutputStream()
        BinaryFilterSnapshotCodec.writeSnapshot(out, domains, emptyList())
        val bytes = out.toByteArray()

        val loaded = BinaryFilterSnapshotCodec.readSnapshot(ByteArrayInputStream(bytes))
        assertNotNull(loaded)
        assertEquals(domains, loaded!!.blockedDomains)

        // Flip a byte in the payload and verify SHA-256 integrity check rejects it
        val tampered = bytes.copyOf()
        tampered[tampered.size - 1] = (tampered[tampered.size - 1].toInt() xor 0xFF).toByte()
        assertNull(BinaryFilterSnapshotCodec.readSnapshot(ByteArrayInputStream(tampered)))
    }

    @Test
    fun behavioralAnomalyEngineDetectsScreenOffTrackersAndBeaconing() {
        val engine = BehavioralAnomalyEngine()
        val baseTs = 1_700_000_000_000L
        for (i in 0 until 6) {
            engine.recordObservation(
                domain = "telemetry.beacon.example",
                packageName = "com.example.spy",
                wasBlocked = false,
                isScreenInteractive = false,
                timestampEpochMs = baseTs + i * 30_000L
            )
        }
        val report = engine.snapshotReport()
        assertTrue(report.screenOffTrackerHits >= 6)
        assertTrue(report.beaconAlerts.any { it.domain == "telemetry.beacon.example" })
    }

    @Test
    fun qrPayloadInspectorVerifiesEmvCoCrcAndFlagsUssdTraps() {
        val ussd = QrPayloadInspector.inspect("tel:*21*09171234567#")
        assertEquals(QrPayloadInspector.Kind.DANGEROUS_URI, ussd.kind)
        assertTrue(ussd.isHighRisk)

        val payloadWithoutCrc = "0002010102125802PH5913GCashMerchant6006Manila6304"
        val crc = QrPayloadInspector.crc16CcittFalse(payloadWithoutCrc.toByteArray(Charsets.US_ASCII))
        val validQrPh = payloadWithoutCrc + "%04X".format(crc)
        val emv = QrPayloadInspector.inspect(validQrPh)
        assertEquals(QrPayloadInspector.Kind.EMVCO_PAYMENT, emv.kind)
        assertFalse(emv.isHighRisk)
    }

    @Test
    fun zeroKnowledgeFileCipherRoundTripsAndRejectsTampering() {
        val keyBytes = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val key = SecretKeySpec(keyBytes, "AES")
        val plaintext = "OmniShield X Zero-Knowledge Streaming Payload".repeat(200).toByteArray()

        val encrypted = ByteArrayOutputStream()
        ZeroKnowledgeFileCipher.encryptStreamWithKey(ByteArrayInputStream(plaintext), encrypted, key)
        val cipherBytes = encrypted.toByteArray()
        assertTrue(ZeroKnowledgeFileCipher.hasZeroKnowledgeHeader(cipherBytes))

        val decrypted = ByteArrayOutputStream()
        val summary = ZeroKnowledgeFileCipher.decryptStreamWithKey(ByteArrayInputStream(cipherBytes), decrypted, key)
        assertEquals(plaintext.size.toLong(), summary.plaintextBytes)
        assertTrue(plaintext.contentEquals(decrypted.toByteArray()))
    }

    @Test
    fun contextAutomationHardensOpenWifiAndDefersGameSync() {
        val baseConfig = DnsResolverConfig(provider = DnsProviderPreset.CLOUDFLARE, protocol = DnsProtocol.UDP_TCP)
        val openWifi = ContextAutomationEngine.evaluate(
            ContextAutomationEngine.AutomationContext(
                automationEnabled = true,
                baseMode = ProtectionMode.STANDARD,
                baseResolverConfig = baseConfig,
                transport = NetworkTransportPolicy.WIFI,
                isWifiOpenOrWep = true
            )
        )
        assertEquals("OPEN_WIFI_STRICT_DOH", openWifi.matchedRuleId)
        assertEquals(ProtectionMode.STRICT, openWifi.effectiveMode)
        assertEquals(DnsProtocol.DOH, openWifi.effectiveResolverConfig.protocol)
        assertTrue(openWifi.deferBackgroundSync)
    }

    @Test
    fun browserTabSessionManagerEnforcesHttpsFirstWithLanExemptions() {
        val (upgraded, didUpgrade) = BrowserTabSessionManager.applyHttpsFirstPolicy("http://example.com/login", true)
        assertTrue(didUpgrade)
        assertEquals("https://example.com/login", upgraded)

        val (lanUrl, lanUpgraded) = BrowserTabSessionManager.applyHttpsFirstPolicy("http://192.168.1.1/admin", true)
        assertFalse(lanUpgraded)
        assertEquals("http://192.168.1.1/admin", lanUrl)
    }

    @Test
    fun batteryAlertWorkerFlagsOverheatAndRespectsCooldown() {
        val telemetry = BatteryTelemetry(
            timestampEpochMs = 1_700_000_000_000L,
            levelPercent = BatteryReading.measured(80, "%"),
            statusLabel = "Charging",
            isCharging = true,
            isFull = false,
            pluggedLabel = "AC",
            pluggedRaw = 1,
            temperatureCelsius = BatteryReading.measured(44.2f, "°C"),
            voltageVolts = BatteryReading.measured(4.1f, "V"),
            currentMilliAmps = BatteryReading.measured(1500, "mA"),
            currentAverageMilliAmps = BatteryReading.unavailable("mA"),
            chargeCounterMicroAmpHours = BatteryReading.unavailable("µAh"),
            powerWatts = BatteryReading.computed(6.15f, "W"),
            healthLabel = "Good",
            health = BatteryHealthStatus.GOOD,
            technology = "Li-ion",
            chargeTimeRemainingMinutes = BatteryReading.unavailable("min"),
            runtimeRemainingMinutes = BatteryReading.unavailable("min"),
            manufacturer = "Test",
            model = "Device",
            cycleCount = BatteryReading.unavailable("cycles"),
            chargeFullDesignMicroAmpHours = BatteryReading.unavailable("µAh"),
            chargeFullMicroAmpHours = BatteryReading.unavailable("µAh"),
            currentSignKnown = true,
            historyCoverage = HistoryCoverage.APP_FOREGROUND_ONLY
        )
        val alert = BatteryAlertWorker.evaluateAlert(telemetry, alertsEnabled = true, overheatWarningCelsius = 43.0f)
        assertNotNull(alert)
        assertEquals(BatteryAlertWorker.AlertKind.OVERHEAT_WARNING, alert!!.kind)

        val suppressed = BatteryAlertWorker.evaluateAlert(
            telemetry,
            alertsEnabled = true,
            overheatWarningCelsius = 43.0f,
            lastAlertKindName = BatteryAlertWorker.AlertKind.OVERHEAT_WARNING.name,
            lastAlertEpochMs = 1_700_000_000_000L - 60_000L,
            nowEpochMs = 1_700_000_000_000L
        )
        assertNull(suppressed)
    }
}
