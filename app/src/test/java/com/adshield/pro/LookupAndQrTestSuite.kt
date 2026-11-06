package com.adshield.pro

import com.adshield.pro.engine.connectors.ConnectorCatalogue
import com.adshield.pro.engine.connectors.IndicatorRisk
import com.adshield.pro.engine.security.QrImageDecoder
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Guards for the on-demand lookup engine, CIDR matching and the local QR decoder.
 *
 * The connector-definition tests are deliberately source-based: they catch the class of defect
 * where a catalogue entry names a native probe that no `when` branch implements, which no runtime
 * test can find because the probe simply reports "not implemented".
 */
class LookupAndQrTestSuite {

    // ---------------------------------------------------------------- QR

    @Test
    fun `qr encoder and decoder agree on a payload`() {
        val result = QrImageDecoder.selfTest("https://example.com/pay?to=merchant")
        assertTrue("self-test failed: ${result.exceptionOrNull()?.message}", result.isSuccess)
        assertTrue(result.getOrThrow().text.startsWith("https://example.com/pay"))
    }

    @Test
    fun `blank image yields no payload instead of a guess`() {
        val width = 120
        val height = 120
        val pixels = IntArray(width * height) { 0xFFFFFFFF.toInt() }
        assertTrue(QrImageDecoder.decodeArgb(width, height, pixels) == null)
    }

    @Test
    fun `oversized images are refused before decoding`() {
        val width = 9_000
        val height = 9_000
        assertTrue(QrImageDecoder.decodeArgb(width, height, IntArray(4)) == null)
    }

    // ---------------------------------------------------------------- CIDR

    @Test
    fun `cidr containment matches real networks`() {
        assertTrue(IndicatorRisk.ipInCidr("1.2.3.4", "1.2.0.0/16"))
        assertTrue(IndicatorRisk.ipInCidr("192.168.255.1", "192.168.0.0/16"))
        assertTrue(IndicatorRisk.ipInCidr("8.8.8.8", "0.0.0.0/0"))
        assertFalse(IndicatorRisk.ipInCidr("1.3.0.1", "1.2.0.0/16"))
        assertFalse(IndicatorRisk.ipInCidr("1.2.3.4", "1.2.3.4"))
        assertFalse(IndicatorRisk.ipInCidr("999.2.3.4", "1.2.0.0/16"))
        assertFalse(IndicatorRisk.ipInCidr("1.2.3.4", "1.2.0.0/33"))
    }

    // ---------------------------------------------------------------- catalogue integrity

    @Test
    fun `every implemented native probe has a dispatch branch`() {
        val handled = probeIdsInSource(nativeProbesSource())
        assertTrue("No probe ids found in NativeConnectorProbes.kt", handled.size > 40)
        val missing = ConnectorCatalogue.all
            .filter { it.implemented && it.method == "CALL" }
            .map { it.handlerId }
            .filter { it != "none" && it !in handled }
            .distinct()
        assertTrue("Native handlers with no dispatch branch: $missing", missing.isEmpty())
    }

    @Test
    fun `no native handler is dead code`() {
        val handled = probeIdsInSource(nativeProbesSource())
        val referenced = ConnectorCatalogue.all.map { it.handlerId }.toSet()
        val unused = handled.filter { it != "none" && it !in referenced }
        assertTrue("Dispatch branches no connector uses: $unused", unused.isEmpty())
    }

    @Test
    fun `lookup connectors are https templated and cacheable`() {
        val lookups = ConnectorCatalogue.all.filter { it.isLookup && it.implemented }
        assertTrue("Expected lookup connectors to exist", lookups.isNotEmpty())
        lookups.forEach { spec ->
            assertNotNull("${spec.id} has no queryField", spec.queryField)
            assertTrue("${spec.id} endpoint is not https", spec.endpoint.startsWith("https://"))
            assertTrue("${spec.id} endpoint has no {value} template", spec.endpoint.contains("{value}"))
            assertTrue("${spec.id} TTL below one minute", spec.cacheTtlMs >= 60_000L)
            assertTrue("${spec.id} lookup must not be default-enabled", !spec.defaultEnabled)
        }
    }

    @Test
    fun `lookup connectors never require a key to be counted as implemented`() {
        ConnectorCatalogue.all.filter { it.isLookup }.forEach { spec ->
            if (spec.requiresKey) {
                assertFalse("${spec.id} is key-gated but marked implemented", spec.implemented)
                assertFalse("${spec.id} is key-gated but default-enabled", spec.defaultEnabled)
            }
        }
    }

    @Test
    fun `retired sources are not implemented`() {
        ConnectorCatalogue.all.forEach { spec ->
            if (spec.verification == com.adshield.pro.domain.connectors.VerificationClass.SOURCE_UNAVAILABLE) {
                assertFalse("${spec.id} is unavailable but implemented", spec.implemented)
            }
        }
    }

    // ---------------------------------------------------------------- helpers

    private fun nativeProbesSource(): String {
        val candidates = listOf(
            "src/main/java/com/adshield/pro/engine/connectors/NativeConnectorProbes.kt",
            "app/src/main/java/com/adshield/pro/engine/connectors/NativeConnectorProbes.kt"
        )
        return candidates.map(::File).firstOrNull { it.isFile }?.readText()
            ?: error("NativeConnectorProbes.kt not found from ${File(".").absolutePath}")
    }

    private fun probeIdsInSource(source: String): Set<String> =
        Regex("\"(probe\\.[a-z0-9-]+|none)\"\\s*->")
            .findAll(source)
            .map { it.groupValues[1] }
            .toSet()
}
