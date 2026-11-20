package com.adshield.pro

import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.adshield.pro.engine.evolution.EvolutionPublisherConfiguration
import com.adshield.pro.engine.evolution.EvolutionUpdateStager
import com.adshield.pro.engine.evolution.SignedEvolutionPackage
import com.adshield.pro.ui.evolution.EvolutionSettingsCard
import com.adshield.pro.ui.theme.AdShieldProTheme
import java.io.File
import java.net.URL
import java.security.KeyPairGenerator
import java.security.Signature
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class EvolutionUpdaterDeviceTest {
    @get:Rule val compose = createComposeRule()

    @Test fun settingsConsentStartsOffAndCanBeDisabledWithoutPublisher() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertTrue(EvolutionPublisherConfiguration.setEnabled(context, false))
        assertFalse(EvolutionPublisherConfiguration.enabled(context))
        if (EvolutionPublisherConfiguration.createStager(context) == null) {
            assertFalse(EvolutionPublisherConfiguration.setEnabled(context, true))
        }
        compose.setContent { AdShieldProTheme { EvolutionSettingsCard() } }
        compose.onNodeWithText("Signed APK reputation updates").assertExists()
        assertFalse(EvolutionPublisherConfiguration.enabled(context))
    }

    @Test fun androidPrivateFilesystemSupportsAtomicActivationAndRollback() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val directory = File(context.noBackupFilesDir, "evolution-device-test-${System.nanoTime()}")
        val pair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val now = System.currentTimeMillis() / 1000
        fun packet(sequence: Long): ByteArray {
            val data = SignedEvolutionPackage.payload(SignedEvolutionPackage.Manifest(
                "device-test-only", sequence, now - 1, now + 3600, 1, Long.MAX_VALUE,
                listOf(SignedEvolutionPackage.Indicator("a".repeat(64), "malware"))))
            val signature = Signature.getInstance("SHA256withRSA").run {
                initSign(pair.private); update(data); sign()
            }
            return SignedEvolutionPackage.envelope(data, signature)
        }
        try {
            val stager = EvolutionUpdateStager(directory, URL("https://example.invalid/no-network"),
                mapOf("device-test-only" to pair.public), 1)
            stager.stage(packet(1)); assertTrue(stager.activateLatest())
            assertEquals("malware", stager.lookupSha256("a".repeat(64)))
            stager.stage(packet(2)); assertTrue(stager.activateLatest())
            assertTrue(stager.rollback())
            assertEquals(1L, stager.activeStatus()!!.sequence)
            assertFalse(stager.activateLatest())
        } finally { directory.deleteRecursively() }
    }
}
