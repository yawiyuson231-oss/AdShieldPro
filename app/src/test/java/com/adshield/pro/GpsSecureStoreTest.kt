package com.adshield.pro

import com.adshield.pro.gps.security.LocationCipher
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import javax.crypto.AEADBadTagException
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/**
 * AdShield Pro — encrypted location history container (`ADSE1`).
 *
 * [LocationCipher] is the pure part of the Keystore-backed store: identical code path, any
 * [SecretKey]. That lets the container format, the wrong-key case and tamper detection be proven
 * on the JVM; the Keystore itself and the file store still need a device.
 */
class GpsSecureStoreTest {

    private fun key(): SecretKey {
        val generator = KeyGenerator.getInstance("AES")
        generator.init(256)
        return generator.generateKey()
    }

    private val sampleTrip = """
        {"trip":"2026-11-05T08:00:00Z","points":[[14.5995,120.9842,8.0,29.2],[14.6001,120.9849,6.0,31.0]]}
    """.trimIndent().toByteArray(Charsets.UTF_8)

    @Test
    fun testEncryptedContainerIsNotThePlaintext() {
        val secret = key()
        val container = LocationCipher.encrypt(secret, sampleTrip)
        assertTrue("the container must be larger than the payload (header + IV + GCM tag)", container.size > sampleTrip.size)
        assertFalse(
            "the plaintext must not survive inside the ciphertext",
            String(container, Charsets.ISO_8859_1).contains("14.5995")
        )
        assertTrue("the container must announce its own format", LocationCipher.isContainer(container))
    }

    @Test
    fun testRoundTripRestoresTheExactBytes() {
        val secret = key()
        assertArrayEquals(sampleTrip, LocationCipher.decrypt(secret, LocationCipher.encrypt(secret, sampleTrip)))
    }

    @Test
    fun testSameKeyTwiceProducesDifferentContainers() {
        // A fresh random IV per write: two writes of identical trip data must not be linkable on disk.
        val secret = key()
        val first = LocationCipher.encrypt(secret, sampleTrip)
        val second = LocationCipher.encrypt(secret, sampleTrip)
        assertFalse("IV reuse would leak equality of trips", first.contentEquals(second))
        assertArrayEquals(sampleTrip, LocationCipher.decrypt(secret, second))
    }

    @Test
    fun testHeaderLayoutMatchesTheDocumentedFormat() {
        val container = LocationCipher.encrypt(key(), sampleTrip)
        assertEquals("ADSE1", String(container.copyOfRange(0, 5), Charsets.US_ASCII))
        assertEquals(LocationCipher.IV_BYTES, container[5].toInt())
        // 5 magic + 1 length + 12 IV + payload + 16-byte GCM tag.
        assertEquals(5 + 1 + LocationCipher.IV_BYTES, container.size - sampleTrip.size - 16)
    }

    @Test
    fun testWrongKeyIsRejected() {
        val container = LocationCipher.encrypt(key(), sampleTrip)
        val failure = runCatching { LocationCipher.decrypt(key(), container) }.exceptionOrNull()
        assertNotNull("a different key must not decrypt the file", failure)
    }

    @Test
    fun testTamperedCiphertextFailsAuthentication() {
        val secret = key()
        val container = LocationCipher.encrypt(secret, sampleTrip)
        // Flip one bit in the last ciphertext block: GCM must refuse rather than return garbage.
        container[container.size - 1] = (container[container.size - 1].toInt() xor 0x01).toByte()
        val failure = runCatching { LocationCipher.decrypt(secret, container) }.exceptionOrNull()
        assertTrue(
            "tampering must surface as an authentication failure, got $failure",
            failure is AEADBadTagException
        )
    }

    @Test
    fun testTamperedIvFailsAuthentication() {
        val secret = key()
        val container = LocationCipher.encrypt(secret, sampleTrip)
        container[5 + 1] = (container[5 + 1].toInt() xor 0xff).toByte()
        assertNotNull(runCatching { LocationCipher.decrypt(secret, container) }.exceptionOrNull())
    }

    @Test
    fun testPlaintextFileIsNotMistakenForAContainer() {
        assertFalse(LocationCipher.isContainer(sampleTrip))
        val failure = runCatching { LocationCipher.decrypt(key(), sampleTrip) }.exceptionOrNull()
        assertTrue(failure is IllegalArgumentException)
        assertTrue(
            "the error must say what the file should have been, got: ${failure?.message}",
            failure?.message?.contains("AdShield") == true
        )
    }

    @Test
    fun testHeaderOnlyFileIsRejectedAsTruncated() {
        val container = LocationCipher.encrypt(key(), sampleTrip)
        val truncated = container.copyOf(12) // magic + length + a partial IV, no payload
        assertFalse(LocationCipher.isContainer(truncated))
        val failure = runCatching { LocationCipher.decrypt(key(), truncated) }.exceptionOrNull()
        assertTrue(failure is IllegalArgumentException)
    }

    @Test
    fun testEmptyPayloadStillRoundTrips() {
        // A user who deletes their history writes an empty document, not a corrupt one.
        val secret = key()
        val empty = ByteArray(0)
        val container = LocationCipher.encrypt(secret, empty)
        assertArrayEquals(empty, LocationCipher.decrypt(secret, container))
    }

    @Test
    fun testRestoredKeyDecryptsEarlierData() {
        // Models the real upgrade path: the raw key bytes are reloaded from the Keystore on the next
        // app start, and yesterday's trips must still open.
        val secret = key()
        val container = LocationCipher.encrypt(secret, sampleTrip)
        val reloaded = SecretKeySpec(secret.encoded, "AES")
        assertArrayEquals(sampleTrip, LocationCipher.decrypt(reloaded, container))
    }
}
