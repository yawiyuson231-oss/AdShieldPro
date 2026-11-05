package com.adshield.pro

import com.adshield.pro.cloud.data.ClientSideCipher
import com.adshield.pro.cloud.data.CloudCryptoFormat
import com.adshield.pro.cloud.data.CloudSession
import com.adshield.pro.cloud.util.ByteFormat
import com.adshield.pro.cloud.util.Hashing
import com.adshield.pro.engine.browser.OnionAddress
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * JVM tests for the pure logic behind CyberShield Cloud and the private browser.
 * Everything here runs offline, with no Android framework dependency.
 */
class CloudLogicTestSuite {

    // ------------------------------------------------------------------ crypto
    @Test
    fun `client side encryption round trips and produces a versioned container`() {
        val plaintext = """{"kind":"full","rules":["ads.example.com"]}""".toByteArray()
        val cipher = ClientSideCipher()
        val encrypted = cipher.encrypt(plaintext, "correct horse battery".toCharArray())

        assertEquals(CloudCryptoFormat.MAGIC, String(encrypted.data, 0, 8, Charsets.US_ASCII))
        assertTrue("ciphertext must differ from plaintext", !encrypted.data.contentEquals(plaintext))
        assertTrue(cipher.looksEncrypted(encrypted.data))
        assertEquals(Hashing.sha256Hex(plaintext), encrypted.sha256OfPlaintext)

        val decrypted = cipher.decrypt(encrypted.data, "correct horse battery".toCharArray())
        assertArrayEquals(plaintext, decrypted)
    }

    @Test(expected = javax.crypto.AEADBadTagException::class)
    fun `wrong passphrase fails authenticated decryption`() {
        val cipher = ClientSideCipher()
        val encrypted = cipher.encrypt("secret dns config".toByteArray(), "right-pass".toCharArray())
        cipher.decrypt(encrypted.data, "wrong-pass".toCharArray())
    }

    @Test
    fun `encryption is non-deterministic thanks to random salt and iv`() {
        val cipher = ClientSideCipher()
        val a = cipher.encrypt("same input".toByteArray(), "pass".toCharArray())
        val b = cipher.encrypt("same input".toByteArray(), "pass".toCharArray())
        assertNotEquals(a.data.toList(), b.data.toList())
        assertEquals(a.sha256OfPlaintext, b.sha256OfPlaintext)
    }

    @Test
    fun `tampered ciphertext is rejected`() {
        val cipher = ClientSideCipher()
        val encrypted = cipher.encrypt("payload".toByteArray(), "pass".toCharArray())
        val tampered = encrypted.data.copyOf()
        tampered[tampered.size - 1] = (tampered[tampered.size - 1].toInt() xor 0xFF).toByte()
        val threw = runCatching { cipher.decrypt(tampered, "pass".toCharArray()) }.isFailure
        assertTrue("tampered container must not decrypt", threw)
    }

    // ------------------------------------------------------------------ hashing / formatting
    @Test
    fun `sha256 matches the known digest`() {
        assertEquals(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            Hashing.sha256Hex("abc")
        )
    }

    @Test
    fun `stream hashing equals in memory hashing and reports progress`() {
        val data = ByteArray(300_000) { (it % 251).toByte() }
        var lastReported = 0L
        val streamed = Hashing.sha256HexStream(data.inputStream(), data.size.toLong()) { hashed, _ ->
            lastReported = hashed
        }
        assertEquals(Hashing.sha256Hex(data), streamed)
        assertEquals(data.size.toLong(), lastReported)
    }

    @Test
    fun `cancelled stream hashing stops early`() {
        val data = ByteArray(8 * 1024 * 1024)
        val threw = runCatching {
            Hashing.sha256HexStream(data.inputStream(), data.size.toLong(), isCancelled = { true })
        }.isFailure
        assertTrue(threw)
    }

    @Test
    fun `byte formatting is human readable`() {
        assertEquals("512 B", ByteFormat.human(512))
        assertEquals("1.0 KB", ByteFormat.human(1024))
        assertEquals("1.0 MB", ByteFormat.human(1024L * 1024))
        assertEquals("1.0 GB", ByteFormat.human(1024L * 1024 * 1024))
        assertEquals("2.5 GB", ByteFormat.human((2.5 * 1024 * 1024 * 1024).toLong()))
    }

    @Test
    fun `eta is negative when no throughput is known`() {
        assertEquals(-1L, ByteFormat.etaSeconds(1000, 0))
        assertEquals(10L, ByteFormat.etaSeconds(1000, 100))
    }

    // ------------------------------------------------------------------ session lifecycle
    @Test
    fun `session refresh window is five minutes before expiry`() {
        val fresh = CloudSession("a", "r", System.currentTimeMillis() + 3_600_000, "u", "e@x.test")
        assertFalse(fresh.needsRefresh)
        assertFalse(fresh.isExpired)

        val almostExpired = CloudSession("a", "r", System.currentTimeMillis() + 60_000, "u", "e@x.test")
        assertTrue(almostExpired.needsRefresh)

        val expired = CloudSession("a", "r", System.currentTimeMillis() - 1, "u", "e@x.test")
        assertTrue(expired.isExpired)
    }

    // ------------------------------------------------------------------ onion / tor
    @Test
    fun `onion hosts are recognised`() {
        val v3 = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"
        assertTrue(OnionAddress.isOnion(v3))
        assertTrue(OnionAddress.isOnionHost(v3))
        assertTrue(OnionAddress.isVersion3(v3))
        assertTrue(OnionAddress.isOnion("http://$v3/search?q=privacy"))
        assertTrue(OnionAddress.isOnion("$v3.onion."))

        val v2 = "expyuzz4wqqyqhjn.onion"
        assertTrue(OnionAddress.isOnionHost(v2))
        assertFalse(OnionAddress.isVersion3(v2))

        assertFalse(OnionAddress.isOnion("https://example.com"))
        assertFalse(OnionAddress.isOnionHost("notanonion.onion.example.com"))
        assertFalse(OnionAddress.isOnionHost("short.onion"))
    }

    @Test
    fun `onion urls default to http and clearweb urls to https`() {
        val v3 = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"
        assertEquals("http://$v3", OnionAddress.toLoadableUrl(v3))
        assertEquals("https://example.com", OnionAddress.toLoadableUrl("example.com"))
        assertEquals("https://example.com/x", OnionAddress.toLoadableUrl("https://example.com/x"))
        assertTrue(OnionAddress.toLoadableUrl("privacy dns")!!.startsWith("https://duckduckgo.com/?q="))
        assertNull(OnionAddress.toLoadableUrl(""))
        assertNull(OnionAddress.toLoadableUrl("javascript:alert(1)"))
        assertNull(OnionAddress.toLoadableUrl("file:///etc/passwd"))
    }

    @Test
    fun `reachability never claims tor when no proxy exists`() {
        val onion = "http://expyuzz4wqqyqhjn.onion"
        assertEquals(
            OnionAddress.Reachability.ONION_WITHOUT_PROXY,
            OnionAddress.reachability(onion, torEnabled = true, proxyConfigured = false)
        )
        assertEquals(
            OnionAddress.Reachability.ONION_PROXY_DISABLED,
            OnionAddress.reachability(onion, torEnabled = false, proxyConfigured = true)
        )
        assertEquals(
            OnionAddress.Reachability.ONION_VIA_PROXY,
            OnionAddress.reachability(onion, torEnabled = true, proxyConfigured = true)
        )
        assertEquals(
            OnionAddress.Reachability.CLEARNET,
            OnionAddress.reachability("https://example.com", torEnabled = true, proxyConfigured = true)
        )
    }

    @Test
    fun `host extraction handles ports and casing`() {
        assertEquals("example.com", OnionAddress.hostOf("HTTPS://Example.COM:443/path"))
        assertEquals("example.com", OnionAddress.hostOf("example.com"))
        assertEquals("", OnionAddress.hostOf("   "))
    }
}
