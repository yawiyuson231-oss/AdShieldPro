package com.adshield.pro

import com.adshield.pro.engine.filter.TemporaryAllowlist
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TemporaryAllowlistTest {

    private fun allowlistAt(now: Long): TemporaryAllowlist =
        TemporaryAllowlist().apply { clock = { now } }

    @Test
    fun testAGrantCoversTheNameAndItsSubdomainsOnly() {
        val list = allowlistAt(1_000L)
        assertNotNull(list.grant("googlevideo.com", durationMs = 600_000L))
        assertTrue(list.isAllowed("googlevideo.com"))
        assertTrue(list.isAllowed("r1---sn-a3xen.googlevideo.com"))
        assertTrue(list.isAllowed("GOOGLEVIDEO.com."))
        assertFalse("must not cover a sibling zone", list.isAllowed("notgooglevideo.com"))
        assertFalse("must not cover the parent", list.isAllowed("com"))
        assertFalse(list.isAllowed("example.com"))
    }

    @Test
    fun testAGrantExpiresAndDisappearsFromTheActiveList() {
        val list = TemporaryAllowlist()
        var now = 1_000L
        list.clock = { now }
        list.grant("ads.example.com", durationMs = 120_000L)
        assertTrue(list.isAllowed("ads.example.com"))
        assertEquals(1, list.activeGrants().size)
        now += 120_000L
        assertFalse("a grant ends exactly at its expiry", list.isAllowed("ads.example.com"))
        assertTrue(list.activeGrants().isEmpty())
    }

    @Test
    fun testAPublicSuffixOrGarbageIsRefused() {
        val list = allowlistAt(1_000L)
        assertNull("a bare TLD is refused", list.grant("com"))
        assertNull("an empty name is refused", list.grant("   "))
        assertNull("wildcards are refused", list.grant("*.example.com"))
        assertNull("spaces are refused", list.grant("ads example.com"))
        assertNull(list.grant("http://example.com/ads"))
        assertTrue(list.activeGrants().isEmpty())
    }

    @Test
    fun testDurationIsClampedToTheBoundedWindow() {
        val list = allowlistAt(1_000_000L)
        val tooLong = list.grant("example.com", durationMs = 24 * 60 * 60 * 1000L)
        assertEquals(1_000_000L + TemporaryAllowlist.MAX_DURATION_MS, tooLong!!.expiresAtEpochMs)
        val tooShort = list.grant("other.example.com", durationMs = 1L)
        assertEquals(1_000_000L + TemporaryAllowlist.MIN_DURATION_MS, tooShort!!.expiresAtEpochMs)
    }

    @Test
    fun testTheSoonestExpiringGrantIsEvictedWhenFull() {
        var now = 0L
        val list = TemporaryAllowlist()
        list.clock = { now }
        // Fill the list; every grant expires at a distinct time so eviction is deterministic.
        repeat(TemporaryAllowlist.MAX_GRANTS) { index ->
            now = index.toLong() * 1_000L
            assertNotNull(list.grant("host$index.example.com", durationMs = 3_600_000L))
        }
        assertEquals(TemporaryAllowlist.MAX_GRANTS, list.activeGrants().size)
        now = TemporaryAllowlist.MAX_GRANTS * 1_000L
        assertNotNull(list.grant("new.example.com", durationMs = 3_600_000L))
        assertEquals(TemporaryAllowlist.MAX_GRANTS, list.activeGrants().size)
        assertNull("host0 had the earliest expiry, so it is the one evicted", list.match("host0.example.com"))
        assertTrue(list.isAllowed("host1.example.com"))
    }

    @Test
    fun testRevokeAndClearRemoveAccessImmediately() {
        val list = allowlistAt(5_000L)
        list.grant("a.example.com")
        list.grant("b.example.com")
        assertTrue(list.revoke("a.example.com"))
        assertFalse(list.isAllowed("a.example.com"))
        assertFalse("revoking twice is not a silent success", list.revoke("a.example.com"))
        list.clear()
        assertFalse(list.isAllowed("b.example.com"))
        assertEquals(0, list.effectiveSize())
    }

    private fun TemporaryAllowlist.effectiveSize(): Int = activeGrants().size
}
