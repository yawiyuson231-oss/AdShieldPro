package com.adshield.pro

import com.adshield.pro.engine.dns.dnsUdpWithTcpRetry
import com.adshield.pro.engine.dns.firstUsableDnsAddress
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.delay
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Test

class DnsAddressFallbackTest {
    @Test
    fun usesOnlyTheFastFirstAddressAndNeverRetriesCompleteUdpOverTcp() = runTest {
        val calls = mutableListOf<Int>()
        val result = firstUsableDnsAddress(listOf(1, 2, 3, 4), 650) { address ->
            calls += address
            dnsUdpWithTcpRetry(2700, udp = { "complete" }, tcp = { error("Unexpected TCP") })
        }
        assertEquals("complete", result)
        assertEquals(listOf(1), calls)
    }

    @Test
    fun laterAddressesStartWithinTheProviderBudgetAndLosingSocketsAreCancelled() = runTest {
        val started = mutableListOf<Int>()
        val cancelled = mutableListOf<Int>()
        val result = withTimeout(6500) {
            firstUsableDnsAddress(listOf(1, 2, 3, 4), 650) { address ->
                started += address
                if (address == 4) return@firstUsableDnsAddress "usable"
                try {
                    awaitCancellation()
                } finally {
                    cancelled += address
                }
            }
        }
        assertEquals("usable", result)
        assertEquals(listOf(1, 2, 3, 4), started)
        assertEquals(setOf(1, 2, 3), cancelled.toSet())
    }

    @Test
    fun lateMatchingUdpTruncationDoesNotSpendTheTcpRetryBudget() = runTest {
        val result = withTimeout(6500) {
            dnsUdpWithTcpRetry(2700, udp = { delay(1750); null }, tcp = { delay(1200); "complete TCP" })
        }
        assertEquals("complete TCP", result)
    }
}
