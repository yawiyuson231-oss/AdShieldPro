package com.adshield.pro

import com.adshield.pro.ui.model.TemporaryLeaseText
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TemporaryLeaseTextTest {

    @Test
    fun testTheRemainingLabelIsPlainAndNeverNegative() {
        assertEquals("15 min left", TemporaryLeaseText.remainingLabel(15L))
        assertEquals("1 min left", TemporaryLeaseText.remainingLabel(1L))
        assertEquals("ending now", TemporaryLeaseText.remainingLabel(0L))
        assertEquals("ending now", TemporaryLeaseText.remainingLabel(-5L))
    }

    @Test
    fun testTheLabelNeverClaimsMoreTimeThanRemains() {
        listOf(0L, 1L, 2L, 14L, 59L, 60L).forEach { minutes ->
            val label = TemporaryLeaseText.remainingLabel(minutes)
            assertFalse("a label must not be empty: $minutes", label.isBlank())
            if (minutes > 0L) {
                assertTrue("the label must state the minutes: $minutes -> $label", label.startsWith("$minutes min"))
            }
        }
    }
}
