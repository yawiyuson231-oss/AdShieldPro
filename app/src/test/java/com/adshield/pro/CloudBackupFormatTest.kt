package com.adshield.pro

import com.adshield.pro.data.cloud.CloudBackupFormat
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CloudBackupFormatTest {

    @Test
    fun fileName_isStableAndStrictlyRecognised() {
        val fileName = CloudBackupFormat.fileName(1_735_689_600_123L)

        assertEquals("adshield-pro-backup-1735689600123.json", fileName)
        assertTrue(CloudBackupFormat.isBackupFileName(fileName))
        assertFalse(CloudBackupFormat.isBackupFileName("adshield-pro-backup-1735689600123 (1).json"))
        assertFalse(CloudBackupFormat.isBackupFileName("my-adshield-pro-backup-1735689600123.json"))
        assertFalse(CloudBackupFormat.isBackupFileName("adshield-pro-backup-not-a-date.json"))
    }

    @Test(expected = IllegalArgumentException::class)
    fun fileName_rejectsNegativeTimes() {
        CloudBackupFormat.fileName(-1L)
    }
}
