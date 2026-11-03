package com.adshield.pro

import com.adshield.pro.update.UpdateAssetSelection
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Regression tests for the in-app self-updater's release-asset selection.
 *
 * A certified GitHub release carries the release APK, a checksum file and the CI
 * keystore. The updater must never pick the debug APK (different applicationId
 * suffix + signing key) or a non-APK file, otherwise "update" turns into a failed
 * install or a second app.
 */
class UpdateAssetSelectionTest {

    @Test
    fun testUpdaterOnlyPicksTheReleaseApk() {
        // Real asset list order of a CI release: debug APK first, then the release APK.
        val realWorld = listOf(
            "app-debug.apk",
            "app-release.apk",
            "ci-release.keystore",
            "OmniShield-X-4.7.1-release.apk.sha256"
        )
        assertEquals("app-release.apk", UpdateAssetSelection.pickReleaseApkName(realWorld))

        // Only the debug build was uploaded: offer nothing rather than the wrong package.
        assertNull(UpdateAssetSelection.pickReleaseApkName(listOf("app-debug.apk", "ci-release.keystore")))
        assertNull(UpdateAssetSelection.pickReleaseApkName(emptyList()))

        assertFalse(UpdateAssetSelection.isInstallableReleaseApk("app-debug.apk"))
        assertFalse(UpdateAssetSelection.isInstallableReleaseApk("DEBUG-app.apk"))
        assertFalse(UpdateAssetSelection.isInstallableReleaseApk("OmniShield-X-4.7.1-release.apk.sha256"))
        assertTrue(UpdateAssetSelection.isInstallableReleaseApk("app-release.apk"))
        assertTrue(UpdateAssetSelection.isInstallableReleaseApk("OmniShield-X-4.7.1-release.APK"))
    }
}
