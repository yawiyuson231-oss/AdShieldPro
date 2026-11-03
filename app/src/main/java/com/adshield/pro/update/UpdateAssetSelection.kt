package com.adshield.pro.update

/**
 * Asset selection rules for the in-app self-updater.
 *
 * The GitHub release for a certified build carries several assets (release APK,
 * checksum file, CI keystore). Only the release APK can update an installed copy:
 * the debug build uses an `.debug` applicationId suffix and a different signing
 * key, so installing it would either fail or create a second app.
 *
 * Deliberately pure (no Android or OkHttp imports) so the rule is unit-testable.
 */
object UpdateAssetSelection {

    /** True when [assetName] is an installable, non-debug APK asset. */
    fun isInstallableReleaseApk(assetName: String): Boolean =
        assetName.endsWith(".apk", ignoreCase = true) &&
            !assetName.contains("debug", ignoreCase = true)

    /** First installable release APK in GitHub's asset order, or null when there is none. */
    fun pickReleaseApkName(assetNames: List<String>): String? =
        assetNames.firstOrNull(::isInstallableReleaseApk)
}
