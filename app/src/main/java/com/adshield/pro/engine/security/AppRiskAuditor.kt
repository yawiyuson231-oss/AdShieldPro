package com.adshield.pro.engine.security

/**
 * AdShield Pro — Installed App Risk Auditor (Pure Kotlin rules, unit-testable).
 *
 * Reviews Android-visible app metadata: install source, requested permissions, declared
 * component bindings, and target SDK. Declarations are not permission grants or observed behavior.
 */
class AppRiskAuditor {

    enum class RiskLevel { TRUSTED, LOW, MEDIUM, HIGH }

    data class AppSecurityProfile(
        val packageName: String,
        val appName: String,
        val versionName: String?,
        val targetSdkVersion: Int,
        val requestedPermissions: List<String>,
        val installerPackageName: String?,
        val isSystemApp: Boolean,
        val isUpdatedSystemApp: Boolean = false,
        val firstInstallTimeEpochMs: Long = 0L,
        val declaredComponentPermissions: Set<String> = emptySet()
    )

    data class AppRiskAudit(
        val profile: AppSecurityProfile,
        val riskLevel: RiskLevel,
        val riskScore: Int,
        val findings: List<String>,
        val summary: String
    )

    data class VisibleAudit(val visibleCount: Int, val inspected: List<AppRiskAudit>) {
        val unavailableCount: Int get() = visibleCount - inspected.size
    }

    fun audit(profile: AppSecurityProfile): AppRiskAudit {
        val findings = ArrayList<String>()
        var score = 0

        val requested = profile.requestedPermissions.toHashSet()
        fun has(permission: String) = "android.permission.$permission" in requested
        fun declaresBinding(permission: String) = "android.permission.$permission" in profile.declaredComponentPermissions
        val declaresAccessibility = declaresBinding("BIND_ACCESSIBILITY_SERVICE")

        // Installer origin trust
        when (profile.installerPackageName) {
            "com.android.vending", "com.google.android.feedback" -> {
                // Play Store origin — baseline trust
            }
            null, "" -> {
                findings.add("Unknown install source (no installer reported)")
                score += 15
            }
            else -> {
                findings.add("Android reported this installer: ${profile.installerPackageName}")
                score += 10
            }
        }

        if (declaresAccessibility) {
            findings.add("Declares an Accessibility binding; this does not confirm the service is enabled")
            score += 30
        }
        if (declaresAccessibility && has("RECEIVE_SMS")) {
            findings.add("Declares Accessibility and requests SMS receive access (potential SMS interception, not observed)")
            score += 25
        }

        // Silent install dropper pattern
        if (has("REQUEST_INSTALL_PACKAGES")) {
            findings.add("Requests permission to install other packages")
            score += 15
        }
        if (has("REQUEST_INSTALL_PACKAGES") && !has("INTERNET")) {
            findings.add("Requests package installation without requesting Internet access")
            score += 10
        }

        // Lockware / device admin
        if (declaresBinding("BIND_DEVICE_ADMIN")) {
            findings.add("Declares a device administrator binding; active admin status was not checked")
            score += 15
        }
        if (declaresBinding("BIND_NOTIFICATION_LISTENER_SERVICE")) {
            findings.add("Declares a notification listener binding; notification access was not verified")
            score += 12
        }

        // Surveillance stack
        if (has("RECORD_AUDIO") && has("CAMERA") &&
            has("ACCESS_BACKGROUND_LOCATION")
        ) {
            findings.add("Requests microphone, camera and background location together")
            score += 25
        }
        if (has("SEND_SMS") && has("READ_CONTACTS")) {
            findings.add("Requests SMS sending and contacts access together")
            score += 12
        }

        // SDK hygiene
        if (profile.targetSdkVersion in 1..28 && !profile.isSystemApp) {
            findings.add("Targets an older Android version (targetSdk ${profile.targetSdkVersion})")
            score += 12
        }

        // Updated system app (possible privileged tampering on old ROMs)
        if (profile.isUpdatedSystemApp && profile.installerPackageName != "com.android.vending") {
            findings.add("Android did not report Google Play as the installer for this system app update")
            score += 6
        }

        // System apps get baseline trust discount
        if (profile.isSystemApp && !profile.isUpdatedSystemApp) {
            score = (score * 0.6f).toInt()
        }

        val level = when {
            score >= 55 -> RiskLevel.HIGH
            score >= 28 -> RiskLevel.MEDIUM
            score >= 10 -> RiskLevel.LOW
            else -> RiskLevel.TRUSTED
        }
        val summary = when (level) {
            RiskLevel.HIGH -> "High-risk metadata indicators. Review the app and its permissions in Android Settings."
            RiskLevel.MEDIUM -> "Elevated risk. Verify the source and revoke any unneeded permissions."
            RiskLevel.LOW -> "Minor privacy indicators in the available app metadata."
            RiskLevel.TRUSTED -> "No risk indicators matched the available app metadata."
        }

        return AppRiskAudit(
            profile = profile,
            riskLevel = level,
            riskScore = score.coerceAtMost(100),
            findings = findings,
            summary = summary
        )
    }
}
