package com.adshield.pro.engine.compliance

import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.os.Build
import android.provider.Settings
import com.adshield.pro.data.local.preferences.AppSettingsState
import com.adshield.pro.domain.model.VpnRuntimeState
import com.adshield.pro.domain.model.VpnStatus
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Reads the real Android signals the compliance evaluator needs. Every read is wrapped so a
 * missing/forbidden signal becomes `null` (UNKNOWN downstream) instead of a crash or a guess.
 * No special permission is required for any of these reads.
 */
@Singleton
class ComplianceSignalCollector @Inject constructor(
    @ApplicationContext private val context: Context
) {

    fun collect(
        vpnState: VpnRuntimeState,
        settings: AppSettingsState,
        threatSignatureCount: Int,
        highRiskAppCount: Int?,
        bundledBaselineAvailable: Boolean
    ): ComplianceChecker.DeviceSecuritySignals {
        val keyguard = context.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as? DevicePolicyManager

        val encrypted: Boolean? = runCatching {
            when (dpm?.storageEncryptionStatus) {
                DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE,
                DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER,
                DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_DEFAULT_KEY -> true
                DevicePolicyManager.ENCRYPTION_STATUS_UNSUPPORTED,
                DevicePolicyManager.ENCRYPTION_STATUS_INACTIVE -> false
                else -> null
            }
        }.getOrNull()

        val adb: Boolean? = runCatching {
            Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED) == 1
        }.getOrNull()

        val devOptions: Boolean? = runCatching {
            Settings.Global.getInt(context.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED) == 1
        }.getOrNull()

        val canInstall: Boolean? = runCatching {
            context.packageManager.canRequestPackageInstalls()
        }.getOrNull()

        return ComplianceChecker.DeviceSecuritySignals(
            deviceLabel = "${Build.MANUFACTURER} ${Build.MODEL}",
            androidRelease = Build.VERSION.RELEASE ?: Build.VERSION.SDK_INT.toString(),
            sdkInt = Build.VERSION.SDK_INT,
            securityPatchLevel = runCatching { Build.VERSION.SECURITY_PATCH }.getOrNull(),
            screenLockEnabled = runCatching { keyguard?.isDeviceSecure }.getOrNull(),
            storageEncrypted = encrypted,
            adbEnabled = adb,
            developerOptionsEnabled = devOptions,
            vpnActive = vpnState.status == VpnStatus.CONNECTED,
            threatSignatureCount = threatSignatureCount,
            autoUpdateFiltersEnabled = settings.autoUpdateFiltersEnabled,
            lastFilterUpdateEpochMs = settings.lastFilterUpdateEpochMs,
            bundledBaselineAvailable = bundledBaselineAvailable,
            scheduledScanEnabled = settings.scheduledScanEnabled,
            detailedDnsLoggingEnabled = settings.detailedDnsLoggingEnabled,
            logRetentionDays = settings.logRetentionDays,
            highRiskAppCount = highRiskAppCount,
            appCanInstallUnknownSources = canInstall
        )
    }
}
