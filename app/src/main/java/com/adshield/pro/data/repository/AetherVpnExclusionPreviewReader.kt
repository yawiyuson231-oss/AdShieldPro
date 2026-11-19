package com.adshield.pro.data.repository

import android.content.Context
import com.adshield.pro.engine.aether.AetherVpnExclusionPreview
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import javax.inject.Inject

/** Reads only from committed settings, the local setup receipt, and package labels. */
class AetherVpnExclusionPreviewReader @Inject constructor(
    @ApplicationContext private val context: Context,
    private val repository: AdShieldRepository
) {
    internal data class Target(val packageName: String, val appLabel: String?)

    internal suspend fun targets(): List<Target> = withContext(Dispatchers.IO) {
        val saved = repository.settingsFlow.first().excludedAppPackages
        val pm = context.packageManager
        AetherVpnExclusionPreview.targets(saved, context.packageName).map { packageName ->
            ensureActive()
            // Only look up names for saved exclusions. Missing packages are still saved settings.
            val label = runCatching {
                pm.getApplicationLabel(pm.getApplicationInfo(packageName, 0)).toString()
            }.getOrNull()?.filterNot { it.isISOControl() || Character.getType(it) == Character.FORMAT.toInt() }
                ?.trim()?.take(96)?.takeIf { it.isNotEmpty() && it != packageName }
            Target(packageName, label)
        }
    }

    internal suspend fun preview(selectedPackage: String): AetherVpnExclusionPreview.Report? = withContext(Dispatchers.IO) {
        // Re-read after the tap: the chooser or an earlier review can be out of date.
        val saved = repository.settingsFlow.first()
        val runtime = repository.vpnRuntimeState.value
        AetherVpnExclusionPreview.compare(
            selectedPackage, context.packageName, saved.excludedAppPackages, saved.dnsFirewallPolicy,
            runtime, System.currentTimeMillis()
        )
    }
}
