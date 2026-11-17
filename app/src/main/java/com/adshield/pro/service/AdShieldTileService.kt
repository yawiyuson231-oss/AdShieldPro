package com.adshield.pro.service

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.graphics.drawable.Icon
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.core.content.ContextCompat
import com.adshield.pro.MainActivity
import com.adshield.pro.R
import com.adshield.pro.data.local.preferences.UserPreferencesRepository
import com.adshield.pro.data.repository.AdShieldRepository
import com.adshield.pro.domain.model.TileVisualState
import com.adshield.pro.domain.model.VpnStatus
import com.adshield.pro.engine.platform.ProtectionSnoozeController
import com.adshield.pro.engine.platform.ProtectionSnoozeEngine
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.inject.Inject

/**
 * One-tap Android Quick Settings tile for toggling AdShield Pro's local DNS-filtering VPN (or
 * resuming early from a timed pause). Requires zero ADB or root setup — only standard Android VPN
 * consent on the very first activation.
 */
@AndroidEntryPoint
class AdShieldTileService : TileService() {

    @Inject lateinit var repository: AdShieldRepository
    @Inject lateinit var preferencesRepository: UserPreferencesRepository
    @Inject lateinit var snoozeController: ProtectionSnoozeController

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override fun onTileAdded() {
        super.onTileAdded()
        refreshTile()
    }

    override fun onStartListening() {
        super.onStartListening()
        refreshTile()
    }

    override fun onClick() {
        super.onClick()
        if (runCatching { VpnService.prepare(this) }.getOrNull() != null) {
            openConsentFlow()
            return
        }
        serviceScope.launch {
            val now = System.currentTimeMillis()
            val runtime = repository.vpnRuntimeState.value
            val settings = preferencesRepository.getSettingsSnapshot()
            val isSnoozed = ProtectionSnoozeEngine.isSnoozeActive(settings.vpnSnoozeUntilEpochMs, now)

            when {
                runtime.status == VpnStatus.PAUSED || (isSnoozed && settings.vpnShouldRemainActive) -> {
                    val resumed = snoozeController.resumeNow()
                    if (!resumed) {
                        withContext(Dispatchers.Main) { openConsentFlow() }
                        return@launch
                    }
                }
                runtime.status == VpnStatus.CONNECTED || runtime.status == VpnStatus.STARTING ||
                    runtime.status == VpnStatus.RECONNECTING -> {
                    snoozeController.clearSnooze()
                    preferencesRepository.setVpnShouldRemainActive(false)
                    runCatching {
                        startService(
                            Intent(this@AdShieldTileService, AdShieldVpnService::class.java).apply {
                                action = AdShieldVpnService.ACTION_STOP_VPN
                            }
                        )
                    }
                }
                else -> {
                    snoozeController.clearSnooze()
                    preferencesRepository.setVpnShouldRemainActive(true)
                    val started = runCatching {
                        ContextCompat.startForegroundService(
                            this@AdShieldTileService,
                            Intent(this@AdShieldTileService, AdShieldVpnService::class.java).apply {
                                action = AdShieldVpnService.ACTION_START_VPN
                            }
                        )
                    }.isSuccess
                    if (!started) {
                        withContext(Dispatchers.Main) { openConsentFlow() }
                        return@launch
                    }
                }
            }
            refreshTileNow()
            delay(400L)
            refreshTileNow()
            AdShieldWidgetProvider.refreshAll(applicationContext)
        }
    }

    private fun refreshTile() {
        serviceScope.launch {
            val settings = preferencesRepository.getSettingsSnapshot()
            if (ProtectionSnoozeEngine.isSnoozeDue(
                    settings.vpnSnoozeUntilEpochMs,
                    settings.vpnShouldRemainActive,
                    System.currentTimeMillis()
                )
            ) {
                snoozeController.executeDueSnoozeResume()
            }
            refreshTileNow()
        }
    }

    private suspend fun refreshTileNow() {
        val runtime = repository.vpnRuntimeState.value
        val settings = preferencesRepository.getSettingsSnapshot()
        val hasConsent = runCatching { VpnService.prepare(this@AdShieldTileService) == null }
            .getOrDefault(false)
        val presentation = ProtectionSnoozeEngine.presentShieldTile(
            vpnStatus = runtime.status,
            vpnShouldRemainActive = settings.vpnShouldRemainActive,
            snoozeUntilEpochMs = settings.vpnSnoozeUntilEpochMs,
            sessionBlockedQueries = runtime.sessionBlockedQueries,
            hasVpnConsent = hasConsent,
            nowEpochMs = System.currentTimeMillis()
        )
        withContext(Dispatchers.Main) {
            val tile = qsTile ?: return@withContext
            tile.label = presentation.label
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                tile.subtitle = presentation.subtitle
            }
            tile.contentDescription = presentation.contentDescription
            tile.icon = Icon.createWithResource(this@AdShieldTileService, R.drawable.ic_tile_adshield)
            tile.state = when (presentation.state) {
                TileVisualState.ACTIVE -> Tile.STATE_ACTIVE
                TileVisualState.INACTIVE -> Tile.STATE_INACTIVE
                TileVisualState.UNAVAILABLE -> Tile.STATE_UNAVAILABLE
            }
            tile.updateTile()
        }
    }

    @SuppressLint("StartActivityAndCollapseDeprecated")
    @Suppress("DEPRECATION")
    private fun openConsentFlow() {
        val intent = Intent(this, MainActivity::class.java).apply {
            action = ProtectionSnoozeController.ACTION_START_VPN_WITH_CONSENT
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            val pendingIntent = PendingIntent.getActivity(
                this,
                REQUEST_CODE_CONSENT,
                intent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            startActivityAndCollapse(pendingIntent)
        } else {
            startActivityAndCollapse(intent)
        }
    }

    override fun onDestroy() {
        serviceScope.cancel()
        super.onDestroy()
    }

    companion object {
        private const val REQUEST_CODE_CONSENT = 7209

        fun requestSync(context: Context) {
            val app = context.applicationContext
            requestListeningState(app, ComponentName(app, AdShieldTileService::class.java))
        }
    }
}
