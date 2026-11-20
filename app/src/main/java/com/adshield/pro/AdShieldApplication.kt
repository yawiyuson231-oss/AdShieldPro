package com.adshield.pro

import android.app.Application
import androidx.hilt.work.HiltWorkerFactory
import androidx.work.Configuration
import com.adshield.pro.data.local.preferences.UserPreferencesRepository
import com.adshield.pro.data.repository.ProviderCredentialStore
import com.adshield.pro.engine.intelligence.IntelligenceMonitor
import com.adshield.pro.update.GitHubUpdateWorker
import com.adshield.pro.worker.FilterUpdateWorker
import com.adshield.pro.worker.IntelligenceRetentionWorker
import com.adshield.pro.worker.ConnectorRetentionWorker
import com.adshield.pro.worker.ConnectorSyncWorker
import com.adshield.pro.worker.SmartOptimizationWorker
import com.adshield.pro.worker.ScheduledScanWorker
import com.adshield.pro.worker.WorldMonitorWatchWorker
import dagger.hilt.android.HiltAndroidApp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltAndroidApp
/**
 * Marks coroutine scopes that live exactly as long as the process, so shutdown-critical
 * writes can be awaited without risking a dependency cycle (the VPN service needs the
 * context to reach the repository, and the repository cannot see the service).
 *
 * Without this marker, `stopSelf()` cancels the service's own scope underneath three
 * DataStore writes that are the only thing preventing protection from silently coming
 * back after the next reboot.
 */
interface ProcessScopeOwner {
    /** A scope tied to the application, not to any component's lifetime. */
    val appScope: CoroutineScope
}

class AdShieldApplication : Application(), Configuration.Provider, ProcessScopeOwner {

    @Inject lateinit var workerFactory: HiltWorkerFactory
    @Inject lateinit var preferencesRepository: UserPreferencesRepository
    @Inject lateinit var intelligenceMonitor: IntelligenceMonitor
    @Inject lateinit var credentialStore: ProviderCredentialStore

    override val appScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override val workManagerConfiguration: Configuration
        get() = Configuration.Builder()
            .setWorkerFactory(workerFactory)
            .setMinimumLoggingLevel(android.util.Log.INFO)
            .build()

    override fun onCreate() {
        super.onCreate()
        // Process-lifetime observation of real telemetry and settings transitions. This does not
        // request background execution: it stops with the process, while DNS protection continues
        // to run in the foreground VPN service regardless of whether the map is open.
        intelligenceMonitor.start()
        IntelligenceRetentionWorker.schedule(this)
        ConnectorSyncWorker.schedule(this)
        ConnectorRetentionWorker.schedule(this)
        WorldMonitorWatchWorker.schedule(this)
        GitHubUpdateWorker.schedule(this)
        appScope.launch {
            // Optional signed-data staging is disabled unless explicitly consented and configured.
            com.adshield.pro.engine.evolution.EvolutionUpdateWorker.reconcile(this@AdShieldApplication)
            credentialStore.removeRetiredAgentCredential()
            val settings = preferencesRepository.getSettingsSnapshot()
            // Reconcile opted-in security scans even when a worker/receiver starts the process
            // without creating the dashboard ViewModel. WorkManager owns persistent execution.
            ScheduledScanWorker.scheduleOrCancel(
                this@AdShieldApplication, settings.scheduledScanEnabled, settings.scheduledScanIntervalHours
            )
            FilterUpdateWorker.scheduleOrCancelPeriodicUpdates(
                context = this@AdShieldApplication,
                enabled = settings.autoUpdateFiltersEnabled,
                intervalHours = settings.updateIntervalHours
            )
            SmartOptimizationWorker.scheduleOrCancelSmartMaintenance(
                context = this@AdShieldApplication,
                enabled = settings.smartAutoOptimizeEnabled,
                intervalHours = settings.autoJunkCleanIntervalHours
            )
        }
    }
}
