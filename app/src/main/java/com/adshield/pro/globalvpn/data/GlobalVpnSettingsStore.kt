package com.adshield.pro.globalvpn.data

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.adshield.pro.globalvpn.model.ConnectionHistoryEntry
import com.adshield.pro.globalvpn.model.GlobalVpnSettings
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import javax.inject.Inject
import javax.inject.Singleton

private val Context.globalVpnDataStore: DataStore<Preferences> by preferencesDataStore(
    name = "global_vpn_settings"
)

/**
 * Settings + connection history for the Global VPN feature only. Uses its own DataStore file so
 * it never reads or writes the existing DNS system's `adshield_pro_preferences`.
 */
@Singleton
class GlobalVpnSettingsStore @Inject constructor(
    @ApplicationContext private val context: Context
) {
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
    private val settingsKey = stringPreferencesKey("global_vpn_settings_json")
    private val historyKey = stringPreferencesKey("global_vpn_history_json")

    val settings: Flow<GlobalVpnSettings> = context.globalVpnDataStore.data.map { prefs ->
        prefs[settingsKey]?.let {
            runCatching { json.decodeFromString<GlobalVpnSettings>(it) }.getOrNull()
        } ?: GlobalVpnSettings()
    }

    val history: Flow<List<ConnectionHistoryEntry>> = context.globalVpnDataStore.data.map { prefs ->
        prefs[historyKey]?.let {
            runCatching { json.decodeFromString<List<ConnectionHistoryEntry>>(it) }.getOrNull()
        } ?: emptyList()
    }

    suspend fun current(): GlobalVpnSettings = settings.first()

    suspend fun update(transform: (GlobalVpnSettings) -> GlobalVpnSettings) {
        context.globalVpnDataStore.edit { prefs ->
            val existing = prefs[settingsKey]?.let {
                runCatching { json.decodeFromString<GlobalVpnSettings>(it) }.getOrNull()
            } ?: GlobalVpnSettings()
            prefs[settingsKey] = json.encodeToString(transform(existing))
        }
    }

    suspend fun recordSession(entry: ConnectionHistoryEntry) {
        context.globalVpnDataStore.edit { prefs ->
            val existing = prefs[historyKey]?.let {
                runCatching { json.decodeFromString<List<ConnectionHistoryEntry>>(it) }.getOrNull()
            } ?: emptyList()
            val updated = (listOf(entry) + existing).take(MAX_HISTORY)
            prefs[historyKey] = json.encodeToString(updated)
        }
    }

    suspend fun closeSession(id: String, endedAtEpochMs: Long, rxBytes: Long, txBytes: Long, outcome: String) {
        context.globalVpnDataStore.edit { prefs ->
            val existing = prefs[historyKey]?.let {
                runCatching { json.decodeFromString<List<ConnectionHistoryEntry>>(it) }.getOrNull()
            } ?: emptyList()
            val updated = existing.map {
                if (it.id == id) it.copy(
                    endedAtEpochMs = endedAtEpochMs,
                    rxBytes = rxBytes,
                    txBytes = txBytes,
                    outcome = outcome
                ) else it
            }
            prefs[historyKey] = json.encodeToString(updated)
        }
    }

    suspend fun clearHistory() {
        context.globalVpnDataStore.edit { it.remove(historyKey) }
    }

    companion object {
        const val MAX_HISTORY = 200
    }
}
