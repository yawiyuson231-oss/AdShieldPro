package com.adshield.pro.vpn

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.serialization.json.Json
import javax.inject.Inject
import javax.inject.Singleton

private val Context.vpnCatalogStore: DataStore<Preferences> by preferencesDataStore(name = "adshield_vpn_catalog")

/**
 * User-owned VPN server catalog. Starts EMPTY on purpose: the app ships no fake servers.
 * Users add real endpoints (their own WireGuard/OpenVPN server, or a provider they pay for —
 * the app itself never requires one) or import a WireGuard .conf, which registers the endpoint.
 */
@Singleton
class VpnServerCatalog @Inject constructor(@ApplicationContext private val context: Context) {

    private val json = Json { ignoreUnknownKeys = true }
    private val store get() = context.vpnCatalogStore

    private object Keys {
        val SERVERS = stringPreferencesKey("servers_json")
        val THREATS = stringPreferencesKey("threat_events_json")
    }

    val serversFlow: Flow<List<VpnServer>> = store.data.map { prefs ->
        prefs[Keys.SERVERS]?.let { raw ->
            runCatching { json.decodeFromString<List<VpnServer>>(raw) }.getOrDefault(emptyList())
        } ?: emptyList()
    }

    val threatsFlow: Flow<List<VpnThreatEvent>> = store.data.map { prefs ->
        prefs[Keys.THREATS]?.let { raw ->
            runCatching { json.decodeFromString<List<VpnThreatEvent>>(raw) }.getOrDefault(emptyList())
        } ?: emptyList()
    }

    suspend fun servers(): List<VpnServer> = serversFlow.first()

    suspend fun addServer(server: VpnServer) {
        store.edit { prefs ->
            val list = serversFlow.first().toMutableList()
            list.removeAll { it.id == server.id }
            list.add(server)
            prefs[Keys.SERVERS] = json.encodeToString(list)
        }
    }

    suspend fun removeServer(id: String) {
        store.edit { prefs ->
            val list = serversFlow.first().filterNot { it.id == id }
            prefs[Keys.SERVERS] = json.encodeToString(list)
        }
    }

    suspend fun updateServer(updated: VpnServer) {
        store.edit { prefs ->
            val list = serversFlow.first().map { if (it.id == updated.id) updated else it }
            prefs[Keys.SERVERS] = json.encodeToString(list)
        }
    }

    suspend fun toggleFavorite(id: String) {
        store.edit { prefs ->
            val list = serversFlow.first().map { if (it.id == id) it.copy(isFavorite = !it.isFavorite) else it }
            prefs[Keys.SERVERS] = json.encodeToString(list)
        }
    }

    suspend fun markUsed(id: String, nowEpochMs: Long) {
        store.edit { prefs ->
            val list = serversFlow.first().map { if (it.id == id) it.copy(lastUsedEpochMs = nowEpochMs) else it }
            prefs[Keys.SERVERS] = json.encodeToString(list)
        }
    }

    suspend fun recordThreat(event: VpnThreatEvent) {
        store.edit { prefs ->
            val list = threatsFlow.first().toMutableList()
            list.add(0, event)
            prefs[Keys.THREATS] = json.encodeToString(list.take(100))
        }
    }

    suspend fun clearThreats() {
        store.edit { prefs -> prefs.remove(Keys.THREATS) }
    }
}
