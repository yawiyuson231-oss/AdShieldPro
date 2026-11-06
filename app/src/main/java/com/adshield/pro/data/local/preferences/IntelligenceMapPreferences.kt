package com.adshield.pro.data.local.preferences

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.adshield.pro.domain.intelligence.IntelligenceModule
import com.adshield.pro.domain.intelligence.NodePosition
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

private val Context.intelligenceMapDataStore: DataStore<Preferences> by preferencesDataStore(
    name = "adshield_intelligence_map"
)

/**
 * Node-layout persistence for the live intelligence map.
 *
 * Deliberately a separate DataStore file: dragging a node writes frequently and must never
 * invalidate `AppSettingsState` (which would recompose every screen). Positions are normalised to
 * the [0,1] world square, so the same layout works on a phone, a tablet and in either orientation.
 * Unknown or corrupted entries are ignored rather than crashing the map.
 */
@Singleton
class IntelligenceMapPreferences @Inject constructor(
    @ApplicationContext private val context: Context
) {
    private val json = Json { ignoreUnknownKeys = true }

    private object Keys {
        val NODE_LAYOUT = stringPreferencesKey("node_layout_json")
    }

    val layoutFlow: Flow<Map<IntelligenceModule, NodePosition>> = context.intelligenceMapDataStore.data
        .catch { cause -> if (cause is IOException) emit(emptyPreferences()) else throw cause }
        .map { prefs -> decode(prefs[Keys.NODE_LAYOUT]) }
        .distinctUntilChanged()

    suspend fun saveNode(module: IntelligenceModule, position: NodePosition) {
        val safe = position.clamped()
        context.intelligenceMapDataStore.edit { prefs ->
            val current = decode(prefs[Keys.NODE_LAYOUT]).toMutableMap()
            current[module] = safe
            prefs[Keys.NODE_LAYOUT] = json.encodeToString(
                MapSerializerHolder.serializer,
                current.mapKeys { it.key.id }
            )
        }
    }

    suspend fun resetLayout() {
        context.intelligenceMapDataStore.edit { it.remove(Keys.NODE_LAYOUT) }
    }

    private fun decode(raw: String?): Map<IntelligenceModule, NodePosition> {
        if (raw.isNullOrBlank()) return emptyMap()
        val decoded = runCatching {
            json.decodeFromString(MapSerializerHolder.serializer, raw)
        }.getOrDefault(emptyMap())
        return decoded.mapNotNull { (id, position) ->
            val module = IntelligenceModule.fromIdOrNull(id) ?: return@mapNotNull null
            if (!module.isNode) return@mapNotNull null
            module to position.clamped()
        }.toMap()
    }

    private object MapSerializerHolder {
        val serializer = MapSerializer(String.serializer(), NodePosition.serializer())
    }
}
