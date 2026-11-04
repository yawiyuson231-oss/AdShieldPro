package com.adshield.pro.data.local.preferences

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.adshield.pro.engine.security.QuarantineNaming
import com.adshield.pro.engine.security.QuarantinedItem
import com.adshield.pro.engine.security.ScanJournal
import com.adshield.pro.engine.security.SecurityScanRecord
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

private val Context.scanJournalDataStore: DataStore<Preferences> by preferencesDataStore(
    name = "adshield_scan_journal"
)

/**
 * Persistent scan history and quarantine index.
 *
 * Deliberately a **separate DataStore file** from the settings store: scan results are written
 * frequently, and keeping them out of `AppSettingsState` means a completed scan can never trigger
 * a settings-wide recomposition of every screen.
 *
 * A corrupt or unreadable journal degrades to an empty journal instead of crashing the app.
 */
@Singleton
class ScanJournalStore @Inject constructor(
    @ApplicationContext private val context: Context
) {
    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }

    private object Keys {
        val HISTORY_JSON = stringPreferencesKey("scan_history_json")
        val QUARANTINE_JSON = stringPreferencesKey("quarantine_index_json")
    }

    private fun decodeHistory(prefs: Preferences): List<SecurityScanRecord> =
        prefs[Keys.HISTORY_JSON]?.let { raw ->
            runCatching { json.decodeFromString<List<SecurityScanRecord>>(raw) }.getOrDefault(emptyList())
        } ?: emptyList()

    private fun decodeQuarantine(prefs: Preferences): List<QuarantinedItem> =
        prefs[Keys.QUARANTINE_JSON]?.let { raw ->
            runCatching { json.decodeFromString<List<QuarantinedItem>>(raw) }.getOrDefault(emptyList())
        } ?: emptyList()

    val historyFlow: Flow<List<SecurityScanRecord>> = context.scanJournalDataStore.data
        .catch { cause -> if (cause is IOException) emit(emptyPreferences()) else throw cause }
        .map { decodeHistory(it) }
        .distinctUntilChanged()

    val quarantineFlow: Flow<List<QuarantinedItem>> = context.scanJournalDataStore.data
        .catch { cause -> if (cause is IOException) emit(emptyPreferences()) else throw cause }
        .map { decodeQuarantine(it) }
        .distinctUntilChanged()

    suspend fun historySnapshot(): List<SecurityScanRecord> = historyFlow.first()

    suspend fun quarantineSnapshot(): List<QuarantinedItem> = quarantineFlow.first()

    /**
     * Persists a record and returns the stored copy. The id is assigned inside the DataStore
     * transaction so concurrent scans cannot collide (see [ScanJournal.nextId]).
     */
    suspend fun record(record: SecurityScanRecord): SecurityScanRecord {
        var stored = record
        context.scanJournalDataStore.edit { prefs ->
            val existing = decodeHistory(prefs)
            stored = record.copy(id = ScanJournal.nextId(existing, record.timestampEpochMs))
            prefs[Keys.HISTORY_JSON] = json.encodeToString(ScanJournal.append(existing, stored))
        }
        return stored
    }

    /** Batch persist (scheduled runs). Returns the stored copies, newest first. */
    suspend fun recordAll(records: List<SecurityScanRecord>): List<SecurityScanRecord> {
        if (records.isEmpty()) return emptyList()
        var stored: List<SecurityScanRecord> = emptyList()
        context.scanJournalDataStore.edit { prefs ->
            val existing = decodeHistory(prefs)
            var next = existing
            stored = records.map { record ->
                val withId = record.copy(id = ScanJournal.nextId(next, record.timestampEpochMs))
                next = ScanJournal.append(next, withId)
                withId
            }.reversed()
            prefs[Keys.HISTORY_JSON] = json.encodeToString(next)
        }
        return stored
    }

    suspend fun clearHistory() {
        context.scanJournalDataStore.edit { it.remove(Keys.HISTORY_JSON) }
    }

    suspend fun addQuarantined(item: QuarantinedItem) {
        context.scanJournalDataStore.edit { prefs ->
            val existing = decodeQuarantine(prefs)
            prefs[Keys.QUARANTINE_JSON] = json.encodeToString(QuarantineNaming.append(existing, item))
        }
    }

    suspend fun updateQuarantined(item: QuarantinedItem) {
        context.scanJournalDataStore.edit { prefs ->
            val existing = decodeQuarantine(prefs)
            prefs[Keys.QUARANTINE_JSON] =
                json.encodeToString(existing.map { if (it.id == item.id) item else it })
        }
    }

    suspend fun removeQuarantined(id: Long) {
        context.scanJournalDataStore.edit { prefs ->
            val existing = decodeQuarantine(prefs)
            prefs[Keys.QUARANTINE_JSON] = json.encodeToString(existing.filterNot { it.id == id })
        }
    }
}
