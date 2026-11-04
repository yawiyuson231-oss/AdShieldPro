package com.adshield.pro.engine.security

import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.File
import java.nio.charset.StandardCharsets

/**
 * Persistent on-device store for individual security scans (files, URLs, APKs, apps) and
 * multi-module Complete System Scan reports (`filesDir/security_scan_history.json`).
 */
class SecurityScanHistoryStore(
    private val storeFile: File
) {

    @Serializable
    private data class PersistedScanState(
        val scanRecords: List<SecurityScanRecord> = emptyList(),
        val systemReports: List<SystemScannerEngine.SystemScanReport> = emptyList()
    )

    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }

    private val lock = Any()
    private var state: PersistedScanState = load()

    fun getScanRecords(): List<SecurityScanRecord> = synchronized(lock) { state.scanRecords }

    fun getSystemReports(): List<SystemScannerEngine.SystemScanReport> = synchronized(lock) { state.systemReports }

    fun recordItemScan(record: SecurityScanRecord): List<SecurityScanRecord> = synchronized(lock) {
        val updated = (listOf(record) + state.scanRecords.filterNot { it.id == record.id }).take(MAX_ITEM_RECORDS)
        state = state.copy(scanRecords = updated)
        persistLocked()
        updated
    }

    fun recordSystemScan(report: SystemScannerEngine.SystemScanReport): List<SystemScannerEngine.SystemScanReport> =
        synchronized(lock) {
            val updated = (listOf(report) + state.systemReports.filterNot { it.id == report.id }).take(MAX_SYSTEM_REPORTS)
            state = state.copy(systemReports = updated)
            persistLocked()
            updated
        }

    fun clearAll() = synchronized(lock) {
        state = PersistedScanState()
        persistLocked()
    }

    private fun load(): PersistedScanState {
        if (!storeFile.exists()) return PersistedScanState()
        return runCatching {
            json.decodeFromString<PersistedScanState>(storeFile.readText(StandardCharsets.UTF_8))
        }.getOrDefault(PersistedScanState())
    }

    private fun persistLocked() {
        runCatching {
            storeFile.parentFile?.mkdirs()
            val tmp = File(storeFile.parentFile, "${storeFile.name}.tmp")
            tmp.writeText(json.encodeToString(state), StandardCharsets.UTF_8)
            if (!tmp.renameTo(storeFile)) {
                tmp.copyTo(storeFile, overwrite = true)
                tmp.delete()
            }
        }
    }

    companion object {
        private const val MAX_ITEM_RECORDS = 100
        private const val MAX_SYSTEM_REPORTS = 30
    }
}
