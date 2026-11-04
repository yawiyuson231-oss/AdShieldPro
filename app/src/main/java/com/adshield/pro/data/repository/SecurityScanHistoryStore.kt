package com.adshield.pro.data.repository

import com.adshield.pro.data.local.db.AdShieldDao
import com.adshield.pro.data.local.db.SecurityScanEntity
import com.adshield.pro.engine.security.ScanKind
import com.adshield.pro.engine.security.SecurityLevel
import com.adshield.pro.engine.security.SecurityScanRecord
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class SecurityScanHistoryStore @Inject constructor(
    private val dao: AdShieldDao
) {
    private val json = Json { ignoreUnknownKeys = true }
    private val findingsSerializer = ListSerializer(String.serializer())

    val history: Flow<List<SecurityScanRecord>> = dao.observeSecurityScans().map { rows ->
        rows.map { row ->
            SecurityScanRecord(
                id = row.id,
                kind = runCatching { ScanKind.valueOf(row.kind) }.getOrDefault(ScanKind.FILE),
                target = row.target,
                threatLevel = runCatching { SecurityLevel.valueOf(row.threatLevel) }.getOrDefault(SecurityLevel.SUSPICIOUS),
                riskScore = row.riskScore,
                threatName = row.threatName,
                findings = runCatching {
                    json.decodeFromString(findingsSerializer, row.findingsJson)
                }.getOrElse { listOf("Stored findings could not be decoded: ${it.message ?: "invalid data"}") },
                recommendation = row.recommendation,
                timestampEpochMs = row.timestampEpochMs,
                sourceUri = row.sourceUri
            )
        }
    }

    suspend fun record(scan: SecurityScanRecord) {
        dao.upsertSecurityScan(
            SecurityScanEntity(
                id = scan.id,
                kind = scan.kind.name,
                target = scan.target,
                sourceUri = scan.sourceUri,
                threatLevel = scan.threatLevel.name,
                riskScore = scan.riskScore,
                threatName = scan.threatName,
                findingsJson = json.encodeToString(findingsSerializer, scan.findings),
                recommendation = scan.recommendation,
                timestampEpochMs = scan.timestampEpochMs
            )
        )
    }

    suspend fun remove(id: Long) = dao.deleteSecurityScan(id)
    suspend fun clear() = dao.clearSecurityScans()
}
