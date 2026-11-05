package com.adshield.pro.cloud.data

import androidx.room.Dao
import androidx.room.Database
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.RoomDatabase

/**
 * Local cache + transfer queue for the cloud module.
 *
 * Kept in its own database (separate from [com.adshield.pro.data.local.db.AdShieldDatabase]) so
 * the DNS engine's schema and migrations are never touched by cloud work. Version 1 ships with
 * an explicit migration policy: every future version adds a `Migration` and a schema export
 * under app/schemas; destructive fallback is only allowed for downgrades.
 */
@Entity(tableName = "cloud_files")
data class CloudFileEntity(
    @PrimaryKey val id: String,
    val parentId: String?,
    val name: String,
    val kind: String,
    val mime: String?,
    val size: Long,
    val sha256: String?,
    val version: Int,
    val status: String,
    val scanStatus: String,
    val scanDetail: String?,
    val encrypted: Boolean,
    val updatedAt: Long,
    val cachedAt: Long
)

@Entity(tableName = "cloud_transfers")
data class CloudTransferEntity(
    @PrimaryKey val id: String,
    val direction: String,           // upload | download
    val fileName: String,
    val mime: String,
    val size: Long,
    val bytesDone: Long,
    val status: String,              // queued | running | paused | failed | completed | cancelled
    val error: String?,
    val uploadId: String?,
    val nodeId: String?,
    val localUri: String?,
    val localPath: String?,
    val sha256: String?,
    val partSize: Long,
    val partsTotal: Int,
    val purpose: String,             // file | version | backup
    val backupKind: String?,
    val backupLabel: String?,
    val parentId: String?,
    val encrypted: Boolean,
    val createdAt: Long,
    val updatedAt: Long
) {
    val progress: Float get() = if (size <= 0) 0f else (bytesDone.toFloat() / size.toFloat()).coerceIn(0f, 1f)
}

@Entity(tableName = "cloud_backups")
data class CloudBackupEntity(
    @PrimaryKey val id: String,
    val kind: String,
    val label: String,
    val size: Long,
    val sha256: String,
    val encrypted: Boolean,
    val integrityOk: Boolean,
    val createdAt: Long,
    val verifiedAt: Long?,
    val restoredAt: Long?,
    val syncedAt: Long
)

@Entity(tableName = "cloud_shares")
data class CloudShareEntity(
    @PrimaryKey val id: String,
    val nodeId: String,
    val fileName: String,
    val expiresAt: Long,
    val maxDownloads: Int,
    val downloadCount: Int,
    val passwordProtected: Boolean,
    val allowPreview: Boolean,
    val revoked: Boolean,
    val createdAt: Long,
    val cachedAt: Long
)

@Entity(tableName = "cloud_audit")
data class CloudAuditEntity(
    @PrimaryKey val id: String,
    val action: String,
    val success: Boolean,
    val detail: String?,
    val createdAt: Long,
    val cachedAt: Long
)

@Dao
interface CloudDao {

    // ---- file cache
    @Query("SELECT * FROM cloud_files WHERE parentId IS :parentId ORDER BY kind ASC, name COLLATE NOCASE ASC")
    suspend fun filesInFolder(parentId: String?): List<CloudFileEntity>

    @Query("SELECT * FROM cloud_files ORDER BY updatedAt DESC LIMIT :limit")
    suspend fun recentFiles(limit: Int): List<CloudFileEntity>

    @Query("SELECT * FROM cloud_files WHERE id = :id")
    suspend fun file(id: String): CloudFileEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertFiles(files: List<CloudFileEntity>)

    @Query("DELETE FROM cloud_files WHERE parentId IS :parentId")
    suspend fun clearFolder(parentId: String?)

    @Query("DELETE FROM cloud_files")
    suspend fun clearFiles()

    // ---- transfers
    @Query("SELECT * FROM cloud_transfers ORDER BY createdAt DESC")
    suspend fun allTransfers(): List<CloudTransferEntity>

    @Query("SELECT * FROM cloud_transfers WHERE status IN ('queued','running') ORDER BY createdAt ASC")
    suspend fun activeTransfers(): List<CloudTransferEntity>

    @Query("SELECT * FROM cloud_transfers WHERE id = :id")
    suspend fun transfer(id: String): CloudTransferEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertTransfer(transfer: CloudTransferEntity)

    @Query(
        "UPDATE cloud_transfers SET bytesDone = :bytesDone, status = :status, error = :error, updatedAt = :updatedAt WHERE id = :id"
    )
    suspend fun updateTransferProgress(id: String, bytesDone: Long, status: String, error: String?, updatedAt: Long)

    @Query("UPDATE cloud_transfers SET status = :status, error = :error, updatedAt = :updatedAt WHERE id = :id")
    suspend fun updateTransferStatus(id: String, status: String, error: String?, updatedAt: Long)

    @Query("UPDATE cloud_transfers SET uploadId = :uploadId, partsTotal = :partsTotal, partSize = :partSize, updatedAt = :updatedAt WHERE id = :id")
    suspend fun saveUploadSession(id: String, uploadId: String, partsTotal: Int, partSize: Long, updatedAt: Long)

    @Query("UPDATE cloud_transfers SET localPath = :path, status = 'completed', bytesDone = size, updatedAt = :updatedAt WHERE id = :id")
    suspend fun saveDownloadedPath(id: String, path: String, updatedAt: Long)

    @Query("UPDATE cloud_transfers SET nodeId = :nodeId, sha256 = :sha256, status = 'completed', bytesDone = size, updatedAt = :updatedAt WHERE id = :id")
    suspend fun markCompleted(id: String, nodeId: String?, sha256: String?, updatedAt: Long)

    @Query("DELETE FROM cloud_transfers WHERE status IN ('completed','cancelled') AND updatedAt < :olderThanMs")
    suspend fun pruneFinishedTransfers(olderThanMs: Long)

    @Query("DELETE FROM cloud_transfers WHERE id = :id")
    suspend fun deleteTransfer(id: String)

    // ---- backups
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertBackups(backups: List<CloudBackupEntity>)

    @Query("SELECT * FROM cloud_backups ORDER BY createdAt DESC")
    suspend fun allBackups(): List<CloudBackupEntity>

    @Query("SELECT * FROM cloud_backups WHERE id = :id")
    suspend fun backup(id: String): CloudBackupEntity?

    @Query("UPDATE cloud_backups SET integrityOk = :ok, verifiedAt = :verifiedAt WHERE id = :id")
    suspend fun markBackupVerified(id: String, ok: Boolean, verifiedAt: Long)

    @Query("UPDATE cloud_backups SET restoredAt = :restoredAt WHERE id = :id")
    suspend fun markBackupRestored(id: String, restoredAt: Long)

    @Query("DELETE FROM cloud_backups WHERE id = :id")
    suspend fun deleteBackup(id: String)

    // ---- shares
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertShares(shares: List<CloudShareEntity>)

    @Query("SELECT * FROM cloud_shares ORDER BY createdAt DESC")
    suspend fun allShares(): List<CloudShareEntity>

    @Query("UPDATE cloud_shares SET revoked = 1 WHERE id = :id")
    suspend fun markShareRevoked(id: String)

    @Query("DELETE FROM cloud_shares WHERE id = :id")
    suspend fun deleteShare(id: String)

    // ---- audit
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertAudit(entries: List<CloudAuditEntity>)

    @Query("SELECT * FROM cloud_audit ORDER BY createdAt DESC LIMIT :limit")
    suspend fun recentAudit(limit: Int): List<CloudAuditEntity>

    @Query("DELETE FROM cloud_audit WHERE createdAt < :olderThanMs")
    suspend fun pruneAudit(olderThanMs: Long)
}

@Database(
    entities = [
        CloudFileEntity::class,
        CloudTransferEntity::class,
        CloudBackupEntity::class,
        CloudShareEntity::class,
        CloudAuditEntity::class
    ],
    version = 1,
    exportSchema = true
)
abstract class CloudDatabase : RoomDatabase() {
    abstract fun cloudDao(): CloudDao

    companion object {
        const val DATABASE_NAME = "adshield_cloud_v1.db"
    }
}
