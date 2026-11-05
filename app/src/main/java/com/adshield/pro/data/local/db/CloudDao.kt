package com.adshield.pro.data.local.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import kotlinx.coroutines.flow.Flow

@Dao
interface CloudDao {

    // --- Cloud file cache ---
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertCloudFiles(files: List<CloudFileEntity>)

    @Query("SELECT * FROM cloud_files WHERE is_deleted = 0 AND folder_path = :folder ORDER BY name ASC")
    fun observeFiles(folder: String): Flow<List<CloudFileEntity>>

    @Query("SELECT * FROM cloud_files WHERE is_deleted = 0 ORDER BY updated_at_epoch_ms DESC")
    fun observeAllFiles(): Flow<List<CloudFileEntity>>

    @Query("SELECT * FROM cloud_files WHERE is_deleted = 0 AND sha256 = :sha256 AND size_bytes = :size LIMIT 1")
    suspend fun findDuplicate(sha256: String, size: Long): CloudFileEntity?

    @Query("SELECT * FROM cloud_files WHERE is_deleted = 1 ORDER BY updated_at_epoch_ms DESC")
    fun observeTrash(): Flow<List<CloudFileEntity>>

    @Query("DELETE FROM cloud_files")
    suspend fun clearCloudFiles()

    // --- Transfer queue ---
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertTransfer(transfer: CloudTransferEntity)

    @Update
    suspend fun updateTransfer(transfer: CloudTransferEntity)

    @Query("SELECT * FROM cloud_transfers ORDER BY updated_at_epoch_ms DESC")
    fun observeTransfers(): Flow<List<CloudTransferEntity>>

    @Query("SELECT * FROM cloud_transfers WHERE state IN ('QUEUED','RUNNING','PAUSED') ORDER BY updated_at_epoch_ms ASC")
    suspend fun pendingTransfers(): List<CloudTransferEntity>

    @Query("DELETE FROM cloud_transfers WHERE state IN ('DONE','CANCELLED')")
    suspend fun pruneFinishedTransfers()

    // --- DNS backup history ---
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertDnsBackup(backup: CloudDnsBackupEntity)

    @Query("SELECT * FROM cloud_dns_backups ORDER BY created_at_epoch_ms DESC")
    fun observeDnsBackups(): Flow<List<CloudDnsBackupEntity>>

    @Query("UPDATE cloud_dns_backups SET restored_at_epoch_ms = :restoredAt WHERE id = :id")
    suspend fun markBackupRestored(id: String, restoredAt: Long)
}
