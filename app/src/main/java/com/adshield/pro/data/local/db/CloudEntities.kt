package com.adshield.pro.data.local.db

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * Local cache of the user's cloud file metadata. The server (D1) is the source of truth; this
 * table only makes the UI work while offline and tracks sync state.
 */
@Entity(
    tableName = "cloud_files",
    indices = [Index(value = ["folder_path"]), Index(value = ["sha256"])]
)
data class CloudFileEntity(
    @PrimaryKey
    @ColumnInfo(name = "id")
    val id: String,
    @ColumnInfo(name = "name")
    val name: String,
    @ColumnInfo(name = "folder_path")
    val folderPath: String,
    @ColumnInfo(name = "size_bytes")
    val sizeBytes: Long,
    @ColumnInfo(name = "mime_type")
    val mimeType: String,
    @ColumnInfo(name = "sha256")
    val sha256: String,
    @ColumnInfo(name = "is_deleted")
    val isDeleted: Boolean,
    @ColumnInfo(name = "version")
    val version: Int,
    @ColumnInfo(name = "updated_at_epoch_ms")
    val updatedAtEpochMs: Long
)

/** Upload/download transfer queue. Drives the Upload Manager UI and resumable transfers. */
@Entity(
    tableName = "cloud_transfers",
    indices = [Index(value = ["state"])]
)
data class CloudTransferEntity(
    @PrimaryKey
    @ColumnInfo(name = "id")
    val id: String,
    @ColumnInfo(name = "direction")
    val direction: String, // "UPLOAD" or "DOWNLOAD"
    @ColumnInfo(name = "file_id")
    val fileId: String?,
    @ColumnInfo(name = "display_name")
    val displayName: String,
    @ColumnInfo(name = "source_uri")
    val sourceUri: String,
    @ColumnInfo(name = "dest_uri")
    val destUri: String,
    @ColumnInfo(name = "total_bytes")
    val totalBytes: Long,
    @ColumnInfo(name = "done_bytes")
    val doneBytes: Long,
    @ColumnInfo(name = "state")
    val state: String, // QUEUED, RUNNING, PAUSED, DONE, FAILED, CANCELLED
    @ColumnInfo(name = "sha256")
    val sha256: String,
    @ColumnInfo(name = "error_message")
    val errorMessage: String = "",
    @ColumnInfo(name = "updated_at_epoch_ms")
    val updatedAtEpochMs: Long
)

/** History of DNS configuration cloud backups (integrity hash verified on restore). */
@Entity(tableName = "cloud_dns_backups")
data class CloudDnsBackupEntity(
    @PrimaryKey
    @ColumnInfo(name = "id")
    val id: String,
    @ColumnInfo(name = "label")
    val label: String,
    @ColumnInfo(name = "cloud_file_id")
    val cloudFileId: String,
    @ColumnInfo(name = "sha256")
    val sha256: String,
    @ColumnInfo(name = "created_at_epoch_ms")
    val createdAtEpochMs: Long,
    @ColumnInfo(name = "restored_at_epoch_ms")
    val restoredAtEpochMs: Long? = null
)
