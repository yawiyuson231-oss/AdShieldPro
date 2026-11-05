package com.adshield.pro.data.cloud

import android.content.ContentResolver
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import com.adshield.pro.data.local.preferences.UserPreferencesRepository
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Saves and reads configuration backups from a user-selected Storage Access Framework tree.
 *
 * This class deliberately has no provider-specific OAuth or server credentials. The user chooses
 * a folder from Android's system picker; it can belong to an installed cloud document provider
 * (such as Drive, OneDrive, Dropbox or WebDAV) or ordinary device storage. The selected provider
 * is responsible for remote synchronisation. We only ever read and write files in the folder the
 * user granted.
 */
@Singleton
class CloudBackupManager @Inject constructor(
    @ApplicationContext private val context: Context,
    private val preferences: UserPreferencesRepository
) {

    data class StoredBackup(
        val displayName: String,
        val uri: Uri,
        val lastModifiedEpochMs: Long,
        val sizeBytes: Long
    )

    suspend fun connect(treeUri: Uri): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            val previousTreeUri = preferences.getSettingsSnapshot().cloudBackupTreeUri
            val grantedFlags = Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
            // OpenDocumentTree supplies a persistable grant. Do this before saving the URI so a
            // selection that cannot survive a reboot never looks selected in the UI.
            context.contentResolver.takePersistableUriPermission(treeUri, grantedFlags)
            preferences.setCloudBackupDestination(treeUri.toString())
            if (previousTreeUri != null && previousTreeUri != treeUri.toString()) {
                releaseFolderPermission(Uri.parse(previousTreeUri))
            }
        }.mapError("Couldn't keep access to that folder. Select a writable folder and try again.")
    }

    suspend fun disconnect() = withContext(Dispatchers.IO) {
        val treeUri = preferences.getSettingsSnapshot().cloudBackupTreeUri
        preferences.clearCloudBackupDestination()
        if (treeUri != null) releaseFolderPermission(Uri.parse(treeUri))
    }

    private fun releaseFolderPermission(treeUri: Uri) {
        val grantedFlags = Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
        runCatching { context.contentResolver.releasePersistableUriPermission(treeUri, grantedFlags) }
    }

    /**
     * Writes a new versioned file, then prunes only old AdShield configuration backups. Versioned
     * writes avoid overwriting the only usable backup if a document provider fails mid-write.
     */
    suspend fun saveConfiguration(json: String): Result<StoredBackup> = withContext(Dispatchers.IO) {
        runCatching {
            require(json.isNotBlank()) { "The configuration backup was empty." }
            require(json.length <= MAX_BACKUP_CHARACTERS) { "The configuration backup is unexpectedly large." }

            val treeUri = connectedTreeUri()
            val resolver = context.contentResolver
            val parent = rootDocumentUri(treeUri)
            val timestamp = System.currentTimeMillis()
            val displayName = CloudBackupFormat.fileName(timestamp)
            val documentUri = DocumentsContract.createDocument(
                resolver,
                parent,
                MIME_TYPE_JSON,
                displayName
            ) ?: throw IOException("The selected provider did not create a backup file.")

            try {
                resolver.openOutputStream(documentUri, "wt")?.bufferedWriter(Charsets.UTF_8)?.use { writer ->
                    writer.write(json)
                } ?: throw IOException("The selected provider did not open the backup file for writing.")
            } catch (error: Throwable) {
                // Best effort: do not leave a misleading partial backup behind.
                runCatching { DocumentsContract.deleteDocument(resolver, documentUri) }
                throw error
            }

            val stored = StoredBackup(
                displayName = displayName,
                uri = documentUri,
                lastModifiedEpochMs = timestamp,
                sizeBytes = json.toByteArray(Charsets.UTF_8).size.toLong()
            )
            preferences.recordCloudBackupSuccess(timestamp)
            // Retention is best-effort. A provider can refuse deletions while the new backup is
            // still valid, so a cleanup problem must not be reported as a failed backup.
            runCatching { pruneOldBackups(treeUri, keep = MAX_BACKUPS) }
            stored
        }.mapError("Cloud backup failed. Check the selected folder is still available and writable.")
    }

    /** Reads the newest valid AdShield configuration backup from the selected tree. */
    suspend fun readLatestConfiguration(): Result<String> = withContext(Dispatchers.IO) {
        runCatching {
            val treeUri = connectedTreeUri()
            val backup = listBackups(treeUri).maxWithOrNull(
                compareBy<StoredBackup> { it.lastModifiedEpochMs }.thenBy { it.displayName }
            ) ?: throw IOException("No AdShield configuration backup was found in the selected folder.")
            require(backup.sizeBytes <= MAX_BACKUP_BYTES) {
                "The newest configuration backup has an unsupported size."
            }
            // Some document providers report an unknown size as zero; bounded streaming below
            // remains the authority and still rejects an empty file.
            readUtf8Bounded(context.contentResolver, backup.uri, MAX_BACKUP_CHARACTERS)
        }.mapError("Cloud restore failed. Check the selected folder and backup file, then try again.")
    }

    private suspend fun connectedTreeUri(): Uri {
        val raw = preferences.getSettingsSnapshot().cloudBackupTreeUri
            ?: throw IllegalStateException("Choose a cloud backup folder first.")
        return Uri.parse(raw)
    }

    private fun rootDocumentUri(treeUri: Uri): Uri = DocumentsContract.buildDocumentUriUsingTree(
        treeUri,
        DocumentsContract.getTreeDocumentId(treeUri)
    )

    private fun listBackups(treeUri: Uri): List<StoredBackup> {
        val resolver = context.contentResolver
        val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(
            treeUri,
            DocumentsContract.getTreeDocumentId(treeUri)
        )
        val projection = arrayOf(
            DocumentsContract.Document.COLUMN_DOCUMENT_ID,
            DocumentsContract.Document.COLUMN_DISPLAY_NAME,
            DocumentsContract.Document.COLUMN_MIME_TYPE,
            DocumentsContract.Document.COLUMN_LAST_MODIFIED,
            OpenableColumns.SIZE
        )
        val cursor = resolver.query(childrenUri, projection, null, null, null)
            ?: throw IOException("The selected provider did not return its folder contents.")
        cursor.use {
            val documentIdIndex = it.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_DOCUMENT_ID)
            val displayNameIndex = it.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_DISPLAY_NAME)
            val mimeTypeIndex = it.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_MIME_TYPE)
            val lastModifiedIndex = it.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_LAST_MODIFIED)
            val sizeIndex = it.getColumnIndexOrThrow(OpenableColumns.SIZE)
            return buildList {
                while (it.moveToNext()) {
                    val displayName = it.getString(displayNameIndex) ?: continue
                    val mimeType = it.getString(mimeTypeIndex)
                    if (mimeType == DocumentsContract.Document.MIME_TYPE_DIR ||
                        !CloudBackupFormat.isBackupFileName(displayName)
                    ) {
                        continue
                    }
                    val documentId = it.getString(documentIdIndex) ?: continue
                    add(
                        StoredBackup(
                            displayName = displayName,
                            uri = DocumentsContract.buildDocumentUriUsingTree(treeUri, documentId),
                            lastModifiedEpochMs = it.getLongOrZero(lastModifiedIndex),
                            sizeBytes = it.getLongOrZero(sizeIndex)
                        )
                    )
                }
            }
        }
    }

    private fun pruneOldBackups(treeUri: Uri, keep: Int) {
        val resolver = context.contentResolver
        listBackups(treeUri)
            .sortedWith(compareByDescending<StoredBackup> { it.lastModifiedEpochMs }.thenByDescending { it.displayName })
            .drop(keep)
            .forEach { oldBackup -> runCatching { DocumentsContract.deleteDocument(resolver, oldBackup.uri) } }
    }

    private fun android.database.Cursor.getLongOrZero(index: Int): Long =
        if (isNull(index)) 0L else getLong(index).coerceAtLeast(0L)

    private fun readUtf8Bounded(resolver: ContentResolver, uri: Uri, maxCharacters: Int): String {
        val input = resolver.openInputStream(uri)
            ?: throw IOException("The selected provider did not open the backup for reading.")
        input.bufferedReader(Charsets.UTF_8).use { reader ->
            val content = StringBuilder()
            val buffer = CharArray(8 * 1024)
            while (true) {
                val count = reader.read(buffer)
                if (count < 0) break
                if (content.length + count > maxCharacters) {
                    throw IOException("The configuration backup is larger than the safe limit.")
                }
                content.append(buffer, 0, count)
            }
            require(content.isNotBlank()) { "The configuration backup is empty." }
            return content.toString()
        }
    }

    private fun <T> Result<T>.mapError(publicMessage: String): Result<T> = fold(
        onSuccess = { Result.success(it) },
        onFailure = { Result.failure(IllegalStateException(publicMessage)) }
    )

    private companion object {
        const val MIME_TYPE_JSON = "application/json"
        const val MAX_BACKUPS = 5
        const val MAX_BACKUP_CHARACTERS = 1_000_000
        const val MAX_BACKUP_BYTES = 1_500_000L
    }
}

/** File names are intentionally narrow so this feature never touches user files in the folder. */
object CloudBackupFormat {
    private const val PREFIX = "adshield-pro-backup-"
    private const val SUFFIX = ".json"
    private val backupName = Regex("^${Regex.escape(PREFIX)}\\d{13}${Regex.escape(SUFFIX)}$")

    fun fileName(epochMillis: Long): String {
        require(epochMillis >= 0) { "Backup time must be positive." }
        return "$PREFIX${epochMillis.toString().padStart(13, '0')}$SUFFIX"
    }

    fun isBackupFileName(displayName: String): Boolean = backupName.matches(displayName)
}
