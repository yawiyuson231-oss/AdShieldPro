package com.adshield.pro.data.repository

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import com.adshield.pro.domain.model.DuplicateFileGroup
import com.adshield.pro.domain.model.FileScanProgress
import com.adshield.pro.domain.model.ManagedFile
import com.adshield.pro.domain.model.ManagedFileListing
import com.adshield.pro.engine.security.SecurityEngine
import com.adshield.pro.engine.security.SecurityScanRecord
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.MessageDigest
import javax.inject.Inject
import javax.inject.Singleton

data class SafScanBatchResult(
    val records: List<SecurityScanRecord>,
    val skipped: Int,
    val errors: Int
)

@Singleton
class SafFileRepository @Inject constructor(
    @ApplicationContext private val context: Context,
    private val securityEngine: SecurityEngine,
    private val scanHistory: SecurityScanHistoryStore
) {
    private val resolver = context.contentResolver

    suspend fun list(tree: Uri, documentId: String? = null): ManagedFileListing = withContext(Dispatchers.IO) {
        val id = documentId ?: DocumentsContract.getTreeDocumentId(tree)
        val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(tree, id)
        val files = ArrayList<ManagedFile>()
        resolver.query(childrenUri, PROJECTION, null, null, null)?.use { cursor ->
            val idColumn = cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_DOCUMENT_ID)
            val nameColumn = cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_DISPLAY_NAME)
            val mimeColumn = cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_MIME_TYPE)
            val sizeColumn = cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_SIZE)
            val modifiedColumn = cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_LAST_MODIFIED)
            var count = 0
            while (cursor.moveToNext() && count < MAX_LISTING_ENTRIES) {
                count++
                val childId = cursor.getString(idColumn)
                val mime = cursor.getString(mimeColumn) ?: "application/octet-stream"
                val childUri = DocumentsContract.buildDocumentUriUsingTree(tree, childId)
                files += ManagedFile(
                    uri = childUri.toString(),
                    documentId = childId,
                    name = cursor.getString(nameColumn) ?: "Unnamed",
                    mimeType = mime,
                    sizeBytes = if (cursor.isNull(sizeColumn)) 0L else cursor.getLong(sizeColumn).coerceAtLeast(0L),
                    lastModifiedEpochMs = if (cursor.isNull(modifiedColumn)) 0L else cursor.getLong(modifiedColumn),
                    isDirectory = mime == DocumentsContract.Document.MIME_TYPE_DIR
                )
            }
        } ?: error("The storage provider returned no folder listing")
        ManagedFileListing(
            treeUri = tree.toString(),
            documentId = id,
            files = files.sortedWith(compareByDescending<ManagedFile> { it.isDirectory }.thenBy { it.name.lowercase() })
        )
    }

    suspend fun createFolder(tree: Uri, parentId: String, name: String): ManagedFile = withContext(Dispatchers.IO) {
        requireValidName(name)
        val parent = DocumentsContract.buildDocumentUriUsingTree(tree, parentId)
        val created = DocumentsContract.createDocument(
            resolver, parent, DocumentsContract.Document.MIME_TYPE_DIR, name.trim()
        ) ?: error("The storage provider could not create this folder")
        fileFromUri(tree, created, name.trim(), DocumentsContract.Document.MIME_TYPE_DIR)
    }

    suspend fun rename(tree: Uri, file: ManagedFile, newName: String) = withContext(Dispatchers.IO) {
        requireValidName(newName)
        DocumentsContract.renameDocument(resolver, Uri.parse(file.uri), newName.trim())
            ?: error("The storage provider refused to rename this item")
    }

    suspend fun delete(file: ManagedFile) = withContext(Dispatchers.IO) {
        val deleted = DocumentsContract.deleteDocument(resolver, Uri.parse(file.uri))
        if (!deleted) error("The storage provider refused to delete this item")
    }

    suspend fun importDocument(
        tree: Uri,
        parentId: String,
        source: Uri,
        name: String,
        mimeType: String
    ) = withContext(Dispatchers.IO) {
        requireValidName(name)
        val parent = DocumentsContract.buildDocumentUriUsingTree(tree, parentId)
        val created = DocumentsContract.createDocument(
            resolver, parent, mimeType.ifBlank { "application/octet-stream" }, name.trim()
        ) ?: error("The storage provider could not create the destination file")
        try {
            val input = resolver.openInputStream(source) ?: error("Cannot read the import source")
            val output = resolver.openOutputStream(created, "wt") ?: error("Cannot write the imported file")
            input.use { sourceStream -> output.use { destination -> sourceStream.copyTo(destination, 128 * 1024) } }
        } catch (failure: Throwable) {
            runCatching { DocumentsContract.deleteDocument(resolver, created) }
            throw failure
        }
    }

    suspend fun scanTree(
        tree: Uri,
        rootDocumentId: String,
        onProgress: (FileScanProgress) -> Unit
    ): SafScanBatchResult = withContext(Dispatchers.IO) {
        val collected = collectFiles(tree, rootDocumentId)
        val candidates = collected.files
        onProgress(FileScanProgress(running = true, total = candidates.size, skipped = collected.truncated))
        val records = ArrayList<SecurityScanRecord>()
        var skipped = collected.truncated
        var errors = 0
        candidates.forEachIndexed { index, file ->
            onProgress(FileScanProgress(running = true, current = index + 1, total = candidates.size, currentName = file.name, skipped = skipped, errors = errors))
            if (file.sizeBytes > MAX_SINGLE_SCAN_BYTES) {
                skipped++
                onProgress(FileScanProgress(running = true, current = index + 1, total = candidates.size, currentName = file.name, scanned = records.size, skipped = skipped, errors = errors))
                return@forEachIndexed
            }
            try {
                val result = securityEngine.scanUriContent(Uri.parse(file.uri), file.name)
                if (result == null) {
                    errors++
                } else {
                    val persisted = result.copy(sourceUri = file.uri)
                    scanHistory.record(persisted)
                    records += persisted
                }
            } catch (_: Throwable) {
                errors++
            }
            onProgress(FileScanProgress(running = true, current = index + 1, total = candidates.size, currentName = file.name, scanned = records.size, skipped = skipped, errors = errors))
        }
        SafScanBatchResult(records, skipped, errors)
    }

    suspend fun findDuplicates(tree: Uri, rootDocumentId: String): List<DuplicateFileGroup> = withContext(Dispatchers.IO) {
        val collected = collectFiles(tree, rootDocumentId)
        val candidates = collected.files.filter { it.sizeBytes > 0L }
            .groupBy { it.sizeBytes }.values.filter { it.size > 1 }.flatten()
        candidates.mapNotNull { file ->
            runCatching { file to sha256(Uri.parse(file.uri)) }.getOrNull()
        }.groupBy { (file, hash) -> file.sizeBytes.toString() + ":" + hash }
            .values.filter { it.size > 1 }
            .map { group ->
                DuplicateFileGroup(
                    sha256 = group.first().second,
                    sizeBytes = group.first().first.sizeBytes,
                    files = group.map { it.first }
                )
            }.sortedByDescending { it.sizeBytes * it.files.size }
    }

    private fun collectFiles(tree: Uri, rootDocumentId: String): CollectedFiles {
        val files = ArrayList<ManagedFile>()
        val pending = ArrayDeque<String>()
        val visited = HashSet<String>()
        pending.add(rootDocumentId)
        var truncated = 0
        while (pending.isNotEmpty() && files.size < MAX_SCAN_FILES) {
            val id = pending.removeFirst()
            if (!visited.add(id)) continue
            val listing = runCatching { listBlocking(tree, id) }.getOrElse { continue }
            listing.files.forEach { file ->
                if (file.isDirectory) pending.add(file.documentId)
                else if (files.size < MAX_SCAN_FILES) files += file else truncated++
            }
        }
        if (pending.isNotEmpty()) truncated++
        return CollectedFiles(files, truncated)
    }

    private fun listBlocking(tree: Uri, documentId: String): List<ManagedFile> {
        val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(tree, documentId)
        val files = ArrayList<ManagedFile>()
        resolver.query(childrenUri, PROJECTION, null, null, null)?.use { cursor ->
            while (cursor.moveToNext()) {
                val childId = cursor.getString(0)
                val mime = cursor.getString(2) ?: "application/octet-stream"
                files += ManagedFile(
                    uri = DocumentsContract.buildDocumentUriUsingTree(tree, childId).toString(),
                    documentId = childId,
                    name = cursor.getString(1) ?: "Unnamed",
                    mimeType = mime,
                    sizeBytes = if (cursor.isNull(3)) 0L else cursor.getLong(3).coerceAtLeast(0L),
                    lastModifiedEpochMs = if (cursor.isNull(4)) 0L else cursor.getLong(4),
                    isDirectory = mime == DocumentsContract.Document.MIME_TYPE_DIR
                )
            }
        }
        return files
    }

    private fun fileFromUri(tree: Uri, uri: Uri, name: String, mime: String): ManagedFile {
        val id = DocumentsContract.getDocumentId(uri)
        return ManagedFile(uri.toString(), id, name, mime, 0L, 0L, mime == DocumentsContract.Document.MIME_TYPE_DIR)
    }

    private fun sha256(uri: Uri): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val input = resolver.openInputStream(uri) ?: error("Cannot read file")
        input.use {
            val buffer = ByteArray(128 * 1024)
            while (true) {
                val read = it.read(buffer)
                if (read < 0) break
                digest.update(buffer, 0, read)
            }
        }
        return digest.digest().joinToString("") { byte -> "%02x".format(byte) }
    }

    private fun requireValidName(name: String) {
        val value = name.trim()
        require(value.isNotEmpty() && value.length <= 255) { "Enter a name between 1 and 255 characters" }
        require(!value.contains('/') && !value.contains('\\') && value != "." && value != ".." && !value.any { it.isISOControl() }) {
            "The name contains unsupported path characters"
        }
    }

    private data class CollectedFiles(val files: List<ManagedFile>, val truncated: Int)

    companion object {
        private const val MAX_LISTING_ENTRIES = 1000
        private const val MAX_SCAN_FILES = 250
        private const val MAX_SINGLE_SCAN_BYTES = 512L * 1024L * 1024L
        private val PROJECTION = arrayOf(
            DocumentsContract.Document.COLUMN_DOCUMENT_ID,
            DocumentsContract.Document.COLUMN_DISPLAY_NAME,
            DocumentsContract.Document.COLUMN_MIME_TYPE,
            DocumentsContract.Document.COLUMN_SIZE,
            DocumentsContract.Document.COLUMN_LAST_MODIFIED
        )
    }
}
