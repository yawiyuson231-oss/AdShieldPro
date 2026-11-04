package com.adshield.pro.engine.storage

import com.adshield.pro.engine.security.ApkAnalyzer
import com.adshield.pro.engine.security.FileThreatScanner
import com.adshield.pro.engine.security.SecurityLevel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.File
import java.io.InputStream
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.UUID

/**
 * AdShield Pro — Universal App & File Support Manager.
 *
 * Imports, classifies, verifies magic-byte signatures, scans for structural/APK threats, and
 * manages user-selected files and APKs inside app-scoped workspace storage (`filesDir/managed_files/`)
 * without requesting broad `MANAGE_EXTERNAL_STORAGE` permissions.
 */
class UniversalFileManager(
    private val workspaceDir: File,
    private val fileScanner: FileThreatScanner = FileThreatScanner(),
    private val apkAnalyzer: ApkAnalyzer = ApkAnalyzer()
) {

    @Serializable
    enum class ManagedMediaKind(val label: String) {
        PHOTO("Photos"),
        VIDEO("Videos"),
        AUDIO("Audio"),
        DOCUMENT("Documents"),
        APK("Applications (APK)"),
        ARCHIVE("Archives"),
        OTHER("Other")
    }

    @Serializable
    data class ManagedFileItem(
        val id: String,
        val displayName: String,
        val localFileName: String,
        val mimeType: String,
        val detectedSignatureMime: String?,
        val mimeMismatchWarning: String?,
        val kind: ManagedMediaKind,
        val sizeBytes: Long,
        val sha256: String,
        val securityLevel: SecurityLevel,
        val riskScore: Int,
        val apkPackageName: String? = null,
        val apkPermissionsCount: Int = 0,
        val findings: List<String> = emptyList(),
        val importedAtEpochMs: Long
    )

    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }

    private val filesSubDir = File(workspaceDir, "items").apply { mkdirs() }
    private val indexFile = File(workspaceDir, "managed_index.json")
    private val lock = Any()
    private var items: List<ManagedFileItem> = loadIndex()

    fun listManagedFiles(kindFilter: ManagedMediaKind? = null, query: String = ""): List<ManagedFileItem> =
        synchronized(lock) {
            val q = query.trim().lowercase()
            items.filter { item ->
                (kindFilter == null || item.kind == kindFilter) &&
                    (q.isEmpty() ||
                        item.displayName.lowercase().contains(q) ||
                        (item.apkPackageName?.lowercase()?.contains(q) == true))
            }.sortedByDescending { it.importedAtEpochMs }
        }

    fun getFileForItem(itemId: String): File? = synchronized(lock) {
        val item = items.firstOrNull { it.id == itemId } ?: return@synchronized null
        File(filesSubDir, item.localFileName).takeIf { it.exists() }
    }

    suspend fun importStream(
        inputStream: InputStream,
        displayName: String,
        declaredMime: String?
    ): Result<ManagedFileItem> = withContext(Dispatchers.IO) {
        runCatching {
            val cleanDisplay = sanitizeName(displayName)
            val id = UUID.randomUUID().toString()
            val ext = cleanDisplay.substringAfterLast('.', "").take(12)
            val localFileName = if (ext.isNotEmpty()) "${id.take(12)}.$ext" else id.take(12)
            val destFile = File(filesSubDir, localFileName)

            val digest = MessageDigest.getInstance("SHA-256")
            val header = ByteArray(32)
            var headerLen = 0

            try {
                destFile.outputStream().use { out ->
                    val buf = ByteArray(DEFAULT_BUFFER_SIZE)
                    while (true) {
                        val r = inputStream.read(buf)
                        if (r < 0) break
                        if (r > 0) {
                            if (headerLen < header.size) {
                                val c = minOf(r, header.size - headerLen)
                                System.arraycopy(buf, 0, header, headerLen, c)
                                headerLen += c
                            }
                            digest.update(buf, 0, r)
                            out.write(buf, 0, r)
                        }
                    }
                }

                val sha256 = digest.digest().joinToString("") { "%02x".format(it) }
                val headerSlice = header.copyOf(headerLen)
                val sigMime = detectMagicMime(headerSlice)
                val resolvedMime = resolveMimeType(cleanDisplay, declaredMime, headerSlice)
                val kind = classifyKind(cleanDisplay, resolvedMime)
                val mismatch = detectMimeSpoofWarning(cleanDisplay, sigMime)

                val fileVerdict = fileScanner.scanFile(destFile)
                val isApk = kind == ManagedMediaKind.APK ||
                    cleanDisplay.endsWith(".apk", ignoreCase = true)
                val apkReport = if (isApk) {
                    runCatching { apkAnalyzer.analyzeApk(destFile) }.getOrNull()
                } else null

                val combinedFindings = buildList {
                    if (mismatch != null) add(mismatch)
                    addAll(fileVerdict.findings)
                    if (apkReport != null) addAll(apkReport.riskReasons)
                }.distinct()

                val combinedScore = maxOf(
                    fileVerdict.riskScore,
                    apkReport?.riskScore ?: 0,
                    if (mismatch != null) 45 else 0
                ).coerceAtMost(100)

                val level = when {
                    fileVerdict.threatLevel == FileThreatScanner.ThreatLevel.DANGEROUS ||
                        apkReport?.threatLevel == ApkAnalyzer.ThreatLevel.DANGEROUS -> SecurityLevel.DANGEROUS
                    fileVerdict.threatLevel == FileThreatScanner.ThreatLevel.SUSPICIOUS ||
                        apkReport?.threatLevel == ApkAnalyzer.ThreatLevel.SUSPICIOUS ||
                        mismatch != null -> SecurityLevel.SUSPICIOUS
                    else -> SecurityLevel.CLEAN
                }

                val managed = ManagedFileItem(
                    id = id,
                    displayName = cleanDisplay,
                    localFileName = localFileName,
                    mimeType = resolvedMime,
                    detectedSignatureMime = sigMime,
                    mimeMismatchWarning = mismatch,
                    kind = kind,
                    sizeBytes = destFile.length(),
                    sha256 = sha256,
                    securityLevel = level,
                    riskScore = combinedScore,
                    apkPackageName = apkReport?.packageName,
                    apkPermissionsCount = apkReport?.requestedPermissions?.size ?: 0,
                    findings = combinedFindings,
                    importedAtEpochMs = System.currentTimeMillis()
                )

                synchronized(lock) {
                    items = listOf(managed) + items
                    saveIndexLocked()
                }
                managed
            } catch (t: Throwable) {
                destFile.delete()
                throw t
            }
        }
    }

    fun deleteManagedItem(itemId: String): Boolean = synchronized(lock) {
        val target = items.firstOrNull { it.id == itemId } ?: return@synchronized false
        File(filesSubDir, target.localFileName).delete()
        items = items.filterNot { it.id == itemId }
        saveIndexLocked()
        true
    }

    private fun loadIndex(): List<ManagedFileItem> {
        if (!indexFile.exists()) return emptyList()
        return runCatching {
            json.decodeFromString<List<ManagedFileItem>>(indexFile.readText(StandardCharsets.UTF_8))
        }.getOrDefault(emptyList())
    }

    private fun saveIndexLocked() {
        workspaceDir.mkdirs()
        indexFile.writeText(json.encodeToString(items), StandardCharsets.UTF_8)
    }

    companion object {
        fun detectMagicMime(header: ByteArray): String? {
            if (header.size < 4) return null
            val b0 = header[0].toInt() and 0xFF
            val b1 = header[1].toInt() and 0xFF
            val b2 = header[2].toInt() and 0xFF
            val b3 = header[3].toInt() and 0xFF

            if (b0 == 0x89 && b1 == 0x50 && b2 == 0x4E && b3 == 0x47) return "image/png"
            if (b0 == 0xFF && b1 == 0xD8 && b2 == 0xFF) return "image/jpeg"
            if (b0 == 0x47 && b1 == 0x49 && b2 == 0x46 && b3 == 0x38) return "image/gif"
            if (b0 == 0x25 && b1 == 0x50 && b2 == 0x44 && b3 == 0x46) return "application/pdf"
            if (b0 == 0x50 && b1 == 0x4B && b2 == 0x03 && b3 == 0x04) return "application/zip"
            if (b0 == 0x4F && b1 == 0x67 && b2 == 0x67 && b3 == 0x53) return "audio/ogg"
            if (b0 == 0x66 && b1 == 0x4C && b2 == 0x61 && b3 == 0x43) return "audio/flac"
            if (b0 == 0x49 && b1 == 0x44 && b2 == 0x33) return "audio/mpeg"
            if (b0 == 0xFF && (b1 and 0xE0) == 0xE0) return "audio/mpeg"
            if (b0 == 0x1A && b1 == 0x45 && b2 == 0xDF && b3 == 0xA3) return "video/webm"
            if (b0 == 0x7F && b1 == 0x45 && b2 == 0x4C && b3 == 0x46) return "application/x-elf"
            if (b0 == 0x4D && b1 == 0x5A) return "application/x-msdownload"

            if (header.size >= 12) {
                val riff = String(header, 0, 4, StandardCharsets.US_ASCII)
                val sub = String(header, 8, 4, StandardCharsets.US_ASCII)
                if (riff == "RIFF" && sub == "WEBP") return "image/webp"
                if (riff == "RIFF" && sub == "WAVE") return "audio/wav"
                if (riff == "RIFF" && sub == "AVI ") return "video/x-msvideo"
                val ftyp = String(header, 4, 4, StandardCharsets.US_ASCII)
                if (ftyp == "ftyp") {
                    val brand = String(header, 8, 4, StandardCharsets.US_ASCII)
                    return if (brand.startsWith("M4A")) "audio/mp4" else "video/mp4"
                }
            }
            return null
        }

        fun resolveMimeType(fileName: String, declaredMime: String?, headerBytes: ByteArray): String {
            val ext = fileName.substringAfterLast('.', "").lowercase()
            if (ext == "apk") return "application/vnd.android.package-archive"
            val magic = detectMagicMime(headerBytes)
            if (magic != null && magic != "application/zip") return magic
            if (!declaredMime.isNullOrBlank() && declaredMime != "application/octet-stream" && declaredMime != "*/*") {
                return declaredMime
            }
            return when (ext) {
                "jpg", "jpeg" -> "image/jpeg"
                "png" -> "image/png"
                "webp" -> "image/webp"
                "gif" -> "image/gif"
                "mp4", "m4v" -> "video/mp4"
                "webm" -> "video/webm"
                "mkv" -> "video/x-matroska"
                "mov" -> "video/quicktime"
                "mp3" -> "audio/mpeg"
                "m4a" -> "audio/mp4"
                "wav" -> "audio/wav"
                "ogg", "opus" -> "audio/ogg"
                "flac" -> "audio/flac"
                "aac" -> "audio/aac"
                "pdf" -> "application/pdf"
                "txt", "log", "md" -> "text/plain"
                "csv" -> "text/csv"
                "json" -> "application/json"
                "zip" -> "application/zip"
                else -> magic ?: "application/octet-stream"
            }
        }

        fun classifyKind(fileName: String, mimeType: String): ManagedMediaKind {
            val ext = fileName.substringAfterLast('.', "").lowercase()
            val lower = mimeType.lowercase()
            return when {
                ext in setOf("apk", "apks", "xapk") || lower == "application/vnd.android.package-archive" ->
                    ManagedMediaKind.APK
                lower.startsWith("image/") || ext in setOf("jpg", "jpeg", "png", "webp", "gif", "bmp", "heic") ->
                    ManagedMediaKind.PHOTO
                lower.startsWith("video/") || ext in setOf("mp4", "webm", "mkv", "mov", "avi", "m4v") ->
                    ManagedMediaKind.VIDEO
                lower.startsWith("audio/") || ext in setOf("mp3", "m4a", "wav", "ogg", "opus", "flac", "aac") ->
                    ManagedMediaKind.AUDIO
                ext in setOf("zip", "rar", "7z", "tar", "gz") || lower == "application/zip" ->
                    ManagedMediaKind.ARCHIVE
                lower.startsWith("text/") || lower == "application/pdf" || lower == "application/json" ||
                    ext in setOf("pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "md", "csv", "json") ->
                    ManagedMediaKind.DOCUMENT
                else -> ManagedMediaKind.OTHER
            }
        }

        fun detectMimeSpoofWarning(fileName: String, detectedMagicMime: String?): String? {
            if (detectedMagicMime == null) return null
            val ext = fileName.substringAfterLast('.', "").lowercase()
            if ((detectedMagicMime == "application/x-msdownload" || detectedMagicMime == "application/x-elf") &&
                ext in setOf("jpg", "jpeg", "png", "gif", "webp", "pdf", "mp3", "mp4", "txt", "doc", "docx")
            ) {
                return "Extension spoof detected: '$fileName' carries executable header ($detectedMagicMime)."
            }
            if (detectedMagicMime == "application/zip" && ext in setOf("jpg", "jpeg", "png", "pdf", "mp3", "mp4")) {
                return "Container mismatch: '$fileName' has a ZIP/APK archive header under a media/document extension."
            }
            return null
        }

        private fun sanitizeName(raw: String): String =
            raw.trim().substringAfterLast('/').substringAfterLast('\\')
                .replace(Regex("""[\u0000-\u001F<>:"|?*]"""), "_")
                .take(120)
                .ifBlank { "imported_${System.currentTimeMillis()}" }
    }
}
