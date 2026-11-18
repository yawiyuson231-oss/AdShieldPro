package com.adshield.pro.engine.security

import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.RandomAccessFile
import java.security.MessageDigest
import java.util.concurrent.CancellationException
import java.util.zip.ZipFile

/**
 * AdShield Pro — Deep File Threat Scanner (Pure Kotlin, unit-testable).
 *
 * Scans any accessible file for:
 * 1. Exact signature matches (industry-standard EICAR antivirus test signature).
 * 2. Corroborated executable header indicators inside JPEG, PNG, GIF and PDF containers.
 * 3. Script-based droppers (PowerShell -enc, curl|sh, mshta, certutil download chains).
 * 4. Macro-laden Office documents (vbaProject.bin inside OOXML zip containers).
 * 5. Path-traversal (Zip Slip) archive entries.
 * 6. Suspicious double-extension naming (invoice.pdf.exe).
 *
 * Everything runs locally — no file ever leaves the device.
 */
class FileThreatScanner {

    enum class ThreatLevel { CLEAN, SUSPICIOUS, DANGEROUS }

    data class FileVerdict(
        val fileName: String,
        val sizeBytes: Long,
        val sha256: String?,
        val threatLevel: ThreatLevel,
        val riskScore: Int,
        val threatName: String?,
        val findings: List<String>,
        val recommendation: String,
        val limitations: List<String> = emptyList()
    ) {
        val isClean: Boolean get() = threatLevel == ThreatLevel.CLEAN
    }

    fun scanFile(file: File, checkpoint: () -> Unit = {}): FileVerdict {
        checkpoint()
        val size = file.length()
        val sha = computeSha256OrNull(file, checkpoint)
        val findings = ArrayList<String>()
        val limitations = ArrayList<String>()
        if (sha == null) limitations += "Couldn't read the full file for fingerprinting."
        if (size > MAX_DEEP_SCAN_BYTES) limitations += "Content checks sampled the first 24 MiB."
        var score = 0
        var threatName: String? = null

        // 1. Filename heuristics (cheap, always run)
        val lowerName = file.name.lowercase()
        if (DOUBLE_EXTENSION_REGEX.containsMatchIn(lowerName)) {
            findings.add("Double-extension filename disguising an executable ('${lowerName.substringAfterLast('.')}') as a document/media file")
            score += 45
            threatName = "Double-Extension Dropper Pattern"
        }
        if (lowerName.endsWith(".apk") || lowerName.endsWith(".apks") || lowerName.endsWith(".xapk")) {
            findings.add("Android package installer — verify the source before installing")
            score += 5
        }
        if (lowerName.endsWith(".exe") || lowerName.endsWith(".scr") || lowerName.endsWith(".bat") ||
            lowerName.endsWith(".cmd") || lowerName.endsWith(".msi") || lowerName.endsWith(".vbs") ||
            lowerName.endsWith(".jar")
        ) {
            findings.add("Desktop-executable format cannot run safely on Android and is commonly shared as malware bait")
            score += 20
        }

        val head = readOrNull { file.inputStream().use { it.readHeader() } }
        if (head == null) {
            limitations += "Couldn't read the file contents."
        } else {
            // 2. Polyglot detection: media/document container hiding a real executable
            if (head.size >= 4) {
                val container = detectContainer(head)
                if (container != null) {
                    val embedded = readOrNull { findEmbeddedExecutableMarker(file, checkpoint) }
                    if (embedded == null) {
                        limitations += "Couldn't finish checking for embedded executable headers."
                    } else if (embedded.isNotEmpty()) {
                        findings.add("Embedded $embedded header in a $container container")
                        score += 90
                        threatName = "Polyglot Executable Indicator ($container → $embedded)"
                    }
                }
            }

            // 3/4/5. Content signature + dropper script heuristics (streamed, bounded)
            val content = readOrNull { scanContentStream(file, checkpoint) }
            if (content != null) {
                findings.addAll(content.findings)
                score += content.score
                if (threatName == null) threatName = content.threatName
            } else limitations += "Couldn't finish checking content for signatures and script indicators."

            // Only inspect ZIP metadata. Never extract or execute archive contents.
            if (hasZipHeader(head) || lowerName.substringAfterLast('.') in ZIP_EXTENSIONS) {
                val archive = readOrNull { inspectZipArchive(file, checkpoint) }
                if (archive != null) {
                    findings.addAll(archive.findings)
                    score += archive.score
                    if (threatName == null) threatName = archive.threatName
                    if (archive.limited) limitations += "Archive checks stopped after $MAX_ZIP_ENTRIES entries."
                } else limitations += "Couldn't inspect ZIP archive metadata."
            }
        }

        val level = when {
            score >= 70 -> ThreatLevel.DANGEROUS
            score >= 25 -> ThreatLevel.SUSPICIOUS
            else -> ThreatLevel.CLEAN
        }
        val recommendation = when (level) {
            ThreatLevel.DANGEROUS -> "Do not open or install this file. Review the indicators and verify the source."
            ThreatLevel.SUSPICIOUS -> "Verify the source before opening this file. The findings are indicators, not proof."
            ThreatLevel.CLEAN -> when {
                limitations.isNotEmpty() -> "Some checks were incomplete. A lack of matching indicators does not guarantee safety."
                findings.isNotEmpty() -> "Low-scoring indicators matched. Verify the source before using this file."
                else -> "No threat indicators matched. A local scan cannot guarantee safety."
            }
        }

        return FileVerdict(
            fileName = file.name,
            sizeBytes = size,
            sha256 = sha,
            threatLevel = level,
            riskScore = score.coerceAtMost(100),
            threatName = threatName,
            findings = findings,
            recommendation = recommendation,
            limitations = limitations
        )
    }

    private fun InputStream.readHeader(): ByteArray {
        val header = ByteArray(16)
        var filled = 0
        while (filled < header.size) {
            val count = read(header, filled, header.size - filled)
            if (count <= 0) break
            filled += count
        }
        return header.copyOf(filled)
    }

    private fun detectContainer(head: ByteArray): String? {
        return when {
            head.size >= 3 && head[0] == 0xFF.toByte() && head[1] == 0xD8.toByte() && head[2] == 0xFF.toByte() -> "JPEG image"
            head.size >= 4 && head[0] == 0x89.toByte() && head[1] == 0x50.toByte() && head[2] == 0x4E.toByte() && head[3] == 0x47.toByte() -> "PNG image"
            head.size >= 3 && head[0] == 'G'.code.toByte() && head[1] == 'I'.code.toByte() && head[2] == 'F'.code.toByte() -> "GIF image"
            head.size >= 4 && head[0] == 0x25.toByte() && head[1] == 0x50.toByte() && head[2] == 0x44.toByte() && head[3] == 0x46.toByte() -> "PDF document"
            else -> null
        }
    }

    private fun hasZipHeader(head: ByteArray): Boolean = head.size >= 4 &&
        head[0] == 0x50.toByte() && head[1] == 0x4B.toByte() &&
        ((head[2] == 3.toByte() && head[3] == 4.toByte()) || (head[2] == 5.toByte() && head[3] == 6.toByte()))

    /** Short magic alone (especially 'MZ') is common in non-executable content. Corroborate it. */
    private fun findEmbeddedExecutableMarker(file: File, checkpoint: () -> Unit): String = RandomAccessFile(file, "r").use { input ->
        val limit = minOf(MAX_DEEP_SCAN_BYTES, input.length())
        val bytes = ByteArray(CHUNK_SIZE + MAX_PE_OFFSET + 24)
        var offset = 0L
        while (offset < limit) {
            checkpoint()
            val read = minOf(bytes.size.toLong(), limit - offset).toInt()
            input.seek(offset)
            input.readFully(bytes, 0, read)
            val window = minOf(CHUNK_SIZE, read)
            for (i in 0 until window) {
                when (bytes[i].toInt()) {
                    0x4D -> if (i + 64 <= read && bytes[i + 1] == 0x5A.toByte()) {
                        val header = bytes.leInt(i + 60)
                        if (header in 64..MAX_PE_OFFSET && i + header + 24 <= read) {
                            val pe = i + header
                            if (bytes.leInt(pe) == 0x00004550 && bytes.leInt(pe + 4) != 0 &&
                                (bytes[pe + 6] != 0.toByte() || bytes[pe + 7] != 0.toByte())
                            ) return "Windows PE"
                        }
                    }
                    0x7F -> if (i + 16 <= read && bytes.leInt(i) == 0x464C457F &&
                        bytes[i + 4].toInt() in 1..2 && bytes[i + 5].toInt() in 1..2 && bytes[i + 6] == 1.toByte()
                    ) return "ELF executable"
                    0x64 -> if (i + 8 <= read && bytes.leInt(i) == 0x0A786564 && bytes[i + 7] == 0.toByte() &&
                        (i + 4 until i + 7).all { bytes[it].toInt() in '0'.code..'9'.code }
                    ) return "Android DEX"
                }
            }
            offset += window
        }
        ""
    }

    private fun ByteArray.leInt(index: Int): Int = (this[index].toInt() and 0xFF) or
        ((this[index + 1].toInt() and 0xFF) shl 8) or ((this[index + 2].toInt() and 0xFF) shl 16) or
        (this[index + 3].toInt() shl 24)

    private data class ContentFindings(val findings: List<String>, val score: Int, val threatName: String?)

    private fun scanContentStream(file: File, checkpoint: () -> Unit): ContentFindings {
        val matched = BooleanArray(SCRIPT_PATTERNS.size)
        var expression = false
        var decoder = false
        file.inputStream().use { input ->
            val bytes = ByteArray(CHUNK_SIZE)
            var remaining = MAX_DEEP_SCAN_BYTES
            var overlap = ""
            while (remaining > 0) {
                checkpoint()
                val read = input.read(bytes, 0, minOf(remaining, bytes.size.toLong()).toInt())
                if (read <= 0) break
                val text = overlap + String(bytes, 0, read, Charsets.ISO_8859_1)
                if (text.contains(EICAR_STRING)) return ContentFindings(
                    listOf("Exact match: EICAR antivirus test signature (industry-standard detection test file)"),
                    100, "EICAR.Test.File"
                )
                // Check every window, including signatures that cross a chunk boundary. Deduplicate hits.
                SCRIPT_PATTERNS.forEachIndexed { index, (pattern, _) ->
                    if (!matched[index]) matched[index] = pattern.containsMatchIn(text)
                }
                expression = expression || text.contains("Invoke-Expression", ignoreCase = true)
                decoder = decoder || text.contains("FromBase64String", ignoreCase = true) ||
                    text.contains("DownloadString", ignoreCase = true)
                overlap = text.takeLast(256) // Longer than any of the bounded patterns.
                remaining -= read
            }
        }
        val findings = SCRIPT_PATTERNS.mapIndexedNotNull { index, (_, label) -> label.takeIf { matched[index] } }
        if (findings.isNotEmpty()) return ContentFindings(findings, findings.size * 60, "Script Dropper Technique")
        if (expression && decoder) return ContentFindings(
            listOf("PowerShell expression execution and decoding or download markers"), 55, "Script Dropper Technique"
        )
        return ContentFindings(emptyList(), 0, null)
    }

    private data class ArchiveFindings(val findings: List<String>, val score: Int, val threatName: String?, val limited: Boolean)

    private fun inspectZipArchive(file: File, checkpoint: () -> Unit): ArchiveFindings = ZipFile(file).use { zip ->
        val entries = zip.entries()
        var checked = 0
        var traversals = false
        var macros = false
        while (entries.hasMoreElements() && checked < MAX_ZIP_ENTRIES) {
            checkpoint()
            val name = entries.nextElement().name.replace('\\', '/')
            checked++
            traversals = traversals || name.split('/').contains("..")
            macros = macros || name.equals("word/vbaProject.bin", ignoreCase = true) ||
                name.equals("xl/vbaProject.bin", ignoreCase = true) || name.equals("ppt/vbaProject.bin", ignoreCase = true)
        }
        ArchiveFindings(
            findings = buildList {
                if (traversals) add("Zip-Slip path traversal entry found")
                if (macros) add("Office document with embedded VBA macro project (vbaProject.bin)")
            },
            score = (if (traversals) 70 else 0) + (if (macros) 40 else 0),
            threatName = when {
                traversals -> "Archive Path Traversal (Zip Slip)"
                macros -> "Macro-Carrying Office Document"
                else -> null
            },
            limited = entries.hasMoreElements()
        )
    }

    private fun computeSha256OrNull(file: File, checkpoint: () -> Unit): String? = readOrNull {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val bytes = ByteArray(CHUNK_SIZE)
            while (true) {
                checkpoint()
                val read = input.read(bytes)
                if (read <= 0) break
                digest.update(bytes, 0, read)
            }
        }
        digest.digest().joinToString("") { "%02x".format(it) }
    }

    private inline fun <T> readOrNull(block: () -> T): T? = try {
        block()
    } catch (cancelled: CancellationException) {
        throw cancelled
    } catch (_: IOException) {
        null
    } catch (_: SecurityException) {
        null
    }

    companion object {
        private const val MAX_DEEP_SCAN_BYTES = 24L * 1024 * 1024
        private const val CHUNK_SIZE = 65_536
        private const val MAX_PE_OFFSET = 4_096
        private const val MAX_ZIP_ENTRIES = 4_096
        private val ZIP_EXTENSIONS = setOf("zip", "apk", "apks", "xapk", "docx", "docm", "xlsx", "xlsm", "pptx", "pptm", "jar")
        private val SCRIPT_PATTERNS = listOf(
            Regex("""powershell(\.exe)?.{0,40}-(enc|EncodedCommand|w hidden)""", RegexOption.IGNORE_CASE) to
                "Obfuscated PowerShell dropper command (-enc/hidden)",
            Regex("""certutil.{0,30}-urlcache""", RegexOption.IGNORE_CASE) to "certutil download command indicator",
            Regex("""mshta\s{1,32}https?://""", RegexOption.IGNORE_CASE) to "mshta remote script execution indicator",
            Regex("""(curl|wget).{0,60}\|\s{0,32}(sudo\s{1,32})?(ba)?sh""", RegexOption.IGNORE_CASE) to
                "Pipe-to-shell command indicator",
            Regex("""rundll32\s{1,32}javascript""", RegexOption.IGNORE_CASE) to "rundll32 JavaScript execution indicator"
        )

        /** Industry-standard EICAR test payload — the only "malware" string shipped with AdShield Pro. */
        const val EICAR_STRING =
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*"

        private val DOUBLE_EXTENSION_REGEX =
            Regex("""\.(pdf|jpg|jpeg|png|doc|docx|txt|mp4|mp3|gif|xlsx|pptx)\.(exe|apk|scr|bat|cmd|jar|vbs|js)$""")
    }
}
