package com.adshield.pro.engine.security

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.CancellationException
import java.util.zip.ZipEntry
import java.util.zip.ZipFile

/**
 * AdShield Pro — Static APK / App Package Analyzer (Pure Kotlin, unit-testable).
 *
 * Performs real structural analysis of Android package archives WITHOUT installing them:
 * 1. Binary AndroidManifest (AXML) parser — extracts the real package name and every
 *    requested permission straight from the compiled manifest chunk (no root needed).
 * 2. Dangerous permission-combination risk scoring (accessibility abuse, SMS interception,
 *    silent-install droppers, contact/screen exfiltration stacks).
 * 3. Dynamic code loading & packer detection (DexClassLoader/InMemoryDexClassLoader,
 *    commercial APK packers like jiagu/secshell/DEXHelper).
 * 4. Archive integrity checks (duplicate entries, path traversal).
 *
 * This mirrors how mobile threat defense products triage unknown APKs on-device.
 */
class ApkAnalyzer {

    enum class ThreatLevel { CLEAN, SUSPICIOUS, DANGEROUS }

    data class ApkReport(
        val fileName: String,
        val packageName: String?,
        val requestedPermissions: List<String>,
        val riskScore: Int,
        val threatLevel: ThreatLevel,
        val riskReasons: List<String>,
        val isSigned: Boolean,
        val usesDynamicCodeLoading: Boolean,
        val usesPackerOrObfuscator: Boolean,
        val limitations: List<String> = emptyList(),
        val signerSha256: String? = null,
        val signerSubject: String? = null,
        val signatureSchemeVersion: Int = 0,
        val cloneMismatchDetected: Boolean = false
    ) {
        val isClean: Boolean get() = threatLevel == ThreatLevel.CLEAN
    }

    fun analyzeApk(
        file: File,
        checkpoint: () -> Unit = {},
        installedAppSignerSha256: String? = null
    ): ApkReport {
        val reasons = ArrayList<String>()
        val limitations = ArrayList<String>()
        checkpoint()
        var score = 0
        var packageName: String? = null
        var permissions: List<String> = emptyList()
        var isSigned = false
        var dynamicLoading = false
        var packer = false

        try {
            ZipFile(file).use { zip ->
                val manifestEntry: ZipEntry? = zip.getEntry("AndroidManifest.xml")
                if (manifestEntry != null && manifestEntry.size in 1L..MANIFEST_LIMIT) {
                    val bytes = zip.getInputStream(manifestEntry).use { readBounded(it, MANIFEST_LIMIT, checkpoint) }
                    if (bytes.size.toLong() == manifestEntry.size) {
                        val parsed = parseBinaryAndroidManifest(bytes, checkpoint)
                        packageName = parsed.first
                        permissions = parsed.second
                    }
                }

                val entries = zip.entries()
                var checked = 0
                var dexRemaining = DEX_LIMIT
                var dexLimited = false
                while (checked < ENTRY_LIMIT && entries.hasMoreElements()) {
                    checkpoint()
                    checked++
                    val e = entries.nextElement()
                    val name = e.name.lowercase()
                    if (name.startsWith("meta-inf/") && (name.endsWith(".rsa") || name.endsWith(".dsa") || name.endsWith(".ec"))) {
                        isSigned = true
                    }
                    if (name.startsWith("lib/") && PACKER_LIB_MARKERS.any { name.contains(it) }) packer = true
                    if (name.startsWith("classes") && name.endsWith(".dex")) {
                        // Apply one shared decompression budget across all DEX entries.
                        if (dexRemaining == 0L) {
                            dexLimited = true
                            continue
                        }
                        val indicators = zip.getInputStream(e).use { inspectDex(it, dexRemaining, checkpoint) }
                        dexRemaining -= indicators.bytesRead
                        dexLimited = dexLimited || (dexRemaining == 0L && e.size > indicators.bytesRead)
                        dynamicLoading = dynamicLoading || indicators.dynamicLoading
                        packer = packer || indicators.packer
                    }
                }
                if (entries.hasMoreElements()) limitations += "APK entry checks stopped after $ENTRY_LIMIT entries."
                if (dexLimited) limitations += "APK code indicator checks reached the 12 MiB DEX read limit."
            }
            if (!isSigned) isSigned = hasApkSigBlockV2Plus(file)
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            limitations += "Couldn't finish reading APK metadata."
        }
        checkpoint()

        // --- Permission risk scoring ---
        for (perm in permissions) {
            val weight = PERMISSION_RISK_WEIGHT[perm] ?: 0
            score += weight
        }
        val permissionNames = permissions.toHashSet()
        fun requests(name: String) = "android.permission.$name" in permissionNames

        if (requests("ACCESSIBILITY_SERVICE") ||
            requests("BIND_ACCESSIBILITY_SERVICE")
        ) {
            reasons.add("Requests an accessibility-related permission; service and grant status were not verified")
            score += 30
        }
        if (requests("RECEIVE_SMS") && requests("READ_SMS")) {
            reasons.add("SMS interception indicator: requests both SMS receive and read permissions")
            score += 25
        }
        if (requests("REQUEST_INSTALL_PACKAGES") && dynamicLoading) {
            reasons.add("Requests package installation and contains dynamic code loading references")
            score += 35
        }
        if (requests("READ_CONTACTS") && requests("READ_CALL_LOG") &&
            requests("RECORD_AUDIO")
        ) {
            reasons.add("Requests contacts, call log and microphone permissions together")
            score += 20
        }
        if (requests("SYSTEM_ALERT_WINDOW") && requests("QUERY_ALL_PACKAGES")) {
            reasons.add("Requests overlay window and broad app visibility permissions together")
            score += 15
        }

        // Package-name hygiene
        val pkg = packageName ?: ""
        val lowerPkg = pkg.lowercase()
        if (lowerPkg.isNotEmpty()) {
            if (SUSPICIOUS_PACKAGE_TOKENS.any { lowerPkg.contains(it) }) {
                reasons.add("Package name contains cracker/modware tokens")
                score += 20
            }
            if (lowerPkg.count { it == '.' } == 1 && !lowerPkg.startsWith("com.") && !lowerPkg.startsWith("org.") &&
                !lowerPkg.startsWith("net.") && !lowerPkg.startsWith("io.")
            ) {
                reasons.add("Package uses a short publisher namespace")
                score += 8
            }
        } else {
            limitations += "APK manifest package and permissions could not be confirmed."
        }

        if (!isSigned) {
            reasons.add("No APK signing markers found in the inspected metadata")
            score += 12
        }
        val sigReport = ApkSignatureVerifier.inspectApkSignatures(
            apkFile = file,
            packageName = packageName,
            installedAppSignerSha256 = installedAppSignerSha256
        )
        if (sigReport.hasSignatureMarkers) {
            isSigned = true
        }
        if (sigReport.addedRiskScore > 0) {
            score += sigReport.addedRiskScore
            reasons.addAll(sigReport.findings)
        }
        if (dynamicLoading && !packer) {
            reasons.add("Contains dynamic code loading references; behavior was not observed")
            score += 10
        }
        if (packer) {
            reasons.add("Contains APK packer or obfuscator markers")
            score += 12
        }

        val level = when {
            score >= 60 -> ThreatLevel.DANGEROUS
            score >= 25 -> ThreatLevel.SUSPICIOUS
            else -> ThreatLevel.CLEAN
        }

        return ApkReport(
            fileName = file.name,
            packageName = packageName,
            requestedPermissions = permissions.sortedDescending(),
            riskScore = score.coerceAtMost(100),
            threatLevel = level,
            riskReasons = reasons,
            isSigned = isSigned,
            usesDynamicCodeLoading = dynamicLoading,
            usesPackerOrObfuscator = packer,
            limitations = limitations,
            signerSha256 = sigReport.primarySha256,
            signerSubject = sigReport.primarySubject,
            signatureSchemeVersion = sigReport.schemeVersion,
            cloneMismatchDetected = sigReport.cloneMismatchDetected
        )
    }

    /**
     * Minimal, hardened parser for compiled binary AndroidManifest.xml (AXML).
     * Returns (packageName, requestedPermissions). Malformed input produces an empty result;
     * cancellation is allowed to propagate.
     */
    fun parseBinaryAndroidManifest(data: ByteArray, checkpoint: () -> Unit = {}): Pair<String?, List<String>> {
        return runCatching {
            if (data.size < 8) return@runCatching Pair(null, emptyList<String>())
            val buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)

            val rootType = buf.getShort(0).toInt() and 0xFFFF
            if (rootType != 0x0003) return@runCatching Pair(null, emptyList<String>()) // not RES_XML_TYPE
            val rootHeaderSize = buf.getShort(2).toInt() and 0xFFFF
            val rootSize = buf.getInt(4)
            if (rootSize > data.size || rootHeaderSize !in 8..rootSize) return@runCatching Pair(null, emptyList<String>())

            var stringPool: List<String> = emptyList()
            var packageAttr: String? = null
            val permissions = LinkedHashSet<String>()

            var offset = rootHeaderSize
            while (offset <= rootSize - 8) {
                checkpoint()
                val type = (data[offset].toInt() and 0xFF) or ((data[offset + 1].toInt() and 0xFF) shl 8)
                val headerSize = (data[offset + 2].toInt() and 0xFF) or ((data[offset + 3].toInt() and 0xFF) shl 8)
                val chunkSize = buf.getInt(offset + 4)
                if (headerSize !in 8..chunkSize || chunkSize > rootSize - offset) {
                    return@runCatching Pair(null, emptyList<String>())
                }
                val chunkEnd = offset + chunkSize

                when (type) {
                    0x0001 -> { // RES_STRING_POOL_TYPE
                        if (stringPool.isNotEmpty()) return@runCatching Pair(null, emptyList<String>())
                        stringPool = parseStringPool(data, offset, chunkSize, headerSize, checkpoint)
                        if (stringPool.isEmpty()) return@runCatching Pair(null, emptyList<String>())
                    }
                    0x0102 -> { // RES_XML_START_ELEMENT_TYPE
                        if (stringPool.isNotEmpty()) {
                            // Node: chunkHeader(8) + lineNumber(4) + comment(4) = headerSize
                            // attrExt: ns(4) + name(4) + attributeStart(2) + attributeSize(2)
                            //          + attributeCount(2) + idIndex(2) + classIndex(2) + styleIndex(2)
                            val nodeBase = offset
                            if (headerSize >= 16 && chunkSize - headerSize >= 20) {
                                buf.position(nodeBase + headerSize)
                                buf.int // ns
                                val nameIdx = buf.int
                                val attributeStart = buf.short.toInt() and 0xFFFF
                                val attributeSize = buf.short.toInt() and 0xFFFF
                                val attributeCount = buf.short.toInt() and 0xFFFF

                                val elementName = stringPool.getOrNull(nameIdx)
                                val attrBase = nodeBase + headerSize + attributeStart
                                if (attributeStart >= 20 && attributeSize >= 20 &&
                                    attrBase + attributeSize.toLong() * attributeCount <= chunkEnd
                                ) {
                                    for (i in 0 until attributeCount) {
                                        buf.position(attrBase + i * attributeSize)
                                        buf.int // attr ns
                                        val aNameIdx = buf.int
                                        val rawValueIdx = buf.int
                                        buf.short // typed value size
                                        buf.get() // res0
                                        val dataType = buf.get().toInt()
                                        val dataValue = buf.int
                                        val attrName = stringPool.getOrNull(aNameIdx)
                                        val value: String? = when {
                                            dataType == 0x03 -> stringPool.getOrNull(dataValue) // STRING pool reference
                                            rawValueIdx >= 0 -> stringPool.getOrNull(rawValueIdx)
                                            else -> null
                                        }
                                        if (elementName == "uses-permission" && attrName == "name") {
                                            value?.let { permissions.add(it) }
                                            if (permissions.size > 4_096) return@runCatching Pair(null, emptyList<String>())
                                        }
                                        if (elementName == "manifest" && attrName == "package") {
                                            packageAttr = value
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                offset += chunkSize
            }
            if (offset != rootSize) Pair(null, emptyList<String>()) else Pair(packageAttr, permissions.toList())
        }.getOrElse { failure ->
            if (failure !is Exception || failure is CancellationException) throw failure
            Pair(null, emptyList())
        }
    }

    /** Parses a RES_STRING_POOL_TYPE chunk into decoded strings (UTF-8 and UTF-16 encodings). */
    private fun parseStringPool(
        data: ByteArray, chunkOffset: Int, chunkSize: Int, headerSize: Int, checkpoint: () -> Unit
    ): List<String> {
        if (headerSize < 28 || headerSize > chunkSize) return emptyList()
        val buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)
        val stringCount = buf.getInt(chunkOffset + 8)
        val styleCount = buf.getInt(chunkOffset + 12)
        val flags = buf.getInt(chunkOffset + 16)
        val stringsStart = buf.getInt(chunkOffset + 20)
        val stylesStart = buf.getInt(chunkOffset + 24)
        val tableEnd = headerSize + 4L * (stringCount.toLong() + styleCount)
        val end = if (stylesStart == 0) chunkSize else stylesStart
        if (stringCount !in 0..60_000 || styleCount < 0 || stringsStart < tableEnd || end !in stringsStart..chunkSize) {
            return emptyList()
        }
        val isUtf8 = (flags and (1 shl 8)) != 0
        val result = ArrayList<String>(stringCount)
        var remainingChars = 1_048_576
        for (i in 0 until stringCount) {
            if ((i and 255) == 0) checkpoint()
            val off = buf.getInt(chunkOffset + headerSize + i * 4)
            if (off !in 0 until end - stringsStart) return emptyList()
            val absolute = chunkOffset + stringsStart + off
            val str = (if (isUtf8) decodeUtf8PoolString(data, absolute, chunkOffset + end)
                else decodeUtf16PoolString(data, absolute, chunkOffset + end)) ?: return emptyList()
            remainingChars -= str.length
            if (remainingChars < 0) return emptyList()
            result.add(str)
        }
        return result
    }

    private fun decodeUtf16PoolString(data: ByteArray, pos: Int, end: Int): String? {
        var p = pos
        if (p < 0 || p + 2 > end) return null
        val buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)
        var len = buf.getShort(p).toInt() and 0xFFFF
        p += 2
        if (len and 0x8000 != 0) {
            if (p + 2 > end) return null
            len = ((len and 0x7FFF) shl 16) or (buf.getShort(p).toInt() and 0xFFFF)
            p += 2
        }
        if (len !in 0..4_096 || p.toLong() + len * 2L + 2L > end) return null
        val chars = CharArray(len)
        for (i in 0 until len) {
            chars[i] = buf.getChar(p + i * 2)
        }
        return String(chars)
    }

    private fun decodeUtf8PoolString(data: ByteArray, pos: Int, end: Int): String? {
        var p = pos
        if (p < 0 || p >= end) return null
        // utf16 length (u8 or u8*2), then utf8 length (u8 or u8*2), then bytes, then NUL
        var b = data[p].toInt() and 0xFF
        p++
        if (b and 0x80 != 0) {
            if (p >= end) return null
            b = ((b and 0x7F) shl 8) or (data[p].toInt() and 0xFF)
            p++
        }
        if (p >= end) return null
        // b is utf16 char count; skip
        var len = data[p].toInt() and 0xFF
        p++
        if (len and 0x80 != 0) {
            if (p >= end) return null
            len = ((len and 0x7F) shl 8) or (data[p].toInt() and 0xFF)
            p++
        }
        if (len !in 0..16_384 || p.toLong() + len + 1L > end) return null
        return String(data, p, len, Charsets.UTF_8)
    }

    /** Detects APK Signature Scheme v2/v3/v4 signing blocks ("APK Sig Block 42") before ZIP EOCD. */
    private fun hasApkSigBlockV2Plus(file: File): Boolean = runCatching {
        val len = file.length()
        if (len < 54L) return@runCatching false
        java.io.RandomAccessFile(file, "r").use { raf ->
            val tailLen = minOf(len, 65_557L).toInt()
            val tail = ByteArray(tailLen)
            raf.seek(len - tailLen)
            raf.readFully(tail)
            // Locate ZIP End of Central Directory (0x06054b50) scanning backward.
            var eocd = -1
            for (i in tailLen - 22 downTo 0) {
                if (tail[i] == 0x50.toByte() && tail[i + 1] == 0x4b.toByte() &&
                    tail[i + 2] == 0x05.toByte() && tail[i + 3] == 0x06.toByte()
                ) {
                    eocd = i
                    break
                }
            }
            if (eocd < 0) return@runCatching false
            val cdOffset = ByteBuffer.wrap(tail, eocd + 16, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL
            if (cdOffset < 32L || cdOffset > len) return@runCatching false
            val magic = ByteArray(16)
            raf.seek(cdOffset - 16L)
            raf.readFully(magic)
            String(magic, Charsets.US_ASCII) == "APK Sig Block 42"
        }
    }.getOrDefault(false)

    private fun readBounded(input: InputStream, maxBytes: Long, checkpoint: () -> Unit): ByteArray {
        val out = ByteArrayOutputStream()
        val buffer = ByteArray(65536)
        var total = 0L
        while (total < maxBytes) {
            checkpoint()
            val read = input.read(buffer, 0, buffer.size.coerceAtMost((maxBytes - total).toInt()))
            if (read <= 0) break
            out.write(buffer, 0, read)
            total += read
        }
        return out.toByteArray()
    }

    private data class DexIndicators(val bytesRead: Long, val dynamicLoading: Boolean, val packer: Boolean)

    private fun inspectDex(input: InputStream, budget: Long, checkpoint: () -> Unit): DexIndicators {
        val buffer = ByteArray(65_536)
        var read = 0L
        var overlap = ""
        var dynamic = false
        var packer = false
        while (read < budget) {
            checkpoint()
            val count = input.read(buffer, 0, minOf(buffer.size.toLong(), budget - read).toInt())
            if (count <= 0) break
            read += count
            val text = overlap + String(buffer, 0, count, Charsets.ISO_8859_1)
            dynamic = dynamic || text.contains("InMemoryDexClassLoader") || text.contains("dalvik/system/DexClassLoader")
            packer = packer || text.contains("libjiagu") || text.contains("libDexHelper")
            overlap = text.takeLast(32)
        }
        return DexIndicators(read, dynamic, packer)
    }

    companion object {
        private const val ENTRY_LIMIT = 4_096
        private const val MANIFEST_LIMIT = 4L * 1024 * 1024
        private const val DEX_LIMIT = 12L * 1024 * 1024
        private val PACKER_LIB_MARKERS = listOf(
            "libjiagu", "libjiagu_art", "libjiagu_x86", "libdexhelper", "libsecexe", "libsecmain",
            "libprotectclass", "libshellx", "libnqshield", "libexecmain", "libtup", "libexec.so"
        )

        private val SUSPICIOUS_PACKAGE_TOKENS = listOf(
            "lucky", "patcher", "patch", "crack", "modded", "hack", "cheat", "premiumfree",
            "modapk", "apkpuremod", "freecoins", "unlimited", "injection"
        )

        /** Real Android permission strings and their risk weight in triage scoring. */
        val PERMISSION_RISK_WEIGHT = mapOf(
            "android.permission.ACCESSIBILITY_SERVICE" to 0, // scored via combo rules
            "android.permission.BIND_ACCESSIBILITY_SERVICE" to 0,
            "android.permission.RECEIVE_SMS" to 12,
            "android.permission.READ_SMS" to 10,
            "android.permission.SEND_SMS" to 14,
            "android.permission.RECEIVE_MMS" to 6,
            "android.permission.REQUEST_INSTALL_PACKAGES" to 12,
            "android.permission.READ_CONTACTS" to 6,
            "android.permission.WRITE_CONTACTS" to 5,
            "android.permission.READ_CALL_LOG" to 8,
            "android.permission.CALL_PHONE" to 6,
            "android.permission.RECORD_AUDIO" to 5,
            "android.permission.CAMERA" to 4,
            "android.permission.ACCESS_FINE_LOCATION" to 5,
            "android.permission.ACCESS_BACKGROUND_LOCATION" to 8,
            "android.permission.SYSTEM_ALERT_WINDOW" to 6,
            "android.permission.QUERY_ALL_PACKAGES" to 4,
            "android.permission.READ_PHONE_STATE" to 5,
            "android.permission.READ_PHONE_NUMBERS" to 4,
            "android.permission.GET_ACCOUNTS" to 4,
            "android.permission.READ_EXTERNAL_STORAGE" to 2,
            "android.permission.WRITE_EXTERNAL_STORAGE" to 2,
            "android.permission.MANAGE_EXTERNAL_STORAGE" to 6,
            "android.permission.PACKAGE_USAGE_STATS" to 4,
            "android.permission.BIND_DEVICE_ADMIN" to 10,
            "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE" to 10,
            "android.permission.FOREGROUND_SERVICE" to 1,
            "android.permission.USE_FULL_SCREEN_INTENT" to 3
        )
    }
}
