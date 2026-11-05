package com.adshield.pro.cloud.util

import java.io.InputStream
import java.security.MessageDigest
import java.util.Locale

/**
 * Streaming SHA-256 helpers used for duplicate detection, integrity verification
 * and upload resume bookkeeping. Never buffers a whole file in memory.
 */
object Hashing {

    private const val BUFFER = 64 * 1024

    fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).toHex()

    fun sha256Hex(text: String): String = sha256Hex(text.toByteArray(Charsets.UTF_8))

    /**
     * Hashes a stream. [onProgress] receives (bytesHashed, totalBytes) and may be called
     * from a background thread; callers must throttle UI updates themselves.
     */
    fun sha256HexStream(
        input: InputStream,
        totalBytes: Long = -1,
        onProgress: ((Long, Long) -> Unit)? = null,
        isCancelled: (() -> Boolean)? = null
    ): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(BUFFER)
        var hashed = 0L
        var lastReport = 0L
        while (true) {
            if (isCancelled?.invoke() == true) throw InterruptedException("Hash computation cancelled")
            val read = input.read(buffer)
            if (read <= 0) break
            digest.update(buffer, 0, read)
            hashed += read
            if (hashed - lastReport >= 1024 * 1024) {
                lastReport = hashed
                onProgress?.invoke(hashed, totalBytes)
            }
        }
        onProgress?.invoke(hashed, totalBytes)
        return digest.digest().toHex()
    }

    fun ByteArray.toHex(): String {
        val builder = StringBuilder(size * 2)
        for (byte in this) builder.append(((byte.toInt() and 0xFF) + 0x100).toString(16).substring(1))
        return builder.toString().lowercase(Locale.US)
    }
}

/** Human readable byte formatting shared by the cloud UI. */
object ByteFormat {
    fun human(bytes: Long): String {
        if (bytes < 0) return "—"
        if (bytes < 1024) return "$bytes B"
        val units = arrayOf("KB", "MB", "GB", "TB")
        var value = bytes.toDouble() / 1024
        var index = 0
        while (value >= 1024 && index < units.size - 1) {
            value /= 1024
            index += 1
        }
        return if (value >= 100) {
            String.format(Locale.US, "%.0f %s", value, units[index])
        } else {
            String.format(Locale.US, "%.1f %s", value, units[index])
        }
    }

    fun humanPerSecond(bytesPerSecond: Long): String = "${human(bytesPerSecond)}/s"

    fun etaSeconds(remainingBytes: Long, bytesPerSecond: Long): Long {
        if (bytesPerSecond <= 0) return -1
        return (remainingBytes / bytesPerSecond).coerceAtLeast(0)
    }
}
