package com.adshield.pro.cloud

/**
 * Pure quota logic for the free-tier cloud storage. No Android types — fully covered by the
 * JVM test suite. The rules:
 *
 *  - never claim more capacity than the server reported;
 *  - warn at 80% usage, hard-block new uploads at 95%;
 *  - never auto-switch to paid infrastructure — there is no code path that does.
 */
object QuotaManager {

    enum class QuotaState { OK, WARNING, BLOCKED, UNKNOWN }

    fun stateFor(usedBytes: Long, quotaBytes: Long): QuotaState {
        if (quotaBytes <= 0L) return QuotaState.UNKNOWN
        val fraction = usedBytes.toDouble() / quotaBytes.toDouble()
        return when {
            fraction >= CloudConfig.QUOTA_BLOCK_FRACTION -> QuotaState.BLOCKED
            fraction >= CloudConfig.QUOTA_WARNING_FRACTION -> QuotaState.WARNING
            else -> QuotaState.OK
        }
    }

    /**
     * Whether an upload of [incomingBytes] may start. Returns a human-readable reason when not,
     * so the UI can show the real cause instead of a generic failure.
     */
    fun canUpload(incomingBytes: Long, usedBytes: Long, quotaBytes: Long): Result<Unit> {
        if (incomingBytes <= 0L) return Result.failure(IllegalArgumentException("Empty files are not uploaded."))
        if (incomingBytes > CloudConfig.CLIENT_SIDE_MAX_FILE_BYTES) {
            return Result.failure(IllegalStateException("File exceeds the 1 GiB per-file limit."))
        }
        if (quotaBytes <= 0L) {
            return Result.failure(IllegalStateException("Server did not report a quota; refusing to guess."))
        }
        val remaining = quotaBytes - usedBytes
        if (incomingBytes > remaining) {
            return Result.failure(
                IllegalStateException(
                    "Not enough cloud storage: ${formatBytes(incomingBytes)} needed, ${formatBytes(remaining.coerceAtLeast(0))} left."
                )
            )
        }
        if (stateFor(usedBytes + incomingBytes, quotaBytes) == QuotaState.BLOCKED) {
            return Result.failure(IllegalStateException("Upload would cross the 95% quota guard. Free more space first."))
        }
        return Result.success(Unit)
    }

    fun formatBytes(bytes: Long): String {
        if (bytes < 0) return "0 B"
        val units = arrayOf("B", "KB", "MB", "GB", "TB")
        var value = bytes.toDouble()
        var unit = 0
        while (value >= 1024.0 && unit < units.lastIndex) {
            value /= 1024.0
            unit++
        }
        return if (unit == 0) "${bytes} B" else "%.1f %s".format(value, units[unit])
    }
}
