package com.adshield.pro.engine.evolution

/** Advisory text only. Never changes the local scan score, level, quarantine or DNS decisions. */
internal object EvolutionAdvisoryText {
    data class Result(val finding: String? = null, val limitation: String? = null)
    fun evaluate(enabled: Boolean, sha256: String?, lookup: (String) -> String?): Result {
        if (!enabled) return Result()
        if (sha256 == null) return Result(limitation = "Publisher reputation unavailable: no complete file fingerprint.")
        return try {
            val category = lookup(sha256)
            if (category == null) Result(limitation = "No active publisher reputation match. This does not establish safety.")
            else {
                require(category in setOf("malware", "phishing", "unwanted"))
                Result(finding = "Signed publisher advisory: this exact APK hash is labeled '$category'. Review independently; this advisory does not change the local verdict.")
            }
        } catch (cancelled: java.util.concurrent.CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            Result(limitation = "Publisher reputation unavailable, expired or invalid. Local scanning still ran; safety is not established.")
        }
    }
}
