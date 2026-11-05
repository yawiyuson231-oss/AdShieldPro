package com.adshield.pro.cloud

/**
 * AdShield Pro — cloud storage configuration.
 *
 * Budget rule: $0. The default backend is a Cloudflare Worker (free tier: 100k requests/day)
 * backed by R2 (free tier: 10 GB storage, 1M Class A ops/month) and D1 (free tier: 5M rows read/
 * day, 100k writes/day). No paid service is required and the app never auto-upgrades anything.
 *
 * The endpoint URL is NOT hardcoded to a service this project does not operate. The user points
 * the app at their own free-tier Worker (see cloud-worker/README.md). Until a valid HTTPS Worker
 * URL is configured, every cloud screen shows an honest "backend not configured" state — nothing
 * is simulated.
 */
object CloudConfig {

    /**
     * Default Worker base URL. Empty means "not configured" — the app will refuse cloud calls
     * and show the setup instructions instead of pretending to work.
     */
    const val DEFAULT_API_BASE_URL: String = ""

    /** Hard cap we enforce client-side regardless of what the server reports. */
    const val CLIENT_SIDE_MAX_FILE_BYTES: Long = 1_073_741_824L // 1 GiB per file

    /** Upload chunk size for multipart uploads (5 MiB, R2/S3 minimum part size). */
    const val UPLOAD_CHUNK_BYTES: Long = 5L * 1024L * 1024L

    /** Signed content URLs issued by the Worker must not outlive this window. */
    const val MAX_SIGNED_URL_TTL_SECONDS: Long = 900L // 15 minutes

    /** R2 free-tier storage allowance, used for the "provider quota" display. */
    const val R2_FREE_TIER_BYTES: Long = 10L * 1024L * 1024L * 1024L // 10 GB

    /** Per-user quota enforced by the Worker (D1 row). Default free allowance. */
    const val DEFAULT_USER_QUOTA_BYTES: Long = R2_FREE_TIER_BYTES

    /** Warn the user when usage crosses this fraction of the quota. */
    const val QUOTA_WARNING_FRACTION: Float = 0.80f

    /** Block new uploads when usage crosses this fraction of the quota. */
    const val QUOTA_BLOCK_FRACTION: Float = 0.95f

    /** Only https:// endpoints are accepted; the manifest already forbids cleartext. */
    fun isValidApiBaseUrl(raw: String): Boolean {
        val trimmed = raw.trim().lowercase()
        return trimmed.startsWith("https://") && trimmed.length > "https://".length &&
            !trimmed.contains(' ') && !trimmed.endsWith("/")
    }
}
