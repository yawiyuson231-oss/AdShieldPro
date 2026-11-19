package com.adshield.pro.update

data class GitHubRelease(
    val tag: String,
    val name: String,
    val code: Int,
    val apk: String,
    val sha256: String,
    val notes: String
)

/** Only releases for AdShield Pro Secure can update the replacement app. */
internal object GitHubReleaseMetadata {
    data class Asset(val name: String, val downloadUrl: String, val digest: String?)

    private const val TAG_PREFIX = "secure-v"
    private val REPOSITORY = Regex("[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
    private val STABLE_TAG = Regex("""$TAG_PREFIX(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)""")
    private val SHA256 = Regex("[0-9a-fA-F]{64}")

    fun isRepository(value: String): Boolean = value.matches(REPOSITORY) &&
        value.split('/').none { it == "." || it == ".." }

    fun versionCode(tag: String): Int? {
        val version = STABLE_TAG.matchEntire(tag) ?: return null
        val major = version.groupValues[1].toIntOrNull() ?: return null
        val minor = version.groupValues[2].toIntOrNull() ?: return null
        val patch = version.groupValues[3].toIntOrNull() ?: return null
        if (minor > 99 || patch > 99) return null
        val code = major * 10_000L + minor * 100 + patch
        return code.takeIf { it in 1L..Int.MAX_VALUE.toLong() }?.toInt()
    }

    fun isSha256(value: String): Boolean = value.matches(SHA256)

    private fun apkName(tag: String): String = "AdShieldPro-Secure-${tag.removePrefix(TAG_PREFIX)}-release.apk"

    fun isTrustedApkUrl(repository: String, tag: String, url: String): Boolean {
        if (!isRepository(repository) || versionCode(tag) == null) return false
        val root = "https://github.com/"
        if (!url.startsWith(root)) return false
        val repoPrefix = "$repository/"
        val path = url.removePrefix(root)
        return path.startsWith(repoPrefix, ignoreCase = true) &&
            path.substring(repoPrefix.length) == "releases/download/$tag/${apkName(tag)}"
    }

    fun select(
        repository: String,
        tag: String,
        draft: Boolean,
        preRelease: Boolean,
        body: String?,
        assets: Sequence<Asset>
    ): GitHubRelease? {
        // GitHub's pre-release flag intentionally keeps this separate identity off the
        // legacy app's /releases/latest route. Only the exact secure-v* channel is supported.
        if (draft || !preRelease || !isRepository(repository)) return null
        val code = versionCode(tag) ?: return null
        val name = tag.removePrefix(TAG_PREFIX)
        val asset = assets.singleOrNull { it.name == apkName(tag) } ?: return null
        if (!isTrustedApkUrl(repository, tag, asset.downloadUrl)) return null
        val digest = asset.digest ?: return null
        if (!digest.startsWith("sha256:", ignoreCase = true)) return null
        val sha = digest.substringAfter(':').takeIf(::isSha256)?.lowercase() ?: return null
        val notes = body.orEmpty().trim().take(1800).ifBlank { "Performance improvements and protection updates." }
        return GitHubRelease(tag, name, code, asset.downloadUrl, sha, notes)
    }
}
