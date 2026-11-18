package com.adshield.pro.update

data class GitHubRelease(
    val tag: String,
    val name: String,
    val code: Int,
    val apk: String,
    val sha256: String,
    val notes: String
)

/** Validates metadata before offering a GitHub release as an in-app update. */
internal object GitHubReleaseMetadata {
    data class Asset(val name: String, val downloadUrl: String, val digest: String?)

    private val REPOSITORY = Regex("[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
    private val STABLE_TAG = Regex("""v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)""")
    private val SHA256 = Regex("[0-9a-fA-F]{64}")
    private val APK_FILE = Regex("""[A-Za-z0-9_.-]+\.[aA][pP][kK]""")
    private val SPLIT_ABI = Regex("""[-_](arm64[-_]?v8a|armeabi[-_]?v7a|x86|x86_64)(?=[-_.])""")
    private val TEST_APK = Regex("""(?:^|[-_.])test(?=[-_.])""")

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

    fun isInstallableReleaseApk(name: String): Boolean {
        val lower = name.lowercase()
        return name.matches(APK_FILE) && !lower.contains("debug") &&
            !SPLIT_ABI.containsMatchIn(lower) && !TEST_APK.containsMatchIn(lower)
    }

    private fun apkFileName(repository: String, tag: String, url: String): String? {
        // GitHub supplies a canonical HTTPS URL, not a URL template. Restrict the path to the
        // selected release tag and a single APK filename, without query/fragment/extra segments.
        val root = "https://github.com/"
        if (!url.startsWith(root)) return null
        val repoPrefix = "$repository/"
        val path = url.removePrefix(root)
        if (!path.startsWith(repoPrefix, ignoreCase = true)) return null
        val releasePrefix = "releases/download/$tag/"
        val releasePath = path.substring(repoPrefix.length)
        if (!releasePath.startsWith(releasePrefix)) return null
        return releasePath.substring(releasePrefix.length).takeIf(::isInstallableReleaseApk)
    }

    fun isTrustedApkUrl(repository: String, tag: String, url: String): Boolean =
        isRepository(repository) && versionCode(tag) != null && apkFileName(repository, tag, url) != null

    fun select(
        repository: String,
        tag: String,
        draft: Boolean,
        preRelease: Boolean,
        body: String?,
        assets: Sequence<Asset>
    ): GitHubRelease? {
        if (draft || preRelease || !isRepository(repository)) return null
        val code = versionCode(tag) ?: return null
        val name = tag.removePrefix("v")
        val notes = body.orEmpty().trim().take(1800).ifBlank { "Performance improvements and protection updates." }
        var fallback: GitHubRelease? = null
        for (asset in assets) {
            if (apkFileName(repository, tag, asset.downloadUrl) != asset.name) continue
            val digest = asset.digest ?: continue
            if (!digest.startsWith("sha256:", ignoreCase = true)) continue
            val sha256 = digest.substringAfter(':').takeIf(::isSha256)?.lowercase() ?: continue
            val release = GitHubRelease(tag, name, code, asset.downloadUrl, sha256, notes)
            if (asset.name.contains("release", true) || asset.name.contains("universal", true)) return release
            if (fallback == null) fallback = release
        }
        return fallback
    }
}
