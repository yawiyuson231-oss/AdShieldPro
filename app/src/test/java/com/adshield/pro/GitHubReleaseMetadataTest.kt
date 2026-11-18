package com.adshield.pro

import com.adshield.pro.update.GitHubReleaseMetadata
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class GitHubReleaseMetadataTest {
    private val repo = "example/AdShieldPro"
    private val tag = "v2.11.1"
    private val apkName = "AdShieldPro-2.11.1-release.apk"
    private val url = "https://github.com/$repo/releases/download/$tag/$apkName"
    private val valid = GitHubReleaseMetadata.Asset(apkName, url, "sha256:${"ab".repeat(32)}")

    @Test
    fun refusesPartialOrOverflowingVersionTags() {
        for (invalid in listOf("test-v2.11.1", "v2.11.1-rc2", "v2.11.1.2", "v2.011.1", "v2.100.0", "v214748.36.48", "v0.0.0")) {
            assertNull(GitHubReleaseMetadata.versionCode(invalid))
        }
        assertEquals(21_101, GitHubReleaseMetadata.versionCode(tag))
        assertEquals(21_101, GitHubReleaseMetadata.versionCode("2.11.1"))
    }

    @Test
    fun refusesDraftAndPrereleaseEvenWithValidAssets() {
        assertNull(GitHubReleaseMetadata.select(repo, tag, true, false, null, sequenceOf(valid)))
        assertNull(GitHubReleaseMetadata.select(repo, tag, false, true, null, sequenceOf(valid)))
    }

    @Test
    fun requiresWellFormedSha256AndSkipsAnUnverifiedCandidate() {
        for (digest in listOf(null, "", "sha256:123", "sha256:${"xy".repeat(32)}", "sha512:${"ab".repeat(64)}")) {
            assertNull(select(valid.copy(digest = digest)))
        }
        val unavailable = "app-release.apk"
        val invalid = GitHubReleaseMetadata.Asset(unavailable, url.substringBeforeLast('/') + "/$unavailable", null)
        assertEquals(url, select(invalid, valid)?.apk)
    }

    @Test
    fun refusesAssetFromDifferentRepositoryTagOrFilename() {
        assertNull(select(valid.copy(downloadUrl = url.replace(repo, "example/DifferentApp"))))
        assertNull(select(valid.copy(downloadUrl = url.replace("/$tag/", "/v2.11.0/"))))
        assertNull(select(valid.copy(name = "app-release.apk")))
        assertEquals(url, select(valid)?.apk)
    }

    private fun select(vararg assets: GitHubReleaseMetadata.Asset) =
        GitHubReleaseMetadata.select(repo, tag, false, false, null, assets.asSequence())
}
