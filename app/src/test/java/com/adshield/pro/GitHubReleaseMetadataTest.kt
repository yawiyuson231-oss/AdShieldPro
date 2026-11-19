package com.adshield.pro

import com.adshield.pro.update.GitHubReleaseMetadata
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class GitHubReleaseMetadataTest {
    private val repo = "example/AdShieldPro"
    private val tag = "secure-v2.11.1"
    private val apkName = "AdShieldPro-Secure-2.11.1-release.apk"
    private val url = "https://github.com/$repo/releases/download/$tag/$apkName"
    private val valid = GitHubReleaseMetadata.Asset(apkName, url, "sha256:${"ab".repeat(32)}")

    @Test
    fun refusesLegacyPreviewCandidateAndInvalidSecureTags() {
        for (invalid in listOf("v2.11.1", "preview-v2.11.1-run.123.1", "test-secure-v2.11.1", "secure-v2.11.1-rc2",
            "secure-v2.11.1.2", "secure-v2.011.1", "secure-v2.100.0", "secure-v214748.36.48", "secure-v0.0.0")) {
            assertNull(GitHubReleaseMetadata.versionCode(invalid))
            assertNull(GitHubReleaseMetadata.select(repo, invalid, false, true, null, sequenceOf(valid)))
        }
        assertEquals(21_101, GitHubReleaseMetadata.versionCode(tag))
    }

    @Test
    fun refusesDraftAndNonIsolatedSecureReleaseEvenWithValidAssets() {
        assertNull(GitHubReleaseMetadata.select(repo, tag, true, true, null, sequenceOf(valid)))
        assertNull(GitHubReleaseMetadata.select(repo, tag, false, false, null, sequenceOf(valid)))
    }

    @Test
    fun requiresWellFormedSha256AndRejectsAmbiguousAssets() {
        for (digest in listOf(null, "", "sha256:123", "sha256:${"xy".repeat(32)}", "sha512:${"ab".repeat(64)}")) {
            assertNull(select(valid.copy(digest = digest)))
        }
        assertNull(select(valid, valid.copy(digest = "sha256:${"cd".repeat(32)}")))
        assertEquals(url, select(valid)?.apk)
    }

    @Test
    fun refusesAssetFromDifferentRepositoryTagOrFilename() {
        assertNull(select(valid.copy(downloadUrl = url.replace(repo, "example/DifferentApp"))))
        assertNull(select(valid.copy(downloadUrl = url.replace("/$tag/", "/secure-v2.11.0/"))))
        assertNull(select(valid.copy(name = "AdShieldPro-2.11.1-release.apk")))
        assertEquals(url, select(valid)?.apk)
    }

    private fun select(vararg assets: GitHubReleaseMetadata.Asset) =
        GitHubReleaseMetadata.select(repo, tag, false, true, null, assets.asSequence())
}
