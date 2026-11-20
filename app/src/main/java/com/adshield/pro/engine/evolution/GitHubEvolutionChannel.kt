package com.adshield.pro.engine.evolution

import java.net.URI
import java.net.URL

/** Dedicated data tag; never use releases/latest, which is reserved for app releases. */
internal object GitHubEvolutionChannel {
    const val REPOSITORY = "yawiyuson231-oss/AdShieldPro"
    const val ASSET_PATH = "/$REPOSITORY/releases/download/evolution-data/reputation.evo"
    const val ENDPOINT = "https://github.com$ASSET_PATH"
    private val cdnHosts = setOf("release-assets.githubusercontent.com", "objects.githubusercontent.com")

    fun validateEndpoint(url: URL) {
        requireSafeHttps(url)
        if (url.host.equals("github.com", ignoreCase = true)) {
            require(url.path == ASSET_PATH && url.query == null) { "Not the pinned evolution channel" }
        } else {
            // Other HTTPS publishers are supported, but they cannot redirect to GitHub CDNs.
            require(url.query == null)
        }
    }

    fun redirect(initial: URL, current: URL, location: String, redirectsSoFar: Int): URL {
        require(redirectsSoFar in 0..2) { "Too many redirects" }
        validateEndpoint(initial)
        require(initial.toExternalForm() == ENDPOINT) { "Redirects require the pinned GitHub channel" }
        requireSafeHttps(current)
        require(current.toExternalForm() == ENDPOINT || current.host in cdnHosts)
        require(location.length in 1..8192)
        val next = URI(current.toExternalForm()).resolve(location).toURL()
        requireSafeHttps(next)
        require(next.host in cdnHosts) { "Unapproved asset host" }
        require(next.path.isNotBlank() && next.path != "/")
        return next
    }

    private fun requireSafeHttps(url: URL) {
        require(url.protocol == "https" && url.host.isNotBlank())
        require(url.port == -1 || url.port == 443)
        require(url.userInfo == null && url.ref == null)
    }
}
