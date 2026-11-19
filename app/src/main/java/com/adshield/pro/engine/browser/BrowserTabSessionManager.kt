package com.adshield.pro.engine.browser

import java.net.URI
import java.util.Locale

/**
 * Multi-Tab Isolated Session Manager & HTTPS-First Navigation Guard for the Privacy Browser.
 *
 * Pure, deterministic state holder so tab lifecycle, bounds (`MAX_TABS = 12`), private-tab markers,
 * and automatic cleartext `http://` -> `https://` upgrades are 100% JVM unit-testable.
 */
object BrowserTabSessionManager {

    const val MAX_TABS = 12

    data class BrowserTab(
        val id: Long,
        val title: String,
        val url: String,
        val isPrivate: Boolean = false,
        val httpsUpgradesCount: Int = 0
    )

    data class TabDeckState(
        val tabs: List<BrowserTab>,
        val activeTabId: Long,
        val nextId: Long
    ) {
        val activeTab: BrowserTab
            get() = tabs.firstOrNull { it.id == activeTabId } ?: tabs.first()
    }

    fun createInitialState(homeUrl: String, isPrivateDefault: Boolean = false): TabDeckState {
        val initial = BrowserTab(
            id = 1L,
            title = hostOrTitle(homeUrl),
            url = homeUrl,
            isPrivate = isPrivateDefault
        )
        return TabDeckState(
            tabs = listOf(initial),
            activeTabId = 1L,
            nextId = 2L
        )
    }

    fun openNewTab(
        state: TabDeckState,
        url: String,
        isPrivate: Boolean = false
    ): TabDeckState {
        val trimmedList = if (state.tabs.size >= MAX_TABS) {
            state.tabs.drop(1)
        } else {
            state.tabs
        }
        val tab = BrowserTab(
            id = state.nextId,
            title = hostOrTitle(url),
            url = url,
            isPrivate = isPrivate
        )
        return TabDeckState(
            tabs = trimmedList + tab,
            activeTabId = tab.id,
            nextId = state.nextId + 1L
        )
    }

    fun closeTab(state: TabDeckState, tabId: Long, fallbackHomeUrl: String): TabDeckState {
        val remaining = state.tabs.filterNot { it.id == tabId }
        if (remaining.isEmpty()) {
            val fresh = BrowserTab(
                id = state.nextId,
                title = hostOrTitle(fallbackHomeUrl),
                url = fallbackHomeUrl,
                isPrivate = state.activeTab.isPrivate
            )
            return TabDeckState(
                tabs = listOf(fresh),
                activeTabId = fresh.id,
                nextId = state.nextId + 1L
            )
        }
        val nextActive = if (state.activeTabId == tabId) remaining.last().id else state.activeTabId
        return state.copy(tabs = remaining, activeTabId = nextActive)
    }

    fun selectTab(state: TabDeckState, tabId: Long): TabDeckState =
        if (state.tabs.any { it.id == tabId }) state.copy(activeTabId = tabId) else state

    fun updateActiveTabUrl(
        state: TabDeckState,
        newUrl: String,
        newTitle: String? = null,
        wasHttpsUpgraded: Boolean = false
    ): TabDeckState {
        val updated = state.tabs.map { tab ->
            if (tab.id == state.activeTabId) {
                tab.copy(
                    url = newUrl,
                    title = newTitle?.takeIf { it.isNotBlank() } ?: hostOrTitle(newUrl),
                    httpsUpgradesCount = tab.httpsUpgradesCount + if (wasHttpsUpgraded) 1 else 0
                )
            } else {
                tab
            }
        }
        return state.copy(tabs = updated)
    }

    /**
     * Upgrades cleartext `http://` navigations to `https://` when [httpsFirstEnabled] is true,
     * excluding loopback (`localhost`, `127.0.0.1`), `.onion` services, and RFC 1918 LAN literals
     * where local routers/admin panels commonly lack public TLS certificates.
     */
    fun applyHttpsFirstPolicy(rawUrl: String, httpsFirstEnabled: Boolean): Pair<String, Boolean> {
        val trimmed = rawUrl.trim()
        if (!httpsFirstEnabled || !trimmed.startsWith("http://", ignoreCase = true)) {
            return trimmed to false
        }
        val uri = runCatching { URI(trimmed) }.getOrNull() ?: return trimmed to false
        val host = uri.host?.lowercase(Locale.US)?.trimEnd('.') ?: return trimmed to false
        if (isExemptCleartextHost(host)) {
            return trimmed to false
        }
        if (uri.port != -1 && uri.port != 80) {
            return trimmed to false
        }
        val upgraded = "https://" + trimmed.substring("http://".length)
        return upgraded to true
    }

    private fun isExemptCleartextHost(host: String): Boolean {
        if (host == "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".onion")) {
            return true
        }
        if (host.startsWith("127.") || host.startsWith("10.") || host.startsWith("192.168.") || host.startsWith("169.254.")) {
            return true
        }
        if (host.startsWith("172.")) {
            val second = host.split('.').getOrNull(1)?.toIntOrNull()
            if (second != null && second in 16..31) return true
        }
        return false
    }

    private fun hostOrTitle(url: String): String {
        val host = runCatching { URI(url).host }.getOrNull()?.removePrefix("www.")
        return host?.takeIf { it.isNotBlank() } ?: "New Tab"
    }
}
