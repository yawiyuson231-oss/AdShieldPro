package com.adshield.pro

import com.adshield.pro.engine.browser.PrivateSearch
import com.adshield.pro.engine.browser.SearchProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Private search contracts: provider selection must survive corrupt preferences, a search term
 * must never be able to inject extra query parameters, and address-vs-search resolution must be
 * predictable (an explicit http:// is never silently rewritten).
 */
class PrivateSearchTest {

    @Test
    fun providerLookup_isCaseInsensitiveAndTrimmed() {
        assertEquals(SearchProvider.GOOGLE, SearchProvider.fromName("google"))
        assertEquals(SearchProvider.GOOGLE, SearchProvider.fromName("  GOOGLE  "))
        assertEquals(SearchProvider.DUCKDUCKGO, SearchProvider.fromName("DuckDuckGo"))
    }

    @Test
    fun providerLookup_unknownOrMissingFallsBackToPrivacyDefault() {
        assertEquals(SearchProvider.DUCKDUCKGO, SearchProvider.fromName(null))
        assertEquals(SearchProvider.DUCKDUCKGO, SearchProvider.fromName(""))
        assertEquals(SearchProvider.DUCKDUCKGO, SearchProvider.fromName("bing"))
        assertEquals(SearchProvider.DUCKDUCKGO, SearchProvider.fromName("garbage-value"))
    }

    @Test
    fun everyProviderSearchesOverHttps() {
        SearchProvider.entries.forEach { provider ->
            assertTrue(
                "${provider.name} must search over HTTPS",
                PrivateSearch.isSecure(provider.searchUrl("test"))
            )
            assertTrue(
                "${provider.name} home must be HTTPS",
                PrivateSearch.isSecure(provider.homeUrl)
            )
        }
    }

    @Test
    fun searchUrl_encodesSpacesAsPercent20() {
        assertEquals(
            "https://duckduckgo.com/?q=privacy%20tools",
            SearchProvider.DUCKDUCKGO.searchUrl("privacy tools")
        )
        assertEquals(
            "https://www.google.com/search?q=privacy%20tools",
            SearchProvider.GOOGLE.searchUrl("privacy tools")
        )
    }

    @Test
    fun searchUrl_cannotInjectExtraQueryParameters() {
        val url = SearchProvider.DUCKDUCKGO.searchUrl("cats&safe=off&kp=-2")
        assertEquals("https://duckduckgo.com/?q=cats%26safe%3Doff%26kp%3D-2", url)
        // Exactly one '?' and no unescaped '&' — the term stayed inside the q value.
        assertEquals(1, url.count { it == '?' })
        assertFalse(url.contains('&'))
    }

    @Test
    fun searchUrl_escapesReservedCharacters() {
        val url = SearchProvider.GOOGLE.searchUrl("a+b=c?d#e/f%g")
        assertEquals("https://www.google.com/search?q=a%2Bb%3Dc%3Fd%23e%2Ff%25g", url)
    }

    @Test
    fun searchUrl_encodesUtf8PerByte() {
        // "é" = C3 A9, "日" = E6 97 A5
        assertEquals("https://duckduckgo.com/?q=caf%C3%A9", SearchProvider.DUCKDUCKGO.searchUrl("café"))
        assertEquals("https://duckduckgo.com/?q=%E6%97%A5", SearchProvider.DUCKDUCKGO.searchUrl("日"))
    }

    @Test
    fun searchUrl_keepsUnreservedCharactersReadable() {
        assertEquals(
            "https://duckduckgo.com/?q=aZ09-_.~",
            SearchProvider.DUCKDUCKGO.searchUrl("aZ09-_.~")
        )
    }

    @Test
    fun searchUrl_trimsAndDoesNotDoubleEncode() {
        assertEquals(
            "https://duckduckgo.com/?q=already%20encoded",
            SearchProvider.DUCKDUCKGO.searchUrl("  already encoded  ")
        )
        // A literal percent in the term is escaped once, not treated as an existing escape.
        assertEquals(
            "https://duckduckgo.com/?q=100%25",
            SearchProvider.DUCKDUCKGO.searchUrl("100%")
        )
    }

    @Test
    fun emptyInputGoesToSelectedProviderHome() {
        assertEquals(SearchProvider.DUCKDUCKGO.homeUrl, PrivateSearch.resolveInput("", SearchProvider.DUCKDUCKGO))
        assertEquals(SearchProvider.GOOGLE.homeUrl, PrivateSearch.resolveInput("   ", SearchProvider.GOOGLE))
    }

    @Test
    fun explicitHttpsIsPreservedExactly() {
        val url = "https://example.com/path?a=1"
        assertEquals(url, PrivateSearch.resolveInput(url, SearchProvider.GOOGLE))
    }

    @Test
    fun explicitHttpIsNotSilentlyRewritten() {
        // Rewriting would break HTTP-only hosts such as local router admin pages.
        val url = "http://192.168.1.1/admin"
        assertEquals(url, PrivateSearch.resolveInput(url, SearchProvider.DUCKDUCKGO))
        assertFalse(PrivateSearch.isSecure(url))
    }

    @Test
    fun bareHostIsUpgradedToHttps() {
        assertEquals("https://example.com", PrivateSearch.resolveInput("example.com", SearchProvider.GOOGLE))
        assertEquals(
            "https://example.com/a/b",
            PrivateSearch.resolveInput("  example.com/a/b  ", SearchProvider.DUCKDUCKGO)
        )
    }

    @Test
    fun plainTermsBecomeProviderSearches() {
        assertEquals(
            "https://www.google.com/search?q=android%20permissions",
            PrivateSearch.resolveInput("android permissions", SearchProvider.GOOGLE)
        )
        assertEquals(
            "https://duckduckgo.com/?q=stalkerware",
            PrivateSearch.resolveInput("stalkerware", SearchProvider.DUCKDUCKGO)
        )
    }

    @Test
    fun switchingProviderChangesOnlyTheSearchEndpoint() {
        val term = "threat report"
        val ddg = PrivateSearch.resolveInput(term, SearchProvider.DUCKDUCKGO)
        val google = PrivateSearch.resolveInput(term, SearchProvider.GOOGLE)
        assertTrue(ddg.startsWith("https://duckduckgo.com/?q="))
        assertTrue(google.startsWith("https://www.google.com/search?q="))
        assertEquals(ddg.substringAfter("?q="), google.substringAfter("?q="))
    }

    @Test
    fun addressDetectionMatchesTheDocumentedRule() {
        assertTrue(PrivateSearch.looksLikeAddress("example.com"))
        assertTrue(PrivateSearch.looksLikeAddress("https://example.com"))
        assertTrue(PrivateSearch.looksLikeAddress("http://example.com"))
        assertFalse(PrivateSearch.looksLikeAddress("two words.com"))
        assertFalse(PrivateSearch.looksLikeAddress("nodots"))
        assertFalse(PrivateSearch.looksLikeAddress(""))
        assertFalse(PrivateSearch.looksLikeAddress("   "))
    }

    @Test
    fun providerLabelsAndPrivacyNotesArePresentAndHonest() {
        SearchProvider.entries.forEach { provider ->
            assertTrue(provider.label.isNotBlank())
            assertTrue(provider.privacyNote.isNotBlank())
        }
        assertTrue(
            "Google's note must disclose that the query is not anonymous",
            SearchProvider.GOOGLE.privacyNote.contains("not anonymous")
        )
    }
}
