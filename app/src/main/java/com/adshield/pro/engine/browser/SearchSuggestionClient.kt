package com.adshield.pro.engine.browser

import com.adshield.pro.domain.model.SearchProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import javax.inject.Singleton

/** Optional provider suggestions. Enabling this sends the typed query to the selected provider. */
@Singleton
class SearchSuggestionClient @Inject constructor() {
    private val json = Json { ignoreUnknownKeys = true }
    private val client = OkHttpClient.Builder()
        .connectTimeout(4, TimeUnit.SECONDS)
        .readTimeout(4, TimeUnit.SECONDS)
        .build()

    suspend fun fetch(query: String, provider: SearchProvider): List<String> = withContext(Dispatchers.IO) {
        val trimmed = query.trim()
        if (trimmed.length < 2) return@withContext emptyList()
        val endpoint = when (provider) {
            SearchProvider.DUCKDUCKGO -> "https://duckduckgo.com/ac/".toHttpUrl().newBuilder()
                .addQueryParameter("q", trimmed)
                .addQueryParameter("type", "list")
                .build()
            SearchProvider.GOOGLE -> "https://suggestqueries.google.com/complete/search".toHttpUrl().newBuilder()
                .addQueryParameter("client", "firefox")
                .addQueryParameter("q", trimmed)
                .build()
        }
        client.newCall(
            Request.Builder().url(endpoint).header("Accept", "application/json").build()
        ).execute().use { response ->
            if (!response.isSuccessful) return@withContext emptyList()
            val root = runCatching {
                json.parseToJsonElement(response.body?.string() ?: return@withContext emptyList())
            }.getOrElse { return@withContext emptyList() }
            val candidates = when (provider) {
                SearchProvider.DUCKDUCKGO -> (root as? JsonArray)?.mapNotNull { item ->
                    ((item as? JsonObject)?.get("phrase") as? JsonPrimitive)?.content
                }.orEmpty()
                SearchProvider.GOOGLE -> ((root as? JsonArray)?.getOrNull(1) as? JsonArray)?.mapNotNull { item ->
                    (item as? JsonPrimitive)?.content
                }.orEmpty()
            }
            candidates.map { it.trim() }
                .filter { it.isNotEmpty() }
                .distinct()
                .take(8)
                .map { it.take(200) }
        }
    }
}
