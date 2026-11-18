package com.adshield.pro.engine.aether

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import java.net.URI
import java.util.Locale
import java.util.UUID

internal enum class AetherOnlineProvider(val label: String, val defaultModel: String = "") {
    GEMINI("Google Gemini", "gemini-3.5-flash-lite"),
    OPENAI("OpenAI"),
    COMPATIBLE("Other compatible API")
}

internal enum class AetherChatLimit(val parameter: String) {
    MAX_TOKENS("max_tokens"), MAX_COMPLETION_TOKENS("max_completion_tokens")
}

/** Public details for consent. The revision also binds a review to a specific saved key. */
internal data class AetherOnlineEndpoint(
    val provider: AetherOnlineProvider,
    val url: String,
    val model: String,
    val chatLimit: AetherChatLimit,
    val revision: String?
)

internal class AetherOnlineConfig private constructor(val endpoint: AetherOnlineEndpoint, val token: String) {
    // Don't turn this into a data class: its default toString would include the key.
    class Input(
        val provider: AetherOnlineProvider,
        val url: String,
        val model: String,
        val token: String,
        val chatLimit: AetherChatLimit = AetherChatLimit.MAX_TOKENS
    )

    sealed interface Validation {
        data class Ready(val config: AetherOnlineConfig) : Validation
        data class Invalid(val issue: Issue) : Validation
    }

    enum class Issue(val message: String) {
        KEY("Paste just the API key or bearer token, without quotes or extra text."),
        MODEL("Enter a text model ID from your provider (not an API key or a URL)."),
        GEMINI_MODEL("Enter a Gemini model ID, such as gemini-3.5-flash-lite, not a URL."),
        URL("Enter the provider’s HTTPS base URL or full /chat/completions URL, without a key or query string.")
    }

    fun encodeForVault(): String = buildJsonObject {
        put("provider", endpoint.provider.name)
        put("endpoint", endpoint.url)
        put("model", endpoint.model)
        put("chatLimit", endpoint.chatLimit.name)
        put("revision", endpoint.revision)
        put("token", token)
    }.toString()

    companion object {
        const val OPENAI_URL = "https://api.openai.com/v1/chat/completions"
        const val GEMINI_HOST = "https://generativelanguage.googleapis.com"
        const val MAX_ENDPOINT_CHARS = 512
        const val MAX_MODEL_CHARS = 128
        const val MAX_KEY_CHARS = 1_024
        private const val CHAT_PATH = "/chat/completions"
        private val modelName = Regex("[A-Za-z0-9._:/@-]{1,$MAX_MODEL_CHARS}")
        private val geminiName = Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,${MAX_MODEL_CHARS - 1}}")
        private val path = Regex("(?:/[A-Za-z0-9_.~-]+)*/?")
        private val nonBaseSegments = setOf("models", "responses", "messages", "chat", "completions")

        fun validate(input: Input): Validation = validate(input, UUID.randomUUID().toString(), allowBaseUrl = true)

        private fun validate(input: Input, revision: String?, allowBaseUrl: Boolean): Validation {
            val key = input.token.trim()
            // Accept opaque gateway tokens as well as provider keys. Use only visible ASCII in
            // the header, with no spaces, quotes, escapes or control characters.
            if (key.length !in 1..MAX_KEY_CHARS || "://" in key ||
                key.any { it !in '!'..'~' || it == '"' || it == '\'' || it == '\\' }
            ) {
                return Validation.Invalid(Issue.KEY)
            }
            val typedModel = input.model.trim()
            val model = if (input.provider == AetherOnlineProvider.GEMINI) typedModel.removePrefix("models/") else typedModel
            val modelSyntax = if (input.provider == AetherOnlineProvider.GEMINI) geminiName else modelName
            if (!modelSyntax.matches(model) || model == key || "://" in model) {
                return Validation.Invalid(if (input.provider == AetherOnlineProvider.GEMINI) Issue.GEMINI_MODEL else Issue.MODEL)
            }
            val url = when (input.provider) {
                AetherOnlineProvider.GEMINI -> "$GEMINI_HOST/v1beta/models/$model:generateContent"
                    .takeIf { input.url.isBlank() || input.url == it }
                AetherOnlineProvider.OPENAI -> OPENAI_URL.takeIf { input.url.isBlank() || input.url == it }
                AetherOnlineProvider.COMPATIBLE -> compatibleUrl(input.url, allowBaseUrl)
            } ?: return Validation.Invalid(Issue.URL)
            if (key.length >= 8 && (key in url || key in model)) return Validation.Invalid(Issue.KEY)
            val chatLimit = when (input.provider) {
                AetherOnlineProvider.GEMINI -> AetherChatLimit.MAX_TOKENS // Not used by the native protocol.
                AetherOnlineProvider.OPENAI -> AetherChatLimit.MAX_COMPLETION_TOKENS
                AetherOnlineProvider.COMPATIBLE -> input.chatLimit
            }
            return Validation.Ready(AetherOnlineConfig(AetherOnlineEndpoint(input.provider, url, model, chatLimit, revision), key))
        }

        /** Accept base and full URLs on setup, but always save and review the actual POST URL. */
        private fun compatibleUrl(raw: String, allowBase: Boolean): String? {
            val trimmed = raw.trim()
            if (trimmed.length > MAX_ENDPOINT_CHARS) return null
            val uri = runCatching { URI(trimmed) }.getOrNull() ?: return null
            val host = uri.host?.lowercase(Locale.ROOT) ?: return null
            if (!uri.scheme.equals("https", ignoreCase = true) || uri.rawUserInfo != null ||
                uri.rawQuery != null || uri.rawFragment != null || (uri.port != -1 && uri.port !in 1..65_535) ||
                !path.matches(uri.rawPath.orEmpty()) || uri.normalize() != uri
            ) return null
            val prefix = uri.rawPath.orEmpty().trimEnd('/')
            if (!prefix.endsWith(CHAT_PATH) &&
                (!allowBase || prefix.substringAfterLast('/').lowercase(Locale.ROOT) in nonBaseSegments || "$CHAT_PATH/" in prefix)
            ) return null
            val base = prefix.removeSuffix(CHAT_PATH)
            if (base.split('/').any { it == "." || it == ".." }) return null
            val port = if (uri.port == -1 || uri.port == 443) "" else ":${uri.port}"
            // Use the same canonical URL as the transport (including literal IPv6 spelling).
            return "https://$host$port$base$CHAT_PATH".toHttpUrlOrNull()?.toString()?.takeIf { it.length <= MAX_ENDPOINT_CHARS }
        }

        /** Existing endpoint/model/token records are read without deleting their encrypted data. */
        fun decodeFromVault(encoded: String): AetherOnlineConfig? {
            if (encoded.length > 8_192) return null
            val fields = runCatching { Json.parseToJsonElement(encoded) as? JsonObject }.getOrNull() ?: return null
            val storedUrl = fields.text("endpoint") ?: return null
            val model = fields.text("model") ?: return null
            val key = fields.text("token") ?: return null
            if ("provider" !in fields) {
                // Retain the old wire format even for an OpenAI URL. A working legacy model may
                // require system messages or max_tokens. Users can select the new preset explicitly.
                val legacy = Input(AetherOnlineProvider.COMPATIBLE, storedUrl, model, key)
                return (validate(legacy, revision = null, allowBaseUrl = false) as? Validation.Ready)?.config
            }
            val provider = AetherOnlineProvider.entries.firstOrNull { it.name == fields.text("provider") } ?: return null
            val chatLimit = AetherChatLimit.entries.firstOrNull { it.name == fields.text("chatLimit") } ?: return null
            val revision = fields.text("revision") ?: return null
            if (runCatching { UUID.fromString(revision).toString() }.getOrNull() != revision) return null
            val config = (validate(Input(provider, storedUrl, model, key, chatLimit), revision, allowBaseUrl = false)
                as? Validation.Ready)?.config
            return config?.takeIf { it.endpoint.url == storedUrl }
        }
    }
}
