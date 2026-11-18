package com.adshield.pro.engine.aether

import com.adshield.pro.engine.aether.AetherOnlineResult.Problem
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import java.text.Normalizer
import java.util.concurrent.atomic.AtomicBoolean

/** Only a reviewed, short task description can be sent. The link-scanner field is never attached. */
internal class AetherOnlinePrompt private constructor(val text: String) {
    companion object {
        const val CONNECTION_TEST = "Audit my installed apps"
        // Catch common pasted web addresses, email addresses and IP literals. This is not a complete
        // secret detector: the user also reviews the exact text and can choose offline instead.
        private val address = Regex(
            """(?i)://|@|(?:[\p{L}0-9-]+\.)+[\p{L}]{2,}|(?:[0-9]{1,3}\.){3}[0-9]{1,3}|[0-9a-f:]*::[0-9a-f:]+|(?:[0-9a-f]{1,4}:){2,}"""
        )

        fun create(request: String): AetherOnlinePrompt? {
            if (request.length > AetherTaskModel.MAX_REQUEST_CHARS) return null
            val text = request.trim()
            if (text.isEmpty() || text.any {
                    (it.isISOControl() && it != '\n') || Character.getType(it) == Character.FORMAT.toInt()
                } ||
                address.containsMatchIn(Normalizer.normalize(text, Normalizer.Form.NFKC))
            ) return null
            return AetherOnlinePrompt(text)
        }
    }
}

/** Distinct from task approval: accepting this review only permits sending text to the named endpoint. */
internal class AetherOnlineApproval {
    data class Review(val id: Long, val endpoint: AetherOnlineEndpoint, val prompt: AetherOnlinePrompt, val test: Boolean)
    class Approved internal constructor(val endpoint: AetherOnlineEndpoint, val prompt: AetherOnlinePrompt, val test: Boolean) {
        private val used = AtomicBoolean(false)

        // The dispatch boundary checks the vault again. Neither an old review nor a reused
        // permission can send the text with a different credential or a changed destination.
        fun consumeFor(current: AetherOnlineEndpoint?): Boolean = used.compareAndSet(false, true) && endpoint == current
    }

    private var sequence = 0L
    var pending: Review? = null
        private set

    fun preview(endpoint: AetherOnlineEndpoint, prompt: AetherOnlinePrompt, test: Boolean): Review =
        Review(++sequence, endpoint, prompt, test).also { pending = it }

    fun dismiss(id: Long) {
        if (pending?.id == id) pending = null
    }

    fun approve(id: Long): Approved? {
        val review = pending?.takeIf { it.id == id } ?: return null
        pending = null
        return Approved(review.endpoint, review.prompt, review.test)
    }
}

internal sealed interface AetherOnlineResult {
    data class Suggested(val task: AetherSecurityTask) : AetherOnlineResult
    data object Unsupported : AetherOnlineResult
    data class Failed(val problem: Problem) : AetherOnlineResult

    enum class Problem(val message: String) {
        NOT_CONFIGURED("The saved AI connection is missing or changed. Open AI API settings to reconnect."),
        AUTH("The provider rejected the API key or access. Check the key, its restrictions, and model access."),
        QUOTA("The provider hit a quota or rate limit. Check your usage and billing before trying again."),
        BILLING("The provider requires billing or has reached a spending limit. Check your provider account."),
        ACCOUNT_SETUP("The provider refused the request because a project, billing, or region requirement was not met."),
        MODEL_OR_ENDPOINT("The provider couldn't find the model or API route. Check the model ID and API settings."),
        TOKEN_PARAMETER("The API rejected the output token setting. For a custom API, select the token parameter your provider supports."),
        REQUEST("The provider rejected the request. Check that the selected model and API support text generation."),
        REDIRECT("The API tried to redirect. Use the final HTTPS endpoint; the key wasn't forwarded."),
        NETWORK("Couldn't reach the AI API. Check internet access and the API hostname."),
        TIMEOUT("The AI API took too long. Try a faster text model or use Find task offline. The provider may have received the request."),
        TLS("Couldn't verify a secure connection to this API. Check the HTTPS URL and certificate."),
        SERVICE("The AI provider is unavailable. Try again later."),
        BLOCKED("The provider refused or filtered the reply. No task was suggested."),
        INCOMPLETE("The model didn't finish its answer within the output limit. Try a faster text model."),
        REPLY_TOO_LARGE("The API returned more data than allowed. Choose a text model or use Find task offline."),
        INVALID_REPLY("The API replied, but the selected model didn't return a valid task. Try a different text model or use Find task offline.")
    }
}

/** Provider-specific text protocols with no tools or phone context. Both return only an allowed task ID. */
internal object AetherOnlineProtocol {
    const val MAX_REPLY_BYTES = 65_536L
    private const val OUTPUT_TOKENS = 2_048 // Includes hidden reasoning on models that use it.
    private const val MAX_JSON_DEPTH = 32
    private const val UNSUPPORTED = "UNSUPPORTED"
    private val singleLineFence = Regex("```(?:text|json)?[ \t]*\r?\n([^\r\n]+)\r?\n```")
    private val geminiTextFields = setOf("text", "thought", "thoughtSignature")
    private val geminiBlockedReasons = setOf(
        "SAFETY", "RECITATION", "BLOCKLIST", "PROHIBITED_CONTENT", "SPII", "MODEL_ARMOR", "LANGUAGE",
        "IMAGE_SAFETY", "IMAGE_PROHIBITED_CONTENT", "IMAGE_RECITATION"
    )
    private val instructions = """
        Classify the user's request into one AdShield phone security task. Do not answer the request or execute anything.
        Return exactly one of these IDs, with no other text:
        CHECK_PHONE: review current AdShield protection, Wi-Fi or phone health.
        AUDIT_APPS: inspect installed application permission and install-source risks.
        SCAN_LINK: check one link for phishing, without visiting it.
        BENCHMARK_DNS: measure upstream DNS resolver latency.
        ENABLE_ALIAS_SHIELD: turn on AdShield's DNS Alias Shield only if explicitly requested.
        SCAN_FILE: inspect one document or APK that the user will separately select; no filename or file contents are needed in the request.
        SECURITY_REVIEW: a broad read-only security review combining CHECK_PHONE and AUDIT_APPS. Use only for a general security review or a request for both checks with no extra actions or exclusions.
        UNSUPPORTED: no matching task, a negative request, ambiguous intent, or a combination other than SECURITY_REVIEW.
    """.trimIndent()

    fun requestBody(endpoint: AetherOnlineEndpoint, prompt: AetherOnlinePrompt): String = buildJsonObject {
        when (endpoint.provider) {
            AetherOnlineProvider.GEMINI -> {
                putJsonObject("systemInstruction") { putTextParts(instructions) }
                putJsonArray("contents") {
                    addJsonObject { put("role", "user"); putTextParts(prompt.text) }
                }
                putJsonObject("generationConfig") { put("maxOutputTokens", OUTPUT_TOKENS) }
            }
            AetherOnlineProvider.OPENAI, AetherOnlineProvider.COMPATIBLE -> {
                put("model", endpoint.model)
                put("stream", false)
                put(endpoint.chatLimit.parameter, OUTPUT_TOKENS)
                val instructionRole = if (endpoint.provider == AetherOnlineProvider.OPENAI) "developer" else "system"
                putJsonArray("messages") {
                    addJsonObject { put("role", instructionRole); put("content", instructions) }
                    addJsonObject { put("role", "user"); put("content", prompt.text) }
                }
            }
        }
    }.toString()

    fun parseReply(endpoint: AetherOnlineEndpoint, body: String, prompt: AetherOnlinePrompt): AetherOnlineResult {
        val envelope = parseObject(body) ?: return failed(Problem.INVALID_REPLY)
        if (envelope.isPresent("error")) return failed(errorProblem(envelope) ?: Problem.INVALID_REPLY)
        return when (endpoint.provider) {
            AetherOnlineProvider.GEMINI -> parseGemini(envelope, prompt)
            AetherOnlineProvider.OPENAI, AetherOnlineProvider.COMPATIBLE -> parseChat(envelope, prompt)
        }
    }

    private fun parseChat(envelope: JsonObject, prompt: AetherOnlinePrompt): AetherOnlineResult {
        val choice = envelope.singleObject("choices") ?: return failed(Problem.INVALID_REPLY)
        when (choice.text("finish_reason")) {
            "length" -> return failed(Problem.INCOMPLETE)
            "content_filter" -> return failed(Problem.BLOCKED)
            "stop" -> Unit
            else -> return failed(Problem.INVALID_REPLY)
        }
        val message = choice["message"] as? JsonObject ?: return failed(Problem.INVALID_REPLY)
        if (message.text("role") != "assistant" || message.isPresent("function_call") ||
            (message.isPresent("tool_calls") && (message["tool_calls"] as? JsonArray)?.isEmpty() != true)
        ) return failed(Problem.INVALID_REPLY)
        if (message.isPresent("refusal") && message.text("refusal")?.isBlank() != true) return failed(Problem.BLOCKED)
        val text = message.text("content") ?: readChatTextParts(message["content"] as? JsonArray)
            ?: return failed(Problem.INVALID_REPLY)
        return decide(text, prompt)
    }

    private fun parseGemini(envelope: JsonObject, prompt: AetherOnlinePrompt): AetherOnlineResult {
        val blockReason = (envelope["promptFeedback"] as? JsonObject)?.text("blockReason")
        if (blockReason != null && blockReason != "BLOCK_REASON_UNSPECIFIED") return failed(Problem.BLOCKED)
        val candidate = envelope.singleObject("candidates") ?: return failed(Problem.INVALID_REPLY)
        when (candidate.text("finishReason")) {
            "MAX_TOKENS" -> return failed(Problem.INCOMPLETE)
            in geminiBlockedReasons -> return failed(Problem.BLOCKED)
            "STOP" -> Unit
            else -> return failed(Problem.INVALID_REPLY)
        }
        val content = candidate["content"] as? JsonObject ?: return failed(Problem.INVALID_REPLY)
        if (content.isPresent("role") && content.text("role") != "model") return failed(Problem.INVALID_REPLY)
        val parts = content["parts"] as? JsonArray ?: return failed(Problem.INVALID_REPLY)
        val text = buildString {
            for (element in parts) {
                val part = element as? JsonObject ?: return failed(Problem.INVALID_REPLY)
                // In particular, reject function calls and media; never read thought text as a task.
                if (part.keys.any { it !in geminiTextFields }) return failed(Problem.INVALID_REPLY)
                val thought = if (part.isPresent("thought")) {
                    (part["thought"] as? JsonPrimitive)?.takeUnless { it.isString }?.booleanOrNull
                        ?: return failed(Problem.INVALID_REPLY)
                } else false
                if (!thought) {
                    val visibleText = part.text("text")
                    if (visibleText != null) append(visibleText)
                    else if (part.isPresent("text") || part.text("thoughtSignature").isNullOrEmpty()) {
                        return failed(Problem.INVALID_REPLY)
                    }
                }
            }
        }
        return decide(text, prompt)
    }

    private fun readChatTextParts(parts: JsonArray?): String? {
        if (parts == null) return null
        return buildString {
            for (element in parts) {
                val part = element as? JsonObject ?: return null
                if (part.text("type") != "text" || part.keys.any { it != "type" && it != "text" }) return null
                append(part.text("text") ?: return null)
            }
        }
    }

    private fun decide(text: String, prompt: AetherOnlinePrompt): AetherOnlineResult {
        // Some compatible providers quote or fence the one label. Never extract labels from prose.
        val trimmed = text.trim()
        if (trimmed.length > 128) return failed(Problem.INVALID_REPLY)
        val label = (singleLineFence.matchEntire(trimmed)?.groupValues?.get(1)?.trim() ?: trimmed).removeSurrounding("\"")
        if (label == UNSUPPORTED) return AetherOnlineResult.Unsupported
        val task = AetherSecurityTask.entries.firstOrNull { it.name == label } ?: return failed(Problem.INVALID_REPLY)
        return if (AetherTaskPolicy.allows(task, AetherTaskPolicy.tokens(prompt.text))) {
            AetherOnlineResult.Suggested(task)
        } else AetherOnlineResult.Unsupported
    }

    fun httpFailure(status: Int, body: String? = null): AetherOnlineResult.Failed = failed(when (status) {
        in 300..399 -> Problem.REDIRECT
        in 500..599 -> Problem.SERVICE
        else -> body?.let(::parseObject)?.let(::errorProblem) ?: when (status) {
            401, 403 -> Problem.AUTH
            402 -> Problem.BILLING
            404, 405, 410 -> Problem.MODEL_OR_ENDPOINT
            408 -> Problem.TIMEOUT
            429 -> Problem.QUOTA
            else -> Problem.REQUEST
        }
    })

    // Classify documented error codes only. The server's free-form error message is never displayed.
    private fun errorProblem(envelope: JsonObject): Problem? {
        val error = envelope["error"] as? JsonObject ?: return null
        val codes = buildSet {
            error.text("code")?.let { add(it) }
            error.text("status")?.let { add(it) }
            (error["details"] as? JsonArray)?.forEach { (it as? JsonObject)?.text("reason")?.let { reason -> add(reason) } }
        }
        return when {
            codes.any { it in billingErrors } -> Problem.BILLING
            codes.any { it in quotaErrors } -> Problem.QUOTA
            codes.any { it in keyErrors } -> Problem.AUTH
            "FAILED_PRECONDITION" in codes -> Problem.ACCOUNT_SETUP
            "NOT_FOUND" in codes || "model_not_found" in codes -> Problem.MODEL_OR_ENDPOINT
            AetherChatLimit.entries.any { it.parameter == error.text("param") } -> Problem.TOKEN_PARAMETER
            else -> null
        }
    }

    private fun parseObject(body: String): JsonObject? {
        if (body.length > MAX_REPLY_BYTES) return null
        // Avoid deeply nested untrusted responses even if they fit in the byte limit.
        var depth = 0
        var quoted = false
        var escaped = false
        for (character in body) {
            if (escaped) escaped = false
            else if (quoted && character == '\\') escaped = true
            else if (character == '"') quoted = !quoted
            else if (!quoted) when (character) {
                '{', '[' -> if (++depth > MAX_JSON_DEPTH) return null
                '}', ']' -> if (--depth < 0) return null
            }
        }
        if (quoted || depth != 0) return null
        return runCatching { Json.parseToJsonElement(body) as? JsonObject }.getOrNull()
    }

    private fun failed(problem: Problem) = AetherOnlineResult.Failed(problem)

    private val keyErrors = setOf(
        "invalid_api_key", "UNAUTHENTICATED", "PERMISSION_DENIED", "API_KEY_INVALID", "API_KEY_EXPIRED",
        "API_KEY_SERVICE_BLOCKED", "API_KEY_HTTP_REFERRER_BLOCKED", "API_KEY_IP_ADDRESS_BLOCKED", "ACCESS_TOKEN_TYPE_UNSUPPORTED"
    )
    private val quotaErrors = setOf("insufficient_quota", "rate_limit_exceeded", "RESOURCE_EXHAUSTED", "RATE_LIMIT_EXCEEDED")
    private val billingErrors = setOf("billing_hard_limit_reached", "billing_not_active", "BILLING_DISABLED")
}

private fun kotlinx.serialization.json.JsonObjectBuilder.putTextParts(text: String) =
    putJsonArray("parts") { addJsonObject { put("text", text) } }

private fun JsonObject.singleObject(key: String): JsonObject? = (this[key] as? JsonArray)?.singleOrNull() as? JsonObject
private fun JsonObject.isPresent(key: String): Boolean = get(key)?.let { it != JsonNull } == true
internal fun JsonObject.text(key: String): String? = (get(key) as? JsonPrimitive)?.takeIf { it.isString }?.content
