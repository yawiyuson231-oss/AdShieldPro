package com.adshield.pro

import com.adshield.pro.engine.aether.AetherChatLimit
import com.adshield.pro.engine.aether.AetherOnlineApproval
import com.adshield.pro.engine.aether.AetherOnlineConfig
import com.adshield.pro.engine.aether.AetherOnlinePrompt
import com.adshield.pro.engine.aether.AetherOnlineProtocol
import com.adshield.pro.engine.aether.AetherOnlineProvider as Provider
import com.adshield.pro.engine.aether.AetherOnlineResult
import com.adshield.pro.engine.aether.AetherOnlineResult.Problem
import com.adshield.pro.engine.aether.AetherSecurityTask as Task
import com.adshield.pro.engine.aether.AetherTaskApproval
import com.adshield.pro.engine.aether.AetherTaskSource
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AetherOnlinePlannerTest {
    private val endpoint = "https://model.example/v1/chat/completions"
    private val model = "fixture-model"
    private val testToken = "fixture-token"
    private val config = connection(Provider.COMPATIBLE, endpoint, model)
    private val gemini = connection(Provider.GEMINI, "", "models/gemini-3.5-flash-lite")
    private val prompt = requireNotNull(AetherOnlinePrompt.create("Audit my installed apps"))

    @Test
    fun savesTokenAndDestinationTogetherAndRejectsUnsafeEndpoints() {
        val restored = requireNotNull(AetherOnlineConfig.decodeFromVault(config.encodeForVault()))
        assertEquals(config.endpoint, restored.endpoint)
        assertEquals(testToken, restored.token)
        assertFalse(config.endpoint.toString().contains(testToken))
        listOf(
            "http://model.example/v1/chat/completions",
            "https://model.example@another.example/v1/chat/completions",
            "https://model.example/v1/chat/completions?key=secret",
            "https://model.example/v1/chat/completions#fragment",
            "https://model.example:65536/v1/chat/completions",
            "https://model.example/a/../v1/chat/completions",
            "https://model.example/v1/models",
            "https://model.example/v1/responses",
            "https://model.example/v1//chat/completions",
            "https://model.example/v1/%2e%2e/chat/completions"
        ).forEach {
            assertEquals(it, AetherOnlineConfig.Validation.Invalid(AetherOnlineConfig.Issue.URL), validate(Provider.COMPATIBLE, it, model))
        }
        assertEquals(AetherOnlineConfig.Validation.Invalid(AetherOnlineConfig.Issue.MODEL), validate(Provider.COMPATIBLE, endpoint, ""))
        listOf("test-token\r\nAuthorization: other", "Bearer fixture-token", "https://model.example/v1?key=fixture").forEach {
            assertEquals(AetherOnlineConfig.Validation.Invalid(AetherOnlineConfig.Issue.KEY),
                validate(Provider.COMPATIBLE, endpoint, model, it))
        }
    }

    @Test
    fun outboundReviewContainsOnlyTypedTaskTextAndNeverIncludesScannedLinks() {
        listOf("Check https://link.example/private?id=123", "Check link.example", "Review 192.0.2.1",
            "Check [2001:db8::1]", "Review my@example.com", "Check\u202E this app", "Check " + "a".repeat(240), ""
        ).forEach { assertNull(it, AetherOnlinePrompt.create(it)) }
        val body = AetherOnlineProtocol.requestBody(config.endpoint, prompt)
        val json = Json.parseToJsonElement(body) as JsonObject
        assertEquals(setOf("model", "stream", "max_tokens", "messages"), json.keys)
        assertEquals(JsonPrimitive(model), json["model"])
        assertEquals(JsonPrimitive(2_048), json["max_tokens"])
        val messages = json["messages"] as JsonArray
        assertEquals(2, messages.size)
        val user = messages[1] as JsonObject
        assertEquals(JsonPrimitive("user"), user["role"])
        assertEquals(JsonPrimitive(prompt.text), user["content"])
        assertFalse(body.contains(testToken))
        assertFalse(body.contains(endpoint))
    }

    @Test
    fun approvalToSendDoesNotApproveAnOnlineSuggestedTask() {
        val sends = AetherOnlineApproval()
        val review = sends.preview(config.endpoint, prompt, test = false)
        assertNull(sends.approve(review.id - 1))
        sends.dismiss(review.id)
        assertNull(sends.approve(review.id))
        val again = sends.preview(config.endpoint, prompt, test = false)
        val permitted = requireNotNull(sends.approve(again.id))
        assertEquals(config.endpoint, permitted.endpoint)
        assertEquals(prompt.text, permitted.prompt.text)
        assertNull(sends.approve(again.id))

        val result = parse(reply("AUDIT_APPS"), permitted.prompt) as AetherOnlineResult.Suggested
        val tasks = AetherTaskApproval()
        assertNull(tasks.approve(again.id))
        val taskReview = tasks.propose(result.task, AetherTaskSource.ONLINE_API)
        tasks.dismiss(taskReview.id)
        assertNull(tasks.approve(taskReview.id))
    }

    @Test
    fun acceptsOnlyOneLabelAndRejectsToolCallsAndMalformedReplies() {
        assertEquals(AetherOnlineResult.Suggested(Task.AUDIT_APPS), parse(reply(" AUDIT_APPS "), prompt))
        assertEquals(AetherOnlineResult.Unsupported, parse(reply("UNSUPPORTED"), prompt))
        val invalid = AetherOnlineResult.Failed(Problem.INVALID_REPLY)
        listOf("<html>provider error</html>", "{}", reply("AUDIT_APPS: run now"),
            reply("SCAN_LINK https://link.example"), reply("DELETE_FILES"), reply("AUDIT_APPS", extra = ",\"tool_calls\":[{}]"),
            reply("AUDIT_APPS\\nPlease act now"), "[".repeat(80) + "]".repeat(80)
        ).forEach { assertEquals(invalid, parse(it, prompt)) }
        assertEquals(AetherOnlineResult.Failed(Problem.INCOMPLETE), parse(reply("AUDIT_APPS", finish = "length"), prompt))
        assertEquals(AetherOnlineResult.Failed(Problem.BLOCKED), parse(reply("AUDIT_APPS", extra = ",\"refusal\":\"refused\""), prompt))
    }

    @Test
    fun onlineProviderCannotConvertStatusQuestionsOrNegationIntoASettingChange() {
        val text = requireNotNull(AetherOnlinePrompt.create("Is Alias Shield on already?"))
        assertEquals(AetherOnlineResult.Unsupported, parse(reply("ENABLE_ALIAS_SHIELD"), text))
        val noAudit = requireNotNull(AetherOnlinePrompt.create("Please don't audit my apps"))
        assertEquals(AetherOnlineResult.Unsupported, parse(reply("AUDIT_APPS"), noAudit))
        val explanation = requireNotNull(AetherOnlinePrompt.create("Why would I turn on Alias Shield?"))
        assertEquals(AetherOnlineResult.Unsupported, parse(reply("ENABLE_ALIAS_SHIELD"), explanation))
        val explicit = requireNotNull(AetherOnlinePrompt.create("Turn on DNS Alias Shield"))
        assertEquals(AetherOnlineResult.Suggested(Task.ENABLE_ALIAS_SHIELD),
            parse(reply("ENABLE_ALIAS_SHIELD"), explicit))
    }

    @Test
    fun supportsReviewAndFileToolsWithoutAllowingExpandedOrDestructiveRequests() {
        val reviewPrompt = requireNotNull(AetherOnlinePrompt.create("Review my phone protection and app permissions together"))
        assertEquals(AetherOnlineResult.Suggested(Task.SECURITY_REVIEW), parse(reply("SECURITY_REVIEW"), reviewPrompt))
        val narrowed = requireNotNull(AetherOnlinePrompt.create("Check protection only, skip my apps"))
        assertEquals(AetherOnlineResult.Unsupported, parse(reply("SECURITY_REVIEW"), narrowed))
        val wifiOnly = requireNotNull(AetherOnlinePrompt.create("Check my Wi-Fi connection"))
        assertEquals(AetherOnlineResult.Unsupported, parse(reply("SECURITY_REVIEW"), wifiOnly))
        val filePrompt = requireNotNull(AetherOnlinePrompt.create("Scan this APK before I install it"))
        assertEquals(AetherOnlineResult.Suggested(Task.SCAN_FILE), parse(reply("SCAN_FILE"), filePrompt))
        assertEquals(AetherOnlineResult.Unsupported, parse(reply("AUDIT_APPS"), filePrompt))
        assertEquals(AetherOnlineResult.Unsupported, parse(reply("SCAN_FILE"), prompt))
        val delete = requireNotNull(AetherOnlinePrompt.create("Delete a suspicious attachment"))
        assertEquals(AetherOnlineResult.Unsupported, parse(reply("SCAN_FILE"), delete))
    }

    @Test
    fun httpFailuresAreDistinguishedWithoutDisplayingProviderBodies() {
        assertEquals(Problem.REDIRECT, AetherOnlineProtocol.httpFailure(307).problem)
        assertEquals(Problem.AUTH, AetherOnlineProtocol.httpFailure(401).problem)
        assertEquals(Problem.QUOTA, AetherOnlineProtocol.httpFailure(429).problem)
        assertEquals(Problem.SERVICE, AetherOnlineProtocol.httpFailure(503).problem)
        assertEquals(Problem.MODEL_OR_ENDPOINT, AetherOnlineProtocol.httpFailure(404).problem)
        assertTrue(Problem.AUTH.message.contains("API key"))
    }

    @Test
    fun pinsGeminiAndOpenAiAndNormalizesCompatibleBaseUrls() {
        assertEquals("gemini-3.5-flash-lite", gemini.endpoint.model)
        assertEquals("https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash-lite:generateContent", gemini.endpoint.url)
        assertEquals("https://gateway.example:8443/openai/v1/chat/completions",
            connection(Provider.COMPATIBLE, "https://Gateway.Example:8443/openai/v1/", "meta/model").endpoint.url)
        assertEquals("https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
            connection(Provider.COMPATIBLE, "https://generativelanguage.googleapis.com/v1beta/openai/", "gemini-3.5-flash-lite").endpoint.url)
        assertEquals("https://[2001:db8::1]/v1/chat/completions",
            connection(Provider.COMPATIBLE, "https://[2001:0DB8:0:0:0:0:0:1]:443/v1", model).endpoint.url)
        assertEquals(AetherOnlineConfig.OPENAI_URL, connection(Provider.OPENAI, "", "fixture-chat-model").endpoint.url)
        listOf(Provider.GEMINI, Provider.OPENAI).forEach { provider ->
            assertEquals(AetherOnlineConfig.Validation.Invalid(AetherOnlineConfig.Issue.URL), validate(provider, endpoint, model))
        }
        listOf("models/", "models/models/gemini", "gemini:streamGenerateContent", "gemini?key=value", "../other", "models/gemini/child").forEach {
            assertEquals(it, AetherOnlineConfig.Validation.Invalid(AetherOnlineConfig.Issue.GEMINI_MODEL), validate(Provider.GEMINI, "", it))
        }
    }

    @Test
    fun restoresOldConnectionsWithoutResavingKeysAndBindsApprovalToARevision() {
        fun previousRecord(url: String, key: String = testToken) = buildJsonObject {
            put("endpoint", url); put("model", model); put("token", key)
        }.toString()
        val old = requireNotNull(AetherOnlineConfig.decodeFromVault(previousRecord(endpoint)))
        assertEquals(Provider.COMPATIBLE, old.endpoint.provider)
        assertEquals(testToken, old.token)
        val gateway = requireNotNull(AetherOnlineConfig.decodeFromVault(previousRecord(
            "https://Model.Example:443/tenant~2/v1/chat/completions", "opaque-fixture!")))
        assertEquals("https://model.example/tenant~2/v1/chat/completions", gateway.endpoint.url)
        assertEquals("opaque-fixture!", gateway.token)
        assertNull(AetherOnlineConfig.decodeFromVault(previousRecord("https://model.example/v1")))
        val openAi = requireNotNull(AetherOnlineConfig.decodeFromVault(previousRecord(AetherOnlineConfig.OPENAI_URL)))
        assertEquals(Provider.COMPATIBLE, openAi.endpoint.provider)
        assertEquals(AetherOnlineConfig.OPENAI_URL, openAi.endpoint.url)
        assertEquals(AetherChatLimit.MAX_TOKENS, openAi.endpoint.chatLimit)
        val approvals = AetherOnlineApproval()
        val review = approvals.preview(config.endpoint, prompt, test = true)
        val approved = requireNotNull(approvals.approve(review.id))
        val restored = AetherOnlineConfig.decodeFromVault(config.encodeForVault())?.endpoint
        val replacement = connection(Provider.COMPATIBLE, endpoint, model, "replacement-fixture-key").endpoint
        assertEquals(approved.endpoint, restored)
        assertFalse(approved.consumeFor(replacement))
        assertFalse(approved.consumeFor(restored))
        assertNull(approvals.approve(review.id))
        val freshReview = approvals.preview(requireNotNull(restored), prompt, test = true)
        val permitted = requireNotNull(approvals.approve(freshReview.id))
        assertTrue(permitted.consumeFor(restored))
        assertFalse(permitted.consumeFor(restored))
        assertNull(AetherOnlineConfig.decodeFromVault(config.encodeForVault().replace("COMPATIBLE", "future-provider")))
    }

    @Test
    fun nativeGeminiSendsOnlyOneTextTurnAndOpenAiUsesModernOutputLimit() {
        val request = AetherOnlineProtocol.requestBody(gemini.endpoint, prompt)
        val json = Json.parseToJsonElement(request) as JsonObject
        assertEquals(setOf("systemInstruction", "contents", "generationConfig"), json.keys)
        val turn = (json["contents"] as JsonArray).single() as JsonObject
        assertEquals(JsonPrimitive("user"), turn["role"])
        val part = (turn["parts"] as JsonArray).single() as JsonObject
        assertEquals(setOf("text"), part.keys)
        assertEquals(JsonPrimitive(prompt.text), part["text"])
        assertEquals(JsonPrimitive(2_048), (json["generationConfig"] as JsonObject)["maxOutputTokens"])
        assertFalse(request.contains(testToken))
        for (configured in listOf(connection(Provider.OPENAI, "", model),
            connection(Provider.COMPATIBLE, endpoint, model, limit = AetherChatLimit.MAX_COMPLETION_TOKENS))) {
            val chat = Json.parseToJsonElement(AetherOnlineProtocol.requestBody(configured.endpoint, prompt)) as JsonObject
            assertEquals(JsonPrimitive(2_048), chat["max_completion_tokens"])
            assertFalse("max_tokens" in chat)
            val role = if (configured.endpoint.provider == Provider.OPENAI) "developer" else "system"
            assertEquals(JsonPrimitive(role), ((chat["messages"] as JsonArray).first() as JsonObject)["role"])
        }
    }

    @Test
    fun acceptsOnlyWholeLabelsFromTextOrHarmlessWrappers() {
        val expected = AetherOnlineResult.Suggested(Task.AUDIT_APPS)
        assertEquals(expected, parse(reply("AUDIT_APPS", extra = ",\"tool_calls\":[],\"function_call\":null"), prompt))
        assertEquals(expected, parse(reply("```text\\nAUDIT_APPS\\n```"), prompt))
        val parts = reply("AUDIT_APPS").replace("\"AUDIT_APPS\"", """[{"type":"text","text":"AUDIT_APPS"}]""")
        assertEquals(expected, parse(parts, prompt))
        assertEquals(AetherOnlineResult.Failed(Problem.INVALID_REPLY), parse(reply("Run AUDIT_APPS on my phone"), prompt))
    }

    @Test
    fun geminiUsesOnlyFinalTextAndRejectsIncompleteRepliesAndToolCalls() {
        fun parseGemini(parts: String, finish: String = "STOP", request: AetherOnlinePrompt = prompt): AetherOnlineResult {
            val body = """{"candidates":[{"content":{"role":"model","parts":[$parts]},"finishReason":"$finish"}]}"""
            return AetherOnlineProtocol.parseReply(gemini.endpoint, body, request)
        }
        val finalText = """{"text":"AUDIT_APPS","thoughtSignature":"fixture-sig"}"""
        assertEquals(AetherOnlineResult.Suggested(Task.AUDIT_APPS),
            parseGemini("""{"text":"CHECK_PHONE","thought":true},$finalText"""))
        assertEquals(AetherOnlineResult.Suggested(Task.AUDIT_APPS),
            parseGemini("""{"thoughtSignature":"metadata-only"},$finalText"""))
        assertEquals(AetherOnlineResult.Failed(Problem.INVALID_REPLY), parseGemini("""{"text":"AUDIT_APPS","thought":true}"""))
        assertEquals(AetherOnlineResult.Failed(Problem.INVALID_REPLY), parseGemini("""$finalText,{"functionCall":{"name":"audit"}}"""))
        assertEquals(AetherOnlineResult.Failed(Problem.INCOMPLETE), parseGemini(finalText, "MAX_TOKENS"))
        assertEquals(AetherOnlineResult.Failed(Problem.BLOCKED), parseGemini(finalText, "SAFETY"))
        assertEquals(AetherOnlineResult.Failed(Problem.BLOCKED), AetherOnlineProtocol.parseReply(gemini.endpoint,
            """{"promptFeedback":{"blockReason":"SAFETY"}}""", prompt))
        val status = requireNotNull(AetherOnlinePrompt.create("Is Alias Shield already on?"))
        assertEquals(AetherOnlineResult.Unsupported, parseGemini("""{"text":"ENABLE_ALIAS_SHIELD"}""", request = status))
    }

    @Test
    fun recognizesProviderErrorCodesWithoutLeakingPrivateErrorText() {
        val auth = """{"error":{"code":400,"message":"secret echoed by fixture","status":"INVALID_ARGUMENT","details":[{"reason":"API_KEY_INVALID"}]}}"""
        assertEquals(Problem.AUTH, AetherOnlineProtocol.httpFailure(400, auth).problem)
        assertEquals(Problem.TOKEN_PARAMETER, AetherOnlineProtocol.httpFailure(400,
            """{"error":{"code":"unsupported_parameter","param":"max_tokens"}}""").problem)
        assertEquals(Problem.ACCOUNT_SETUP, AetherOnlineProtocol.httpFailure(400,
            """{"error":{"status":"FAILED_PRECONDITION"}}""").problem)
        assertEquals(Problem.QUOTA, AetherOnlineProtocol.httpFailure(403,
            """{"error":{"status":"RESOURCE_EXHAUSTED"}}""").problem)
        assertEquals(Problem.BILLING, AetherOnlineProtocol.httpFailure(403,
            """{"error":{"status":"PERMISSION_DENIED","details":[{"reason":"BILLING_DISABLED"}]}}""").problem)
        assertEquals(Problem.REQUEST, AetherOnlineProtocol.httpFailure(400,
            """{"error":{"message":"API_KEY_INVALID"}}""").problem)
        assertEquals(AetherOnlineResult.Failed(Problem.AUTH), AetherOnlineProtocol.parseReply(gemini.endpoint, auth, prompt))
        assertFalse(AetherOnlineProtocol.httpFailure(400, auth).toString().contains("secret"))
    }

    private fun parse(body: String, request: AetherOnlinePrompt) = AetherOnlineProtocol.parseReply(config.endpoint, body, request)

    private fun validate(provider: Provider, url: String, name: String, key: String = testToken, limit: AetherChatLimit = AetherChatLimit.MAX_TOKENS) =
        AetherOnlineConfig.validate(AetherOnlineConfig.Input(provider, url, name, key, limit))

    private fun connection(provider: Provider, url: String, name: String, key: String = testToken, limit: AetherChatLimit = AetherChatLimit.MAX_TOKENS) =
        (validate(provider, url, name, key, limit) as AetherOnlineConfig.Validation.Ready).config

    private fun reply(label: String, extra: String = "", finish: String = "stop") =
        """{"choices":[{"finish_reason":"$finish","message":{"role":"assistant","content":"$label"$extra}}]}"""
}
