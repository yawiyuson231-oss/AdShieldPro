package com.adshield.pro

import com.adshield.pro.domain.model.CustomRule
import com.adshield.pro.domain.model.DnsFirewallPolicy
import com.adshield.pro.domain.model.DnsResolverConfig
import com.adshield.pro.domain.model.NetworkTransportPolicy
import com.adshield.pro.domain.model.RuleCategory
import com.adshield.pro.domain.model.RuleMatchType
import com.adshield.pro.domain.model.RuleType
import com.adshield.pro.engine.aether.AetherDnsPolicyReview
import com.adshield.pro.engine.aether.DomainRiskAnalyzer
import com.adshield.pro.engine.filter.FilterRuleEngine
import com.adshield.pro.engine.security.AppRiskAuditor
import java.io.File
import java.security.MessageDigest
import java.time.Instant
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Test-only adapters. No sockets, PackageManager, APK installation or production state. */
class EvolutionDetectorEvidenceTest {
    private val root: File
        get() = generateSequence(File(System.getProperty("user.dir"))) { it.parentFile }
            .first { File(it, "tools/evolution/fixtures/synthetic-v1.json").isFile }

    private fun sha(file: File): String = MessageDigest.getInstance("SHA-256")
        .digest(file.readBytes()).joinToString("") { "%02x".format(it) }

    private fun predict(category: String, input: JsonObject): Boolean = when (category) {
        // Threshold is an EVALUATION policy only, not a new shipping blocking threshold.
        "domain", "phishing" -> DomainRiskAnalyzer.riskScore(
            DomainRiskAnalyzer.analyze(input.getValue("target").jsonPrimitive.content)
        ) >= 25
        "apk_metadata" -> {
            fun strings(key: String) = input.getValue(key).jsonArray.map { it.jsonPrimitive.content }
            val profile = AppRiskAuditor.AppSecurityProfile(
                packageName = "test.fixture.metadata",
                appName = "Synthetic metadata only",
                versionName = "1",
                targetSdkVersion = input.getValue("target_sdk").jsonPrimitive.int,
                requestedPermissions = strings("permissions").map { "android.permission.$it" },
                declaredComponentPermissions = strings("bindings").map { "android.permission.$it" }.toSet(),
                installerPackageName = input["installer"]?.jsonPrimitive?.contentOrNull,
                isSystemApp = false
            )
            AppRiskAuditor().audit(profile).riskLevel in setOf(
                AppRiskAuditor.RiskLevel.MEDIUM, AppRiskAuditor.RiskLevel.HIGH
            )
        }
        "dns_filter" -> {
            val engine = FilterRuleEngine()
            engine.updateFilterListRules(
                subdomainRules = mapOf("blocked.fixture.test" to FilterRuleEngine.FilterListEntry(
                    RuleCategory.MALWARE, "Synthetic test-only list", RuleMatchType.SUBDOMAIN
                )), exactRules = emptyMap(), wildcardRules = emptyList()
            )
            if (input.getValue("allow").jsonPrimitive.boolean) {
                engine.updateCustomRules(listOf(CustomRule(
                    rawPattern = "blocked.fixture.test", normalizedPattern = "blocked.fixture.test",
                    ruleType = RuleType.ALLOW, matchType = RuleMatchType.SUBDOMAIN
                )))
            }
            engine.evaluate(input.getValue("target").jsonPrimitive.content).isBlocked
        }
        "configuration" -> {
            val policy = if (input.getValue("wifi_only").jsonPrimitive.boolean) {
                DnsFirewallPolicy(protectedTransports = setOf(NetworkTransportPolicy.WIFI))
            } else DnsFirewallPolicy()
            val summary = AetherDnsPolicyReview.inspect(
                DnsResolverConfig(), policy, emptySet(),
                aliasShieldOn = input.getValue("alias_shield").jsonPrimitive.boolean
            ).summary
            !summary.aliasShieldOn || summary.networksWithoutDomainFiltering.isNotEmpty()
        }
        else -> error("Unknown fixture category: $category")
    }

    @Test
    fun exportsActualDetectorPredictionsWithoutUsingLabelsForInference() {
        val dataset = File(root, "tools/evolution/fixtures/synthetic-v1.json")
        val samples = Json.parseToJsonElement(dataset.readText()).jsonArray.map { it.jsonObject }
        val predictions = samples.associate { sample ->
            sample.getValue("id").jsonPrimitive.content to predict(
                sample.getValue("category").jsonPrimitive.content, sample.getValue("input").jsonObject
            )
        }
        assertEquals(samples.size, predictions.size)
        assertTrue(predictions.values.any { it })
        assertTrue(predictions.values.any { !it })
        // Golden DNS guarantees, not a requirement to pretend the heuristic has perfect recall.
        assertEquals(true, predictions["dns_filter:blocked"])
        assertEquals(true, predictions["dns_filter:subdomain"])
        assertEquals(false, predictions["dns_filter:allow-override"])
        assertEquals(false, predictions["dns_filter:suffix-boundary"])
        assertEquals(false, predictions["apk_metadata:binding-in-request-list"])

        val sourcePaths = File(root, "app/src/main").walkTopDown()
            .filter { it.isFile && it.extension == "kt" }
            .map { it.relativeTo(root).invariantSeparatorsPath }.toList() + listOf(
                "app/src/test/java/com/adshield/pro/EvolutionDetectorEvidenceTest.kt",
                "app/build.gradle.kts", "build.gradle.kts", "settings.gradle.kts",
                "gradle/libs.versions.toml"
            )
        val evidence = buildJsonObject {
            put("schema", 1)
            put("adapter", "android-pure-detectors-v1")
            put("scope", "public-synthetic-regression-not-independent-holdout")
            put("created_at", Instant.now().toString())
            put("dataset_file_sha256", sha(dataset))
            put("source_manifest", buildJsonObject {
                sourcePaths.sorted().forEach { put(it, sha(File(root, it))) }
            })
            put("predictions", buildJsonObject { predictions.forEach { (key, value) -> put(key, value) } })
        }
        val output = File(root, ".ci/evolution/current.json")
        output.parentFile.mkdirs()
        output.writeText(evidence.toString() + "\n")
        assertTrue(output.length() > 0L)
    }
}
