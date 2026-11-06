package com.adshield.pro.testing

import com.adshield.pro.domain.model.RuleCategory
import com.adshield.pro.engine.filter.FilterRuleEngine
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths

/**
 * Shared access to the rule assets that actually ship in the APK, for JVM tests.
 *
 * Tests must measure what the device will run, so every helper here goes through the *production*
 * parser ([FilterRuleEngine.parseFilterListContent]) instead of a hand-rolled reimplementation of
 * the rule syntax. That is the whole point: if the parser and the test disagree, the test is
 * worthless.
 */
object BundledAsset {

    const val DEFAULT_BLOCKLIST = "default_blocklist.txt"
    const val CORE_LITE_ADS = "core_lite_ads.txt"
    const val CORE_MAX_ADS = "core_max_ads.txt"
    const val CORE_MAX_THREATS = "core_max_threats.txt"
    const val VIDEO_AD_NETWORK = "video_ad_network.txt"

    /** Every rule file shipped in `app/src/main/assets` that carries block rules. */
    val RULE_LISTS: List<String> = listOf(
        DEFAULT_BLOCKLIST,
        CORE_LITE_ADS,
        CORE_MAX_ADS,
        CORE_MAX_THREATS,
        VIDEO_AD_NETWORK
    )

    /**
     * Gradle JVM tests run with the module directory as the working directory, while plain unit
     * runs start at the repository root. Walk up until the assets folder is found.
     */
    fun repoRoot(): Path {
        var dir: Path? = Paths.get("").toAbsolutePath()
        repeat(6) {
            val candidate = dir ?: return@repeat
            if (Files.isDirectory(candidate.resolve("app/src/main/assets"))) return candidate
            dir = candidate.parent
        }
        return Paths.get("").toAbsolutePath()
    }

    fun assetPath(name: String): Path = repoRoot().resolve("app/src/main/assets").resolve(name)

    /** Parses [name] with the production parser and returns the set of blocked hostnames. */
    fun parsedHosts(name: String, engine: FilterRuleEngine = FilterRuleEngine()): Set<String> =
        engine.parseFilterListContent(
            assetPath(name).toFile().readText(),
            RuleCategory.ADS,
            name
        ).map { it.subdomainRules.keys }.getOrDefault(emptySet())

    /** Loads [name] into [engine] exactly the way the repository does at startup. */
    fun loadInto(engine: FilterRuleEngine, name: String) {
        val parsed = engine.parseFilterListContent(
            assetPath(name).toFile().readText(),
            RuleCategory.ADS,
            name
        ).getOrThrow()
        engine.updateFilterListRules(
            subdomainRules = parsed.subdomainRules,
            exactRules = parsed.exactRules,
            wildcardRules = parsed.wildcardRules,
            allowSubdomains = parsed.allowSubdomains
        )
    }
}
