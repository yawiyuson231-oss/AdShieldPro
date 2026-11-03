package com.adshield.pro.engine.aether

import com.adshield.pro.engine.compat.ProtectedDomainCatalog
import com.adshield.pro.engine.filter.FilterRuleEngine
import com.adshield.pro.domain.model.ProtectionMode
import com.adshield.pro.domain.model.RuleCategory

/**
 * OmniShield X — Digital Twin (Part 7).
 *
 * Real simulation harness: a candidate rule set is loaded into a THROWAWAY engine
 * instance and exercised against the must-work corpus (video, auth, payments,
 * stores, games, messaging + the Critical Protection catalog) BEFORE promotion.
 * A candidate that breaks any must-work domain fails simulation and is reported
 * with the exact conflicting rules. CI runs this against the real bundled lists;
 * the ViewModel can surface the same report before the user enables new lists.
 */
object RuleDigitalTwin {

    /** Domains that must resolve for users to consider the product working. */
    val MUST_WORK_CORPUS: Set<String> = setOf(
        "www.youtube.com", "r1---sn-ab5l6ne7.googlevideo.com", "i.ytimg.com",
        "www.netflix.com", "occ-0-2794-2795.1.nflxso.net",
        "www.tiktok.com", "p16-sign.tiktokcdn.com", "v20.muscdn.com",
        "www.facebook.com", "scontent.xx.fbcdn.net", "www.instagram.com",
        "accounts.google.com", "play.google.com", "android.clients.google.com",
        "login.microsoftonline.com", "appleid.apple.com",
        "www.paypal.com", "api.stripe.com", "www.gcash.com",
        "aena.ms", "ylgdmirp.yleaflyrn.aena.ms", "clientsettings.roblox.com",
        "web.whatsapp.com", "api.telegram.org", "discord.com", "gateway.discord.gg"
    )

    data class SimulationReport(
        val candidateRuleCount: Int,
        val testedDomains: Int,
        /** Non-catalog must-work domains the candidate would break in production. */
        val conflicts: List<String>,
        /** Catalog-protected domains the candidate WOULD block — shielded at runtime, but the rule is overbroad. */
        val coveredByCriticalProtection: List<String>,
        val passed: Boolean
    )

    /**
     * Simulates the candidate maps against the must-work corpus. Returns every
     * conflict with the blocking rule name so authors can fix the list.
     */
    fun simulateCandidate(
        subdomainRules: Map<String, FilterRuleEngine.FilterListEntry>,
        exactRules: Map<String, FilterRuleEngine.FilterListEntry>,
        wildcardRules: List<FilterRuleEngine.WildcardEntry>,
        mode: ProtectionMode = ProtectionMode.STANDARD
    ): SimulationReport {
        val twin = FilterRuleEngine()
        twin.updateFilterListRules(
            subdomainRules = subdomainRules,
            exactRules = exactRules,
            wildcardRules = wildcardRules,
            allowSubdomains = emptySet() // simulate raw candidate without the safety net
        )
        twin.updateProtectionMode(mode)

        val conflicts = ArrayList<String>()
        val covered = ArrayList<String>()
        val corpus = MUST_WORK_CORPUS + ProtectedDomainCatalog.protectedDomains
        for (host in corpus) {
            val result = twin.evaluate(host)
            if (result.isBlocked) {
                conflicts.add("$host <- '${result.matchedRule}' (${result.sourceName})")
            } else if (result.sourceName.contains("Critical Protection")) {
                // The candidate rule targets this host but the Critical Protection layer shields it.
                covered.add("$host <- '${result.matchedRule}'")
            }
        }
        return SimulationReport(
            candidateRuleCount = subdomainRules.size + exactRules.size + wildcardRules.size,
            testedDomains = corpus.size,
            conflicts = conflicts,
            coveredByCriticalProtection = covered,
            passed = conflicts.isEmpty()
        )
    }
}
