package com.adshield.pro.engine.dns

import com.adshield.pro.domain.model.FilterEvaluationResult
import com.adshield.pro.domain.model.RuleCategory
import com.adshield.pro.engine.filter.FilterRuleEngine
import javax.inject.Inject
import javax.inject.Singleton

/**
 * INFINITY DNS — CNAME Intelligence Engine
 *
 * Detects CNAME cloaking, analyzes CNAME chains, and maps domain relationships.
 *
 * CNAME cloaking: tracker.example.com CNAME tracker.adnetwork.com — the first-party
 * name hides the third-party tracker. DNS filtering must follow the chain.
 *
 * Capabilities:
 * - Parse CNAME records from upstream DNS responses
 * - Walk CNAME chains up to 8 hops (RFC limit)
 * - Detect cloaking (first-party name → known tracker)
 * - Third-party vs first-party classification
 * - Domain relationship mapping
 * - TTL-aware chain evaluation
 */
@Singleton
class CnameIntelligenceEngine @Inject constructor(
    private val filterEngine: FilterRuleEngine
) {

    data class CnameRecord(
        val alias: String,
        val canonical: String,
        val ttlSeconds: Int
    )

    data class CnameChain(
        val queryDomain: String,
        val chain: List<CnameRecord>,
        val finalTarget: String?,
        val isCloaked: Boolean,
        val cloakedCategory: RuleCategory?,
        val cloakedSource: String?,
        val chainLength: Int,
        val hasLoop: Boolean
    )

    data class CnameEvaluation(
        val originalDomain: String,
        val chain: CnameChain,
        val shouldBlock: Boolean,
        val blockingReason: String?,
        val evaluation: FilterEvaluationResult?
    )

    companion object {
        const val MAX_CNAME_HOPS = 8
        const val CNAME_TYPE = 5

        /** Known tracking/ad infrastructure that is frequently hidden behind CNAME cloaking */
        val KNOWN_CLOAKED_TRACKERS = setOf(
            "oajs.openx.net",
            "eulerian.net",
            "criteo.net",
            "criteo.com",
            "adobe.com",
            "demdex.net",
            "everesttech.net",
            "scorecardresearch.com",
            "doubleclick.net",
            "googlesyndication.com",
            "googleadservices.com",
            "google-analytics.com",
            "googletagmanager.com",
            "facebook.net",
            "facebook.com",
            "fbcdn.net",
            "taboola.com",
            "outbrain.com",
            "quantserve.com",
            "chartbeat.com",
            "hotjar.com",
            "mixpanel.com",
            "segment.com",
            "segment.io",
            "amplitude.com",
            "braze.com",
            "adjust.com",
            "appsflyer.com",
            "branch.io"
        )

        /** First-party eTLD+1 extraction for cloaking detection */
        fun registrableDomain(domain: String): String {
            val parts = domain.lowercase().trimEnd('.').split('.')
            if (parts.size <= 2) return domain.lowercase()
            // Handle common 2-level TLDs
            val twoLevelTlds = setOf("co", "com", "net", "org", "gov", "ac", "ne", "or", "go")
            val last = parts.last()
            val secondLast = parts[parts.size - 2]
            return if (last.length == 2 && secondLast in twoLevelTlds) {
                parts.takeLast(3).joinToString(".")
            } else {
                parts.takeLast(2).joinToString(".")
            }
        }

        fun isThirdParty(queryDomain: String, canonicalDomain: String): Boolean {
            return registrableDomain(queryDomain) != registrableDomain(canonicalDomain)
        }
    }

    /**
     * Parse CNAME records from a raw DNS response.
     * Returns empty list if no CNAME records or malformed data.
     */
    fun parseCnameRecords(dnsResponse: ByteArray): List<CnameRecord> {
        if (dnsResponse.size < 12) return emptyList()
        return try {
            parseCnameRecordsInternal(dnsResponse)
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun parseCnameRecordsInternal(dnsResponse: ByteArray): List<CnameRecord> {
        val records = mutableListOf<CnameRecord>()
        val qdCount = u16(dnsResponse, 4)
        val anCount = u16(dnsResponse, 6)
        if (qdCount != 1 || anCount == 0 || anCount > 128) return emptyList()

        // Skip question section
        var offset = 12
        val qNameEnd = findNameEnd(dnsResponse, 0, offset, dnsResponse.size) ?: return emptyList()
        offset = qNameEnd + 4 // skip QTYPE + QCLASS
        if (offset > dnsResponse.size) return emptyList()

        // Parse answer section
        repeat(anCount) {
            if (offset + 10 > dnsResponse.size) return@repeat
            val nameEnd = findNameEnd(dnsResponse, 0, offset, dnsResponse.size) ?: return@repeat
            val aliasName = readName(dnsResponse, 0, offset, dnsResponse.size) ?: run {
                offset = nameEnd + 10
                val rdLen = u16(dnsResponse, nameEnd + 8)
                offset += rdLen
                return@repeat
            }
            val type = u16(dnsResponse, nameEnd)
            // ttl at nameEnd+4, rdLength at nameEnd+8
            val ttl = ((dnsResponse[nameEnd + 4].toInt() and 0xFF) shl 24) or
                ((dnsResponse[nameEnd + 5].toInt() and 0xFF) shl 16) or
                ((dnsResponse[nameEnd + 6].toInt() and 0xFF) shl 8) or
                (dnsResponse[nameEnd + 7].toInt() and 0xFF)
            val rdLength = u16(dnsResponse, nameEnd + 8)
            val rdataOffset = nameEnd + 10

            if (type == CNAME_TYPE && rdataOffset + rdLength <= dnsResponse.size && rdLength >= 2) {
                val canonical = readName(dnsResponse, 0, rdataOffset, dnsResponse.size)
                if (canonical != null && canonical.isNotEmpty()) {
                    records.add(
                        CnameRecord(
                            alias = aliasName.lowercase(),
                            canonical = canonical.lowercase().trimEnd('.'),
                            ttlSeconds = ttl.coerceIn(15, 86400)
                        )
                    )
                }
            }
            offset = rdataOffset + rdLength
            if (offset > dnsResponse.size) return@repeat
        }
        return records
    }

    /**
     * Build CNAME chain from parsed records starting at query domain.
     */
    fun buildChain(queryDomain: String, records: List<CnameRecord>): CnameChain {
        val normalizedQuery = queryDomain.lowercase().trimEnd('.')
        if (records.isEmpty()) {
            return CnameChain(
                queryDomain = normalizedQuery,
                chain = emptyList(),
                finalTarget = null,
                isCloaked = false,
                cloakedCategory = null,
                cloakedSource = null,
                chainLength = 0,
                hasLoop = false
            )
        }

        val chain = mutableListOf<CnameRecord>()
        val visited = mutableSetOf<String>()
        var current = normalizedQuery
        var hasLoop = false

        // Build lookup map: alias -> canonical
        val aliasMap = records.associate { it.alias.lowercase() to it }

        var hops = 0
        while (hops < MAX_CNAME_HOPS) {
            if (!visited.add(current)) {
                hasLoop = true
                break
            }
            val record = aliasMap[current] ?: break
            chain.add(record)
            current = record.canonical.lowercase()
            hops++
        }

        val finalTarget = chain.lastOrNull()?.canonical

        // Detect cloaking: first-party → known tracker
        var isCloaked = false
        var cloakedCategory: RuleCategory? = null
        var cloakedSource: String? = null

        for (record in chain) {
            if (isThirdParty(normalizedQuery, record.canonical)) {
                val eval = filterEngine.evaluate(record.canonical)
                if (eval.isBlocked) {
                    isCloaked = true
                    cloakedCategory = eval.matchedCategory
                    cloakedSource = eval.sourceName
                    break
                }
                // Also check against known cloaked tracker set
                val canonicalRegistrable = registrableDomain(record.canonical)
                if (KNOWN_CLOAKED_TRACKERS.any { tracker ->
                        record.canonical == tracker || record.canonical.endsWith(".$tracker") ||
                            canonicalRegistrable == tracker
                    }) {
                    isCloaked = true
                    cloakedCategory = RuleCategory.TRACKERS
                    cloakedSource = "CNAME Cloaking Intelligence"
                    break
                }
            }
        }

        return CnameChain(
            queryDomain = normalizedQuery,
            chain = chain,
            finalTarget = finalTarget,
            isCloaked = isCloaked,
            cloakedCategory = cloakedCategory,
            cloakedSource = cloakedSource,
            chainLength = chain.size,
            hasLoop = hasLoop
        )
    }

    /**
     * Full evaluation: parse response, build chain, determine if query should be blocked
     * due to CNAME cloaking.
     */
    fun evaluate(queryDomain: String, dnsResponse: ByteArray): CnameEvaluation {
        val records = parseCnameRecords(dnsResponse)
        val chain = buildChain(queryDomain, records)

        if (chain.isCloaked) {
            val eval = FilterEvaluationResult(
                domain = queryDomain,
                isBlocked = true,
                matchedRule = "CNAME→${chain.chain.lastOrNull()?.canonical}",
                matchedCategory = chain.cloakedCategory,
                matchType = null,
                sourceName = chain.cloakedSource ?: "CNAME Cloaking",
                priority = 55,
                evaluationTimeMicros = 0
            )
            return CnameEvaluation(
                originalDomain = queryDomain,
                chain = chain,
                shouldBlock = true,
                blockingReason = "CNAME cloaking: ${queryDomain} → ${chain.chain.joinToString(" → ") { it.canonical }} [${chain.cloakedCategory?.displayName}]",
                evaluation = eval
            )
        }

        return CnameEvaluation(
            originalDomain = queryDomain,
            chain = chain,
            shouldBlock = false,
            blockingReason = null,
            evaluation = null
        )
    }

    /**
     * Analyze upstream response for suspicious CNAME patterns (heuristic).
     */
    fun analyzeSuspiciousChain(chain: CnameChain): List<String> {
        val issues = mutableListOf<String>()
        if (chain.hasLoop) issues.add("CNAME loop detected — possible DNS manipulation")
        if (chain.chainLength > 4) issues.add("Unusually long CNAME chain (${chain.chainLength} hops)")
        if (chain.chain.any { it.ttlSeconds < 30 }) issues.add("Very short TTL in CNAME chain — possible fast-flux")
        // Detect cross-TLD cloaking (e.g., example.com → tracker.net)
        val queryTld = chain.queryDomain.substringAfterLast('.', "")
        for (record in chain.chain) {
            val canonicalTld = record.canonical.substringAfterLast('.', "")
            if (queryTld != canonicalTld && isThirdParty(chain.queryDomain, record.canonical)) {
                issues.add("Cross-TLD CNAME: ${record.alias} → ${record.canonical}")
            }
        }
        return issues
    }

    // ---- DNS wire helpers ----

    private fun u16(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xFF) shl 8) or (bytes[offset + 1].toInt() and 0xFF)

    private fun findNameEnd(packet: ByteArray, msgStart: Int, startPos: Int, limit: Int): Int? {
        var pos = startPos
        var jumps = 0
        var jumped = false
        var nextAfterJump = -1
        while (true) {
            if (pos >= limit || pos < msgStart) return null
            val len = packet[pos].toInt() and 0xFF
            if (len == 0) {
                return if (jumped) nextAfterJump else pos + 1
            }
            val masked = len and 0xC0
            if (masked == 0xC0) {
                if (pos + 1 >= limit) return null
                if (!jumped) {
                    nextAfterJump = pos + 2
                    jumped = true
                }
                jumps++
                if (jumps > 16) return null
                val ptr = ((len and 0x3F) shl 8) or (packet[pos + 1].toInt() and 0xFF)
                val target = msgStart + ptr
                if (target < msgStart || target >= limit || target == pos) return null
                pos = target
            } else if (masked == 0x00) {
                if (len > 63 || pos + 1 + len > limit) return null
                pos += 1 + len
            } else return null
        }
    }

    private fun readName(packet: ByteArray, msgStart: Int, startPos: Int, limit: Int): String? {
        val sb = StringBuilder()
        var pos = startPos
        var jumps = 0
        var jumped = false
        var chars = 0
        while (true) {
            if (pos >= limit || pos < msgStart) return null
            val len = packet[pos].toInt() and 0xFF
            if (len == 0) break
            val masked = len and 0xC0
            if (masked == 0xC0) {
                if (pos + 1 >= limit) return null
                jumps++
                if (jumps > 16) return null
                if (!jumped) jumped = true
                val ptr = ((len and 0x3F) shl 8) or (packet[pos + 1].toInt() and 0xFF)
                val target = msgStart + ptr
                if (target < msgStart || target >= limit || target == pos) return null
                pos = target
            } else if (masked == 0x00) {
                if (len > 63 || pos + 1 + len > limit) return null
                if (sb.isNotEmpty()) { sb.append('.'); chars++ }
                for (i in 0 until len) {
                    val ch = (packet[pos + 1 + i].toInt() and 0xFF).toChar()
                    if (ch.code < 0x20 || ch.code == 0x7F) return null
                    sb.append(ch)
                }
                chars += len
                if (chars > 253) return null
                pos += 1 + len
            } else return null
        }
        return sb.toString()
    }
}
