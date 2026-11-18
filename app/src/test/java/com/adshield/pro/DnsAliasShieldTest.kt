package com.adshield.pro

import com.adshield.pro.domain.model.CustomRule
import com.adshield.pro.domain.model.RuleCategory
import com.adshield.pro.domain.model.RuleMatchType
import com.adshield.pro.domain.model.RuleType
import com.adshield.pro.engine.dns.CnameCloakingInspector
import com.adshield.pro.engine.dns.DnsPacketCodec
import com.adshield.pro.engine.dns.DnsPacketCodec.CLASS_IN
import com.adshield.pro.engine.dns.DnsPacketCodec.TYPE_A
import com.adshield.pro.engine.dns.DnsPacketCodec.TYPE_AAAA
import com.adshield.pro.engine.dns.DnsPacketCodec.TYPE_CNAME
import com.adshield.pro.engine.dns.DnsPacketCodec.TYPE_HTTPS
import com.adshield.pro.engine.dns.DnsPacketCodec.TYPE_SVCB
import com.adshield.pro.engine.dns.DnsResponseValidator
import com.adshield.pro.engine.filter.FilterRuleEngine
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream

class DnsAliasShieldTest {
    @Test
    fun followsHttpsAliasModeAndCnamesInUnorderedAnswers() {
        val wire = response(TYPE_HTTPS, listOf(
            binding(TYPE_HTTPS, TRACKER.uppercase(), owner = "service.publisher.example"),
            binding(TYPE_HTTPS, "service.publisher.example", owner = "edge.publisher.example", priority = 0),
            cname(QUESTION, "Edge.publisher.example")
        ))
        DnsResponseValidator.validate(query(TYPE_HTTPS).rawPayload, wire)
        val result = inspect(wire, engineWithTrackerList())
        assertTrue(result.shouldBlock)
        assertEquals(TRACKER, result.cloakedTarget)
        assertEquals(RuleCategory.TRACKERS, result.matchedCategory)
        assertEquals("HTTPS Uncloaking · Test tracker list", result.sourceName)
        assertEquals(listOf("edge.publisher.example"), result.cnameChain)
    }

    @Test
    fun checksSvcbServiceModeNamesButDoesNotInterpretOpaqueParametersAsNames() {
        val question = "_dns.publisher.example"
        val port = wire { writeShort(3); writeShort(2); writeShort(853) }
        val blocked = response(TYPE_SVCB, listOf(binding(TYPE_SVCB, TRACKER, owner = question, params = port)), question)
        val engine = engineWithTrackerList()
        val result = inspect(blocked, engine, question)
        assertTrue(result.shouldBlock)
        assertEquals("SVCB Uncloaking · Test tracker list", result.sourceName)

        val opaque = wire { writeShort(65280); writeShort(TRACKER.length); writeBytes(TRACKER) }
        val allowed = response(TYPE_SVCB, listOf(
            binding(TYPE_SVCB, "dns.publisher.example", owner = question, params = opaque)
        ), question)
        assertFalse(inspect(allowed, engine, question).shouldBlock)
    }

    @Test
    fun ignoresUnrelatedRecordsAndUsesOnlyMatchingTypesAndClassInTheAnswer() {
        val engine = engineWithTrackerList()
        val wire = response(TYPE_HTTPS, listOf(
            cname("unrelated.publisher.example", TRACKER),
            binding(TYPE_HTTPS, TRACKER, owner = "unrelated.publisher.example"),
            binding(TYPE_SVCB, TRACKER),
            binding(TYPE_HTTPS, TRACKER).copy(rrClass = 3),
            binding(TYPE_HTTPS, "service.publisher.example")
        ), additional = listOf(binding(TYPE_HTTPS, TRACKER)))
        assertEquals(listOf("service.publisher.example"), DnsPacketCodec.extractAnswerAliases(wire).map { it.target })
        assertFalse(inspect(wire, engine).shouldBlock)
        assertFalse(inspect(response(TYPE_A, listOf(binding(TYPE_HTTPS, TRACKER))), engine).shouldBlock)
        assertFalse(inspect(response(TYPE_HTTPS, listOf(binding(TYPE_HTTPS, TRACKER)), qClass = 3), engine).shouldBlock)
        assertFalse(inspect(response(TYPE_HTTPS, listOf(binding(TYPE_HTTPS, TRACKER))), engine, "other.example").shouldBlock)
    }

    @Test
    fun aliasModeTakesPrecedenceAndRootTargetsDoNotNameAnotherHost() {
        val engine = engineWithTrackerList()
        val trackerService = binding(TYPE_HTTPS, TRACKER)
        assertTrue(inspect(response(TYPE_HTTPS, listOf(trackerService)), engine).shouldBlock)
        val aliasMode = binding(TYPE_HTTPS, "edge.publisher.example", priority = 0)
        assertFalse(inspect(response(TYPE_HTTPS, listOf(trackerService, aliasMode)), engine).shouldBlock)
        val noService = binding(TYPE_HTTPS, ".", priority = 0)
        assertTrue(DnsPacketCodec.extractAnswerAliases(response(TYPE_HTTPS, listOf(trackerService, noService))).isEmpty())
        val useOwner = binding(TYPE_HTTPS, ".")
        assertTrue(DnsPacketCodec.extractAnswerAliases(response(TYPE_HTTPS, listOf(useOwner))).isEmpty())
    }

    @Test
    fun readsCompressedCnameTargets() {
        val target = wire {
            writeByte(4)
            writeBytes("edge")
            writeShort(0xC012) // Offset 18: publisher.example in the question.
        }
        val wire = response(TYPE_A, listOf(Record(QUESTION, TYPE_CNAME, target)))
        assertEquals(listOf("edge.publisher.example"), DnsPacketCodec.extractCnameTargets(wire))
    }

    @Test
    fun ignoresMalformedBindingNamesAndParameterFraming() {
        val compressed = Record(QUESTION, TYPE_HTTPS, wire { writeShort(1); writeShort(0xC012) })
        val unterminated = binding(TYPE_HTTPS, TRACKER).let { it.copy(data = it.data.dropLast(1).toByteArray()) }
        val shortParam = wire { writeShort(3); writeShort(2); writeByte(1) }
        val brokenParams = binding(TYPE_HTTPS, TRACKER, params = shortParam)
        assertTrue(DnsPacketCodec.extractAnswerAliases(response(TYPE_HTTPS, listOf(compressed, unterminated, brokenParams))).isEmpty())
    }

    @Test
    fun terminatesAliasCyclesWithoutCheckingUnreachableCnames() {
        val edge = "edge.publisher.example"
        val wire = response(TYPE_AAAA, listOf(
            cname("unrelated.publisher.example", TRACKER),
            cname(edge, QUESTION),
            cname(QUESTION, edge)
        ))
        assertEquals(listOf(edge), DnsPacketCodec.extractCnameTargets(wire))
        assertFalse(inspect(wire, engineWithTrackerList()).shouldBlock)
    }

    @Test
    fun respectsQueryAndTargetAllowlistsAndPassthroughOnTheSameAnswer() {
        val wire = response(TYPE_HTTPS, listOf(binding(TYPE_HTTPS, TRACKER)))
        val engine = engineWithTrackerList()
        assertFalse(inspect(wire, engine, enabled = false).shouldBlock)
        assertFalse(inspect(wire, engine, bypass = true).shouldBlock)
        assertTrue(inspect(wire, engine).shouldBlock)

        engine.updateCustomRules(listOf(rule(QUESTION, RuleType.ALLOW)))
        assertFalse(inspect(wire, engine).shouldBlock)
        engine.updateCustomRules(listOf(rule(TRACKER, RuleType.ALLOW)))
        assertFalse(inspect(wire, engine).shouldBlock)
        engine.updateCustomRules(emptyList())
        assertTrue(inspect(wire, engine).shouldBlock)
    }

    @Test
    fun protectsPlaybackTargetsButHonorsExplicitBlockRulesAndKnownAdvertMatches() {
        val playback = "rr3---sn-test.googlevideo.com"
        val advert = "ads.twitch.tv"
        val engine = engineWithTrackerList(playback, advert)
        val wire = response(TYPE_HTTPS, listOf(binding(TYPE_HTTPS, playback)))
        assertTrue(engine.evaluate(playback).isBlocked) // Confirm it is the shield's playback exception.
        assertFalse(inspect(wire, engine).shouldBlock)
        assertTrue(inspect(response(TYPE_HTTPS, listOf(binding(TYPE_HTTPS, advert))), engine).shouldBlock)
        engine.updateCustomRules(listOf(rule(playback, RuleType.BLOCK)))
        assertTrue(inspect(wire, engine).shouldBlock)
    }

    @Test
    fun blockedServiceBindingsReturnNoDataWithoutClaimingTheNameDoesNotExist() {
        for (type in listOf(TYPE_HTTPS, TYPE_SVCB)) {
            val query = query(type)
            for (sinkhole in listOf(false, true)) {
                val blocked = CnameCloakingInspector.blockedReply(query, sinkhole)
                val inspection = DnsResponseValidator.validate(query.rawPayload, blocked.bytes)
                assertEquals(0, inspection.responseCode)
                assertEquals(0, inspection.answerCount)
                assertFalse(inspection.authenticatedData)
                assertArrayEquals(query.rawPayload.copyOfRange(12, query.rawPayload.size), blocked.bytes.copyOfRange(12, blocked.bytes.size))
                assertTrue(blocked.label.contains("NODATA"))
            }
        }
        // Existing CNAME-over-address blocking modes are unchanged.
        for (type in listOf(TYPE_A, TYPE_AAAA)) {
            val query = query(type)
            val nx = CnameCloakingInspector.blockedReply(query, sinkholeZeroIp = false)
            val sink = CnameCloakingInspector.blockedReply(query, sinkholeZeroIp = true)
            assertEquals(3, DnsResponseValidator.validate(query.rawPayload, nx.bytes).responseCode)
            assertEquals(1, DnsResponseValidator.validate(query.rawPayload, sink.bytes).answerCount)
        }
    }

    private fun inspect(
        wire: ByteArray,
        engine: FilterRuleEngine,
        question: String = QUESTION,
        enabled: Boolean = true,
        bypass: Boolean = false
    ) = CnameCloakingInspector.inspect(
        questionDomain = question,
        dnsResponse = wire,
        filterEngine = engine,
        enabled = enabled,
        bypassDomainFilters = bypass
    )

    private fun engineWithTrackerList(vararg domains: String): FilterRuleEngine = FilterRuleEngine().apply {
        val list = parseFilterListContent(
            (listOf(TRACKER) + domains).joinToString("\n") { "||$it^" },
            RuleCategory.TRACKERS,
            "Test tracker list"
        ).getOrThrow()
        updateFilterListRules(list.subdomainRules, list.exactRules, list.wildcardRules, list.allowSubdomains)
    }

    private fun rule(domain: String, action: RuleType) =
        CustomRule(rawPattern = domain, normalizedPattern = domain, ruleType = action, matchType = RuleMatchType.EXACT)

    private data class Record(val owner: String, val type: Int, val data: ByteArray, val rrClass: Int = CLASS_IN)

    private fun cname(owner: String, target: String) = Record(owner, TYPE_CNAME, wire { name(target) })

    private fun binding(type: Int, target: String, owner: String = QUESTION, priority: Int = 1, params: ByteArray = byteArrayOf()) =
        Record(owner, type, wire { writeShort(priority); name(target); write(params) })

    private fun query(type: Int): DnsPacketCodec.ParsedDnsQuery = checkNotNull(DnsPacketCodec.parseQuery(wire {
        writeShort(0x1234)
        writeShort(0x0120) // RD and AD requested. The locally generated response must not claim AD.
        writeShort(1)
        repeat(3) { writeShort(0) }
        name(QUESTION)
        writeShort(type)
        writeShort(CLASS_IN)
    }))

    private fun response(
        type: Int,
        answers: List<Record>,
        question: String = QUESTION,
        additional: List<Record> = emptyList(),
        qClass: Int = CLASS_IN
    ): ByteArray = wire {
        writeShort(0x1234)
        writeShort(0x81A0) // QR, RD, RA, AD
        writeShort(1)
        writeShort(answers.size)
        writeShort(0)
        writeShort(additional.size)
        name(question)
        writeShort(type)
        writeShort(qClass)
        for (rr in answers + additional) {
            if (rr.owner == question) writeShort(0xC00C) else name(rr.owner)
            writeShort(rr.type)
            writeShort(rr.rrClass)
            writeInt(60)
            writeShort(rr.data.size)
            write(rr.data)
        }
    }

    private fun wire(block: DataOutputStream.() -> Unit): ByteArray {
        val bytes = ByteArrayOutputStream()
        DataOutputStream(bytes).use { it.block() }
        return bytes.toByteArray()
    }

    private fun DataOutputStream.name(domain: String) {
        if (domain != ".") {
            for (label in domain.split('.')) {
                writeByte(label.length)
                writeBytes(label)
            }
        }
        writeByte(0)
    }

    private companion object {
        const val QUESTION = "stats.publisher.example"
        const val TRACKER = "collector.trackers.example"
    }
}
