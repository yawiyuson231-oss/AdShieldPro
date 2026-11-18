package com.adshield.pro.engine.dns

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer

/**
 * RFC 1035 / RFC 3596 wire-format DNS message parser and synthetic response builder.
 * Hardened against malformed packets, truncated labels, and compression-pointer loops.
 */
object DnsPacketCodec {

    const val TYPE_A = 1
    const val TYPE_NS = 2
    const val TYPE_CNAME = 5
    const val TYPE_SOA = 6
    const val TYPE_PTR = 12
    const val TYPE_MX = 15
    const val TYPE_TXT = 16
    const val TYPE_AAAA = 28
    const val TYPE_SVCB = 64
    const val TYPE_HTTPS = 65

    const val CLASS_IN = 1

    private const val MAX_RESPONSE_RECORDS = 4096

    internal enum class AnswerAliasType { CNAME, HTTPS, SVCB }

    internal data class AnswerAlias(val type: AnswerAliasType, val target: String)

    data class ParsedDnsQuery(
        val transactionId: Int,
        val flags: Int,
        val questionDomain: String,
        val qType: Int,
        val qClass: Int,
        val questionSectionEndOffset: Int,
        val rawPayload: ByteArray
    ) {
        val qTypeName: String
            get() = when (qType) {
                TYPE_A -> "A"
                TYPE_AAAA -> "AAAA"
                TYPE_CNAME -> "CNAME"
                TYPE_HTTPS -> "HTTPS"
                TYPE_SVCB -> "SVCB"
                TYPE_TXT -> "TXT"
                TYPE_MX -> "MX"
                TYPE_PTR -> "PTR"
                else -> "TYPE$qType"
            }

        val cacheKey: String
            get() = "${questionDomain.lowercase()}:$qType:$qClass"
    }

    /**
     * Parses a raw DNS query packet (without TCP 2-byte length prefix).
     * Returns null if the packet is malformed, truncated, or is already a response (QR == 1).
     */
    fun parseQuery(payload: ByteArray, offset: Int = 0, length: Int = payload.size - offset): ParsedDnsQuery? {
        if (length < 12 || offset < 0 || offset + length > payload.size) return null

        val txId = ((payload[offset].toInt() and 0xFF) shl 8) or (payload[offset + 1].toInt() and 0xFF)
        val flags = ((payload[offset + 2].toInt() and 0xFF) shl 8) or (payload[offset + 3].toInt() and 0xFF)

        // QR bit (highest bit of flags) must be 0 for a query, and OPCODE (0x7800) must be 0 (QUERY)
        if ((flags and 0x8000) != 0 || (flags and 0x7800) != 0) return null

        val qdCount = ((payload[offset + 4].toInt() and 0xFF) shl 8) or (payload[offset + 5].toInt() and 0xFF)
        if (qdCount <= 0 || qdCount > 64) return null

        val limit = offset + length
        val nameResult = readDomainName(payload, offset, offset + 12, limit) ?: return null
        val afterNameOffset = nameResult.nextOffset

        // Need 4 bytes for QTYPE (2) and QCLASS (2)
        if (afterNameOffset + 4 > limit) return null

        val qType = ((payload[afterNameOffset].toInt() and 0xFF) shl 8) or
            (payload[afterNameOffset + 1].toInt() and 0xFF)
        val qClass = ((payload[afterNameOffset + 2].toInt() and 0xFF) shl 8) or
            (payload[afterNameOffset + 3].toInt() and 0xFF)

        val normalizedDomain = nameResult.domain.trimEnd('.').lowercase()
        if (normalizedDomain.isEmpty() || normalizedDomain.length > 253) return null

        val rawCopy = payload.copyOfRange(offset, limit)
        return ParsedDnsQuery(
            transactionId = txId,
            flags = flags,
            questionDomain = normalizedDomain,
            qType = qType,
            qClass = qClass,
            questionSectionEndOffset = (afterNameOffset + 4) - offset,
            rawPayload = rawCopy
        )
    }

    private data class DomainReadResult(
        val domain: String,
        val nextOffset: Int,
        val hasDotInLabel: Boolean
    ) {
        // Don't confuse literal wire labels with dotted hostnames or pass URL-like strings to
        // the filter engine. Underscores are valid in DNS service names (e.g. _dns.example).
        fun policyName(): String? {
            if (hasDotInLabel) return null
            val valid = domain.all { ch ->
                ch in 'a'..'z' || ch in 'A'..'Z' || ch in '0'..'9' || ch == '.' || ch == '-' || ch == '_'
            }
            return if (valid) domain.lowercase() else null
        }
    }

    private fun readDomainName(
        packet: ByteArray,
        msgStart: Int,
        startPos: Int,
        limit: Int,
        allowCompression: Boolean = true
    ): DomainReadResult? {
        val sb = StringBuilder(64)
        var pos = startPos
        var nextPosAfterQuestion = -1
        var jumped = false
        var jumpCount = 0
        var totalChars = 0
        var hasDotInLabel = false

        while (true) {
            if (pos >= limit || pos < msgStart) return null
            val lenByte = packet[pos].toInt() and 0xFF

            if (lenByte == 0) {
                if (!jumped) {
                    nextPosAfterQuestion = pos + 1
                }
                break
            }

            val pointerMask = lenByte and 0xC0
            if (pointerMask == 0xC0) {
                // RFC 1035 Compression pointer: 2 bytes
                if (!allowCompression || pos + 1 >= limit) return null
                if (!jumped) {
                    nextPosAfterQuestion = pos + 2
                    jumped = true
                }
                jumpCount++
                if (jumpCount > 16) {
                    // Cyclic pointer loop protection
                    return null
                }
                val pointerOffset = ((lenByte and 0x3F) shl 8) or (packet[pos + 1].toInt() and 0xFF)
                val targetPos = msgStart + pointerOffset
                if (pointerOffset < 12 || targetPos >= limit || targetPos == pos) return null
                pos = targetPos
            } else if (pointerMask == 0x00) {
                // Standard label (1..63 bytes)
                val labelLen = lenByte
                if (labelLen > 63 || pos + 1 + labelLen > limit) return null
                if (sb.isNotEmpty()) {
                    sb.append('.')
                    totalChars++
                }
                for (i in 0 until labelLen) {
                    val ch = (packet[pos + 1 + i].toInt() and 0xFF).toChar()
                    // Reject control characters
                    if (ch.code < 0x20 || ch.code == 0x7F) return null
                    if (ch == '.') hasDotInLabel = true
                    sb.append(ch)
                }
                totalChars += labelLen
                if (totalChars > 253) return null
                pos += 1 + labelLen
            } else {
                // Invalid label type bits (0x40 or 0x80)
                return null
            }
        }

        if (nextPosAfterQuestion < 0) return null
        return DomainReadResult(sb.toString(), nextPosAfterQuestion, hasDotInLabel)
    }

    /**
     * Synthesizes a wire-format DNS response for a blocked domain.
     *
     * @param query Parsed incoming DNS query
     * @param sinkholeZeroIp If true, responds with 0.0.0.0 for A and :: for AAAA (RCODE=0);
     *                       if false, responds with NXDOMAIN (RCODE=3).
     * @param ttlSeconds TTL for the synthetic record (default 60 seconds).
     */
    fun buildBlockedResponse(
        query: ParsedDnsQuery,
        sinkholeZeroIp: Boolean,
        ttlSeconds: Int = 60
    ): ByteArray = buildPolicyResponse(query, if (sinkholeZeroIp) 0 else 3, sinkholeZeroIp, ttlSeconds)

    /** Suppresses a record type without claiming the queried name doesn't exist. */
    internal fun buildNoDataResponse(query: ParsedDnsQuery): ByteArray =
        buildPolicyResponse(query, rcode = 0, sinkholeZeroIp = false, ttlSeconds = 0)

    private fun buildPolicyResponse(
        query: ParsedDnsQuery,
        rcode: Int,
        sinkholeZeroIp: Boolean,
        ttlSeconds: Int
    ): ByteArray {
        val out = ByteArrayOutputStream(128)
        val rdBit = query.flags and 0x0100 // Preserve Recursion Desired bit

        val canSinkholeIp = sinkholeZeroIp &&
            query.qClass == CLASS_IN &&
            (query.qType == TYPE_A || query.qType == TYPE_AAAA)
        // QR = 1 (0x8000), AA = 0, RA = 1 (0x0080)
        val responseFlags = 0x8000 or rdBit or 0x0080 or rcode

        val answerCount = if (canSinkholeIp) 1 else 0

        // 12-byte DNS Header
        writeU16(out, query.transactionId)
        writeU16(out, responseFlags)
        writeU16(out, 1) // QDCOUNT = 1
        writeU16(out, answerCount) // ANCOUNT
        writeU16(out, 0) // NSCOUNT = 0
        writeU16(out, 0) // ARCOUNT = 0

        // Copy original Question Section (from byte 12 to questionSectionEndOffset)
        val qSectionLen = (query.questionSectionEndOffset - 12).coerceAtLeast(0)
        if (qSectionLen > 0 && 12 + qSectionLen <= query.rawPayload.size) {
            out.write(query.rawPayload, 12, qSectionLen)
        } else {
            // Fallback question encoding
            writeDomainLabels(out, query.questionDomain)
            writeU16(out, query.qType)
            writeU16(out, query.qClass)
        }

        if (canSinkholeIp) {
            // Name pointer to offset 12 (0xC00C)
            writeU16(out, 0xC00C)
            writeU16(out, query.qType)
            writeU16(out, CLASS_IN)
            writeU32(out, ttlSeconds.toLong())
            if (query.qType == TYPE_A) {
                writeU16(out, 4) // RDLENGTH = 4 (0.0.0.0)
                out.write(byteArrayOf(0, 0, 0, 0))
            } else {
                writeU16(out, 16) // RDLENGTH = 16 (::)
                out.write(ByteArray(16))
            }
        }

        return out.toByteArray()
    }

    /**
     * Synthesizes a SERVFAIL (RCODE = 2) DNS response when upstream resolution fails completely.
     */
    fun buildServFailResponse(query: ParsedDnsQuery): ByteArray {
        val out = ByteArrayOutputStream(64)
        val rdBit = query.flags and 0x0100
        val responseFlags = 0x8000 or rdBit or 0x0080 or 2 // RCODE = 2 (SERVFAIL)

        writeU16(out, query.transactionId)
        writeU16(out, responseFlags)
        writeU16(out, 1)
        writeU16(out, 0)
        writeU16(out, 0)
        writeU16(out, 0)

        val qSectionLen = (query.questionSectionEndOffset - 12).coerceAtLeast(0)
        if (qSectionLen > 0 && 12 + qSectionLen <= query.rawPayload.size) {
            out.write(query.rawPayload, 12, qSectionLen)
        }
        return out.toByteArray()
    }

    /**
     * Returns a response that is guaranteed to fit inside a single UDP datagram of
     * [maxPayloadBytes] bytes.
     *
     * DNS answers fetched over DoH/DoT can be several kilobytes (DNSSEC, many A records,
     * EDNS0). Writing such a packet straight back to the TUN interface exceeds the interface
     * MTU, the write fails and the requesting app only sees a DNS timeout. Instead we return
     * the upstream message untouched when it fits, and otherwise synthesize a standards
     * compliant truncated answer:
     *  - transaction ID, QR, RD, RA and RCODE are preserved from the upstream response,
     *  - the TC (truncated, 0x0200) bit is set so the stub resolver retries over TCP,
     *  - the original question section is preserved and every record section is dropped
     *    (RFC 1035 §4.2.1, RFC 2181 §9).
     */
    fun fitResponseToUdpLimit(
        query: ParsedDnsQuery,
        responseBytes: ByteArray,
        maxPayloadBytes: Int
    ): ByteArray {
        if (responseBytes.size < 12) return buildServFailResponse(query)
        val limit = maxPayloadBytes.coerceAtLeast(12)
        if (responseBytes.size <= limit) return responseBytes

        val txId = ((responseBytes[0].toInt() and 0xFF) shl 8) or (responseBytes[1].toInt() and 0xFF)
        val upstreamFlags = ((responseBytes[2].toInt() and 0xFF) shl 8) or (responseBytes[3].toInt() and 0xFF)
        val truncatedFlags = (upstreamFlags or 0x8000 or 0x0200) and 0xFFFF

        fun build(includeQuestion: Boolean): ByteArray {
            val out = ByteArrayOutputStream(limit)
            writeU16(out, txId)
            writeU16(out, truncatedFlags)
            writeU16(out, if (includeQuestion) 1 else 0) // QDCOUNT
            writeU16(out, 0) // ANCOUNT
            writeU16(out, 0) // NSCOUNT
            writeU16(out, 0) // ARCOUNT
            if (includeQuestion) {
                val qSectionLen = (query.questionSectionEndOffset - 12).coerceAtLeast(0)
                if (qSectionLen > 0 && 12 + qSectionLen <= query.rawPayload.size) {
                    out.write(query.rawPayload, 12, qSectionLen)
                } else {
                    writeDomainLabels(out, query.questionDomain)
                    writeU16(out, query.qType)
                    writeU16(out, query.qClass)
                }
            }
            return out.toByteArray()
        }

        val withQuestion = build(true)
        if (withQuestion.size <= limit) return withQuestion
        // Pathologically small limit: keep the header only so the client still learns about TC.
        return build(false)
    }

    /**
     * Rewrites the 2-byte DNS Transaction ID on a cached DNS response.
     */
    fun rewriteTransactionId(dnsMessage: ByteArray, newTransactionId: Int): ByteArray {
        if (dnsMessage.size < 2) return dnsMessage
        val copy = dnsMessage.copyOf()
        copy[0] = ((newTransactionId ushr 8) and 0xFF).toByte()
        copy[1] = (newTransactionId and 0xFF).toByte()
        return copy
    }

    /**
     * Extracts a conservative cache TTL (in seconds) from an upstream DNS response, clamped to [15, 1800].
     */
    fun extractResponseTtlSeconds(dnsResponse: ByteArray): Int {
        if (dnsResponse.size < 12) return 60
        val flags = ((dnsResponse[2].toInt() and 0xFF) shl 8) or (dnsResponse[3].toInt() and 0xFF)
        val rcode = flags and 0x000F
        if (rcode != 0) return 30 // Short cache for NXDOMAIN

        val anCount = ((dnsResponse[6].toInt() and 0xFF) shl 8) or (dnsResponse[7].toInt() and 0xFF)
        if (anCount <= 0) return 60

        // Walk all answer RRs and take the minimum TTL so a long-TTL CNAME cannot mask a short A/AAAA TTL.
        val qdCount = u16At(dnsResponse, 4)
        var offset = 12
        repeat(qdCount) {
            val qRead = readDomainName(dnsResponse, 0, offset, dnsResponse.size) ?: return 120
            offset = qRead.nextOffset + 4
            if (offset > dnsResponse.size) return 120
        }
        var minTtl = Long.MAX_VALUE
        repeat(anCount.coerceAtMost(256)) {
            val nameRead = readDomainName(dnsResponse, 0, offset, dnsResponse.size) ?: return@repeat
            val rrHeader = nameRead.nextOffset
            if (rrHeader + 10 > dnsResponse.size) return@repeat
            val ttl = ByteBuffer.wrap(dnsResponse, rrHeader + 4, 4).int.toLong() and 0xFFFFFFFFL
            val rdLength = u16At(dnsResponse, rrHeader + 8)
            val nextOffset = rrHeader + 10 + rdLength
            if (nextOffset > dnsResponse.size) return@repeat
            if (ttl < minTtl) minTtl = ttl
            offset = nextOffset
        }
        if (minTtl != Long.MAX_VALUE) {
            return minTtl.coerceIn(15L, 1800L).toInt()
        }
        return 120
    }

    /**
     * Walks every resource record with bounds and compression-pointer checks.
     * Returns null for malformed wire data; otherwise returns all RR types present.
     */
    fun inspectResponseRecordTypes(message: ByteArray): Set<Int>? {
        if (message.size < 12) return null
        val qd = u16At(message, 4)
        val records = u16At(message, 6) + u16At(message, 8) + u16At(message, 10)
        if (qd != 1 || records > MAX_RESPONSE_RECORDS) return null
        var offset = 12
        val question = readDomainName(message, 0, offset, message.size) ?: return null
        offset = question.nextOffset + 4
        if (offset > message.size) return null
        val types = mutableSetOf<Int>()
        repeat(records) {
            val name = readDomainName(message, 0, offset, message.size) ?: return null
            offset = name.nextOffset
            if (offset + 10 > message.size) return null
            types.add(u16At(message, offset))
            val rdLength = u16At(message, offset + 8)
            offset += 10 + rdLength
            if (offset > message.size) return null
        }
        // Trailing bytes are not a valid DNS message and can conceal parser differentials.
        return if (offset == message.size) types else null
    }

    /** Returns normalized CNAME targets reachable from the response question. */
    fun extractCnameTargets(dnsResponse: ByteArray): List<String> = extractAnswerAliases(dnsResponse)
        .filter { it.type == AnswerAliasType.CNAME }
        .map { it.target }

    private data class AliasRecord(val alias: AnswerAlias, val follow: Boolean)

    /**
     * Selects reachable IN-class CNAME and RFC 9460 HTTPS/SVCB targets from a standard NOERROR
     * answer. Only matching service-binding types are examined, and Authority/Additional records
     * never contribute to blocking. Callers still validate the original query and full response.
     */
    internal fun extractAnswerAliases(message: ByteArray, expectedQuestion: String? = null): List<AnswerAlias> {
        if (message.size < 12) return emptyList()
        val flags = u16At(message, 2)
        // Require QR=1 and reject non-QUERY opcodes, truncation, reserved Z and nonzero RCODE.
        if (flags and 0x8000 == 0 || flags and 0x7A4F != 0) return emptyList()
        val answerCount = u16At(message, 6)
        if (u16At(message, 4) != 1 || answerCount !in 1..MAX_RESPONSE_RECORDS) return emptyList()
        val question = readDomainName(message, 0, 12, message.size) ?: return emptyList()
        val questionName = question.policyName()?.takeIf { it.isNotEmpty() } ?: return emptyList()
        if (expectedQuestion != null && !questionName.equals(expectedQuestion.trim().trimEnd('.'), ignoreCase = true)) {
            return emptyList()
        }
        var offset = question.nextOffset + 4
        if (offset > message.size || u16At(message, question.nextOffset + 2) != CLASS_IN) return emptyList()
        val questionType = u16At(message, question.nextOffset)

        // Index by owner, not wire order: the next link may appear before its parent.
        val byOwner = mutableMapOf<String, MutableList<AliasRecord>>()
        repeat(answerCount) {
            val ownerRead = readDomainName(message, 0, offset, message.size) ?: return emptyList()
            val header = ownerRead.nextOffset
            if (header + 10 > message.size) return emptyList()
            val start = header + 10
            val end = start + u16At(message, header + 8)
            if (end > message.size) return emptyList()
            offset = end
            if (u16At(message, header + 2) != CLASS_IN) return@repeat
            val wireType = u16At(message, header)
            val type = when {
                wireType == TYPE_CNAME -> AnswerAliasType.CNAME
                wireType == questionType && wireType == TYPE_HTTPS -> AnswerAliasType.HTTPS
                wireType == questionType && wireType == TYPE_SVCB -> AnswerAliasType.SVCB
                else -> return@repeat
            }
            val owner = ownerRead.policyName() ?: return@repeat
            val record = readAliasRecord(message, type, start, end) ?: return@repeat
            byOwner.getOrPut(owner) { mutableListOf() }.add(record)
        }
        if (questionName !in byOwner) return emptyList()

        val targets = linkedSetOf<AnswerAlias>()
        val visited = hashSetOf(questionName)
        val pending = ArrayDeque<String>().apply { addLast(questionName) }
        while (pending.isNotEmpty()) {
            val records = byOwner[pending.removeFirst()] ?: continue
            val hasCname = records.any { it.alias.type == AnswerAliasType.CNAME }
            // AliasMode takes precedence over ServiceMode in a service-binding RRset.
            val hasAlias = records.any { it.follow }
            for ((alias, follow) in records) {
                if ((hasCname && alias.type != AnswerAliasType.CNAME) || (hasAlias && !follow)) continue
                // Root in ServiceMode means the owner; in AliasMode it means no service.
                if (alias.target.isEmpty() || alias.target == questionName) continue
                targets.add(alias)
                if (follow && alias.target in byOwner && visited.add(alias.target)) pending.addLast(alias.target)
            }
        }
        return targets.toList()
    }

    private fun readAliasRecord(message: ByteArray, type: AnswerAliasType, start: Int, end: Int): AliasRecord? {
        if (type == AnswerAliasType.CNAME) {
            val name = readDomainName(message, 0, start, end) ?: return null
            val target = name.policyName()?.takeIf { it.isNotEmpty() } ?: return null
            if (name.nextOffset != end) return null
            return AliasRecord(AnswerAlias(type, target), follow = true)
        }

        if (end - start < 3) return null // SvcPriority plus at least the root label
        val isAliasMode = u16At(message, start) == 0
        val name = readDomainName(message, 0, start + 2, end, allowCompression = false) ?: return null
        val target = name.policyName() ?: return null
        // AliasMode recipients ignore SvcParams. In ServiceMode make sure the key/length/value
        // fields fit the RDATA and keys are ordered, without interpreting hints as hostnames.
        if (!isAliasMode && !validSvcParamFraming(message, name.nextOffset, end)) return null
        return AliasRecord(AnswerAlias(type, target), follow = isAliasMode)
    }

    private fun validSvcParamFraming(message: ByteArray, start: Int, end: Int): Boolean {
        var offset = start
        var previousKey = -1
        while (offset < end) {
            if (end - offset < 4) return false
            val key = u16At(message, offset)
            if (key <= previousKey) return false
            previousKey = key
            offset += 4 + u16At(message, offset + 2)
        }
        return offset == end
    }

    private fun u16At(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xFF) shl 8) or (bytes[offset + 1].toInt() and 0xFF)

    private fun writeDomainLabels(out: ByteArrayOutputStream, domain: String) {
        val labels = domain.trim('.').split('.')
        for (label in labels) {
            val bytes = label.toByteArray(Charsets.US_ASCII)
            out.write(bytes.size and 0x3F)
            out.write(bytes)
        }
        out.write(0)
    }

    private fun writeU16(out: ByteArrayOutputStream, value: Int) {
        out.write((value ushr 8) and 0xFF)
        out.write(value and 0xFF)
    }

    private fun writeU32(out: ByteArrayOutputStream, value: Long) {
        out.write(((value ushr 24) and 0xFF).toInt())
        out.write(((value ushr 16) and 0xFF).toInt())
        out.write(((value ushr 8) and 0xFF).toInt())
        out.write((value and 0xFF).toInt())
    }
}
