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
    const val TYPE_OPT = 41
    const val EDNS_OPTION_CLIENT_SUBNET = 8

    /** Bounds every cache lifetime is clamped to, positive or negative. */
    const val MIN_POSITIVE_TTL_SECONDS = 15L
    const val MAX_POSITIVE_TTL_SECONDS = 1800L

    /** Lifetime used when a negative answer carries no usable SOA record. */
    const val NEGATIVE_TTL_FALLBACK_SECONDS = 30

    const val CLASS_IN = 1

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

        // QR bit (highest bit of flags) must be 0 for a query
        val isResponse = (flags and 0x8000) != 0
        if (isResponse) return null

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
        val nextOffset: Int
    )

    private fun readDomainName(
        packet: ByteArray,
        msgStart: Int,
        startPos: Int,
        limit: Int
    ): DomainReadResult? {
        val sb = StringBuilder(64)
        var pos = startPos
        var nextPosAfterQuestion = -1
        var jumped = false
        var jumpCount = 0
        var totalChars = 0

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
                if (pos + 1 >= limit) return null
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
                if (targetPos < msgStart || targetPos >= limit || targetPos == pos) return null
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
        return DomainReadResult(sb.toString(), nextPosAfterQuestion)
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
    ): ByteArray {
        val out = ByteArrayOutputStream(128)
        val rdBit = query.flags and 0x0100 // Preserve Recursion Desired bit

        val canSinkholeIp = sinkholeZeroIp && (query.qType == TYPE_A || query.qType == TYPE_AAAA)
        val rcode = if (sinkholeZeroIp) 0 else 3 // 0 = NOERROR, 3 = NXDOMAIN
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
     *
     * Negative answers (NXDOMAIN and NODATA) use the RFC 2308 lifetime instead: the smaller of the
     * authority SOA record's TTL and its MINIMUM field. A server that publishes "this name does not
     * exist for an hour" is believed, and a server that publishes 30 s is not cached for longer.
     */
    fun extractResponseTtlSeconds(dnsResponse: ByteArray): Int {
        if (dnsResponse.size < 12) return 60
        val flags = ((dnsResponse[2].toInt() and 0xFF) shl 8) or (dnsResponse[3].toInt() and 0xFF)
        val rcode = flags and 0x000F
        if (rcode == 3) return extractNegativeTtlSeconds(dnsResponse) // NXDOMAIN

        val anCount = ((dnsResponse[6].toInt() and 0xFF) shl 8) or (dnsResponse[7].toInt() and 0xFF)
        // NODATA: the name exists but has no record of this type, also a negative answer.
        if (rcode == 0 && anCount <= 0) return extractNegativeTtlSeconds(dnsResponse)
        if (rcode != 0) return NEGATIVE_TTL_FALLBACK_SECONDS

        // Skip question section to inspect first answer TTL if easily reachable
        val qRead = readDomainName(dnsResponse, 0, 12, dnsResponse.size) ?: return 120
        val firstAnswerOffset = qRead.nextOffset + 4
        val nameRead = readDomainName(dnsResponse, 0, firstAnswerOffset, dnsResponse.size) ?: return 120
        val ttlOffset = nameRead.nextOffset + 4 // skip TYPE(2) + CLASS(2)
        if (ttlOffset + 4 <= dnsResponse.size) {
            val ttl = ByteBuffer.wrap(dnsResponse, ttlOffset, 4).int
            return ttl.coerceIn(MIN_POSITIVE_TTL_SECONDS.toInt(), MAX_POSITIVE_TTL_SECONDS.toInt())
        }
        return 120
    }

    /**
     * RFC 2308 negative-cache lifetime: `min(SOA TTL, SOA MINIMUM)` from the authority section,
     * clamped to the same bounds as a positive answer. Falls back to
     * [NEGATIVE_TTL_FALLBACK_SECONDS] when the response carries no usable SOA.
     */
    fun extractNegativeTtlSeconds(dnsResponse: ByteArray): Int {
        if (dnsResponse.size < 12) return NEGATIVE_TTL_FALLBACK_SECONDS
        val questionCount = u16At(dnsResponse, 4)
        val answerCount = u16At(dnsResponse, 6)
        val authorityCount = u16At(dnsResponse, 8)
        var offset = 12
        repeat(questionCount) {
            val name = readDomainName(dnsResponse, 0, offset, dnsResponse.size)
                ?: return NEGATIVE_TTL_FALLBACK_SECONDS
            offset = name.nextOffset + 4
            if (offset > dnsResponse.size) return NEGATIVE_TTL_FALLBACK_SECONDS
        }
        repeat(answerCount) {
            offset = readResourceRecord(dnsResponse, offset)?.nextOffset
                ?: return NEGATIVE_TTL_FALLBACK_SECONDS
        }
        repeat(authorityCount) {
            val record = readResourceRecord(dnsResponse, offset)
                ?: return NEGATIVE_TTL_FALLBACK_SECONDS
            offset = record.nextOffset
            if (record.type == TYPE_SOA) {
                val minimum = readSoaMinimum(dnsResponse, record.dataStart, record.dataLength)
                if (minimum != null) {
                    return minOf(record.ttlSeconds, minimum.toLong())
                        .coerceIn(MIN_POSITIVE_TTL_SECONDS, MAX_POSITIVE_TTL_SECONDS)
                        .toInt()
                }
            }
        }
        return NEGATIVE_TTL_FALLBACK_SECONDS
    }

    /** SOA MINIMUM (the last of the five 32-bit fields), or null when the RDATA is malformed. */
    private fun readSoaMinimum(packet: ByteArray, dataStart: Int, dataLength: Int): Int? {
        val end = dataStart + dataLength
        if (end > packet.size) return null
        val mname = readDomainName(packet, 0, dataStart, end) ?: return null
        val rname = readDomainName(packet, 0, mname.nextOffset, end) ?: return null
        val minimumOffset = rname.nextOffset + 16 // serial, refresh, retry, expire
        if (minimumOffset + 4 > end) return null
        return u32At(packet, minimumOffset)
    }

    private fun u32At(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xFF) shl 24) or
            ((bytes[offset + 1].toInt() and 0xFF) shl 16) or
            ((bytes[offset + 2].toInt() and 0xFF) shl 8) or
            (bytes[offset + 3].toInt() and 0xFF)

    /**
     * Walks every resource record with bounds and compression-pointer checks.
     * Returns null for malformed wire data; otherwise returns all RR types present.
     */
    fun inspectResponseRecordTypes(message: ByteArray): Set<Int>? {
        if (message.size < 12) return null
        val qd = u16At(message, 4)
        val records = u16At(message, 6) + u16At(message, 8) + u16At(message, 10)
        if (qd != 1 || records > 4096) return null
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

    /**
     * Rewrites every resource-record TTL to [ttlSeconds] so a cache hit reports the time the entry
     * still has left instead of its original lifetime.
     *
     * EDNS0 OPT records are skipped: their TTL field carries extended RCODE and flag bits, not a
     * lifetime. Returns null when the message is malformed, so callers fall back to the stored
     * bytes rather than serving a half-rewritten answer.
     */
    fun rewriteResponseTtls(message: ByteArray, ttlSeconds: Int): ByteArray? {
        if (message.size < 12) return null
        val questionCount = u16At(message, 4)
        val recordCount = u16At(message, 6) + u16At(message, 8) + u16At(message, 10)
        if (questionCount != 1 || recordCount > 4096) return null

        val copy = message.copyOf()
        var offset = 12
        val question = readDomainName(copy, 0, offset, copy.size) ?: return null
        offset = question.nextOffset + 4
        if (offset > copy.size) return null

        val ttl = ttlSeconds.coerceAtLeast(1)
        repeat(recordCount) {
            val owner = readDomainName(copy, 0, offset, copy.size) ?: return null
            offset = owner.nextOffset
            if (offset + 10 > copy.size) return null
            val type = u16At(copy, offset)
            if (type != TYPE_OPT) {
                val ttlOffset = offset + 4
                copy[ttlOffset] = ((ttl ushr 24) and 0xFF).toByte()
                copy[ttlOffset + 1] = ((ttl ushr 16) and 0xFF).toByte()
                copy[ttlOffset + 2] = ((ttl ushr 8) and 0xFF).toByte()
                copy[ttlOffset + 3] = (ttl and 0xFF).toByte()
            }
            offset += 10 + u16At(copy, offset + 8)
            if (offset > copy.size) return null
        }
        if (offset != copy.size) return null
        return copy
    }

    /**
     * Collects the CNAME targets of a response, in record order, up to [maxTargets].
     *
     * Returns an empty list when the answer contains no CNAME, and null when the message is not
     * a well-formed response. Callers must treat null as "cannot judge" and never enforce a
     * cloaking decision on data this parser could not fully walk.
     */
    fun extractCnameTargets(message: ByteArray, maxTargets: Int = 8): List<String>? {
        if (message.size < 12) return null
        if ((u16At(message, 2) and 0x8000) == 0) return null // not a response
        val questionCount = u16At(message, 4)
        val recordCount = u16At(message, 6) + u16At(message, 8) + u16At(message, 10)
        if (questionCount != 1 || recordCount > 4096) return null

        var offset = 12
        val question = readDomainName(message, 0, offset, message.size) ?: return null
        offset = question.nextOffset + 4
        if (offset > message.size) return null

        val targets = mutableListOf<String>()
        repeat(recordCount) {
            val owner = readDomainName(message, 0, offset, message.size) ?: return null
            offset = owner.nextOffset
            if (offset + 10 > message.size) return null
            val type = u16At(message, offset)
            val rdLength = u16At(message, offset + 8)
            val rdStart = offset + 10
            val rdEnd = rdStart + rdLength
            if (rdEnd > message.size) return null
            if (type == TYPE_CNAME && rdLength > 0 && targets.size < maxTargets) {
                val target = readDomainName(message, 0, rdStart, message.size) ?: return null
                // A compressed target ends two bytes into RDATA; an uncompressed one must end
                // exactly at the RDATA boundary. Anything else is a parser differential.
                if (target.nextOffset > rdEnd) return null
                if (target.domain.isNotBlank()) targets += target.domain.lowercase()
            }
            offset = rdEnd
        }
        // Trailing bytes would let two parsers disagree about the same message.
        if (offset != message.size) return null
        return targets
    }

    /**
     * Removes the EDNS Client Subnet option (RFC 7871) from an outgoing query.
     *
     * A forwarding resolver that receives a client subnet can hand it to authoritative servers,
     * which lets a CDN correlate unrelated lookups from the same device. The app only needs a
     * client subnet for the streaming hosts where geo-accurate answers were opted into, so every
     * other query is normalised before it leaves the tunnel.
     *
     * Every other option (cookie, padding, ...), the OPT record's UDP payload size, its extended
     * RCODE/version and the DO bit are preserved byte for byte. Returns the untouched array when
     * the query has no client subnet option, and null when the message cannot be walked safely so
     * the caller can forward the original query rather than a half-rewritten one.
     */
    fun stripEdnsClientSubnet(query: ByteArray): ByteArray? {
        if (query.size < 12) return null
        val questionCount = u16At(query, 4)
        val answerCount = u16At(query, 6)
        val authorityCount = u16At(query, 8)
        val additionalCount = u16At(query, 10)
        var offset = 12
        repeat(questionCount) {
            val name = readDomainName(query, 0, offset, query.size) ?: return null
            offset = name.nextOffset + 4
            if (offset > query.size) return null
        }
        repeat(answerCount + authorityCount) {
            offset = readResourceRecord(query, offset)?.nextOffset ?: return null
        }
        val additionalStart = offset
        val additional = ArrayList<WireRecord>(additionalCount)
        repeat(additionalCount) {
            val record = readResourceRecord(query, offset) ?: return null
            offset = record.nextOffset
            additional += record
        }
        // Trailing bytes would let two parsers disagree about the same message.
        if (offset != query.size) return null

        val out = ByteArrayOutputStream(query.size)
        var changed = false
        for (record in additional) {
            val stripped = if (record.type == TYPE_OPT) {
                stripClientSubnetOption(query, record.dataStart, record.dataLength)
            } else {
                null
            }
            if (stripped == null) {
                out.write(query, record.start, record.nextOffset - record.start)
            } else {
                changed = true
                out.write(query, record.start, record.typeOffset + 8 - record.start)
                writeU16(out, stripped.size)
                out.write(stripped)
            }
        }
        if (!changed) return query
        val rebuilt = ByteArrayOutputStream(query.size)
        rebuilt.write(query, 0, additionalStart)
        val additionalBytes = out.toByteArray()
        rebuilt.write(additionalBytes, 0, additionalBytes.size)
        return rebuilt.toByteArray()
    }

    private fun stripClientSubnetOption(packet: ByteArray, dataStart: Int, dataLength: Int): ByteArray? {
        val end = dataStart + dataLength
        val kept = ByteArrayOutputStream(dataLength)
        var position = dataStart
        var removed = false
        while (position < end) {
            if (position + 4 > end) return null
            val code = u16At(packet, position)
            val length = u16At(packet, position + 2)
            if (position + 4 + length > end) return null
            if (code == EDNS_OPTION_CLIENT_SUBNET) {
                removed = true
            } else {
                kept.write(packet, position, 4 + length)
            }
            position += 4 + length
        }
        return if (removed) kept.toByteArray() else null
    }

    /** One address record from an answer section, as raw bytes (4 for A, 16 for AAAA). */
    data class AddressAnswer(val type: Int, val addressBytes: ByteArray)

    /**
     * Every A and AAAA record in the answer section, in wire order, or null when the message
     * cannot be walked safely. Used by the rebinding guard; the caller decides what an address
     * means, the codec only reports what is there.
     */
    fun extractAddressAnswers(message: ByteArray, maxAnswers: Int = 64): List<AddressAnswer>? {
        if (message.size < 12) return null
        if ((u16At(message, 2) and 0x8000) == 0) return null // not a response
        val questionCount = u16At(message, 4)
        val answerCount = u16At(message, 6)
        val recordCount = answerCount + u16At(message, 8) + u16At(message, 10)
        if (questionCount != 1 || recordCount > 4096) return null

        var offset = 12
        val question = readDomainName(message, 0, offset, message.size) ?: return null
        offset = question.nextOffset + 4
        if (offset > message.size) return null

        val answers = mutableListOf<AddressAnswer>()
        repeat(recordCount) { index ->
            val owner = readDomainName(message, 0, offset, message.size) ?: return null
            offset = owner.nextOffset
            if (offset + 10 > message.size) return null
            val type = u16At(message, offset)
            val rdLength = u16At(message, offset + 8)
            val rdStart = offset + 10
            val rdEnd = rdStart + rdLength
            if (rdEnd > message.size) return null
            // Only the answer section can carry the addresses a client will connect to.
            if (index < answerCount && answers.size < maxAnswers) {
                if (type == TYPE_A && rdLength == 4) {
                    answers += AddressAnswer(TYPE_A, message.copyOfRange(rdStart, rdEnd))
                } else if (type == TYPE_AAAA && rdLength == 16) {
                    answers += AddressAnswer(TYPE_AAAA, message.copyOfRange(rdStart, rdEnd))
                }
            }
            offset = rdEnd
        }
        if (offset != message.size) return null
        return answers
    }

    /** First question of any message, query or response, with the case folded away. */
    data class WireQuestion(val domain: String, val qType: Int, val qClass: Int)

    /**
     * Reads the first question of a message regardless of the QR bit, so a response can be
     * compared with the question that was actually asked.
     */
    fun firstQuestion(message: ByteArray): WireQuestion? {
        if (message.size < 12) return null
        if (u16At(message, 4) < 1) return null
        val name = readDomainName(message, 0, 12, message.size) ?: return null
        val typeOffset = name.nextOffset
        if (typeOffset + 4 > message.size) return null
        return WireQuestion(
            domain = name.domain.lowercase().trimEnd('.'),
            qType = u16At(message, typeOffset),
            qClass = u16At(message, typeOffset + 2)
        )
    }

    private data class WireRecord(
        val start: Int,
        val typeOffset: Int,
        val nextOffset: Int,
        val type: Int,
        val ttlSeconds: Long,
        val dataStart: Int,
        val dataLength: Int
    )

    private fun readResourceRecord(packet: ByteArray, startPos: Int): WireRecord? {
        val name = readDomainName(packet, 0, startPos, packet.size) ?: return null
        val typeOffset = name.nextOffset
        if (typeOffset + 10 > packet.size) return null
        val dataLength = u16At(packet, typeOffset + 8)
        val dataStart = typeOffset + 10
        if (dataStart + dataLength > packet.size) return null
        val ttl = ((u16At(packet, typeOffset + 4).toLong() shl 16) or
            u16At(packet, typeOffset + 6).toLong())
        return WireRecord(
            start = startPos,
            typeOffset = typeOffset,
            nextOffset = dataStart + dataLength,
            type = u16At(packet, typeOffset),
            ttlSeconds = ttl,
            dataStart = dataStart,
            dataLength = dataLength
        )
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
