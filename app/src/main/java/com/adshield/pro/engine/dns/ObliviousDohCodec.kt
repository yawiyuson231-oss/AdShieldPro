package com.adshield.pro.engine.dns

import java.io.ByteArrayOutputStream
import java.net.URI
import java.net.URLEncoder
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * RFC 9230 — Oblivious DNS over HTTPS (ODoH) Wire Framing & Relay Target Builder.
 *
 * Separates the client's network address (visible only to the ODoH Relay) from the plaintext DNS
 * question (visible only to the ODoH Target), preventing any single upstream party from linking
 * client IP addresses with queried domain names.
 *
 * Implements:
 * - `ObliviousDoHMessage` binary wire encoding/decoding (`message_type` 0x01 query / 0x02 response,
 *   16-bit `key_id` length + `key_id`, 16-bit `encrypted_message` length + payload)
 * - `ObliviousDoHQueryBody` / `ObliviousDoHResponseBody` framing with deterministic RFC 9230
 *   block-aligned zero padding (`padding` bytes verified to be all `0x00` on decode)
 * - Strict HTTPS ODoH Relay URL construction (`?targethost=...&targetpath=...`) rejecting private,
 *   loopback, link-local, or non-HTTPS targets
 * - Pluggable [OdohSuite] interface so standard HPKE (`KEM+KDF+AEAD`) or symmetric test contexts
 *   can seal/open query and response bodies deterministically on the JVM.
 */
object ObliviousDohCodec {

    const val CONTENT_TYPE_ODOH = "application/oblivious-dns-message"
    const val CONTENT_TYPE_ODOH_CONFIG = "application/oblivious-dns-configs"

    const val MESSAGE_TYPE_QUERY: Int = 0x01
    const val MESSAGE_TYPE_RESPONSE: Int = 0x02

    private const val MAX_WIRE_MESSAGE_BYTES = 65_535
    private const val DEFAULT_QUERY_PAD_BLOCK = 64
    private const val DEFAULT_RESPONSE_PAD_BLOCK = 128

    data class ObliviousMessage(
        val messageType: Int,
        val keyId: ByteArray,
        val encryptedPayload: ByteArray
    ) {
        override fun equals(other: Any?): Boolean =
            other is ObliviousMessage &&
                messageType == other.messageType &&
                keyId.contentEquals(other.keyId) &&
                encryptedPayload.contentEquals(other.encryptedPayload)

        override fun hashCode(): Int {
            var result = messageType
            result = 31 * result + keyId.contentHashCode()
            result = 31 * result + encryptedPayload.contentHashCode()
            return result
        }
    }

    data class PlaintextBody(
        val dnsWire: ByteArray,
        val paddingLength: Int
    ) {
        override fun equals(other: Any?): Boolean =
            other is PlaintextBody &&
                dnsWire.contentEquals(other.dnsWire) &&
                paddingLength == other.paddingLength

        override fun hashCode(): Int = 31 * dnsWire.contentHashCode() + paddingLength
    }

    interface OdohSuite {
        val keyId: ByteArray
        fun sealQuery(plaintextQueryBody: ByteArray, aad: ByteArray): ByteArray
        fun openQuery(encryptedPayload: ByteArray, aad: ByteArray): ByteArray
        fun sealResponse(plaintextResponseBody: ByteArray, queryBody: ByteArray, aad: ByteArray): ByteArray
        fun openResponse(encryptedPayload: ByteArray, queryBody: ByteArray, aad: ByteArray): ByteArray
    }

    /**
     * Authenticated HKDF-SHA256 + AES-256-GCM ODoH cryptographic context binding responses to the
     * exact query body and RFC 9230 message header AAD (`message_type || uint16(key_id.len) || key_id`).
     */
    class AesGcmHkdfOdohSuite(
        override val keyId: ByteArray,
        sharedSecret: ByteArray,
        private val random: SecureRandom = SecureRandom()
    ) : OdohSuite {
        private val queryKey: SecretKeySpec
        private val responseMasterKey: ByteArray

        init {
            require(keyId.isNotEmpty() && keyId.size <= 256) { "Invalid ODoH key_id length" }
            require(sharedSecret.size >= 16) { "ODoH shared secret must be at least 16 bytes" }
            val prk = hmacSha256(keyId, sharedSecret)
            queryKey = SecretKeySpec(hmacSha256(prk, "odoh-query-key".toByteArray(Charsets.US_ASCII)), "AES")
            responseMasterKey = hmacSha256(prk, "odoh-response-secret".toByteArray(Charsets.US_ASCII))
        }

        override fun sealQuery(plaintextQueryBody: ByteArray, aad: ByteArray): ByteArray {
            val nonce = ByteArray(12).also { random.nextBytes(it) }
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, queryKey, GCMParameterSpec(128, nonce))
            cipher.updateAAD(aad)
            return nonce + cipher.doFinal(plaintextQueryBody)
        }

        override fun openQuery(encryptedPayload: ByteArray, aad: ByteArray): ByteArray {
            require(encryptedPayload.size >= 28) { "Truncated ODoH encrypted query" }
            val nonce = encryptedPayload.copyOfRange(0, 12)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, queryKey, GCMParameterSpec(128, nonce))
            cipher.updateAAD(aad)
            return cipher.doFinal(encryptedPayload, 12, encryptedPayload.size - 12)
        }

        override fun sealResponse(plaintextResponseBody: ByteArray, queryBody: ByteArray, aad: ByteArray): ByteArray {
            val responseNonce = ByteArray(16).also { random.nextBytes(it) }
            val (key, gcmNonce) = deriveResponseKeyAndNonce(queryBody, responseNonce)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, gcmNonce))
            cipher.updateAAD(aad)
            return responseNonce + cipher.doFinal(plaintextResponseBody)
        }

        override fun openResponse(encryptedPayload: ByteArray, queryBody: ByteArray, aad: ByteArray): ByteArray {
            require(encryptedPayload.size >= 32) { "Truncated ODoH encrypted response" }
            val responseNonce = encryptedPayload.copyOfRange(0, 16)
            val (key, gcmNonce) = deriveResponseKeyAndNonce(queryBody, responseNonce)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, gcmNonce))
            cipher.updateAAD(aad)
            return cipher.doFinal(encryptedPayload, 16, encryptedPayload.size - 16)
        }

        private fun deriveResponseKeyAndNonce(
            queryBody: ByteArray,
            responseNonce: ByteArray
        ): Pair<SecretKeySpec, ByteArray> {
            val prk = hmacSha256(responseMasterKey, queryBody + responseNonce)
            val keyBytes = hmacSha256(prk, "odoh-resp-aes256".toByteArray(Charsets.US_ASCII))
            val nonceBytes = hmacSha256(prk, "odoh-resp-nonce".toByteArray(Charsets.US_ASCII)).copyOfRange(0, 12)
            return SecretKeySpec(keyBytes, "AES") to nonceBytes
        }

        private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(key, "HmacSHA256"))
            return mac.doFinal(data)
        }
    }

    /** Encodes a DNS payload + RFC 9230 zero padding into an `ObliviousDoHQueryBody` / `ResponseBody`. */
    fun encodePlaintextBody(dnsWire: ByteArray, padBlockBytes: Int = DEFAULT_QUERY_PAD_BLOCK): ByteArray {
        require(dnsWire.size in 12..MAX_WIRE_MESSAGE_BYTES) { "Invalid DNS wire size: ${dnsWire.size}" }
        val block = padBlockBytes.coerceIn(1, 4096)
        val baseLen = 2 + dnsWire.size + 2
        val remainder = baseLen % block
        val padLen = if (remainder == 0) 0 else (block - remainder)
        val out = ByteArrayOutputStream(baseLen + padLen)
        writeU16(out, dnsWire.size)
        out.write(dnsWire)
        writeU16(out, padLen)
        if (padLen > 0) {
            out.write(ByteArray(padLen))
        }
        return out.toByteArray()
    }

    /** Decodes and validates an `ObliviousDoHQueryBody` or `ObliviousDoHResponseBody` per RFC 9230 §4. */
    fun decodePlaintextBody(body: ByteArray): PlaintextBody {
        require(body.size >= 16) { "ODoH body shorter than minimum DNS header + lengths" }
        val dnsLen = readU16(body, 0)
        require(dnsLen >= 12 && 2 + dnsLen + 2 <= body.size) { "Malformed ODoH dns_message length" }
        val dnsWire = body.copyOfRange(2, 2 + dnsLen)
        val padLenOffset = 2 + dnsLen
        val padLen = readU16(body, padLenOffset)
        require(padLenOffset + 2 + padLen == body.size) { "ODoH body trailing or truncated padding" }
        for (i in (padLenOffset + 2) until body.size) {
            if (body[i].toInt() != 0) {
                throw IllegalArgumentException("RFC 9230 violation: non-zero byte in ODoH padding")
            }
        }
        return PlaintextBody(dnsWire = dnsWire, paddingLength = padLen)
    }

    /** Encodes an `ObliviousDoHMessage` wire structure. */
    fun encodeMessage(message: ObliviousMessage): ByteArray {
        require(message.messageType == MESSAGE_TYPE_QUERY || message.messageType == MESSAGE_TYPE_RESPONSE) {
            "Unsupported ODoH message_type: ${message.messageType}"
        }
        require(message.keyId.size <= MAX_WIRE_MESSAGE_BYTES) { "key_id exceeds uint16" }
        require(message.encryptedPayload.isNotEmpty() && message.encryptedPayload.size <= MAX_WIRE_MESSAGE_BYTES) {
            "Invalid encrypted_message length"
        }
        val out = ByteArrayOutputStream(5 + message.keyId.size + message.encryptedPayload.size)
        out.write(message.messageType and 0xFF)
        writeU16(out, message.keyId.size)
        out.write(message.keyId)
        writeU16(out, message.encryptedPayload.size)
        out.write(message.encryptedPayload)
        return out.toByteArray()
    }

    /** Decodes an `ObliviousDoHMessage` wire structure with exact bounds checks. */
    fun decodeMessage(wire: ByteArray): ObliviousMessage {
        require(wire.size >= 6) { "ODoH wire message truncated" }
        val msgType = wire[0].toInt() and 0xFF
        require(msgType == MESSAGE_TYPE_QUERY || msgType == MESSAGE_TYPE_RESPONSE) {
            "Invalid ODoH message_type: $msgType"
        }
        val keyIdLen = readU16(wire, 1)
        require(3 + keyIdLen + 2 <= wire.size) { "ODoH key_id truncated" }
        val keyId = wire.copyOfRange(3, 3 + keyIdLen)
        val encOffset = 3 + keyIdLen
        val encLen = readU16(wire, encOffset)
        require(encLen > 0 && encOffset + 2 + encLen == wire.size) {
            "ODoH encrypted_message length mismatch"
        }
        val encrypted = wire.copyOfRange(encOffset + 2, wire.size)
        return ObliviousMessage(
            messageType = msgType,
            keyId = keyId,
            encryptedPayload = encrypted
        )
    }

    /** Seals a raw DNS wire query into a ready-to-POST `application/oblivious-dns-message` payload. */
    fun buildObliviousQuery(
        dnsQueryWire: ByteArray,
        suite: OdohSuite,
        padBlockBytes: Int = DEFAULT_QUERY_PAD_BLOCK
    ): Pair<ByteArray, ByteArray> {
        val queryBody = encodePlaintextBody(dnsQueryWire, padBlockBytes)
        val aad = buildMessageAad(MESSAGE_TYPE_QUERY, suite.keyId)
        val encrypted = suite.sealQuery(queryBody, aad)
        val wire = encodeMessage(
            ObliviousMessage(
                messageType = MESSAGE_TYPE_QUERY,
                keyId = suite.keyId.copyOf(),
                encryptedPayload = encrypted
            )
        )
        return wire to queryBody
    }

    /** Opens an `application/oblivious-dns-message` query at the target. */
    fun openObliviousQuery(wire: ByteArray, suite: OdohSuite): Pair<PlaintextBody, ByteArray> {
        val msg = decodeMessage(wire)
        require(msg.messageType == MESSAGE_TYPE_QUERY) { "Expected ODoH query message (0x01)" }
        require(msg.keyId.contentEquals(suite.keyId)) { "Unknown ODoH key_id" }
        val aad = buildMessageAad(MESSAGE_TYPE_QUERY, msg.keyId)
        val queryBody = suite.openQuery(msg.encryptedPayload, aad)
        return decodePlaintextBody(queryBody) to queryBody
    }

    /** Seals a DNS wire response bound to [queryBody] into an `ObliviousDoHMessage` (type `0x02`). */
    fun buildObliviousResponse(
        dnsResponseWire: ByteArray,
        queryBody: ByteArray,
        suite: OdohSuite,
        padBlockBytes: Int = DEFAULT_RESPONSE_PAD_BLOCK
    ): ByteArray {
        val responseBody = encodePlaintextBody(dnsResponseWire, padBlockBytes)
        val emptyResponseKeyId = ByteArray(0)
        val aad = buildMessageAad(MESSAGE_TYPE_RESPONSE, emptyResponseKeyId)
        val encrypted = suite.sealResponse(responseBody, queryBody, aad)
        return encodeMessage(
            ObliviousMessage(
                messageType = MESSAGE_TYPE_RESPONSE,
                keyId = emptyResponseKeyId,
                encryptedPayload = encrypted
            )
        )
    }

    /** Opens and validates an `application/oblivious-dns-message` response bound to [queryBody]. */
    fun openObliviousResponse(
        responseWire: ByteArray,
        queryBody: ByteArray,
        suite: OdohSuite
    ): PlaintextBody {
        val msg = decodeMessage(responseWire)
        require(msg.messageType == MESSAGE_TYPE_RESPONSE) { "Expected ODoH response message (0x02)" }
        require(msg.keyId.isEmpty()) { "RFC 9230 requires empty key_id on ODoH responses" }
        val aad = buildMessageAad(MESSAGE_TYPE_RESPONSE, msg.keyId)
        val plainBody = suite.openResponse(msg.encryptedPayload, queryBody, aad)
        return decodePlaintextBody(plainBody)
    }

    /**
     * Constructs an RFC 9230 §5.1 relay request URL (`https://relay.example/proxy?targethost=...&targetpath=...`)
     * while strictly enforcing HTTPS and rejecting private/loopback/IP-literal SSRF targets.
     */
    fun buildRelayRequestUrl(
        relayUrl: String,
        targetUrl: String
    ): String {
        val relayUri = runCatching { URI(relayUrl.trim()) }.getOrNull()
            ?: throw IllegalArgumentException("Invalid ODoH relay URL")
        val targetUri = runCatching { URI(targetUrl.trim()) }.getOrNull()
            ?: throw IllegalArgumentException("Invalid ODoH target URL")

        require(relayUri.scheme.equals("https", ignoreCase = true)) { "ODoH relay must use HTTPS" }
        require(targetUri.scheme.equals("https", ignoreCase = true)) { "ODoH target must use HTTPS" }

        val relayHost = relayUri.host?.lowercase()?.trimEnd('.')
            ?: throw IllegalArgumentException("ODoH relay hostname missing")
        val targetHost = targetUri.host?.lowercase()?.trimEnd('.')
            ?: throw IllegalArgumentException("ODoH target hostname missing")

        require(!isForbiddenHost(relayHost)) { "ODoH relay host cannot be loopback or private" }
        require(!isForbiddenHost(targetHost)) { "ODoH target host cannot be loopback or private" }
        require(!relayHost.equals(targetHost, ignoreCase = true)) {
            "ODoH relay and target must be operated on distinct hosts to preserve unlinkability"
        }

        val targetHostWithPort = if (targetUri.port != -1 && targetUri.port != 443) {
            "$targetHost:${targetUri.port}"
        } else {
            targetHost
        }
        val rawPath = targetUri.rawPath?.takeIf { it.isNotBlank() } ?: "/dns-query"
        require(rawPath.startsWith("/")) { "ODoH target path must start with '/'" }

        val encodedHost = URLEncoder.encode(targetHostWithPort, "UTF-8")
        val encodedPath = URLEncoder.encode(rawPath, "UTF-8")
        val baseRelay = URI(
            "https",
            null,
            relayHost,
            relayUri.port,
            relayUri.rawPath?.takeIf { it.isNotBlank() } ?: "/proxy",
            null,
            null
        ).toASCIIString()
        return "$baseRelay?targethost=$encodedHost&targetpath=$encodedPath"
    }

    private fun isForbiddenHost(host: String): Boolean {
        if (host.isBlank() || host == "localhost" || host.endsWith(".localhost") || host.endsWith(".local")) {
            return true
        }
        if (host.startsWith("127.") || host.startsWith("10.") || host.startsWith("192.168.") ||
            host.startsWith("169.254.") || host == "0.0.0.0" || host == "::1" || host.startsWith("[")
        ) {
            return true
        }
        if (host.startsWith("172.")) {
            val second = host.split('.').getOrNull(1)?.toIntOrNull()
            if (second != null && second in 16..31) return true
        }
        return false
    }

    private fun buildMessageAad(messageType: Int, keyId: ByteArray): ByteArray {
        val out = ByteArrayOutputStream(3 + keyId.size)
        out.write(messageType and 0xFF)
        writeU16(out, keyId.size)
        out.write(keyId)
        return out.toByteArray()
    }

    private fun writeU16(out: ByteArrayOutputStream, value: Int) {
        out.write((value ushr 8) and 0xFF)
        out.write(value and 0xFF)
    }

    private fun readU16(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xFF) shl 8) or (bytes[offset + 1].toInt() and 0xFF)
}
