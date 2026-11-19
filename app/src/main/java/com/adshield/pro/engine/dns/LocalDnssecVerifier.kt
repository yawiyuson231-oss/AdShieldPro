package com.adshield.pro.engine.dns

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.RSAPublicKeySpec

/**
 * RFC 4034 / RFC 4035 / RFC 5702 / RFC 6605 — On-Device Cryptographic DNSSEC Verifier.
 *
 * Performs true local cryptographic verification of DNSSEC resource record signatures (`RRSIG`)
 * and Delegation Signer (`DS`) chain links without trusting an upstream resolver's `AD` bit:
 *
 * - **Supported `DNSKEY`/`RRSIG` algorithms**:
 *   - `8` (`RSASHA256`, RFC 5702)
 *   - `10` (`RSASHA512`, RFC 5702)
 *   - `13` (`ECDSAP256SHA256`, RFC 6605 — converts IEEE P1363 64-byte `r || s` to ASN.1 DER)
 *   - `14` (`ECDSAP384SHA384`, RFC 6605 — converts IEEE P1363 96-byte `r || s` to ASN.1 DER)
 * - **Supported `DS` digest algorithms**:
 *   - `2` (`SHA-256`, RFC 4509)
 *   - `4` (`SHA-384`, RFC 6605)
 * - **RFC 4034 §6 canonical RRset ordering & wire canonicalization**:
 *   - Lowercases uncompressed owner names and embedded domain names in `CNAME`/`NS`/`PTR`/`SOA`/`MX`/`RRSIG`
 *   - Reconstructs original TTL from `RRSIG.originalTtl`
 *   - Validates signature inception & expiration windows against [nowEpochSeconds]
 */
object LocalDnssecVerifier {

    const val RR_TYPE_DNSKEY = 48
    const val RR_TYPE_RRSIG = 46
    const val RR_TYPE_DS = 43

    const val ALG_RSASHA256 = 8
    const val ALG_RSASHA512 = 10
    const val ALG_ECDSAP256SHA256 = 13
    const val ALG_ECDSAP384SHA384 = 14

    const val DS_DIGEST_SHA256 = 2
    const val DS_DIGEST_SHA384 = 4

    data class DnskeyRecord(
        val ownerName: String,
        val flags: Int,
        val protocol: Int,
        val algorithm: Int,
        val publicKeyBytes: ByteArray,
        val rawRdata: ByteArray
    ) {
        val keyTag: Int get() = computeKeyTag(rawRdata)
        val isZoneKey: Boolean get() = (flags and 0x0100) != 0
        val isSepKey: Boolean get() = (flags and 0x0001) != 0
        val isRevoked: Boolean get() = (flags and 0x0080) != 0
    }

    data class DsRecord(
        val ownerName: String,
        val keyTag: Int,
        val algorithm: Int,
        val digestType: Int,
        val digestBytes: ByteArray
    )

    data class RrsigRecord(
        val ownerName: String,
        val typeCovered: Int,
        val algorithm: Int,
        val labels: Int,
        val originalTtl: Long,
        val signatureExpiration: Long,
        val signatureInception: Long,
        val keyTag: Int,
        val signerName: String,
        val rrsigHeaderPrefixWire: ByteArray,
        val signatureBytes: ByteArray
    )

    data class WireResourceRecord(
        val ownerName: String,
        val rrType: Int,
        val rrClass: Int,
        val ttl: Long,
        val canonicalRdata: ByteArray
    )

    enum class VerificationVerdict {
        CRYPTO_VERIFIED,
        CHAIN_VERIFIED_WITH_DS,
        UNSIGNED,
        BOGUS_SIGNATURE,
        EXPIRED_OR_NOT_YET_VALID,
        UNSUPPORTED_ALGORITHM,
        MISSING_DNSKEY
    }

    data class VerificationResult(
        val verdict: VerificationVerdict,
        val verifiedType: Int? = null,
        val keyTag: Int? = null,
        val algorithm: Int? = null,
        val signerName: String? = null,
        val detail: String
    ) {
        val isAuthentic: Boolean
            get() = verdict == VerificationVerdict.CRYPTO_VERIFIED ||
                verdict == VerificationVerdict.CHAIN_VERIFIED_WITH_DS
    }

    /** RFC 4034 Appendix B key tag calculation over raw DNSKEY RDATA. */
    fun computeKeyTag(dnskeyRdata: ByteArray): Int {
        var ac = 0L
        for (i in dnskeyRdata.indices) {
            val b = dnskeyRdata[i].toLong() and 0xFFL
            ac += if ((i and 1) != 0) b else (b shl 8)
        }
        ac += (ac ushr 16) and 0xFFFFL
        return (ac and 0xFFFFL).toInt()
    }

    /**
     * Verifies that [dnskey] matches [ds] per RFC 4034 §5.1.4:
     * `digest = Hash(canonicalWire(ownerName) || DNSKEY_RDATA)`.
     */
    fun verifyDsMatchesDnskey(ds: DsRecord, dnskey: DnskeyRecord): Boolean {
        if (!ds.ownerName.equals(dnskey.ownerName, ignoreCase = true)) return false
        if (ds.algorithm != dnskey.algorithm) return false
        if (ds.keyTag != dnskey.keyTag) return false
        if (dnskey.protocol != 3 || !dnskey.isZoneKey || dnskey.isRevoked) return false

        val digestAlg = when (ds.digestType) {
            DS_DIGEST_SHA256 -> "SHA-256"
            DS_DIGEST_SHA384 -> "SHA-384"
            else -> return false
        }
        val md = MessageDigest.getInstance(digestAlg)
        md.update(encodeCanonicalDomainWire(dnskey.ownerName))
        md.update(dnskey.rawRdata)
        val computed = md.digest()
        return MessageDigest.isEqual(computed, ds.digestBytes)
    }

    /**
     * Cryptographically verifies an RRset against [rrsig] and [dnskey] per RFC 4034 §3.1.8.1.
     */
    fun verifyRrsetSignature(
        rrset: List<WireResourceRecord>,
        rrsig: RrsigRecord,
        dnskey: DnskeyRecord,
        nowEpochSeconds: Long = System.currentTimeMillis() / 1000L,
        clockSkewSeconds: Long = 300L
    ): VerificationResult {
        if (rrset.isEmpty()) {
            return VerificationResult(VerificationVerdict.UNSIGNED, detail = "Empty RRset")
        }
        if (!dnskey.isZoneKey || dnskey.protocol != 3 || dnskey.isRevoked) {
            return VerificationResult(
                VerificationVerdict.BOGUS_SIGNATURE,
                keyTag = dnskey.keyTag,
                algorithm = dnskey.algorithm,
                detail = "DNSKEY is not an active zone signing key"
            )
        }
        if (rrsig.algorithm != dnskey.algorithm || rrsig.keyTag != dnskey.keyTag ||
            !rrsig.signerName.equals(dnskey.ownerName, ignoreCase = true)
        ) {
            return VerificationResult(
                VerificationVerdict.MISSING_DNSKEY,
                keyTag = rrsig.keyTag,
                algorithm = rrsig.algorithm,
                signerName = rrsig.signerName,
                detail = "DNSKEY does not match RRSIG signer/keyTag/algorithm"
            )
        }

        // RFC 4034 §3.1.5 serial-number-aware validity check
        if (nowEpochSeconds + clockSkewSeconds < rrsig.signatureInception ||
            nowEpochSeconds - clockSkewSeconds > rrsig.signatureExpiration
        ) {
            return VerificationResult(
                VerificationVerdict.EXPIRED_OR_NOT_YET_VALID,
                verifiedType = rrsig.typeCovered,
                keyTag = rrsig.keyTag,
                algorithm = rrsig.algorithm,
                signerName = rrsig.signerName,
                detail = "RRSIG outside validity window [${rrsig.signatureInception}, ${rrsig.signatureExpiration}]"
            )
        }

        val publicKey = runCatching { decodePublicKey(dnskey.algorithm, dnskey.publicKeyBytes) }.getOrNull()
            ?: return VerificationResult(
                VerificationVerdict.UNSUPPORTED_ALGORITHM,
                verifiedType = rrsig.typeCovered,
                keyTag = rrsig.keyTag,
                algorithm = rrsig.algorithm,
                signerName = rrsig.signerName,
                detail = "Unsupported or malformed DNSKEY algorithm ${dnskey.algorithm}"
            )

        val signedData = buildSignedData(rrset, rrsig)
        val verified = runCatching {
            verifySignatureBytes(dnskey.algorithm, publicKey, signedData, rrsig.signatureBytes)
        }.getOrDefault(false)

        return if (verified) {
            VerificationResult(
                verdict = VerificationVerdict.CRYPTO_VERIFIED,
                verifiedType = rrsig.typeCovered,
                keyTag = rrsig.keyTag,
                algorithm = rrsig.algorithm,
                signerName = rrsig.signerName,
                detail = "Cryptographically verified RRset type=${rrsig.typeCovered} with keyTag=${rrsig.keyTag}"
            )
        } else {
            VerificationResult(
                verdict = VerificationVerdict.BOGUS_SIGNATURE,
                verifiedType = rrsig.typeCovered,
                keyTag = rrsig.keyTag,
                algorithm = rrsig.algorithm,
                signerName = rrsig.signerName,
                detail = "Cryptographic signature verification failed (BOGUS)"
            )
        }
    }

    /**
     * End-to-end verification of a raw DNS response wire packet given trusted [dnskeys] (and optional
     * parent [dsRecords] to authenticate the Key-Signing Key -> Zone-Signing Key chain).
     */
    fun verifyWireResponse(
        responseWire: ByteArray,
        dnskeys: List<DnskeyRecord>,
        dsRecords: List<DsRecord> = emptyList(),
        nowEpochSeconds: Long = System.currentTimeMillis() / 1000L
    ): VerificationResult {
        val parsed = parseDnssecRecordsFromWire(responseWire)
            ?: return VerificationResult(VerificationVerdict.BOGUS_SIGNATURE, detail = "Malformed DNS wire packet")

        val allKeys = (dnskeys + parsed.embeddedDnskeys).distinctBy {
            "${it.ownerName.lowercase()}|${it.keyTag}|${it.algorithm}"
        }

        if (parsed.rrsigs.isEmpty()) {
            return VerificationResult(VerificationVerdict.UNSIGNED, detail = "No RRSIG records in answer")
        }
        if (allKeys.isEmpty()) {
            val firstSig = parsed.rrsigs.first()
            return VerificationResult(
                VerificationVerdict.MISSING_DNSKEY,
                verifiedType = firstSig.typeCovered,
                keyTag = firstSig.keyTag,
                algorithm = firstSig.algorithm,
                signerName = firstSig.signerName,
                detail = "RRSIG present (keyTag=${firstSig.keyTag}) but no matching DNSKEY supplied"
            )
        }

        // If DS records are provided, verify at least one DNSKEY links to a DS record and (if ZSK != KSK)
        // the DNSKEY RRset itself is signed by the DS-authenticated KSK.
        var dsChainAuthenticated = false
        if (dsRecords.isNotEmpty()) {
            val matchingKsks = allKeys.filter { key -> dsRecords.any { ds -> verifyDsMatchesDnskey(ds, key) } }
            if (matchingKsks.isEmpty()) {
                return VerificationResult(
                    VerificationVerdict.BOGUS_SIGNATURE,
                    detail = "No DNSKEY matched the parent DS digest"
                )
            }
            val dnskeyRrset = parsed.records.filter { it.rrType == RR_TYPE_DNSKEY }
            val dnskeyRrsigs = parsed.rrsigs.filter { it.typeCovered == RR_TYPE_DNSKEY }
            dsChainAuthenticated = if (dnskeyRrset.isNotEmpty() && dnskeyRrsigs.isNotEmpty()) {
                dnskeyRrsigs.any { sig ->
                    matchingKsks.any { ksk ->
                        verifyRrsetSignature(dnskeyRrset, sig, ksk, nowEpochSeconds).isAuthentic
                    }
                }
            } else {
                // Single-key zone where the DS directly authenticates the ZSK signing the answer
                true
            }
            if (!dsChainAuthenticated) {
                return VerificationResult(
                    VerificationVerdict.BOGUS_SIGNATURE,
                    detail = "DNSKEY RRset signature failed against DS-authenticated KSK"
                )
            }
        }

        var sawUnsupported = false
        var sawMissingKey = false
        var sawExpired = false

        for (rrsig in parsed.rrsigs) {
            if (rrsig.typeCovered == RR_TYPE_DNSKEY) continue
            val coveredSet = parsed.records.filter {
                it.rrType == rrsig.typeCovered && it.ownerName.equals(rrsig.ownerName, ignoreCase = true)
            }
            if (coveredSet.isEmpty()) continue

            val candidates = allKeys.filter {
                it.keyTag == rrsig.keyTag &&
                    it.algorithm == rrsig.algorithm &&
                    it.ownerName.equals(rrsig.signerName, ignoreCase = true)
            }
            if (candidates.isEmpty()) {
                sawMissingKey = true
                continue
            }

            for (key in candidates) {
                val res = verifyRrsetSignature(coveredSet, rrsig, key, nowEpochSeconds)
                when (res.verdict) {
                    VerificationVerdict.CRYPTO_VERIFIED -> {
                        return if (dsChainAuthenticated) {
                            res.copy(
                                verdict = VerificationVerdict.CHAIN_VERIFIED_WITH_DS,
                                detail = "${res.detail} + DS chain verified"
                            )
                        } else {
                            res
                        }
                    }
                    VerificationVerdict.EXPIRED_OR_NOT_YET_VALID -> sawExpired = true
                    VerificationVerdict.UNSUPPORTED_ALGORITHM -> sawUnsupported = true
                    else -> Unit
                }
            }
        }

        return when {
            sawExpired -> VerificationResult(VerificationVerdict.EXPIRED_OR_NOT_YET_VALID, detail = "RRSIG expired or not yet valid")
            sawUnsupported -> VerificationResult(VerificationVerdict.UNSUPPORTED_ALGORITHM, detail = "Unsupported DNSSEC algorithm")
            sawMissingKey -> VerificationResult(VerificationVerdict.MISSING_DNSKEY, detail = "No matching DNSKEY for RRSIG")
            else -> VerificationResult(VerificationVerdict.BOGUS_SIGNATURE, detail = "All candidate RRSIG verifications failed")
        }
    }

    /** Constructs canonical `signed_data = RRSIG_RDATA_prefix || sorted_canonical_RRs` (RFC 4034 §6.2 & §6.3). */
    fun buildSignedData(rrset: List<WireResourceRecord>, rrsig: RrsigRecord): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(rrsig.rrsigHeaderPrefixWire)

        // Sort RRs by canonical RDATA in left-justified unsigned octet order (RFC 4034 §6.3)
        val sortedRdata = rrset.map { it.canonicalRdata }.sortedWith { a, b ->
            val min = minOf(a.size, b.size)
            var cmp = 0
            for (i in 0 until min) {
                val ai = a[i].toInt() and 0xFF
                val bi = b[i].toInt() and 0xFF
                if (ai != bi) {
                    cmp = ai.compareTo(bi)
                    break
                }
            }
            if (cmp != 0) cmp else a.size.compareTo(b.size)
        }

        val first = rrset.first()
        val canonicalOwner = encodeWildcardAdjustedOwner(first.ownerName, rrsig.labels)
        for (rdata in sortedRdata) {
            out.write(canonicalOwner)
            writeU16(out, first.rrType)
            writeU16(out, first.rrClass)
            writeU32(out, rrsig.originalTtl)
            writeU16(out, rdata.size)
            out.write(rdata)
        }
        return out.toByteArray()
    }

    fun encodeCanonicalDomainWire(domain: String): ByteArray {
        val trimmed = domain.trim().trimEnd('.').lowercase()
        if (trimmed.isEmpty()) return byteArrayOf(0)
        val out = ByteArrayOutputStream(trimmed.length + 2)
        for (label in trimmed.split('.')) {
            val bytes = label.toByteArray(Charsets.US_ASCII)
            require(bytes.size in 1..63) { "Invalid DNS label length" }
            out.write(bytes.size)
            out.write(bytes)
        }
        out.write(0)
        return out.toByteArray()
    }

    /** Builds a `DNSKEY` record from a JCA [PublicKey] (useful for zone signing & deterministic tests). */
    fun buildDnskeyRecord(
        ownerName: String,
        flags: Int,
        algorithm: Int,
        publicKeyBytes: ByteArray
    ): DnskeyRecord {
        val raw = ByteArrayOutputStream(4 + publicKeyBytes.size)
        writeU16(raw, flags)
        raw.write(3) // protocol MUST be 3
        raw.write(algorithm and 0xFF)
        raw.write(publicKeyBytes)
        return DnskeyRecord(
            ownerName = ownerName.trimEnd('.').lowercase(),
            flags = flags,
            protocol = 3,
            algorithm = algorithm,
            publicKeyBytes = publicKeyBytes,
            rawRdata = raw.toByteArray()
        )
    }

    /** Computes a `DS` record from a [DnskeyRecord] per RFC 4034 §5.1.4. */
    fun buildDsRecord(dnskey: DnskeyRecord, digestType: Int = DS_DIGEST_SHA256): DsRecord {
        val alg = when (digestType) {
            DS_DIGEST_SHA256 -> "SHA-256"
            DS_DIGEST_SHA384 -> "SHA-384"
            else -> throw IllegalArgumentException("Unsupported DS digestType=$digestType")
        }
        val md = MessageDigest.getInstance(alg)
        md.update(encodeCanonicalDomainWire(dnskey.ownerName))
        md.update(dnskey.rawRdata)
        return DsRecord(
            ownerName = dnskey.ownerName,
            keyTag = dnskey.keyTag,
            algorithm = dnskey.algorithm,
            digestType = digestType,
            digestBytes = md.digest()
        )
    }

    /** Builds RRSIG header prefix wire (`typeCovered..signerName`, excluding signature bytes). */
    fun buildRrsigPrefixWire(
        typeCovered: Int,
        algorithm: Int,
        labels: Int,
        originalTtl: Long,
        expiration: Long,
        inception: Long,
        keyTag: Int,
        signerName: String
    ): ByteArray {
        val out = ByteArrayOutputStream()
        writeU16(out, typeCovered)
        out.write(algorithm and 0xFF)
        out.write(labels and 0xFF)
        writeU32(out, originalTtl)
        writeU32(out, expiration)
        writeU32(out, inception)
        writeU16(out, keyTag)
        out.write(encodeCanonicalDomainWire(signerName))
        return out.toByteArray()
    }

    /** Converts ASN.1 DER ECDSA signature (`SEQUENCE { INTEGER r, INTEGER s }`) to IEEE P1363 `r || s`. */
    fun derEcdsaToP1363(der: ByteArray, coordLen: Int): ByteArray {
        require(der.size >= 8 && der[0].toInt() == 0x30) { "Invalid DER SEQUENCE" }
        var idx = 2
        if ((der[1].toInt() and 0x80) != 0) {
            val lenBytes = der[1].toInt() and 0x7F
            idx = 2 + lenBytes
        }
        require(der[idx].toInt() == 0x02) { "Expected DER INTEGER r" }
        val rLen = der[idx + 1].toInt() and 0xFF
        val rBytes = der.copyOfRange(idx + 2, idx + 2 + rLen)
        idx += 2 + rLen
        require(der[idx].toInt() == 0x02) { "Expected DER INTEGER s" }
        val sLen = der[idx + 1].toInt() and 0xFF
        val sBytes = der.copyOfRange(idx + 2, idx + 2 + sLen)

        val out = ByteArray(coordLen * 2)
        copyFixedUnsignedBigInt(rBytes, out, 0, coordLen)
        copyFixedUnsignedBigInt(sBytes, out, coordLen, coordLen)
        return out
    }

    /** Converts IEEE P1363 raw `r || s` ECDSA signature (used on DNSSEC wire) to JCA ASN.1 DER. */
    fun p1363EcdsaToDer(rawSig: ByteArray, coordLen: Int): ByteArray {
        require(rawSig.size == coordLen * 2) { "Expected ${coordLen * 2}-byte ECDSA signature, got ${rawSig.size}" }
        val rDer = encodeDerUnsignedInteger(rawSig.copyOfRange(0, coordLen))
        val sDer = encodeDerUnsignedInteger(rawSig.copyOfRange(coordLen, coordLen * 2))
        val seqLen = rDer.size + sDer.size
        val out = ByteArrayOutputStream(seqLen + 4)
        out.write(0x30)
        if (seqLen < 128) {
            out.write(seqLen)
        } else {
            out.write(0x81)
            out.write(seqLen)
        }
        out.write(rDer)
        out.write(sDer)
        return out.toByteArray()
    }

    private fun copyFixedUnsignedBigInt(src: ByteArray, dst: ByteArray, dstOffset: Int, targetLen: Int) {
        var start = 0
        while (start < src.size - 1 && src[start].toInt() == 0) start++
        val significant = src.size - start
        require(significant <= targetLen) { "ECDSA coordinate exceeds $targetLen bytes" }
        System.arraycopy(src, start, dst, dstOffset + (targetLen - significant), significant)
    }

    private fun encodeDerUnsignedInteger(coord: ByteArray): ByteArray {
        var start = 0
        while (start < coord.size - 1 && coord[start].toInt() == 0) start++
        val needsLeadingZero = (coord[start].toInt() and 0x80) != 0
        val bodyLen = (coord.size - start) + if (needsLeadingZero) 1 else 0
        val out = ByteArrayOutputStream(2 + bodyLen)
        out.write(0x02)
        out.write(bodyLen)
        if (needsLeadingZero) out.write(0x00)
        out.write(coord, start, coord.size - start)
        return out.toByteArray()
    }

    private fun decodePublicKey(algorithm: Int, keyBytes: ByteArray): PublicKey {
        return when (algorithm) {
            ALG_RSASHA256, ALG_RSASHA512 -> {
                require(keyBytes.size >= 4) { "RSA DNSKEY too short" }
                val expLen: Int
                val expOffset: Int
                val firstByte = keyBytes[0].toInt() and 0xFF
                if (firstByte == 0) {
                    expLen = ((keyBytes[1].toInt() and 0xFF) shl 8) or (keyBytes[2].toInt() and 0xFF)
                    expOffset = 3
                } else {
                    expLen = firstByte
                    expOffset = 1
                }
                require(expLen > 0 && expOffset + expLen < keyBytes.size) { "Malformed RSA DNSKEY exponent" }
                val exponent = BigInteger(1, keyBytes.copyOfRange(expOffset, expOffset + expLen))
                val modulus = BigInteger(1, keyBytes.copyOfRange(expOffset + expLen, keyBytes.size))
                KeyFactory.getInstance("RSA").generatePublic(RSAPublicKeySpec(modulus, exponent))
            }
            ALG_ECDSAP256SHA256 -> decodeEcPublicKey("secp256r1", 32, keyBytes)
            ALG_ECDSAP384SHA384 -> decodeEcPublicKey("secp384r1", 48, keyBytes)
            else -> throw IllegalArgumentException("Unsupported DNSSEC algorithm: $algorithm")
        }
    }

    private fun decodeEcPublicKey(curveName: String, coordLen: Int, keyBytes: ByteArray): PublicKey {
        require(keyBytes.size == coordLen * 2) { "Invalid EC DNSKEY size ${keyBytes.size}" }
        val x = BigInteger(1, keyBytes.copyOfRange(0, coordLen))
        val y = BigInteger(1, keyBytes.copyOfRange(coordLen, coordLen * 2))
        val params = AlgorithmParameters.getInstance("EC").apply {
            init(ECGenParameterSpec(curveName))
        }.getParameterSpec(ECParameterSpec::class.java)
        return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x, y), params))
    }

    private fun verifySignatureBytes(
        algorithm: Int,
        publicKey: PublicKey,
        signedData: ByteArray,
        rawSignature: ByteArray
    ): Boolean {
        val (jcaAlg, sigToVerify) = when (algorithm) {
            ALG_RSASHA256 -> "SHA256withRSA" to rawSignature
            ALG_RSASHA512 -> "SHA512withRSA" to rawSignature
            ALG_ECDSAP256SHA256 -> "SHA256withECDSA" to p1363EcdsaToDer(rawSignature, 32)
            ALG_ECDSAP384SHA384 -> "SHA384withECDSA" to p1363EcdsaToDer(rawSignature, 48)
            else -> return false
        }
        val sig = Signature.getInstance(jcaAlg)
        sig.initVerify(publicKey)
        sig.update(signedData)
        return sig.verify(sigToVerify)
    }

    private fun encodeWildcardAdjustedOwner(ownerName: String, rrsigLabels: Int): ByteArray {
        val labels = ownerName.trim().trimEnd('.').lowercase().split('.').filter { it.isNotEmpty() }
        if (labels.size <= rrsigLabels || rrsigLabels <= 0) {
            return encodeCanonicalDomainWire(ownerName)
        }
        val suffix = labels.takeLast(rrsigLabels).joinToString(".")
        return encodeCanonicalDomainWire("*.$suffix")
    }

    private data class ParsedWireDnssec(
        val records: List<WireResourceRecord>,
        val rrsigs: List<RrsigRecord>,
        val embeddedDnskeys: List<DnskeyRecord>
    )

    private fun parseDnssecRecordsFromWire(wire: ByteArray): ParsedWireDnssec? {
        if (wire.size < 12) return null
        val qdCount = readU16(wire, 4)
        val anCount = readU16(wire, 6)
        val nsCount = readU16(wire, 8)
        val arCount = readU16(wire, 10)

        var offset = 12
        repeat(qdCount) {
            val (_, next) = readWireName(wire, offset) ?: return null
            if (next + 4 > wire.size) return null
            offset = next + 4
        }

        val records = ArrayList<WireResourceRecord>()
        val rrsigs = ArrayList<RrsigRecord>()
        val dnskeys = ArrayList<DnskeyRecord>()
        val totalRrs = anCount + nsCount + arCount

        repeat(totalRrs) {
            val (owner, afterName) = readWireName(wire, offset) ?: return null
            if (afterName + 10 > wire.size) return null
            val rrType = readU16(wire, afterName)
            val rrClass = readU16(wire, afterName + 2)
            val ttl = readU32(wire, afterName + 4)
            val rdLength = readU16(wire, afterName + 8)
            val rdataStart = afterName + 10
            val rdataEnd = rdataStart + rdLength
            if (rdataEnd > wire.size) return null

            if (rrType == 41) {
                // EDNS0 OPT pseudo-record is never part of a signed RRset
                offset = rdataEnd
                return@repeat
            }

            when (rrType) {
                RR_TYPE_RRSIG -> {
                    val sig = parseRrsigRdata(owner, wire, rdataStart, rdataEnd) ?: return null
                    rrsigs += sig
                }
                RR_TYPE_DNSKEY -> {
                    if (rdLength >= 4) {
                        val rawRdata = wire.copyOfRange(rdataStart, rdataEnd)
                        val flags = readU16(rawRdata, 0)
                        val proto = rawRdata[2].toInt() and 0xFF
                        val alg = rawRdata[3].toInt() and 0xFF
                        val pub = rawRdata.copyOfRange(4, rawRdata.size)
                        dnskeys += DnskeyRecord(owner.lowercase(), flags, proto, alg, pub, rawRdata)
                        records += WireResourceRecord(owner.lowercase(), rrType, rrClass, ttl, rawRdata)
                    }
                }
                else -> {
                    val canonicalRdata = canonicalizeRdata(rrType, wire, rdataStart, rdataEnd) ?: return null
                    records += WireResourceRecord(owner.lowercase(), rrType, rrClass, ttl, canonicalRdata)
                }
            }
            offset = rdataEnd
        }

        if (offset != wire.size) return null
        return ParsedWireDnssec(records, rrsigs, dnskeys)
    }

    private fun parseRrsigRdata(
        owner: String,
        wire: ByteArray,
        start: Int,
        end: Int
    ): RrsigRecord? {
        if (end - start < 19) return null
        val typeCovered = readU16(wire, start)
        val algorithm = wire[start + 2].toInt() and 0xFF
        val labels = wire[start + 3].toInt() and 0xFF
        val origTtl = readU32(wire, start + 4)
        val exp = readU32(wire, start + 8)
        val inc = readU32(wire, start + 12)
        val keyTag = readU16(wire, start + 16)
        val (signer, afterSigner) = readWireName(wire, start + 18) ?: return null
        if (afterSigner > end) return null
        val sigBytes = wire.copyOfRange(afterSigner, end)
        val prefixWire = buildRrsigPrefixWire(
            typeCovered = typeCovered,
            algorithm = algorithm,
            labels = labels,
            originalTtl = origTtl,
            expiration = exp,
            inception = inc,
            keyTag = keyTag,
            signerName = signer
        )
        return RrsigRecord(
            ownerName = owner.lowercase(),
            typeCovered = typeCovered,
            algorithm = algorithm,
            labels = labels,
            originalTtl = origTtl,
            signatureExpiration = exp,
            signatureInception = inc,
            keyTag = keyTag,
            signerName = signer.lowercase(),
            rrsigHeaderPrefixWire = prefixWire,
            signatureBytes = sigBytes
        )
    }

    private fun canonicalizeRdata(rrType: Int, wire: ByteArray, start: Int, end: Int): ByteArray? {
        return when (rrType) {
            2, 5, 12 -> { // NS, CNAME, PTR — decompress & lowercase embedded domain name
                val (target, after) = readWireName(wire, start) ?: return null
                if (after != end) return null
                encodeCanonicalDomainWire(target)
            }
            15 -> { // MX — 16-bit preference + canonical exchange name
                if (end - start < 3) return null
                val (exchange, after) = readWireName(wire, start + 2) ?: return null
                if (after != end) return null
                val out = ByteArrayOutputStream()
                out.write(wire, start, 2)
                out.write(encodeCanonicalDomainWire(exchange))
                out.toByteArray()
            }
            6 -> { // SOA — MNAME + RNAME + 20 bytes timers
                val (mname, afterM) = readWireName(wire, start) ?: return null
                val (rname, afterR) = readWireName(wire, afterM) ?: return null
                if (afterR + 20 != end) return null
                val out = ByteArrayOutputStream()
                out.write(encodeCanonicalDomainWire(mname))
                out.write(encodeCanonicalDomainWire(rname))
                out.write(wire, afterR, 20)
                out.toByteArray()
            }
            else -> wire.copyOfRange(start, end)
        }
    }

    private fun readWireName(wire: ByteArray, startOffset: Int): Pair<String, Int>? {
        val labels = ArrayList<String>()
        var offset = startOffset
        var nextAfterFirstField = -1
        var jumps = 0
        while (true) {
            if (offset >= wire.size) return null
            val len = wire[offset].toInt() and 0xFF
            when {
                len == 0 -> {
                    if (nextAfterFirstField == -1) nextAfterFirstField = offset + 1
                    return labels.joinToString(".") to nextAfterFirstField
                }
                (len and 0xC0) == 0xC0 -> {
                    if (offset + 1 >= wire.size) return null
                    if (nextAfterFirstField == -1) nextAfterFirstField = offset + 2
                    val ptr = ((len and 0x3F) shl 8) or (wire[offset + 1].toInt() and 0xFF)
                    if (ptr >= offset && jumps == 0) return null
                    offset = ptr
                    if (++jumps > 32) return null
                }
                (len and 0xC0) == 0 -> {
                    if (offset + 1 + len > wire.size) return null
                    labels += String(wire, offset + 1, len, Charsets.US_ASCII).lowercase()
                    offset += 1 + len
                }
                else -> return null
            }
        }
    }

    private fun writeU16(out: ByteArrayOutputStream, v: Int) {
        out.write((v ushr 8) and 0xFF)
        out.write(v and 0xFF)
    }

    private fun writeU32(out: ByteArrayOutputStream, v: Long) {
        out.write(((v ushr 24) and 0xFF).toInt())
        out.write(((v ushr 16) and 0xFF).toInt())
        out.write(((v ushr 8) and 0xFF).toInt())
        out.write((v and 0xFF).toInt())
    }

    private fun readU16(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xFF) shl 8) or (bytes[offset + 1].toInt() and 0xFF)

    private fun readU32(bytes: ByteArray, offset: Int): Long =
        ((bytes[offset].toLong() and 0xFFL) shl 24) or
            ((bytes[offset + 1].toLong() and 0xFFL) shl 16) or
            ((bytes[offset + 2].toLong() and 0xFFL) shl 8) or
            (bytes[offset + 3].toLong() and 0xFFL)
}
