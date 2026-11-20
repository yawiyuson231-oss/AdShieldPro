package com.adshield.pro.engine.evolution

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.security.PublicKey
import java.security.Signature

/** Versioned, data-only wire format. This is not a script, APK, model loader or DNS rule loader. */
internal object SignedEvolutionPackage {
    const val MAX_BYTES = 256 * 1024
    private const val MAGIC = 0x45564F31 // EVO1
    data class Indicator(val sha256: String, val category: String)
    data class Manifest(
        val keyId: String, val sequence: Long, val issuedAt: Long, val expiresAt: Long,
        val minAppVersion: Long, val maxAppVersion: Long, val indicators: List<Indicator>
    )

    /** Publisher-side canonical bytes; the detached RSA signature covers every field. */
    fun payload(manifest: Manifest): ByteArray = ByteArrayOutputStream().also { bytes ->
        DataOutputStream(bytes).use { out ->
            out.writeInt(MAGIC)
            out.writeUTF("adshield-reviewed-apk-reputation-v1")
            out.writeUTF(manifest.keyId)
            out.writeLong(manifest.sequence)
            out.writeLong(manifest.issuedAt)
            out.writeLong(manifest.expiresAt)
            out.writeLong(manifest.minAppVersion)
            out.writeLong(manifest.maxAppVersion)
            out.writeInt(manifest.indicators.size)
            manifest.indicators.forEach { out.writeUTF(it.sha256); out.writeUTF(it.category) }
        }
    }.toByteArray().also { require(it.size <= MAX_BYTES - 1024) }

    fun envelope(payload: ByteArray, signature: ByteArray): ByteArray = ByteArrayOutputStream().also { bytes ->
        DataOutputStream(bytes).use { out ->
            require(payload.size <= MAX_BYTES - 1024 && signature.size in 256..512)
            out.writeInt(payload.size); out.write(payload)
            out.writeInt(signature.size); out.write(signature)
        }
    }.toByteArray()

    fun verify(
        envelope: ByteArray, trustedKeys: Map<String, PublicKey>, appVersion: Long,
        nowSeconds: Long, minimumSequence: Long = 0, allowExpiredStoredRecord: Boolean = false
    ): Manifest {
        require(envelope.size in 1..MAX_BYTES)
        val input = DataInputStream(ByteArrayInputStream(envelope))
        val size = input.readInt()
        require(size in 1..(MAX_BYTES - 1024) && size <= input.available() - 4)
        val payload = ByteArray(size).also(input::readFully)
        val signatureSize = input.readInt()
        require(signatureSize in 256..512 && signatureSize == input.available())
        val signature = ByteArray(signatureSize).also(input::readFully)
        val data = DataInputStream(ByteArrayInputStream(payload))
        require(data.readInt() == MAGIC)
        require(data.readUTF() == "adshield-reviewed-apk-reputation-v1")
        val keyId = data.readUTF()
        require(keyId.matches(Regex("[a-zA-Z0-9_-]{1,64}")))
        val key = requireNotNull(trustedKeys[keyId]) { "Untrusted publisher" }
        require(key is java.security.interfaces.RSAPublicKey && key.modulus.bitLength() in 2048..4096)
        require(Signature.getInstance("SHA256withRSA").run {
            initVerify(key); update(payload); verify(signature)
        }) { "Invalid publisher signature" }
        val sequence = data.readLong()
        val issued = data.readLong()
        val expires = data.readLong()
        val min = data.readLong()
        val max = data.readLong()
        require(sequence > minimumSequence && sequence > 0)
        require(nowSeconds >= 0 && issued >= 0 && issued <= nowSeconds)
        require(expires > issued && expires - issued <= 7 * 24 * 60 * 60)
        require(allowExpiredStoredRecord || nowSeconds < expires) { "Expired update" }
        require(min > 0 && max >= min && appVersion in min..max)
        val count = data.readInt()
        require(count in 1..1000)
        val entries = (0 until count).map { Indicator(data.readUTF(), data.readUTF()) }
        require(entries.all { it.sha256.matches(Regex("[0-9a-f]{64}")) &&
            it.category in setOf("malware", "phishing", "unwanted") })
        require(entries.map { it.sha256 }.toSet().size == count)
        require(data.available() == 0) { "Unexpected payload fields" }
        return Manifest(keyId, sequence, issued, expires, min, max, entries)
    }
}
