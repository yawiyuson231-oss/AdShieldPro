package com.adshield.pro.engine.storage

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Streaming Authenticated Chunked AES-256-GCM File Cipher (`OSZK` v1).
 *
 * Powers Zero-Knowledge Client-Side File Encryption across AdShield Cloud (Backblaze B2),
 * Nextcloud/WebDAV, Telegram Cloud Storage, and at-rest Encrypted Quarantine:
 *
 * Wire format (`OSZK` v1):
 * - `[4 bytes]` Magic `"OSZK"` (`0x4F535A4B`)
 * - `[1 byte]`  Version (`0x01`)
 * - `[1 byte]`  KDF Mode (`0x00` = Direct 256-bit SecretKey, `0x01` = PBKDF2-HMAC-SHA256)
 * - `[4 bytes]` PBKDF2 iteration count (`0` when direct key)
 * - `[16 bytes]` Salt (random even for direct keys, included in per-chunk AAD)
 * - `[12 bytes]` Random base nonce
 * - `[4 bytes]` Plaintext chunk frame size (`default = 65,536` bytes)
 * - Sequence of authenticated chunks until EOF:
 *   - `[4 bytes]` Plaintext byte length of this chunk (`0..chunkSize`)
 *   - `[1 byte]`  Final-chunk flag (`0x01` if last chunk, `0x00` otherwise)
 *   - `[N + 16 bytes]` AES-256-GCM ciphertext + 128-bit authentication tag
 *     - Nonce = `baseNonce XOR bigEndian64(chunkIndex)` in last 8 bytes
 *     - AAD = `"OSZK\x01" || salt || uint64(chunkIndex) || finalFlag`
 *
 * Security guarantees:
 * - Constant ~64 KiB memory footprint for arbitrarily large multi-GB files.
 * - Chunk reordering, duplication, splice, or premature EOF truncation fails AES-GCM tag
 *   verification deterministically because `chunkIndex` and `finalFlag` are bound in AAD and
 *   at least one final chunk (`finalFlag = 0x01`) is mandatory.
 */
object ZeroKnowledgeFileCipher {

    const val MAGIC_INT = 0x4F535A4B // "OSZK"
    private const val VERSION_V1 = 1
    private const val KDF_DIRECT_KEY = 0
    private const val KDF_PBKDF2_SHA256 = 1

    const val DEFAULT_CHUNK_BYTES = 64 * 1024
    const val DEFAULT_PBKDF2_ITERATIONS = 120_000
    private const val GCM_TAG_BITS = 128
    private const val GCM_TAG_BYTES = 16
    private const val SALT_BYTES = 16
    private const val NONCE_BYTES = 12
    const val HEADER_BYTES = 4 + 1 + 1 + 4 + SALT_BYTES + NONCE_BYTES + 4 // 42 bytes

    data class EncryptedStreamSummary(
        val plaintextBytes: Long,
        val ciphertextBytes: Long,
        val plaintextSha256Hex: String,
        val chunkCount: Long
    )

    data class DecryptedStreamSummary(
        val plaintextBytes: Long,
        val plaintextSha256Hex: String,
        val chunkCount: Long
    )

    /** Checks whether [prefixBytes] begins with the `OSZK` v1 Zero-Knowledge envelope header. */
    fun hasZeroKnowledgeHeader(prefixBytes: ByteArray): Boolean {
        if (prefixBytes.size < 5) return false
        val magic = ((prefixBytes[0].toInt() and 0xFF) shl 24) or
            ((prefixBytes[1].toInt() and 0xFF) shl 16) or
            ((prefixBytes[2].toInt() and 0xFF) shl 8) or
            (prefixBytes[3].toInt() and 0xFF)
        return magic == MAGIC_INT && (prefixBytes[4].toInt() and 0xFF) == VERSION_V1
    }

    /** Derives a 256-bit AES key from [passphrase] and [salt] using PBKDF2-HMAC-SHA256. */
    fun deriveKeyFromPassphrase(
        passphrase: CharArray,
        salt: ByteArray,
        iterations: Int = DEFAULT_PBKDF2_ITERATIONS
    ): SecretKey {
        require(passphrase.isNotEmpty()) { "Passphrase must not be empty" }
        require(salt.size == SALT_BYTES) { "Expected $SALT_BYTES-byte salt" }
        val spec = PBEKeySpec(passphrase, salt, iterations.coerceIn(1_000, 2_000_000), 256)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val encoded = factory.generateSecret(spec).encoded
        spec.clearPassword()
        return SecretKeySpec(encoded, "AES")
    }

    /** Encrypts [source] into [sink] using a passphrase-derived AES-256-GCM key. */
    fun encryptStreamWithPassphrase(
        source: InputStream,
        sink: OutputStream,
        passphrase: CharArray,
        iterations: Int = DEFAULT_PBKDF2_ITERATIONS,
        chunkSize: Int = DEFAULT_CHUNK_BYTES,
        random: SecureRandom = SecureRandom()
    ): EncryptedStreamSummary {
        val salt = ByteArray(SALT_BYTES).also { random.nextBytes(it) }
        val key = deriveKeyFromPassphrase(passphrase, salt, iterations)
        return encryptInternal(
            source = source,
            sink = sink,
            key = key,
            kdfMode = KDF_PBKDF2_SHA256,
            iterations = iterations,
            salt = salt,
            chunkSize = chunkSize,
            random = random
        )
    }

    /** Encrypts [source] into [sink] using a direct 256-bit [SecretKey]. */
    fun encryptStreamWithKey(
        source: InputStream,
        sink: OutputStream,
        key: SecretKey,
        chunkSize: Int = DEFAULT_CHUNK_BYTES,
        random: SecureRandom = SecureRandom()
    ): EncryptedStreamSummary {
        val salt = ByteArray(SALT_BYTES).also { random.nextBytes(it) }
        return encryptInternal(
            source = source,
            sink = sink,
            key = key,
            kdfMode = KDF_DIRECT_KEY,
            iterations = 0,
            salt = salt,
            chunkSize = chunkSize,
            random = random
        )
    }

    /** Decrypts and authenticates an `OSZK` v1 stream encrypted with a passphrase. */
    fun decryptStreamWithPassphrase(
        source: InputStream,
        sink: OutputStream,
        passphrase: CharArray
    ): DecryptedStreamSummary {
        return decryptInternal(source, sink) { kdfMode, salt, iterations ->
            require(kdfMode == KDF_PBKDF2_SHA256) { "Stream was not encrypted with a passphrase" }
            deriveKeyFromPassphrase(passphrase, salt, iterations)
        }
    }

    /** Decrypts and authenticates an `OSZK` v1 stream encrypted with a direct [SecretKey]. */
    fun decryptStreamWithKey(
        source: InputStream,
        sink: OutputStream,
        key: SecretKey
    ): DecryptedStreamSummary {
        return decryptInternal(source, sink) { kdfMode, _, _ ->
            require(kdfMode == KDF_DIRECT_KEY) { "Stream requires a passphrase key" }
            key
        }
    }

    private fun encryptInternal(
        source: InputStream,
        sink: OutputStream,
        key: SecretKey,
        kdfMode: Int,
        iterations: Int,
        salt: ByteArray,
        chunkSize: Int,
        random: SecureRandom
    ): EncryptedStreamSummary {
        val frameSize = chunkSize.coerceIn(4 * 1024, 1024 * 1024)
        val baseNonce = ByteArray(NONCE_BYTES).also { random.nextBytes(it) }
        val out = DataOutputStream(sink)

        out.writeInt(MAGIC_INT)
        out.writeByte(VERSION_V1)
        out.writeByte(kdfMode)
        out.writeInt(iterations)
        out.write(salt)
        out.write(baseNonce)
        out.writeInt(frameSize)

        var totalPlain = 0L
        var totalCipher = HEADER_BYTES.toLong()
        var chunkIndex = 0L
        val sha256 = MessageDigest.getInstance("SHA-256")

        var currentBuf = ByteArray(frameSize)
        var nextBuf = ByteArray(frameSize)
        var currentLen = readUpToChunk(source, currentBuf)

        while (true) {
            val nextLen = if (currentLen > 0) readUpToChunk(source, nextBuf) else 0
            val isFinal = nextLen <= 0

            if (currentLen > 0) {
                sha256.update(currentBuf, 0, currentLen)
                totalPlain += currentLen
            }

            val nonce = deriveChunkNonce(baseNonce, chunkIndex)
            val aad = buildChunkAad(salt, chunkIndex, isFinal)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, nonce))
            cipher.updateAAD(aad)
            val encrypted = if (currentLen > 0) {
                cipher.doFinal(currentBuf, 0, currentLen)
            } else {
                cipher.doFinal()
            }

            out.writeInt(currentLen)
            out.writeByte(if (isFinal) 1 else 0)
            out.write(encrypted)

            totalCipher += 5L + encrypted.size
            chunkIndex += 1L

            if (isFinal) break
            val tmp = currentBuf
            currentBuf = nextBuf
            nextBuf = tmp
            currentLen = nextLen
        }
        out.flush()

        return EncryptedStreamSummary(
            plaintextBytes = totalPlain,
            ciphertextBytes = totalCipher,
            plaintextSha256Hex = sha256.digest().joinToString("") { "%02x".format(it) },
            chunkCount = chunkIndex
        )
    }

    private fun decryptInternal(
        source: InputStream,
        sink: OutputStream,
        keyResolver: (kdfMode: Int, salt: ByteArray, iterations: Int) -> SecretKey
    ): DecryptedStreamSummary {
        val input = DataInputStream(source)
        val magic = input.readInt()
        require(magic == MAGIC_INT) { "Not an OSZK Zero-Knowledge encrypted stream" }
        val version = input.readUnsignedByte()
        require(version == VERSION_V1) { "Unsupported OSZK stream version: $version" }
        val kdfMode = input.readUnsignedByte()
        val iterations = input.readInt()
        val salt = ByteArray(SALT_BYTES).also { input.readFully(it) }
        val baseNonce = ByteArray(NONCE_BYTES).also { input.readFully(it) }
        val frameSize = input.readInt()
        require(frameSize in (4 * 1024)..(4 * 1024 * 1024)) { "Invalid OSZK frame size: $frameSize" }

        val key = keyResolver(kdfMode, salt, iterations)
        val sha256 = MessageDigest.getInstance("SHA-256")
        var totalPlain = 0L
        var chunkIndex = 0L
        var sawFinalChunk = false

        while (!sawFinalChunk) {
            val plainLen = try {
                input.readInt()
            } catch (_: EOFException) {
                throw SecurityException("Truncated OSZK stream before authenticated final chunk")
            }
            require(plainLen in 0..frameSize) { "Malformed OSZK chunk length: $plainLen" }
            val finalFlagByte = input.readUnsignedByte()
            require(finalFlagByte == 0 || finalFlagByte == 1) { "Invalid OSZK final-chunk flag" }
            val isFinal = finalFlagByte == 1
            if (plainLen == 0 && !isFinal) {
                throw SecurityException("Zero-length non-final OSZK chunk rejected")
            }

            val cipherBytes = ByteArray(plainLen + GCM_TAG_BYTES)
            input.readFully(cipherBytes)

            val nonce = deriveChunkNonce(baseNonce, chunkIndex)
            val aad = buildChunkAad(salt, chunkIndex, isFinal)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, nonce))
            cipher.updateAAD(aad)
            val decrypted = cipher.doFinal(cipherBytes)

            if (decrypted.isNotEmpty()) {
                sha256.update(decrypted)
                sink.write(decrypted)
                totalPlain += decrypted.size
            }
            chunkIndex += 1L
            sawFinalChunk = isFinal
        }

        // Refuse trailing unauthenticated bytes appended after the final chunk
        if (input.read() != -1) {
            throw SecurityException("Unexpected trailing bytes after final OSZK chunk")
        }
        sink.flush()

        return DecryptedStreamSummary(
            plaintextBytes = totalPlain,
            plaintextSha256Hex = sha256.digest().joinToString("") { "%02x".format(it) },
            chunkCount = chunkIndex
        )
    }

    private fun readUpToChunk(stream: InputStream, buffer: ByteArray): Int {
        var total = 0
        while (total < buffer.size) {
            val r = stream.read(buffer, total, buffer.size - total)
            if (r < 0) break
            total += r
        }
        return total
    }

    private fun deriveChunkNonce(baseNonce: ByteArray, chunkIndex: Long): ByteArray {
        val nonce = baseNonce.copyOf()
        for (i in 0 until 8) {
            val shift = (7 - i) * 8
            nonce[4 + i] = (nonce[4 + i].toInt() xor ((chunkIndex ushr shift).toInt() and 0xFF)).toByte()
        }
        return nonce
    }

    private fun buildChunkAad(salt: ByteArray, chunkIndex: Long, isFinal: Boolean): ByteArray {
        val buf = ByteBuffer.allocate(5 + SALT_BYTES + 8 + 1).order(ByteOrder.BIG_ENDIAN)
        buf.putInt(MAGIC_INT)
        buf.put(VERSION_V1.toByte())
        buf.put(salt)
        buf.putLong(chunkIndex)
        buf.put(if (isFinal) 1.toByte() else 0.toByte())
        return buf.array()
    }
}
