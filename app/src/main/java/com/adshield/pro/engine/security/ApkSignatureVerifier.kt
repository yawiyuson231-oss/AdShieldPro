package com.adshield.pro.engine.security

import java.io.ByteArrayInputStream
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Locale
import java.util.zip.ZipFile

/**
 * Cryptographic APK Signer Inspector & Anti-Tamper Clone Detector.
 *
 * Extracts real X.509 signing certificates from both:
 * - **APK Signature Scheme v2 (`0x7109871a`) & v3 (`0xf05368c0`)** inside `"APK Sig Block 42"`
 * - **JAR v1 (`META-INF/<cert>.RSA`, `.EC`, `.DSA`)** PKCS#7 / X.509 certificate blocks
 *
 * Detects:
 * - **Repackaged Clones (`SIGNATURE_MISMATCH_WITH_INSTALLED`)**: When a sideloaded APK shares the
 *   package ID of an already-installed app on the device (or a caller-supplied reference digest)
 *   but is signed by a different certificate.
 * - **Debug-Key / Test-Signed Sensitive Apps**: Sideloaded APKs impersonating high-target banking,
 *   e-wallet (GCash, Maya, BDO, BPI, UnionBank, PayPal), or messaging packages signed with an
 *   `Android Debug` or unverified certificate.
 */
object ApkSignatureVerifier {

    const val APK_SIG_SCHEME_V2_ID = 0x7109871a
    const val APK_SIG_SCHEME_V3_ID = -0xfac9740 // 0xf05368c0 as signed Int32

    private const val APK_SIG_BLOCK_MAGIC_LO = 0x20676953204b5041L // "APK Sig "
    private const val APK_SIG_BLOCK_MAGIC_HI = 0x3234206b636f6c42L // "Block 42"
    private const val ZIP_EOCD_MAGIC = 0x06054b50
    private const val MAX_SIG_BLOCK_BYTES = 8 * 1024 * 1024

    val PROTECTED_SENSITIVE_PACKAGES: Map<String, String> = mapOf(
        "com.globe.gcash.android" to "GCash",
        "com.paymaya" to "Maya",
        "ph.com.bdo.retail" to "BDO Online",
        "com.bpi.ng.app" to "BPI",
        "com.unionbankph.online" to "UnionBank Online",
        "com.landbank.mobilebanking" to "LANDBANK",
        "com.securitybank.bbx" to "Security Bank",
        "com.paypal.android.p2pmobile" to "PayPal",
        "com.binance.dev" to "Binance",
        "com.whatsapp" to "WhatsApp",
        "org.telegram.messenger" to "Telegram",
        "com.viber.voip" to "Viber",
        "com.google.android.gm" to "Gmail"
    )

    data class SignerCertificateInfo(
        val sha256Hex: String,
        val subjectDn: String,
        val issuerDn: String,
        val signatureAlgorithm: String,
        val notBeforeEpochMs: Long,
        val notAfterEpochMs: Long,
        val isDebugCertificate: Boolean,
        val isSelfSigned: Boolean
    )

    data class SignatureVerificationReport(
        val hasSignatureMarkers: Boolean,
        val schemeVersion: Int,
        val certificates: List<SignerCertificateInfo>,
        val cloneMismatchDetected: Boolean,
        val sensitiveBrandWarning: String?,
        val addedRiskScore: Int,
        val findings: List<String>
    ) {
        val primarySha256: String? get() = certificates.firstOrNull()?.sha256Hex
        val primarySubject: String? get() = certificates.firstOrNull()?.subjectDn
        val isDebugSigned: Boolean get() = certificates.any { it.isDebugCertificate }
    }

    /**
     * Inspects signing certificates inside [apkFile] and evaluates anti-tamper / clone indicators.
     *
     * @param packageName Parsed manifest package name, if known.
     * @param installedAppSignerSha256 Optional SHA-256 hex digest of the currently installed app
     *        with the same [packageName] on the device (from `PackageManager` `SigningInfo`).
     */
    fun inspectApkSignatures(
        apkFile: File,
        packageName: String? = null,
        installedAppSignerSha256: String? = null
    ): SignatureVerificationReport {
        val certsByDigest = LinkedHashMap<String, SignerCertificateInfo>()
        var highestScheme = 0
        var sawJarMarker = false

        // 1. Inspect APK Signature Scheme v2 / v3 block ("APK Sig Block 42")
        runCatching {
            val (scheme, rawCerts) = extractV2V3Certificates(apkFile)
            if (scheme > highestScheme) highestScheme = scheme
            for (der in rawCerts) {
                parseDerCertificate(der)?.let { info ->
                    certsByDigest.putIfAbsent(info.sha256Hex, info)
                }
            }
        }

        // 2. Inspect JAR v1 META-INF/*.RSA | *.EC | *.DSA entries
        runCatching {
            ZipFile(apkFile).use { zip ->
                val entries = zip.entries()
                var count = 0
                while (count < 2_000 && entries.hasMoreElements()) {
                    count++
                    val entry = entries.nextElement()
                    val lower = entry.name.lowercase(Locale.US)
                    if (lower.startsWith("meta-inf/") &&
                        (lower.endsWith(".rsa") || lower.endsWith(".ec") || lower.endsWith(".dsa")) &&
                        entry.size in 1L..(512L * 1024L)
                    ) {
                        sawJarMarker = true
                        if (highestScheme == 0) highestScheme = 1
                        val bytes = zip.getInputStream(entry).use { it.readBytes() }
                        for (cert in parsePkcs7OrDerCertificates(bytes)) {
                            certsByDigest.putIfAbsent(cert.sha256Hex, cert)
                        }
                    }
                }
            }
        }

        val certs = certsByDigest.values.toList()
        val hasMarkers = highestScheme > 0 || sawJarMarker
        val findings = ArrayList<String>()
        var riskDelta = 0
        var cloneMismatch = false
        var brandWarning: String? = null

        val normalizedPkg = packageName?.trim()?.lowercase(Locale.US).orEmpty()
        val sensitiveBrand = PROTECTED_SENSITIVE_PACKAGES[normalizedPkg]

        if (certs.any { it.isDebugCertificate }) {
            findings += "Signed with an Android Debug / test certificate (${certs.first { it.isDebugCertificate }.subjectDn})"
            riskDelta += if (sensitiveBrand != null) 55 else 18
        }

        val normalizedInstalled = installedAppSignerSha256?.trim()?.lowercase(Locale.US)
            ?.replace(":", "")
            ?.takeIf { it.length == 64 }

        if (normalizedInstalled != null && certs.isNotEmpty()) {
            val matchesInstalled = certs.any { it.sha256Hex.equals(normalizedInstalled, ignoreCase = true) }
            if (!matchesInstalled) {
                cloneMismatch = true
                riskDelta += 65
                val targetLabel = sensitiveBrand ?: normalizedPkg.ifEmpty { apkFile.name }
                val warning = "Signer mismatch: APK claims '$targetLabel' but its certificate (${certs.first().sha256Hex.take(16)}…) does not match the installed app (${normalizedInstalled.take(16)}…)"
                brandWarning = warning
                findings += warning
            }
        }

        if (sensitiveBrand != null && brandWarning == null) {
            when {
                !hasMarkers -> {
                    riskDelta += 50
                    brandWarning = "Unsigned APK impersonating protected financial/messaging package $sensitiveBrand ($normalizedPkg)"
                    findings += brandWarning
                }
                certs.isEmpty() -> {
                    riskDelta += 40
                    brandWarning = "APK claims protected package $sensitiveBrand ($normalizedPkg) without a verifiable X.509 signer certificate"
                    findings += brandWarning
                }
                certs.any { it.isDebugCertificate } -> {
                    brandWarning = "Debug-signed repackaged clone indicator for protected app $sensitiveBrand ($normalizedPkg)"
                    findings += brandWarning
                }
            }
        }

        return SignatureVerificationReport(
            hasSignatureMarkers = hasMarkers,
            schemeVersion = highestScheme,
            certificates = certs,
            cloneMismatchDetected = cloneMismatch,
            sensitiveBrandWarning = brandWarning,
            addedRiskScore = riskDelta.coerceIn(0, 85),
            findings = findings
        )
    }

    /** Parses a single DER-encoded X.509 certificate into [SignerCertificateInfo]. */
    fun parseDerCertificate(derBytes: ByteArray): SignerCertificateInfo? = runCatching {
        val cf = CertificateFactory.getInstance("X.509")
        val cert = cf.generateCertificate(ByteArrayInputStream(derBytes)) as? X509Certificate
            ?: return@runCatching null
        toCertInfo(cert)
    }.getOrNull()

    private fun parsePkcs7OrDerCertificates(bytes: ByteArray): List<SignerCertificateInfo> = runCatching {
        val cf = CertificateFactory.getInstance("X.509")
        cf.generateCertificates(ByteArrayInputStream(bytes))
            .mapNotNull { (it as? X509Certificate)?.let(::toCertInfo) }
    }.getOrDefault(emptyList())

    private fun toCertInfo(cert: X509Certificate): SignerCertificateInfo {
        val sha256 = MessageDigest.getInstance("SHA-256")
            .digest(cert.encoded)
            .joinToString("") { "%02x".format(it) }
        val subject = cert.subjectX500Principal?.name.orEmpty()
        val issuer = cert.issuerX500Principal?.name.orEmpty()
        val lowerSubj = subject.lowercase(Locale.US)
        val isDebug = lowerSubj.contains("cn=android debug") ||
            lowerSubj.contains("ou=android debug") ||
            lowerSubj.contains("cn=testkey")
        return SignerCertificateInfo(
            sha256Hex = sha256,
            subjectDn = subject,
            issuerDn = issuer,
            signatureAlgorithm = cert.sigAlgName ?: "UNKNOWN",
            notBeforeEpochMs = cert.notBefore?.time ?: 0L,
            notAfterEpochMs = cert.notAfter?.time ?: 0L,
            isDebugCertificate = isDebug,
            isSelfSigned = subject.isNotEmpty() && subject == issuer
        )
    }

    /**
     * Walks `"APK Sig Block 42"` immediately preceding the ZIP Central Directory and extracts raw
     * DER X.509 certificate bytes from APK Signature Scheme v3 or v2 signers.
     */
    internal fun extractV2V3Certificates(apkFile: File): Pair<Int, List<ByteArray>> {
        val outCerts = ArrayList<ByteArray>()
        var detectedScheme = 0

        RandomAccessFile(apkFile, "r").use { raf ->
            val fileLen = raf.length()
            if (fileLen < 54L) return 0 to emptyList()

            val tailSize = minOf(fileLen, 65_557L).toInt()
            val tail = ByteArray(tailSize)
            raf.seek(fileLen - tailSize)
            raf.readFully(tail)
            val tailBuf = ByteBuffer.wrap(tail).order(ByteOrder.LITTLE_ENDIAN)

            var eocdPos = -1
            for (i in (tailSize - 22) downTo 0) {
                if (tailBuf.getInt(i) == ZIP_EOCD_MAGIC) {
                    val commentLen = tailBuf.getShort(i + 20).toInt() and 0xFFFF
                    if (i + 22 + commentLen == tailSize) {
                        eocdPos = i
                        break
                    }
                }
            }
            if (eocdPos < 0) return 0 to emptyList()

            val centralDirOffset = tailBuf.getInt(eocdPos + 16).toLong() and 0xFFFFFFFFL
            if (centralDirOffset < 32L || centralDirOffset > fileLen - 22L) return 0 to emptyList()

            // Read 24-byte footer of APK Signing Block: [uint64 size_of_block][16-byte magic]
            val footer = ByteArray(24)
            raf.seek(centralDirOffset - 24L)
            raf.readFully(footer)
            val footerBuf = ByteBuffer.wrap(footer).order(ByteOrder.LITTLE_ENDIAN)
            if (footerBuf.getLong(8) != APK_SIG_BLOCK_MAGIC_LO ||
                footerBuf.getLong(16) != APK_SIG_BLOCK_MAGIC_HI
            ) {
                return 0 to emptyList()
            }

            val blockSizeInFooter = footerBuf.getLong(0)
            if (blockSizeInFooter < 24L || blockSizeInFooter > MAX_SIG_BLOCK_BYTES ||
                blockSizeInFooter > centralDirOffset - 8L
            ) {
                return 0 to emptyList()
            }

            val totalBlockSize = (blockSizeInFooter + 8L).toInt()
            val blockStart = centralDirOffset - totalBlockSize
            val blockBytes = ByteArray(totalBlockSize)
            raf.seek(blockStart)
            raf.readFully(blockBytes)
            val blockBuf = ByteBuffer.wrap(blockBytes).order(ByteOrder.LITTLE_ENDIAN)
            val blockSizeInHeader = blockBuf.getLong(0)
            if (blockSizeInHeader != blockSizeInFooter) return 0 to emptyList()

            // Walk ID-value pairs between offset 8 and (totalBlockSize - 24)
            var pos = 8
            val pairsEnd = totalBlockSize - 24
            while (pos + 12 <= pairsEnd) {
                val pairLen = blockBuf.getLong(pos)
                if (pairLen < 4L || pairLen > (pairsEnd - pos - 8).toLong()) break
                val id = blockBuf.getInt(pos + 8)
                val valStart = pos + 12
                val valLen = (pairLen - 4L).toInt()
                if (id == APK_SIG_SCHEME_V3_ID || id == APK_SIG_SCHEME_V2_ID) {
                    val scheme = if (id == APK_SIG_SCHEME_V3_ID) 3 else 2
                    if (scheme > detectedScheme) detectedScheme = scheme
                    val slice = ByteBuffer.wrap(blockBytes, valStart, valLen).order(ByteOrder.LITTLE_ENDIAN)
                    outCerts += parseSignersCertificatesFromSchemeBlock(slice)
                }
                pos += 8 + pairLen.toInt()
            }
        }
        return detectedScheme to outCerts
    }

    /**
     * Parses length-prefixed `signers` sequence in APK Signature Scheme v2/v3:
     * `signers = uint32_len [ signer = uint32_len [ signed_data = uint32_len [ digests = uint32_len [...], certificates = uint32_len [ cert = uint32_len [DER] ] ] ] ]`
     */
    internal fun parseSignersCertificatesFromSchemeBlock(buf: ByteBuffer): List<ByteArray> {
        val certs = ArrayList<ByteArray>()
        val signersSlice = readLengthPrefixedSlice(buf) ?: return emptyList()
        while (signersSlice.hasRemaining()) {
            val signer = readLengthPrefixedSlice(signersSlice) ?: break
            val signedData = readLengthPrefixedSlice(signer) ?: continue
            // Skip digests sequence
            readLengthPrefixedSlice(signedData) ?: continue
            // Read X.509 certificates sequence
            val certSeq = readLengthPrefixedSlice(signedData) ?: continue
            while (certSeq.hasRemaining()) {
                val certSlice = readLengthPrefixedSlice(certSeq) ?: break
                val der = ByteArray(certSlice.remaining())
                certSlice.get(der)
                if (der.isNotEmpty()) certs += der
            }
        }
        return certs
    }

    private fun readLengthPrefixedSlice(buf: ByteBuffer): ByteBuffer? {
        if (buf.remaining() < 4) return null
        val len = buf.int
        if (len < 0 || len > buf.remaining()) return null
        val slice = buf.slice().order(ByteOrder.LITTLE_ENDIAN)
        slice.limit(len)
        buf.position(buf.position() + len)
        return slice
    }
}
