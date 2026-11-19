package com.adshield.pro.engine.security

import com.adshield.pro.engine.browser.LinkSanitizer
import java.util.Locale

/**
 * Multi-Format QR Code Payload Inspector (URLs, EMVCo / QRPh / InstaPay Payment QRs, Wi-Fi, Telecom/USSD).
 *
 * QR scams target users with opaque payloads that bypass visual inspection:
 * 1. **Phishing & Redirect-Wrapped URLs**: Unwraps nested redirect parameters offline via
 *    [LinkSanitizer] and scores punycode/typosquat/credential traps via [UrlThreatScanner].
 * 2. **EMVCo Merchant-Presented Payment QRs (`000201...` — QRPh, InstaPay, PromptPay, SGQR, EMV)**:
 *    Parses TLV data objects (`Tag 59` Merchant Name, `Tag 60` City, `Tag 58` Country, `Tag 53`
 *    ISO-4217 Currency, `Tag 54` Pre-filled Amount, `Tag 62` Reference) and verifies the mandatory
 *    **ISO/IEC 13239 CRC-16/CCITT-FALSE (`0x1021`)** checksum in `Tag 63` to catch tampered payment
 *    QRs or unexpected pre-filled transfer amounts.
 * 3. **Wi-Fi Auto-Connect QRs (`WIFI:S:...;T:...;;`)**: Flags open (`nopass`) or deprecated `WEP`
 *    networks before the user joins an evil-twin hotspot.
 * 4. **USSD / Call-Forwarding & Intent URI Traps**: Flags `*21*` / `**67*` OTP call-divert dial
 *    codes, `intent://` arbitrary component launches, and `javascript:`/`data:` payloads.
 */
object QrPayloadInspector {

    enum class PayloadKind(val label: String) {
        URL("Web Link / URL"),
        EMVCO_PAYMENT("EMVCo / QRPh Merchant Payment"),
        WIFI_CONFIG("Wi-Fi Network Configuration"),
        TELECOM_OR_SMS("Phone / SMS / USSD Action"),
        CRYPTO_PAYMENT("Cryptocurrency Payment URI"),
        ANDROID_INTENT("Android App Intent URI"),
        PLAIN_TEXT("Plain Text")
    }

    enum class VerdictLevel { SAFE_LOOKING, CAUTION, DANGEROUS }

    data class EmvPaymentSummary(
        val merchantName: String?,
        val merchantCity: String?,
        val countryCode: String?,
        val currencyCode: String?,
        val currencyLabel: String?,
        val transactionAmount: String?,
        val isDynamicQr: Boolean,
        val crcValid: Boolean,
        val expectedCrcHex: String,
        val declaredCrcHex: String
    )

    data class WifiConfigSummary(
        val ssid: String,
        val authType: String,
        val isHidden: Boolean
    )

    data class QrInspectionReport(
        val rawPayload: String,
        val kind: PayloadKind,
        val verdict: VerdictLevel,
        val riskScore: Int,
        val headline: String,
        val sanitizedUrl: String? = null,
        val emvPayment: EmvPaymentSummary? = null,
        val wifiConfig: WifiConfigSummary? = null,
        val findings: List<String>
    )

    private val ISO_CURRENCY_LABELS = mapOf(
        "608" to "PHP",
        "840" to "USD",
        "978" to "EUR",
        "392" to "JPY",
        "702" to "SGD",
        "826" to "GBP",
        "036" to "AUD",
        "764" to "THB"
    )

    fun inspect(
        rawPayload: String,
        urlScanner: UrlThreatScanner = UrlThreatScanner()
    ): QrInspectionReport {
        val trimmed = rawPayload.trim()
        if (trimmed.isEmpty()) {
            return QrInspectionReport(
                rawPayload = "",
                kind = PayloadKind.PLAIN_TEXT,
                verdict = VerdictLevel.CAUTION,
                riskScore = 20,
                headline = "Empty QR payload",
                findings = listOf("QR code decoded to an empty string")
            )
        }

        val lower = trimmed.lowercase(Locale.US)

        // 1. Dangerous executable / intent schemes
        if (lower.startsWith("javascript:") || lower.startsWith("data:") || lower.startsWith("vbscript:")) {
            return QrInspectionReport(
                rawPayload = trimmed,
                kind = PayloadKind.URL,
                verdict = VerdictLevel.DANGEROUS,
                riskScore = 90,
                headline = "Executable script/data URI inside QR code",
                findings = listOf("QR contains an active '${trimmed.substringBefore(':')}:' payload that must never be opened")
            )
        }

        if (lower.startsWith("intent:") || lower.startsWith("android-app:")) {
            return QrInspectionReport(
                rawPayload = trimmed,
                kind = PayloadKind.ANDROID_INTENT,
                verdict = VerdictLevel.CAUTION,
                riskScore = 55,
                headline = "Android deep-link intent URI",
                findings = listOf(
                    "Launches a specific Android app/component directly; verify target package and fallback URL before opening"
                )
            )
        }

        // 2. EMVCo / QRPh / InstaPay Merchant Payment QR ("000201...")
        if (trimmed.startsWith("000201") && trimmed.length >= 24) {
            return inspectEmvCoPaymentQr(trimmed)
        }

        // 3. Wi-Fi Network Provisioning QR ("WIFI:...")
        if (lower.startsWith("wifi:")) {
            return inspectWifiQr(trimmed)
        }

        // 4. Telecom / SMS / USSD dial traps
        if (lower.startsWith("tel:") || lower.startsWith("sms:") || lower.startsWith("smsto:") ||
            trimmed.startsWith("*21*") || trimmed.startsWith("**21*") || trimmed.startsWith("**67*") ||
            trimmed.startsWith("**61*") || trimmed.startsWith("**62*")
        ) {
            return inspectTelecomQr(trimmed)
        }

        // 5. Crypto / UPI URI
        if (lower.startsWith("bitcoin:") || lower.startsWith("ethereum:") || lower.startsWith("solana:") ||
            lower.startsWith("upi://")
        ) {
            return QrInspectionReport(
                rawPayload = trimmed,
                kind = PayloadKind.CRYPTO_PAYMENT,
                verdict = VerdictLevel.CAUTION,
                riskScore = 40,
                headline = "Direct payment transfer URI",
                findings = listOf("Initiates an irreversible payment/wallet request; confirm recipient address and amount")
            )
        }

        // 6. HTTP / HTTPS URL (or bare domain link)
        if (lower.startsWith("http://") || lower.startsWith("https://")) {
            val cleaned = LinkSanitizer.sanitize(trimmed)
            val targetUrl = cleaned.cleanedUrl
            val urlVerdict = urlScanner.scanUrl(targetUrl)
            val findings = ArrayList<String>()
            if (cleaned.unwrappedFromHost != null) {
                findings += "Unwrapped hidden redirect wrapper from ${cleaned.unwrappedFromHost}"
            }
            if (cleaned.removedParameters.isNotEmpty()) {
                findings += "Stripped ${cleaned.removedParameters.size} tracking parameter(s): ${cleaned.removedParameters.take(4).joinToString(", ")}"
            }
            findings.addAll(urlVerdict.reasons)
            val score = maxOf(
                urlVerdict.riskScore,
                if (lower.startsWith("http://")) 35 else 0,
                if (cleaned.unwrappedFromHost != null) 25 else 0
            ).coerceIn(0, 100)
            val level = when {
                urlVerdict.threatLevel == UrlThreatScanner.ThreatLevel.DANGEROUS || score >= 65 -> VerdictLevel.DANGEROUS
                urlVerdict.threatLevel == UrlThreatScanner.ThreatLevel.SUSPICIOUS || score >= 25 -> VerdictLevel.CAUTION
                else -> VerdictLevel.SAFE_LOOKING
            }
            return QrInspectionReport(
                rawPayload = trimmed,
                kind = PayloadKind.URL,
                verdict = level,
                riskScore = score,
                headline = when (level) {
                    VerdictLevel.DANGEROUS -> "High-risk phishing / malicious QR URL"
                    VerdictLevel.CAUTION -> "QR link requires caution before opening"
                    VerdictLevel.SAFE_LOOKING -> "No local phishing indicators found in QR URL"
                },
                sanitizedUrl = targetUrl,
                findings = findings.ifEmpty { listOf("Inspected hostname and URL structure locally") }
            )
        }

        return QrInspectionReport(
            rawPayload = trimmed,
            kind = PayloadKind.PLAIN_TEXT,
            verdict = VerdictLevel.SAFE_LOOKING,
            riskScore = 0,
            headline = "Plain-text QR note (${trimmed.length} chars)",
            findings = listOf("Contains non-executable plain text")
        )
    }

    /** Computes ISO/IEC 13239 CRC-16/CCITT-FALSE (`poly = 0x1021, init = 0xFFFF`) used by EMVCo QRs. */
    fun computeEmvCrc16Hex(asciiInput: String): String {
        var crc = 0xFFFF
        val bytes = asciiInput.toByteArray(Charsets.US_ASCII)
        for (b in bytes) {
            crc = crc xor ((b.toInt() and 0xFF) shl 8)
            repeat(8) {
                crc = if ((crc and 0x8000) != 0) {
                    ((crc shl 1) xor 0x1021) and 0xFFFF
                } else {
                    (crc shl 1) and 0xFFFF
                }
            }
        }
        return String.format(Locale.US, "%04X", crc)
    }

    /** Builds a valid EMVCo / QRPh payload with computed `6304<CRC>` trailer (helpful for self-tests). */
    fun appendEmvCrc(bodyWithoutTag63: String): String {
        val prefix = "${bodyWithoutTag63}6304"
        return prefix + computeEmvCrc16Hex(prefix)
    }

    private fun inspectEmvCoPaymentQr(payload: String): QrInspectionReport {
        val tags = LinkedHashMap<String, String>()
        var idx = 0
        var malformedStructure = false
        while (idx + 4 <= payload.length) {
            val tag = payload.substring(idx, idx + 2)
            val len = payload.substring(idx + 2, idx + 4).toIntOrNull()
            if (len == null || len < 0 || idx + 4 + len > payload.length) {
                malformedStructure = true
                break
            }
            val value = payload.substring(idx + 4, idx + 4 + len)
            tags[tag] = value
            idx += 4 + len
            if (tag == "63") break
        }
        if (idx != payload.length) malformedStructure = true

        val declaredCrc = tags["63"]?.uppercase(Locale.US).orEmpty()
        val crcMarkerIdx = payload.lastIndexOf("6304")
        val expectedCrc = if (crcMarkerIdx >= 0 && crcMarkerIdx + 8 == payload.length) {
            computeEmvCrc16Hex(payload.substring(0, crcMarkerIdx + 4))
        } else {
            ""
        }
        val crcValid = !malformedStructure && declaredCrc.length == 4 && declaredCrc == expectedCrc

        val poiMethod = tags["01"]
        val currencyCode = tags["53"]
        val currencyLabel = currencyCode?.let { ISO_CURRENCY_LABELS[it] ?: "ISO-$it" }
        val amountStr = tags["54"]
        val country = tags["58"]
        val merchantName = tags["59"]
        val merchantCity = tags["60"]

        val summary = EmvPaymentSummary(
            merchantName = merchantName,
            merchantCity = merchantCity,
            countryCode = country,
            currencyCode = currencyCode,
            currencyLabel = currencyLabel,
            transactionAmount = amountStr,
            isDynamicQr = poiMethod == "12",
            crcValid = crcValid,
            expectedCrcHex = expectedCrc,
            declaredCrcHex = declaredCrc
        )

        val findings = ArrayList<String>()
        var score = 0
        if (!crcValid) {
            score += 80
            findings += "EMVCo CRC-16 checksum FAILED (declared=${declaredCrc.ifEmpty { "missing" }}, expected=${expectedCrc.ifEmpty { "n/a" }}) — payment QR may be tampered or corrupted"
        } else {
            findings += "EMVCo CRC-16 checksum verified ($declaredCrc)"
        }

        if (merchantName.isNullOrBlank()) {
            score += 30
            findings += "Merchant name (Tag 59) is missing from payment QR"
        } else {
            findings += "Merchant: $merchantName${merchantCity?.let { " ($it)" }.orEmpty()}"
        }

        val parsedAmount = amountStr?.toDoubleOrNull()
        if (parsedAmount != null && parsedAmount > 0.0) {
            score += 20
            findings += "Pre-filled transfer amount: ${currencyLabel ?: ""} $amountStr — verify you intend to send money, not receive"
        }

        val verdict = when {
            !crcValid || score >= 65 -> VerdictLevel.DANGEROUS
            score >= 20 -> VerdictLevel.CAUTION
            else -> VerdictLevel.SAFE_LOOKING
        }
        return QrInspectionReport(
            rawPayload = payload,
            kind = PayloadKind.EMVCO_PAYMENT,
            verdict = verdict,
            riskScore = score.coerceIn(0, 100),
            headline = when {
                !crcValid -> "Tampered or invalid EMVCo / QRPh payment code"
                parsedAmount != null -> "Payment QR requesting ${currencyLabel ?: ""} $amountStr to ${merchantName ?: "Unknown"}"
                else -> "Verified EMVCo / QRPh merchant code: ${merchantName ?: "Unknown"}"
            },
            emvPayment = summary,
            findings = findings
        )
    }

    private fun inspectWifiQr(payload: String): QrInspectionReport {
        val body = payload.substringAfter(':').trimEnd(';')
        val fields = LinkedHashMap<String, String>()
        for (part in body.split(';')) {
            val sep = part.indexOf(':')
            if (sep > 0) {
                fields[part.substring(0, sep).uppercase(Locale.US)] = part.substring(sep + 1)
            }
        }
        val ssid = fields["S"].orEmpty()
        val auth = fields["T"]?.uppercase(Locale.US)?.ifBlank { "NOPASS" } ?: "NOPASS"
        val hidden = fields["H"]?.equals("true", ignoreCase = true) == true

        val findings = ArrayList<String>()
        var score = 0
        if (auth == "NOPASS" || auth == "NONE") {
            score += 45
            findings += "Open unencrypted Wi-Fi network ('$ssid') — vulnerable to traffic interception and rogue captive portals"
        } else if (auth == "WEP") {
            score += 55
            findings += "Deprecated WEP Wi-Fi security ('$ssid') — trivially crackable"
        } else {
            findings += "Wi-Fi network '$ssid' uses $auth authentication"
        }
        if (hidden) {
            score += 15
            findings += "Connects to a hidden SSID"
        }

        val level = when {
            score >= 55 -> VerdictLevel.DANGEROUS
            score >= 20 -> VerdictLevel.CAUTION
            else -> VerdictLevel.SAFE_LOOKING
        }
        return QrInspectionReport(
            rawPayload = payload,
            kind = PayloadKind.WIFI_CONFIG,
            verdict = level,
            riskScore = score,
            headline = "Wi-Fi config for '${ssid.ifBlank { "Unnamed" }}' ($auth)",
            wifiConfig = WifiConfigSummary(ssid = ssid, authType = auth, isHidden = hidden),
            findings = findings
        )
    }

    private fun inspectTelecomQr(payload: String): QrInspectionReport {
        val decoded = payload.replace("%23", "#", ignoreCase = true).replace("%2A", "*", ignoreCase = true)
        val isCallForwardUssd = Regex("""(\*\*?\d{2}\*|##\d{2}#)""").containsMatchIn(decoded)
        return if (isCallForwardUssd) {
            QrInspectionReport(
                rawPayload = payload,
                kind = PayloadKind.TELECOM_OR_SMS,
                verdict = VerdictLevel.DANGEROUS,
                riskScore = 90,
                headline = "USSD call/OTP forwarding code detected",
                findings = listOf(
                    "Contains carrier USSD MMI forwarding sequence ('$decoded') commonly used to hijack voice OTPs"
                )
            )
        } else {
            QrInspectionReport(
                rawPayload = payload,
                kind = PayloadKind.TELECOM_OR_SMS,
                verdict = VerdictLevel.CAUTION,
                riskScore = 25,
                headline = "Phone call or pre-addressed SMS QR",
                findings = listOf("Review recipient number and message text before dialing or sending")
            )
        }
    }
}
