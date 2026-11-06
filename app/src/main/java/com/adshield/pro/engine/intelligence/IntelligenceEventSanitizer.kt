package com.adshield.pro.engine.intelligence

import com.adshield.pro.domain.intelligence.IntelligenceAction
import com.adshield.pro.domain.intelligence.IntelligenceEvent
import com.adshield.pro.domain.intelligence.IntelligenceEventType
import com.adshield.pro.domain.intelligence.IntelligenceMetric
import com.adshield.pro.domain.intelligence.IntelligenceModule
import com.adshield.pro.domain.intelligence.IntelligenceSeverity

/**
 * Validation, severity policy and redaction for intelligence events.
 *
 * Three invariants matter here, and all three are unit-tested:
 *  1. **No evidence, no event.** An event whose evidence collapses to blank is dropped instead of
 *     stored with a placeholder.
 *  2. **No downgrades.** A publisher can escalate an event above its catalogue severity but never
 *     below it, so a broken caller cannot label a critical resolver failure as INFO.
 *  3. **No secrets in labels.** Tokens, passwords, e-mail addresses, card/phone numbers and
 *     long opaque blobs are masked before anything reaches Room or a map label.
 */
object IntelligenceEventSanitizer {

    const val MAX_TITLE = 96
    const val MAX_DESCRIPTION = 320
    const val MAX_EVIDENCE = 480
    const val MAX_METRICS = 8
    const val MAX_RELATED_IDS = 8
    const val MAX_METRIC_LABEL = 32
    const val MAX_METRIC_VALUE = 48
    const val MAX_FUTURE_SKEW_MS = 5 * 60_000L
    const val MAX_AGE_MS = 400L * 24L * 60L * 60L * 1_000L

    private val controlChars = Regex("[\\u0000-\\u0008\\u000B\\u000C\\u000E-\\u001F\\u007F]")
    private val userInfo = Regex("(://)[^/@\\s]+@")
    private val secretAssignment = Regex(
        "(?i)\\b(token|access_token|refresh_token|key|api_key|apikey|secret|password|passwd|pwd|auth|authorization|sig|signature|session|sessionid|otp|pin|code)=([^&\\s,;]+)"
    )
    private val bearer = Regex("(?i)\\bbearer\\s+[A-Za-z0-9._~+/-]+=*")
    private val email = Regex("[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\\.[A-Za-z]{2,})")
    private val longDigitRun = Regex("\\d{9,}")
    private val opaqueBlob = Regex("[A-Za-z0-9+/_=-]{32,}")

    /** Masks secrets and personal identifiers, then collapses whitespace and bounds the length. */
    fun sanitizeText(raw: String?, maxLength: Int): String {
        if (raw.isNullOrBlank()) return ""
        var text = raw.replace(controlChars, " ")
        text = userInfo.replace(text, "$1***@")
        text = bearer.replace(text, "Bearer [redacted]")
        text = secretAssignment.replace(text, "$1=[redacted]")
        text = email.replace(text, "***@$1")
        text = longDigitRun.replace(text, "[redacted-number]")
        text = opaqueBlob.replace(text, "[redacted-token]")
        text = text.replace(Regex("\\s+"), " ").trim()
        return if (text.length <= maxLength) text else text.take(maxLength - 1).trimEnd() + "…"
    }

    /** Domains are evidence, but an unparseable or absurd host must never reach a label. */
    fun sanitizeDomain(raw: String?): String {
        val host = raw?.trim()?.lowercase()?.trimEnd('.') ?: return ""
        if (host.isEmpty() || host.length > 253) return ""
        if (host.any { it.isWhitespace() || it == '@' || it == '/' || it == '\\' }) return ""
        if (!host.contains('.') && !host.contains(':')) return ""
        if (!host.all { it.isLetterOrDigit() || it == '.' || it == '-' || it == '_' || it == ':' }) return ""
        return host
    }

    fun sanitizeMetric(metric: IntelligenceMetric): IntelligenceMetric? {
        val label = sanitizeText(metric.label, MAX_METRIC_LABEL)
        val value = sanitizeText(metric.value, MAX_METRIC_VALUE)
        if (label.isBlank() || value.isBlank()) return null
        return metric.copy(label = label, value = value, detail = sanitizeText(metric.detail, MAX_METRIC_VALUE))
    }

    data class Result(val event: IntelligenceEvent?, val rejectionReason: String?)

    /**
     * Validates and normalises a draft. Returns `null` event plus a reason when the draft cannot
     * honestly be stored (missing evidence, module/type mismatch, unusable timestamp).
     */
    fun sanitize(draft: IntelligenceEvent, nowEpochMs: Long): Result {
        if (draft.type.module != draft.module) {
            return Result(null, "module ${draft.module.id} does not own type ${draft.type.code}")
        }
        if (draft.timestampEpochMs <= 0L) return Result(null, "missing timestamp")
        if (draft.timestampEpochMs > nowEpochMs + MAX_FUTURE_SKEW_MS) {
            return Result(null, "timestamp is in the future")
        }
        if (nowEpochMs - draft.timestampEpochMs > MAX_AGE_MS) return Result(null, "event is older than retention")

        val evidence = sanitizeText(draft.evidence, MAX_EVIDENCE)
        if (evidence.isBlank()) return Result(null, "no evidence attached")

        val title = sanitizeText(draft.title, MAX_TITLE).ifBlank { draft.type.label }
        val description = sanitizeText(draft.description, MAX_DESCRIPTION).ifBlank { evidence }

        // Severity may only be raised above the catalogue default, never lowered.
        val severity = if (draft.severity.rank < draft.type.defaultSeverity.rank) {
            draft.type.defaultSeverity
        } else {
            draft.severity
        }

        val allowedActions = IntelligenceAction.forModule(draft.module).toSet()
        val actions = draft.actions.filter { it in allowedActions }.distinct().take(4)
        val metrics = draft.metrics.mapNotNull { sanitizeMetric(it) }.take(MAX_METRICS)
        val related = draft.relatedObjectIds
            .map { sanitizeText(it, 48) }
            .filter { it.isNotBlank() }
            .distinct()
            .take(MAX_RELATED_IDS)

        val event = draft.copy(
            module = draft.type.module,
            severity = severity,
            title = title,
            description = description,
            evidence = evidence,
            evidenceRef = draft.evidenceRef?.let { sanitizeText(it, 64) }?.takeIf { it.isNotBlank() },
            relatedObjectIds = related,
            actions = actions,
            metrics = metrics
        )
        return Result(event, null)
    }

    /** Convenience for tests and callers that only need the boolean contract. */
    fun isValid(draft: IntelligenceEvent, nowEpochMs: Long): Boolean =
        sanitize(draft, nowEpochMs).event != null

    /** The severity a publisher is allowed to attach for a given type. */
    fun normalisedSeverity(type: IntelligenceEventType, requested: IntelligenceSeverity): IntelligenceSeverity =
        if (requested.rank < type.defaultSeverity.rank) type.defaultSeverity else requested

    fun moduleOf(type: IntelligenceEventType): IntelligenceModule = type.module
}
