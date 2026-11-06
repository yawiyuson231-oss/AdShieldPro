package com.adshield.pro.engine.connectors

import com.adshield.pro.domain.connectors.ConnectorRuntime
import com.adshield.pro.domain.connectors.ConnectorSpec
import com.adshield.pro.domain.connectors.FeedParseException
import com.adshield.pro.domain.connectors.SyncOutcome

/**
 * Pure sync state machine: one connector + its previous runtime + a transport in, one outcome out.
 *
 * The engine never invents success. A connector only reports [SyncOutcome.Success] when the HTTP
 * layer received a valid 2xx/304 response and (for 2xx) the parser understood the body. Rate limits,
 * provider errors and timeouts map to distinct outcomes so the UI can say what actually happened.
 */
class ConnectorSyncEngine(
    private val transport: ConnectorTransport,
    private val now: () -> Long = System::currentTimeMillis
) {

    fun sync(spec: ConnectorSpec, runtime: ConnectorRuntime): SyncOutcome {
        if (!spec.implemented) return SyncOutcome.Skipped
        if (spec.requiresKey) return SyncOutcome.NotConfigured
        if (!runtime.enabled) return SyncOutcome.Skipped

        val nowMs = now()
        runtime.nextAllowedEpochMs?.let { next ->
            if (next > nowMs) {
                return SyncOutcome.Retryable(
                    httpCode = null,
                    reason = "cooling down for ${(next - nowMs) / 1_000L}s",
                    latencyMs = 0L,
                    retryAfterMs = next - nowMs
                )
            }
        }

        val result = transport.get(spec, runtime.etag, runtime.lastModified)
        return when (result) {
            is TransportResult.Failure -> SyncOutcome.Retryable(
                httpCode = null,
                reason = result.reason,
                latencyMs = result.latencyMs,
                retryAfterMs = backoffFor(runtime.consecutiveFailures + 1),
                offline = result.offline
            )

            is TransportResult.Response -> evaluate(spec, result)
        }
    }

    private fun evaluate(spec: ConnectorSpec, response: TransportResult.Response): SyncOutcome {
        val code = response.code
        return when {
            code == 304 -> SyncOutcome.Success(
                indicators = emptyList(),
                rowsSeen = 0,
                httpCode = code,
                notModified = true,
                etag = response.etag,
                lastModified = response.lastModified,
                latencyMs = response.latencyMs,
                summary = "not modified since last sync"
            )

            code == 429 -> SyncOutcome.Retryable(
                httpCode = code,
                reason = "provider rate limit",
                latencyMs = response.latencyMs,
                retryAfterMs = response.retryAfterMs ?: RATE_LIMIT_COOLDOWN_MS
            )

            code == 401 || code == 403 -> SyncOutcome.Failed(
                httpCode = code,
                reason = "provider refused anonymous access (credentials required)",
                latencyMs = response.latencyMs
            )

            code in 500..599 -> SyncOutcome.Retryable(
                httpCode = code,
                reason = "provider error HTTP $code",
                latencyMs = response.latencyMs,
                retryAfterMs = response.retryAfterMs ?: RATE_LIMIT_COOLDOWN_MS
            )

            code !in 200..299 -> SyncOutcome.Failed(
                httpCode = code,
                reason = "HTTP $code",
                latencyMs = response.latencyMs
            )

            response.body.isNullOrBlank() -> SyncOutcome.Failed(
                httpCode = code,
                reason = "empty response body",
                latencyMs = response.latencyMs
            )

            else -> {
                try {
                    val parsed = ConnectorParsers.parse(spec.handlerId, spec, response.body, now())
                    SyncOutcome.Success(
                        indicators = parsed.indicators,
                        rowsSeen = parsed.rowsSeen,
                        httpCode = code,
                        notModified = false,
                        etag = response.etag,
                        lastModified = response.lastModified,
                        latencyMs = response.latencyMs,
                        summary = parsed.note
                    )
                } catch (parse: FeedParseException) {
                    SyncOutcome.Failed(
                        httpCode = code,
                        reason = "invalid response: ${parse.message}",
                        latencyMs = response.latencyMs
                    )
                } catch (other: Exception) {
                    SyncOutcome.Failed(
                        httpCode = code,
                        reason = "parser failed: ${other.javaClass.simpleName}",
                        latencyMs = response.latencyMs
                    )
                }
            }
        }
    }

    companion object {
        const val RATE_LIMIT_COOLDOWN_MS = 15L * 60L * 1_000L
        const val MAX_BACKOFF_MS = 6L * 60L * 60L * 1_000L

        /** 30 s, 1 min, 2 min, ... capped at 6 h. Zero failures means "no penalty". */
        fun backoffFor(consecutiveFailures: Int): Long {
            if (consecutiveFailures <= 0) return 0L
            val exponent = (consecutiveFailures - 1).coerceAtMost(12)
            val base = 30_000L shl exponent
            return base.coerceAtMost(MAX_BACKOFF_MS)
        }
    }
}
