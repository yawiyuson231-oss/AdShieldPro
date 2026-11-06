package com.adshield.pro.data.repository

import com.adshield.pro.domain.intelligence.IntelligenceEvent
import com.adshield.pro.domain.intelligence.IntelligenceEventType
import com.adshield.pro.engine.intelligence.IntelligenceEventSanitizer
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import javax.inject.Inject
import javax.inject.Singleton

/**
 * De-duplication policy for repeated identical observations.
 *
 * A DNS filter blocks the same tracker hundreds of times per minute; storing every single match
 * would fill the bounded history and make the map useless. The policy is pure so the cooldown
 * behaviour is unit-testable, and it is keyed on *what actually happened* — never on a timer that
 * could manufacture events.
 */
object IntelligenceDedupePolicy {

    private const val MINUTE = 60_000L

    fun keyFor(event: IntelligenceEvent): String {
        val subject = event.evidenceRef
            ?: event.relatedObjectIds.firstOrNull()
            ?: event.title
        return "${event.type.code}|$subject"
    }

    fun cooldownMs(type: IntelligenceEventType): Long = when (type) {
        IntelligenceEventType.NETWORK_THREAT_BLOCKED -> 10 * MINUTE
        IntelligenceEventType.DEVICE_THERMAL_WARNING,
        IntelligenceEventType.DEVICE_THERMAL_RECOVERED,
        IntelligenceEventType.DEVICE_TELEMETRY_UNAVAILABLE,
        IntelligenceEventType.DEVICE_HEALTH_ALERT -> 30 * MINUTE
        IntelligenceEventType.NETWORK_PROTECTION_STARTED,
        IntelligenceEventType.NETWORK_PROTECTION_STOPPED,
        IntelligenceEventType.NETWORK_FILTERING_PAUSED,
        IntelligenceEventType.NETWORK_RESOLVER_ERROR,
        IntelligenceEventType.NETWORK_RULES_MISSING -> 15_000L
        IntelligenceEventType.AUTOMATION_JOB_OK,
        IntelligenceEventType.AUTOMATION_JOB_FAILED -> 60_000L
        IntelligenceEventType.EMERGENCY_LOCKDOWN_ON,
        IntelligenceEventType.EMERGENCY_LOCKDOWN_OFF,
        IntelligenceEventType.EMERGENCY_READINESS_DEGRADED -> 5 * MINUTE
        IntelligenceEventType.CYBER_SCAN_FINDING,
        IntelligenceEventType.CYBER_SCAN_CLEAN,
        IntelligenceEventType.CYBER_QUARANTINE_ADDED,
        IntelligenceEventType.FINANCIAL_PAYMENT_RISK,
        IntelligenceEventType.FINANCIAL_LINK_CLEAN,
        IntelligenceEventType.PRIVACY_PERMISSION_FINDING,
        IntelligenceEventType.PRIVACY_AUDIT_CLEAN -> 0L
        IntelligenceEventType.PRIVACY_SETTING_CHANGED,
        IntelligenceEventType.AUTOMATION_SETTING_CHANGED -> 30_000L
    }
}

/**
 * Single ingestion point for every module service.
 *
 * Callers hand over a fully-built draft describing something that really happened. The recorder
 * validates it ([IntelligenceEventSanitizer]), de-duplicates repeats, and writes it asynchronously
 * so a DNS hot path is never blocked by SQLite. Nothing here can create activity on its own.
 */
@Singleton
class IntelligenceRecorder @Inject constructor(
    private val repository: IntelligenceRepository
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val mutex = Mutex()
    private val lastEmitted = LinkedHashMap<String, Long>()

    /** Fire-and-forget (DNS hot path, VPN callbacks, workers). */
    fun record(draft: IntelligenceEvent) {
        scope.launch { emit(draft) }
    }

    fun recordAll(drafts: List<IntelligenceEvent>) {
        if (drafts.isEmpty()) return
        scope.launch { drafts.forEach { emit(it) } }
    }

    /**
     * Suspending variant for callers that need to know whether the event was stored (tests and
     * the scan-journal bridge).
     */
    suspend fun emit(draft: IntelligenceEvent, nowEpochMs: Long = System.currentTimeMillis()): IntelligenceEvent? {
        val sanitized = IntelligenceEventSanitizer.sanitize(draft, nowEpochMs).event ?: return null
        val key = IntelligenceDedupePolicy.keyFor(sanitized)
        val cooldown = IntelligenceDedupePolicy.cooldownMs(sanitized.type)
        mutex.withLock {
            val last = lastEmitted[key]
            if (cooldown > 0L && last != null && nowEpochMs - last < cooldown) return null
            lastEmitted[key] = nowEpochMs
            if (lastEmitted.size > MAX_DEDUPE_KEYS) {
                val oldest = lastEmitted.entries.minByOrNull { it.value }?.key
                if (oldest != null) lastEmitted.remove(oldest)
            }
        }
        return repository.record(sanitized, nowEpochMs)
    }

    /** Visible for tests: how many distinct dedupe keys are tracked right now. */
    fun trackedKeyCount(): Int = lastEmitted.size

    companion object {
        /** Bounded so the de-duplication map itself cannot grow without limit. */
        const val MAX_DEDUPE_KEYS = 256
    }
}
