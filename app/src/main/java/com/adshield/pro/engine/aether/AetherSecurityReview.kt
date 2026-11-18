package com.adshield.pro.engine.aether

import com.adshield.pro.engine.security.AppRiskAuditor
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withTimeoutOrNull

internal data class AetherAppReview(
    val visible: Int,
    val inspected: Int,
    val highRisk: Int,
    val needsReview: Int,
    val topFindings: List<AppRiskAuditor.AppRiskAudit>
) {
    val unavailable: Int get() = visible - inspected

    companion object {
        fun from(audit: AppRiskAuditor.VisibleAudit): AetherAppReview {
            val flagged = audit.inspected.filter {
                it.riskLevel == AppRiskAuditor.RiskLevel.HIGH || it.riskLevel == AppRiskAuditor.RiskLevel.MEDIUM
            }
            return AetherAppReview(
                visible = audit.visibleCount,
                inspected = audit.inspected.size,
                highRisk = flagged.count { it.riskLevel == AppRiskAuditor.RiskLevel.HIGH },
                needsReview = flagged.size,
                topFindings = flagged.sortedByDescending { it.riskScore }.take(8)
            )
        }
    }
}

internal sealed interface AetherTaskProgress {
    data object ReadingPhone : AetherTaskProgress
    data object ReadingFile : AetherTaskProgress
    data object InspectingFile : AetherTaskProgress
    data class ReadingApps(val processed: Int, val visible: Int) : AetherTaskProgress
}

/** A fixed read-only workflow. The model cannot supply steps, settings writes, or network targets. */
internal object AetherSecurityReview {
    const val PHONE_TIMEOUT_MS = 8_000L
    const val APPS_TIMEOUT_MS = 30_000L

    enum class MissingReason(val label: String) {
        TIMED_OUT("Took too long"), FAILED("Couldn't finish")
    }

    sealed interface Reading<out T> {
        val value: T? get() = null
        data class Received<T>(override val value: T) : Reading<T>
        data class Missing(val reason: MissingReason) : Reading<Nothing>
    }

    data class Report(
        val phone: Reading<AetherPhoneAgent.Report>,
        val apps: Reading<AetherAppReview>,
        val finishedAtMs: Long
    ) {
        // Receipt for the two authorized steps, not a device safety score.
        val hasGaps: Boolean get() = phone.value?.hasUnavailableReadings != false ||
            apps.value?.let { it.inspected == 0 || it.unavailable > 0 } != false
    }

    suspend fun run(
        readPhone: suspend () -> AetherPhoneAgent.Report,
        readApps: suspend () -> AetherAppReview,
        publish: (AetherTaskProgress) -> Unit,
        phoneTimeoutMs: Long = PHONE_TIMEOUT_MS,
        appsTimeoutMs: Long = APPS_TIMEOUT_MS,
        now: () -> Long = System::currentTimeMillis
    ): Report {
        val context = currentCoroutineContext()
        context.ensureActive()
        publish(AetherTaskProgress.ReadingPhone)
        val phone = readStep(phoneTimeoutMs, readPhone)
        context.ensureActive()
        publish(AetherTaskProgress.ReadingApps(0, 0))
        val apps = readStep(appsTimeoutMs, readApps)
        context.ensureActive()
        return Report(phone, apps, now())
    }

    private suspend fun <T : Any> readStep(timeoutMs: Long, read: suspend () -> T): Reading<T> = try {
        // withTimeoutOrNull handles only this step's deadline. Parent/user cancellation propagates.
        withTimeoutOrNull(timeoutMs) { Reading.Received(read()) } ?: Reading.Missing(MissingReason.TIMED_OUT)
    } catch (cancelled: CancellationException) {
        throw cancelled
    } catch (_: Exception) {
        Reading.Missing(MissingReason.FAILED)
    }
}
