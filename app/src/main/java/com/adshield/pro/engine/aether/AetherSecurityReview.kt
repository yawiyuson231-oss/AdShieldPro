package com.adshield.pro.engine.aether

import com.adshield.pro.domain.model.DnsProtocol
import com.adshield.pro.domain.model.DnssecMode
import com.adshield.pro.engine.security.AppRiskAuditor
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
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
            val flagged = audit.inspected.filter { it.hasReviewIndicators() }
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

private fun AppRiskAuditor.AppRiskAudit.hasReviewIndicators() =
    riskLevel == AppRiskAuditor.RiskLevel.HIGH || riskLevel == AppRiskAuditor.RiskLevel.MEDIUM

internal sealed interface AetherTaskProgress {
    data object ReviewingSecurity : AetherTaskProgress
    data object ReadingFile : AetherTaskProgress
    data object InspectingFile : AetherTaskProgress
    data class ReadingApps(val processed: Int, val visible: Int) : AetherTaskProgress
}

/** One approved, fixed read-only workflow. Three specialists return evidence; none receives model text. */
internal object AetherSecurityReview {
    const val PHONE_TIMEOUT_MS = 8_000L
    private const val DNS_POLICY_TIMEOUT_MS = 5_000L
    const val APPS_TIMEOUT_MS = 30_000L
    private const val MAX_APP_MATCH_DETAILS = 4
    private const val MAX_PRIORITIES = 5

    enum class MissingReason(val label: String) {
        TIMED_OUT("Took too long"), FAILED("Couldn't finish")
    }

    enum class Source(val label: String) {
        PROTECTION("Phone protection"), DNS("Saved DNS policy"), APPS("App metadata"), APP_POLICY("App metadata + saved DNS policy")
    }

    sealed interface Reading<out T> {
        val value: T? get() = null
        val checkedAtMs: Long? get() = null
        data class Received<T>(override val value: T, override val checkedAtMs: Long) : Reading<T>
        data class Missing(val reason: MissingReason) : Reading<Nothing>
    }

    data class PriorityFinding(val source: Source, val title: String, val detail: String, val nextTool: AetherPhoneAgent.Tool? = null)

    data class AppPolicyMatch(
        val packageName: String,
        val appName: String,
        val level: AppRiskAuditor.RiskLevel,
        val exception: AetherDnsPolicyReview.AppException,
        val indicators: List<String>
    )

    data class Report(
        val phone: Reading<AetherPhoneAgent.Report>,
        val dns: Reading<AetherDnsPolicyReview.Summary>,
        val apps: Reading<AetherAppReview>,
        val priorities: List<PriorityFinding>,
        /** Null means the comparison could not run; zero means no matches among inspected apps. */
        val appPolicyMatchCount: Int?,
        val appPolicyMatches: List<AppPolicyMatch>,
        val finishedAtMs: Long
    ) {
        val hasGaps: Boolean get() = phone.value?.hasUnavailableReadings != false ||
            dns.value == null || apps.value?.let { it.inspected == 0 || it.unavailable > 0 } != false
    }

    suspend fun run(
        readPhone: suspend () -> AetherPhoneAgent.Report,
        readDns: suspend () -> AetherDnsPolicyReview.Snapshot,
        readApps: suspend () -> AppRiskAuditor.VisibleAudit,
        publish: (AetherTaskProgress) -> Unit,
        phoneTimeoutMs: Long = PHONE_TIMEOUT_MS,
        dnsTimeoutMs: Long = DNS_POLICY_TIMEOUT_MS,
        appsTimeoutMs: Long = APPS_TIMEOUT_MS,
        now: () -> Long = System::currentTimeMillis
    ): Report = coroutineScope {
        ensureActive()
        publish(AetherTaskProgress.ReviewingSecurity)
        // Independent deadlines; a failed or slow reader doesn't prevent the others from reading.
        val phone = async { readStep(phoneTimeoutMs, now, readPhone) }
        val dns = async { readStep(dnsTimeoutMs, now, readDns) }
        val apps = async { readStep(appsTimeoutMs, now, readApps) }
        val result = combine(phone.await(), dns.await(), apps.await(), now())
        ensureActive()
        result
    }

    private suspend fun <T : Any> readStep(timeoutMs: Long, now: () -> Long, read: suspend () -> T): Reading<T> = try {
        withTimeoutOrNull(timeoutMs) {
            val evidence = read()
            currentCoroutineContext().ensureActive()
            Reading.Received(evidence, now())
        } ?: Reading.Missing(MissingReason.TIMED_OUT)
    } catch (cancelled: CancellationException) {
        throw cancelled
    } catch (_: Exception) {
        Reading.Missing(MissingReason.FAILED)
    }

    private fun combine(
        phone: Reading<AetherPhoneAgent.Report>,
        dns: Reading<AetherDnsPolicyReview.Snapshot>,
        audit: Reading<AppRiskAuditor.VisibleAudit>,
        finishedAtMs: Long
    ): Report {
        val settings = dns.value
        val inspected = audit.value?.inspected
        val matches = if (settings != null && !inspected.isNullOrEmpty()) {
            // Join exact Android package IDs over the full audit, not only the displayed top eight.
            inspected.asSequence().filter { it.hasReviewIndicators() }.mapNotNull { app ->
                settings.exceptionFor(app.profile.packageName)?.let { exception -> app to exception }
            }.sortedWith(compareByDescending<Pair<AppRiskAuditor.AppRiskAudit, AetherDnsPolicyReview.AppException>> { it.first.riskLevel }
                .thenByDescending { it.first.riskScore }.thenBy { it.first.profile.packageName }).toList()
        } else null
        val dnsSummary = dns.map { it.summary }
        val appSummary = audit.map(AetherAppReview::from)
        return Report(
            phone = phone,
            dns = dnsSummary,
            apps = appSummary,
            priorities = prioritize(phone.value, dnsSummary.value, appSummary.value, matches?.size),
            appPolicyMatchCount = matches?.size,
            appPolicyMatches = matches.orEmpty().take(MAX_APP_MATCH_DETAILS).map { (app, exception) ->
                AppPolicyMatch(app.profile.packageName, app.profile.appName, app.riskLevel, exception, app.findings.take(3))
            },
            finishedAtMs = finishedAtMs
        )
    }

    private fun prioritize(
        phone: AetherPhoneAgent.Report?,
        dns: AetherDnsPolicyReview.Summary?,
        apps: AetherAppReview?,
        matches: Int?
    ): List<PriorityFinding> = buildList {
        val protection = phone?.findings.orEmpty()
        fun addProtection(finding: AetherPhoneAgent.Finding) = add(PriorityFinding(Source.PROTECTION,
            finding.title, finding.evidence, finding.nextTool))
        protection.filter { it.priority == AetherPhoneAgent.Priority.ATTENTION }.forEach { addProtection(it) }
        if (dns != null && dns.excludedAppsWithBlockRules > 0) {
            add(PriorityFinding(Source.DNS, "DNS block rules overlap with VPN exclusions",
                "${dns.excludedAppsWithBlockRules} saved app settings ask AdShield to block DNS for apps also marked as excluded. Per-app DNS rules only apply to requests that enter the tunnel.",
                AetherPhoneAgent.Tool.APP_FIREWALL))
        }
        if (matches != null && matches > 0) {
            add(PriorityFinding(Source.APP_POLICY, "App indicators and DNS exceptions overlap",
                "$matches inspected app(s) with review indicators also have a saved DNS exception. Review whether the exceptions are still needed. This does not show that an app is malicious or sent traffic.",
                AetherPhoneAgent.Tool.APP_FIREWALL))
        } else if (apps != null && apps.highRisk > 0) {
            add(PriorityFinding(Source.APPS, "Review high-risk app indicators",
                "${apps.highRisk} inspected app(s) had high-risk metadata indicators. See the app evidence below; declared permissions do not prove use or abuse."))
        }
        if (dns?.failover == AetherDnsPolicyReview.Failover.NO_BACKUPS) {
            add(PriorityFinding(Source.DNS, "Encrypted failover has no eligible backup",
                "The setting is on, but only the primary resolver is in the saved plan. Add a backup only if you trust its DNS policy.", AetherPhoneAgent.Tool.DNS_SETTINGS))
        }
        if (dns?.protocol == DnsProtocol.UDP_TCP && dns.dnssecMode == DnssecMode.REQUIRE_AUTHENTICATED_ANSWERS) {
            add(PriorityFinding(Source.DNS, "Strict AD checks use a plaintext path",
                "The DNSSEC setting checks a resolver flag, not a local signature chain. The selected transport does not authenticate the upstream channel.", AetherPhoneAgent.Tool.DNS_SETTINGS))
        }
        protection.filter { it.priority == AetherPhoneAgent.Priority.REVIEW }.forEach { addProtection(it) }
    }.take(MAX_PRIORITIES)

    private fun <T, R> Reading<T>.map(transform: (T) -> R): Reading<R> = when (this) {
        is Reading.Received -> Reading.Received(transform(value), checkedAtMs)
        is Reading.Missing -> this
    }
}
