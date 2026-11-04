package com.adshield.pro.engine.platform

import com.adshield.pro.domain.model.DnsProtocol
import com.adshield.pro.domain.model.DnsProviderPreset
import com.adshield.pro.domain.model.DnsResolverConfig
import com.adshield.pro.domain.model.VpnRuntimeState
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.net.URI

/**
 * AdShield Pro — Privacy-Scrubbed Exportable Diagnostic Report Builder.
 *
 * Generates a structured JSON report summarizing runtime health, capability counts, rule counts,
 * battery telemetry, and VPN state while scrubbing custom DoH query tokens, credentials, and
 * per-domain browsing history so users can safely inspect or share diagnostics.
 */
object DiagnosticReportBuilder {

    @Serializable
    data class DiagnosticReport(
        val generatedAtEpochMs: Long,
        val appVersionName: String,
        val appVersionCode: Int,
        val sdkInt: Int,
        val formFactor: String,
        val supportedPlatform: Boolean,
        val cpuArchitectures: List<String>,
        val capabilitySummary: String,
        val implementedCapabilities: Int,
        val partialCapabilities: Int,
        val unavailableCapabilities: Int,
        val vpnStatus: String,
        val activeProtectionMode: String,
        val loadedRuleCount: Int,
        val dnsProtocol: String,
        val dnsPreset: String,
        val scrubbedResolverEndpoint: String,
        val ipv6Enabled: Boolean,
        val sessionTotalQueries: Long,
        val sessionBlockedQueries: Long,
        val averageLatencyMs: Int,
        val lastVpnError: String?,
        val batteryLevelPercent: Int?,
        val batteryTempCelsius: Float?,
        val batteryHealthLabel: String?
    )

    private val prettyJson = Json {
        prettyPrint = true
        encodeDefaults = true
    }

    fun buildJson(
        versionName: String,
        versionCode: Int,
        deviceProfile: DeviceProfile?,
        vpnState: VpnRuntimeState,
        batteryLevelPercent: Int?,
        batteryTempCelsius: Float?,
        batteryHealthLabel: String?
    ): String {
        val report = DiagnosticReport(
            generatedAtEpochMs = System.currentTimeMillis(),
            appVersionName = versionName,
            appVersionCode = versionCode,
            sdkInt = deviceProfile?.sdkInt ?: android.os.Build.VERSION.SDK_INT,
            formFactor = deviceProfile?.formFactor?.name ?: "UNKNOWN",
            supportedPlatform = deviceProfile?.supportedPlatform ?: true,
            cpuArchitectures = deviceProfile?.cpuArchitectures ?: emptyList(),
            capabilitySummary = CapabilityRegistry.summary(),
            implementedCapabilities = CapabilityRegistry.count(CapabilityStatus.IMPLEMENTED),
            partialCapabilities = CapabilityRegistry.count(CapabilityStatus.PARTIAL),
            unavailableCapabilities = CapabilityRegistry.count(CapabilityStatus.UNAVAILABLE),
            vpnStatus = vpnState.status.name,
            activeProtectionMode = vpnState.activeMode.name,
            loadedRuleCount = vpnState.loadedRuleCount,
            dnsProtocol = vpnState.resolverConfig.protocol.name,
            dnsPreset = vpnState.resolverConfig.preset.name,
            scrubbedResolverEndpoint = scrubResolverEndpoint(vpnState.resolverConfig),
            ipv6Enabled = vpnState.resolverConfig.enableIpv6,
            sessionTotalQueries = vpnState.sessionTotalQueries,
            sessionBlockedQueries = vpnState.sessionBlockedQueries,
            averageLatencyMs = vpnState.averageLatencyMs,
            lastVpnError = vpnState.lastError,
            batteryLevelPercent = batteryLevelPercent,
            batteryTempCelsius = batteryTempCelsius,
            batteryHealthLabel = batteryHealthLabel
        )
        return prettyJson.encodeToString(report)
    }

    /**
     * Scrubs user-specific path tokens or query parameters from custom DoH endpoints while
     * preserving preset names so private account identifiers never leak into diagnostic exports.
     */
    fun scrubResolverEndpoint(config: DnsResolverConfig): String {
        if (config.preset != DnsProviderPreset.CUSTOM) {
            return when (config.protocol) {
                DnsProtocol.DOH -> config.preset.dohUrl
                DnsProtocol.DOT -> config.preset.dotHostname
                DnsProtocol.UDP_TCP -> config.preset.primaryIpv4
            }
        }
        return when (config.protocol) {
            DnsProtocol.DOH -> {
                val uri = runCatching { URI(config.activeDohUrl) }.getOrNull()
                if (uri?.host != null) {
                    "${uri.scheme ?: "https"}://${uri.host}/<redacted-custom-path>"
                } else {
                    "<custom-doh-endpoint>"
                }
            }
            DnsProtocol.DOT -> config.activeDotHost.ifBlank { "<custom-dot-host>" }
            DnsProtocol.UDP_TCP -> "<custom-ipv4-resolver>"
        }
    }
}
