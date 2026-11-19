package com.adshield.pro.engine.dns

import com.adshield.pro.domain.model.DnsProtocol
import com.adshield.pro.domain.model.DnsProviderPreset
import com.adshield.pro.domain.model.DnsResolverConfig
import com.adshield.pro.domain.model.DnssecMode
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withTimeoutOrNull
import java.net.SocketTimeoutException

data class DnsBenchmarkEntry(
    val preset: DnsProviderPreset,
    val providerName: String,
    val reachable: Boolean,
    val latencyMs: Int?,
    val responseCode: Int?,
    val answerCount: Int?,
    val dnssecStatus: DnssecStatus?,
    val forwardsClientSubnet: Boolean,
    val isCurrentlySelected: Boolean,
    val errorMessage: String? = null
)

data class DnsBenchmarkReport(
    val probeDomain: String,
    val protocol: DnsProtocol,
    val testedAtEpochMs: Long,
    val entries: List<DnsBenchmarkEntry>
) {
    val fastestReachable: DnsBenchmarkEntry?
        get() = entries.firstOrNull { it.reachable && it.latencyMs != null }

    val reachableCount: Int
        get() = entries.count { it.reachable }
}

/**
 * Runs genuine, uncached wire-format DNS probes across all built-in upstream presets (plus
 * [DnsProviderPreset.CUSTOM] when currently selected) using the user's selected [DnsProtocol],
 * then deterministically ranks reachable providers from lowest to highest measured round-trip time.
 *
 * No synthetic latencies, no third-party speed-test APIs, and no plaintext fallback when probing
 * DoH or DoT.
 */
object DnsResolverBenchmark {

    const val DEFAULT_PROBE_DOMAIN = "example.com"
    private const val PER_PROVIDER_TIMEOUT_MS = 5_000L

    fun candidatePresets(config: DnsResolverConfig): List<DnsProviderPreset> {
        val presets = DnsProviderPreset.entries.filter { it != DnsProviderPreset.CUSTOM }
        return if (config.preset == DnsProviderPreset.CUSTOM) {
            presets + DnsProviderPreset.CUSTOM
        } else {
            presets
        }
    }

    fun rankEntries(entries: List<DnsBenchmarkEntry>): List<DnsBenchmarkEntry> {
        return entries.sortedWith(
            compareByDescending<DnsBenchmarkEntry> { it.reachable }
                .thenBy { it.latencyMs ?: Int.MAX_VALUE }
                .thenByDescending { it.isCurrentlySelected }
                .thenBy { it.providerName.lowercase() }
        )
    }

    suspend fun run(
        resolver: UpstreamDnsResolver,
        config: DnsResolverConfig,
        domainInput: String = DEFAULT_PROBE_DOMAIN,
        nowEpochMs: Long = System.currentTimeMillis()
    ): DnsBenchmarkReport {
        val cleanDomain = domainInput.trim().ifBlank { DEFAULT_PROBE_DOMAIN }
        val normalizedName = requireNotNull(DnsPacketCodec.parseQuery(DnsDiagnosticQueryFactory.build(cleanDomain))) {
            "Enter a valid DNS name"
        }.questionDomain

        // Normal unsigned answers remain eligible in a reachability test.
        val probeConfig = config.copy(dnssecMode = DnssecMode.REPORT_ONLY)
        val rawEntries = coroutineScope {
            candidatePresets(config).map { preset ->
                async {
                    val endpoint = DnsProviderRegistry.endpoint(preset, probeConfig)
                    val query = requireNotNull(DnsPacketCodec.parseQuery(DnsDiagnosticQueryFactory.build(normalizedName)))
                    val emptyEntry = DnsBenchmarkEntry(preset, preset.displayName, false, null, null, null, null,
                        preset.forwardsClientSubnet, preset == config.preset)
                    try {
                        val result = withTimeoutOrNull(PER_PROVIDER_TIMEOUT_MS) {
                            resolver.probeEndpoint(query, probeConfig, endpoint)
                        } ?: throw SocketTimeoutException("DNS benchmark timed out")
                        val reply = requireNotNull(result.inspection)
                        emptyEntry.copy(reachable = true, latencyMs = result.latencyMs, responseCode = reply.responseCode,
                            answerCount = reply.answerCount, dnssecStatus = reply.dnssecStatus)
                    } catch (cancel: CancellationException) {
                        throw cancel
                    } catch (error: Exception) {
                        val reply = (error as? DnsResponseValidationException)?.inspection
                        val details = reply?.extendedErrorCodes.orEmpty().joinToString("; ", transform = ::dnsExtendedErrorLabel)
                        emptyEntry.copy(responseCode = reply?.responseCode,
                            errorMessage = dnsFailureReason(error) + if (details.isEmpty()) "" else " · $details")
                    }
                }
            }.awaitAll()
        }

        return DnsBenchmarkReport(
            probeDomain = normalizedName,
            protocol = config.protocol,
            testedAtEpochMs = nowEpochMs,
            entries = rankEntries(rawEntries)
        )
    }
}
