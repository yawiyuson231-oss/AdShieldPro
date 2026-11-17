package com.adshield.pro.engine.dns

import com.adshield.pro.domain.model.DnsProtocol
import com.adshield.pro.domain.model.DnsProviderPreset
import com.adshield.pro.domain.model.DnsResolverConfig
import com.adshield.pro.domain.model.DnssecMode
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withTimeout

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
        // Validate domain syntax up front using the same EDNS0+DO factory as DNS diagnostics.
        DnsDiagnosticQueryFactory.build(cleanDomain)

        // Probe in REPORT_ONLY DNSSEC mode so unsigned responses still report status honestly
        // instead of failing providers that do not set the AD bit on a given name.
        val probeConfig = config.copy(dnssecMode = DnssecMode.REPORT_ONLY)
        val presets = candidatePresets(config)

        val rawEntries = coroutineScope {
            presets.map { preset ->
                async {
                    val endpoint = DnsProviderRegistry.endpoint(preset, probeConfig)
                    val wire = DnsDiagnosticQueryFactory.build(cleanDomain)
                    val query = DnsPacketCodec.parseQuery(wire)
                        ?: return@async DnsBenchmarkEntry(
                            preset = preset,
                            providerName = preset.displayName,
                            reachable = false,
                            latencyMs = null,
                            responseCode = null,
                            answerCount = null,
                            dnssecStatus = null,
                            forwardsClientSubnet = preset.forwardsClientSubnet,
                            isCurrentlySelected = preset == config.preset,
                            errorMessage = "Invalid probe query"
                        )
                    try {
                        val result = withTimeout(PER_PROVIDER_TIMEOUT_MS) {
                            resolver.probeEndpoint(query, probeConfig, endpoint)
                        }
                        val inspection = runCatching {
                            DnsResponseValidator.validate(wire, result.responseBytes, DnssecMode.REPORT_ONLY)
                        }.getOrNull()
                        val ok = inspection != null && (inspection.responseCode == 0 || inspection.responseCode == 3)
                        DnsBenchmarkEntry(
                            preset = preset,
                            providerName = preset.displayName,
                            reachable = ok,
                            latencyMs = if (ok) result.latencyMs else null,
                            responseCode = inspection?.responseCode,
                            answerCount = inspection?.answerCount,
                            dnssecStatus = result.dnssecStatus ?: inspection?.dnssecStatus,
                            forwardsClientSubnet = preset.forwardsClientSubnet,
                            isCurrentlySelected = preset == config.preset,
                            errorMessage = if (ok) null else "RCODE ${inspection?.responseCode ?: "invalid"}"
                        )
                    } catch (_: kotlinx.coroutines.TimeoutCancellationException) {
                        DnsBenchmarkEntry(
                            preset = preset,
                            providerName = preset.displayName,
                            reachable = false,
                            latencyMs = null,
                            responseCode = null,
                            answerCount = null,
                            dnssecStatus = null,
                            forwardsClientSubnet = preset.forwardsClientSubnet,
                            isCurrentlySelected = preset == config.preset,
                            errorMessage = "Timed out"
                        )
                    } catch (c: CancellationException) {
                        throw c
                    } catch (t: Throwable) {
                        DnsBenchmarkEntry(
                            preset = preset,
                            providerName = preset.displayName,
                            reachable = false,
                            latencyMs = null,
                            responseCode = null,
                            answerCount = null,
                            dnssecStatus = null,
                            forwardsClientSubnet = preset.forwardsClientSubnet,
                            isCurrentlySelected = preset == config.preset,
                            errorMessage = (t.message ?: t.javaClass.simpleName).take(80)
                        )
                    }
                }
            }.awaitAll()
        }

        return DnsBenchmarkReport(
            probeDomain = cleanDomain.trimEnd('.').lowercase(),
            protocol = config.protocol,
            testedAtEpochMs = nowEpochMs,
            entries = rankEntries(rawEntries)
        )
    }
}
