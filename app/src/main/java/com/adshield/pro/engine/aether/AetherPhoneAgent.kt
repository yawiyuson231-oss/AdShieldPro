package com.adshield.pro.engine.aether

import com.adshield.pro.domain.model.DnsActivityRecord
import com.adshield.pro.domain.model.DnsProtocol
import com.adshield.pro.domain.model.DnsProviderPreset
import com.adshield.pro.domain.model.ProtectionMode
import com.adshield.pro.domain.model.RuleCategory
import com.adshield.pro.domain.model.VpnStatus

/** Read-only, on-device phone triage. Findings are rules over measured or configured inputs. */
object AetherPhoneAgent {
    enum class Tool(val label: String) {
        PROTECTION("Open protection"),
        DNS_SETTINGS("Open DNS settings"),
        DNS_BENCHMARK("Run DNS benchmark"),
        NETWORK_SETTINGS("Open Android network settings"),
        OPTIMIZER("Open Smart Boost"),
        BATTERY("Check battery and heat"),
        APP_FIREWALL("Review app DNS rules"),
        BROWSER("Open browser controls"),
        DNS_ACTIVITY("View DNS activity"),
        ENABLE_ALIAS_SHIELD("Turn on DNS Alias Shield"),
        FILE_SCAN("Scan a file"),
        LINK_SCAN("Check a link"),
        APP_AUDIT("Review installed apps"),
        SCAN_HISTORY("Review past scans")
    }

    enum class Priority(val label: String) { ATTENTION("Needs attention"), REVIEW("Worth reviewing"), INFO("Observed") }
    enum class Transport(val label: String) {
        WIFI("Wi-Fi"), CELLULAR("Mobile data"), ETHERNET("Ethernet"), VPN("VPN; underlying network not reported"),
        OTHER("Other Android network"), NONE("No Android default network"), UNKNOWN("Not reported")
    }
    enum class WifiSecurity(val label: String) {
        OPEN("Open"), WEP("WEP"), WPA_PERSONAL("WPA/WPA2 Personal"), WPA_ENTERPRISE("Enterprise"),
        WPA3_PERSONAL("WPA3 Personal"), ENHANCED_OPEN("Enhanced Open")
    }
    enum class Thermal(val label: String) {
        NORMAL("No thermal pressure reported"), ELEVATED("Elevated thermal status"), SEVERE("Severe thermal status or higher")
    }

    data class Settings(
        val vpnRequested: Boolean,
        val protocol: DnsProtocol,
        val resolver: DnsProviderPreset,
        val mode: ProtectionMode,
        val allowlistOnly: Boolean,
        val aliasShieldOn: Boolean,
        val dnsLoggingOn: Boolean,
        val excludedApps: Int,
        val allowDnsOverrides: Int,
        val unfilteredNetworks: Int,
        val blocksThirdPartyCookies: Boolean,
        val automaticFilterUpdates: Boolean,
        val scheduledScans: Boolean
    )
    data class Protection(val status: VpnStatus, val rulesLoaded: Int, val observedQueries: Long, val blockedQueries: Long)
    data class Network(
        val transport: Transport,
        val internetValidated: Boolean? = null,
        val captivePortal: Boolean = false,
        val wifiSecurity: WifiSecurity? = null,
        val signalDbm: Int? = null
    )
    data class Device(val lowMemory: Boolean?, val freeStorageBytes: Long?, val thermal: Thermal?)
    data class ScanHistory(val retained: Int, val flaggedTargets: Int, val flaggedAppAudits: Int)
    data class Snapshot(
        val settings: Settings,
        val protection: Protection,
        val network: Network,
        val device: Device,
        val dnsRecords: List<DnsActivityRecord>?,
        val scanHistory: ScanHistory?,
        val capturedAtMs: Long
    )

    data class Finding(val title: String, val priority: Priority, val evidence: String, val nextTool: Tool)
    data class Section(val title: String, val readings: List<String>)
    data class Report(
        val capturedAtMs: Long,
        val findings: List<Finding>,
        val sections: List<Section>,
        val hasUnavailableReadings: Boolean = false
    )

    private const val HOUR_MS = 3_600_000L
    private const val DNS_SAMPLE_LIMIT = 250
    private const val MIN_TIMED_QUERIES = 5
    private const val SLOW_DNS_P95_MS = 400
    private const val WEAK_WIFI_DBM = -80
    private const val GIB = 1_073_741_824L

    fun review(snapshot: Snapshot): Report {
        val (settings, protection, network, device, records, history, now) = snapshot
        // An opt-out also hides any previously saved detailed rows. Keep only a recent, bounded sample.
        val recent = if (settings.dnsLoggingOn) records?.asSequence()?.take(DNS_SAMPLE_LIMIT)
            ?.filter { it.timestampEpochMs in (now - HOUR_MS).coerceAtLeast(1L)..now }?.toList() else null
        val failures = recent.orEmpty().count(::isResolverFailure)
        val timed = recent.orEmpty().filter { !it.isBlocked && !isResolverFailure(it) && it.latencyMs > 0 }
            .map { it.latencyMs }.sorted()
        val p95 = timed.takeIf { it.size >= MIN_TIMED_QUERIES }?.let { it[(it.size * 95 + 99) / 100 - 1] }
        val wifiDbm = network.signalDbm?.takeIf { network.transport == Transport.WIFI && it in -110..-1 }
        val wifiSecurity = network.wifiSecurity?.takeIf { network.transport == Transport.WIFI }
        val freeStorage = device.freeStorageBytes?.takeIf { it >= 0 }
        val freeStorageLabel = freeStorage?.let { "${it / (GIB / 1024)} MiB available" } ?: "Not reported"
        val bypasses = settings.excludedApps > 0 || settings.allowDnsOverrides > 0 || settings.unfilteredNetworks > 0
        val coverage = "${settings.excludedApps} app exclusions · ${settings.allowDnsOverrides} Allow DNS overrides · ${settings.unfilteredNetworks} unfiltered network types"

        val findings = buildList {
            fun flag(title: String, priority: Priority, evidence: String, tool: Tool) = add(Finding(title, priority, evidence, tool))

            when (protection.status) {
                VpnStatus.ERROR -> flag("DNS protection reported an error", Priority.ATTENTION, "The AdShield tunnel state is Error. Check protection before relying on filtering.", Tool.PROTECTION)
                VpnStatus.PAUSED -> flag("DNS filtering is paused", Priority.ATTENTION, "AdShield reports that DNS filtering is paused. Resume it when ready.", Tool.PROTECTION)
                VpnStatus.DISCONNECTED -> flag("DNS protection is off", if (settings.vpnRequested) Priority.ATTENTION else Priority.INFO,
                    "The AdShield tunnel is not connected. DNS requests are not being filtered by it.", Tool.PROTECTION)
                VpnStatus.CONNECTED -> if (protection.rulesLoaded <= 0) {
                    flag("No DNS filter rules loaded", Priority.ATTENTION, "The tunnel reports Connected but reports zero loaded rules.", Tool.PROTECTION)
                }
                VpnStatus.STARTING, VpnStatus.RECONNECTING -> Unit
            }
            if (settings.protocol == DnsProtocol.UDP_TCP) {
                flag("Unencrypted upstream DNS is selected", Priority.REVIEW, "AdShield is configured to use standard DNS. Choose DoH or DoT if you want encryption to the resolver.", Tool.DNS_SETTINGS)
            }
            if (!settings.aliasShieldOn) {
                flag("DNS Alias Shield is off", Priority.REVIEW, "This saved setting disables checks for blocked destinations in CNAME, HTTPS and SVCB replies.", Tool.ENABLE_ALIAS_SHIELD)
            }
            if (settings.allowlistOnly) {
                flag("Allowlist-only DNS is on", Priority.REVIEW,
                    "AdShield's emergency DNS setting can block sites that aren't explicitly allowed. Review this setting if apps stop loading.", Tool.DNS_SETTINGS)
            }
            if (bypasses) flag("Some DNS traffic may bypass filtering", Priority.REVIEW, coverage, Tool.APP_FIREWALL)
            if (!settings.blocksThirdPartyCookies) flag("Third-party cookies are allowed in AdShield's browser", Priority.INFO,
                "This is an in-app browser setting, not the cookie policy for other browsers.", Tool.BROWSER)
            if (network.captivePortal) flag("Network sign-in may be needed", Priority.ATTENTION, "Android reports a captive portal on its default network.", Tool.NETWORK_SETTINGS)
            else if (network.transport == Transport.NONE || network.internetValidated == false) {
                flag("Android has not confirmed internet access", Priority.REVIEW, "There is no validated default connection in this Android reading. Check the connection before blaming DNS.", Tool.NETWORK_SETTINGS)
            }
            if (wifiSecurity == WifiSecurity.OPEN || wifiSecurity == WifiSecurity.WEP) {
                flag("Wi-Fi is open or uses outdated security", Priority.ATTENTION, "Android reported ${wifiSecurity.label}. Prefer a trusted secured network or trusted mobile data.", Tool.NETWORK_SETTINGS)
            }
            if (wifiDbm != null && wifiDbm <= WEAK_WIFI_DBM) {
                flag("Wi-Fi signal is weak", Priority.REVIEW, "Android reported $wifiDbm dBm. Try moving closer to the router, then check again. Signal strength is not a speed test.", Tool.NETWORK_SETTINGS)
            }
            if (failures >= 3 || (p95 != null && p95 >= SLOW_DNS_P95_MS)) {
                val timing = p95?.let { " · $it ms p95 across ${timed.size} timed requests" }.orEmpty()
                flag("Recent DNS requests were slow or failed", Priority.REVIEW,
                    "$failures logged resolver failures$timing in the recent sample. It may include more than one network; compare providers on your current connection.", Tool.DNS_BENCHMARK)
            }
            if (device.lowMemory == true) flag("Android reports low memory", Priority.REVIEW, "Memory pressure can affect responsiveness. Review AdShield's own memory and cache tools; it cannot free memory in other apps by force.", Tool.OPTIMIZER)
            if (freeStorage != null && freeStorage < 2 * GIB) flag("Phone storage is low", Priority.REVIEW, "$freeStorageLabel on the volume AdShield uses. Review storage before deleting anything.", Tool.OPTIMIZER)
            if (device.thermal == Thermal.SEVERE) flag("Android reports severe heat pressure", Priority.ATTENTION, "Android may throttle performance until the phone cools. Pause demanding tasks and review the battery reading.", Tool.BATTERY)
            if (history != null && (history.flaggedTargets > 0 || history.flaggedAppAudits > 0)) {
                flag("Past scan results need review", Priority.REVIEW, "${history.flaggedTargets} flagged file/link records · ${history.flaggedAppAudits} app permission audits with risk indicators. These are recorded results, not proof of a current infection.", Tool.SCAN_HISTORY)
            }
        }.sortedBy { it.priority.ordinal }

        val dnsReadings = when {
            !settings.dnsLoggingOn -> listOf("Detailed DNS logging is off. Saved DNS rows were not used.")
            recent == null -> listOf("Detailed DNS activity was not available.")
            recent.isEmpty() -> listOf("No recent DNS rows in the saved sample. This does not mean there was no traffic.")
            else -> {
                val blocked = recent.count { it.isBlocked }
                val malware = recent.count { it.isBlocked && it.category == RuleCategory.MALWARE }
                val aliases = recent.count { it.isBlocked && it.sourceList.substringBefore(" · ") in aliasSources }
                listOf(
                    "Last hour, up to $DNS_SAMPLE_LIMIT saved lookups: ${recent.size} logged · $blocked blocked · $failures resolver failures",
                    "$malware blocks tagged malware/phishing · $aliases DNS Alias Shield blocks",
                    p95?.let { "DNS timing: $it ms p95 across ${timed.size} recorded requests (not internet speed)" }
                        ?: "Too few timed requests for a DNS latency estimate (${timed.size}/$MIN_TIMED_QUERIES)"
                )
            }
        }
        val unavailable = network.transport in setOf(Transport.UNKNOWN, Transport.VPN) ||
            (network.transport != Transport.NONE && network.internetValidated == null) ||
            (network.transport == Transport.WIFI && (wifiSecurity == null || wifiDbm == null)) ||
            device.lowMemory == null || freeStorage == null || device.thermal == null ||
            (settings.dnsLoggingOn && recent == null) || history == null
        return Report(now, findings, listOf(
            Section("Connection", buildList {
                add("Android default network: ${network.transport.label}")
                add(when (network.internetValidated) {
                    true -> "Android validated internet access"
                    false -> "Internet access not validated by Android"
                    null -> "Internet validation not available"
                })
                if (network.transport == Transport.WIFI) {
                    add("Wi-Fi security: ${wifiSecurity?.label ?: "Not reported by Android"}")
                    add("Wi-Fi signal: ${wifiDbm?.let { "$it dBm" } ?: "Not reported by Android"}")
                }
            }),
            Section("AdShield settings checked", listOf(
                "Tunnel: ${protection.status.name.lowercase().replaceFirstChar { it.uppercase() }} · ${protection.rulesLoaded} rules reported",
                "Configured upstream: ${settings.resolver.displayName} · ${settings.protocol.label}",
                "Protection mode: ${settings.mode.title} · Allowlist-only DNS: ${onOff(settings.allowlistOnly)}",
                "DNS Alias Shield: ${onOff(settings.aliasShieldOn)} · Detailed DNS logs: ${onOff(settings.dnsLoggingOn)}",
                coverage,
                "AdShield browser third-party cookie blocking: ${onOff(settings.blocksThirdPartyCookies)}",
                "Automatic filter updates: ${onOff(settings.automaticFilterUpdates)} · Scheduled scans: ${onOff(settings.scheduledScans)}"
            )),
            Section("Recorded activity", listOf("AdShield runtime counters: ${protection.observedQueries} DNS requests · ${protection.blockedQueries} blocks") + dnsReadings +
                (history?.let { listOf("Retained security records: ${it.retained} · ${it.flaggedTargets} flagged file/link records · ${it.flaggedAppAudits} flagged app audits") }
                    ?: listOf("Scan history not available"))),
            Section("Phone health", listOf(
                "Storage: $freeStorageLabel",
                "Memory: ${when (device.lowMemory) { true -> "Low memory reported"; false -> "No low-memory warning"; null -> "Not reported" }}",
                "Heat: ${device.thermal?.label ?: "Not reported"}"
            ))
        ), hasUnavailableReadings = unavailable)
    }

    private val aliasSources = setOf("CNAME Uncloaking", "HTTPS Uncloaking", "SVCB Uncloaking")
    private fun isResolverFailure(record: DnsActivityRecord): Boolean = !record.isBlocked && record.protocolUsed.startsWith("SERVFAIL (")
    private fun onOff(on: Boolean) = if (on) "On" else "Off"
}
