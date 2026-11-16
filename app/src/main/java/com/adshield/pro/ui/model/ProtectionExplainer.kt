package com.adshield.pro.ui.model

import com.adshield.pro.domain.model.DnsProtocol
import com.adshield.pro.domain.model.ProtectionArchitecture
import com.adshield.pro.domain.model.ProtectionMode

data class ExplainerPoint(val title: String, val detail: String)

/**
 * Content for the "How protection works" screen.
 *
 * Everything that could be contradicted by the shipped code is derived from the objects the tunnel
 * actually reads at runtime: [ProtectionArchitecture] for routes and ports, [ProtectionMode] for
 * which blocked answers are synthesised, [DnsProtocol] for the upstream transports. The literal
 * prose is limited to facts that are fixed by the design (no remote server, DNS-only routing,
 * Android's VPN rules), not by numbers an engineer might tune.
 */
object ProtectionExplainer {

    const val TITLE = "How protection works"
    const val HEADLINE = "A local DNS filter that Android treats as a VPN"

    const val SUMMARY =
        "AdShield answers DNS lookups on this device. There is no remote VPN server anywhere in " +
            "the app: your IP address, your location and your browsing traffic are untouched."

    /** One line naming exactly what is routed into the tunnel. */
    val ROUTE_SENTENCE: String =
        "Only ${ProtectionArchitecture.routes.joinToString(" and ") { it.cidr }} are routed into " +
            "the tunnel, on port ${ProtectionArchitecture.DNS_PORT}. Every other packet matches " +
            "no route and leaves over your normal Wi-Fi or mobile connection."

    val ROUTES: List<ExplainerPoint> = ProtectionArchitecture.routes.map { route ->
        ExplainerPoint(
            title = "${route.family} ${route.cidr}",
            detail = if (route.family == "IPv6") {
                "Installed only when IPv6 DNS is enabled. A /${route.prefixLength} is a single address, not a network."
            } else {
                "The virtual DNS server Android hands to every app. A /${route.prefixLength} is a single address, not a network."
            }
        )
    }

    /** Why the Android status bar shows a VPN key even though no traffic is tunnelled remotely. */
    val WHY_THE_KEY_ICON: List<ExplainerPoint> = listOf(
        ExplainerPoint(
            title = "There is no other door",
            detail = "Android has no public API that lets one app answer DNS for another app, and " +
                "without root the system hosts file cannot be edited."
        ),
        ExplainerPoint(
            title = "Private DNS is not a filter",
            detail = "Android's Private DNS setting accepts a DoT hostname only. It cannot filter, " +
                "log, or apply per-app rules."
        ),
        ExplainerPoint(
            title = "The VPN permission is the sanctioned way",
            detail = "That one-time permission is the only supported way to receive " +
                "another app's packets. That is why the OS shows the key icon."
        ),
        ExplainerPoint(
            title = "One VPN at a time",
            detail = "Android allows a single active VPN. Starting another VPN app replaces this " +
                "one, and Always-On VPN must point at the app you want protecting you."
        )
    )

    /** What the tunnel carries, in order. */
    val FLOW: List<String> = listOf(
        "An app asks Android to resolve a name",
        "Android's resolver sends that query to the tunnel's virtual DNS address",
        "AdShield checks your rules, protection mode and per-app / per-network policy",
        "Blocked: answered locally, nothing leaves the phone",
        "Allowed: forwarded to your chosen provider over DoH or DoT"
    )

    val CAN_DO: List<ExplainerPoint> = listOf(
        ExplainerPoint(
            title = "Filter every app that uses system DNS",
            detail = "The tunnel is set as the device DNS server, so all of those apps get the same " +
                "on-device decision."
        ),
        ExplainerPoint(
            title = "Answer blocked names locally",
            detail = "A blocked lookup never reaches the network: AdShield synthesises the response " +
                "itself (see the protection modes below)."
        ),
        ExplainerPoint(
            title = "Encrypt the lookups it forwards",
            detail = "Allowed lookups go to your selected provider over DNS-over-HTTPS or " +
                "DNS-over-TLS. Plain UDP/TCP 53 exists as an explicit choice, never as a silent fallback."
        ),
        ExplainerPoint(
            title = "Exclude apps and per-app policies",
            detail = "Excluded apps are removed from the tunnel entirely. Apps can also be set to " +
                "block all DNS or to bypass filtering."
        ),
        ExplainerPoint(
            title = "Pause without tearing down",
            detail = "Paused forwards DNS unfiltered to your provider while the tunnel stays " +
                "established, so resuming is instant."
        ),
        ExplainerPoint(
            title = "Restore after reboot and network switches",
            detail = "Protection is restored on boot when you enabled that, and re-binds when Wi-Fi " +
                "and mobile data hand over."
        )
    )

    val CANNOT_DO: List<ExplainerPoint> = listOf(
        ExplainerPoint(
            title = "Hide your IP address or change your location",
            detail = "There is no exit node to route through, so this is not a geo-unblocking or " +
                "anonymising VPN."
        ),
        ExplainerPoint(
            title = "Read or decrypt HTTPS traffic",
            detail = "Only DNS packets enter the tunnel. Web, video and game traffic is never " +
                "intercepted or inspected."
        ),
        ExplainerPoint(
            title = "Block hardcoded IP addresses",
            detail = "An app connecting to a numeric address performs no lookup, so there is no " +
                "name for the filter to judge."
        ),
        ExplainerPoint(
            title = "Catch apps with their own resolver",
            detail = "Apps using a private DoH or QUIC resolver never ask the system DNS, so they " +
                "bypass the tunnel's filtering."
        ),
        ExplainerPoint(
            title = "Remove first-party streaming ads",
            detail = "YouTube, TikTok and Instagram serve ads from the same hosts as the content; " +
                "blocking those names would break playback."
        ),
        ExplainerPoint(
            title = "Prove your resolver is not leaking",
            detail = "No external DNS leak test is implemented, so the app makes no such claim."
        ),
        ExplainerPoint(
            title = "Hide your source address from the resolver",
            detail = "The EDNS Client Subnet option is removed from every query, but your resolver " +
                "still sees the IP address that sent it."
        )
    )

    /** Blocked-answer behaviour, read from the same enum the DNS codec is driven by. */
    val BLOCK_ANSWERS: List<ExplainerPoint> = ProtectionMode.entries.map { mode ->
        val base = if (mode.blockSinkholeZeroIp) {
            "Blocked A/AAAA lookups answer 0.0.0.0 or ::; other query types answer NXDOMAIN."
        } else {
            "Blocked lookups answer NXDOMAIN, so the app sees the name does not exist."
        }
        val cloaking = if (mode.enforceCnameCloaking) {
            " First-party names that resolve through a blocked tracker are blocked too."
        } else {
            ""
        }
        ExplainerPoint(title = mode.title, detail = base + cloaking)
    }

    /**
     * Why CNAME enforcement is limited to the aggressive modes: refusing a first-party name that
     * merely points at a blocked third party can break a site that genuinely depends on it.
     */
    const val CNAME_NOTE =
        "Strict and Custom modes also block a first-party name that resolves through a blocked " +
            "tracker (CNAME cloaking). Balanced modes leave those lookups alone, so a site that " +
            "genuinely relies on a third party keeps working."

    /** Upstream transports from the protocol enum, so a new protocol cannot go unmentioned. */
    val UPSTREAM_MODES: List<ExplainerPoint> = DnsProtocol.entries.map { protocol ->
        ExplainerPoint(title = protocol.label, detail = protocol.description)
    }

    /**
     * What leaves the tunnel about the user's network position: nothing, unless the user opted
     * into geo-accurate answers for a streaming host.
     */
    const val CLIENT_SUBNET_NOTE =
        "Queries leave the tunnel without the EDNS Client Subnet option, so a CDN cannot use your " +
            "network position to link unrelated lookups. The one exception is a streaming host you opted " +
            "into geo-accurate answers for; there the subnet is kept so the nearest edge is returned."

    const val UPSTREAM_NOTE =
        "If the encrypted upstream fails, AdShield returns SERVFAIL rather than quietly " +
            "downgrading to plaintext. Opt-in failover only moves between providers you selected."
}
