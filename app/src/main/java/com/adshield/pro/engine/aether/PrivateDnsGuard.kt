package com.adshield.pro.engine.aether

/**
 * OmniShield X — Private DNS bypass guard.
 *
 * Android's "Private DNS" (Settings → Network → Private DNS, strict hostname mode)
 * makes the SYSTEM resolver send DNS over DoT directly to the configured provider,
 * IGNORING the DNS servers a local VPN advertises. The traffic is TLS on port 853
 * to an internet IP, so a DNS-only tunnel never sees it — with strict Private DNS
 * on, the firewall receives zero queries and appears "not working".
 *
 * This guard parses the real system state so the UI can tell the user exactly
 * what is happening and how to fix it (no guessing, no lying).
 */
object PrivateDnsGuard {

    enum class Mode { OFF, AUTO_OPPORTUNISTIC, STRICT_BYPASS, UNKNOWN }

    data class Assessment(
        val mode: Mode,
        val providerHostname: String?,
        val bypassesLocalVpn: Boolean,
        val userGuidance: String?
    )

    /** Pure mapping of the raw Settings.Global values. */
    fun parse(mode: String?, providerHostname: String?): Assessment = when {
        mode == "hostname" && !providerHostname.isNullOrBlank() -> Assessment(
            mode = Mode.STRICT_BYPASS,
            providerHostname = providerHostname,
            bypassesLocalVpn = true,
            userGuidance = "Android Private DNS ($providerHostname) is sending all DNS straight out " +
                "as encrypted traffic — OmniShield never sees it, so ads are NOT blocked. " +
                "Fix: Settings → Network & internet → Private DNS → set to Automatic or Off."
        )
        mode == "hostname" -> Assessment(
            mode = Mode.STRICT_BYPASS,
            providerHostname = null,
            bypassesLocalVpn = true,
            userGuidance = "Android Private DNS is set to a strict hostname — it bypasses OmniShield. " +
                "Set Private DNS to Automatic or Off."
        )
        mode == "opportunistic" -> Assessment(
            mode = Mode.AUTO_OPPORTUNISTIC,
            providerHostname = providerHostname,
            bypassesLocalVpn = false,
            userGuidance = null
        )
        mode == "off" || mode == null -> Assessment(
            mode = Mode.OFF,
            providerHostname = null,
            bypassesLocalVpn = false,
            userGuidance = null
        )
        else -> Assessment(Mode.UNKNOWN, providerHostname, bypassesLocalVpn = false, userGuidance = null)
    }
}
