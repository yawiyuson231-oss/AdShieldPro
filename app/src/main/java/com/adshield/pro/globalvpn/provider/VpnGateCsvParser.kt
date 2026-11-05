package com.adshield.pro.globalvpn.provider

import java.util.Base64

/**
 * Pure parser for the official VPN Gate public CSV API (https://www.vpngate.net/api/iphone/).
 * Only real rows are returned; the embedded OpenVPN configuration is decoded from Base64 exactly as
 * published. No server is synthesized.
 */
object VpnGateCsvParser {

    data class VpnGateEntry(
        val hostName: String,
        val ip: String,
        val countryShort: String,
        val countryLong: String,
        val pingMs: Int?,
        val speedMbps: Double?,
        val sessions: Int?,
        val port: Int,
        val openVpnConfig: String
    ) {
        val id: String get() = "vpngate-$ip-$port"
    }

    private val remoteRegex = Regex("""remote\s+(\S+)\s+(\d+)""")

    fun parse(csv: String): List<VpnGateEntry> {
        val entries = mutableListOf<VpnGateEntry>()
        for (raw in csv.lineSequence()) {
            val line = raw.trim()
            if (line.isEmpty() || line.startsWith("*") || line.startsWith("#")) continue
            val fields = line.split(",", limit = 15)
            if (fields.size < 15) continue
            val config = decodeBase64(fields[14]) ?: continue
            if (!config.contains("remote")) continue
            val port = remoteRegex.find(config)?.groupValues?.get(2)?.toIntOrNull() ?: 443
            entries.add(
                VpnGateEntry(
                    hostName = fields[0],
                    ip = fields[1],
                    countryShort = fields[6].ifBlank { "UN" },
                    countryLong = fields[5].ifBlank { "Unknown" },
                    pingMs = fields[3].trim().toIntOrNull(),
                    speedMbps = fields[4].trim().toDoubleOrNull()?.let { it / 1_000_000.0 },
                    sessions = fields[7].trim().toIntOrNull(),
                    port = port,
                    openVpnConfig = config
                )
            )
        }
        return entries
    }

    private fun decodeBase64(value: String): String? =
        runCatching {
            val cleaned = value.trim()
            if (cleaned.isEmpty()) return null
            String(Base64.getDecoder().decode(cleaned), Charsets.UTF_8)
        }.getOrNull()
}
