package com.adshield.pro.globalvpn

import com.adshield.pro.globalvpn.provider.VpnGateCsvParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

class VpnGateCsvParserTest {

    private fun csvRow(ip: String, country: String, code: String, ping: String, config: String): String {
        val b64 = Base64.getEncoder().encodeToString(config.toByteArray())
        return listOf(
            "vpn-$ip", ip, "1500000", ping, "250000000", country, code,
            "12", "86400", "1000", "5000", "2weeks", "operator", "message", b64
        ).joinToString(",")
    }

    @Test
    fun parsesRealRowsAndSkipsComments() {
        val config = "client\nremote 203.0.113.7 1443\nproto tcp\n"
        val csv = buildString {
            appendLine("*vpn_servers")
            appendLine("#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVPNSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64")
            appendLine(csvRow("203.0.113.7", "Japan", "JP", "15", config))
            appendLine("*")
        }
        val entries = VpnGateCsvParser.parse(csv)
        assertEquals(1, entries.size)
        val entry = entries.first()
        assertEquals("JP", entry.countryShort)
        assertEquals("Japan", entry.countryLong)
        assertEquals(15, entry.pingMs)
        assertEquals(1443, entry.port)
        assertTrue(entry.openVpnConfig.contains("remote 203.0.113.7"))
        assertEquals("vpngate-203.0.113.7-1443", entry.id)
    }

    @Test
    fun skipsRowsWithoutConfig() {
        val csv = "#header\nvpn-x,198.51.100.1,1,1,1,Nowhere,NW,0,0,0,0,none,op,msg,\n"
        assertTrue(VpnGateCsvParser.parse(csv).isEmpty())
    }

    @Test
    fun handlesMissingPing() {
        val config = "client\nremote 198.51.100.9 443\n"
        val csv = csvRow("198.51.100.9", "United States", "US", "-", config)
        val entries = VpnGateCsvParser.parse(csv)
        assertEquals(1, entries.size)
        assertEquals(null, entries.first().pingMs)
    }
}
