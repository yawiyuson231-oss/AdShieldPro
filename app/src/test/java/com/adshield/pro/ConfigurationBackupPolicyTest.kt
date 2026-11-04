package com.adshield.pro

import com.adshield.pro.domain.model.DnsProtocol
import com.adshield.pro.domain.model.DnsProviderPreset
import com.adshield.pro.domain.model.DnsResolverConfig
import com.adshield.pro.engine.security.ConfigurationBackupPolicy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class ConfigurationBackupPolicyTest {
    @Test
    fun backupEnvelope_rejectsOversizedPayloadBeforeWrites() {
        assertThrows(IllegalArgumentException::class.java) {
            ConfigurationBackupPolicy.validateEnvelope("x".repeat(2_000_001), 0, 0)
        }
        assertThrows(IllegalArgumentException::class.java) {
            ConfigurationBackupPolicy.validateEnvelope("{}", 20_001, 0)
        }
        ConfigurationBackupPolicy.validateEnvelope("{}", 100, 20)
    }

    @Test
    fun customDoh_requiresHttpsWithoutEmbeddedCredentials() {
        val valid = DnsResolverConfig(
            preset = DnsProviderPreset.CUSTOM,
            protocol = DnsProtocol.DOH,
            customDohUrl = "https://dns.example.com/dns-query"
        )
        assertEquals(valid, ConfigurationBackupPolicy.validateResolver(valid))
        assertThrows(IllegalArgumentException::class.java) {
            ConfigurationBackupPolicy.validateResolver(valid.copy(customDohUrl = "http://dns.example.com/dns-query"))
        }
        assertThrows(IllegalArgumentException::class.java) {
            ConfigurationBackupPolicy.validateResolver(valid.copy(customDohUrl = "https://user:secret@dns.example.com/dns-query"))
        }
    }

    @Test
    fun customDot_rejectsInjectionAndNormalizesTrailingDot() {
        val valid = DnsResolverConfig(
            preset = DnsProviderPreset.CUSTOM,
            protocol = DnsProtocol.DOT,
            customDotHost = "dns.example.com."
        )
        assertEquals("dns.example.com", ConfigurationBackupPolicy.validateResolver(valid).customDotHost)
        assertThrows(IllegalArgumentException::class.java) {
            ConfigurationBackupPolicy.validateResolver(valid.copy(customDotHost = "dns.example.com:853/path"))
        }
    }

    @Test
    fun customPlainDns_acceptsOnlyIpLiteralsNotHostnames() {
        val valid = DnsResolverConfig(
            preset = DnsProviderPreset.CUSTOM,
            protocol = DnsProtocol.UDP_TCP,
            customPrimaryIpv4 = "1.1.1.1",
            customSecondaryIpv4 = "2606:4700:4700::1111"
        )
        assertEquals(valid, ConfigurationBackupPolicy.validateResolver(valid))
        assertThrows(IllegalArgumentException::class.java) {
            ConfigurationBackupPolicy.validateResolver(valid.copy(customPrimaryIpv4 = "attacker.example"))
        }
    }
}
