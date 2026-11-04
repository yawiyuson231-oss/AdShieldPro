package com.adshield.pro.engine.security

import com.adshield.pro.domain.model.DnsProtocol
import com.adshield.pro.domain.model.DnsProviderPreset
import com.adshield.pro.domain.model.DnsResolverConfig
import com.adshield.pro.engine.network.IpReputationAnalyzer
import java.net.URI

/** Fail-before-write validation for user-imported configuration backups. */
object ConfigurationBackupPolicy {
    const val MAX_BACKUP_CHARS = 2_000_000
    const val MAX_RULES = 20_000
    const val MAX_EXCEPTIONS = 5_000

    fun validateEnvelope(rawJson: String, ruleCount: Int, exceptionCount: Int) {
        require(rawJson.length <= MAX_BACKUP_CHARS) { "Backup exceeds the 2 MB safety limit" }
        require(ruleCount in 0..MAX_RULES) { "Backup contains too many custom rules" }
        require(exceptionCount in 0..MAX_EXCEPTIONS) { "Backup contains too many exceptions" }
    }

    /** Validate only fields that can redirect future DNS traffic to an imported endpoint. */
    fun validateResolver(config: DnsResolverConfig): DnsResolverConfig {
        if (config.preset != DnsProviderPreset.CUSTOM) return config
        return when (config.protocol) {
            DnsProtocol.DOH -> {
                val uri = runCatching { URI(config.customDohUrl.trim()) }.getOrElse {
                    throw IllegalArgumentException("Custom DoH URL is invalid")
                }
                require(uri.scheme.equals("https", true) && !uri.host.isNullOrBlank()) {
                    "Custom DoH must be a valid HTTPS URL"
                }
                require(uri.userInfo == null && uri.fragment == null) {
                    "Custom DoH URL must not contain credentials or fragments"
                }
                config
            }
            DnsProtocol.DOT -> {
                val host = config.customDotHost.trim().removeSuffix(".")
                require(host.length <= 253 && Regex("(?i)^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$").matches(host)) {
                    "Custom DoT hostname is invalid"
                }
                config.copy(customDotHost = host)
            }
            DnsProtocol.UDP_TCP -> {
                require(isIpLiteral(config.customPrimaryIpv4)) { "Primary custom DNS IP is invalid" }
                require(isIpLiteral(config.customSecondaryIpv4)) { "Secondary custom DNS IP is invalid" }
                config
            }
        }
    }

    private fun isIpLiteral(value: String): Boolean =
        IpReputationAnalyzer.assessLiteral(value).reputation != IpReputationAnalyzer.Reputation.INVALID
}
