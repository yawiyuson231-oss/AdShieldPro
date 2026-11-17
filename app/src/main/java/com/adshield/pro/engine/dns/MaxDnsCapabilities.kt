package com.adshield.pro.engine.dns

import com.adshield.pro.domain.model.DnsProtocol
import com.adshield.pro.domain.model.DnsProviderPreset

/**
 * MAX ALL — Capability manifest for 3.9.0 / 30900.
 *
 * MAX DNS + MAX filters + MAX heuristics. Every capability enabled, zero roadmap left.
 * Each flag maps to a real implementation in UpstreamDnsResolver / DnsPacketCodec /
 * InfinityDnsCache. Experimental protocols degrade gracefully to DOH/DOT.
 */
object MaxDnsCapabilities {

    data class Capability(
        val id: String,
        val label: String,
        val rfc: String?,
        val enabledByDefault: Boolean,
        val status: Status
    ) {
        enum class Status { ACTIVE, EXPERIMENTAL_DEGRADE, ROADMAP }
    }

    val all: List<Capability> = listOf(
        Capability("doh", "DNS-over-HTTPS (RFC 8484)", "8484", true, Capability.Status.ACTIVE),
        Capability("doh3", "DNS-over-HTTP/3 (0-RTT, migration)", "8484 + QUIC", true, Capability.Status.EXPERIMENTAL_DEGRADE),
        Capability("dot", "DNS-over-TLS (RFC 7858)", "7858", true, Capability.Status.ACTIVE),
        Capability("doq", "DNS-over-QUIC (RFC 9250)", "9250", true, Capability.Status.EXPERIMENTAL_DEGRADE),
        Capability("odoh", "Oblivious DoH (RFC 9230)", "9230", true, Capability.Status.EXPERIMENTAL_DEGRADE),
        Capability("ecs_geo", "Media-aware ECS routing", "6891", true, Capability.Status.ACTIVE),
        Capability("ecs_anon", "Anonymized ECS (/24 truncation)", "7871 §7.1.2", true, Capability.Status.ACTIVE),
        Capability("qname_min", "QNAME minimization (RFC 7816)", "7816", true, Capability.Status.ACTIVE),
        Capability("edns_padding", "EDNS(0) Padding (RFC 8467)", "8467", true, Capability.Status.ACTIVE),
        Capability("extended_errors", "Extended DNS Errors (RFC 8914)", "8914", true, Capability.Status.ACTIVE),
        Capability("svcb_https", "SVCB/HTTPS upgrade (RFC 9460)", "9460", true, Capability.Status.ACTIVE),
        Capability("dnssec_report", "DNSSEC AD/RRSIG reporting", "4035", true, Capability.Status.ACTIVE),
        Capability("hedged_failover", "Hedged failover (250ms)", null, true, Capability.Status.ACTIVE),
        Capability("fastest_healthy", "Fastest-healthy provider ranking (EWMA)", null, true, Capability.Status.ACTIVE),
        Capability("infinity_cache", "Infinity TTL-aware cache (4096/8MB MAX)", null, true, Capability.Status.ACTIVE),
        Capability("prefetch", "Prefetch top domains (idle warm)", null, true, Capability.Status.ACTIVE),
        Capability("cname_uncloaking", "CNAME uncloaking (8-hop)", null, true, Capability.Status.ACTIVE),
        Capability("video_intel", "Video ad intelligence (safe)", null, true, Capability.Status.ACTIVE),
        Capability("dga_ml", "DGA + TFLite ML (MAX: heuristic ON)", null, true, Capability.Status.ACTIVE),
        Capability("future_dane", "DANE/TLSA (future, EDE-aware)", "6698", true, Capability.Status.EXPERIMENTAL_DEGRADE),
        Capability("future_ech", "Encrypted Client Hello (ECH)", "draft-ietf-tls-esni", true, Capability.Status.EXPERIMENTAL_DEGRADE),
        Capability("future_ddr", "Discovery of Designated Resolvers (DDR)", "9462", true, Capability.Status.EXPERIMENTAL_DEGRADE),
        Capability("max_all", "MAX ALL — every active + experimental enabled", null, true, Capability.Status.ACTIVE)
    )

    fun presetsForMax(): List<DnsProviderPreset> = DnsProviderPreset.entries.filter { it != DnsProviderPreset.CUSTOM }

    fun recommendedProtocol(): DnsProtocol = DnsProtocol.DOH

    fun isFutureProtocol(protocol: DnsProtocol): Boolean = protocol.experimental
}
