package com.adshield.pro.engine.dns

/**
 * CNAME-cloaking enforcement.
 *
 * A first-party-looking host can resolve through a tracking vendor's endpoint:
 *
 * ```
 * metrics.shop.example.  CNAME  shop-account.tracker.example.
 * shop-account.tracker.example.  A  203.0.113.10
 * ```
 *
 * The filter engine judges the name that was queried, so that lookup is allowed even though the
 * connection lands on a blocked tracker. This guard inspects the CNAME chain of an
 * otherwise-allowed answer and reports the first hop the filter already blocks, letting the caller
 * answer the original query locally instead.
 *
 * Honest limits:
 * - It is enforcement by consequence: a legitimate first-party host that genuinely depends on a
 *   blocked third party will stop resolving too. Callers must only run it in protection modes that
 *   accept that compatibility risk.
 * - Nothing is decided from unparseable wire data: [DnsPacketCodec.extractCnameTargets] returns
 *   null and this guard reports no target.
 * - Only CNAME is followed. HTTPS/SVCB hints are not chains, and DNSSEC validation stays upstream.
 */
object DnsCnameGuard {

    /** Maximum chain hops inspected per answer; longer chains are truncated, not trusted blindly. */
    const val MAX_CHAIN_HOPS = 8

    /**
     * Returns the first CNAME target of [responseBytes] that [isBlocked] reports as blocked,
     * or null when the answer has no blocked hop or cannot be parsed.
     */
    fun firstBlockedTarget(
        responseBytes: ByteArray,
        maxTargets: Int = MAX_CHAIN_HOPS,
        isBlocked: (String) -> Boolean
    ): String? {
        val targets = DnsPacketCodec.extractCnameTargets(responseBytes, maxTargets) ?: return null
        return targets.firstOrNull { target -> target.isNotBlank() && isBlocked(target) }
    }
}
