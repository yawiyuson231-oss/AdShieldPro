package com.adshield.pro.domain.model

/** In-memory evidence from a successful Android VpnService.Builder.establish(). Not a traffic log. */
@ConsistentCopyVisibility
data class VpnTunnelReceipt internal constructor(
    val generation: Long,
    val establishedAtEpochMs: Long,
    val hasIpv6DnsRoute: Boolean,
    val acceptedExclusions: Set<String>,
    val rejectedExclusions: Set<String>
)

/** Outcomes of building the user exclusion list. They are not applied until establish succeeds. */
internal class VpnExclusionSetup private constructor(
    val accepted: Set<String>,
    val rejected: Set<String>
) {
    companion object {
        fun collect(saved: Set<String>, ownPackage: String, addExclusion: (String) -> Boolean): VpnExclusionSetup {
            val accepted = linkedSetOf<String>()
            val rejected = linkedSetOf<String>()
            for (packageName in saved) {
                // AdShield's own exclusion is infrastructure, not a user exception receipt.
                if (packageName.isBlank() || packageName == ownPackage) continue
                if (addExclusion(packageName)) accepted.add(packageName) else rejected.add(packageName)
            }
            return VpnExclusionSetup(accepted.toSet(), rejected.toSet())
        }
    }
}
