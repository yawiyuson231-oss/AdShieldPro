package com.adshield.pro.engine.intelligence

import com.adshield.pro.data.local.preferences.AppSettingsState

/** Names changed saved controls without logging resolver endpoints, packages or policy values. */
internal object SecurityConfigurationChanges {
    fun changedControls(before: AppSettingsState, after: AppSettingsState): List<String> = buildList {
        if (before.resolverConfig != after.resolverConfig) add("resolver configuration")
        if (before.cnameUncloakingEnabled != after.cnameUncloakingEnabled) add("alias inspection")
        if (before.protectionMode != after.protectionMode) add("filtering mode")
        if (before.excludedAppPackages != after.excludedAppPackages) add("application exclusions")
        if (before.dnsFirewallPolicy.appPolicies != after.dnsFirewallPolicy.appPolicies) add("application DNS policy")
        if (before.dnsFirewallPolicy.protectedTransports != after.dnsFirewallPolicy.protectedTransports) add("network filtering scope")
        if (before.detailedDnsLoggingEnabled != after.detailedDnsLoggingEnabled) add("DNS history collection")
    }
}
