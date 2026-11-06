package com.adshield.pro.engine.intelligence

import com.adshield.pro.domain.intelligence.IntelligenceModule
import com.adshield.pro.domain.intelligence.IntelligenceModuleState
import com.adshield.pro.domain.intelligence.ModuleSnapshot

/**
 * Recommended actions shown in a node's detail panel.
 *
 * Every line maps to something the user can really do in this app (or a real safety instruction
 * such as "do not open the link"). Nothing here claims the app can clean, block or repair
 * something it cannot.
 */
object IntelligenceRecommendations {

    fun forSnapshot(snapshot: ModuleSnapshot): List<String> {
        val recommendations = mutableListOf<String>()
        when (snapshot.module) {
            IntelligenceModule.NETWORK_DEFENSE -> when (snapshot.state) {
                IntelligenceModuleState.CRITICAL -> {
                    recommendations += "Reconnect the local DNS firewall from this panel"
                    recommendations += "If it keeps failing, open Settings and re-run resolver diagnostics"
                }
                IntelligenceModuleState.WARNING -> {
                    recommendations += "Resume filtering or sync the enabled filter lists"
                    recommendations += "Open Live to inspect the real DNS event feed"
                }
                IntelligenceModuleState.DISABLED, IntelligenceModuleState.OFFLINE -> {
                    recommendations += "Turn protection on to restore DNS filtering"
                }
                else -> recommendations += "No action required — filtering is active"
            }
            IntelligenceModule.DEVICE_INTELLIGENCE -> when (snapshot.state) {
                IntelligenceModuleState.CRITICAL, IntelligenceModuleState.WARNING -> {
                    recommendations += "Reduce load and, if charging, unplug until the battery cools"
                    recommendations += "Run the battery diagnosis to re-measure temperature and health"
                }
                IntelligenceModuleState.OFFLINE -> {
                    recommendations += "This device does not expose the sensor; measured values stay unavailable"
                }
                else -> recommendations += "No action required — readings are within the configured threshold"
            }
            IntelligenceModule.CYBER_DEFENSE -> when (snapshot.state) {
                IntelligenceModuleState.CRITICAL, IntelligenceModuleState.WARNING -> {
                    recommendations += "Open Security to review the scan finding and its evidence"
                    recommendations += "Quarantine the scanned file only if you trust the report"
                }
                else -> recommendations += "No action required — the last scan recorded no fresh finding"
            }
            IntelligenceModule.FINANCIAL_DEFENSE -> when (snapshot.state) {
                IntelligenceModuleState.CRITICAL, IntelligenceModuleState.WARNING -> {
                    recommendations += "Do not open the link; navigate to the service through its official app"
                    recommendations += "Verify any payment request with the provider directly"
                }
                else -> recommendations += "No action required — no risky payment link is on record"
            }
            IntelligenceModule.PRIVACY_DEFENSE -> when (snapshot.state) {
                IntelligenceModuleState.WARNING, IntelligenceModuleState.CRITICAL -> {
                    recommendations += "Open Security → Apps and review the flagged permissions"
                    recommendations += "Re-run the installed-app audit after revoking access"
                }
                IntelligenceModuleState.DISABLED -> {
                    recommendations += "Turn the browser privacy shields back on in Ad Blocker"
                }
                else -> recommendations += "No action required — no fresh exposure was found"
            }
            IntelligenceModule.EMERGENCY_INTELLIGENCE -> when {
                snapshot.state == IntelligenceModuleState.CRITICAL ->
                    recommendations += "Restore the DNS tunnel before relying on lockdown"
                snapshot.state == IntelligenceModuleState.WARNING &&
                    snapshot.stateDetail.contains("lockdown", ignoreCase = true) ->
                    recommendations += "Release lockdown when the emergency is over"
                snapshot.state == IntelligenceModuleState.WARNING ->
                    recommendations += "Start protection so lockdown would actually filter DNS"
                else -> recommendations += "Readiness checks pass — no action required"
            }
            IntelligenceModule.AUTOMATION_CORE -> when (snapshot.state) {
                IntelligenceModuleState.WARNING, IntelligenceModuleState.CRITICAL -> {
                    recommendations += "Open Optimizer to inspect the failing scheduled job"
                    recommendations += "Sync filter lists manually while the schedule recovers"
                }
                IntelligenceModuleState.DISABLED ->
                    recommendations += "Enable at least one automation to keep protection current"
                else -> recommendations += "No action required — scheduled jobs are running"
            }
            IntelligenceModule.CORE -> {
                recommendations += if (snapshot.state.isProblem) {
                    "Open the module with the highest severity to inspect its evidence"
                } else {
                    "No action required — every module is reporting"
                }
            }
        }
        return recommendations.distinct()
    }
}
