package com.adshield.pro.ui.model

import com.adshield.pro.engine.platform.Capability
import com.adshield.pro.engine.platform.CapabilityStatus

/** Pure catalogue filtering: status is a build classification, not a live health check. */
object CapabilityStatusFilter {
    fun filter(capabilities: List<Capability>, query: String, status: CapabilityStatus?): List<Capability> {
        val term = query.trim()
        return capabilities.filter { capability ->
            (status == null || capability.status == status) &&
                (term.isEmpty() || capability.name.contains(term, ignoreCase = true) ||
                    capability.area.label.contains(term, ignoreCase = true) ||
                    capability.limitations.any { it.contains(term, ignoreCase = true) })
        }
    }
}
