package com.adshield.pro.engine.security

/** Bounded, process-local declared-permission comparisons. Not grant/behavior monitoring. */
internal class PermissionObservationHistory(private val capacity: Int = 512) {
    private data class Snapshot(val installedAt: Long, val requested: Set<String>, val bindings: Set<String>)
    private val previous = LinkedHashMap<String, Snapshot>(16, 0.75f, true)

    init { require(capacity in 1..512) }

    @Synchronized
    fun observe(profiles: List<AppRiskAuditor.AppSecurityProfile>): Int {
        var changed = 0
        profiles.forEach { profile ->
            val current = Snapshot(profile.firstInstallTimeEpochMs,
                profile.requestedPermissions.toSet(), profile.declaredComponentPermissions.toSet())
            val before = previous[profile.packageName]
            // An unseen/reinstalled/evicted app establishes a baseline, not a made-up change.
            if (before != null && before.installedAt == current.installedAt && before != current) changed++
            previous[profile.packageName] = current
            while (previous.size > capacity) previous.remove(previous.keys.first())
        }
        return changed
    }
}
