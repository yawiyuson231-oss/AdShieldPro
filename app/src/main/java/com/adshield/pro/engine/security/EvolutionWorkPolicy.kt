package com.adshield.pro.engine.security

/** Pure pacing policy for optional audits, never DNS routing/filtering or a protection switch. */
internal object EvolutionWorkPolicy {
    data class Conditions(
        val lowMemory: Boolean? = null,
        val availableRamBytes: Long? = null,
        val batteryPercent: Int? = null,
        val severeThermal: Boolean? = null,
        /** Fraction of available CPU time used by this process, not system-wide CPU load. */
        val appCpuFraction: Double? = null,
        val freeStorageBytes: Long? = null,
        val networkValidated: Boolean? = null,
        val networkMetered: Boolean? = null
    )

    data class Plan(val batchSize: Int, val yieldMillis: Long, val cacheEntries: Int,
                    val optionalResearchSyncAllowed: Boolean) {
        // Invariant, not a configurable constructor parameter.
        val essentialProtectionEnabled: Boolean get() = true
    }

    fun plan(conditions: Conditions): Plan {
        val memoryConstrained = conditions.lowMemory != false ||
            conditions.availableRamBytes?.let { it < 128L * 1024 * 1024 } != false
        val storageConstrained = conditions.freeStorageBytes?.let { it < 128L * 1024 * 1024 } != false
        val lowBattery = conditions.batteryPercent?.takeIf { it in 0..100 }?.let { it <= 15 } ?: true
        val cpuBusy = conditions.appCpuFraction?.takeIf { it.isFinite() && it in 0.0..1.0 }
            ?.let { it >= 0.8 } ?: true
        val hot = conditions.severeThermal != false
        val constrained = memoryConstrained || lowBattery || cpuBusy || hot
        return Plan(
            batchSize = if (constrained) 4 else 16,
            yieldMillis = when { hot -> 50L; lowBattery -> 25L; cpuBusy -> 10L; else -> 0L },
            cacheEntries = when { memoryConstrained || storageConstrained -> 0; constrained -> 16; else -> 128 },
            optionalResearchSyncAllowed = !constrained && !storageConstrained &&
                conditions.networkValidated == true && conditions.networkMetered == false
        )
    }
}

/** Memory-only memoization. Callers must use the entire current detector input as the key. */
internal class BoundedAuditCache<K, V> {
    private val entries = LinkedHashMap<K, V>(16, 0.75f, true)

    @Synchronized
    fun getOrCompute(key: K, capacity: Int, compute: () -> V): V {
        require(capacity in 0..128)
        while (entries.size > capacity) entries.remove(entries.keys.first())
        if (capacity == 0) return compute()
        entries[key]?.let { return it }
        val result = compute() // Failed/cancelled computations are never cached.
        entries[key] = result
        while (entries.size > capacity) entries.remove(entries.keys.first())
        return result
    }
}
