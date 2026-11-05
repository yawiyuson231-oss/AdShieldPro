package com.adshield.pro.cybershield

/**
 * Maps REAL on-device DNS events (persisted by AdShieldVpnService through Room)
 * into normalized threat events and statistics. Nothing here invents events:
 * every output row traces back to one persisted DNS query record.
 */
object ThreatEventMapper {

    const val DAY_MS = 86_400_000L

    fun registrableDomain(domain: String): String {
        val parts = domain.trim().trimEnd('.').lowercase().split('.')
        return if (parts.size >= 2) parts.takeLast(2).joinToString(".") else domain.lowercase()
    }

    fun map(event: DnsEventSnapshot): ThreatEvent {
        val aether = event.sourceList.startsWith("AETHER")
        val confirmed = aether && event.sourceList.contains("confirmed", ignoreCase = true)
        val category = event.category ?: "OTHER"
        val severity: CsSeverity
        val description: String
        if (event.isBlocked) {
            when {
                confirmed && category == "MALWARE" -> {
                    severity = CsSeverity.CRITICAL
                    description = "Confirmed malicious domain blocked by AETHER verified intelligence"
                }
                category == "MALWARE" -> {
                    severity = CsSeverity.HIGH
                    description = "Malware / phishing domain blocked by threat filter list"
                }
                category == "TRACKERS" -> {
                    severity = CsSeverity.MEDIUM
                    description = "Tracking / analytics endpoint blocked"
                }
                category == "CUSTOM" -> {
                    severity = CsSeverity.MEDIUM
                    description = "Domain blocked by a user-defined rule"
                }
                category == "STRICT_TELEMETRY" -> {
                    severity = CsSeverity.LOW
                    description = "Telemetry endpoint blocked (strict filtering)"
                }
                else -> {
                    severity = CsSeverity.LOW
                    description = "Advertising domain blocked"
                }
            }
        } else {
            severity = CsSeverity.INFO
            description = "DNS query allowed"
        }
        val evidence = buildList {
            add("DNS ${event.queryType} query at ${event.timestampEpochMs}")
            event.matchedRule?.let { add("Matched rule: $it") }
            add("Decision source: ${event.sourceList}")
            if (event.protocolUsed.isNotBlank()) add("Response: ${event.protocolUsed}")
            event.appName?.let { add("Requesting app: $it") }
        }
        return ThreatEvent(
            id = "dns-${event.id}",
            timestampEpochMs = event.timestampEpochMs,
            domain = event.domain,
            severity = severity,
            action = if (event.isBlocked) CsEventAction.BLOCKED else CsEventAction.ALLOWED,
            category = category,
            description = description,
            source = CsDataSource.ON_DEVICE,
            sourceDetail = event.sourceList,
            matchedRule = event.matchedRule,
            appName = event.appName,
            appPackageName = event.appPackageName,
            evidence = evidence
        )
    }

    fun mapAll(events: List<DnsEventSnapshot>): List<ThreatEvent> = events.map(::map)

    /** Severity statistics over a real event window. Empty input yields honest zeros. */
    fun summarize(events: List<ThreatEvent>, nowEpochMs: Long, windowMs: Long = DAY_MS): ThreatStats {
        val window = events.filter { nowEpochMs - it.timestampEpochMs <= windowMs }
        val blocked = window.filter { it.action == CsEventAction.BLOCKED }
        val bySeverity = CsSeverity.entries.associateWith { sev ->
            window.count { it.severity == sev }.toLong()
        }
        val activeDomains = blocked
            .filter { it.severity >= CsSeverity.MEDIUM }
            .map { registrableDomain(it.domain) }
            .toSet()
        return ThreatStats(
            windowLabel = if (windowMs == DAY_MS) "Last 24 h" else "Last ${windowMs / 3_600_000} h",
            totalEvents = window.size.toLong(),
            blocked = blocked.size.toLong(),
            allowed = window.count { it.action == CsEventAction.ALLOWED }.toLong(),
            bySeverity = bySeverity,
            activeThreatDomains = activeDomains.size,
            criticalCount = bySeverity[CsSeverity.CRITICAL] ?: 0L,
            highCount = bySeverity[CsSeverity.HIGH] ?: 0L
        )
    }

    /** Blocked-event counts per category (attack-vector analytics). */
    fun attackVectors(events: List<ThreatEvent>, nowEpochMs: Long, windowMs: Long = DAY_MS): List<CategoryCount> {
        val blocked = events.filter {
            it.action == CsEventAction.BLOCKED && nowEpochMs - it.timestampEpochMs <= windowMs
        }
        if (blocked.isEmpty()) return emptyList()
        val total = blocked.size.toFloat()
        return blocked.groupingBy { it.category }.eachCount()
            .map { (cat, count) -> CategoryCount(cat, count.toLong(), count / total) }
            .sortedByDescending { it.count }
    }

    /** 24 hourly buckets ending at [nowEpochMs]; real counts only. */
    fun hourlyBuckets(events: List<ThreatEvent>, nowEpochMs: Long): List<HourBucket> {
        val hourMs = 3_600_000L
        val endHour = nowEpochMs / hourMs
        val startHour = endHour - 23
        val blocked = LongArray(24)
        val allowed = LongArray(24)
        for (e in events) {
            val h = e.timestampEpochMs / hourMs
            if (h < startHour || h > endHour) continue
            val idx = (h - startHour).toInt()
            if (e.action == CsEventAction.BLOCKED) blocked[idx]++ else allowed[idx]++
        }
        return (0 until 24).map { HourBucket((startHour + it) * hourMs, blocked[it], allowed[it]) }
    }

    fun protocolDistribution(events: List<DnsEventSnapshot>, nowEpochMs: Long, windowMs: Long = DAY_MS): List<ProtocolCount> {
        val window = events.filter { nowEpochMs - it.timestampEpochMs <= windowMs }
        if (window.isEmpty()) return emptyList()
        fun bucket(protocol: String): String = when {
            protocol.startsWith("DoH", true) -> "DoH"
            protocol.startsWith("DoT", true) -> "DoT"
            protocol.startsWith("AETHER", true) -> "AI block"
            protocol.contains("Sinkhole", true) || protocol.contains("NXDOMAIN", true) -> "Sinkhole"
            protocol.startsWith("UDP", true) -> "UDP"
            protocol.startsWith("TCP", true) -> "TCP"
            else -> "Other"
        }
        val total = window.size.toFloat()
        return window.groupingBy { bucket(it.protocolUsed) }.eachCount()
            .map { (p, c) -> ProtocolCount(p, c.toLong(), c / total) }
            .sortedByDescending { it.count }
    }
}

/**
 * Correlates related real events into incidents grouped by registrable domain.
 * Pure and deterministic; the incident summary only states observed facts.
 */
object CorrelationEngine {
    fun correlate(
        events: List<ThreatEvent>,
        nowEpochMs: Long,
        windowMs: Long = ThreatEventMapper.DAY_MS,
        maxIncidents: Int = 100
    ): List<ThreatIncident> {
        val relevant = events.filter {
            nowEpochMs - it.timestampEpochMs <= windowMs &&
                (it.action == CsEventAction.BLOCKED || it.action == CsEventAction.FLAGGED) &&
                it.severity >= CsSeverity.LOW
        }
        return relevant.groupBy { ThreatEventMapper.registrableDomain(it.domain) }
            .map { (key, group) ->
                val sorted = group.sortedByDescending { it.timestampEpochMs }
                val severity = group.maxOf { it.severity }
                val sources = group.map { it.sourceDetail.substringBefore(':').trim() }
                    .filter { it.isNotBlank() }.distinct().take(4)
                val apps = group.mapNotNull { it.appName }.distinct().take(4)
                val blockedCount = group.count { it.action == CsEventAction.BLOCKED }
                ThreatIncident(
                    key = key,
                    domain = key,
                    severity = severity,
                    eventCount = group.size,
                    blockedCount = blockedCount,
                    firstSeenEpochMs = group.minOf { it.timestampEpochMs },
                    lastSeenEpochMs = group.maxOf { it.timestampEpochMs },
                    sources = sources,
                    apps = apps,
                    summary = buildString {
                        append("$blockedCount blocked / ${group.size} events")
                        if (apps.isNotEmpty()) append(" · ${apps.size} app${if (apps.size > 1) "s" else ""}")
                        if (sources.isNotEmpty()) append(" · ${sources.joinToString(", ")}")
                    },
                    events = sorted.take(50)
                )
            }
            .sortedWith(compareByDescending<ThreatIncident> { it.severity }
                .thenByDescending { it.eventCount }
                .thenByDescending { it.lastSeenEpochMs })
            .take(maxIncidents)
    }
}
