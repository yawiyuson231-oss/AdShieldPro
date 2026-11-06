package com.adshield.pro.gps.traffic

import android.content.Context
import com.adshield.pro.gps.data.GeocodingClient
import com.adshield.pro.gps.data.GpsDao
import com.adshield.pro.gps.data.GpsPreferences
import com.adshield.pro.gps.data.SegmentTrafficEntity
import com.adshield.pro.gps.data.TrafficApiClient
import com.adshield.pro.gps.data.TrafficIncidentEntity
import com.adshield.pro.gps.data.TrafficObservationEntity
import com.adshield.pro.gps.engine.GnssFix
import com.adshield.pro.gps.geo.GeoPoint
import com.adshield.pro.gps.security.LocationPrivacyPolicy
import com.adshield.pro.gps.security.TelemetryGate
import com.adshield.pro.gps.worker.TrafficSyncWorker
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AdShield Pro — traffic state owner.
 *
 * Data flow, in order of trust:
 *   1. observations recorded by *this* device on segments it actually drove;
 *   2. aggregates the community backend reports for those segments;
 *   3. nothing — which renders as UNKNOWN (grey).
 *
 * There is no step 4. No commercial feed, no interpolation from averages, no "typical at this hour"
 * guess presented as live. When the map shows green, at least one real observer drove that segment
 * within the last half hour, and the UI shows how many.
 */
@Singleton
class TrafficRepository @Inject constructor(
    @ApplicationContext private val context: Context,
    private val dao: GpsDao,
    private val preferences: GpsPreferences,
    private val apiClient: TrafficApiClient,
    private val geocoding: GeocodingClient
) {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /** Segments around the user, discovered from the road names the offline graph/router knows. */
    private var matcher = SegmentMatcher(emptyList())
    private val knownSegments = LinkedHashMap<String, RoadSegment>()

    private val _segments = MutableStateFlow<List<SegmentTrafficState>>(emptyList())
    val segments: StateFlow<List<SegmentTrafficState>> = _segments.asStateFlow()

    private val _incidents = MutableStateFlow<List<TrafficIncident>>(emptyList())
    val incidents: StateFlow<List<TrafficIncident>> = _incidents.asStateFlow()

    private val _status = MutableStateFlow(TrafficStatus())
    val status: StateFlow<TrafficStatus> = _status.asStateFlow()

    private val _gateLog = MutableStateFlow<List<String>>(emptyList())
    val gateLog: StateFlow<List<String>> = _gateLog.asStateFlow()

    private val deduplicator = IncidentDeduplicator()
    private var recorder: SpeedObservationRecorder? = null
    private var reporterToken: String = ""
    private var lastFetchAtMs = 0L

    data class TrafficStatus(
        val backendConfigured: Boolean = false,
        val backendEnabled: Boolean = false,
        val contributing: Boolean = false,
        val ownSamples: Int = 0,
        val queuedSamples: Int = 0,
        val measuredSegments: Int = 0,
        val unknownSegments: Int = 0,
        val lastSyncAtMs: Long = 0L,
        val lastError: String? = null,
        val message: String = "No traffic data available"
    )

    @Volatile private var initialised = false

    /**
     * One-time setup, idempotent.
     *
     * This used to unconditionally replace `recorder` from a coroutine. If it landed after the
     * first `onFix` (or after `updateSegments`), it silently threw away whatever segment window was
     * being accumulated, so the first observation after app start was usually lost. It now only
     * creates the recorder if there is none, and refuses to run twice.
     */
    fun initialise() {
        if (initialised) return
        initialised = true
        scope.launch {
            reporterToken = preferences.reporterToken()
            if (recorder == null) recorder = SpeedObservationRecorder(reporterToken = reporterToken)
            refreshFromDatabase()
        }
    }

    /** Called when the road segments for the visible area become known. */
    fun updateSegments(segments: List<RoadSegment>) {
        knownSegments.clear()
        segments.forEach { knownSegments[it.id] = it }
        matcher = SegmentMatcher(segments)
        scope.launch { refreshFromDatabase() }
    }

    /**
     * Feeds one fix from the GPS engine. This is the only entry point that creates observations, and
     * it asks [TelemetryGate] first.
     */
    fun onFix(fix: GnssFix, policy: LocationPrivacyPolicy, compromised: Boolean) {
        val activeRecorder = recorder ?: return
        if (compromised && policy.contributeTraffic) {
            // Say it in the gate log: otherwise a user whose position is flagged sees "no traffic
            // ever recorded" with no explanation anywhere in the UI.
            _gateLog.value = (listOf("${clock()} Not recorded: position failed the integrity check") +
                _gateLog.value).take(40)
        }
        val match = matcher.matchDetailed(fix.position)
        val segment = match.segment

        val completed = activeRecorder.onFix(fix, segment, compromised)
        if (completed != null) {
            val alreadySent = false
            val decision = TelemetryGate.evaluate(
                policy = policy,
                integrityCompromised = compromised,
                mockFlagged = fix.mockProviderFlag,
                accuracyMeters = fix.accuracyMeters,
                speedKmh = completed.speedKmh,
                segmentId = completed.segmentId,
                alreadySentSegment = alreadySent
            )
            if (decision.allowed) {
                scope.launch {
                    dao.insertObservation(
                        TrafficObservationEntity(
                            segmentId = completed.segmentId,
                            speedKmh = completed.speedKmh,
                            capturedAtMs = completed.timestampMs,
                            accuracyMeters = completed.accuracyMeters,
                            headingDegrees = completed.headingDegrees,
                            sampleCount = completed.sampleCount,
                            queuedForUpload = true
                        )
                    )
                    _gateLog.value = (listOf("${clock()} ${decision.reason}") + _gateLog.value).take(40)
                    refreshFromDatabase()
                    TrafficSyncWorker.enqueueUpload(context)
                }
            } else {
                _gateLog.value = (listOf("${clock()} Not recorded: ${decision.reason}") + _gateLog.value).take(40)
            }
            // Start a fresh recorder window; the token and thresholds stay the same.
            recorder = SpeedObservationRecorder(reporterToken = reporterToken)
        } else if (match.rejectionReason != null && policy.contributeTraffic) {
            _gateLog.value = (listOf("${clock()} No segment: ${match.rejectionReason}") + _gateLog.value).take(40)
        }
    }

    fun completeTrip(policy: LocationPrivacyPolicy) {
        val activeRecorder = recorder ?: return
        // The partial segment is always closed so the window does not leak into the next trip; it is
        // only *stored* when the user opted in.
        val completed = activeRecorder.complete()
        recorder = SpeedObservationRecorder(reporterToken = reporterToken)
        if (completed == null) return
        if (!policy.contributeTraffic) {
            _gateLog.value = (listOf("${clock()} Trip closed: sharing is off, sample discarded") +
                _gateLog.value).take(40)
            return
        }
        scope.launch {
            dao.insertObservation(
                TrafficObservationEntity(
                    segmentId = completed.segmentId,
                    speedKmh = completed.speedKmh,
                    capturedAtMs = completed.timestampMs,
                    accuracyMeters = completed.accuracyMeters,
                    headingDegrees = completed.headingDegrees,
                    sampleCount = completed.sampleCount,
                    queuedForUpload = true
                )
            )
            refreshFromDatabase()
            TrafficSyncWorker.enqueueUpload(context)
        }
    }

    /** Recomputes the visible traffic from local samples + server aggregates. */
    private suspend fun refreshFromDatabase() {
        val policy = preferences.currentPolicy()
        val since = System.currentTimeMillis() - TrafficAggregator.SAMPLE_WINDOW_MINUTES * 60_000L
        val observations = dao.observationsSince(since)
        val cached = dao.allSegmentTraffic()
        val history = dao.historySince(System.currentTimeMillis() - 7L * 24 * 3600_000L)
        val incidents = dao.activeIncidents(System.currentTimeMillis()).mapNotNull { it.toModel() }

        val bySegment = observations.groupBy { it.segmentId }
        val states = knownSegments.values.map { segment ->
            val own = bySegment[segment.id].orEmpty().map { row ->
                SpeedObservation(
                    segmentId = row.segmentId,
                    speedKmh = row.speedKmh,
                    timestampMs = row.capturedAtMs,
                    accuracyMeters = row.accuracyMeters,
                    headingDegrees = row.headingDegrees,
                    reporterToken = reporterToken,
                    sampleCount = row.sampleCount
                )
            }
            val historical = history.filter { it.segmentId == segment.id }.map { it.averageSpeedKmh }
            val aggregate = TrafficAggregator.aggregate(segment, own, historicalSpeeds = historical)
            val server = cached.firstOrNull { it.segmentId == segment.id }
            val serverIsNewer = server != null && (aggregate.newestTimestampMs ?: 0L) < server.updatedAtMs
            val state = if (serverIsNewer && server != null) {
                SegmentTrafficState(
                    segmentId = segment.id,
                    segmentName = server.segmentName ?: segment.name,
                    level = CongestionLevel.valueOf(server.level),
                    averageSpeedKmh = server.averageSpeedKmh,
                    freeFlowSpeedKmh = server.freeFlowKmh,
                    sampleCount = server.sampleCount,
                    reporterCount = server.reporterCount,
                    confidence = server.confidence,
                    updatedAtMs = server.updatedAtMs,
                    ageMinutes = ((System.currentTimeMillis() - server.updatedAtMs) / 60_000L).coerceAtLeast(0L),
                    source = TrafficSource.COMMUNITY
                )
            } else {
                SegmentTrafficState(
                    segmentId = segment.id,
                    segmentName = segment.name,
                    level = aggregate.level,
                    averageSpeedKmh = aggregate.averageSpeedKmh,
                    freeFlowSpeedKmh = aggregate.freeFlowSpeedKmh,
                    sampleCount = aggregate.sampleCount,
                    reporterCount = aggregate.reporterCount,
                    confidence = aggregate.confidence,
                    updatedAtMs = aggregate.newestTimestampMs,
                    ageMinutes = aggregate.newestTimestampMs?.let {
                        ((System.currentTimeMillis() - it) / 60_000L).coerceAtLeast(0L)
                    },
                    source = if (aggregate.sampleCount > 0) TrafficSource.DEVICE_SAMPLES else TrafficSource.UNKNOWN
                )
            }.copy(incidents = incidents.filter { it.segmentId == segment.id })
            state
        }
        _segments.value = states
        _incidents.value = incidents

        val measured = states.count { it.isMeasured }
        val unknown = states.size - measured
        _status.value = _status.value.copy(
            contributing = policy.contributeTraffic,
            ownSamples = observations.size,
            measuredSegments = measured,
            unknownSegments = unknown,
            lastError = apiClient.lastError,
            message = when {
                states.isEmpty() -> "No road segments loaded for this area yet"
                measured == 0 -> "UNKNOWN — no observations from any device in the last " +
                    "${TrafficAggregator.SAMPLE_WINDOW_MINUTES} minutes"
                else -> "$measured of ${states.size} road segments have measured traffic"
            }
        )
    }

    /** Pulls community aggregates for the loaded segments, if a backend is configured. */
    fun syncCommunity() {
        scope.launch {
            val configured = !apiClient.backendUrl().isNullOrBlank()
            val enabled = apiClient.isEnabled()
            _status.value = _status.value.copy(backendConfigured = configured, backendEnabled = enabled)
            if (!configured || !enabled || knownSegments.isEmpty()) {
                if (!configured) {
                    _status.value = _status.value.copy(
                        lastError = null,
                        message = if (_segments.value.none { it.isMeasured }) {
                            "UNKNOWN — no community backend configured and no device observations yet"
                        } else {
                            _status.value.message
                        }
                    )
                }
                return@launch
            }
            val states = apiClient.fetchSegments(knownSegments.keys.take(100))
            if (states.isNotEmpty()) {
                dao.upsertSegmentTraffic(
                    states.map { state ->
                        SegmentTrafficEntity(
                            segmentId = state.segmentId,
                            segmentName = state.segmentName,
                            level = TrafficAggregator
                                .classify(state.averageSpeedKmh, state.freeFlowKmh ?: TrafficAggregator.DEFAULT_FREE_FLOW_KMH)
                                .name,
                            averageSpeedKmh = state.averageSpeedKmh,
                            freeFlowKmh = state.freeFlowKmh,
                            sampleCount = state.sampleCount,
                            reporterCount = 0,
                            confidence = state.confidence,
                            updatedAtMs = state.updatedAtMs,
                            source = TrafficSource.COMMUNITY.name
                        )
                    }
                )
                lastFetchAtMs = System.currentTimeMillis()
            }
            _status.value = _status.value.copy(
                lastSyncAtMs = lastFetchAtMs,
                lastError = apiClient.lastError
            )
            refreshFromDatabase()
        }
    }

    /** Submits a user report after validation and duplicate suppression. */
    fun reportIncident(
        kind: IncidentKind,
        fix: GnssFix?,
        notes: String?,
        integrityCompromised: Boolean,
        policy: LocationPrivacyPolicy
    ): ReportOutcome {
        if (!policy.allowIncidentReporting) {
            return ReportOutcome(false, "Incident reporting is switched off in Location security")
        }
        if (fix == null) return ReportOutcome(false, "No GPS fix yet")
        val validation = IncidentValidator.validate(
            kind = kind,
            position = fix.position,
            lastFixAgeMs = System.currentTimeMillis() - fix.timeMs,
            accuracyMeters = fix.accuracyMeters,
            integrityCompromised = integrityCompromised,
            notes = notes
        )
        if (!validation.accepted) return ReportOutcome(false, validation.reason)

        val match = matcher.matchDetailed(fix.position)
        val existing = _incidents.value
        val decision = deduplicator.evaluate(kind, fix.position, reporterToken, existing)
        if (!decision.accepted && !decision.confirmation) {
            return ReportOutcome(false, decision.reason)
        }
        if (decision.confirmation && decision.mergeInto != null) {
            scope.launch {
                dao.confirmIncident(decision.mergeInto)
                refreshFromDatabase()
            }
            return ReportOutcome(true, "Counted as a confirmation of an existing report")
        }

        val now = System.currentTimeMillis()
        val incident = TrafficIncident(
            id = "local-$now",
            kind = kind,
            position = fix.position,
            roadName = match.segment?.name,
            segmentId = match.segment?.id,
            reportedAtMs = now,
            expiresAtMs = now + kind.defaultLifetimeMinutes * 60_000L,
            reporterToken = reporterToken,
            confirmations = 0,
            notes = notes
        )
        scope.launch {
            dao.upsertIncident(incident.toEntity(reportedByMe = true, syncState = "PENDING"))
            deduplicator.record(incident)
            refreshFromDatabase()
            if (!apiClient.backendUrl().isNullOrBlank() && apiClient.isEnabled()) {
                TrafficSyncWorker.enqueueUpload(context)
            }
        }
        return ReportOutcome(true, "Report saved on this device")
    }

    /** Removes every traffic artefact this device produced or cached. */
    fun clearLocal() {
        scope.launch {
            dao.deleteAllObservations()
            dao.deleteAllSegmentTraffic()
            dao.deleteAllHistory()
            _segments.value = emptyList()
            _incidents.value = emptyList()
            _gateLog.value = emptyList()
            recorder = SpeedObservationRecorder(reporterToken = reporterToken)
        }
    }

    fun dismissIncident(id: String) {
        scope.launch {
            dao.deleteIncident(id)
            refreshFromDatabase()
        }
    }

    /** Reverse-geocodes for the incident list labels; failures leave the label empty. */
    suspend fun describePosition(point: GeoPoint): String? {
        val results = geocoding.search("${point.latitude},${point.longitude}", limit = 1)
        return results.firstOrNull()?.shortName
    }

    private fun clock(): String =
        java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US).format(java.util.Date())

    data class ReportOutcome(val accepted: Boolean, val message: String?)

    companion object {
        /** How far from the current position segments are still considered "visible". */
        const val SEGMENT_RADIUS_METERS = 2_500.0
    }
}

internal fun TrafficIncidentEntity.toModel(): TrafficIncident? = runCatching {
    TrafficIncident(
        id = id,
        kind = IncidentKind.valueOf(kind),
        position = GeoPoint(latitude, longitude),
        roadName = roadName,
        segmentId = segmentId,
        reportedAtMs = reportedAtMs,
        expiresAtMs = expiresAtMs,
        reporterToken = reporterToken,
        confirmations = confirmations,
        notes = notes
    )
}.getOrNull()

internal fun TrafficIncident.toEntity(reportedByMe: Boolean, syncState: String): TrafficIncidentEntity =
    TrafficIncidentEntity(
        id = id,
        kind = kind.name,
        latitude = position.latitude,
        longitude = position.longitude,
        roadName = roadName,
        segmentId = segmentId,
        reportedAtMs = reportedAtMs,
        expiresAtMs = expiresAtMs,
        reporterToken = reporterToken,
        confirmations = confirmations,
        notes = notes,
        reportedByMe = reportedByMe,
        syncState = syncState
    )
