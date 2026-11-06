package com.adshield.pro.ui.model

import com.adshield.pro.domain.intelligence.IntelligenceEvent
import com.adshield.pro.domain.intelligence.IntelligenceFilters
import com.adshield.pro.domain.intelligence.IntelligenceModule
import com.adshield.pro.domain.intelligence.IntelligenceSystemState
import com.adshield.pro.domain.intelligence.NodePosition

/** Where the camera should go next. Consumed once by the map canvas. */
sealed interface MapCameraTarget {
    data object FitAll : MapCameraTarget
    data class OnModule(val module: IntelligenceModule) : MapCameraTarget
    data class OnEvent(val module: IntelligenceModule, val eventId: Long) : MapCameraTarget
}

data class MapCameraCommand(
    val token: Long,
    val target: MapCameraTarget,
    val animate: Boolean = true
)

/**
 * Everything the intelligence map screen renders. Produced by
 * [com.adshield.pro.ui.viewmodel.IntelligenceMapViewModel] from live app state only.
 *
 * [isLive] is a *visual* switch: when it is false the displayed [system] is the frozen snapshot
 * while [newEventsWhilePaused] keeps counting events that the recorder is still storing. DNS
 * protection, VPN filtering and background jobs are untouched by it.
 */
data class IntelligenceMapUiState(
    val system: IntelligenceSystemState,
    val allEvents: List<IntelligenceEvent>,
    val nodePositions: Map<IntelligenceModule, NodePosition>,
    val filters: IntelligenceFilters,
    val isLive: Boolean,
    val pausedAtEpochMs: Long?,
    val newEventsWhilePaused: Int,
    val isEditingLayout: Boolean,
    val selectedModule: IntelligenceModule?,
    val selectedEvent: IntelligenceEvent?,
    val cameraCommand: MapCameraCommand?,
    val isHistoryEmpty: Boolean
) {
    val selectedSnapshot get() = selectedModule?.let { system.snapshotFor(it) }

    fun historyFor(module: IntelligenceModule, limit: Int = 40): List<IntelligenceEvent> =
        allEvents.asSequence().filter { it.module == module }.take(limit).toList()
}
