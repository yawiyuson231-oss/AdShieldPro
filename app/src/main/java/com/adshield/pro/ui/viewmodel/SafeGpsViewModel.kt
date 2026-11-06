package com.adshield.pro.ui.viewmodel

import android.app.Application
import android.content.Intent
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import com.adshield.pro.engine.location.CaptureResult
import com.adshield.pro.engine.location.DeviceSettingTarget
import com.adshield.pro.engine.location.LocationAnalysis
import com.adshield.pro.engine.location.LocationAnalyzer
import com.adshield.pro.engine.location.LocationFix
import com.adshield.pro.engine.location.LocationPermission
import com.adshield.pro.engine.location.LocationSafetyAdvisor
import com.adshield.pro.engine.location.SafeGpsLocator
import com.adshield.pro.engine.location.SafetyFact
import com.adshield.pro.engine.location.ShareMode
import com.adshield.pro.engine.location.SharePlan
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.util.TimeZone
import javax.inject.Inject

/**
 * AdShield Pro — Safe GPS screen state.
 *
 * Owns one capture at a time. The screen only renders this state: every judgement (quality,
 * consistency, rounding, whether a pin may be shared at all) comes from
 * [LocationSafetyAdvisor], which is unit-tested on the JVM.
 */
data class SafeGpsUiState(
    val running: Boolean = false,
    val fixes: List<LocationFix> = emptyList(),
    val message: String? = null,
    val stopReason: String? = null,
    val targetAccuracyMeters: Double = 10.0,
    val timeoutMs: Long = 30_000L,
    val gridMeters: Int = 0,
    val shareMode: ShareMode = ShareMode.EVERYDAY,
    val checklist: List<SafetyFact> = emptyList(),
    val permission: LocationPermission = LocationPermission.NOT_DETERMINED,
    val hasProvider: Boolean = true,
    val mockSeen: Boolean = false,
    val analysis: LocationAnalysis = LocationAnalysis(),
    val sharePlan: SharePlan? = null
) {
    val hasFix: Boolean get() = analysis.hasFix
    val canShare: Boolean get() = sharePlan?.blocked == false
}

@HiltViewModel
class SafeGpsViewModel @Inject constructor(application: Application) : AndroidViewModel(application) {

    private val locator = SafeGpsLocator(application.applicationContext)
    private var captureJob: Job? = null

    private val _state = MutableStateFlow(
        SafeGpsUiState(
            permission = locator.permissionState(),
            hasProvider = locator.hasProvider(),
            checklist = LocationSafetyAdvisor.deviceChecklist(locator.deviceContext())
        ).let { initial ->
            initial.copy(analysis = LocationAnalyzer.analyse(emptyList(), initial.targetAccuracyMeters))
        }
    )
    val state: StateFlow<SafeGpsUiState> = _state.asStateFlow()

    /** Re-reads permissions and device switches; call when the screen resumes. */
    fun refreshDeviceState() {
        val context = locator.deviceContext(mockProvidersEnabled = if (_state.value.mockSeen) true else null)
        _state.value = _state.value.copy(
            permission = context.permission,
            hasProvider = locator.hasProvider(),
            checklist = LocationSafetyAdvisor.deviceChecklist(context)
        )
        recompute()
    }

    fun setTargetAccuracy(meters: Double) {
        _state.value = _state.value.copy(targetAccuracyMeters = meters)
        recompute()
    }

    fun setTimeoutSeconds(seconds: Long) {
        _state.value = _state.value.copy(timeoutMs = seconds * 1_000L)
        recompute()
    }

    fun setGridMeters(meters: Int) {
        _state.value = _state.value.copy(gridMeters = meters)
        recompute()
    }

    fun setShareMode(mode: ShareMode) {
        _state.value = _state.value.copy(shareMode = mode)
        recompute()
    }

    /** Called after the system permission dialog returns. */
    fun onPermissionResult(granted: Boolean, permanentDenial: Boolean = false) {
        val permission = when {
            granted -> LocationPermission.GRANTED
            permanentDenial -> LocationPermission.DENIED_PERMANENTLY
            else -> LocationPermission.DENIED
        }
        _state.value = _state.value.copy(permission = permission)
        refreshDeviceState()
        if (!granted) {
            _state.value = _state.value.copy(
                message = "Location permission was not granted. The app cannot read a position without it — " +
                    "and it does not try to work around a refusal."
            )
        }
    }

    fun startCapture() {
        if (_state.value.running) return
        if (locator.permissionState() != LocationPermission.GRANTED) {
            _state.value = _state.value.copy(
                message = "Allow location access first. Nothing is located until you grant it.",
                permission = locator.permissionState()
            )
            return
        }
        val target = _state.value.targetAccuracyMeters
        val timeout = _state.value.timeoutMs
        _state.value = _state.value.copy(
            running = true,
            fixes = emptyList(),
            message = "Sampling high-accuracy fixes. A cold GPS lock can take 10–30 s — stay still, outdoors if you can.",
            stopReason = null,
            sharePlan = null
        )
        captureJob?.cancel()
        captureJob = viewModelScope.launch {
            val result: CaptureResult = locator.captureOnce(
                targetAccuracyMeters = target,
                timeoutMs = timeout,
                onFix = { fix, accepted ->
                    val analysis = LocationAnalyzer.analyse(accepted, target)
                    _state.value = _state.value.copy(
                        fixes = accepted,
                        analysis = analysis,
                        message = "Best so far ±" + LocationAnalyzer.formatMeters(fix.accuracyMeters) +
                            " · " + accepted.size + " fix(es) · " +
                            if (analysis.consistent) "consistent" else "fixes disagree so far",
                        mockSeen = _state.value.mockSeen || fix.mock
                    )
                }
            )
            val analysis = LocationAnalyzer.analyse(result.fixes, target)
            _state.value = _state.value.copy(
                running = false,
                fixes = result.fixes,
                analysis = analysis,
                stopReason = result.stopReason,
                message = result.stopReason,
                mockSeen = _state.value.mockSeen || result.fixes.any { it.mock }
            )
            refreshDeviceState()
        }
    }

    fun stopCapture() {
        captureJob?.cancel()
        captureJob = null
        val analysis = LocationAnalyzer.analyse(_state.value.fixes, _state.value.targetAccuracyMeters)
        _state.value = _state.value.copy(
            running = false,
            analysis = analysis,
            stopReason = if (analysis.hasFix) {
                "Stopped by you. The pin below is from the ${analysis.count} fix(es) received before you stopped."
            } else {
                "Stopped before any usable fix arrived."
            }
        )
        recompute()
    }

    /** Rebuilds the share plan after every relevant change. */
    fun recompute() {
        val current = _state.value
        val analysis = LocationAnalyzer.analyse(current.fixes, current.targetAccuracyMeters)
        val plan = if (analysis.hasFix) {
            LocationSafetyAdvisor.buildSharePlan(
                analysis = analysis,
                mode = current.shareMode,
                gridMeters = current.gridMeters,
                nowWallClockMs = System.currentTimeMillis(),
                timeZoneLabel = LocationSafetyAdvisor.timeZoneLabel(TimeZone.getDefault()),
                mapUrl = LocationSafetyAdvisor.openStreetMapUrl(
                    if (current.gridMeters > 0) {
                        LocationAnalyzer.round(analysis.best!!, current.gridMeters)!!.point
                    } else {
                        analysis.best!!.point
                    }
                ),
                emergencyNumber = "911"
            )
        } else {
            null
        }
        _state.value = current.copy(analysis = analysis, sharePlan = plan)
    }

    fun settingIntent(target: DeviceSettingTarget): Intent = locator.settingIntent(target)

    fun clearMessage() {
        _state.value = _state.value.copy(message = null)
    }

    override fun onCleared() {
        captureJob?.cancel()
        super.onCleared()
    }
}
