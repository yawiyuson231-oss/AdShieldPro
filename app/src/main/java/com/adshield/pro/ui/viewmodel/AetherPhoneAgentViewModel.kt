package com.adshield.pro.ui.viewmodel

import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.adshield.pro.data.repository.AetherSecurityTools
import com.adshield.pro.data.repository.AetherTaskResult
import com.adshield.pro.engine.aether.AetherFilePickerApproval
import com.adshield.pro.engine.aether.AetherSecurityReview
import com.adshield.pro.engine.aether.AetherSecurityTask
import com.adshield.pro.engine.aether.AetherTaskApproval
import com.adshield.pro.engine.aether.AetherTaskProgress
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Job
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import javax.inject.Inject

/** Foreground, on-device suggestions. Only a separate user approval can run a check. */
@HiltViewModel
class AetherPhoneAgentViewModel @Inject constructor(
    private val tools: AetherSecurityTools
) : ViewModel() {
    internal data class State(
        val findingTask: Boolean = false,
        val proposal: AetherTaskApproval.Proposal? = null,
        val running: AetherSecurityTask? = null,
        val progress: AetherTaskProgress? = null,
        val stopping: Boolean = false,
        val fileChoiceId: Long? = null,
        val result: AetherTaskResult? = null,
        val message: String? = null
    ) {
        val busy get() = findingTask || running != null || fileChoiceId != null
        val canStart get() = !busy && proposal == null
    }

    private val approvals = AetherTaskApproval()
    private val fileApproval = AetherFilePickerApproval()
    private var suggestionJob: Job? = null
    private var taskJob: Job? = null
    private val _state = MutableStateFlow(State())
    internal val state = _state.asStateFlow()

    fun findTask(request: String) {
        if (!_state.value.canStart || request.isBlank()) return
        _state.update { it.copy(findingTask = true, message = null) }
        suggestionJob = viewModelScope.launch {
            try {
                val task = withTimeout(5_000) { tools.suggest(request) }
                ensureActive()
                if (task == null) {
                    _state.update { it.copy(findingTask = false,
                        message = "I couldn't match that to one check. Try “Security review”, or choose a check below.") }
                } else {
                    showProposal(task, suggested = true)
                }
            } catch (_: TimeoutCancellationException) {
                modelUnavailable()
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                modelUnavailable()
            }
        }
    }

    private fun modelUnavailable() {
        _state.update { it.copy(findingTask = false, message = "Couldn't use the on-device model. You can still choose a check below.") }
    }

    internal fun proposeTool(task: AetherSecurityTask) {
        if (_state.value.canStart) showProposal(task)
    }

    private fun showProposal(task: AetherSecurityTask, suggested: Boolean = false) {
        val proposal = approvals.propose(task, suggested)
        _state.update { it.copy(findingTask = false, proposal = proposal, message = null) }
    }

    fun dismissProposal(id: Long) {
        if (_state.value.proposal?.id != id) return
        approvals.dismiss(id)
        _state.update { it.copy(proposal = null) }
    }

    fun screenStopped() {
        suggestionJob?.cancel()
        suggestionJob = null
        approvals.pending?.let { dismissProposal(it.id) }
        cancelTask()
        _state.update { it.copy(findingTask = false) }
        // The system picker temporarily covers this activity. Keep its one pending choice until it
        // returns (but not across composition disposal, navigation, or process recreation).
    }

    fun leaveAgent() {
        screenStopped()
        fileApproval.clear()
        _state.update { it.copy(fileChoiceId = null, result = null, message = null) }
    }

    private fun takeTaskApproval(id: Long, link: String = ""): AetherTaskApproval.Approved? {
        val current = _state.value
        if (current.busy || current.proposal?.id != id) return null
        val approved = approvals.approve(id, link) ?: return null
        _state.update { it.copy(proposal = null, message = null) }
        return approved
    }

    fun approveTask(id: Long, link: String) {
        if (_state.value.proposal?.task == AetherSecurityTask.SCAN_FILE) return
        takeTaskApproval(id, link)?.let { runTask(it) }
    }

    fun beginFileChoice(id: Long): Boolean {
        if (_state.value.proposal?.task != AetherSecurityTask.SCAN_FILE) return false
        fileApproval.await(takeTaskApproval(id) ?: return false)
        _state.update { it.copy(fileChoiceId = id) }
        return true
    }

    fun finishFileChoice(id: Long, uri: Uri?) {
        if (_state.value.fileChoiceId != id) return
        val approved = fileApproval.consume(id)
        _state.update { it.copy(fileChoiceId = null) }
        if (uri?.scheme == "content" && approved != null) {
            runTask(approved, uri)
        } else {
            _state.update { it.copy(message = "No accessible file was selected. Nothing was scanned.") }
        }
    }

    fun cancelTask() {
        val current = _state.value
        if (current.running?.canCancel != true || current.stopping) return
        _state.update { it.copy(stopping = true) }
        taskJob?.cancel()
    }

    private fun runTask(approved: AetherTaskApproval.Approved, chosenFile: Uri? = null) {
        val task = approved.task
        _state.update { it.copy(running = task, progress = null, stopping = false, result = null, message = null) }
        // Install cancellation handling before dispatching I/O so an immediate stop clears the check.
        taskJob = viewModelScope.launch(start = CoroutineStart.UNDISPATCHED) {
            val execute: suspend () -> AetherTaskResult = {
                tools.run(approved, chosenFile) { progress ->
                    _state.update { state ->
                        if (state.running == task && !state.stopping) state.copy(progress = progress) else state
                    }
                }
            }
            try {
                ensureActive()
                val timeout = when (task) {
                    AetherSecurityTask.SECURITY_REVIEW -> null // Each read has its own deadline.
                    AetherSecurityTask.AUDIT_APPS -> AetherSecurityReview.APPS_TIMEOUT_MS
                    AetherSecurityTask.BENCHMARK_DNS -> 15_000L
                    AetherSecurityTask.SCAN_FILE -> 35_000L
                    else -> AetherSecurityReview.PHONE_TIMEOUT_MS
                }
                val result = if (timeout == null) execute() else withTimeout(timeout) { execute() }
                ensureActive()
                finishTask(result)
            } catch (_: TimeoutCancellationException) {
                taskFailed(task, "The task took too long.")
            } catch (cancelled: CancellationException) {
                val note = if (task == AetherSecurityTask.BENCHMARK_DNS) " Lookups already sent cannot be recalled." else ""
                finishTask(result = null, message = "Check canceled. No new result.$note")
                throw cancelled
            } catch (_: Exception) {
                taskFailed(task, "The task couldn't finish.")
            }
        }
    }

    private fun finishTask(result: AetherTaskResult?, message: String? = null) {
        _state.update { it.copy(running = null, progress = null, stopping = false, result = result, message = message) }
    }

    private fun taskFailed(task: AetherSecurityTask, reason: String) {
        val next = if (task == AetherSecurityTask.ENABLE_ALIAS_SHIELD) {
            "Check the Alias Shield toggle in AdShield Settings to see whether it changed."
        } else "No result was recorded. Try again."
        finishTask(result = null, message = "$reason $next")
    }
}
