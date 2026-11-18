package com.adshield.pro.ui.viewmodel

import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.adshield.pro.data.repository.AetherOnlinePlanner
import com.adshield.pro.data.repository.AetherSecurityTools
import com.adshield.pro.data.repository.AetherTaskResult
import com.adshield.pro.data.repository.planAttempt
import com.adshield.pro.engine.aether.AetherFilePickerApproval
import com.adshield.pro.engine.aether.AetherGuidedPlan
import com.adshield.pro.engine.aether.AetherOnlineApproval
import com.adshield.pro.engine.aether.AetherOnlineConfig
import com.adshield.pro.engine.aether.AetherOnlineEndpoint
import com.adshield.pro.engine.aether.AetherOnlinePrompt
import com.adshield.pro.engine.aether.AetherOnlineResult
import com.adshield.pro.engine.aether.AetherPlanRequest
import com.adshield.pro.engine.aether.AetherSecurityReview
import com.adshield.pro.engine.aether.AetherSecurityTask
import com.adshield.pro.engine.aether.AetherTaskApproval
import com.adshield.pro.engine.aether.AetherTaskProgress
import com.adshield.pro.engine.aether.AetherTaskSource
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

/** Foreground requests only. Consent to send text is separate from consent to run the proposed task. */
@HiltViewModel
class AetherPhoneAgentViewModel @Inject constructor(
    private val tools: AetherSecurityTools,
    private val online: AetherOnlinePlanner
) : ViewModel() {
    internal data class State(
        val planning: AetherTaskSource? = null,
        val proposal: AetherTaskApproval.Proposal? = null,
        val running: AetherSecurityTask? = null,
        val progress: AetherTaskProgress? = null,
        val stopping: Boolean = false,
        val fileChoiceId: Long? = null,
        val plan: AetherGuidedPlan<AetherTaskResult>? = null,
        val result: AetherTaskResult? = null,
        val message: String? = null,
        val api: AetherOnlineEndpoint? = null,
        val apiStatus: String? = null,
        val apiSetupOpen: Boolean = false,
        val apiStorageBusy: Boolean = true,
        val apiSetupError: String? = null,
        val sendReview: AetherOnlineApproval.Review? = null
    ) {
        val busy get() = planning != null || running != null || fileChoiceId != null
        private val idle get() = !busy && proposal == null && sendReview == null && !apiSetupOpen
        val canStart get() = idle && plan == null
        val canUsePlan get() = idle && plan != null
        val canUseApi get() = canStart && !apiStorageBusy
    }

    private val approvals = AetherTaskApproval()
    private val outboundApprovals = AetherOnlineApproval()
    private var planningJob: Job? = null
    private var taskJob: Job? = null
    private var planSequence = 0L
    private val fileApproval = AetherFilePickerApproval()
    private val _state = MutableStateFlow(State())
    internal val state = _state.asStateFlow()

    init {
        viewModelScope.launch {
            val endpoint = try {
                online.configuredEndpoint()
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                null // An unreadable saved connection is not considered ready.
            }
            _state.update { it.copy(api = endpoint, apiStorageBusy = false) }
        }
    }

    fun findTask(request: String) {
        if (!_state.value.canStart || request.isBlank()) return
        _state.value = _state.value.copy(planning = AetherTaskSource.OFFLINE_MODEL, message = null)
        planningJob = viewModelScope.launch {
            try {
                val found = withTimeout(5_000) { tools.plan(request) }
                ensureActive()
                when (found) {
                    is AetherPlanRequest.Result.Single -> modelSuggestion(found.task, AetherTaskSource.OFFLINE_MODEL)
                    is AetherPlanRequest.Result.Steps -> {
                        val plan = AetherGuidedPlan.create<AetherTaskResult>(++planSequence, found.tasks)
                        _state.update { it.copy(planning = null, plan = plan, result = null, message = null) }
                    }
                    is AetherPlanRequest.Result.Rejected -> _state.update { it.copy(planning = null, message = found.message) }
                }
            } catch (_: TimeoutCancellationException) {
                offlineUnavailable()
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                offlineUnavailable()
            }
        }
    }

    fun openApiSetup() {
        if (_state.value.canUseApi) _state.update { it.copy(apiSetupOpen = true, apiSetupError = null) }
    }

    fun closeApiSetup() {
        if (!_state.value.apiStorageBusy) _state.value = _state.value.copy(apiSetupOpen = false, apiSetupError = null)
    }

    internal fun saveApi(input: AetherOnlineConfig.Input) {
        if (!_state.value.apiSetupOpen || _state.value.apiStorageBusy) return
        when (val validation = AetherOnlineConfig.validate(input)) {
            is AetherOnlineConfig.Validation.Invalid -> _state.update { it.copy(apiSetupError = validation.issue.message) }
            is AetherOnlineConfig.Validation.Ready -> {
                val config = validation.config
                updateApi(config.endpoint) { online.save(config) }
            }
        }
    }

    fun disconnectApi() {
        if (!_state.value.apiSetupOpen || _state.value.apiStorageBusy) return
        updateApi(null) { online.disconnect() }
    }

    private fun updateApi(endpoint: AetherOnlineEndpoint?, change: suspend () -> Unit) {
        _state.value = _state.value.copy(apiStorageBusy = true, apiSetupError = null)
        viewModelScope.launch {
            try {
                change()
                val reviewTest = endpoint != null && _state.value.apiSetupOpen
                _state.update {
                    it.copy(api = endpoint, apiStorageBusy = false, apiSetupOpen = false, apiStatus = null,
                        message = if (endpoint == null) "Online AI disconnected." else "API settings saved on this phone.")
                }
                // Saving opens the same explicit consent screen; it never sends a test automatically.
                if (reviewTest) reviewApiTest()
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                _state.value = _state.value.copy(apiStorageBusy = false,
                    apiSetupError = "AdShield couldn't update the encrypted settings. Try again.")
            }
        }
    }

    fun reviewOnlineRequest(request: String) = reviewSend(request, test = false)

    fun reviewApiTest() = reviewSend(AetherOnlinePrompt.CONNECTION_TEST, test = true)

    private fun reviewSend(request: String, test: Boolean) {
        if (!_state.value.canUseApi) return
        val endpoint = _state.value.api ?: return
        if (!test && AetherPlanRequest.hasSequence(request)) {
            _state.update { it.copy(message = "Use Find task offline for a guided plan. Nothing was sent to the AI API.") }
            return
        }
        val prompt = AetherOnlinePrompt.create(request)
        if (prompt == null) {
            _state.value = _state.value.copy(message = "Describe the task without pasting a link, email address, or IP address. You can also use the offline model.")
            return
        }
        _state.value = _state.value.copy(sendReview = outboundApprovals.preview(endpoint, prompt, test), message = null)
    }

    fun dismissSend(id: Long) {
        if (_state.value.sendReview?.id != id) return
        outboundApprovals.dismiss(id)
        _state.value = _state.value.copy(sendReview = null)
    }

    fun sendOnline(id: Long) {
        val current = _state.value
        if (current.busy || current.apiStorageBusy || current.sendReview?.id != id) return
        val approved = outboundApprovals.approve(id) ?: return
        _state.value = _state.value.copy(sendReview = null, planning = AetherTaskSource.ONLINE_API, message = null)
        planningJob = viewModelScope.launch {
            try {
                val result = online.suggest(approved)
                ensureActive()
                when (result) {
                    is AetherOnlineResult.Failed -> onlineFailed(result.problem)
                    AetherOnlineResult.Unsupported -> onlineSuggestion(approved.test, null)
                    is AetherOnlineResult.Suggested -> onlineSuggestion(approved.test, result.task)
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                onlineFailed(AetherOnlineResult.Problem.NETWORK)
            }
        }
    }

    fun stopOnlineRequest() {
        if (_state.value.planning != AetherTaskSource.ONLINE_API) return
        planningJob?.cancel()
        planningJob = null
        _state.value = _state.value.copy(planning = null,
            message = "Stopped waiting for the AI API. Your provider may already have received the request. No task ran.")
    }

    private fun onlineSuggestion(test: Boolean, task: AetherSecurityTask?) {
        if (test) {
            val status = if (task == AetherSecurityTask.AUDIT_APPS) {
                "API test passed for this model. No audit ran."
            } else "The API replied but didn't recognize the test. Try a different text model."
            _state.update { it.copy(planning = null, apiStatus = status, message = status) }
        } else {
            _state.update { it.copy(apiStatus = if (task != null) "The model returned a supported task."
                else "The API responded, but no supported task was suggested.") }
            modelSuggestion(task, AetherTaskSource.ONLINE_API)
        }
    }

    private fun onlineFailed(problem: AetherOnlineResult.Problem) {
        _state.update { it.copy(planning = null, apiStatus = problem.message, message = problem.message) }
    }

    internal fun proposeTool(task: AetherSecurityTask) {
        if (_state.value.canStart) showProposal(task, AetherTaskSource.MANUAL)
    }

    internal fun reviewPlanStep(ref: AetherGuidedPlan.Ref) {
        val current = _state.value
        if (!current.canUsePlan) return
        val task = current.plan?.taskToReview(ref) ?: return
        showProposal(task, AetherTaskSource.GUIDED_PLAN, ref)
    }

    internal fun skipPlanStep(ref: AetherGuidedPlan.Ref) {
        val current = _state.value
        if (!current.canUsePlan) return
        val updated = current.plan?.skip(ref) ?: return
        _state.update { it.copy(plan = updated, message = null) }
    }

    internal fun showPlanReceipt(ref: AetherGuidedPlan.Ref): Boolean {
        val current = _state.value
        if (!current.canUsePlan) return false
        val receipt = current.plan?.receipt(ref) ?: return false
        _state.update { it.copy(result = receipt) }
        return true
    }

    internal fun closePlan(id: Long) {
        val current = _state.value
        if (current.canUsePlan && current.plan?.id == id) {
            _state.update { it.copy(plan = null, result = null, message = null) }
        }
    }

    private fun modelSuggestion(task: AetherSecurityTask?, source: AetherTaskSource) {
        if (task != null) {
            showProposal(task, source)
        } else {
            _state.value = _state.value.copy(planning = null,
                message = "I couldn't match that to one task. Try “Security review” or choose a tool directly.")
        }
    }

    private fun showProposal(task: AetherSecurityTask, source: AetherTaskSource, ref: AetherGuidedPlan.Ref? = null) {
        val proposal = approvals.propose(task, source, ref)
        _state.update { it.copy(planning = null, proposal = proposal, message = null) }
    }

    private fun offlineUnavailable() {
        _state.value = _state.value.copy(planning = null, message = "The on-device model couldn't run. You can still choose a tool below.")
    }

    fun dismissProposal(id: Long) {
        if (_state.value.proposal?.id != id) return
        approvals.dismiss(id)
        _state.value = _state.value.copy(proposal = null)
    }

    fun screenStopped() {
        if (_state.value.planning == AetherTaskSource.ONLINE_API) stopOnlineRequest() else planningJob?.cancel()
        planningJob = null
        approvals.pending?.let { dismissProposal(it.id) }
        outboundApprovals.pending?.let { dismissSend(it.id) }
        cancelTask()
        _state.update { it.copy(planning = null, apiSetupOpen = false, apiSetupError = null) }
        // The system picker temporarily covers this activity. Keep its one pending choice until it
        // returns (but not across composition disposal, navigation, or process recreation).
    }

    fun leaveAgent() {
        screenStopped()
        fileApproval.clear()
        _state.update { it.copy(fileChoiceId = null, plan = null, result = null) }
    }

    private fun takeTaskApproval(id: Long, link: String = ""): AetherTaskApproval.Approved? {
        val current = _state.value
        if (current.busy || current.proposal?.id != id) return null
        val approved = approvals.approve(id, link) ?: return null
        val startedPlan = if (approved.planStep != null) current.plan?.begin(approved) else null
        if ((current.plan != null || approved.planStep != null) && startedPlan == null) {
            _state.update { it.copy(proposal = null, message = "This plan step is no longer ready to run.") }
            return null
        }
        _state.update { it.copy(proposal = null, plan = startedPlan, message = null) }
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
            _state.update {
                it.copy(plan = it.plan?.record(id, AetherGuidedPlan.Attempt.Interrupted()) ?: it.plan,
                    message = "No accessible file was selected. Nothing was scanned.")
            }
        }
    }

    fun cancelTask() {
        val current = _state.value
        if (current.running?.canCancel != true || current.stopping) return
        _state.update { it.copy(stopping = true) }
        taskJob?.cancel()
    }

    fun checkPhone() {
        if (!_state.value.canStart) return
        // This explicit read-only button is a request to run the check, not an AI suggestion.
        val proposal = approvals.propose(AetherSecurityTask.CHECK_PHONE, AetherTaskSource.MANUAL)
        approvals.approve(proposal.id)?.let { runTask(it) }
    }

    private fun runTask(approved: AetherTaskApproval.Approved, chosenFile: Uri? = null) {
        val task = approved.task
        _state.value = _state.value.copy(running = task, progress = null, stopping = false,
            proposal = null, result = null, message = null)
        // Install cancellation handling before dispatching I/O so an immediate stop cannot
        // strand the displayed check (and its plan step) in the running state.
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
                    AetherSecurityTask.SECURITY_REVIEW -> null // Each read has its own deadline and result.
                    AetherSecurityTask.AUDIT_APPS -> AetherSecurityReview.APPS_TIMEOUT_MS
                    AetherSecurityTask.BENCHMARK_DNS -> 15_000L
                    AetherSecurityTask.SCAN_FILE -> 35_000L
                    else -> AetherSecurityReview.PHONE_TIMEOUT_MS
                }
                val result = if (timeout == null) execute() else withTimeout(timeout) { execute() }
                ensureActive()
                finishTask(approved, result)
            } catch (_: TimeoutCancellationException) {
                taskFailed(approved, "The task took too long.")
            } catch (cancelled: CancellationException) {
                val note = if (task == AetherSecurityTask.BENCHMARK_DNS) " Lookups already sent cannot be recalled." else ""
                finishTask(approved, result = null, message = "Check canceled. No new result.$note")
                throw cancelled
            } catch (_: Exception) {
                taskFailed(approved, "The task couldn't finish.")
            }
        }
    }

    private fun finishTask(approved: AetherTaskApproval.Approved, result: AetherTaskResult?, message: String? = null) {
        _state.update { current ->
            val updatedPlan = approved.planStep?.let {
                val attempt = result?.planAttempt() ?: AetherGuidedPlan.Attempt.Interrupted()
                current.plan?.record(approved.id, attempt)
            }
            val stillVisible = approved.planStep == null || updatedPlan != null
            current.copy(running = null, progress = null, stopping = false, plan = updatedPlan ?: current.plan,
                result = if (stillVisible) result else current.result, message = if (stillVisible) message else current.message)
        }
    }

    private fun taskFailed(approved: AetherTaskApproval.Approved, reason: String) {
        val next = when {
            approved.planStep != null -> "No result was recorded for this step. Retry or skip it."
            approved.task == AetherSecurityTask.ENABLE_ALIAS_SHIELD -> "Check the Alias Shield toggle in AdShield Settings to see whether it changed."
            else -> "No result was recorded. Try again."
        }
        finishTask(approved, result = null, message = "$reason $next")
    }
}
