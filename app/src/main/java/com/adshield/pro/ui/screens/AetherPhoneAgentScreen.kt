package com.adshield.pro.ui.screens

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.adshield.pro.data.repository.AetherTaskResult
import com.adshield.pro.engine.aether.AetherFileInput
import com.adshield.pro.engine.aether.AetherPhoneAgent as Agent
import com.adshield.pro.engine.aether.AetherPlanRequest
import com.adshield.pro.engine.aether.AetherSecurityTask as Task
import com.adshield.pro.engine.aether.AetherTaskApproval
import com.adshield.pro.engine.aether.AetherTaskModel
import com.adshield.pro.engine.aether.AetherTaskProgress
import com.adshield.pro.engine.aether.AetherTaskSource
import com.adshield.pro.ui.viewmodel.AetherPhoneAgentViewModel
import kotlinx.coroutines.launch
import java.text.DateFormat
import java.util.Date

@Composable
internal fun AetherPhoneAgentScreen(
    onTool: (Agent.Tool) -> Unit,
    viewModel: AetherPhoneAgentViewModel = hiltViewModel()
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val plan = state.plan
    val resultIndex = if (plan == null) 2 else 1
    val listState = rememberLazyListState()
    val scope = rememberCoroutineScope()
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    var request by remember { mutableStateOf("") }
    var pickerId by remember { mutableStateOf<Long?>(null) }
    LaunchedEffect(plan?.id) {
        if (plan != null) listState.scrollToItem(0)
    }
    val filePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { chosen ->
        val id = pickerId
        pickerId = null
        if (id != null) viewModel.finishFileChoice(id, chosen)
    }
    DisposableEffect(lifecycle, viewModel) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_STOP) viewModel.screenStopped()
        }
        lifecycle.addObserver(observer)
        onDispose {
            lifecycle.removeObserver(observer)
            viewModel.leaveAgent()
        }
    }

    fun select(tool: Agent.Tool) {
        when (tool) {
            Agent.Tool.APP_AUDIT -> viewModel.proposeTool(Task.AUDIT_APPS)
            Agent.Tool.FILE_SCAN -> viewModel.proposeTool(Task.SCAN_FILE)
            Agent.Tool.LINK_SCAN -> viewModel.proposeTool(Task.SCAN_LINK)
            Agent.Tool.DNS_BENCHMARK -> viewModel.proposeTool(Task.BENCHMARK_DNS)
            Agent.Tool.ENABLE_ALIAS_SHIELD -> viewModel.proposeTool(Task.ENABLE_ALIAS_SHIELD)
            else -> onTool(tool)
        }
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        state = listState,
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item(key = "agent-controls") {
            AgentCard(if (plan == null) "AETHER Security Agent" else "AETHER guided plan") {
                if (plan == null) {
                    Text("Check your phone and apps together, or request a guided plan of up to three steps.")
                    Button(onClick = { viewModel.proposeTool(Task.SECURITY_REVIEW) }, enabled = state.canStart) {
                        Text("Security review")
                    }
                    Text("Checks protection and app risks without changing settings.", style = MaterialTheme.typography.bodySmall)
                    OutlinedButton(onClick = { viewModel.proposeTool(Task.SCAN_FILE) }, enabled = state.canStart) {
                        Text("Scan a file")
                    }
                    OutlinedTextField(
                        value = request,
                        onValueChange = { if (it.length <= AetherTaskModel.MAX_REQUEST_CHARS) request = it },
                        label = { Text("What should I check?") },
                        placeholder = { Text(AetherPlanRequest.EXAMPLE) },
                        modifier = Modifier.fillMaxWidth(),
                        enabled = state.canStart,
                        maxLines = 3,
                        supportingText = { Text("Use ‘then’ between checks. Choose any file or link when you review that step.") }
                    )
                    if (state.api != null) {
                        Button(onClick = { viewModel.reviewOnlineRequest(request) }, enabled = request.isNotBlank() && state.canUseApi) {
                            Text("Ask online AI")
                        }
                        OutlinedButton(onClick = { viewModel.findTask(request) }, enabled = request.isNotBlank() && state.canStart) {
                            Text("Find task offline")
                        }
                    } else {
                        Button(onClick = { viewModel.findTask(request) }, enabled = request.isNotBlank() && state.canStart) {
                            Text("Find task offline")
                        }
                    }
                    OutlinedButton(onClick = viewModel::checkPhone, enabled = state.canStart) { Text("Check my phone") }
                    TextButton(onClick = {
                        request = AetherPlanRequest.EXAMPLE
                        viewModel.findTask(request)
                    }, enabled = state.canStart) { Text("Try a guided plan") }
                } else {
                    AetherGuidedPlanSteps(
                        plan = plan,
                        enabled = state.canUsePlan,
                        onReview = viewModel::reviewPlanStep,
                        onSkip = viewModel::skipPlanStep,
                        onReceipt = { ref ->
                            if (viewModel.showPlanReceipt(ref)) listState.requestScrollToItem(resultIndex)
                        },
                        onClose = { viewModel.closePlan(plan.id) }
                    )
                }
                when (state.planning) {
                    AetherTaskSource.ONLINE_API -> {
                        Text("Waiting for the AI API…")
                        TextButton(onClick = viewModel::stopOnlineRequest) { Text("Stop waiting") }
                    }
                    AetherTaskSource.OFFLINE_MODEL -> Text("Finding supported checks on this phone…")
                    else -> Unit
                }
                if (state.fileChoiceId != null) Text("Waiting for Android’s file picker…")
                state.running?.let { task ->
                    val status = if (state.stopping) "Stopping when the current operation returns…" else when (val progress = state.progress) {
                        AetherTaskProgress.ReadingPhone -> "Review step 1 of 2: checking protection, connection and device readings…"
                        AetherTaskProgress.ReadingFile -> "Reading the file you chose…"
                        AetherTaskProgress.InspectingFile -> "Inspecting the local copy…"
                        is AetherTaskProgress.ReadingApps -> {
                            val label = if (task == Task.SECURITY_REVIEW) "Review step 2 of 2: app audit" else "App audit"
                            if (progress.visible > 0) "$label · ${progress.processed}/${progress.visible} processed" else "$label · reading Android app list…"
                        }
                        null -> "Running: ${task.title}…"
                    }
                    Text(status, color = MaterialTheme.colorScheme.primary)
                    if (task.canCancel) {
                        TextButton(onClick = viewModel::cancelTask, enabled = !state.stopping) { Text("Cancel check") }
                    }
                }
                state.message?.let { Text(it, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                if (state.result != null) {
                    TextButton(onClick = { scope.launch { listState.animateScrollToItem(resultIndex) } }) {
                        Text(if (plan == null) "View latest result" else "View selected result")
                    }
                }
            }
        }

        if (plan == null) {
            item(key = "agent-connection") {
                AgentCard("Online AI connection") {
                    val endpoint = state.api
                    if (state.apiStorageBusy && endpoint == null) {
                        Text("Loading saved API settings…")
                    } else if (endpoint == null) {
                        Text("Optional. Use Gemini, OpenAI, or another compatible API. The offline model still works without a key.")
                    } else {
                        Text("${endpoint.provider.label} · ${endpoint.model}", style = MaterialTheme.typography.titleSmall)
                        Text(state.apiStatus ?: "Saved, not tested. Tap Test API to check this model.")
                        TextButton(onClick = viewModel::reviewApiTest, enabled = state.canUseApi) { Text("Test API") }
                    }
                    TextButton(onClick = viewModel::openApiSetup, enabled = state.canUseApi) {
                        Text(if (endpoint == null) "Connect AI API" else "AI API settings")
                    }
                }
            }
        }

        // Plan receipts follow the plan card; standalone results follow the API card.
        val result = state.result
        if (result != null && plan != null) {
            item(key = "back-to-plan") {
                TextButton(onClick = { scope.launch { listState.animateScrollToItem(0) } }) { Text("Back to guided plan") }
            }
        }
        if (result != null && result !is AetherTaskResult.Phone) {
            item(key = "task-result") { AgentTaskResult(result, onTool) }
        }
        val phone = when (result) {
            is AetherTaskResult.Phone -> result.report
            is AetherTaskResult.Review -> result.report.phone.value
            else -> null
        }
        phone?.let { report ->
            item(key = "phone-result") {
                AgentCard("Phone check results") {
                    val checkedAt = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(Date(report.capturedAtMs))
                    Text("Checked $checkedAt. Check again after changing settings or networks.", style = MaterialTheme.typography.bodySmall)
                    if (report.hasUnavailableReadings) Text("Some readings were not available. See the details below.")
                    if (report.findings.isEmpty()) {
                        Text("No issues flagged in the available readings. This isn't a full-device scan.")
                    }
                }
            }
            items(report.findings, key = { "finding:${it.title}" }) { finding ->
                AgentCard(finding.title) {
                    Text(finding.priority.label, style = MaterialTheme.typography.labelLarge,
                        color = if (finding.priority == Agent.Priority.ATTENTION) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary)
                    Text(finding.evidence)
                    OutlinedButton(onClick = { select(finding.nextTool) }, enabled = state.canStart) { Text(finding.nextTool.label) }
                }
            }
            items(report.sections, key = { "section:${it.title}" }) { section ->
                AgentCard(section.title) {
                    section.readings.forEach { Text(it, style = MaterialTheme.typography.bodyMedium) }
                }
            }
        }
        if (plan == null) {
            item {
                AgentCard("Choose a tool yourself") {
                    Text("These tools work offline without typing a request, except the optional DNS benchmark.")
                    listOf(
                        Agent.Tool.APP_AUDIT, Agent.Tool.LINK_SCAN, Agent.Tool.DNS_BENCHMARK, Agent.Tool.ENABLE_ALIAS_SHIELD,
                        Agent.Tool.SCAN_HISTORY, Agent.Tool.DNS_ACTIVITY, Agent.Tool.NETWORK_SETTINGS,
                        Agent.Tool.OPTIMIZER, Agent.Tool.BATTERY
                    ).forEach { tool ->
                        TextButton(onClick = { select(tool) }, enabled = state.canStart) { Text(tool.label) }
                    }
                }
            }
        }

        item {
            Text(
                "Offline requests stay on the phone. Online AI receives only the task description you approve, not the app list, scan results or saved activity. " +
                    "AdShield's tools supply the results.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }

    if (state.apiSetupOpen) {
        AetherApiSetupDialog(
            endpoint = state.api,
            saving = state.apiStorageBusy,
            error = state.apiSetupError,
            onSave = viewModel::saveApi,
            onDisconnect = viewModel::disconnectApi,
            onDismiss = viewModel::closeApiSetup
        )
    }
    state.sendReview?.let { review ->
        AetherApiReviewDialog(review, onSend = { viewModel.sendOnline(review.id) }, onDismiss = { viewModel.dismissSend(review.id) })
    }
    state.proposal?.let { proposal ->
        AgentTaskDialog(
            proposal = proposal,
            onApprove = { link ->
                if (proposal.task != Task.SCAN_FILE) {
                    viewModel.approveTask(proposal.id, link)
                } else if (viewModel.beginFileChoice(proposal.id)) {
                    pickerId = proposal.id
                    try {
                        filePicker.launch(arrayOf("*/*"))
                    } catch (_: Exception) {
                        pickerId = null
                        viewModel.finishFileChoice(proposal.id, null)
                    }
                }
            },
            onDismiss = { viewModel.dismissProposal(proposal.id) }
        )
    }
}

@Composable
private fun AgentTaskDialog(proposal: AetherTaskApproval.Proposal, onApprove: (String) -> Unit, onDismiss: () -> Unit) {
    var link by remember(proposal.id) { mutableStateOf("") }
    val details = when (proposal.task) {
        Task.CHECK_PHONE -> "Read current protection, Wi-Fi, DNS activity and device-health readings. Nothing will change."
        Task.AUDIT_APPS -> "Check permissions and install sources of apps Android lets AdShield see. This won't read private app files or remove anything."
        Task.SECURITY_REVIEW -> "Run two read-only checks: phone protection, connection and device readings; then permissions and install sources of visible apps. No settings will change and no network test will run."
        Task.SCAN_FILE -> "Choose one file up to ${AetherFileInput.MAX_MIB} MiB with Android’s file picker. AdShield inspects it locally and won’t launch, install, upload, or change the original."
        Task.SCAN_LINK -> "Analyze one web link on this phone without opening it. Paste only the link you want to check."
        Task.BENCHMARK_DNS -> "Send a lookup for example.com to the built-in resolvers and your custom resolver if selected, using your configured DNS protocol. No resolver setting will change."
        Task.ENABLE_ALIAS_SHIELD -> "Turn on checks for blocked destinations in DNS replies. This changes only AdShield’s Alias Shield setting. You can turn it off in DNS settings."
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(proposal.task.title) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                when (proposal.source) {
                    AetherTaskSource.ONLINE_API -> Text("Task suggested by online AI", style = MaterialTheme.typography.labelMedium)
                    AetherTaskSource.OFFLINE_MODEL -> Text("Task suggested by on-device AI", style = MaterialTheme.typography.labelMedium)
                    AetherTaskSource.GUIDED_PLAN -> Text("Guided plan · Step ${requireNotNull(proposal.planStep).index + 1}",
                        style = MaterialTheme.typography.labelMedium)
                    AetherTaskSource.MANUAL -> Unit
                }
                Text(details)
                if (proposal.task == Task.SCAN_LINK) {
                    OutlinedTextField(
                        value = link,
                        onValueChange = { if (it.length <= AetherTaskApproval.MAX_LINK_CHARS) link = it },
                        label = { Text("Web link") },
                        placeholder = { Text("https://example.com") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri)
                    )
                }
            }
        },
        confirmButton = {
            TextButton(onClick = { onApprove(link) }, enabled = proposal.task != Task.SCAN_LINK || AetherTaskApproval.isLinkInput(link)) {
                Text(when (proposal.task) {
                    Task.ENABLE_ALIAS_SHIELD -> "Turn on"
                    Task.SCAN_FILE -> "Choose file"
                    Task.SECURITY_REVIEW -> "Run review"
                    else -> "Run task"
                })
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } }
    )
}

@Composable
internal fun AgentCard(title: String, content: @Composable () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium)
            content()
        }
    }
}
