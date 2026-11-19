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
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
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
import com.adshield.pro.engine.aether.AetherSecurityTask as Task
import com.adshield.pro.engine.aether.AetherTaskApproval
import com.adshield.pro.engine.aether.AetherTaskModel
import com.adshield.pro.engine.aether.AetherTaskProgress
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
    val listState = rememberLazyListState()
    val scope = rememberCoroutineScope()
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    var request by remember { mutableStateOf("") }
    var pickerId by remember { mutableStateOf<Long?>(null) }
    var showChecks by remember { mutableStateOf(false) }
    val filePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { chosen ->
        val id = pickerId
        pickerId = null
        if (id != null) viewModel.finishFileChoice(id, chosen)
    }
    DisposableEffect(lifecycle, viewModel) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_STOP) {
                request = ""
                viewModel.screenStopped()
            }
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
        modifier = Modifier.fillMaxSize().testTag("aether-agent-list"),
        state = listState,
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item(key = "agent-controls") {
            AgentCard("AI Agent") {
                Text("Ask for one security check. Suggestions run on this phone with no account or API key.")
                OutlinedTextField(
                    value = request,
                    onValueChange = { if (it.length <= AetherTaskModel.MAX_REQUEST_CHARS) request = it },
                    label = { Text("What should I check?") },
                    placeholder = { Text("Check my phone’s protection") },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = state.canStart,
                    singleLine = true,
                    supportingText = { Text("Task text stays on this phone. You approve every check.") }
                )
                Button(onClick = {
                    viewModel.findTask(request)
                    request = ""
                }, enabled = request.isNotBlank() && state.canStart) { Text("Suggest a check") }
                OutlinedButton(
                    onClick = { viewModel.proposeTool(Task.SECURITY_REVIEW) },
                    enabled = state.canStart,
                    modifier = Modifier.fillMaxWidth()
                ) { Text("Review phone, DNS and apps") }
                TextButton(onClick = { showChecks = !showChecks }, enabled = state.canStart) {
                    Text(if (showChecks) "Hide available checks" else "Choose a check instead")
                }
                if (showChecks) {
                    Task.entries.filter { it != Task.SECURITY_REVIEW }.forEach { task ->
                        TextButton(onClick = { viewModel.proposeTool(task) }, enabled = state.canStart) { Text(task.title) }
                    }
                }
                if (state.findingTask) Text("Finding a check on this phone…")
                if (state.fileChoiceId != null) Text("Waiting for Android’s file picker…")
                state.running?.let { task ->
                    val status = if (state.stopping) "Stopping when the current operation returns…" else when (val progress = state.progress) {
                        AetherTaskProgress.ReviewingSecurity -> "Reviewing phone protection, DNS settings and visible apps…"
                        AetherTaskProgress.ReadingFile -> "Reading the file you chose…"
                        AetherTaskProgress.InspectingFile -> "Inspecting the local copy…"
                        is AetherTaskProgress.ReadingApps -> {
                            val label = if (task == Task.SECURITY_REVIEW) "Security review · apps" else "App audit"
                            if (progress.visible > 0) "$label · ${progress.processed}/${progress.visible} processed"
                            else "$label · reading Android app list…"
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
                    TextButton(onClick = { scope.launch { listState.animateScrollToItem(1) } }) {
                        Text("View latest result")
                    }
                }
            }
        }

        // Results begin immediately after the single controls item.
        val result = state.result
        when (result) {
            is AetherTaskResult.Review -> agentSecurityReviewItems(result.report, ::select, actionsEnabled = state.canStart)
            null, is AetherTaskResult.Phone -> Unit
            else -> item(key = "task-result") { AgentTaskResult(result, ::select, actionsEnabled = state.canStart) }
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
        Task.SECURITY_REVIEW -> "Three on-device specialists check phone protection, saved DNS policy and visible app metadata. It uses the current tunnel’s setup receipt when available, and checks for overlaps between DNS exceptions and app risk indicators. This review won't send data, read private app files or change settings."
        Task.SCAN_FILE -> "Choose one file up to ${AetherFileInput.MAX_MIB} MiB with Android’s file picker. AdShield inspects it locally and won’t launch, install, upload, or change the original."
        Task.SCAN_LINK -> "Analyze one web link on this phone without opening it. Paste only the link you want to check."
        Task.BENCHMARK_DNS -> "Send a lookup for example.com to the built-in resolvers and your custom resolver if selected, using your configured DNS protocol. Your task text is not sent and no resolver setting will change."
        Task.ENABLE_ALIAS_SHIELD -> "Turn on checks for blocked destinations in DNS replies. This changes only AdShield’s Alias Shield setting. You can turn it off in DNS settings."
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(proposal.task.title) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                if (proposal.suggested) Text("Suggested on this phone", style = MaterialTheme.typography.labelMedium)
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
                    else -> "Run check"
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
