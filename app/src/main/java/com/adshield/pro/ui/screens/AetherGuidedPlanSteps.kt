package com.adshield.pro.ui.screens

import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import com.adshield.pro.data.repository.AetherTaskResult
import com.adshield.pro.engine.aether.AetherGuidedPlan
import com.adshield.pro.engine.aether.AetherSecurityTask

@Composable
internal fun AetherGuidedPlanSteps(
    plan: AetherGuidedPlan<AetherTaskResult>,
    enabled: Boolean,
    onReview: (AetherGuidedPlan.Ref) -> Unit,
    onSkip: (AetherGuidedPlan.Ref) -> Unit,
    onReceipt: (AetherGuidedPlan.Ref) -> Unit,
    onClose: () -> Unit
) {
    val finished = plan.steps.count { it.status == AetherGuidedPlan.Status.DONE || it.status == AetherGuidedPlan.Status.LIMITED }
    val skipped = plan.steps.count { it.status == AetherGuidedPlan.Status.SKIPPED }
    val next = plan.next
    Text("${plan.steps.size} steps · $finished finished · $skipped skipped", style = MaterialTheme.typography.labelLarge)
    Text("Approve each check separately. The plan doesn't change settings or send your results to AI.")
    plan.steps.forEachIndexed { index, step ->
        val ref = plan.ref(index)
        HorizontalDivider()
        Text("${index + 1}. ${step.task.title}", style = MaterialTheme.typography.titleSmall)
        val status = when {
            plan.isActive(index) -> "In progress"
            step.status == AetherGuidedPlan.Status.WAITING && next == ref -> "Ready for your review"
            else -> step.status.label
        }
        Text("$status · ${step.task.planScope()}", style = MaterialTheme.typography.bodySmall)
        step.receipt?.let { receipt ->
            receipt.preview()?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
            TextButton(onClick = { onReceipt(ref) }, enabled = enabled) { Text("View step ${index + 1} result") }
        }
    }
    HorizontalDivider()
    if (next != null) {
        val step = next.index + 1
        val retry = plan.steps[next.index].status == AetherGuidedPlan.Status.RETRY
        Button(onClick = { onReview(next) }, enabled = enabled) {
            Text(if (retry) "Review retry for step $step" else "Review step $step")
        }
        TextButton(onClick = { onSkip(next) }, enabled = enabled) { Text("Skip step $step") }
    } else if (finished + skipped == plan.steps.size) {
        Text("No more steps. Results are available until you close the plan or leave the Agent.")
    }
    TextButton(onClick = onClose, enabled = enabled) {
        Text(if (finished + skipped == plan.steps.size) "Close plan" else "End plan")
    }
}

private fun AetherTaskResult.preview(): String? = when (this) {
    is AetherTaskResult.Phone -> "${report.findings.size} findings in the available phone readings"
    is AetherTaskResult.Apps -> "${review.inspected}/${review.visible} visible apps inspected · ${review.needsReview} flagged for review"
    is AetherTaskResult.Review -> report.apps.value?.let { "${it.inspected}/${it.visible} visible apps inspected" }
        ?: "App readings unavailable"
    is AetherTaskResult.Dns -> "${report.reachableCount}/${report.entries.size} resolvers returned usable replies"
    is AetherTaskResult.ScannedFile -> "${record.findings.size} static indicators in the checks that ran"
    AetherTaskResult.FileTooLarge -> "File too large; nothing scanned"
    AetherTaskResult.FileUnavailable -> "File couldn't be read; nothing scanned"
    is AetherTaskResult.Link, AetherTaskResult.AliasShieldOn -> null
}

private fun AetherSecurityTask.planScope() = when (this) {
    AetherSecurityTask.CHECK_PHONE -> "Local phone and protection readings"
    AetherSecurityTask.AUDIT_APPS -> "Visible app metadata only"
    AetherSecurityTask.SECURITY_REVIEW -> "Local phone check and app audit"
    AetherSecurityTask.SCAN_LINK -> "You enter a link; it won't open"
    AetherSecurityTask.SCAN_FILE -> "You choose one file"
    AetherSecurityTask.BENCHMARK_DNS -> "Network test using example.com"
    AetherSecurityTask.ENABLE_ALIAS_SHIELD -> "Unavailable in a plan"
}
