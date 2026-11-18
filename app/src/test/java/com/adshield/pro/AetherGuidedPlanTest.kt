package com.adshield.pro

import com.adshield.pro.data.repository.AetherTaskResult
import com.adshield.pro.data.repository.planAttempt
import com.adshield.pro.domain.model.DnsProtocol
import com.adshield.pro.engine.aether.AetherAppReview
import com.adshield.pro.engine.aether.AetherFilePickerApproval
import com.adshield.pro.engine.aether.AetherGuidedPlan as Plan
import com.adshield.pro.engine.aether.AetherPhoneAgent
import com.adshield.pro.engine.aether.AetherPlanRequest as Request
import com.adshield.pro.engine.aether.AetherSecurityReview
import com.adshield.pro.engine.aether.AetherSecurityTask as Task
import com.adshield.pro.engine.aether.AetherTaskApproval
import com.adshield.pro.engine.aether.AetherTaskModel
import com.adshield.pro.engine.aether.AetherTaskSource
import com.adshield.pro.engine.dns.DnsBenchmarkReport
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class AetherGuidedPlanTest {
    private val model by lazy {
        val asset = "app/src/main/assets/aether/task_model.tsv"
        val root = generateSequence(File(requireNotNull(System.getProperty("user.dir"))).absoluteFile) { it.parentFile }
            .first { File(it, asset).isFile }
        AetherTaskModel.read(File(root, asset).reader())
    }

    @Test
    fun shippedModelBuildsOrderedEnglishAndTaglishPlansWithoutChangingSingleTaskBehavior() {
        val requests = mapOf(
            Request.EXAMPLE to listOf(Task.AUDIT_APPS, Task.BENCHMARK_DNS),
            "Audit my apps, and then test DNS speed" to listOf(Task.AUDIT_APPS, Task.BENCHMARK_DNS),
            "Security review; scan a file; then check a link" to listOf(Task.SECURITY_REVIEW, Task.SCAN_FILE, Task.SCAN_LINK),
            "Audit my installed apps\nTest DNS speed" to listOf(Task.AUDIT_APPS, Task.BENCHMARK_DNS),
            "suriin ang seguridad ng cellphone ko tapos audit my installed apps" to listOf(Task.CHECK_PHONE, Task.AUDIT_APPS)
        )
        requests.forEach { (text, tasks) ->
            assertTrue(text, Request.hasSequence(text))
            assertEquals(text, Request.Result.Steps(tasks), Request.build(text, model::suggest))
        }
        val combinedReview = "Check my protection and audit my apps"
        assertFalse(Request.hasSequence(combinedReview))
        assertEquals(Request.Result.Single(Task.SECURITY_REVIEW), Request.build(combinedReview, model::suggest))
        assertEquals(Request.Result.Single(Task.ENABLE_ALIAS_SHIELD), Request.build("Turn on DNS Alias Shield", model::suggest))
    }

    @Test
    fun rejectsTheWholePlanIfAnyStepIsUnclearRestrictedOrChangesSettings() {
        val blocked = listOf(
            "Audit my apps, then delete my files",
            "Audit my apps, then tell me the weather",
            "Audit my apps, then turn on DNS Alias Shield",
            "Turn on DNS Alias Shield, then scan a file",
            "Audit my apps, then don't scan a file",
            "Audit my apps only if Wi-Fi is open, then test DNS speed",
            "Audit my apps, then check a link unless I'm on mobile data",
            "Audit my apps and remove the risky ones, then scan a file",
            "Audit my apps, then audit my apps",
            "Security review, then audit my apps",
            "Audit my apps; scan a file; check a link; test DNS speed",
            "Audit my apps, then",
            "Audit my apps, then " + "x".repeat(240)
        )
        blocked.forEach { text ->
            assertTrue(text, Request.build(text, model::suggest) is Request.Result.Rejected)
        }
        assertTrue(runCatching { Plan.create<String>(1, listOf(Task.ENABLE_ALIAS_SHIELD, Task.AUDIT_APPS)) }.isFailure)
    }

    @Test
    fun aPastedUrlIsNotASeparatorOrATargetAndStillNeedsAnExplicitLink() {
        val text = "Check this link for phishing https://example.invalid/a;still-one-link"
        assertFalse(Request.hasSequence(text))
        assertEquals(Request.Result.Single(Task.SCAN_LINK), Request.build(text, model::suggest))
        val request = Request.build("$text then scan a file", model::suggest) as Request.Result.Steps
        assertEquals(listOf(Task.SCAN_LINK, Task.SCAN_FILE), request.tasks)
        val plan = Plan.create<String>(4, request.tasks)
        val gate = AetherTaskApproval()
        val proposal = gate.propose(Task.SCAN_LINK, AetherTaskSource.GUIDED_PLAN, plan.ref(0))
        assertNull(gate.approve(proposal.id))
        val userLink = "https://example.invalid/actually-selected"
        val approved = requireNotNull(gate.approve(proposal.id, userLink))
        assertEquals(userLink, approved.link)
        assertTrue(plan.begin(approved)?.isActive(0) == true)
        assertNull(gate.approve(proposal.id, userLink))
    }

    @Test
    fun onlyTheMatchingStepApprovalCanStartOrFinishAnAttempt() {
        val tasks = listOf(Task.AUDIT_APPS, Task.BENCHMARK_DNS)
        val plan = Plan.create<String>(1, tasks)
        val gate = AetherTaskApproval()
        val first = plan.ref(0)
        val second = plan.ref(1)
        assertEquals(first, plan.next)
        assertEquals(Task.AUDIT_APPS, plan.taskToReview(first))
        assertNull(plan.taskToReview(second))
        assertNull(plan.skip(second))
        assertNull(plan.begin(approve(gate, Task.BENCHMARK_DNS, second)))
        val ticket = approve(gate, Task.AUDIT_APPS, first)
        assertNull(Plan.create<String>(2, tasks).begin(ticket))
        val active = requireNotNull(plan.begin(ticket))
        assertTrue(active.isActive(0))
        assertNull(active.next)
        assertNull(active.skip(first))
        assertNull(active.record(ticket.id + 1, Plan.Attempt.Completed("wrong")))
        val done = requireNotNull(active.record(ticket.id, Plan.Attempt.Completed("app receipt", limited = true)))
        assertEquals(Plan.Status.LIMITED, done.steps[0].status)
        assertEquals("app receipt", done.receipt(first))
        assertEquals(Plan.Status.WAITING, done.steps[1].status)
        assertEquals(second, done.next)
        assertFalse(done.isActive(1))
        assertNull(done.skip(first))
        assertNull(done.record(ticket.id, Plan.Attempt.Completed("stale")))
        val skipped = requireNotNull(done.skip(second))
        assertEquals(Plan.Status.SKIPPED, skipped.steps[1].status)
        assertEquals("app receipt", skipped.receipt(first))
        assertNull(skipped.next)
    }

    @Test
    fun failedOrCanceledChecksStayOnTheSameStepAndRequireFreshApproval() {
        val plan = Plan.create<String>(10, listOf(Task.SCAN_FILE, Task.AUDIT_APPS))
        val ref = plan.ref(0)
        val gate = AetherTaskApproval()
        val picker = AetherFilePickerApproval()
        val pending = approve(gate, Task.SCAN_FILE, ref)
        val opened = requireNotNull(plan.begin(pending))
        picker.await(pending)
        assertNull(picker.consume(pending.id - 1))
        val canceled = requireNotNull(picker.consume(pending.id))
        assertNull(picker.consume(pending.id))
        val retry = requireNotNull(opened.record(canceled.id, Plan.Attempt.Interrupted()))
        assertEquals(ref, retry.next)
        assertEquals(Plan.Status.RETRY, retry.steps[0].status)
        assertNull(retry.receipt(ref))
        assertNull(retry.begin(pending))
        val fresh = approve(gate, Task.SCAN_FILE, ref)
        val restarted = requireNotNull(retry.begin(fresh))
        assertNull(restarted.record(canceled.id, Plan.Attempt.Completed("late file result")))
        val failed = requireNotNull(restarted.record(fresh.id, Plan.Attempt.Interrupted("file wasn't readable")))
        assertEquals(ref, failed.next)
        assertEquals("file wasn't readable", failed.receipt(ref))
        assertEquals(Plan.Status.WAITING, failed.steps[1].status)
        assertEquals(plan.ref(1), failed.skip(ref)?.next)
    }

    @Test
    fun receiptsDistinguishMissingEvidenceFromCompletedChecksWithLimits() {
        val noApps = AetherTaskResult.Apps(AetherAppReview(1, 0, 0, 0, emptyList()))
        val someApps = AetherTaskResult.Apps(AetherAppReview(3, 2, 0, 0, emptyList()))
        val missing = AetherSecurityReview.Reading.Missing(AetherSecurityReview.MissingReason.FAILED)
        val noReview = AetherTaskResult.Review(AetherSecurityReview.Report(missing, missing, 50))
        val phone = AetherPhoneAgent.Report(10L, emptyList(), emptyList())
        val partialReview = AetherTaskResult.Review(AetherSecurityReview.Report(AetherSecurityReview.Reading.Received(phone), missing, 50))
        val dns = AetherTaskResult.Dns(DnsBenchmarkReport("example.com", DnsProtocol.DOH, 50, emptyList()))
        listOf(noApps, noReview, AetherTaskResult.FileTooLarge, AetherTaskResult.FileUnavailable).forEach {
            assertEquals(Plan.Attempt.Interrupted(it), it.planAttempt())
        }
        listOf(someApps, partialReview, dns).forEach {
            assertEquals(Plan.Attempt.Completed(it, limited = true), it.planAttempt())
        }
        val full = AetherTaskResult.Phone(phone)
        assertEquals(Plan.Attempt.Completed(full), full.planAttempt())
    }

    private fun approve(gate: AetherTaskApproval, task: Task, ref: Plan.Ref): AetherTaskApproval.Approved {
        return requireNotNull(gate.approve(gate.propose(task, AetherTaskSource.GUIDED_PLAN, ref).id))
    }
}
