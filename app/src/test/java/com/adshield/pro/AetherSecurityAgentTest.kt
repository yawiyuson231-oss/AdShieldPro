package com.adshield.pro

import com.adshield.pro.engine.aether.AetherSecurityTask as Task
import com.adshield.pro.engine.aether.AetherTaskApproval
import com.adshield.pro.engine.aether.AetherTaskModel
import com.adshield.pro.engine.security.UrlThreatScanner
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class AetherSecurityAgentTest {
    private val root = generateSequence(File(requireNotNull(System.getProperty("user.dir"))).absoluteFile) { it.parentFile }
        .first { File(it, "tools/aether_agent/holdout.tsv").isFile }
    private val model by lazy {
        AetherTaskModel.read(File(root, "app/src/main/assets/aether/task_model.tsv").reader())
    }

    @Test
    fun shippedModelMakesUsefulSuggestionsForEverySupportedTask() {
        val requests = mapOf(
            "Check my phone’s protection" to Task.CHECK_PHONE,
            "Audit my apps for risky permissions" to Task.AUDIT_APPS,
            "Audit my apps" to Task.AUDIT_APPS,
            "Check a link" to Task.SCAN_LINK,
            "Test DNS speed" to Task.BENCHMARK_DNS,
            "Turn on DNS Alias Shield" to Task.ENABLE_ALIAS_SHIELD,
            "Security review" to Task.SECURITY_REVIEW,
            "Check my protection and audit my apps" to Task.SECURITY_REVIEW,
            "Scan a file" to Task.SCAN_FILE,
            "pacheck kung scam ang website link" to Task.SCAN_LINK
        )
        requests.forEach { (request, task) -> assertEquals(request, task, model.suggest(request)) }
    }

    @Test
    fun shippedModelMatchesHoldoutWithoutWrongTaskSuggestions() {
        val matches = mutableMapOf<Task, Int>()
        var unsupported = 0
        var supported = 0
        File(root, "tools/aether_agent/holdout.tsv").forEachLine { line ->
            val (label, request) = line.split('\t', limit = 2)
            val suggested = model.suggest(request)
            if (label != "UNSUPPORTED") supported++
            if (label == "UNSUPPORTED") {
                assertNull(request, suggested)
                unsupported++
            } else if (suggested != null) {
                assertEquals(request, Task.valueOf(label), suggested)
                matches[suggested] = (matches[suggested] ?: 0) + 1
            }
        }
        assertEquals(70, supported)
        assertEquals(24, unsupported)
        assertTrue(supported - matches.values.sum() <= 9)
        assertTrue(Task.entries.all { (matches[it] ?: 0) >= 7 })
    }

    @Test
    fun declinesNegatedRequestsAndDoesNotConvertStatusQuestionToSettingChange() {
        listOf("", "Please don’t audit my installed apps", "Avoid scanning a link", "is the alias shield turned on already",
            "do not enable cname protection", "don't turn on dns alias shield", "how do I enable alias shield", "restart my phone", "test dns " + "a".repeat(240)
        ).forEach { assertNull(it, model.suggest(it)) }
    }

    @Test
    fun multiStepRequestsDoNotProposePartialChecks() {
        listOf(
            "Audit my apps, then test DNS speed",
            "Pacheck ang link, tapos i-scan itong file",
            "Test DNS speed; turn on DNS Alias Shield",
            "Audit my apps\nCheck a link"
        ).forEach { assertNull(it, model.suggest(it)) }
        assertEquals(Task.SCAN_LINK, model.suggest("Check a link https://example.com/a;b"))
    }

    @Test
    fun securityReviewDoesNotOverrideNarrowerScopeOrAuthorizeAFollowUp() {
        listOf("Security review without DNS", "Security review but only check my protection",
            "Security review, then test DNS speed").forEach { request ->
            assertTrue(model.suggest(request) != Task.SECURITY_REVIEW)
        }
        val approval = AetherTaskApproval()
        val review = approval.propose(Task.SECURITY_REVIEW, suggested = true)
        val approved = requireNotNull(approval.approve(review.id, "https://example.invalid"))
        assertEquals(Task.SECURITY_REVIEW, approved.task)
        assertNull(approved.link)
        val benchmark = approval.propose(Task.BENCHMARK_DNS)
        assertNull(approval.approve(review.id))
        assertEquals(Task.BENCHMARK_DNS, approval.approve(benchmark.id)?.task)
    }

    @Test
    fun gatedTaskCanOnlyBeApprovedOnceAndNotAfterDismissalOrReplacement() {
        val approval = AetherTaskApproval()
        val task = requireNotNull(model.suggest("Turn on DNS Alias Shield"))
        val cancelled = approval.propose(task, suggested = true)
        assertNull(approval.approve(cancelled.id + 1))
        approval.dismiss(cancelled.id)
        assertNull(approval.approve(cancelled.id))
        val old = approval.propose(task, suggested = true)
        val next = approval.propose(Task.BENCHMARK_DNS)
        assertNull(approval.approve(old.id))
        assertEquals(Task.BENCHMARK_DNS, approval.approve(next.id, "https://example.invalid")?.task)
        assertNull(approval.approve(next.id))
        assertNull(approval.pending)
    }

    @Test
    fun realLocalScannerReceivesOnlyAnExplicitlyApprovedLink() {
        val task = requireNotNull(model.suggest("Check this link for phishing https://example.invalid"))
        assertEquals(Task.SCAN_LINK, task)
        val approval = AetherTaskApproval()
        val plan = approval.propose(task, suggested = true)
        assertNull(approval.approve(plan.id)) // Nothing can be taken from the prompt.
        assertNull(approval.approve(plan.id, "file:///secret"))
        assertNull(approval.approve(plan.id, "ftp://example.com"))
        assertFalse(AetherTaskApproval.isLinkInput("https://one.example https://two.example"))
        val explicitLink = "http://192.0.2.1/login/verify" // Reserved documentation IP, never opened.
        val approved = requireNotNull(approval.approve(plan.id, explicitLink))
        val result = UrlThreatScanner().scan(requireNotNull(approved.link))
        assertEquals(explicitLink, approved.link)
        assertEquals("192.0.2.1", result.normalizedHost)
        assertEquals(UrlThreatScanner.ThreatLevel.SUSPICIOUS, result.threatLevel)
        assertTrue(result.findings.any { "Raw IP" in it })
    }

    @Test
    fun invalidWeightsFailClosedInsteadOfPretendingTheModelRan() {
        val badModels = listOf(
            "",
            "aether-intent-v1\tSHELL_COMMAND\n",
            "aether-intent-v2\tCHECK_PHONE\tAUDIT_APPS\tSCAN_LINK\tBENCHMARK_DNS\tENABLE_ALIAS_SHIELD\tSECURITY_REVIEW\tSCAN_FILE\tUNSUPPORTED\n" +
                "@bias\tNaN\t0\t0\t0\t0\t0\t0\t0\n"
        )
        badModels.forEach { assertTrue(runCatching { AetherTaskModel.read(it.reader()) }.isFailure) }
    }
}
