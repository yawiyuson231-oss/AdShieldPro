package com.adshield.pro.engine.aether

import java.text.Normalizer

/** Compose explicit task clauses locally. An unclear, unsupported, or overlapping step rejects the whole plan. */
internal object AetherPlanRequest {
    const val MAX_STEPS = 3
    const val EXAMPLE = "Audit my apps, then test DNS speed"
    private val separator = Regex("""(?i)(?:\s*[,;]\s*|\s+)(?:(?:and|at)[ \t]+)?(?:then|tapos)\b[\s,:]*|[;\r\n]+""")
    private val inlineLink = Regex("""(?i)\b(?:https?://|www\.)\S+""")
    private val qualifiers = Regex(
        """\b(if|unless|until|else|otherwise|when|while|before|after|kung|kapag|pag|only|just|except|without|excluding|skip|avoid|not|never|no|wag|huwag|ayaw|lang|lamang)\b|n't\b"""
    )
    private val extraAction = Regex(
        """\b(and|at|also|or|plus|saka|atsaka) (?:also )?(check|scan|audit|test|review|inspect|run|turn|enable|disable|open|visit|delete|remove|install|uninstall|upload|download|reset|restart|change)\b"""
    )
    private val allowed = setOf(
        AetherSecurityTask.CHECK_PHONE, AetherSecurityTask.AUDIT_APPS, AetherSecurityTask.SECURITY_REVIEW,
        AetherSecurityTask.SCAN_LINK, AetherSecurityTask.SCAN_FILE, AetherSecurityTask.BENCHMARK_DNS
    )

    sealed interface Result {
        data class Single(val task: AetherSecurityTask?) : Result
        data class Steps(val tasks: List<AetherSecurityTask>) : Result
        data class Rejected(val message: String) : Result
    }

    fun hasSequence(request: String): Boolean = request.length <= AetherTaskModel.MAX_REQUEST_CHARS &&
        separator.containsMatchIn(normalized(request))

    fun build(request: String, suggest: (String) -> AetherSecurityTask?): Result {
        if (request.length > AetherTaskModel.MAX_REQUEST_CHARS) {
            return Result.Rejected("Use at most ${AetherTaskModel.MAX_REQUEST_CHARS} characters. No steps ran.")
        }
        val parts = separator.split(normalized(request), limit = MAX_STEPS + 1).map(String::trim)
        if (parts.size == 1) return Result.Single(suggest(request))
        if (parts.size > MAX_STEPS || parts.any(String::isBlank)) {
            return Result.Rejected("Use two or three complete checks separated by ‘then’. No steps ran.")
        }
        val tasks = parts.mapIndexed { index, clause ->
            val tokens = AetherTaskPolicy.tokens(clause)
            val words = tokens.joinToString(" ")
            val step = index + 1
            if (!AetherTaskPolicy.isAffirmativeRequest(tokens) || qualifiers.containsMatchIn(words) || extraAction.containsMatchIn(words)) {
                return Result.Rejected("Step $step needs to be one unconditional check. Use ‘then’ between checks. No steps ran.")
            }
            val task = suggest(clause)?.takeIf { AetherTaskPolicy.allows(it, tokens) }
                ?: return Result.Rejected("I couldn't match step $step to a supported check. No steps ran.")
            if (task !in allowed) return Result.Rejected("Guided plans don't change settings. Request the setting change separately. No steps ran.")
            task
        }
        if (!isAllowedPlan(tasks)) {
            return Result.Rejected("Use different checks. Security review already includes a phone check and an app audit. No steps ran.")
        }
        return Result.Steps(tasks)
    }

    fun isAllowedPlan(tasks: List<AetherSecurityTask>): Boolean =
        tasks.size in 2..MAX_STEPS && tasks.toSet().size == tasks.size && tasks.all { it in allowed } &&
            (AetherSecurityTask.SECURITY_REVIEW !in tasks ||
                (AetherSecurityTask.CHECK_PHONE !in tasks && AetherSecurityTask.AUDIT_APPS !in tasks))

    // A URL can contain semicolons. Its contents aren't a step or a target for the plan.
    private fun normalized(request: String) = inlineLink.replace(Normalizer.normalize(request, Normalizer.Form.NFKC), " link ").trim()
}

/** In-memory receipts and one active attempt. No tool calls, targets, or automatic next-step dispatch. */
internal class AetherGuidedPlan<R : Any> private constructor(
    val id: Long,
    val steps: List<Step<R>>,
    private val activeIndex: Int? = null,
    private val lastApproval: Long = 0
) {
    data class Ref(val planId: Long, val index: Int)
    data class Step<R : Any>(val task: AetherSecurityTask, val status: Status = Status.WAITING, val receipt: R? = null)

    enum class Status(val label: String, val resolved: Boolean) {
        WAITING("Waiting", false), RETRY("Needs retry or skip", false), DONE("Check finished", true),
        LIMITED("Finished with limits", true), SKIPPED("Skipped", true)
    }

    sealed interface Attempt<out R : Any> {
        data class Completed<R : Any>(val receipt: R, val limited: Boolean = false) : Attempt<R>
        data class Interrupted<R : Any>(val receipt: R? = null) : Attempt<R>
    }

    val next: Ref? get() = if (activeIndex != null) null else steps.indexOfFirst { !it.status.resolved }
        .takeIf { it >= 0 }?.let { Ref(id, it) }

    fun ref(index: Int): Ref = Ref(id, index)
    fun isActive(index: Int): Boolean = activeIndex == index
    fun taskToReview(ref: Ref): AetherSecurityTask? = if (next == ref) steps[ref.index].task else null

    fun begin(approval: AetherTaskApproval.Approved): AetherGuidedPlan<R>? {
        val ref = approval.planStep ?: return null
        if (taskToReview(ref) != approval.task || approval.id <= lastApproval) return null
        return AetherGuidedPlan(id, steps, activeIndex = ref.index, lastApproval = approval.id)
    }

    fun record(approvalId: Long, attempt: Attempt<R>): AetherGuidedPlan<R>? {
        val index = activeIndex ?: return null
        if (approvalId != lastApproval) return null
        val step = steps[index]
        val updated = when (attempt) {
            is Attempt.Completed -> step.copy(status = if (attempt.limited) Status.LIMITED else Status.DONE, receipt = attempt.receipt)
            is Attempt.Interrupted -> step.copy(status = Status.RETRY, receipt = attempt.receipt)
        }
        return replace(index, updated)
    }

    fun skip(ref: Ref): AetherGuidedPlan<R>? = if (next == ref) {
        replace(ref.index, steps[ref.index].copy(status = Status.SKIPPED))
    } else null

    fun receipt(ref: Ref): R? = if (ref.planId == id) steps.getOrNull(ref.index)?.receipt else null

    private fun replace(index: Int, step: Step<R>) = AetherGuidedPlan(
        id, steps.mapIndexed { i, before -> if (i == index) step else before }, lastApproval = lastApproval
    )

    companion object {
        fun <R : Any> create(id: Long, tasks: List<AetherSecurityTask>): AetherGuidedPlan<R> {
            require(AetherPlanRequest.isAllowedPlan(tasks)) { "Invalid guided plan" }
            return AetherGuidedPlan(id, tasks.map { Step<R>(it) })
        }
    }
}
