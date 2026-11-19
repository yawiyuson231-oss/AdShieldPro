package com.adshield.pro.engine.aether

import java.io.Reader
import java.net.URI
import java.text.Normalizer
import java.util.Locale
import kotlin.math.abs
import kotlin.math.exp
import kotlin.math.sqrt

internal enum class AetherSecurityTask(val title: String, val canCancel: Boolean = false) {
    CHECK_PHONE("Check phone protection", canCancel = true),
    AUDIT_APPS("Audit installed apps", canCancel = true),
    SCAN_LINK("Check a link for phishing", canCancel = true),
    BENCHMARK_DNS("Test DNS response times", canCancel = true),
    ENABLE_ALIAS_SHIELD("Turn on DNS Alias Shield"),
    SECURITY_REVIEW("Security review", canCancel = true),
    SCAN_FILE("Scan a file", canCancel = true)
}

/**
 * Offline inference with learned softmax weights (see tools/train_aether_tasks.py). The only
 * possible prediction is a task label, not instructions, target data, or a security verdict.
 */
internal class AetherTaskModel private constructor(
    private val bias: DoubleArray,
    private val weights: Map<String, DoubleArray>
) {
    fun suggest(request: String): AetherSecurityTask? {
        if (request.length > MAX_REQUEST_CHARS || AetherTaskPolicy.isSequence(request)) return null
        val tokens = AetherTaskPolicy.tokens(request)
        if (tokens.size < 2 || !AetherTaskPolicy.isAffirmativeRequest(tokens)) return null
        val features = buildSet {
            addAll(tokens)
            for (i in 1 until tokens.size) add("${tokens[i - 1]}_${tokens[i]}")
            for (token in tokens) {
                val padded = "^$token$"
                for (i in 0..padded.length - 5) add("~${padded.substring(i, i + 5)}")
            }
        }
        val scores = bias.copyOf()
        val norm = sqrt(features.size.toDouble())
        var matched = 0
        for (name in features.sorted()) {
            val coefficients = weights[name] ?: continue
            matched++
            for (i in scores.indices) scores[i] += coefficients[i] / norm
        }
        if (matched < 2) return null
        val ranked = scores.indices.sortedByDescending { scores[it] }
        val best = ranked[0]
        val task = AetherSecurityTask.entries.getOrNull(best) ?: return null // Trained UNSUPPORTED class
        val peak = scores[best]
        val total = scores.sumOf { exp(it - peak) }
        val probability = 1.0 / total
        val gap = probability - exp(scores[ranked[1]] - peak) / total
        if (probability < 0.60 || gap < 0.28) return null
        return task.takeIf { AetherTaskPolicy.allows(it, tokens) }
    }

    companion object {
        const val MAX_REQUEST_CHARS = 240
        private const val MAX_FEATURES = 5_000
        private val header = listOf("aether-intent-v2") + AetherSecurityTask.entries.map { it.name } + "UNSUPPORTED"

        /** Load the versioned asset from the signed APK; corrupt/missing weights are an error. */
        fun read(reader: Reader): AetherTaskModel = reader.buffered().use { input ->
            require(input.readLine()?.split('\t') == header) { "Unknown AETHER model format" }
            val table = HashMap<String, DoubleArray>()
            input.lineSequence().forEach { line ->
                val columns = line.split('\t')
                require(columns.size == header.size && table.size <= MAX_FEATURES)
                val coefficients = DoubleArray(header.size - 1) { i ->
                    columns[i + 1].toDouble().also { require(it.isFinite() && abs(it) <= 100.0) }
                }
                require(columns[0].isNotBlank() && table.put(columns[0], coefficients) == null)
            }
            val bias = requireNotNull(table.remove("@bias"))
            require(table.isNotEmpty())
            AetherTaskModel(bias, table)
        }
    }
}

/** Keep local suggestions within the scope of a single supported check or setting. */
internal object AetherTaskPolicy {
    private val word = Regex("[a-z0-9]+(?:'[a-z]+)?")
    private val link = Regex("\\b(?:https?://|www\\.)\\S+")
    private val sequence = Regex("""(?i)\b(?:then|tapos|saka|atsaka)\b|[;\r\n]""")
    private val unsupportedRequest = Regex("^(please )?(do not|don't|never|avoid|stop|skip|cancel|wag|huwag|ayaw|open|visit|launch|download|upload|install|uninstall|delete|remove|quarantine)\\b")
    private val enableVerb = Regex("\\b(enable|activate|turn on|switch on|buksan|pabukas|i on)\\b")
    private val explanation = Regex("\\b(why|how|what|whether|paano|bakit)\\b")
    private val aliasSetting = Regex("\\b(alias|aliases|cname|cnames)\\b")
    // An expanded workflow must not override the user's explicitly narrower scope.
    private val narrowerScope = Regex("\\b(only|just|without|except|skip|exclude|excluding|avoid|not|no|never|lang|lamang|wag|huwag|ayaw)\\b|n't\\b")
    private val broadSecurity = Regex("\\b(security review|security checkup|combined security|overall (mobile |device |phone )?security)\\b")
    private val phoneScope = Regex("\\b(protection|protect|shield|shielding|wifi|adshield|settings|device security|phone security|network security|seguridad ng phone)\\b")
    private val appScope = Regex("\\b(apps?|applications?|permissions?)\\b")
    private val selectedFileScope = Regex("\\b(files?|archives?|attachments?|documents?|dokumento\\w*|pdf|apks?|xapk|zip|(application|downloaded|local|saved|package) installer|spreadsheet|screenshot)\\b")
    private val negation = Regex("\\b(never|not|no|off|disable|disabling|wag|huwag|ayaw)\\b|n't\\b")

    fun isSequence(request: String): Boolean = sequence.containsMatchIn(
        link.replace(Normalizer.normalize(request, Normalizer.Form.NFKC).lowercase(Locale.ROOT), " link ")
    )

    fun tokens(request: String): List<String> {
        val text = Normalizer.normalize(request, Normalizer.Form.NFKC)
            .lowercase(Locale.ROOT).replace('’', '\'')
        return word.findAll(link.replace(text, " link ")).map { it.value }.toList()
    }

    fun isAffirmativeRequest(tokens: List<String>): Boolean =
        !unsupportedRequest.containsMatchIn(tokens.joinToString(" "))

    fun allows(task: AetherSecurityTask, tokens: List<String>): Boolean {
        if (tokens.size < 2 || !isAffirmativeRequest(tokens)) return false
        val text = tokens.joinToString(" ")
        return when (task) {
            AetherSecurityTask.SECURITY_REVIEW -> !narrowerScope.containsMatchIn(text) &&
                !selectedFileScope.containsMatchIn(text) &&
                (broadSecurity.containsMatchIn(text) || (phoneScope.containsMatchIn(text) && appScope.containsMatchIn(text)))
            AetherSecurityTask.AUDIT_APPS -> !selectedFileScope.containsMatchIn(text)
            AetherSecurityTask.SCAN_FILE -> selectedFileScope.containsMatchIn(text)
            AetherSecurityTask.ENABLE_ALIAS_SHIELD ->
                enableVerb.containsMatchIn(text) && aliasSetting.containsMatchIn(text) &&
                    !negation.containsMatchIn(text) && !explanation.containsMatchIn(text)
            else -> true
        }
    }
}

/** One pending action at a time. A stale dialog or repeated tap cannot approve another task. */
internal class AetherTaskApproval {
    data class Proposal(val id: Long, val task: AetherSecurityTask, val suggested: Boolean)
    class Approved internal constructor(
        val id: Long,
        val task: AetherSecurityTask,
        val link: String?
    )

    private var sequence = 0L
    var pending: Proposal? = null
        private set

    fun propose(task: AetherSecurityTask, suggested: Boolean = false): Proposal =
        Proposal(++sequence, task, suggested).also { pending = it }

    fun dismiss(id: Long) {
        if (pending?.id == id) pending = null
    }

    fun approve(id: Long, urlInput: String = ""): Approved? {
        val current = pending?.takeIf { it.id == id } ?: return null
        // The model cannot supply this argument. The user types/pastes it in the approval dialog.
        val url = if (current.task == AetherSecurityTask.SCAN_LINK) {
            urlInput.trim().takeIf(::isLinkInput) ?: return null
        } else null
        pending = null
        return Approved(current.id, current.task, url)
    }

    companion object {
        const val MAX_LINK_CHARS = 2_048

        fun isLinkInput(input: String): Boolean {
            val url = input.trim()
            if (url.isEmpty() || url.length > MAX_LINK_CHARS || url.any { it.isWhitespace() || it.isISOControl() }) return false
            val parsed = runCatching { URI(if ("://" in url) url else "https://$url") }.getOrNull() ?: return false
            return (parsed.scheme.equals("http", ignoreCase = true) || parsed.scheme.equals("https", ignoreCase = true)) &&
                parsed.host?.let { '.' in it || it.startsWith('[') } == true
        }
    }
}
