package com.adshield.pro.engine.security

/**
 * A deliberately bounded YARA-compatible subset for local, offline file triage.
 *
 * Supported: named rules, ASCII/wide/nocase quoted strings, hex bytes with ?? wildcards,
 * and `any of them`, `all of them`, or `N of them` conditions. Unsupported YARA features are
 * rejected at parse time rather than silently ignored. This is not the full native YARA engine.
 */
class YaraLiteEngine(
    private val rules: List<Rule> = DEFAULT_RULES
) {
    enum class Condition { ANY, ALL, AT_LEAST }

    data class StringPattern(
        val id: String,
        val bytes: ByteArray,
        val noCase: Boolean = false,
        val wide: Boolean = false,
        val wildcardPositions: Set<Int> = emptySet()
    )

    data class Rule(
        val name: String,
        val patterns: List<StringPattern>,
        val condition: Condition,
        val requiredMatches: Int = 1
    )

    data class Match(val ruleName: String, val matchedStringIds: List<String>)

    fun scan(content: String): List<Match> = rules.mapNotNull { rule ->
        val matched = rule.patterns.filter { pattern -> contains(content, pattern) }.map { it.id }
        val matchesCondition = when (rule.condition) {
            Condition.ANY -> matched.isNotEmpty()
            Condition.ALL -> matched.size == rule.patterns.size
            Condition.AT_LEAST -> matched.size >= rule.requiredMatches
        }
        if (matchesCondition) Match(rule.name, matched) else null
    }

    private fun contains(content: String, pattern: StringPattern): Boolean {
        if (pattern.bytes.isEmpty()) return false
        val source = if (pattern.wide) content else content
        val needle = if (pattern.wide) {
            pattern.bytes.flatMap { listOf(it, 0.toByte()) }.toByteArray()
        } else pattern.bytes
        val wildcards = if (pattern.wide) {
            pattern.wildcardPositions.flatMap { setOf(it * 2, it * 2 + 1) }.toSet()
        } else pattern.wildcardPositions
        if (needle.size > source.length) return false
        outer@ for (start in 0..source.length - needle.size) {
            for (index in needle.indices) {
                if (index in wildcards) continue
                var actual = source[start + index].code
                var expected = needle[index].toInt() and 0xFF
                if (pattern.noCase) {
                    actual = asciiLower(actual)
                    expected = asciiLower(expected)
                }
                if (actual != expected) continue@outer
            }
            return true
        }
        return false
    }

    private fun asciiLower(value: Int): Int = if (value in 65..90) value + 32 else value

    companion object {
        private const val MAX_RULE_TEXT = 1_048_576
        private const val MAX_RULES = 128
        private val RULE_HEADER_REGEX = Regex("\\brule\\s+([A-Za-z_][A-Za-z0-9_]*)")
        private val QUOTED_REGEX = Regex("\\\$([A-Za-z_][A-Za-z0-9_]*)\\s*=\\s*\"((?:\\\\.|[^\"\\\\])*)\"\\s*([^\\r\\n]*)")
        private val HEX_REGEX = Regex("\\\$([A-Za-z_][A-Za-z0-9_]*)\\s*=\\s*\\{([^}]*)\\}\\s*([^\\r\\n]*)")

        fun parse(ruleText: String): List<Rule> {
            require(ruleText.length <= MAX_RULE_TEXT) { "YARA rule bundle exceeds 1 MiB" }
            val sanitized = ruleText.replace(Regex("/\\*.*?\\*/", RegexOption.DOT_MATCHES_ALL), " ")
            val blocks = mutableListOf<Pair<String, String>>()
            var cursor = 0
            while (true) {
                val header = RULE_HEADER_REGEX.find(sanitized, cursor) ?: break
                val open = sanitized.indexOf('{', header.range.last + 1)
                if (open < 0) break
                val close = matchingBrace(sanitized, open)
                if (close < 0) break
                blocks += header.groupValues[1] to sanitized.substring(open + 1, close)
                cursor = close + 1
                if (blocks.size > MAX_RULES) break
            }
            require(blocks.isNotEmpty()) { "No supported YARA rules found" }
            require(blocks.size <= MAX_RULES) { "Too many YARA rules" }
            return blocks.map { (name, body) ->
                val section = Regex("\\bstrings\\s*:(.*?)\\bcondition\\s*:(.*)", RegexOption.DOT_MATCHES_ALL)
                    .find(body) ?: throw IllegalArgumentException("Rule $name requires strings and condition sections")
                val stringSection = section.groupValues[1]
                val conditionText = section.groupValues[2].trim()
                val quoted = QUOTED_REGEX.findAll(stringSection).map { parseQuoted(it) }.toList()
                val hex = HEX_REGEX.findAll(stringSection).map { parseHex(it) }.toList()
                val patterns = quoted + hex
                require(patterns.isNotEmpty() && patterns.size <= 256) { "Rule $name has no supported strings or too many strings" }
                require(patterns.map { it.id }.distinct().size == patterns.size) { "Rule $name has duplicate string IDs" }
                val (condition, count) = parseCondition(conditionText)
                require(condition != Condition.AT_LEAST || count <= patterns.size) { "Rule $name condition exceeds string count" }
                Rule(name, patterns, condition, count)
            }
        }

        private fun matchingBrace(text: String, openIndex: Int): Int {
            var depth = 0
            var inString = false
            var index = openIndex
            while (index < text.length) {
                when (val char = text[index]) {
                    '\\' -> index++
                    '"' -> inString = !inString
                    '{' -> if (!inString) depth++
                    '}' -> if (!inString) {
                        depth--
                        if (depth == 0) return index
                    }
                }
                index++
            }
            return -1
        }

        private fun parseQuoted(match: MatchResult): StringPattern {
            val raw = match.groupValues[2]
            val modifiers = match.groupValues[3].split(Regex("\\s+")).filter { it.isNotBlank() }
            require(modifiers.all { it in setOf("ascii", "wide", "nocase") }) { "Unsupported string modifier" }
            val bytes = decodeEscapes(raw)
            require(bytes.size in 1..4096) { "String must contain 1..4096 bytes" }
            return StringPattern(match.groupValues[1], bytes, "nocase" in modifiers, "wide" in modifiers)
        }

        private fun parseHex(match: MatchResult): StringPattern {
            require(match.groupValues[3].isBlank()) { "Modifiers are not supported on hex strings" }
            val tokens = match.groupValues[2].trim().split(Regex("\\s+")).filter { it.isNotBlank() }
            require(tokens.size in 1..4096) { "Hex string must contain 1..4096 bytes" }
            val wildcards = mutableSetOf<Int>()
            val bytes = tokens.mapIndexed { index, token ->
                when {
                    token == "??" -> { wildcards += index; 0 }
                    token.matches(Regex("[0-9A-Fa-f]{2}")) -> token.toInt(16)
                    else -> throw IllegalArgumentException("Only complete hex bytes and ?? wildcards are supported")
                }
            }
            return StringPattern(match.groupValues[1], bytes.map { it.toByte() }.toByteArray(), wildcardPositions = wildcards)
        }

        private fun decodeEscapes(raw: String): ByteArray {
            val out = java.io.ByteArrayOutputStream()
            var index = 0
            while (index < raw.length) {
                val char = raw[index]
                if (char != '\\') {
                    val encoded = char.toString().toByteArray(Charsets.ISO_8859_1)
                    out.write(encoded)
                    index++
                    continue
                }
                require(index + 1 < raw.length) { "Dangling string escape" }
                when (val escaped = raw[index + 1]) {
                    'n' -> out.write(10)
                    'r' -> out.write(13)
                    't' -> out.write(9)
                    '\\', '"' -> out.write(escaped.code)
                    'x' -> {
                        require(index + 3 < raw.length) { "Short hex escape" }
                        out.write(raw.substring(index + 2, index + 4).toInt(16))
                        index += 2
                    }
                    else -> throw IllegalArgumentException("Unsupported escape: \\$escaped")
                }
                index += 2
            }
            return out.toByteArray()
        }

        private fun parseCondition(text: String): Pair<Condition, Int> {
            val compact = text.replace(Regex("//.*"), "").trim()
            return when {
                compact.equals("any of them", true) -> Condition.ANY to 1
                compact.equals("all of them", true) -> Condition.ALL to 1
                else -> {
                    val count = Regex("^(\\d+)\\s+of\\s+them$", RegexOption.IGNORE_CASE).find(compact)
                        ?: throw IllegalArgumentException("Unsupported condition; use any/all/N of them")
                    Condition.AT_LEAST to count.groupValues[1].toInt()
                }
            }
        }

        private val DEFAULT_RULES = parse(
            """
            rule EICAR_Test_File {
                strings:
                    ${'$'}eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}${'$'}EICAR-STANDARD-ANTIVIRUS-TEST-FILE!${'$'}H+H*"
                condition:
                    any of them
            }
            rule PowerShell_Encoded_Dropper {
                strings:
                    ${'$'}shell = "powershell" nocase
                    ${'$'}encoded = "-enc" nocase
                condition:
                    all of them
            }
            rule Pipe_To_Shell_Loader {
                strings:
                    ${'$'}curl = "curl " nocase
                    ${'$'}pipe = "| sh" nocase
                condition:
                    all of them
            }
            """.trimIndent()
        )
    }
}
