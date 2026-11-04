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
        private const val MAX_STRINGS_PER_RULE = 256
        private const val MAX_STRING_BYTES = 4096

        /**
         * Parses the supported YARA subset with a hand-written, single-pass scanner.
         *
         * Regular expressions were deliberately removed: Java's regex engine recurses once per
         * matched character, so a long quoted string raised a StackOverflowError that no size
         * check could intercept. The scanner is linear in the size of the input and every limit
         * is enforced before the input is accepted.
         */
        fun parse(ruleText: String): List<Rule> {
            require(ruleText.length <= MAX_RULE_TEXT) { "YARA rule bundle exceeds 1 MiB" }
            val text = stripComments(ruleText)
            val blocks = mutableListOf<Pair<String, String>>()
            var cursor = 0
            while (blocks.size <= MAX_RULES) {
                val header = findRuleHeader(text, cursor) ?: break
                val open = text.indexOf('{', header.second)
                if (open < 0) break
                val close = matchingBrace(text, open)
                if (close < 0) break
                blocks += header.first to text.substring(open + 1, close)
                cursor = close + 1
            }
            require(blocks.isNotEmpty()) { "No supported YARA rules found" }
            require(blocks.size <= MAX_RULES) { "Too many YARA rules" }
            return blocks.map { (name, body) -> parseRule(name, body) }
        }

        private fun parseRule(name: String, body: String): Rule {
            val stringsAt = indexOfSection(body, "strings")
            val conditionAt = if (stringsAt >= 0) indexOfSection(body, "condition", stringsAt + 1) else -1
            require(stringsAt >= 0 && conditionAt > stringsAt) {
                "Rule $name requires strings and condition sections"
            }
            val stringsSection = body.substring(stringsAt, conditionAt)
            val conditionText = body.substring(conditionAt).substringAfter(':').trim()
            val patterns = parseStrings(name, stringsSection)
            require(patterns.isNotEmpty()) { "Rule $name has no supported strings" }
            require(patterns.size <= MAX_STRINGS_PER_RULE) { "Rule $name has too many strings" }
            require(patterns.map { it.id }.distinct().size == patterns.size) { "Rule $name has duplicate string IDs" }
            val (condition, count) = parseCondition(conditionText)
            require(condition != Condition.AT_LEAST || count <= patterns.size) {
                "Rule $name condition exceeds string count"
            }
            return Rule(name, patterns, condition, count)
        }

        /** Reads `$id = "text"` and `$id = { 4D 5A ?? }` declarations, one character at a time. */
        private fun parseStrings(ruleName: String, section: String): List<StringPattern> {
            val patterns = mutableListOf<StringPattern>()
            var index = 0
            while (index < section.length) {
                val char = section[index]
                if (char != '$' || (index > 0 && section[index - 1].isIdentifierPart())) {
                    index++
                    continue
                }
                val idStart = index + 1
                var idEnd = idStart
                while (idEnd < section.length && section[idEnd].isIdentifierPart()) idEnd++
                if (idEnd == idStart) {
                    index = idEnd
                    continue
                }
                val id = section.substring(idStart, idEnd)
                var cursor = skipSpaces(section, idEnd)
                if (cursor >= section.length || section[cursor] != '=') {
                    index = cursor
                    continue
                }
                cursor = skipSpaces(section, cursor + 1)
                if (cursor >= section.length) break
                val lineEnd = endOfLine(section, cursor)
                when (section[cursor]) {
                    '"' -> {
                        val close = findClosingQuote(section, cursor)
                        require(close > cursor) { "Rule $ruleName has an unterminated string" }
                        val raw = section.substring(cursor + 1, close)
                        val bytes = decodeEscapes(raw)
                        require(bytes.size in 1..MAX_STRING_BYTES) { "String must contain 1..$MAX_STRING_BYTES bytes" }
                        val modifiers = section.substring(close + 1, lineEnd)
                            .split(' ', '\t', ',').filter { it.isNotBlank() }
                        require(modifiers.all { it == "ascii" || it == "wide" || it == "nocase" }) {
                            "Unsupported string modifier in rule $ruleName"
                        }
                        patterns += StringPattern(id, bytes, "nocase" in modifiers, "wide" in modifiers)
                        index = lineEnd
                    }
                    '{' -> {
                        val close = section.indexOf('}', cursor)
                        require(close > cursor) { "Rule $ruleName has an unterminated hex string" }
                        val trailing = section.substring(close + 1, lineEnd).trim()
                        require(trailing.isEmpty()) { "Modifiers are not supported on hex strings" }
                        patterns += parseHex(id, section.substring(cursor + 1, close), ruleName)
                        index = lineEnd
                    }
                    else -> index = lineEnd
                }
            }
            return patterns
        }

        private fun parseHex(id: String, inner: String, ruleName: String): StringPattern {
            val tokens = inner.split(' ', '\t', '\r', '\n').filter { it.isNotBlank() }
            require(tokens.size in 1..MAX_STRING_BYTES) { "Hex string must contain 1..$MAX_STRING_BYTES bytes" }
            val wildcards = mutableSetOf<Int>()
            val bytes = ByteArray(tokens.size)
            tokens.forEachIndexed { index, token ->
                when {
                    token == "??" -> wildcards += index
                    token.length == 2 && token.all { it.isHexDigit() } -> bytes[index] = token.toInt(16).toByte()
                    else -> throw IllegalArgumentException(
                        "Only complete hex bytes and ?? wildcards are supported in rule $ruleName"
                    )
                }
            }
            return StringPattern(id, bytes, wildcardPositions = wildcards)
        }

        private fun parseCondition(text: String): Pair<Condition, Int> {
            val compact = text.trim()
            return when {
                compact.equals("any of them", ignoreCase = true) -> Condition.ANY to 1
                compact.equals("all of them", ignoreCase = true) -> Condition.ALL to 1
                else -> {
                    val separator = compact.indexOf(" of them", ignoreCase = true)
                    require(separator > 0) { "Unsupported condition; use any/all/N of them" }
                    val count = compact.substring(0, separator).trim().toIntOrNull()
                        ?: throw IllegalArgumentException("Unsupported condition; use any/all/N of them")
                    require(count >= 1) { "Unsupported condition; use any/all/N of them" }
                    Condition.AT_LEAST to count
                }
            }
        }

        private fun findRuleHeader(text: String, fromIndex: Int): Pair<String, Int>? {
            var index = fromIndex
            while (index < text.length) {
                val at = text.indexOf("rule", index)
                if (at < 0) return null
                val beforeOk = at == 0 || !text[at - 1].isIdentifierPart()
                if (beforeOk) {
                    var cursor = at + 4
                    if (cursor < text.length && text[cursor].isWhitespace()) {
                        cursor = skipSpaces(text, cursor)
                        val nameStart = cursor
                        while (cursor < text.length && text[cursor].isIdentifierPart()) cursor++
                        if (cursor > nameStart) return text.substring(nameStart, cursor) to cursor
                    }
                }
                index = at + 4
            }
            return null
        }

        private fun indexOfSection(text: String, label: String, fromIndex: Int = 0): Int {
            var index = fromIndex
            while (index < text.length) {
                val at = text.indexOf(label, index)
                if (at < 0) return -1
                val beforeOk = at == 0 || !text[at - 1].isIdentifierPart()
                var cursor = at + label.length
                cursor = skipSpaces(text, cursor)
                if (beforeOk && cursor < text.length && text[cursor] == ':') return at
                index = at + label.length
            }
            return -1
        }

        private fun matchingBrace(text: String, openIndex: Int): Int {
            var depth = 0
            var inString = false
            var index = openIndex
            while (index < text.length) {
                when (text[index]) {
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

        private fun findClosingQuote(text: String, openIndex: Int): Int {
            var index = openIndex + 1
            while (index < text.length) {
                when (text[index]) {
                    '\\' -> index++
                    '"' -> return index
                }
                index++
            }
            return -1
        }

        private fun stripComments(text: String): String {
            val out = StringBuilder(text.length)
            var index = 0
            var inString = false
            while (index < text.length) {
                val char = text[index]
                if (inString) {
                    out.append(char)
                    when {
                        char == '\\' && index + 1 < text.length -> out.append(text[++index])
                        char == '"' -> inString = false
                    }
                    index++
                    continue
                }
                when {
                    char == '"' -> { inString = true; out.append(char); index++ }
                    char == '/' && index + 1 < text.length && text[index + 1] == '/' -> {
                        while (index < text.length && text[index] != '\n') index++
                    }
                    char == '/' && index + 1 < text.length && text[index + 1] == '*' -> {
                        index += 2
                        while (index + 1 < text.length && !(text[index] == '*' && text[index + 1] == '/')) index++
                        index = (index + 2).coerceAtMost(text.length)
                    }
                    else -> { out.append(char); index++ }
                }
            }
            return out.toString()
        }

        private fun skipSpaces(text: String, fromIndex: Int): Int {
            var index = fromIndex
            while (index < text.length && text[index].isWhitespace()) index++
            return index
        }

        private fun endOfLine(text: String, fromIndex: Int): Int {
            val newline = text.indexOf('\n', fromIndex)
            return if (newline < 0) text.length else newline
        }

        private fun Char.isIdentifierPart(): Boolean = this == '_' || isLetterOrDigit()

        private fun Char.isHexDigit(): Boolean =
            this in '0'..'9' || this in 'a'..'f' || this in 'A'..'F'

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
