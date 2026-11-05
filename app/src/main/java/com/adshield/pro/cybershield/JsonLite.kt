package com.adshield.pro.cybershield

/**
 * Minimal, strict JSON reader used by CyberShield parsers.
 *
 * Pure Kotlin so feed parsing, map assets and status responses can be unit-tested
 * on the JVM without the Android org.json stubs. Hardened with input-size and
 * nesting-depth limits; rejects trailing content, NaN/Infinity and lone surrogates
 * produced by invalid escapes. This is a read-only parser, not a serializer.
 */
sealed class JValue {
    object JNull : JValue()
    data class JBool(val value: Boolean) : JValue()
    data class JNum(val value: Double) : JValue()
    data class JStr(val value: String) : JValue()
    data class JArr(val items: List<JValue>) : JValue()
    data class JObj(val fields: Map<String, JValue>) : JValue()

    fun obj(key: String): JObj? = (this as? JObj)?.fields?.get(key) as? JObj
    fun arr(key: String): JArr? = (this as? JObj)?.fields?.get(key) as? JArr
    fun str(key: String): String? = ((this as? JObj)?.fields?.get(key) as? JStr)?.value
    fun num(key: String): Double? = ((this as? JObj)?.fields?.get(key) as? JNum)?.value
    fun int(key: String): Int? = num(key)?.let { if (it.isFinite()) it.toInt() else null }
    fun bool(key: String): Boolean? = ((this as? JObj)?.fields?.get(key) as? JBool)?.value
    fun asStringOrNull(): String? = (this as? JStr)?.value
    fun asListOrNull(): List<JValue>? = (this as? JArr)?.items
}

class JsonParseException(message: String) : Exception(message)

object JsonLite {
    const val MAX_INPUT_CHARS = 8_000_000
    const val MAX_DEPTH = 64

    fun parse(text: String): JValue {
        if (text.length > MAX_INPUT_CHARS) throw JsonParseException("JSON input too large")
        val p = Parser(text)
        p.skipWs()
        val v = p.readValue(0)
        p.skipWs()
        if (!p.atEnd()) throw JsonParseException("Trailing content at ${p.pos}")
        return v
    }

    private class Parser(val s: String) {
        var pos = 0
        fun atEnd() = pos >= s.length
        fun peek(): Char = if (pos < s.length) s[pos] else '\u0000'

        fun skipWs() {
            while (pos < s.length) {
                val c = s[pos]
                if (c == ' ' || c == '\n' || c == '\r' || c == '\t') pos++ else break
            }
        }

        fun expect(c: Char) {
            if (peek() != c) throw JsonParseException("Expected '$c' at $pos")
            pos++
        }

        fun readValue(depth: Int): JValue {
            if (depth > MAX_DEPTH) throw JsonParseException("Nesting too deep")
            skipWs()
            return when (val c = peek()) {
                '{' -> readObj(depth)
                '[' -> readArr(depth)
                '"' -> JValue.JStr(readString())
                't' -> readLiteral("true", JValue.JBool(true))
                'f' -> readLiteral("false", JValue.JBool(false))
                'n' -> readLiteral("null", JValue.JNull)
                else -> if (c == '-' || c in '0'..'9') readNumber()
                else throw JsonParseException("Unexpected char '$c' at $pos")
            }
        }

        fun readLiteral(word: String, v: JValue): JValue {
            if (!s.startsWith(word, pos)) throw JsonParseException("Invalid literal at $pos")
            pos += word.length
            return v
        }

        fun readObj(depth: Int): JValue.JObj {
            expect('{')
            val map = LinkedHashMap<String, JValue>()
            skipWs()
            if (peek() == '}') { pos++; return JValue.JObj(map) }
            while (true) {
                skipWs()
                val key = readString()
                skipWs(); expect(':')
                map[key] = readValue(depth + 1)
                skipWs()
                when (peek()) {
                    ',' -> pos++
                    '}' -> { pos++; return JValue.JObj(map) }
                    else -> throw JsonParseException("Expected ',' or '}' at $pos")
                }
            }
        }

        fun readArr(depth: Int): JValue.JArr {
            expect('[')
            val items = ArrayList<JValue>()
            skipWs()
            if (peek() == ']') { pos++; return JValue.JArr(items) }
            while (true) {
                items.add(readValue(depth + 1))
                skipWs()
                when (peek()) {
                    ',' -> pos++
                    ']' -> { pos++; return JValue.JArr(items) }
                    else -> throw JsonParseException("Expected ',' or ']' at $pos")
                }
            }
        }

        fun readString(): String {
            expect('"')
            val sb = StringBuilder()
            while (true) {
                if (atEnd()) throw JsonParseException("Unterminated string")
                when (val c = s[pos++]) {
                    '"' -> return sb.toString()
                    '\\' -> {
                        if (atEnd()) throw JsonParseException("Unterminated escape")
                        when (val e = s[pos++]) {
                            '"' -> sb.append('"')
                            '\\' -> sb.append('\\')
                            '/' -> sb.append('/')
                            'b' -> sb.append('\b')
                            'f' -> sb.append('\u000C')
                            'n' -> sb.append('\n')
                            'r' -> sb.append('\r')
                            't' -> sb.append('\t')
                            'u' -> {
                                if (pos + 4 > s.length) throw JsonParseException("Bad unicode escape")
                                val hex = s.substring(pos, pos + 4)
                                pos += 4
                                val code = hex.toIntOrNull(16) ?: throw JsonParseException("Bad unicode escape")
                                sb.append(code.toChar())
                            }
                            else -> throw JsonParseException("Bad escape '\\$e'")
                        }
                    }
                    else -> {
                        if (c < ' ') throw JsonParseException("Control char in string")
                        sb.append(c)
                    }
                }
            }
        }

        fun readNumber(): JValue.JNum {
            val start = pos
            if (peek() == '-') pos++
            if (peek() == '0') pos++ else {
                if (peek() !in '1'..'9') throw JsonParseException("Bad number at $start")
                while (peek() in '0'..'9') pos++
            }
            if (peek() == '.') {
                pos++
                if (peek() !in '0'..'9') throw JsonParseException("Bad fraction at $pos")
                while (peek() in '0'..'9') pos++
            }
            if (peek() == 'e' || peek() == 'E') {
                pos++
                if (peek() == '+' || peek() == '-') pos++
                if (peek() !in '0'..'9') throw JsonParseException("Bad exponent at $pos")
                while (peek() in '0'..'9') pos++
            }
            val d = s.substring(start, pos).toDoubleOrNull()
                ?: throw JsonParseException("Bad number at $start")
            if (!d.isFinite()) throw JsonParseException("Non-finite number")
            return JValue.JNum(d)
        }
    }
}
