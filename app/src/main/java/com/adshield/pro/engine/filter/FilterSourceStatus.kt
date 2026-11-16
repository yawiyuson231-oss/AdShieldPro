package com.adshield.pro.engine.filter

/**
 * The one-line status a filter source shows in the UI.
 *
 * It exists so the playback-safety work is visible where it happens: when a list contains lines
 * that would remove a media zone or a shared CDN, those lines are refused at parse time, and the
 * user deserves to see that the list they added was trimmed rather than silently ignored.
 */
object FilterSourceStatus {

    fun describe(
        prefix: String,
        validRules: Int,
        duplicateCount: Int,
        rejectedUnsafeRules: Int
    ): String {
        val base = "$prefix ($validRules ${if (validRules == 1) "rule" else "rules"}"
        val extra = buildList {
            if (duplicateCount > 0) add("$duplicateCount duplicate${if (duplicateCount == 1) "" else "s"}")
            if (rejectedUnsafeRules > 0) {
                add("$rejectedUnsafeRules unsafe line${if (rejectedUnsafeRules == 1) "" else "s"} ignored")
            }
        }
        return if (extra.isEmpty()) "$base)" else "$base; ${extra.joinToString(", ")})"
    }
}
