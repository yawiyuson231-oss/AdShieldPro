package com.adshield.pro.engine.adskip

/**
 * OmniShield X — Notification Ad Shield classifier.
 *
 * Conservative, explainable classification of notifications as advertising.
 * A notification is flagged for dismissal ONLY with 2+ independent signals,
 * and NEVER for messaging/call packages (false-positive protection).
 */
object NotificationAdClassifier {

    enum class Verdict { LIKELY_AD, KEEP }

    data class Input(
        val packageName: String,
        val title: String,
        val body: String
    )

    private val AD_PHRASES = listOf(
        "sponsored", "% off", "sale", "deal of the day", "limited time",
        "flash sale", "buy now", "shop now", "discount", "free gift",
        "you've won", "you have won", "congratulations", "claim your",
        "unsubscribe", "promo", "special offer", "best price", "coupon"
    )

    private val PROTECTED_PACKAGES = listOf(
        "com.whatsapp", "org.telegram", "com.google.android.apps.messaging",
        "com.discord", "org.thoughtcrime.securesms", "com.facebook.orca",
        "com.android.mms", "com.samsung.android.messaging", "com.viber",
        "com.skype", "com.snapchat", "jp.naver.line.android", "com.bbm",
        "com.android.dialer", "com.google.android.dialer"
    )

    data class Result(val verdict: Verdict, val signals: List<String>)

    fun classify(input: Input): Result {
        if (PROTECTED_PACKAGES.any { input.packageName.startsWith(it) }) {
            return Result(Verdict.KEEP, listOf("protected package (messaging/calls are never dismissed)"))
        }
        val haystack = "${input.title} ${input.body}".lowercase()
        val signals = ArrayList<String>(3)

        for (phrase in AD_PHRASES) {
            if (haystack.contains(phrase) && signals.size < 3) signals.add("phrase:'$phrase'")
        }
        if (Regex("""\d{1,3}\s?%\s?off""", RegexOption.IGNORE_CASE).containsMatchIn(haystack)) {
            signals.add("pattern:percent-off")
        }
        if (Regex("""[^\w\s]\s?\d""").containsMatchIn(input.body) && haystack.contains("only")) {
            signals.add("pattern:price-urgency")
        }

        return if (signals.size >= 2) Result(Verdict.LIKELY_AD, signals)
        else Result(Verdict.KEEP, signals.ifEmpty { listOf("fewer than 2 signals — kept") })
    }
}
