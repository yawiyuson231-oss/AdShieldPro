package com.adshield.pro.engine.adskip

/**
 * OmniShield X — In-App Ad Defense: YouTube Auto-Skip decision engine.
 *
 * Pure, deterministic, testable logic used by the Accessibility service to find
 * and close REAL ad UI inside the YouTube apps (the only non-root mechanism
 * that affects in-app video ads). The service only clicks buttons a human
 * could click (Skip ad / Close overlay) — it never modifies other apps.
 *
 * HONEST SCOPE: covers skippable/overlay ads whose skip/close controls are
 * exposed to accessibility. Server-side stitched unskippable ads cannot be
 * removed — the engine reports nothing rather than pretending.
 */
object AdSkipDecisionEngine {

    /** Packages the engine may ever act on (belt to the service config's own filter). */
    val TARGET_PACKAGES = setOf(
        "com.google.android.youtube",
        "com.google.android.apps.youtube.music"
    )

    /** Skip-button resource-id fragments (YouTube app id names across versions). */
    private val SKIP_ID_TOKENS = listOf("skip_ad", "skip_ad_button", "skip_button")

    /** Close/collapse controls for overlay & banner ads. */
    private val CLOSE_ID_TOKENS = listOf(
        "overlay_close", "close_ad", "ad_close", "ad_attribute_close",
        "companion_close", "mute_skip_close"
    )

    // UNIVERSAL SAFETY RULE: bare "Skip" ("Skip to content"), "✕" (cart drawers),
    // or "Close" (dialogs) are NOT ads. Both tokens ("skip"+"ad" / "close"+"ad")
    // must appear, so unknown apps can never be mis-clicked.
    private const val AD_TOKEN = "ad"
    private val SKIP_TEXTS = listOf("skip ad", "skip ads", "skip the ad", "skip in")
    private val CLOSE_TEXTS = listOf("close ad", "close ads", "remove ad", "close overlay")

    enum class ActionType { CLICK_SKIP, CLICK_CLOSE, NONE }

    data class Action(val type: ActionType, val reason: String)

    data class NodeInfo(
        val viewIdResourceName: String?,
        val text: String?,
        val contentDescription: String?,
        val isClickable: Boolean,
        val packageName: String?
    )

    /** Decides what (if anything) should be done for one node. Deterministic. */
    fun decide(node: NodeInfo, pkg: String, allowedPackages: Set<String> = TARGET_PACKAGES): Action {
        if (pkg !in allowedPackages) return Action(ActionType.NONE, "package not managed")
        val id = node.viewIdResourceName?.lowercase().orEmpty()
        val text = node.text.orEmpty().lowercase()
        val desc = node.contentDescription.orEmpty().lowercase()

        if (node.isClickable) {
            if (SKIP_ID_TOKENS.any { id.contains(it) }) return Action(ActionType.CLICK_SKIP, "id~$id")
            if (CLOSE_ID_TOKENS.any { id.contains(it) }) return Action(ActionType.CLICK_CLOSE, "id~$id")

            // Text-based fallbacks (localized builds may not expose stable ids)
            val combined = "$text $desc"
            if (combined.contains(AD_TOKEN)) {
                if (SKIP_TEXTS.any { combined.contains(it) })
                    return Action(ActionType.CLICK_SKIP, "text~'${(node.text ?: node.contentDescription)?.take(24)}'")
                if (CLOSE_TEXTS.any { combined.contains(it) })
                    return Action(ActionType.CLICK_CLOSE, "text~'${(node.text ?: node.contentDescription)?.take(24)}'")
            }
            // Countdown variant: "Skip in 5s" (contains "skip in", ad implied by player context)
            if (combined.contains("skip in") && Regex("""skip in \d""").containsMatchIn(combined))
                return Action(ActionType.CLICK_SKIP, "text~countdown")
            // NEVER touch the ad's own call-to-action — that helps the advertiser
            if (listOf("download", "install", "buy", "shop now", "learn more", "sign up").any { combined.contains(it) })
                return Action(ActionType.NONE, "ad-CTA guard")
        }
        return Action(ActionType.NONE, "")
    }

    /**
     * Picks the single best action from a scanned node batch.
     * Skip beats Close (skipping ends the ad; closing only removes overlays).
     */
    fun pickBest(candidates: List<Pair<NodeInfo, Action>>): Pair<NodeInfo, Action>? =
        candidates.firstOrNull { it.second.type == ActionType.CLICK_SKIP }
            ?: candidates.firstOrNull { it.second.type == ActionType.CLICK_CLOSE }

    /**
     * Rate limiter: clicks are throttled so the service never spams the UI.
     * minIntervalMs default 900 — faster than any human, slower than a flood.
     */
    class Throttle(private val minIntervalMs: Long = 900L) {
        var lastActionAt: Long = 0L
            private set

        fun tryAcquire(now: Long): Boolean {
            if (now - lastActionAt < minIntervalMs) return false
            lastActionAt = now
            return true
        }
    }
}
