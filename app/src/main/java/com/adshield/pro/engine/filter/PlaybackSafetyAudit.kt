package com.adshield.pro.engine.filter

/**
 * Answers the question a DNS blocker can never prove from logs: *is my current filtering still
 * compatible with playing video?*
 *
 * It probes a small, stable set of media-delivery zones through whatever the caller uses to decide a
 * block (the loaded lists, the user's rules and the safety allowlist, in that engine's order). If one
 * of them is refused, playback will fail on any app that needs it, and no log line will ever say so
 * clearly — so the audit says it in one sentence.
 *
 * The probes are delivery zones shared by many players, not one vendor's API host, and this audit only
 * reads: it never changes a rule, a mode or a catalogue entry.
 */
object PlaybackSafetyAudit {

    enum class Severity { OK, WARNING, PROBLEM }

    data class Finding(val title: String, val detail: String, val severity: Severity)

    /** Media delivery zones whose refusal stops playback, with what each one carries. */
    val MEDIA_PROBES: List<Pair<String, String>> = listOf(
        "googlevideo.com" to "YouTube and Google video segments",
        "ytimg.com" to "YouTube thumbnails and player assets",
        "akamaized.net" to "media segments for many streaming apps",
        "cloudfront.net" to "media segments for many streaming apps",
        "cdn.jwplayer.com" to "JW Player library and segments",
        "vod.dai.google.com" to "server-side stitched video adverts"
    )

    /** Zones that should be covered for third-party advert blocking to do anything at all. */
    val ADVERT_PROBES: List<Pair<String, String>> = listOf(
        "doubleclick.net" to "Google ad serving",
        "adservice.google.com" to "Google mobile ad service",
        "2mdn.net" to "Google ad creative delivery"
    )

    fun audit(isBlocked: (String) -> Boolean): List<Finding> {
        val findings = ArrayList<Finding>()

        val brokenMedia = MEDIA_PROBES.filter { (host, _) -> isBlocked(host) }
        if (brokenMedia.isEmpty()) {
            findings += Finding(
                title = "Playback zones are clear",
                detail = "No loaded rule or user rule refuses the ${MEDIA_PROBES.size} media zones this " +
                    "check probes, so ad blocking is not standing in the way of playback.",
                severity = Severity.OK
            )
        } else {
            brokenMedia.forEach { (host, carries) ->
                findings += Finding(
                    title = "$host is blocked",
                    detail = "That zone carries $carries. A refused lookup there stops playback in apps " +
                        "that use it — disable the list or rule that matches it.",
                    severity = Severity.PROBLEM
                )
            }
        }

        val uncovered = ADVERT_PROBES.filterNot { (host, _) -> isBlocked(host) }
        if (uncovered.size == ADVERT_PROBES.size) {
            findings += Finding(
                title = "No advert zone is covered",
                detail = "None of the ${ADVERT_PROBES.size} advert zones this check probes is refused. " +
                    "Check that a filter list is loaded and that the video-ad baseline is on.",
                severity = Severity.WARNING
            )
        } else if (uncovered.isNotEmpty()) {
            findings += Finding(
                title = "${uncovered.size} advert zone(s) not covered",
                detail = uncovered.joinToString(", ") { it.first } +
                    " are not refused, which is normal when those networks are not in your lists.",
                severity = Severity.WARNING
            )
        }

        if (findings.none { it.severity == Severity.WARNING || it.severity == Severity.PROBLEM }) {
            findings += Finding(
                title = "Advert blocking is active",
                detail = "At least one advert zone is refused and no media zone is, which is the shape you want.",
                severity = Severity.OK
            )
        }
        return findings
    }
}
