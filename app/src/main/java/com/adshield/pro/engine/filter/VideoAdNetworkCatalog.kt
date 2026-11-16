package com.adshield.pro.engine.filter

/**
 * Built-in baseline of video advert and ad-measurement infrastructure.
 *
 * Why this exists next to the filter lists: an in-stream advert is normally fetched from a host
 * that is *not* the media host. Blocking that host removes the advert and leaves playback intact,
 * and it works even when no list is loaded or the installed list is months old. Every entry is a
 * whole zone (`doubleclick.net`), never a host inside a media domain, so the playback guard's
 * exemptions cannot be undermined from here.
 *
 * Two risk tiers are enforced differently:
 *
 *  - [Risk.SAFE] hosts only serve adverts, ad verification or measurement. A failed fetch is
 *    ignored by players, so they are blocked in every filtering mode.
 *  - [Risk.CONDITIONAL] hosts also ship player or rewarded-ad code. A missing answer can surface
 *    as a stuck "loading advert" step in a few apps, so they are blocked only by the modes that
 *    already warn about compatibility risk (Strict and Custom).
 *
 * What this cannot do, and the reason it is not a claim of "no video ads": an advert served from
 * the same host as the video (YouTube, TikTok, Instagram feeds) never performs a separate DNS
 * lookup, so no DNS filter can separate it from the content. See `docs/VIDEO_AD_BLOCKING.md`.
 */
object VideoAdNetworkCatalog {

    enum class Risk {
        /** Advert delivery or measurement only: blocking cannot remove playback. */
        SAFE,

        /** May ship player or rewarded-ad code: blocked by the aggressive modes only. */
        CONDITIONAL
    }

    data class Entry(
        val suffix: String,
        val network: String,
        val risk: Risk,
        /** What the host actually does, in the operator's own words where possible. */
        val note: String
    )

    data class Match(val entry: Entry, val blocked: Boolean, val reason: String)

    /**
     * Matched on host-or-subdomain of [Entry.suffix]. Order is significant only for readability:
     * no suffix is a parent of another entry.
     */
    val ENTRIES: List<Entry> = listOf(
        // Google / DoubleClick ad serving and measurement (not YouTube media delivery).
        Entry("doubleclick.net", "Google DoubleClick", Risk.SAFE, "Ad serving, targeting and view measurement"),
        Entry("2mdn.net", "Google 2mdn", Risk.SAFE, "Ad creative hosting for DoubleClick campaigns"),
        Entry("googlesyndication.com", "Google AdSense/AdX", Risk.SAFE, "Ad syndication and creative delivery"),
        Entry("googleadservices.com", "Google Ads", Risk.SAFE, "Paid-click redirect and conversion measurement"),

        // Programmatic video ad exchanges and servers.
        Entry("criteo.com", "Criteo", Risk.SAFE, "Retargeting and sponsored product adverts"),
        Entry("criteo.net", "Criteo", Risk.SAFE, "Retargeting creative delivery"),
        Entry("adsrvr.org", "The Trade Desk", Risk.SAFE, "Programmatic bid requests"),
        Entry("rubiconproject.com", "Magnite", Risk.SAFE, "Programmatic video supply-side bidding"),
        Entry("pubmatic.com", "PubMatic", Risk.SAFE, "Programmatic bidding"),
        Entry("casalemedia.com", "Index Exchange", Risk.SAFE, "Programmatic bidding"),
        Entry("adnxs.com", "Xandr", Risk.SAFE, "Programmatic bidding"),
        Entry("smartadserver.com", "Equativ", Risk.SAFE, "Ad server and bidding"),
        Entry("adform.net", "Adform", Risk.SAFE, "Ad serving and measurement"),
        Entry("teads.tv", "Teads", Risk.SAFE, "Outstream video ad serving"),
        Entry("spotxchange.com", "SpotX", Risk.SAFE, "Video ad serving"),
        Entry("tremorhub.com", "Tremor Video", Risk.SAFE, "Video ad serving"),
        Entry("flashtalking.com", "Flashtalking", Risk.SAFE, "Ad serving and creative measurement"),
        Entry("serving-sys.com", "Sizmek/Amazon", Risk.SAFE, "Ad serving"),
        Entry("yieldmo.com", "Yieldmo", Risk.SAFE, "Ad formats and bidding"),
        Entry("undertone.com", "Undertone", Risk.SAFE, "High-impact ad serving"),

        // Native / recommendation adverts (the "sponsored stories" slots).
        Entry("taboola.com", "Taboola", Risk.SAFE, "Sponsored content and video recommendations"),
        Entry("outbrain.com", "Outbrain", Risk.SAFE, "Sponsored content and video recommendations"),

        // Ad verification and audience measurement attached to video adverts.
        Entry("moatads.com", "Oracle Moat", Risk.SAFE, "Video ad viewability measurement"),
        Entry("adsafeprotected.com", "Integral Ad Science", Risk.SAFE, "Ad verification and brand safety"),
        Entry("doubleverify.com", "DoubleVerify", Risk.SAFE, "Ad verification and fraud measurement"),
        Entry("imrworldwide.com", "Nielsen", Risk.SAFE, "Audience measurement"),
        Entry("scorecardresearch.com", "Comscore", Risk.SAFE, "Audience measurement"),
        Entry("quantserve.com", "Quantcast", Risk.SAFE, "Audience measurement"),

        // Retail media and platform ad networks.
        Entry("amazon-adsystem.com", "Amazon Ads", Risk.SAFE, "Retail ad serving"),
        Entry("ads.tiktok.com", "TikTok Ads", Risk.SAFE, "Ad campaign delivery outside the video feed"),
        Entry("analytics.tiktok.com", "TikTok Analytics", Risk.SAFE, "TikTok event measurement"),

        // Video ad servers and player libraries that can make a player stall when absent.
        Entry("fwmrm.net", "FreeWheel", Risk.CONDITIONAL, "Video ad server used by large streaming apps"),
        Entry("freewheel.tv", "FreeWheel", Risk.CONDITIONAL, "Video ad server used by large streaming apps"),

        // In-app rewarded video networks: blocking them removes the advert, but an app that
        // gates content behind "watch to unlock" can show an error instead.
        Entry("unityads.unity3d.com", "Unity Ads", Risk.CONDITIONAL, "Rewarded video in games"),
        Entry("applovin.com", "AppLovin", Risk.CONDITIONAL, "Rewarded video in games"),
        Entry("vungle.com", "Vungle", Risk.CONDITIONAL, "Rewarded video in games"),
        Entry("adcolony.com", "AdColony", Risk.CONDITIONAL, "Rewarded video in games"),
        Entry("chartboost.com", "Chartboost", Risk.CONDITIONAL, "Rewarded video in games"),
        Entry("ironsrc.com", "ironSource", Risk.CONDITIONAL, "Rewarded video in games"),
        Entry("inmobi.com", "InMobi", Risk.CONDITIONAL, "Rewarded video in games")
    )

    /** The catalogue entry whose zone contains [input], or null. Label boundaries are strict. */
    fun entryFor(input: String): Entry? {
        val domain = DnsMediaPlaybackGuard.normalizeDomain(input)
        if (domain.isEmpty()) return null
        return ENTRIES.firstOrNull { entry ->
            domain == entry.suffix || domain.endsWith(".${entry.suffix}")
        }
    }

    /**
     * The enforcement decision for [input], or null when the catalogue does not cover it.
     *
     * Playback always wins: a host the playback guard protects is never blocked from here, and
     * [Risk.CONDITIONAL] entries need [allowConditional] (the aggressive modes) before they are
     * blocked. A returned [Match] with `blocked = false` is still useful for diagnostics.
     */
    fun matchForEnforcement(input: String, allowConditional: Boolean): Match? {
        val entry = entryFor(input) ?: return null
        if (DnsMediaPlaybackGuard.isProtectedPlaybackHost(input)) {
            return Match(entry, blocked = false, reason = "Playback infrastructure is never blocked")
        }
        if (entry.risk == Risk.CONDITIONAL && !allowConditional) {
            return Match(
                entry,
                blocked = false,
                reason = "${entry.network} can ship player code; only Strict and Custom block it"
            )
        }
        return Match(
            entry,
            blocked = true,
            reason = "${entry.network}: ${entry.note}"
        )
    }
}
