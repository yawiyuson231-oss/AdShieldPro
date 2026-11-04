package com.adshield.pro.engine.compat

/**
 * OmniShield X Infinity — Critical Content & Authentication Protection (Module 4/5).
 *
 * Registrable domains in this catalog are NEVER blocked by filter lists, in any
 * protection mode. They cover shared content-delivery infrastructure (video/audio
 * streaming, thumbnails), authentication/login endpoints, payment & banking,
 * app-store/OS updates, game servers and messaging — the domains that break user
 * experience when aggressive lists collide with them.
 *
 * Philosophy (Module 5 spec): never block a shared content-delivery domain merely
 * because it *might* serve advertisements. Explicit USER custom block rules still
 * take precedence (checked earlier in the evaluation ladder) — this layer only
 * protects against automated blocklist rules.
 *
 * NOTE (honest scope): this is a domain-level safety net for DNS filtering. It does
 * not and cannot remove ads served from the same domains as content (e.g. YouTube
 * in-app video ads) — that is disclosed in the UI.
 */
object ProtectedDomainCatalog {

    enum class ProtectionGroup(val label: String) {
        VIDEO_STREAMING("Video & Streaming Content"),
        AUTH_IDENTITY("Authentication & Identity"),
        PAYMENTS_BANKING("Payments & Banking"),
        APP_STORE_UPDATES("App Store & System Updates"),
        GAME_SERVERS("Game Servers"),
        MESSAGING("Messaging & Notifications")
    }

    private val catalog: Map<String, ProtectionGroup> = buildMap {
        // --- Video & streaming content (playback + thumbnails) ---
        putGroup(
            ProtectionGroup.VIDEO_STREAMING,
            "googlevideo.com", "ytimg.com", "youtube.com", "youtube-nocookie.com",
            "netflix.com", "nflxvideo.net", "nflxso.net", "nflximg.net", "nflxext.com",
            "hulu.com", "huluim.com", "primevideo.com", "media-amazon.com", "amazonvideo.com",
            "disneyplus.com", "disney-plus.net", "dssott.com", "bamgrid.com",
            "twitch.tv", "twitchcdn.net", "jtvnw.net",
            "tiktok.com", "tiktokcdn.com", "tiktokv.com", "muscdn.com", "musical.ly", "ibyteimg.com",
            "facebook.com", "fbcdn.net", "instagram.com", "cdninstagram.com",
            "vimeo.com", "vimeocdn.com", "dailymotion.com", "dmcdn.net",
            "spotify.com", "scdn.co", "spotifycdn.com",
            "pinterest.com", "pinimg.com"
        )

        // --- Authentication, identity, OS infra ---
        // NOTE: vendors like Microsoft/Apple also serve TELEMETRY from their main domains,
        // so only genuine auth/update hosts are protected there — Strict telemetry blocking
        // must keep working (verified in DnsFirewallCompatibilityTest + legacy suite).
        putGroup(
            ProtectionGroup.AUTH_IDENTITY,
            "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
            "gvt1.com", "gvt2.com", "withgoogle.com",
            "login.microsoftonline.com", "login.live.com", "live.com", "outlook.com",
            "office.com", "windowsupdate.com", "wustat.windows.com", "do.dsp.mp.microsoft.com",
            "appleid.apple.com", "icloud.com", "mesu.apple.com", "gs.apple.com", "mzstatic.com",
            "okta.com", "auth0.com", "onelogin.com",
            "twitter.com", "x.com", "twimg.com",
            "reddit.com", "redd.it", "redditmedia.com", "redditstatic.com",
            "linkedin.com", "licdn.com",
            "yahoo.com", "yimg.com"
        )

        // --- Payments & banking ---
        putGroup(
            ProtectionGroup.PAYMENTS_BANKING,
            "paypal.com", "paypalobjects.com", "venmo.com", "stripe.com", "checkout.com",
            "braintreegateway.com", "braintreepayments.com", "adyen.com", "worldpay.com",
            "squareup.com", "gcash.com", "mynt.xyz", "coins.ph", "paymaya.com", "grab.com",
            "wise.com", "revolut.com", "chase.com", "bankofamerica.com", "wellsfargo.com",
            "citi.com", "hsbc.com", "bpi.com.ph", "bdo.com.ph"
        )

        // --- App stores & OS updates ---
        putGroup(
            ProtectionGroup.APP_STORE_UPDATES,
            "android.com", "samsung.com", "samsungcloud.com", "samsungapps.com",
            "mi.com", "miui.com", "huawei.com", "hicloud.com", "oppomobile.com",
            "vivo.com", "realme.com", "oneplus.com", "amazon.com"
        )

        // --- Game servers (match Module 5/12: games must never break) ---
        putGroup(
            ProtectionGroup.GAME_SERVERS,
            "aena.ms", "moonton.com", "mobilelegends.com",
            "supercell.com", "clashofclans.com", "clashroyaleapp.com",
            "roblox.com", "rbxcdn.com",
            "riotgames.com", "riotcdn.net",
            "epicgames.com", "unrealengine.com",
            "activision.com", "callofduty.com",
            "garena.com", "garenanow.com",
            "mihoyo.com", "hoyoverse.com", "yuanshen.com",
            "konami.com", "minecraft.net", "mojang.com",
            "steampowered.com", "steamcontent.com", "steamcommunity.com",
            "ea.com", "origin.com", "nintendo.com"
        )

        // --- Messaging & notifications ---
        putGroup(
            ProtectionGroup.MESSAGING,
            "whatsapp.com", "whatsapp.net", "telegram.org", "t.me", "signal.org",
            "discord.com", "discordapp.com", "discordapp.net", "discord.media",
            "line.me", "line-scdn.net", "snapchat.com", "sc-cdn.net"
        )
    }

    /** Flat O(1) lookup set of every protected registrable domain. */
    val protectedDomains: Set<String> = catalog.keys

    private fun MutableMap<String, ProtectionGroup>.putGroup(group: ProtectionGroup, vararg domains: String) {
        for (d in domains) put(d, group)
    }

    /**
     * Returns the protection label when [registrableDomain] (or any suffix walked by the
     * caller) is protected, else null. Called on every suffix of the queried domain.
     */
    fun protectionLabelFor(registrableDomain: String): String? {
        val group = catalog[registrableDomain] ?: return null
        return "Critical Protection (${group.label})"
    }

    /** True when the domain falls under a protected registrable domain. */
    fun isProtected(domain: String): Boolean {
        val d = domain.trim().lowercase().trimEnd('.')
        var cursor: String? = d
        while (cursor != null) {
            if (catalog.containsKey(cursor)) return true
            cursor = if (cursor.contains('.')) cursor.substringAfter('.') else null
        }
        return false
    }

    /** Explainability helper (Module 3): which group shields a domain, if any. */
    fun groupFor(domain: String): ProtectionGroup? {
        var cursor: String? = domain.trim().lowercase().trimEnd('.')
        while (cursor != null) {
            catalog[cursor]?.let { return it }
            cursor = if (cursor.contains('.')) cursor.substringAfter('.') else null
        }
        return null
    }
}
