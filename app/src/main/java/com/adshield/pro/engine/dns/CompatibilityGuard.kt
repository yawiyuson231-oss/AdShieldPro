package com.adshield.pro.engine.dns

import javax.inject.Inject
import javax.inject.Singleton

/**
 * INFINITY DNS — Compatibility Guard
 *
 * Ensures essential services are never blocked, preventing false positives
 * that break apps, banking, messaging, gaming, and streaming.
 *
 * Categories of protected domains:
 * - Connectivity checks (Android captive portal)
 * - Google Play Services
 * - Banking & payment apps
 * - Messaging (WhatsApp, Telegram, Signal)
 * - Gaming (Mobile Legends, etc.)
 * - Streaming playback (YouTube, Netflix, etc.)
 * - OS updates & security
 */
@Singleton
class CompatibilityGuard @Inject constructor() {

    enum class ProtectionCategory(val label: String) {
        CONNECTIVITY("Connectivity Checks"),
        PLAY_SERVICES("Google Play Services"),
        BANKING("Banking & Payments"),
        MESSAGING("Messaging Apps"),
        GAMING("Gaming"),
        STREAMING("Streaming Playback"),
        EMAIL("Email Services"),
        OS_UPDATES("OS & Security Updates"),
        AUTHENTICATION("Authentication & SSO"),
        CDN("Content Delivery"),
        ESSENTIAL("Essential Services")
    }

    data class ProtectedDomain(
        val domain: String,
        val category: ProtectionCategory,
        val reason: String,
        val allowSubdomains: Boolean = true
    )

    data class CompatibilityCheck(
        val domain: String,
        val isProtected: Boolean,
        val category: ProtectionCategory?,
        val reason: String?,
        val shouldAllow: Boolean
    )

    companion object {
        val PROTECTED_DOMAINS: List<ProtectedDomain> = listOf(
            // Connectivity checks
            ProtectedDomain("connectivitycheck.gstatic.com", ProtectionCategory.CONNECTIVITY, "Android captive portal detection", true),
            ProtectedDomain("connectivitycheck.android.com", ProtectionCategory.CONNECTIVITY, "Android connectivity check", true),
            ProtectedDomain("clients3.google.com", ProtectionCategory.CONNECTIVITY, "Android connectivity check fallback", true),
            ProtectedDomain("captive.apple.com", ProtectionCategory.CONNECTIVITY, "Apple captive portal (cross-platform)", true),

            // Google Play Services
            ProtectedDomain("play.googleapis.com", ProtectionCategory.PLAY_SERVICES, "Google Play Store API", true),
            ProtectedDomain("android.clients.google.com", ProtectionCategory.PLAY_SERVICES, "Android GMS", true),
            ProtectedDomain("android.googleapis.com", ProtectionCategory.PLAY_SERVICES, "Android GMS", true),
            ProtectedDomain("play-fe.googleapis.com", ProtectionCategory.PLAY_SERVICES, "Play Store frontend", false),
            ProtectedDomain("gmscompliance.googleapis.com", ProtectionCategory.PLAY_SERVICES, "GMS compliance", false),

            // Authentication / SSO
            ProtectedDomain("accounts.google.com", ProtectionCategory.AUTHENTICATION, "Google Sign-In", false),
            ProtectedDomain("accounts.youtube.com", ProtectionCategory.AUTHENTICATION, "YouTube auth", false),
            ProtectedDomain("login.microsoftonline.com", ProtectionCategory.AUTHENTICATION, "Microsoft SSO", true),
            ProtectedDomain("login.live.com", ProtectionCategory.AUTHENTICATION, "Microsoft Live login", true),
            ProtectedDomain("appleid.apple.com", ProtectionCategory.AUTHENTICATION, "Apple ID", true),
            ProtectedDomain("securetoken.googleapis.com", ProtectionCategory.AUTHENTICATION, "Firebase Auth", false),
            ProtectedDomain("identitytoolkit.googleapis.com", ProtectionCategory.AUTHENTICATION, "Firebase Identity", false),

            // Messaging
            ProtectedDomain("whatsapp.com", ProtectionCategory.MESSAGING, "WhatsApp", true),
            ProtectedDomain("whatsapp.net", ProtectionCategory.MESSAGING, "WhatsApp media", true),
            ProtectedDomain("telegram.org", ProtectionCategory.MESSAGING, "Telegram", true),
            ProtectedDomain("signal.org", ProtectionCategory.MESSAGING, "Signal", true),
            ProtectedDomain("viber.com", ProtectionCategory.MESSAGING, "Viber", true),
            ProtectedDomain("messenger.com", ProtectionCategory.MESSAGING, "Facebook Messenger", true),

            // Banking (PH + global)
            ProtectedDomain("gcash.com", ProtectionCategory.BANKING, "GCash", true),
            ProtectedDomain("maya.ph", ProtectionCategory.BANKING, "Maya (PH)", true),
            ProtectedDomain("bdo.com.ph", ProtectionCategory.BANKING, "BDO", true),
            ProtectedDomain("bpi.com.ph", ProtectionCategory.BANKING, "BPI", true),
            ProtectedDomain("metrobank.com.ph", ProtectionCategory.BANKING, "Metrobank", true),
            ProtectedDomain("paypal.com", ProtectionCategory.BANKING, "PayPal", true),
            ProtectedDomain("stripe.com", ProtectionCategory.BANKING, "Stripe payments", true),
            ProtectedDomain("pay.google.com", ProtectionCategory.BANKING, "Google Pay", false),

            // Gaming
            ProtectedDomain("mobilelegends.com", ProtectionCategory.GAMING, "Mobile Legends", true),
            ProtectedDomain("moonton.com", ProtectionCategory.GAMING, "Moonton (MLBB)", true),
            ProtectedDomain("unity3d.com", ProtectionCategory.GAMING, "Unity (careful - only core, not ads)", false),

            // Streaming - playback only
            ProtectedDomain("googlevideo.com", ProtectionCategory.STREAMING, "YouTube media delivery", true),
            ProtectedDomain("youtube.com", ProtectionCategory.STREAMING, "YouTube", true),
            ProtectedDomain("nflxvideo.net", ProtectionCategory.STREAMING, "Netflix media", true),
            ProtectedDomain("nflximg.net", ProtectionCategory.STREAMING, "Netflix images", true),

            // Email
            ProtectedDomain("outlook.com", ProtectionCategory.EMAIL, "Outlook", true),
            ProtectedDomain("gmail.com", ProtectionCategory.EMAIL, "Gmail", true),
            ProtectedDomain("yahoo.com", ProtectionCategory.EMAIL, "Yahoo Mail", true),

            // OS Updates
            ProtectedDomain("update.googleapis.com", ProtectionCategory.OS_UPDATES, "Android updates", false),
            ProtectedDomain("dl.google.com", ProtectionCategory.OS_UPDATES, "Google downloads", false),
            ProtectedDomain("gvt1.com", ProtectionCategory.OS_UPDATES, "Google update delivery", true),

            // CDN (essential)
            ProtectedDomain("gstatic.com", ProtectionCategory.CDN, "Google static content", true),
            ProtectedDomain("googleusercontent.com", ProtectionCategory.CDN, "Google user content", true),
            ProtectedDomain("cloudflare.com", ProtectionCategory.CDN, "Cloudflare", false),
            ProtectedDomain("akamaihd.net", ProtectionCategory.CDN, "Akamai CDN", true),
        )

        // Domains that look like ads but are actually essential sub-resources
        val FALSE_POSITIVE_EXCEPTIONS = setOf(
            "adservice.google.com", // actually Google sign-in related in some contexts - but IS ad serving
            // Note: we deliberately keep this list minimal and well-justified.
            // Each entry must have a documented reason why blocking it breaks legitimate UX.
        )

        // Banking package → required domains mapping (for per-app policy)
        val BANKING_REQUIRED_DOMAINS = mapOf(
            "com.globe.gcash.android" to listOf("gcash.com", "api.gcash.com", "mynt.xyz"),
            "com.paymaya" to listOf("maya.ph", "paymaya.com"),
            "com.bdo.unibank" to listOf("bdo.com.ph"),
            "com.bpi.ng.mobilebanking" to listOf("bpi.com.ph")
        )
    }

    fun check(domain: String): CompatibilityCheck {
        val normalized = domain.lowercase().trim().trimEnd('.')
        if (normalized.isEmpty()) {
            return CompatibilityCheck(domain, false, null, null, false)
        }

        for (protected in PROTECTED_DOMAINS) {
            val matches = if (protected.allowSubdomains) {
                normalized == protected.domain || normalized.endsWith(".${protected.domain}")
            } else {
                normalized == protected.domain
            }
            if (matches) {
                return CompatibilityCheck(
                    domain = normalized,
                    isProtected = true,
                    category = protected.category,
                    reason = protected.reason,
                    shouldAllow = true
                )
            }
        }

        return CompatibilityCheck(
            domain = normalized, isProtected = false,
            category = null, reason = null, shouldAllow = false
        )
    }

    fun isProtected(domain: String): Boolean = check(domain).isProtected

    fun getProtectedDomainsByCategory(category: ProtectionCategory): List<ProtectedDomain> {
        return PROTECTED_DOMAINS.filter { it.category == category }
    }

    /**
     * Validate that a proposed block rule doesn't break essential services.
     * Returns null if safe, or the compatibility issue if it would break something.
     */
    fun validateBlockRule(domain: String): CompatibilityCheck? {
        val check = check(domain)
        return if (check.isProtected) check else null
    }

    /**
     * Get all domains that should never be blocked.
     */
    fun getAllProtectedDomains(): Set<String> = PROTECTED_DOMAINS.map { it.domain }.toSet()

    /**
     * Generate allowlist entries for emergency fallback.
     */
    fun generateEmergencyAllowlist(): Set<String> {
        return PROTECTED_DOMAINS
            .filter { it.category in setOf(
                ProtectionCategory.CONNECTIVITY,
                ProtectionCategory.PLAY_SERVICES,
                ProtectionCategory.AUTHENTICATION,
                ProtectionCategory.OS_UPDATES
            )}
            .map { it.domain }.toSet()
    }
}
