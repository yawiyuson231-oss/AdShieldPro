package com.adshield.pro.engine.filter

/**
 * Account, captcha, single-sign-on and payment zones that no rule is allowed to block.
 *
 * A DNS filter that blocks hard enough will eventually block a host that a login, a checkout or a
 * captcha needs, and the user experiences it as "the app is broken", not as "one advert fewer".
 * These zones are therefore exempted inside the rule engine itself (the `System Safety Allowlist`
 * step, which runs before any feed rule) instead of being left to the quality of the installed
 * lists. It also makes emergency allowlist-only mode usable: logins and payments keep working.
 *
 * Limits, stated plainly: this protects the named zones only. An app that resolves through its own
 * encrypted resolver never reaches the tunnel, and no list of zones can anticipate a host that a
 * single app invents for itself.
 */
object LoginSafetyAllowlist {

    /**
     * Host-level zones for identity, captcha, SSO and payments. Matched on host-or-subdomain, so
     * `login.paypal.com` is covered by `paypal.com` while `evil-paypal.com` is not.
     */
    val ZONES: Set<String> = setOf(
        // Google identity (account chooser, OAuth consent, YouTube sign-in)
        "accounts.google.com",
        "oauth2.googleapis.com",
        "myaccount.google.com",
        "accounts.youtube.com",

        // Apple identity (Apple ID sign-in and two-factor)
        "appleid.apple.com",
        "idmsa.apple.com",

        // Microsoft identity (personal, work/school and ADFS)
        "login.microsoftonline.com",
        "login.live.com",
        "login.microsoft.com",
        "login.windows.net",
        "account.microsoft.com",

        // Bot checks: a blocked captcha is a form that can never be submitted
        "hcaptcha.com",
        "challenges.cloudflare.com",
        "arkoselabs.com",
        "funcaptcha.com",
        "recaptcha.net",

        // Payments and subscriptions
        "paypal.com",
        "stripe.com",
        "braintreegateway.com",
        "adyen.com",
        "checkout.com",
        "worldpay.com",
        "squareup.com",

        // Identity providers and SSO used by third-party apps
        "okta.com",
        "auth0.com",
        "onelogin.com",
        "duosecurity.com",
        "id.me",
        "login.gov"
    )

    private fun matchesHostOrSubdomain(domain: String, zone: String): Boolean =
        domain == zone || domain.endsWith(".$zone")

    /** True when [input] belongs to a zone that must never be blocked. */
    fun isLoginCritical(input: String): Boolean {
        val domain = DnsMediaPlaybackGuard.normalizeDomain(input)
        if (domain.isEmpty()) return false
        return ZONES.any { matchesHostOrSubdomain(domain, it) }
    }
}
