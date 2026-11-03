package com.adshield.pro.engine

/**
 * OmniShield X — Feature Flags (platform spec: "Ship new protections off by
 * default, behind feature flags").
 *
 * Single source of truth for DEFAULTS. New protection classes land here first;
 * DataStore keys store the user's override on top of these defaults. A new flag
 * ships with: a default, a Settings toggle, and a test asserting the default.
 */
object FeatureFlags {

    // --- Shipped protections (defaults reflect current product decisions) ---
    const val ENCRYPTED_DNS_BYPASS_SHIELD_DEFAULT = true
    const val STRICT_HEURISTICS_SHIELD_DEFAULT = true
    const val UNIVERSAL_AD_SKIP_DEFAULT = true

    // --- Spec: new/off-by-default protections ---
    const val NEW_DOMAIN_CHECK_DEFAULT = false // network RDAP lookups stay opt-in
    const val RESOLVER_AUTO_TUNE_DEFAULT = false // auto provider switching stays opt-in
}
