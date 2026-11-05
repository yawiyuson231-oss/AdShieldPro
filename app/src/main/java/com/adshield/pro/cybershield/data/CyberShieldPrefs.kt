package com.adshield.pro.cybershield.data

import android.content.Context
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Dashboard-local preferences. Kept separate from the main DataStore settings
 * so the CyberShield feature is fully additive. Non-secret values only;
 * bearer tokens live in [KeystoreSecretStore].
 */
@Singleton
class CyberShieldPrefs @Inject constructor(
    @ApplicationContext context: Context
) {
    private val prefs = context.getSharedPreferences("cybershield_prefs", Context.MODE_PRIVATE)

    var intelEnabled: Boolean
        get() = prefs.getBoolean(KEY_INTEL_ENABLED, true)
        set(value) = prefs.edit().putBoolean(KEY_INTEL_ENABLED, value).apply()

    /** Explicit, clearly-badged sample markers on the map. Default OFF. */
    var demoMapOverlay: Boolean
        get() = prefs.getBoolean(KEY_DEMO_MAP, false)
        set(value) = prefs.edit().putBoolean(KEY_DEMO_MAP, value).apply()

    /** JSON array of custom cloud endpoints: [{id,name,url,hasToken}]. No secrets. */
    var cloudEndpointsJson: String
        get() = prefs.getString(KEY_CLOUD_ENDPOINTS, "[]") ?: "[]"
        set(value) = prefs.edit().putString(KEY_CLOUD_ENDPOINTS, value).apply()

    companion object {
        private const val KEY_INTEL_ENABLED = "intel_enabled"
        private const val KEY_DEMO_MAP = "demo_map_overlay"
        private const val KEY_CLOUD_ENDPOINTS = "cloud_endpoints_json"
    }
}
