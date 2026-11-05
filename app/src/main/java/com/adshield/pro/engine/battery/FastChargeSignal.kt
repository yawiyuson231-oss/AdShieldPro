package com.adshield.pro.engine.battery

/**
 * AdShield Pro — fast-charge detection from real platform signals.
 *
 * The important design point: [NONE] is the normal case. Many Android builds expose no fast-charge
 * API at all, and the app must then report "Charging" rather than "Fast charging", even when the
 * user knows a 65 W brick is attached. A claim is only made when this device itself published
 * something that can only mean fast charging, and [Detected.source] is printed verbatim in the UI
 * so the claim can be checked against the hardware.
 */
sealed class FastChargeSignal {
    data object NONE : FastChargeSignal()

    /** [signal] is the platform evidence, printed verbatim in the UI. */
    data class Detected(val signal: String) : FastChargeSignal()

    val isPresent: Boolean get() = this is Detected

    /** The platform evidence behind a claim, or null when nothing was published. */
    val source: String?
        get() = when (this) {
            is Detected -> signal
            NONE -> null
        }

    companion object {
        /**
         * `BATTERY_PROPERTY_STATUS` exists on API 34+, where value 6 means fast charging. It is
         * probed by property id rather than referenced as a constant, because the constant does
         * not exist when compiling against older platform stubs.
         */
        const val PROPERTY_STATUS = 6
        private const val STATUS_FAST_CHARGING = 6

        /**
         * Charger protocol tokens some OEMs publish as a battery property. Deliberately
         * conservative: only strings that can only mean fast charging — never the bare words
         * "charger", "usb" or "ac", which every ordinary charger produces.
         */
        val FAST_PROTOCOL_TOKENS = listOf(
            "usb_pd", "power delivery", "pps", "vooc", "supervooc", "dart", "warp",
            "flash charge", "flash_charge", "turbo", "hypercharge", "supercharge",
            "super charge", "qc3", "qc4", "qc5", "quick charge", "quick_charge",
            "fast charge", "fast_charge", "fastcharge"
        )

        /**
         * Resolves the signal from what the platform exposes.
         *
         * @param statusProperty value of `BATTERY_PROPERTY_STATUS`, or null when the device has no
         *        such property
         * @param chargeProtocol optional OEM protocol string (battery property or extra)
         */
        fun from(statusProperty: Int?, chargeProtocol: String?): FastChargeSignal {
            if (statusProperty == STATUS_FAST_CHARGING) {
                return Detected("BATTERY_PROPERTY_STATUS = fast charging")
            }
            val protocol = chargeProtocol?.lowercase()?.trim()
            if (!protocol.isNullOrBlank()) {
                FAST_PROTOCOL_TOKENS.firstOrNull { protocol.contains(it) }?.let { token ->
                    return Detected("Charger reports \"$token\"")
                }
            }
            return NONE
        }
    }
}
