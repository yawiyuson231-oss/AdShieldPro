package com.adshield.pro.engine.battery

/**
 * Decides which battery conditions deserve a system notification.
 *
 * This was the PARTIAL half of "High-temperature and charging-complete alerts": the diagnostics
 * already produced WARNING/CRITICAL findings and the charge state, but nothing watched them
 * while the app was in the background.
 *
 * The policy is a pure function of a snapshot plus the previous alert state, so the JVM suite
 * can prove the properties that matter:
 *   - a warning is raised once per episode, not once per battery broadcast (no notification spam)
 *   - it re-arms only after the condition genuinely clears (hysteresis, not a timer)
 *   - an unavailable sensor never produces an alert, and a 0 °C driver stub is treated as
 *     missing rather than "cold"
 *   - the "charged" alert fires only while the device is still on the charger
 */
object BatteryAlertPolicy {

    enum class AlertKind(val channelId: String, val title: String) {
        OVERHEAT("adshield_battery_temperature", "Battery is too hot"),
        CHARGED("adshield_battery_charged", "Battery is full"),
        CRITICAL_LEVEL("adshield_battery_level", "Battery is critically low")
    }

    /** A notification to post. [key] makes the notification stable per episode. */
    data class Alert(
        val kind: AlertKind,
        val key: String,
        val title: String,
        val body: String,
        val priorityHigh: Boolean
    )

    /** What the policy remembers between battery broadcasts. */
    data class State(
        val overheatLatched: Boolean = false,
        val chargedLatched: Boolean = false,
        val criticalLatched: Boolean = false
    )

    data class Outcome(val alerts: List<Alert>, val state: State, val reasons: List<String>)

    // Hysteresis bands. A 0.5 °C wobble around the threshold must not re-fire the alert.
    const val OVERHEAT_RAISE_CELSIUS = 44f
    const val OVERHEAT_CLEAR_CELSIUS = 40f
    const val CHARGED_LEVEL = 100
    const val CHARGED_CLEAR_LEVEL = 95
    const val CRITICAL_LEVEL = 15
    const val CRITICAL_CLEAR_LEVEL = 20

    /**
     * Rule chain.
     *
     * @param levelPercent null when the device did not report a level
     * @param temperatureCelsius null when the sensor is missing (0 °C driver stubs must be
     *        normalised to null by the caller — see [isPlausibleTemperature])
     * @param isCharging current charging state from ACTION_BATTERY_CHANGED
     * @param chargingComplete true only when the system reports EXTRA_STATUS == FULL
     * @param alertsEnabled user preference; false clears nothing, it just stops posting
     */
    fun evaluate(
        levelPercent: Int?,
        temperatureCelsius: Float?,
        isCharging: Boolean,
        chargingComplete: Boolean,
        previous: State,
        alertsEnabled: Boolean = true
    ): Outcome {
        val reasons = ArrayList<String>()
        val alerts = ArrayList<Alert>()
        var state = previous

        // Thermal ------------------------------------------------------------
        val temp = temperatureCelsius?.takeIf(::isPlausibleTemperature)
        if (temp == null) {
            reasons.add("temperature unavailable — no alert is possible (this is not a 'cool' reading)")
        } else if (!previous.overheatLatched && temp >= OVERHEAT_RAISE_CELSIUS) {
            alerts.add(
                Alert(
                    kind = AlertKind.OVERHEAT,
                    key = "overheat",
                    title = "Battery is too hot",
                    body = "The battery reports ${format(temp)}°C while ${if (isCharging) "charging" else "in use"}. " +
                        "Unplug and let it cool below ${format(OVERHEAT_CLEAR_CELSIUS)}°C — heat permanently ages lithium cells.",
                    priorityHigh = true
                )
            )
            state = state.copy(overheatLatched = true)
            reasons.add("raised the overheat alert at ${format(temp)}°C")
        } else if (previous.overheatLatched && temp <= OVERHEAT_CLEAR_CELSIUS) {
            state = state.copy(overheatLatched = false)
            reasons.add("cleared the overheat alert at ${format(temp)}°C")
        } else if (previous.overheatLatched) {
            reasons.add("overheat alert stays latched: ${format(temp)}°C is still above ${format(OVERHEAT_CLEAR_CELSIUS)}°C")
        }

        // Charging complete ---------------------------------------------------
        val full = chargingComplete || (levelPercent != null && levelPercent >= CHARGED_LEVEL && isCharging)
        if (!previous.chargedLatched && full && isCharging) {
            alerts.add(
                Alert(
                    kind = AlertKind.CHARGED,
                    key = "charged",
                    title = "Battery is full",
                    body = "Charging is complete${levelPercent?.let { " at $it%" } ?: ""}. Unplugging now avoids the " +
                        "trickle-charge heat that ages the cell, and the charger stays cool.",
                    priorityHigh = false
                )
            )
            state = state.copy(chargedLatched = true)
            reasons.add("raised the charged alert")
        } else if (previous.chargedLatched && (!isCharging || (levelPercent != null && levelPercent < CHARGED_CLEAR_LEVEL))) {
            state = state.copy(chargedLatched = false)
            reasons.add("re-armed the charged alert (unplugged or level fell)")
        }

        // Critically low level ------------------------------------------------
        if (levelPercent != null) {
            if (!previous.criticalLatched && levelPercent <= CRITICAL_LEVEL) {
                alerts.add(
                    Alert(
                        kind = AlertKind.CRITICAL_LEVEL,
                        key = "critical-level",
                        title = "Battery is critically low",
                        body = "$levelPercent% remaining. Plug in now to avoid an unsafe shutdown; protection " +
                            "continues while the device is on.",
                        priorityHigh = true
                    )
                )
                state = state.copy(criticalLatched = true)
                reasons.add("raised the low-level alert at $levelPercent%")
            } else if (previous.criticalLatched && levelPercent >= CRITICAL_CLEAR_LEVEL) {
                state = state.copy(criticalLatched = false)
                reasons.add("re-armed the low-level alert at $levelPercent%")
            }
        }

        if (!alertsEnabled) {
            // A disabled preference must not lose the latch: keep the state so re-enabling
            // does not spam a notification for a condition the user already saw.
            return Outcome(emptyList(), state, listOf("alerts are disabled in settings; state updated silently") + reasons)
        }
        return Outcome(alerts, state, reasons)
    }

    /**
     * Several OEM drivers report exactly 0 °C when no sensor is wired. Treat that as missing
     * instead of "the battery is freezing", matching DeviceCompatibility's rule.
     */
    fun isPlausibleTemperature(celsius: Float): Boolean {
        if (celsius.isNaN() || celsius.isInfinite()) return false
        if (celsius == 0f) return false
        return celsius > -20f && celsius < 90f
    }

    /**
     * Builds the diagnostics-derived alert body for a CRITICAL finding, so the notification says
     * what the rule chain actually concluded instead of a generic warning.
     */
    fun forCriticalDiagnostic(diagnostic: BatteryDiagnostic): Alert? {
        if (diagnostic.severity != BatteryDiagnosticSeverity.CRITICAL) return null
        return Alert(
            kind = AlertKind.OVERHEAT,
            key = "diagnostic:${diagnostic.title.lowercase().replace(' ', '-')}",
            title = diagnostic.title,
            body = diagnostic.recommendation,
            priorityHigh = true
        )
    }

    private fun format(value: Float): String = String.format(java.util.Locale.US, "%.1f", value)
}
