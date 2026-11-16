package com.adshield.pro.ui.model

/**
 * One bounded pass-through lease, as the Settings screen shows it.
 *
 * The screen shows the wall-clock time the lease ends instead of a live countdown: an absolute time
 * stays true without a ticker, and a ticking label would recompose every second for no gain.
 */
data class TemporaryLeaseUi(
    val domain: String,
    val endsAtLabel: String,
    val minutesLeft: Long
)

object TemporaryLeaseText {

    /** "12 min left" / "less than a minute left" / "ending now". */
    fun remainingLabel(minutesLeft: Long): String = when {
        minutesLeft <= 0L -> "ending now"
        minutesLeft == 1L -> "1 min left"
        else -> "$minutesLeft min left"
    }
}
