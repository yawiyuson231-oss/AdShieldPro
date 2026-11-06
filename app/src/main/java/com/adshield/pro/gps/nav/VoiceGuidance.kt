package com.adshield.pro.gps.nav

import android.content.Context
import android.speech.tts.TextToSpeech
import android.speech.tts.UtteranceProgressListener
import com.adshield.pro.gps.routing.NavigationPhrases
import com.adshield.pro.gps.routing.RouteProgress
import java.util.Locale

/**
 * AdShield Pro — voice guidance.
 *
 * Uses Android's own `TextToSpeech` engine (offline voices are available for most languages once
 * downloaded in system settings; the app never downloads or bundles a voice, and never needs a
 * network connection to speak).
 *
 * Announcing rules, deliberately conservative:
 *  - one announcement per distance band (1 km / 400 m / 120 m / 25 m), never per fix;
 *  - the same step is never repeated within [repeatGuardMs];
 *  - reroute and arrival are announced once;
 *  - if the engine has no voice for the preferred language, the app reports that instead of
 *    speaking English with a foreign phoneme set.
 */
class VoiceGuidance(private val context: Context) {

    enum class State { UNINITIALISED, INITIALISING, READY, UNAVAILABLE, LANGUAGE_MISSING }

    private var tts: TextToSpeech? = null
    private var state: State = State.UNINITIALISED
    private var lastAnnouncedStep: Int = -1
    private var lastAnnouncedBand: Int = -1
    private var lastAnnounceAtMs: Long = 0L
    private var lastRerouteAtMs: Long = 0L
    private var language: Locale = Locale.US
    var lastError: String? = null
        private set

    val availability: State get() = state

    fun languageTag(): String = language.toLanguageTag()

    /** Initialises the engine. Safe to call repeatedly; only the first call does work. */
    fun initialise(languageTag: String = "en-US", onReady: (Boolean) -> Unit = {}) {
        if (state == State.INITIALISING || state == State.READY) {
            onReady(state == State.READY)
            return
        }
        state = State.INITIALISING
        val requested = Locale.forLanguageTag(languageTag.ifBlank { "en-US" })
        tts = TextToSpeech(context) { status ->
            if (status != TextToSpeech.SUCCESS) {
                state = State.UNAVAILABLE
                lastError = "Text-to-speech engine unavailable on this device"
                onReady(false)
                return@TextToSpeech
            }
            val engine = tts
            if (engine == null) {
                state = State.UNAVAILABLE
                onReady(false)
                return@TextToSpeech
            }
            val result = engine.setLanguage(requested)
            language = requested
            if (result == TextToSpeech.LANG_MISSING_DATA || result == TextToSpeech.LANG_NOT_SUPPORTED) {
                // Try the device default before giving up.
                val fallback = engine.setLanguage(Locale.getDefault())
                if (fallback == TextToSpeech.LANG_MISSING_DATA || fallback == TextToSpeech.LANG_NOT_SUPPORTED) {
                    state = State.LANGUAGE_MISSING
                    lastError = "No installed voice for ${requested.displayLanguage}. " +
                        "Install a voice in Android settings → Text-to-speech output."
                    onReady(false)
                    return@TextToSpeech
                }
                language = Locale.getDefault()
            }
            engine.setSpeechRate(0.98f)
            engine.setPitch(1.0f)
            engine.setOnUtteranceProgressListener(object : UtteranceProgressListener() {
                override fun onStart(utteranceId: String?) = Unit
                override fun onDone(utteranceId: String?) = Unit

                @Deprecated("Deprecated in Java")
                override fun onError(utteranceId: String?) {
                    lastError = "Speech synthesis failed"
                }

                override fun onError(utteranceId: String?, errorCode: Int) {
                    lastError = "Speech synthesis failed ($errorCode)"
                }
            })
            state = State.READY
            onReady(true)
        }
    }

    fun setLanguage(languageTag: String) {
        val locale = Locale.forLanguageTag(languageTag)
        val result = tts?.setLanguage(locale)
        if (result == TextToSpeech.LANG_MISSING_DATA || result == TextToSpeech.LANG_NOT_SUPPORTED) {
            state = State.LANGUAGE_MISSING
            lastError = "No installed voice for ${locale.displayLanguage}"
        } else {
            language = locale
            state = State.READY
        }
    }

    fun speak(text: String, flush: Boolean = false) {
        if (state != State.READY) return
        val engine = tts ?: return
        if (text.isBlank()) return
        // Unique per call: reusing a fixed id makes UtteranceProgressListener report the wrong one.
        val utterance = "adshield-nav-${System.nanoTime()}"
        val queued = engine.speak(text, if (flush) TextToSpeech.QUEUE_FLUSH else TextToSpeech.QUEUE_ADD, null, utterance)
        if (queued != TextToSpeech.SUCCESS) {
            lastError = "The speech engine refused the announcement"
        }
    }

    /**
     * Evaluates a route progress and speaks when appropriate. Returns the text spoken (for the
     * on-screen banner and for tests), or null when nothing was said.
     */
    fun onProgress(progress: RouteProgress, enabled: Boolean): String? {
        if (!enabled || state != State.READY) return null
        val now = System.currentTimeMillis()
        if (progress.finished) {
            if (lastAnnouncedStep != ARRIVED) {
                lastAnnouncedStep = ARRIVED
                val text = "You have arrived at your destination"
                speak(text, flush = true)
                return text
            }
            return null
        }
        val band = NavigationPhrases.announcementBand(progress.distanceToNextManeuverMeters)
        val step = progress.currentStepIndex
        if (band == null) return null
        val sameStep = step == lastAnnouncedStep
        val closerBand = band < lastAnnouncedBand
        val repeated = sameStep && band == lastAnnouncedBand && now - lastAnnounceAtMs > repeatGuardMs(sameStep = true)
        if (sameStep && !closerBand && !repeated) return null

        val instruction = progress.nextInstruction ?: return null
        val text = NavigationPhrases.spokenDistance(progress.distanceToNextManeuverMeters) + ", " +
            instruction.replaceFirstChar { it.lowercase() }
        speak(text)
        lastAnnouncedStep = step
        lastAnnouncedBand = band
        lastAnnounceAtMs = now
        return text
    }

    /** Announced once per reroute; the caller decides when a reroute actually happened. */
    fun onReroute(newInstruction: String?): String? {
        val now = System.currentTimeMillis()
        if (now - lastRerouteAtMs < 8_000L) return null
        lastRerouteAtMs = now
        val text = newInstruction?.let { "Route recalculated. $it" } ?: "Route recalculated"
        speak(text, flush = true)
        lastAnnouncedStep = -1
        lastAnnouncedBand = -1
        return text
    }

    fun announceArrival() = speak("You have arrived at your destination", flush = true)

    fun onOffRoute() {
        val now = System.currentTimeMillis()
        if (now - lastRerouteAtMs < 15_000L) return
        lastRerouteAtMs = now
        speak("You are off route", flush = false)
    }

    fun stop() {
        tts?.stop()
    }

    /**
     * Releases the engine and returns the instance to UNINITIALISED.
     *
     * Safe to call when nothing was ever initialised, and safe to call twice. `TextToSpeech` holds a
     * bound service and a native synthesiser, so not calling this leaks both for the life of the
     * process — which matters here because the guidance object is an app-scoped singleton.
     */
    fun shutdown() {
        runCatching { tts?.stop() }
        runCatching { tts?.shutdown() }
        tts = null
        state = State.UNINITIALISED
        lastAnnouncedStep = -1
        lastAnnouncedBand = -1
        lastAnnounceAtMs = 0L
        lastRerouteAtMs = 0L
        lastError = null
    }

    private fun repeatGuardMs(sameStep: Boolean): Long = if (sameStep) 45_000L else 15_000L

    companion object {
        private const val ARRIVED = -99

        /** Language tags offered in the settings sheet — every one is a normal TTS locale. */
        val SUPPORTED_LANGUAGES: List<Pair<String, String>> = listOf(
            "English (US)" to "en-US",
            "English (UK)" to "en-GB",
            "English (Philippines)" to "en-PH",
            "Filipino" to "fil-PH",
            "Spanish" to "es-ES",
            "French" to "fr-FR",
            "German" to "de-DE",
            "Portuguese (Brazil)" to "pt-BR",
            "Indonesian" to "id-ID",
            "Hindi" to "hi-IN",
            "Japanese" to "ja-JP",
            "Korean" to "ko-KR",
            "Mandarin (China)" to "zh-CN",
            "Arabic" to "ar-SA",
            "Russian" to "ru-RU"
        )
    }
}
