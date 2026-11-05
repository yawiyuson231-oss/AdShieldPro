package com.adshield.pro.gps.nav

import android.content.Context
import com.adshield.pro.gps.routing.RouteProgress
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AdShield Pro — TextToSpeech implementation of [VoiceGuidanceApi].
 *
 * A thin, thread-safe wrapper: the navigation session calls it from a background coroutine, the
 * Compose screen calls it from the main thread, and Android's TTS engine does not like being
 * initialised twice. Initialisation is therefore idempotent and guarded by a lock.
 */
@Singleton
class TtsVoiceGuidance @Inject constructor(
    @ApplicationContext private val context: Context
) : VoiceGuidanceApi {

    private val guidance = VoiceGuidance(context)
    private val lock = Any()

    @Volatile
    private var enabled: Boolean = true

    @Volatile
    private var initialised: Boolean = false

    /** Called by the ViewModel whenever the privacy policy changes. */
    fun setGuidanceEnabled(value: Boolean) {
        enabled = value
        if (!value) guidance.stop()
    }

    fun prepare(languageTag: String = "en-US") {
        synchronized(lock) {
            if (initialised) return
            initialised = true
            guidance.initialise(languageTag)
        }
    }

    fun setLanguage(tag: String) = guidance.setLanguage(tag)

    val availability: VoiceGuidance.State get() = guidance.availability
    val lastError: String? get() = guidance.lastError
    fun languageTag(): String = guidance.languageTag()

    override fun announce(progress: RouteProgress): String? {
        if (!enabled) return null
        prepare()
        return guidance.onProgress(progress, enabled = true)
    }

    override fun onReroute(announcement: String?): String? {
        if (!enabled) return null
        prepare()
        return guidance.onReroute(announcement)
    }

    override fun announceArrival() {
        if (!enabled) return
        prepare()
        guidance.announceArrival()
    }

    override fun stop() = guidance.stop()

    fun speakTestPhrase(): String {
        prepare()
        val text = "AdShield navigation voice is ready. Turn left in 200 metres."
        guidance.speak(text, flush = true)
        return text
    }

    fun shutdown() = guidance.shutdown()
}
