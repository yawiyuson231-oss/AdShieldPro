package com.adshield.pro.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import androidx.lifecycle.LifecycleService
import com.adshield.pro.MainActivity
import com.adshield.pro.R
import com.adshield.pro.gps.engine.GpsEngine
import com.adshield.pro.gps.routing.RouteProgress
import com.adshield.pro.gps.geo.Geodesy
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull

/**
 * AdShield Pro — GPS console foreground service.
 *
 * Exists for one reason Android makes unavoidable: a session that must keep receiving GNSS fixes
 * with the screen off needs a foreground service with `foregroundServiceType="location"`. Without
 * it the OS suspends location updates as soon as the activity stops.
 *
 * Scope kept deliberately narrow, so it can never masquerade as the DNS/VPN module:
 *  - it does not touch VpnService, the tunnel, rules or filter state;
 *  - it does not persist anything itself (TripRecorder does, and only when the user opted in);
 *  - it stops itself as soon as navigation ends or the user stops it.
 *
 * The notification shows the real current state (speed, accuracy, next instruction). If there is no
 * fix yet it says "Searching" instead of inventing a speed.
 */
@AndroidEntryPoint
class GpsConsoleService : LifecycleService() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

    /**
     * The app-scoped engine, injected rather than created here.
     *
     * The GPS screen already runs this engine while it is visible. Constructing a second one in the
     * service meant two independent LocationManager request loops (double battery, two 1 Hz
     * streams) and two writers on the same integrity/trip state. The engine is reference-counted
     * internally, so starting it from the service is safe while the UI also holds it.
     */
    @Inject lateinit var engine: GpsEngine

    private var notificationJob: Job? = null
    private var lastInstruction: String = "Navigation active"
    private var foregroundStarted = false

    override fun onCreate() {
        super.onCreate()
        createChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        super.onStartCommand(intent, flags, startId)
        when (intent?.action) {
            ACTION_STOP -> {
                stopNavigation()
                return START_NOT_STICKY
            }
            ACTION_START, null -> startNavigation()
        }
        return START_NOT_STICKY
    }

    private fun startNavigation() {
        if (foregroundStarted) return
        val started = try {
            ServiceCompat.startForeground(
                this,
                NOTIFICATION_ID,
                buildNotification("Starting GPS console…", null, null),
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION
                } else {
                    0
                }
            )
            true
        } catch (t: Throwable) {
            // Android 12+ throws if the service is started from the background without an
            // exemption. Report it through the shared state instead of crashing the process.
            _state.value = ServiceState(
                running = false,
                error = "Foreground location service could not start: ${t.message}. " +
                    "Open the app and start navigation from the foreground."
            )
            stopSelf()
            false
        }
        if (!started) return
        foregroundStarted = true

        engine.start(intervalMs = 1_000L, holder = HOLDER_SERVICE)
        _state.value = ServiceState(running = true, error = null)

        notificationJob = scope.launch {
            engine.frame.collect { frame ->
                val fix = frame.fix
                val speed = fix?.speedKmh?.let { "${it.toInt()} km/h" } ?: "no fix yet"
                val accuracy = fix?.accuracyMeters?.let { "±${it.toInt()} m" } ?: "—"
                val text = if (fix == null) {
                    "Searching for satellites"
                } else {
                    "$speed · $accuracy · $lastInstruction"
                }
                ServiceCompat.startForeground(
                    this@GpsConsoleService,
                    NOTIFICATION_ID,
                    buildNotification(text, frame.accuracyBand.label, frame.fixState.label),
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                        ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION
                    } else {
                        0
                    }
                )
                _state.value = _state.value.copy(
                    speedKmh = fix?.speedKmh,
                    accuracyMeters = fix?.accuracyMeters,
                    fixState = frame.fixState.label,
                    integrity = frame.integrity.verdict.label
                )
            }
        }
    }

    /** Called by the navigation screen so the notification carries the live instruction. */
    fun onProgress(progress: RouteProgress) {
        lastInstruction = when {
            progress.finished -> "Arrived"
            progress.nextInstruction != null ->
                "${Geodesy.formatDistance(progress.distanceToNextManeuverMeters)} · ${progress.nextInstruction}"
            else -> "Following route"
        }
        _exportedProgress.value = progress
    }

    private fun stopNavigation() {
        // `cancel()` only *requests* cancellation; a collect body already running would still run
        // its `startForeground` call and re-post the notification microseconds after we removed it,
        // leaving an ongoing notification with no service behind it. Joining waits for that body to
        // finish before we remove the notification.
        val dying = notificationJob
        notificationJob = null
        dying?.cancel()
        if (dying != null) {
            kotlinx.coroutines.runBlocking { runCatching { withTimeoutOrNull(500L) { dying.join() } } }
        }
        // The engine is shared with the UI: releasing our hold lets it stop only if nobody else is
        // collecting. Calling stop() unconditionally here froze the map when a user tapped "Stop"
        // in the notification while the GPS screen was open.
        engine.release(HOLDER_SERVICE)
        foregroundStarted = false
        _state.value = ServiceState(running = false, error = null)
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        notificationJob?.cancel()
        notificationJob = null
        engine.release(HOLDER_SERVICE)
        scope.cancel()
        // If the OS destroys us while navigation was live (low memory, task removed), the ongoing
        // notification must not outlive the service that owns it.
        if (foregroundStarted) {
            ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        }
        foregroundStarted = false
        super.onDestroy()
    }

    /**
     * [START_NOT_STICKY] on purpose: everything this service does is *foreground*. A sticky restart
     * has no intent (so [onStartCommand] falls into `startNavigation`) and cannot legally call
     * `startForeground` from the background on Android 12+, which throws and kills the process in a
     * loop. Nothing is lost by not restarting: navigation is driven by the GPS screen, which
     * restarts it in the foreground.
     */
    override fun onTaskRemoved(rootIntent: android.content.Intent?) {
        stopNavigation()
        super.onTaskRemoved(rootIntent)
    }

    override fun onBind(intent: Intent): IBinder? {
        super.onBind(intent)
        return null // Started-only service: the UI talks to it through the static state flows.
    }

    private fun createChannel() {
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Navigation",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Keeps GPS and turn-by-turn guidance running while the screen is off"
                setShowBadge(false)
            }
            manager.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(content: String, accuracy: String?, state: String?): Notification {
        val open = PendingIntent.getActivity(
            this,
            REQUEST_OPEN,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val stop = PendingIntent.getService(
            this,
            REQUEST_STOP,
            Intent(this, GpsConsoleService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val style = NotificationCompat.BigTextStyle().bigText(content)
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification_shield)
            .setContentTitle("AdShield GPS console")
            .setContentText(content)
            .setStyle(style)
            .setSubText(listOfNotNull(accuracy, state).joinToString(" · ").ifBlank { null })
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .setCategory(NotificationCompat.CATEGORY_NAVIGATION)
            .setContentIntent(open)
            .addAction(0, "Stop", stop)
            .build()
    }

    data class ServiceState(
        val running: Boolean = false,
        val speedKmh: Double? = null,
        val accuracyMeters: Float? = null,
        val fixState: String? = null,
        val integrity: String? = null,
        val error: String? = null
    )

    companion object {
        const val ACTION_START = "com.adshield.pro.gps.START_NAV"
        const val ACTION_STOP = "com.adshield.pro.gps.STOP_NAV"
        private const val CHANNEL_ID = "adshield_gps_navigation"
        private const val NOTIFICATION_ID = 4210
        private const val REQUEST_OPEN = 4211
        private const val REQUEST_STOP = 4212

        /** Holder id for this service, distinct from the UI holder. */
        private const val HOLDER_SERVICE = "navigation-service"

        private val _state = MutableStateFlow(ServiceState())
        val state: StateFlow<ServiceState> = _state.asStateFlow()

        private val _exportedProgress = MutableStateFlow<RouteProgress?>(null)
        val progress: StateFlow<RouteProgress?> = _exportedProgress.asStateFlow()

        fun start(context: Context) {
            val intent = Intent(context, GpsConsoleService::class.java).setAction(ACTION_START)
            try {
                androidx.core.content.ContextCompat.startForegroundService(context, intent)
            } catch (t: Throwable) {
                // Background-start restriction: surfaced to the UI, never swallowed silently.
                _state.value = ServiceState(
                    running = false,
                    error = "Android blocked the background location service: ${t.message}"
                )
            }
        }

        fun stop(context: Context) {
            val intent = Intent(context, GpsConsoleService::class.java).setAction(ACTION_STOP)
            runCatching { context.startService(intent) }
        }
    }
}
