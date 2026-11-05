package com.adshield.pro.engine.onion

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.webkit.WebResourceResponse
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Proxy
import java.util.concurrent.TimeUnit

enum class TorState(val label: String) {
    NOT_INSTALLED("Orbot is not installed"),
    STOPPED("Orbot is installed but not running"),
    STARTING("Orbot is starting"),
    CONNECTED("Routing through Tor"),
    ERROR("Tor check failed")
}

@Serializable
data class TorCheckResponse(val IsTor: Boolean = false, val IP: String? = null)

data class TorStatus(
    val state: TorState = TorState.NOT_INSTALLED,
    val detail: String = TorState.NOT_INSTALLED.label,
    val socksPort: Int = DEFAULT_SOCKS_PORT,
    val httpPort: Int = DEFAULT_HTTP_PORT,
    val exitIp: String? = null
) {
    val isConnected: Boolean get() = state == TorState.CONNECTED
}

/**
 * Real onion routing through Orbot.
 *
 * This class never pretends: either a SOCKS proxy at 127.0.0.1:9050 answers and Tor's own check
 * service confirms the exit node, or the status says why it did not. There is no local "Tor-like"
 * fallback and no toggle that only changes a label.
 *
 * Orbot is a separate app the user installs; AdShield Pro asks it to start and then verifies the
 * route end to end by asking check.torproject.org what it sees.
 */
class OnionRoutingManager(private val context: Context) {

    private val json = Json { ignoreUnknownKeys = true }

    /** Tor-capable apps AdShield Pro can hand routing to. */
    fun installedTorApps(): List<String> = KNOWN_TOR_PACKAGES.filter { isInstalled(it) }

    fun isInstalled(packageName: String): Boolean = runCatching {
        context.packageManager.getApplicationInfo(packageName, 0).enabled
    }.getOrDefault(false)

    /** Asks Orbot to start and connect. Returns false when no Orbot is present. */
    fun requestStart(packageName: String = ORBOT_PACKAGE): Boolean {
        if (!isInstalled(packageName)) return false
        val intent = Intent(ACTION_START).apply {
            setPackage(packageName)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        val resolved = runCatching {
            context.packageManager.queryIntentActivities(intent, PackageManager.MATCH_DEFAULT_ONLY)
        }.getOrDefault(emptyList())
        if (resolved.isEmpty()) return false
        return runCatching { context.startActivity(intent); true }.getOrDefault(false)
    }

    /** Play Store / F-Droid deep link for installing Orbot. */
    fun installIntent(packageName: String = ORBOT_PACKAGE): Intent =
        Intent(Intent.ACTION_VIEW, Uri.parse("market://details?id=$packageName")).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }

    fun torClient(port: Int = DEFAULT_SOCKS_PORT): OkHttpClient = OkHttpClient.Builder()
        .proxy(socksProxy(port))
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(45, TimeUnit.SECONDS)
        .build()

    /**
     * Proves the route by asking Tor's own check service through the proxy. A direct connection
     * would also reach the service, so only the `IsTor` flag counts as confirmation.
     */
    suspend fun verify(port: Int = DEFAULT_SOCKS_PORT): TorStatus = withContext(Dispatchers.IO) {
        if (installedTorApps().isEmpty()) {
            return@withContext TorStatus(TorState.NOT_INSTALLED, "Install Orbot to route through Tor.")
        }
        val client = torClient(port)
        val request = Request.Builder().url(TOR_CHECK_URL).get().build()
        val raw = try {
            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    return@withContext TorStatus(
                        TorState.STOPPED,
                        "No answer from the Tor SOCKS proxy on $PROXY_HOST:$port. Start Orbot and wait for it to connect."
                    )
                }
                response.body?.string().orEmpty()
            }
        } catch (e: IOException) {
            return@withContext TorStatus(TorState.STOPPED, "Tor proxy refused the connection: ${e.message}")
        }
        val parsed = runCatching { json.decodeFromString<TorCheckResponse>(raw) }.getOrNull()
            ?: return@withContext TorStatus(TorState.ERROR, "Tor check service returned an unreadable answer.")
        if (!parsed.IsTor) {
            return@withContext TorStatus(TorState.STOPPED, "Traffic reached the internet directly, not through Tor.")
        }
        TorStatus(TorState.CONNECTED, "Confirmed by check.torproject.org through the SOCKS proxy.", port, DEFAULT_HTTP_PORT, parsed.IP)
    }

    /**
     * Fetches a resource through Tor for the WebView interceptor.
     *
     * Returns null on failure so the caller can fall back to the ordinary path rather than showing
     * a blank page; failures are reported by the caller's status check, not hidden here.
     */
    fun fetch(url: String, headers: Map<String, String> = emptyMap(), port: Int = DEFAULT_SOCKS_PORT): WebResourceResponse? =
        runCatching {
            val builder = Request.Builder().url(url).get()
            headers.forEach { (name, value) ->
                if (name.lowercase() !in HOP_BY_HOP_HEADERS) builder.header(name, value)
            }
            val response = torClient(port).newCall(builder.build()).execute()
            if (!response.isSuccessful) {
                response.close()
                return null
            }
            val mimeType = response.header("content-type")?.substringBefore(';')?.trim()
                ?: "application/octet-stream"
            val encoding = response.header("content-encoding")
            val responseHeaders = response.headers.toMultimap()
                .mapValues { (_, values) -> values.joinToString(", ") }
                .toMutableMap()
            // WebView needs CORS headers for cross-origin subresources it would otherwise drop.
            if (url.contains("://")) {
                responseHeaders["Access-Control-Allow-Origin"] = "*"
            }
            val stream = response.body?.byteStream() ?: return null
            WebResourceResponse(
                mimeType,
                encoding,
                response.code,
                response.message.ifBlank { "OK" },
                responseHeaders,
                stream
            )
        }.getOrNull()

    /** `.onion` addresses only resolve over Tor; they are never sent to the device resolver. */
    fun isOnionHost(url: String): Boolean = runCatching {
        Uri.parse(url).host?.lowercase()?.endsWith(".onion") == true
    }.getOrDefault(false)

    companion object {
        const val ORBOT_PACKAGE = "org.torproject.android"
        const val TOR_BROWSER_PACKAGE = "org.torproject.torbrowser_alpha"
        const val ACTION_START = "org.torproject.android.intent.action.START"
        const val ACTION_STATUS = "org.torproject.android.intent.action.STATUS"
        const val EXTRA_STATUS = "org.torproject.android.intent.extra.STATUS"
        const val EXTRA_PROXY_SOCKS = "org.torproject.android.intent.extra.PROXY_SOCKS"
        const val EXTRA_PROXY_HTTP = "org.torproject.android.intent.extra.PROXY_HTTP"
        const val STATUS_ON = "ON"
        const val STATUS_STARTING = "STARTING"
        const val STATUS_OFF = "OFF"
        const val PROXY_HOST = "127.0.0.1"
        const val DEFAULT_SOCKS_PORT = 9050
        const val DEFAULT_HTTP_PORT = 8118
        const val TOR_CHECK_URL = "https://check.torproject.org/api/ip"

        val KNOWN_TOR_PACKAGES = listOf(ORBOT_PACKAGE, TOR_BROWSER_PACKAGE)

        /**
         * Unresolved on purpose: the hostname must be resolved by the Tor exit, never by the
         * device resolver, or a .onion address would leak to the local DNS server.
         */
        fun socksProxy(port: Int = DEFAULT_SOCKS_PORT): Proxy =
            Proxy(Proxy.Type.SOCKS, InetSocketAddress.createUnresolved(PROXY_HOST, port))

        /** Parses Orbot's STATUS broadcast. Pure, so it is verifiable without Android. */
        fun parseStatus(status: String?, socks: Int?, http: Int?): TorStatus = when (status?.uppercase()) {
            STATUS_ON -> TorState.CONNECTED
            STATUS_STARTING -> TorState.STARTING
            STATUS_OFF -> TorState.STOPPED
            else -> TorState.STOPPED
        }.let { state ->
            TorStatus(
                state = state,
                detail = when (state) {
                    TorState.CONNECTED -> "Orbot reports a connected circuit."
                    TorState.STARTING -> "Orbot is building a circuit."
                    else -> "Orbot is not connected."
                },
                socksPort = socks?.takeIf { it > 0 } ?: DEFAULT_SOCKS_PORT,
                httpPort = http?.takeIf { it > 0 } ?: DEFAULT_HTTP_PORT
            )
        }

        private val HOP_BY_HOP_HEADERS = setOf(
            "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
            "te", "trailer", "transfer-encoding", "upgrade", "host", "accept-encoding"
        )
    }
}
