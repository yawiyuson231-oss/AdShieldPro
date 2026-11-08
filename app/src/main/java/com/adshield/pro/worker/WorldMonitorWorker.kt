package com.adshield.pro.worker

import android.content.Context
import android.util.AtomicFile
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.adshield.pro.engine.world.WorldMonitorPolicy
import com.adshield.pro.engine.world.WorldMonitorPolicy.string
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put
import okhttp3.Call
import okhttp3.Callback
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.util.concurrent.TimeUnit
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Opt-in, best-effort daily refresh. No foreground service, exact alarm, location or account.
 * URLs come exclusively from the packaged, generated provider registry. Custom feeds are not
 * silently given native-network access: they remain browser-only and clearly labelled as such.
 */
class WorldMonitorWorker(appContext: Context, params: WorkerParameters) : CoroutineWorker(appContext, params) {
    private val client = OkHttpClient.Builder()
        .connectTimeout(8, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .callTimeout(22, TimeUnit.SECONDS)
        .followRedirects(false)
        .followSslRedirects(false)
        .build()

    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        val prefs = applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        if (!prefs.getBoolean(ENABLED, false)) return@withContext Result.success()
        try {
            val wanted = prefs.getStringSet(SOURCES, emptySet()).orEmpty().toSet()
            val old = runCatching {
                cacheFile(applicationContext).openRead().use { input ->
                    val text = WorldMonitorPolicy.readBoundedUtf8(input, WorldMonitorPolicy.MAX_SNAPSHOT_BYTES)
                    (Json.parseToJsonElement(text).jsonObject["sources"] as? JsonArray).orEmpty()
                        .mapNotNull { element -> (element as? JsonObject)?.let { it.string("id")?.let { id -> id to it } } }.toMap()
                }
            }.getOrDefault(emptyMap())
            val results = mutableListOf<JsonObject>()
            for (source in providers(applicationContext).filter { it.id in wanted }) {
                if (isStopped || !prefs.getBoolean(ENABLED, false)) return@withContext Result.success()
                val previous = old[source.id]
                val now = System.currentTimeMillis()
                val cooldown = (previous?.get("nextAllowedAt") as? JsonPrimitive)?.longOrNull ?: 0L
                if (cooldown > now && previous != null) { results += previous; continue }
                results += fetchSource(source, previous, now)
            }
            if (isStopped || !prefs.getBoolean(ENABLED, false)) return@withContext Result.success()
            val snapshot = buildJsonObject {
                put("version", 1)
                put("generatedAt", System.currentTimeMillis())
                put("sources", JsonArray(results))
            }.toString().toByteArray(Charsets.UTF_8)
            require(snapshot.size <= WorldMonitorPolicy.MAX_SNAPSHOT_BYTES) { "Daily snapshot exceeds its safety limit" }
            val file = cacheFile(applicationContext)
            val output = file.startWrite()
            try { output.write(snapshot); file.finishWrite(output) }
            catch (error: Exception) { file.failWrite(output); throw error }
            Result.success()
        } catch (cancel: CancellationException) { throw cancel }
        catch (_: Exception) { if (runAttemptCount < 2) Result.retry() else Result.failure() }
    }

    private suspend fun fetchSource(source: Provider, previous: JsonObject?, now: Long): JsonObject {
        var nextAllowedAt: Long? = null
        return try {
            val request = Request.Builder().url(source.url)
                .header("Accept", source.accept)
                .header("User-Agent", "OmniShieldX/5.1 WorldMonitor/2.0 (public daily feed reader)")
                .build()
            val payload = await(client.newCall(request)).use { response ->
                if (response.code == 429 || (response.code == 403 && response.header("X-RateLimit-Remaining") == "0")) {
                    val seconds = response.header("Retry-After")?.toLongOrNull()?.coerceIn(60L, 86_400L) ?: 3_600L
                    val reset = response.header("X-RateLimit-Reset")?.toLongOrNull()?.times(1_000L)
                    nextAllowedAt = maxOf(now + seconds * 1_000L, reset ?: 0L).coerceAtMost(now + 86_400_000L)
                    throw IOException("Provider rate limited the daily update (HTTP ${response.code})")
                }
                if (!response.isSuccessful) throw IOException("Provider returned HTTP ${response.code}")
                val body = response.body ?: throw IOException("Provider returned no body")
                if (body.contentLength() > WorldMonitorPolicy.MAX_FEED_BYTES) throw IOException("Source exceeds the 6 MB limit")
                val buffer = okio.Buffer()
                val input = body.source()
                var total = 0L
                while (true) {
                    val read = input.read(buffer, 8_192L)
                    if (read == -1L) break
                    total += read
                    if (total > WorldMonitorPolicy.MAX_FEED_BYTES) throw IOException("Source exceeds the 6 MB limit")
                }
                buffer.readUtf8()
            }
            if (!WorldMonitorPolicy.validFeedShape(source.format, payload)) throw IOException("Provider returned an invalid feed shape")
            buildJsonObject {
                put("id", source.id); put("fetchedAt", now); put("attemptedAt", now)
                put("data", Json.parseToJsonElement(payload))
            }
        } catch (cancel: CancellationException) { throw cancel }
        catch (error: Exception) {
            // Keep the last actual payload across failures; never replace it with an empty success.
            buildJsonObject {
                put("id", source.id); put("attemptedAt", now)
                previous?.get("fetchedAt")?.let { put("fetchedAt", it) }
                previous?.get("data")?.let { put("data", it) }
                put("error", (error.message ?: "Daily source request failed").take(300))
                nextAllowedAt?.let { put("nextAllowedAt", it) }
            }
        }
    }

    private suspend fun await(call: Call): Response = suspendCancellableCoroutine { continuation ->
        continuation.invokeOnCancellation { call.cancel() }
        call.enqueue(object : Callback {
            override fun onFailure(call: Call, error: IOException) {
                if (continuation.isActive) continuation.resumeWithException(error)
            }
            override fun onResponse(call: Call, response: Response) {
                if (continuation.isActive) continuation.resume(response) { _, value, _ -> value.close() }
                else response.close()
            }
        })
    }

    data class Provider(val id: String, val url: String, val accept: String, val format: String)

    companion object {
        const val UNIQUE_NAME = "world-monitor-daily-v2"
        private const val PREFS = "world-monitor-schedule"
        private const val ENABLED = "enabled"
        private const val SOURCES = "sources"

        fun providers(context: Context): List<Provider> = context.assets.open("world-monitor/world/providers.json").use { input ->
            val root = Json.parseToJsonElement(input.bufferedReader().readText()).jsonObject
            (root["sources"] as? JsonArray).orEmpty().take(20).mapNotNull { row ->
                val obj = row as? JsonObject ?: return@mapNotNull null
                val id = obj.string("id") ?: return@mapNotNull null
                val url = obj.string("url") ?: return@mapNotNull null
                val format = obj.string("format") ?: return@mapNotNull null
                if (!WorldMonitorPolicy.publicHttps(url)) return@mapNotNull null
                Provider(id, url, obj.string("accept") ?: "application/json", format)
            }
        }

        fun configure(context: Context, enabled: Boolean, sourceIds: Set<String>) {
            val allowed = providers(context).map { it.id }.toSet()
            context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
                .putBoolean(ENABLED, enabled).putStringSet(SOURCES, sourceIds.intersect(allowed)).apply()
            val manager = WorkManager.getInstance(context)
            if (!enabled) { manager.cancelUniqueWork(UNIQUE_NAME); return }
            val constraints = Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).setRequiresBatteryNotLow(true).build()
            val work = PeriodicWorkRequestBuilder<WorldMonitorWorker>(24, TimeUnit.HOURS)
                .setInitialDelay(24, TimeUnit.HOURS)
                .setConstraints(constraints)
                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 15, TimeUnit.MINUTES).build()
            manager.enqueueUniquePeriodicWork(UNIQUE_NAME, ExistingPeriodicWorkPolicy.KEEP, work)
        }

        fun cacheFile(context: Context): AtomicFile {
            val directory = File(context.filesDir, "world-monitor")
            directory.mkdirs()
            return AtomicFile(File(directory, "latest.json"))
        }

        /** Only this exact path is exposed by the WebView asset loader, never an arbitrary file. */
        fun openSnapshot(context: Context): InputStream? = runCatching {
            val input = cacheFile(context).openRead()
            try {
                require(input.channel.size() <= WorldMonitorPolicy.MAX_SNAPSHOT_BYTES)
                input
            } catch (error: Exception) { input.close(); throw error }
        }.getOrNull()
    }
}
