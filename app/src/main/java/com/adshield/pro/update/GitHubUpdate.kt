package com.adshield.pro.update

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import androidx.hilt.work.HiltWorker
import androidx.work.*
import com.adshield.pro.BuildConfig
import com.adshield.pro.R
import com.adshield.pro.ui.UpdatePromptActivity
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest
import java.util.concurrent.TimeUnit

object GitHubReleaseClient {
    private const val API_BASE = "https://api.github.com/repos/"
    private val httpClient: OkHttpClient by lazy {
        OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(20, TimeUnit.SECONDS)
            .followSslRedirects(false)
            .build()
    }

    fun latest(): GitHubRelease? {
        val repository = BuildConfig.GITHUB_UPDATE_REPOSITORY.trim()
        if (!GitHubReleaseMetadata.isRepository(repository)) return null
        val endpoint = API_BASE + repository + "/releases/latest"
        val request = Request.Builder().url(endpoint)
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "AdShieldPro-Android-Updater").get().build()
        httpClient.newCall(request).execute().use { response ->
            if (!response.isSuccessful) return null
            val json = JSONObject(response.body.string())
            val assets = json.optJSONArray("assets") ?: return null
            return GitHubReleaseMetadata.select(
                repository = repository,
                tag = json.optString("tag_name"),
                draft = json.optBoolean("draft", true),
                preRelease = json.optBoolean("prerelease", true),
                body = json.optString("body").takeUnless { it == "null" },
                assets = (0 until assets.length()).asSequence().mapNotNull { index ->
                    assets.optJSONObject(index)?.let {
                        GitHubReleaseMetadata.Asset(it.optString("name"), it.optString("browser_download_url"), it.optString("digest"))
                    }
                }
            )
        }
    }
}

@HiltWorker
class GitHubUpdateWorker @AssistedInject constructor(
    @Assisted context: Context, @Assisted params: WorkerParameters
) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        // Debug has a different application ID and signer; a production APK is not its update.
        // Also stop already-enqueued work when updating from an earlier debug build.
        if (BuildConfig.DEBUG) return@withContext Result.success()
        try {
            val release = GitHubReleaseClient.latest() ?: return@withContext Result.retry()
            if (release.code <= BuildConfig.VERSION_CODE) return@withContext Result.success()
            if (Build.VERSION.SDK_INT >= 33 &&
                ContextCompat.checkSelfPermission(applicationContext, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
            ) return@withContext Result.success()
            val notifications = NotificationManagerCompat.from(applicationContext)
            if (!notifications.areNotificationsEnabled()) return@withContext Result.success()
            val prefs = applicationContext.getSharedPreferences("adshield_update_state", Context.MODE_PRIVATE)
            if (prefs.getInt("notified_code", 0) >= release.code) return@withContext Result.success()

            if (Build.VERSION.SDK_INT >= 26) {
                val system = applicationContext.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
                system.createNotificationChannel(NotificationChannel(CHANNEL, "App updates", NotificationManager.IMPORTANCE_DEFAULT))
            }
            val intent = Intent(applicationContext, UpdatePromptActivity::class.java).apply {
                putExtra(UpdatePromptActivity.TAG, release.tag)
                putExtra(UpdatePromptActivity.NAME, release.name)
                putExtra(UpdatePromptActivity.CODE, release.code)
                putExtra(UpdatePromptActivity.APK, release.apk)
                putExtra(UpdatePromptActivity.SHA, release.sha256)
                putExtra(UpdatePromptActivity.NOTES, release.notes)
                addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            }
            val pending = PendingIntent.getActivity(applicationContext, release.code, intent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
            notifications.notify(ID, NotificationCompat.Builder(applicationContext, CHANNEL)
                .setSmallIcon(R.drawable.ic_notification_shield)
                .setContentTitle("AdShield Pro " + release.name + " is available")
                .setContentText("Tap to review the update and release notes.")
                .setContentIntent(pending).setAutoCancel(true).build())
            prefs.edit().putInt("notified_code", release.code).apply()
            Result.success()
        } catch (c: kotlinx.coroutines.CancellationException) {
            throw c
        } catch (_: Exception) { Result.retry() }
    }

    companion object {
        private const val CHANNEL = "app_updates"
        private const val ID = 7021
        fun schedule(context: Context) {
            if (BuildConfig.DEBUG) return
            val constraints = Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()
            val work = WorkManager.getInstance(context)
            work.enqueueUniquePeriodicWork("adshield_update_periodic", ExistingPeriodicWorkPolicy.KEEP,
                PeriodicWorkRequestBuilder<GitHubUpdateWorker>(24, TimeUnit.HOURS).setConstraints(constraints).build())
            work.enqueueUniqueWork("adshield_update_startup", ExistingWorkPolicy.KEEP,
                OneTimeWorkRequestBuilder<GitHubUpdateWorker>().setConstraints(constraints).build())
        }
    }
}

object GitHubApkDownload {
    private val downloadClient: OkHttpClient by lazy {
        OkHttpClient.Builder()
            .connectTimeout(20, TimeUnit.SECONDS)
            .readTimeout(60, TimeUnit.SECONDS)
            .followRedirects(true)
            .followSslRedirects(false)
            .build()
    }

    private fun isTrustedGitHubAssetHost(host: String): Boolean {
        val lower = host.lowercase()
        return lower == "github.com" ||
            lower == "objects.githubusercontent.com" ||
            lower == "release-assets.githubusercontent.com" ||
            lower.endsWith(".githubusercontent.com")
    }

    suspend fun get(context: Context, release: GitHubRelease): File = withContext(Dispatchers.IO) {
        val expectedRepo = BuildConfig.GITHUB_UPDATE_REPOSITORY.trim()
        require(GitHubReleaseMetadata.isTrustedApkUrl(expectedRepo, release.tag, release.apk)) {
            "Untrusted APK update URL refused."
        }
        require(GitHubReleaseMetadata.isSha256(release.sha256)) {
            "No valid SHA-256 checksum was provided for this update."
        }
        val request = Request.Builder().url(release.apk).header("User-Agent", "AdShieldPro-Android-Updater").get().build()
        downloadClient.newCall(request).execute().use { response ->
            if (!response.isSuccessful) throw java.io.IOException("Download failed (HTTP " + response.code + ").")
            if (!response.request.url.isHttps || !isTrustedGitHubAssetHost(response.request.url.host)) {
                throw java.io.IOException("Redirected to untrusted update host; download refused.")
            }
            val body = response.body
            val limit = 250L * 1024L * 1024L
            if (body.contentLength() > limit) throw java.io.IOException("APK exceeds the download size limit.")
            val dir = File(context.cacheDir, "updates").apply { mkdirs() }
            val part = File(dir, "adshield-" + release.code + ".apk.part")
            val apk = File(dir, "adshield-" + release.code + ".apk")
            val hash = MessageDigest.getInstance("SHA-256")
            var total = 0L
            try {
                body.byteStream().use { input ->
                    FileOutputStream(part).use { output ->
                        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                        while (true) {
                            val count = input.read(buffer)
                            if (count < 0) break
                            total += count
                            if (total > limit) throw java.io.IOException("APK exceeds the download size limit.")
                            hash.update(buffer, 0, count)
                            output.write(buffer, 0, count)
                        }
                    }
                }
            } catch (t: Throwable) {
                part.delete()
                throw t
            }
            val actual = hash.digest().joinToString("") { "%02x".format(it) }
            if (!actual.equals(release.sha256, true)) {
                part.delete()
                throw java.io.IOException("APK checksum verification failed; it was not installed.")
            }
            if (apk.exists()) apk.delete()
            if (!part.renameTo(apk)) { part.copyTo(apk, true); part.delete() }
            apk
        }
    }
}
