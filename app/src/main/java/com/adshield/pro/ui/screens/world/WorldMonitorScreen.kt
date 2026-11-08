package com.adshield.pro.ui.screens.world

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.webkit.CookieManager
import android.webkit.ValueCallback
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.webkit.WebViewAssetLoader
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature
import com.adshield.pro.engine.world.WorldMonitorPolicy
import com.adshield.pro.engine.world.WorldMonitorPolicy.string
import com.adshield.pro.worker.WorldMonitorWorker
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.jsonObject
import java.io.ByteArrayInputStream

/**
 * Offline-packaged, shared World Monitor v2. No remote page, injected HTML, broad JavaScript
 * interface, GPS permission, file-system access or credentials. Two origin-restricted message
 * channels support user-confirmed SAF exports and the explicitly enabled daily WorkManager job.
 */
@SuppressLint("SetJavaScriptEnabled")
@Composable
fun WorldMonitorScreen(modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val scope = rememberCoroutineScope()
    var webView by remember { mutableStateOf<WebView?>(null) }
    var notice by remember { mutableStateOf<String?>(null) }
    var pendingExport by remember { mutableStateOf<WorldMonitorPolicy.ExportRequest?>(null) }
    var pendingFile by remember { mutableStateOf<ValueCallback<Array<Uri>>?>(null) }

    val exportLauncher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        val request = pendingExport
        pendingExport = null
        val uri = result.data?.data
        if (result.resultCode == Activity.RESULT_OK && uri != null && request != null) {
            scope.launch {
                notice = withContext(Dispatchers.IO) {
                    runCatching {
                        val output = context.contentResolver.openOutputStream(uri, "wt")
                            ?: error("The chosen document could not be opened")
                        output.use { it.write(request.content.toByteArray(Charsets.UTF_8)) }
                        "Export saved: ${request.filename}"
                    }.getOrElse { "Export failed: ${it.message}" }
                }
            }
        } else if (request != null) notice = "Export cancelled. Nothing was written."
    }
    val fileLauncher = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        pendingFile?.onReceiveValue(uri?.let { arrayOf(it) })
        pendingFile = null
    }
    val openExternal: (String) -> Unit = { url ->
        if (WorldMonitorPolicy.publicHttps(url)) {
            runCatching { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url))) }
                .onFailure { notice = "No browser is available to open the source link." }
        } else notice = "Only public HTTPS source links may be opened."
    }

    DisposableEffect(lifecycleOwner, webView) {
        val current = webView
        val observer = LifecycleEventObserver { _, event ->
            when (event) {
                Lifecycle.Event.ON_START -> current?.onResume()
                Lifecycle.Event.ON_STOP -> current?.onPause()
                else -> Unit
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }
    DisposableEffect(Unit) {
        onDispose {
            pendingFile?.onReceiveValue(null)
            pendingFile = null
            webView?.let { view ->
                view.stopLoading()
                if (WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)) {
                    WebViewCompat.removeWebMessageListener(view, "OmniWorldExport")
                    WebViewCompat.removeWebMessageListener(view, "OmniWorldHost")
                }
                view.destroy()
            }
        }
    }

    Column(modifier = modifier.fillMaxSize()) {
        notice?.let { message ->
            Row(modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 6.dp)) {
                Text(message, style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(1f))
                TextButton(onClick = { notice = null }) { Text("Dismiss") }
            }
        }
        AndroidView(
            modifier = Modifier.fillMaxWidth().weight(1f),
            factory = { viewContext ->
                val loader = WebViewAssetLoader.Builder()
                    .addPathHandler("/assets/", WebViewAssetLoader.AssetsPathHandler(viewContext))
                    .addPathHandler("/world-cache/", WebViewAssetLoader.PathHandler { path ->
                        if (path != "latest.json") null else {
                            WorldMonitorWorker.openSnapshot(viewContext)?.let { input ->
                                WebResourceResponse("application/json", "UTF-8", 200, "OK", mapOf("Cache-Control" to "no-store"), input)
                            } ?: blockedResponse(404, "No daily snapshot yet")
                        }
                    }).build()
                WebView(viewContext).apply {
                    webView = this
                    setBackgroundColor(android.graphics.Color.rgb(13, 18, 23))
                    settings.javaScriptEnabled = true
                    settings.domStorageEnabled = true
                    settings.allowFileAccess = false
                    settings.allowContentAccess = false
                    settings.mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
                    settings.javaScriptCanOpenWindowsAutomatically = false
                    settings.setSupportMultipleWindows(false)
                    settings.setGeolocationEnabled(false)
                    settings.mediaPlaybackRequiresUserGesture = true
                    CookieManager.getInstance().setAcceptThirdPartyCookies(this, false)
                    webViewClient = object : WebViewClient() {
                        override fun shouldInterceptRequest(view: WebView?, request: WebResourceRequest): WebResourceResponse? {
                            if (request.url.host == WorldMonitorPolicy.HOST) {
                                return loader.shouldInterceptRequest(request.url) ?: blockedResponse(404, "Local asset not found")
                            }
                            if (!WorldMonitorPolicy.publicHttps(request.url.toString())) return blockedResponse(403, "Only public HTTPS resources are allowed")
                            return null
                        }
                        override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest): Boolean {
                            val url = request.url.toString()
                            if (url == WorldMonitorPolicy.ENTRY_URL || url.startsWith(WorldMonitorPolicy.ENTRY_URL + "#")) return false
                            if (request.isForMainFrame) openExternal(url)
                            return true
                        }
                    }
                    webChromeClient = object : WebChromeClient() {
                        override fun onShowFileChooser(view: WebView?, callback: ValueCallback<Array<Uri>>, params: FileChooserParams?): Boolean {
                            pendingFile?.onReceiveValue(null)
                            pendingFile = callback
                            runCatching { fileLauncher.launch(arrayOf("application/json", "text/plain")) }
                                .onFailure { pendingFile?.onReceiveValue(null); pendingFile = null; notice = "No document picker is available." }
                            return true
                        }
                    }
                    setDownloadListener { _, _, _, _, _ -> notice = "Export requires a recent Android System WebView. Update WebView and retry from World Monitor's Export button." }
                    if (WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)) {
                        WebViewCompat.addWebMessageListener(this, "OmniWorldExport", setOf(WorldMonitorPolicy.ORIGIN)) { _, message, origin, mainFrame, _ ->
                            if (WorldMonitorPolicy.trustedOrigin(origin.toString(), mainFrame)) {
                                val request = WorldMonitorPolicy.exportRequest(message.data.orEmpty())
                                when {
                                    request == null -> notice = "Export rejected: invalid format or larger than 8 MB. Narrow the filters and retry."
                                    pendingExport != null -> notice = "Finish or cancel the current save dialog first."
                                    else -> {
                                        pendingExport = request
                                        runCatching {
                                            exportLauncher.launch(Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                                                addCategory(Intent.CATEGORY_OPENABLE)
                                                type = request.mime
                                                putExtra(Intent.EXTRA_TITLE, request.filename)
                                            })
                                        }.onFailure { pendingExport = null; notice = "No document saver is available: ${it.message}" }
                                    }
                                }
                            }
                        }
                        WebViewCompat.addWebMessageListener(this, "OmniWorldHost", setOf(WorldMonitorPolicy.ORIGIN)) { _, message, origin, mainFrame, _ ->
                            if (WorldMonitorPolicy.trustedOrigin(origin.toString(), mainFrame) && message.data.orEmpty().length <= 8_192) {
                                runCatching {
                                    val request = Json.parseToJsonElement(message.data.orEmpty()).jsonObject
                                    when (request.string("type")) {
                                        "open" -> request.string("url")?.let(openExternal)
                                        "schedule" -> {
                                            val enabled = (request["enabled"] as? JsonPrimitive)?.booleanOrNull ?: false
                                            val allowed = WorldMonitorWorker.providers(viewContext).map { it.id }.toSet()
                                            WorldMonitorWorker.configure(viewContext, enabled, WorldMonitorPolicy.scheduledSources(request, allowed))
                                        }
                                    }
                                }.onFailure { notice = "World Monitor action failed: ${it.message}" }
                            }
                        }
                    } else notice = "Update Android System WebView to enable secure exports and native daily scheduling. The monitor itself still works while open."
                    loadUrl(WorldMonitorPolicy.ENTRY_URL)
                }
            }
        )
    }
}

private fun blockedResponse(code: Int, reason: String) = WebResourceResponse(
    "text/plain", "UTF-8", code, if (code == 404) "Not Found" else "Forbidden",
    mapOf("Cache-Control" to "no-store"), ByteArrayInputStream(reason.toByteArray(Charsets.UTF_8))
)
