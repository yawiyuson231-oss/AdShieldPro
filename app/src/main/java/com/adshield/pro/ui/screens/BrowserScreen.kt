package com.adshield.pro.ui.screens

import android.annotation.SuppressLint
import android.graphics.Bitmap
import android.net.Uri
import android.os.Message
import android.view.ViewGroup
import android.webkit.CookieManager
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebSettings
import android.webkit.WebStorage
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material.icons.filled.CleaningServices
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Tune
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import com.adshield.pro.data.local.preferences.AppSettingsState
import com.adshield.pro.engine.browser.BrowserContentBlocker
import com.adshield.pro.engine.browser.PrivateSearchEngine
import com.adshield.pro.engine.browser.SearchProvider
import com.adshield.pro.ui.theme.AlertRed
import com.adshield.pro.ui.theme.CyberCyan
import com.adshield.pro.ui.theme.ElectricBlue
import com.adshield.pro.ui.theme.EmeraldPrimary
import com.adshield.pro.ui.theme.WarningAmber

@SuppressLint("SetJavaScriptEnabled")
@Composable
fun BrowserScreen(
    settings: AppSettingsState,
    browserContentBlocker: BrowserContentBlocker,
    onToggleSiteException: (String, Boolean) -> Unit,
    onUpdateBrowserPrivacy: (Boolean, Boolean, Boolean, Boolean, Boolean) -> Unit,
    onSelectSearchProvider: (SearchProvider) -> Unit,
    onAddCustomCosmeticSelector: (String) -> Unit,
    onOpenInDownloader: (String) -> Unit,
    onShowFeedback: (String) -> Unit
) {
    val initialHome = settings.preferredSearchProvider.homeUrl
    var urlInput by remember { mutableStateOf(initialHome) }
    var currentPageUrl by remember { mutableStateOf(initialHome) }
    var pageLoadProgress by remember { mutableIntStateOf(100) }
    var blockedSubresources by remember { mutableLongStateOf(browserContentBlocker.getBlockedSubresourceCount()) }
    var blockedPopups by remember { mutableLongStateOf(browserContentBlocker.getBlockedPopupCount()) }
    var strippedTrackers by remember { mutableLongStateOf(browserContentBlocker.getStrippedTrackerParamCount()) }
    var showBrowserShieldSheet by remember { mutableStateOf(false) }

    val currentHost = remember(currentPageUrl) {
        runCatching { Uri.parse(currentPageUrl).host?.lowercase()?.removePrefix("www.") }.getOrNull() ?: ""
    }
    val isCurrentSiteAllowlisted = remember(currentHost, settings.browserSiteExceptions) {
        currentHost.isNotEmpty() && browserContentBlocker.isHostInExceptionSet(currentHost, settings.browserSiteExceptions)
    }

    val latestSettings by rememberUpdatedState(settings)
    val latestCurrentHost by rememberUpdatedState(currentHost)

    val webViewRef = remember { mutableStateOf<WebView?>(null) }

    DisposableEffect(Unit) {
        onDispose {
            webViewRef.value?.let { webView ->
                webView.stopLoading()
                (webView.parent as? ViewGroup)?.removeView(webView)
                webView.destroy()
            }
            webViewRef.value = null
        }
    }

    val performSearchOrNavigate: (String) -> Unit = { raw ->
        val resolved = PrivateSearchEngine.resolveNavigationInput(
            rawInput = raw,
            provider = latestSettings.preferredSearchProvider,
            upgradeHttpToHttps = latestSettings.browserHttpsUpgradeEnabled
        )
        val sanitized = browserContentBlocker.sanitizeTrackingParameters(resolved)
        strippedTrackers = browserContentBlocker.getStrippedTrackerParamCount()
        urlInput = sanitized
        webViewRef.value?.loadUrl(sanitized, PrivateSearchEngine.privacyRequestHeaders())
    }

    Column(modifier = Modifier.fillMaxSize()) {
        // Top Browser Address, Private Search Provider & Shield Toolbar
        Surface(
            color = MaterialTheme.colorScheme.surface,
            tonalElevation = 4.dp,
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(horizontal = 10.dp, vertical = 8.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    IconButton(onClick = { webViewRef.value?.goBack() }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                    IconButton(onClick = { webViewRef.value?.goForward() }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowForward, contentDescription = "Forward")
                    }

                    OutlinedTextField(
                        value = urlInput,
                        onValueChange = { urlInput = it },
                        placeholder = { Text("Private search (${settings.preferredSearchProvider.shortBadge}) or URL…") },
                        singleLine = true,
                        leadingIcon = {
                            Icon(
                                imageVector = Icons.Default.Lock,
                                contentDescription = null,
                                tint = if (currentPageUrl.startsWith("https://")) EmeraldPrimary else WarningAmber,
                                modifier = Modifier.size(16.dp)
                            )
                        },
                        keyboardOptions = KeyboardOptions(imeAction = ImeAction.Go),
                        keyboardActions = KeyboardActions(
                            onGo = { performSearchOrNavigate(urlInput) }
                        ),
                        modifier = Modifier.weight(1f)
                    )

                    IconButton(onClick = { performSearchOrNavigate(urlInput) }) {
                        Icon(Icons.Default.Search, contentDescription = "Search / Go", tint = ElectricBlue)
                    }

                    IconButton(onClick = { webViewRef.value?.reload() }) {
                        Icon(Icons.Default.Refresh, contentDescription = "Reload")
                    }

                    IconButton(onClick = { onOpenInDownloader(currentPageUrl) }) {
                        Icon(Icons.Default.Download, contentDescription = "Open URL in Media Downloader", tint = CyberCyan)
                    }

                    IconButton(onClick = { showBrowserShieldSheet = true }) {
                        Icon(
                            imageVector = Icons.Default.Tune,
                            contentDescription = "Browser Shield Controls",
                            tint = EmeraldPrimary
                        )
                    }
                }

                Spacer(modifier = Modifier.height(6.dp))

                // Private Search Provider Switcher + Live Telemetry Strip
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        SearchProvider.entries.forEach { provider ->
                            FilterChip(
                                selected = settings.preferredSearchProvider == provider,
                                onClick = { onSelectSearchProvider(provider) },
                                label = { Text(provider.shortBadge, style = MaterialTheme.typography.labelSmall) }
                            )
                        }
                        Text(
                            text = "Ads: $blockedSubresources",
                            style = MaterialTheme.typography.labelMedium,
                            color = AlertRed,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = "Pop-ups: $blockedPopups",
                            style = MaterialTheme.typography.labelMedium,
                            color = WarningAmber
                        )
                        Text(
                            text = "Stripped: $strippedTrackers",
                            style = MaterialTheme.typography.labelMedium,
                            color = CyberCyan
                        )
                    }

                    if (currentHost.isNotEmpty()) {
                        Surface(
                            color = if (isCurrentSiteAllowlisted) WarningAmber.copy(alpha = 0.2f) else EmeraldPrimary.copy(alpha = 0.16f),
                            shape = RoundedCornerShape(50)
                        ) {
                            Text(
                                text = if (isCurrentSiteAllowlisted) "Allowlisted" else "Shield ON",
                                style = MaterialTheme.typography.labelMedium,
                                color = if (isCurrentSiteAllowlisted) WarningAmber else EmeraldPrimary,
                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp)
                            )
                        }
                    }
                }

                if (pageLoadProgress in 1..99) {
                    Spacer(modifier = Modifier.height(4.dp))
                    LinearProgressIndicator(
                        progress = { pageLoadProgress / 100f },
                        modifier = Modifier.fillMaxWidth(),
                        color = EmeraldPrimary
                    )
                }
            }
        }

        // WebView Content Area
        AndroidView(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f),
            factory = { ctx ->
                WebView(ctx).also { webView ->
                    webViewRef.value = webView
                    webView.settings.apply {
                        javaScriptEnabled = latestSettings.browserJavaScriptEnabled
                        domStorageEnabled = true
                        databaseEnabled = false
                        mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
                        setSupportMultipleWindows(true)
                        javaScriptCanOpenWindowsAutomatically = false
                        mediaPlaybackRequiresUserGesture = true
                        allowFileAccess = false
                        allowContentAccess = false
                    }

                    val cookieManager = CookieManager.getInstance()
                    cookieManager.setAcceptCookie(true)
                    cookieManager.setAcceptThirdPartyCookies(
                        webView,
                        !latestSettings.browserBlockThirdPartyCookies
                    )

                    webView.webViewClient = object : WebViewClient() {
                        override fun shouldOverrideUrlLoading(
                            view: WebView?,
                            request: WebResourceRequest?
                        ): Boolean {
                            val target = request?.url?.toString() ?: return false
                            val unwrapped = PrivateSearchEngine.sanitizeAndUnwrapUrl(
                                rawUrl = target,
                                upgradeHttpToHttps = latestSettings.browserHttpsUpgradeEnabled
                            )
                            val sanitized = browserContentBlocker.sanitizeTrackingParameters(unwrapped)
                            strippedTrackers = browserContentBlocker.getStrippedTrackerParamCount()
                            if (sanitized != target) {
                                view?.loadUrl(sanitized, PrivateSearchEngine.privacyRequestHeaders())
                                return true
                            }
                            return false
                        }

                        override fun shouldInterceptRequest(
                            view: WebView?,
                            request: WebResourceRequest?
                        ): WebResourceResponse? {
                            val reqUrl = request?.url?.toString() ?: return null
                            val snapSettings = latestSettings
                            val decision = browserContentBlocker.evaluateRequest(
                                requestUrl = reqUrl,
                                pageHost = latestCurrentHost,
                                allowlistedSites = snapSettings.browserSiteExceptions
                            )
                            blockedSubresources = browserContentBlocker.getBlockedSubresourceCount()
                            return if (decision.shouldBlock) {
                                browserContentBlocker.createEmptyBlockedResponse()
                            } else {
                                null
                            }
                        }

                        override fun onPageStarted(view: WebView?, url: String?, favicon: Bitmap?) {
                            super.onPageStarted(view, url, favicon)
                            if (url != null) {
                                currentPageUrl = url
                                urlInput = url
                            }
                        }

                        override fun onPageFinished(view: WebView?, url: String?) {
                            super.onPageFinished(view, url)
                            val snapSettings = latestSettings
                            if (snapSettings.browserCosmeticFilteringEnabled && view != null) {
                                val host = runCatching { Uri.parse(url).host }.getOrNull()
                                val script = browserContentBlocker.buildCosmeticFilterScript(
                                    pageHost = host,
                                    allowlistedSites = snapSettings.browserSiteExceptions,
                                    customSelectors = snapSettings.customCosmeticSelectors
                                )
                                if (script != null) {
                                    view.evaluateJavascript(script, null)
                                }
                            }
                        }
                    }

                    webView.webChromeClient = object : WebChromeClient() {
                        override fun onProgressChanged(view: WebView?, newProgress: Int) {
                            pageLoadProgress = newProgress
                        }

                        override fun onCreateWindow(
                            view: WebView?,
                            isDialog: Boolean,
                            isUserGesture: Boolean,
                            resultMsg: Message?
                        ): Boolean {
                            if (latestSettings.browserPopupBlockingEnabled && !isUserGesture) {
                                browserContentBlocker.recordPopupBlocked()
                                blockedPopups = browserContentBlocker.getBlockedPopupCount()
                                return false
                            }
                            return super.onCreateWindow(view, isDialog, isUserGesture, resultMsg)
                        }
                    }

                    webView.loadUrl(currentPageUrl, PrivateSearchEngine.privacyRequestHeaders())
                }
            },
            update = { webView ->
                webView.settings.javaScriptEnabled = settings.browserJavaScriptEnabled
                webView.settings.mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
                CookieManager.getInstance().setAcceptThirdPartyCookies(
                    webView,
                    !settings.browserBlockThirdPartyCookies
                )
            }
        )
    }

    if (showBrowserShieldSheet) {
        var customCssSelector by remember { mutableStateOf("") }

        AlertDialog(
            onDismissRequest = { showBrowserShieldSheet = false },
            title = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Security, contentDescription = null, tint = EmeraldPrimary)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Private Search & Browser Shield")
                }
            },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(
                        text = settings.preferredSearchProvider.privacySummary,
                        style = MaterialTheme.typography.labelMedium,
                        color = CyberCyan
                    )

                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        SearchProvider.entries.forEach { provider ->
                            FilterChip(
                                selected = settings.preferredSearchProvider == provider,
                                onClick = { onSelectSearchProvider(provider) },
                                label = { Text(provider.displayName) }
                            )
                        }
                    }

                    if (currentHost.isNotEmpty()) {
                        Card(
                            colors = CardDefaults.cardColors(
                                containerColor = MaterialTheme.colorScheme.surfaceVariant
                            )
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(10.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = "Pause Blocking on $currentHost",
                                        style = MaterialTheme.typography.titleMedium
                                    )
                                    Text(
                                        text = "Website-specific allowlist exception",
                                        style = MaterialTheme.typography.labelMedium
                                    )
                                }
                                Switch(
                                    checked = isCurrentSiteAllowlisted,
                                    onCheckedChange = {
                                        onToggleSiteException(currentHost, it)
                                        webViewRef.value?.reload()
                                    }
                                )
                            }
                        }
                    }

                    BrowserSwitchRow(
                        title = "HTTPS-Only Auto-Upgrade",
                        subtitle = "Upgrades http:// links to https:// and blocks mixed content",
                        checked = settings.browserHttpsUpgradeEnabled,
                        onCheckedChange = {
                            onUpdateBrowserPrivacy(
                                settings.browserCosmeticFilteringEnabled,
                                settings.browserPopupBlockingEnabled,
                                settings.browserBlockThirdPartyCookies,
                                settings.browserJavaScriptEnabled,
                                it
                            )
                        }
                    )

                    BrowserSwitchRow(
                        title = "Cosmetic Element Hiding",
                        subtitle = "Collapses ad placeholders & sponsored DOM containers",
                        checked = settings.browserCosmeticFilteringEnabled,
                        onCheckedChange = {
                            onUpdateBrowserPrivacy(
                                it,
                                settings.browserPopupBlockingEnabled,
                                settings.browserBlockThirdPartyCookies,
                                settings.browserJavaScriptEnabled,
                                settings.browserHttpsUpgradeEnabled
                            )
                        }
                    )

                    BrowserSwitchRow(
                        title = "Pop-up & Redirect Blocker",
                        subtitle = "Blocks background window.open() pop-unders",
                        checked = settings.browserPopupBlockingEnabled,
                        onCheckedChange = {
                            onUpdateBrowserPrivacy(
                                settings.browserCosmeticFilteringEnabled,
                                it,
                                settings.browserBlockThirdPartyCookies,
                                settings.browserJavaScriptEnabled,
                                settings.browserHttpsUpgradeEnabled
                            )
                        }
                    )

                    BrowserSwitchRow(
                        title = "Block Third-Party Cookies",
                        subtitle = "Prevents cross-site cookie tracking",
                        checked = settings.browserBlockThirdPartyCookies,
                        onCheckedChange = {
                            onUpdateBrowserPrivacy(
                                settings.browserCosmeticFilteringEnabled,
                                settings.browserPopupBlockingEnabled,
                                it,
                                settings.browserJavaScriptEnabled,
                                settings.browserHttpsUpgradeEnabled
                            )
                        }
                    )

                    BrowserSwitchRow(
                        title = "Enable JavaScript",
                        subtitle = "Disable on untrusted sites for maximum script lockdown",
                        checked = settings.browserJavaScriptEnabled,
                        onCheckedChange = {
                            onUpdateBrowserPrivacy(
                                settings.browserCosmeticFilteringEnabled,
                                settings.browserPopupBlockingEnabled,
                                settings.browserBlockThirdPartyCookies,
                                it,
                                settings.browserHttpsUpgradeEnabled
                            )
                        }
                    )

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        OutlinedTextField(
                            value = customCssSelector,
                            onValueChange = { customCssSelector = it },
                            label = { Text("Add Custom CSS Selector (e.g. .promo-box)") },
                            singleLine = true,
                            modifier = Modifier.weight(1f)
                        )
                        Button(
                            onClick = {
                                if (customCssSelector.isNotBlank()) {
                                    onAddCustomCosmeticSelector(customCssSelector)
                                    customCssSelector = ""
                                    webViewRef.value?.reload()
                                }
                            }
                        ) {
                            Text("Add")
                        }
                    }
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        CookieManager.getInstance().removeAllCookies(null)
                        CookieManager.getInstance().flush()
                        WebStorage.getInstance().deleteAllData()
                        webViewRef.value?.clearCache(true)
                        webViewRef.value?.clearHistory()
                        onShowFeedback("Cleared browser cookies, DOM storage, and cache.")
                        showBrowserShieldSheet = false
                    }
                ) {
                    Icon(Icons.Default.CleaningServices, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Clear Cookies & Cache")
                }
            },
            dismissButton = {
                TextButton(onClick = { showBrowserShieldSheet = false }) {
                    Text("Done")
                }
            }
        )
    }
}

@Composable
private fun BrowserSwitchRow(
    title: String,
    subtitle: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(text = title, style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Medium)
            Text(
                text = subtitle,
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}
