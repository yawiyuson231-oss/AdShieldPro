package com.adshield.pro.ui.screens.worldmonitor

import android.annotation.SuppressLint
import android.content.Intent
import android.net.Uri
import android.view.ViewGroup
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.adshield.pro.domain.worldmonitor.FreshnessClass
import com.adshield.pro.domain.worldmonitor.GeocodeSearchResult
import com.adshield.pro.domain.worldmonitor.SatellitePassPrediction
import com.adshield.pro.domain.worldmonitor.WorldEntity
import com.adshield.pro.domain.worldmonitor.WorldIntelCategory
import com.adshield.pro.domain.worldmonitor.WorldSeverity
import com.adshield.pro.engine.worldmonitor.WorldMonitorAssetAndTileServer
import com.adshield.pro.engine.worldmonitor.WorldMonitorJsBridge
import com.adshield.pro.ui.theme.AlertRed
import com.adshield.pro.ui.theme.CyberCyan
import com.adshield.pro.ui.theme.DeepNavyBackground
import com.adshield.pro.ui.theme.ElectricBlue
import com.adshield.pro.ui.theme.EmeraldPrimary
import com.adshield.pro.ui.theme.NavyBorder
import com.adshield.pro.ui.theme.NavySurface
import com.adshield.pro.ui.theme.NavySurfaceVariant
import com.adshield.pro.ui.theme.SkyBlueGlow
import com.adshield.pro.ui.theme.TextPrimaryDark
import com.adshield.pro.ui.theme.TextSecondaryDark
import com.adshield.pro.ui.theme.WarningAmber
import com.adshield.pro.ui.viewmodel.ClickedLocationInfo
import com.adshield.pro.ui.viewmodel.WorldMonitorDeckTab
import com.adshield.pro.ui.viewmodel.WorldMonitorUiState
import com.adshield.pro.ui.viewmodel.WorldMonitorViewModel
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

@Composable
fun WorldMonitorScreen(
    viewModel: WorldMonitorViewModel,
    onBack: () -> Unit
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val context = LocalContext.current

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(DeepNavyBackground)
    ) {
        WorldMonitorGlobeWebView(
            viewModel = viewModel,
            modifier = Modifier.fillMaxSize()
        )

        if (uiState.fullscreenMode) {
            Row(
                modifier = Modifier
                    .align(Alignment.TopStart)
                    .padding(12.dp)
                    .background(NavySurface.copy(alpha = 0.88f), RoundedCornerShape(20.dp))
                    .border(1.dp, NavyBorder, RoundedCornerShape(20.dp))
                    .padding(horizontal = 10.dp, vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                TextButton(onClick = onBack) {
                    Text("Exit", color = TextPrimaryDark, fontSize = 12.sp)
                }
                TextButton(onClick = viewModel::toggleFullscreen) {
                    Text("Show HUD", color = CyberCyan, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                }
                Text(
                    text = "%.3f°, %.3f°".format(Locale.US, uiState.viewport.centerLat, uiState.viewport.centerLon),
                    color = TextSecondaryDark,
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace,
                    modifier = Modifier.padding(end = 6.dp)
                )
            }
        } else {
            WorldMonitorTopHud(
                uiState = uiState,
                onBack = onBack,
                onSync = { viewModel.syncAllEnabled(force = true) },
                onLoadBuildings = viewModel::load3dBuildingsAtViewport,
                onToggleFullscreen = viewModel::toggleFullscreen,
                onSearchChange = viewModel::updateSearchQuery,
                onSearchSubmit = viewModel::submitGeographicSearch,
                onSelectSearchResult = viewModel::selectSearchResult,
                onToggleCategory = { cat ->
                    val cur = uiState.layerStates[cat]?.visible ?: true
                    viewModel.updateLayerState(cat, visible = !cur)
                },
                modifier = Modifier.align(Alignment.TopCenter)
            )
        }

        Column(
            modifier = Modifier
                .align(Alignment.CenterEnd)
                .padding(end = 10.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            GlobeRoundAction("+") { viewModel.cameraAction("ZOOM_IN") }
            GlobeRoundAction("−") { viewModel.cameraAction("ZOOM_OUT") }
            GlobeRoundAction("3D") { viewModel.cameraAction("TILT_3D") }
            GlobeRoundAction("N") { viewModel.cameraAction("RESET_NORTH") }
            GlobeRoundAction("🌐") { viewModel.cameraAction("HOME") }
        }

        val clicked = uiState.clickedLocation
        if (clicked != null && uiState.selectedEntity == null) {
            ClickedLocationCard(
                info = clicked,
                onDismiss = viewModel::dismissClickedLocation,
                onOpenTwin = {
                    viewModel.dismissClickedLocation()
                    viewModel.selectTab(WorldMonitorDeckTab.TWIN)
                },
                onCreateWatch = {
                    viewModel.dismissClickedLocation()
                    viewModel.selectTab(WorldMonitorDeckTab.WATCHTOWER)
                },
                modifier = Modifier
                    .align(Alignment.BottomCenter)
                    .padding(bottom = if (uiState.deckExpanded && !uiState.fullscreenMode) 310.dp else 64.dp, start = 12.dp, end = 56.dp)
            )
        }

        val selected = uiState.selectedEntity
        if (selected != null) {
            SelectedEntityDossierCard(
                entity = selected,
                passes = uiState.satellitePasses,
                onDismiss = viewModel::dismissSelectedEntity,
                onCenter = { viewModel.focusEntity(selected) },
                onAskAnalyst = {
                    viewModel.askAiAnalyst("Explain selected entity ${selected.title} and assess corroboration and regional exposure")
                    viewModel.dismissSelectedEntity()
                },
                onPredictPasses = { viewModel.computePassesForSelectedSatellite(selected) },
                onOpenSourceUrl = { url ->
                    if (WorldMonitorJsBridge.isAllowedHttpsSourceUrl(url)) {
                        runCatching {
                            context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
                        }
                    }
                },
                modifier = Modifier
                    .align(Alignment.BottomCenter)
                    .padding(bottom = if (uiState.deckExpanded && !uiState.fullscreenMode) 310.dp else 64.dp, start = 10.dp, end = 54.dp)
            )
        }

        if (!uiState.fullscreenMode) {
            WorldMonitorBottomDeck(
                uiState = uiState,
                viewModel = viewModel,
                modifier = Modifier.align(Alignment.BottomCenter)
            )
        }
    }
}

@SuppressLint("SetJavaScriptEnabled")
@Composable
private fun WorldMonitorGlobeWebView(
    viewModel: WorldMonitorViewModel,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val tileAndAssetServer: WorldMonitorAssetAndTileServer = remember(context) { WorldMonitorAssetAndTileServer(context) }
    val jsBridge: WorldMonitorJsBridge = remember(viewModel) { WorldMonitorJsBridge(viewModel) }
    var webViewRef by remember { mutableStateOf<WebView?>(null) }

    LaunchedEffect(webViewRef) {
        val wv = webViewRef ?: return@LaunchedEffect
        viewModel.jsCommands.collect { expr ->
            wv.evaluateJavascript(expr, null)
        }
    }

    DisposableEffect(lifecycleOwner, webViewRef) {
        val observer = LifecycleEventObserver { _, event ->
            when (event) {
                Lifecycle.Event.ON_RESUME -> webViewRef?.onResume()
                Lifecycle.Event.ON_PAUSE -> webViewRef?.onPause()
                else -> Unit
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose {
            lifecycleOwner.lifecycle.removeObserver(observer)
            webViewRef?.let { wv ->
                wv.removeJavascriptInterface(WorldMonitorJsBridge.BRIDGE_NAME)
                wv.stopLoading()
                wv.destroy()
            }
            webViewRef = null
        }
    }

    AndroidView(
        modifier = modifier,
        factory = { ctx ->
            WebView(ctx).apply {
                layoutParams = ViewGroup.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.MATCH_PARENT
                )
                setBackgroundColor(android.graphics.Color.parseColor("#020813"))
                settings.apply {
                    javaScriptEnabled = true
                    domStorageEnabled = true
                    databaseEnabled = false
                    allowFileAccess = false
                    allowContentAccess = false
                    @Suppress("DEPRECATION")
                    allowFileAccessFromFileURLs = false
                    @Suppress("DEPRECATION")
                    allowUniversalAccessFromFileURLs = false
                    mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
                    mediaPlaybackRequiresUserGesture = false
                    setSupportMultipleWindows(false)
                    javaScriptCanOpenWindowsAutomatically = false
                    cacheMode = WebSettings.LOAD_DEFAULT
                }
                jsBridge.attachTo(this)
                webChromeClient = WebChromeClient()
                webViewClient = object : WebViewClient() {
                    override fun shouldInterceptRequest(
                        view: WebView?,
                        request: WebResourceRequest
                    ): WebResourceResponse? = tileAndAssetServer.intercept(request)

                    override fun shouldOverrideUrlLoading(
                        view: WebView?,
                        request: WebResourceRequest
                    ): Boolean = true
                }
                loadUrl(WorldMonitorAssetAndTileServer.ENTRY_URL)
                webViewRef = this
            }
        }
    )
}

@Composable
private fun WorldMonitorTopHud(
    uiState: WorldMonitorUiState,
    onBack: () -> Unit,
    onSync: () -> Unit,
    onLoadBuildings: () -> Unit,
    onToggleFullscreen: () -> Unit,
    onSearchChange: (String) -> Unit,
    onSearchSubmit: () -> Unit,
    onSelectSearchResult: (GeocodeSearchResult) -> Unit,
    onToggleCategory: (WorldIntelCategory) -> Unit,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier
            .fillMaxWidth()
            .padding(horizontal = 10.dp, vertical = 8.dp)
    ) {
        Surface(
            color = NavySurface.copy(alpha = 0.90f),
            shape = RoundedCornerShape(14.dp),
            modifier = Modifier
                .fillMaxWidth()
                .border(1.dp, NavyBorder, RoundedCornerShape(14.dp))
        ) {
            Column(modifier = Modifier.padding(horizontal = 8.dp, vertical = 6.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    IconButton(onClick = onBack, modifier = Modifier.size(34.dp)) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = TextPrimaryDark)
                    }
                    Column(modifier = Modifier.weight(1f)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(
                                text = "WORLD MONITOR 2035",
                                color = TextPrimaryDark,
                                fontWeight = FontWeight.Bold,
                                fontSize = 13.sp,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                            Spacer(Modifier.width(6.dp))
                            if (uiState.simulation.active) {
                                BadgePill("SIMULATION", WarningAmber)
                            } else {
                                BadgePill(
                                    if (uiState.globeReady) "3D LIVE" else "INIT",
                                    if (uiState.globeReady) EmeraldPrimary else CyberCyan
                                )
                            }
                        }
                        Text(
                            text = "%.3f°, %.3f° · Alt %,d km · Elev %d m · %,d items".format(
                                Locale.US,
                                uiState.viewport.centerLat,
                                uiState.viewport.centerLon,
                                (uiState.viewport.cameraAltitudeMeters / 1000L),
                                uiState.viewport.groundElevationMeters,
                                uiState.filteredEntities.size
                            ),
                            color = TextSecondaryDark,
                            fontSize = 10.sp,
                            fontFamily = FontFamily.Monospace,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }

                    TextButton(
                        onClick = onLoadBuildings,
                        contentPadding = PaddingValues(horizontal = 6.dp, vertical = 2.dp)
                    ) {
                        Text("3D City", color = CyberCyan, fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
                    }

                    TextButton(
                        onClick = onToggleFullscreen,
                        contentPadding = PaddingValues(horizontal = 6.dp, vertical = 2.dp)
                    ) {
                        Text("Full", color = SkyBlueGlow, fontSize = 11.sp)
                    }

                    IconButton(onClick = onSync, modifier = Modifier.size(34.dp)) {
                        if (uiState.isSyncing) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(16.dp),
                                strokeWidth = 2.dp,
                                color = CyberCyan
                            )
                        } else {
                            Icon(Icons.Default.Refresh, contentDescription = "Sync Now", tint = EmeraldPrimary)
                        }
                    }
                }

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 4.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    OutlinedTextField(
                        value = uiState.searchQuery,
                        onValueChange = onSearchChange,
                        placeholder = {
                            Text(
                                "Search country, city, airport (MNL/JFK), port, or lat,lon…",
                                fontSize = 11.sp,
                                color = TextSecondaryDark
                            )
                        },
                        singleLine = true,
                        leadingIcon = {
                            Icon(Icons.Default.Search, contentDescription = null, tint = CyberCyan, modifier = Modifier.size(16.dp))
                        },
                        trailingIcon = {
                            if (uiState.searchQuery.isNotEmpty()) {
                                IconButton(onClick = { onSearchChange("") }, modifier = Modifier.size(24.dp)) {
                                    Icon(Icons.Default.Close, contentDescription = "Clear", tint = TextSecondaryDark, modifier = Modifier.size(14.dp))
                                }
                            }
                        },
                        keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
                        keyboardActions = KeyboardActions(onSearch = { onSearchSubmit() }),
                        textStyle = MaterialTheme.typography.bodySmall.copy(color = TextPrimaryDark, fontSize = 12.sp),
                        modifier = Modifier
                            .weight(1f)
                            .height(44.dp)
                    )
                    Spacer(Modifier.width(6.dp))
                    Button(
                        onClick = onSearchSubmit,
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 6.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = ElectricBlue),
                        modifier = Modifier.height(40.dp)
                    ) {
                        Text("Go", fontSize = 12.sp)
                    }
                }

                if (uiState.searchResults.isNotEmpty()) {
                    LazyColumn(
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(max = 150.dp)
                            .padding(top = 4.dp)
                            .background(NavySurfaceVariant, RoundedCornerShape(8.dp))
                    ) {
                        items(items = uiState.searchResults, key = { "${it.displayName}:${it.latitude}:${it.longitude}" }) { res ->
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable { onSelectSearchResult(res) }
                                    .padding(horizontal = 10.dp, vertical = 7.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(res.displayName, color = TextPrimaryDark, fontSize = 12.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                    Text("${res.category} · ${res.attribution}", color = TextSecondaryDark, fontSize = 10.sp)
                                }
                                Text(
                                    "%.2f, %.2f".format(Locale.US, res.latitude, res.longitude),
                                    color = CyberCyan,
                                    fontSize = 10.sp,
                                    fontFamily = FontFamily.Monospace
                                )
                            }
                        }
                    }
                }

                uiState.globeError?.let { err ->
                    Text(text = err, color = AlertRed, fontSize = 11.sp, modifier = Modifier.padding(top = 4.dp))
                }
                uiState.statusBanner?.let { msg ->
                    Text(
                        text = msg,
                        color = CyberCyan,
                        fontSize = 10.sp,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.padding(top = 3.dp)
                    )
                }
            }
        }

        LazyRow(
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 6.dp),
            horizontalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            items(items = WorldIntelCategory.entries, key = { it.name }) { cat ->
                val enabled = uiState.layerStates[cat]?.visible != false
                val count = uiState.categoryCounts[cat] ?: 0
                FilterChip(
                    selected = enabled,
                    onClick = { onToggleCategory(cat) },
                    label = {
                        Text(
                            text = "${cat.shortCode} ($count)",
                            fontSize = 11.sp,
                            fontWeight = if (enabled) FontWeight.SemiBold else FontWeight.Normal
                        )
                    },
                    colors = FilterChipDefaults.filterChipColors(
                        selectedContainerColor = ElectricBlue.copy(alpha = 0.28f),
                        selectedLabelColor = TextPrimaryDark,
                        containerColor = NavySurface.copy(alpha = 0.85f),
                        labelColor = TextSecondaryDark
                    )
                )
            }
        }
    }
}

@Composable
private fun WorldMonitorBottomDeck(
    uiState: WorldMonitorUiState,
    viewModel: WorldMonitorViewModel,
    modifier: Modifier = Modifier
) {
    Surface(
        color = NavySurface.copy(alpha = 0.94f),
        shape = RoundedCornerShape(topStart = 18.dp, topEnd = 18.dp),
        modifier = modifier
            .fillMaxWidth()
            .border(1.dp, NavyBorder, RoundedCornerShape(topStart = 18.dp, topEnd = 18.dp))
    ) {
        Column(modifier = Modifier.fillMaxWidth()) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 8.dp, vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                LazyRow(
                    modifier = Modifier.weight(1f),
                    horizontalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    items(items = WorldMonitorDeckTab.entries, key = { it.name }) { tab ->
                        val active = uiState.activeTab == tab
                        val badgeSuffix = when (tab) {
                            WorldMonitorDeckTab.CORRELATE ->
                                if (uiState.correlations.isNotEmpty()) " (${uiState.correlations.size})" else ""
                            WorldMonitorDeckTab.WATCHTOWER ->
                                if (uiState.watchAlerts.isNotEmpty()) " (${uiState.watchAlerts.size})" else ""
                            else -> ""
                        }
                        FilterChip(
                            selected = active,
                            onClick = { viewModel.selectTab(tab) },
                            label = {
                                Text(
                                    text = tab.label + badgeSuffix,
                                    fontSize = 11.sp,
                                    fontWeight = if (active) FontWeight.Bold else FontWeight.Medium
                                )
                            },
                            colors = FilterChipDefaults.filterChipColors(
                                selectedContainerColor = CyberCyan.copy(alpha = 0.22f),
                                selectedLabelColor = CyberCyan,
                                containerColor = NavySurfaceVariant,
                                labelColor = TextSecondaryDark
                            )
                        )
                    }
                }
                IconButton(onClick = viewModel::toggleDeckExpanded, modifier = Modifier.size(32.dp)) {
                    Icon(
                        imageVector = if (uiState.deckExpanded) Icons.Default.KeyboardArrowDown else Icons.Default.KeyboardArrowUp,
                        contentDescription = "Toggle Deck",
                        tint = TextPrimaryDark
                    )
                }
            }

            if (uiState.deckExpanded) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(255.dp)
                        .padding(horizontal = 10.dp, vertical = 4.dp)
                ) {
                    WorldMonitorDeckContent(uiState = uiState, viewModel = viewModel)
                }
            }
        }
    }
}

@Composable
private fun ClickedLocationCard(
    info: ClickedLocationInfo,
    onDismiss: () -> Unit,
    onOpenTwin: () -> Unit,
    onCreateWatch: () -> Unit,
    modifier: Modifier = Modifier
) {
    Surface(
        color = NavySurface.copy(alpha = 0.95f),
        shape = RoundedCornerShape(14.dp),
        modifier = modifier
            .fillMaxWidth()
            .border(1.dp, CyberCyan.copy(alpha = 0.5f), RoundedCornerShape(14.dp))
    ) {
        Column(modifier = Modifier.padding(10.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = info.placeName ?: "Earth Coordinate Inspection",
                        color = TextPrimaryDark,
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 13.sp,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis
                    )
                    Text(
                        text = "Lat %.4f° · Lon %.4f° · Elevation %,d m MSL%s".format(
                            Locale.US,
                            info.latitude,
                            info.longitude,
                            info.elevationMeters,
                            info.population?.let { " · Country Pop %,d".format(Locale.US, it) }.orEmpty()
                        ),
                        color = CyberCyan,
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace
                    )
                }
                IconButton(onClick = onDismiss, modifier = Modifier.size(26.dp)) {
                    Icon(Icons.Default.Close, contentDescription = "Close", tint = TextSecondaryDark, modifier = Modifier.size(16.dp))
                }
            }
            Row(
                modifier = Modifier.padding(top = 6.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                OutlinedButton(
                    onClick = onOpenTwin,
                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                    modifier = Modifier.height(30.dp)
                ) {
                    Text("Regional Digital Twin", fontSize = 11.sp, color = CyberCyan)
                }
                OutlinedButton(
                    onClick = onCreateWatch,
                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                    modifier = Modifier.height(30.dp)
                ) {
                    Text("Watch Geofence", fontSize = 11.sp, color = EmeraldPrimary)
                }
            }
        }
    }
}

@Composable
private fun SelectedEntityDossierCard(
    entity: WorldEntity,
    passes: List<SatellitePassPrediction>,
    onDismiss: () -> Unit,
    onCenter: () -> Unit,
    onAskAnalyst: () -> Unit,
    onPredictPasses: () -> Unit,
    onOpenSourceUrl: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    val fmt = remember {
        SimpleDateFormat("yyyy-MM-dd HH:mm 'UTC'", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }
    }
    val metricEntries = remember(entity.metricsMap) { entity.metricsMap.entries.take(8) }

    Surface(
        color = NavySurface.copy(alpha = 0.96f),
        shape = RoundedCornerShape(14.dp),
        modifier = modifier
            .fillMaxWidth()
            .heightIn(max = 260.dp)
            .border(1.dp, severityColor(entity.severity), RoundedCornerShape(14.dp))
    ) {
        LazyColumn(
            modifier = Modifier.padding(10.dp),
            verticalArrangement = Arrangement.spacedBy(5.dp)
        ) {
            item(key = "header") {
                Row(verticalAlignment = Alignment.Top) {
                    Column(modifier = Modifier.weight(1f)) {
                        Row(
                            horizontalArrangement = Arrangement.spacedBy(5.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            BadgePill(entity.category.shortCode, ElectricBlue)
                            BadgePill(entity.severity.label, severityColor(entity.severity))
                            BadgePill(entity.freshness.label, freshnessColor(entity.freshness))
                        }
                        Text(
                            text = entity.title,
                            color = TextPrimaryDark,
                            fontWeight = FontWeight.Bold,
                            fontSize = 14.sp,
                            modifier = Modifier.padding(top = 3.dp)
                        )
                        Text(text = entity.summary, color = TextSecondaryDark, fontSize = 12.sp)
                    }
                    IconButton(onClick = onDismiss, modifier = Modifier.size(26.dp)) {
                        Icon(Icons.Default.Close, contentDescription = "Dismiss", tint = TextSecondaryDark, modifier = Modifier.size(16.dp))
                    }
                }
            }

            item(key = "trust_metadata") {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(NavySurfaceVariant, RoundedCornerShape(8.dp))
                        .padding(8.dp),
                    verticalArrangement = Arrangement.spacedBy(2.dp)
                ) {
                    Text(
                        text = "Provider: ${entity.providerName} · Confidence ${entity.confidence}% (${entity.verificationStatus.label})",
                        color = CyberCyan,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.SemiBold
                    )
                    Text(
                        text = "Geo Accuracy: ${entity.geoAccuracy.label} (%.4f°, %.4f°)".format(Locale.US, entity.latitude, entity.longitude),
                        color = TextPrimaryDark,
                        fontSize = 11.sp
                    )
                    Text(
                        text = "Event: ${fmt.format(Date(entity.eventTimeEpochMs))} · Synced: ${fmt.format(Date(entity.retrievedAtEpochMs))}",
                        color = TextSecondaryDark,
                        fontSize = 10.sp,
                        fontFamily = FontFamily.Monospace
                    )
                    Text(
                        text = "Attribution: ${entity.attribution} · ${entity.licenseInfo}",
                        color = TextSecondaryDark,
                        fontSize = 10.sp
                    )
                }
            }

            if (metricEntries.isNotEmpty()) {
                item(key = "attributes") {
                    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        for (entry in metricEntries) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Text(entry.key, color = TextSecondaryDark, fontSize = 11.sp)
                                Text(entry.value, color = TextPrimaryDark, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                            }
                        }
                    }
                }
            }

            if (passes.isNotEmpty()) {
                item(key = "sat_passes_header") {
                    Text(
                        "Predicted 24h Overhead Passes (>10° elevation):",
                        color = EmeraldPrimary,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.SemiBold
                    )
                }
                items(items = passes.take(4), key = { "${it.entityId}:${it.riseEpochMs}" }) { pass ->
                    Text(
                        text = "• ${fmt.format(Date(pass.riseEpochMs))} · Max El ${"%.1f".format(Locale.US, pass.maxElevationDeg)}° · ${pass.durationSeconds}s",
                        color = TextPrimaryDark,
                        fontSize = 10.sp,
                        fontFamily = FontFamily.Monospace
                    )
                }
            }

            item(key = "actions") {
                Row(
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    modifier = Modifier.padding(top = 4.dp)
                ) {
                    OutlinedButton(
                        onClick = onCenter,
                        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 3.dp),
                        modifier = Modifier.height(28.dp)
                    ) {
                        Text("Center", fontSize = 11.sp, color = CyberCyan)
                    }
                    OutlinedButton(
                        onClick = onAskAnalyst,
                        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 3.dp),
                        modifier = Modifier.height(28.dp)
                    ) {
                        Text("AI Brief", fontSize = 11.sp, color = EmeraldPrimary)
                    }
                    if (!entity.tleLine1.isNullOrBlank()) {
                        OutlinedButton(
                            onClick = onPredictPasses,
                            contentPadding = PaddingValues(horizontal = 8.dp, vertical = 3.dp),
                            modifier = Modifier.height(28.dp)
                        ) {
                            Text("Passes", fontSize = 11.sp, color = SkyBlueGlow)
                        }
                    }
                    OutlinedButton(
                        onClick = { onOpenSourceUrl(entity.sourceUrl) },
                        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 3.dp),
                        modifier = Modifier.height(28.dp)
                    ) {
                        Text("Source ↗", fontSize = 11.sp, color = TextPrimaryDark)
                    }
                }
            }
        }
    }
}

@Composable
private fun GlobeRoundAction(label: String, onClick: () -> Unit) {
    Surface(
        color = NavySurface.copy(alpha = 0.88f),
        shape = CircleShape,
        modifier = Modifier
            .size(36.dp)
            .border(1.dp, NavyBorder, CircleShape)
            .clickable(onClick = onClick)
    ) {
        Box(contentAlignment = Alignment.Center) {
            Text(label, color = TextPrimaryDark, fontSize = 12.sp, fontWeight = FontWeight.Bold)
        }
    }
}

@Composable
internal fun BadgePill(text: String, color: Color) {
    Box(
        modifier = Modifier
            .background(color.copy(alpha = 0.20f), RoundedCornerShape(6.dp))
            .border(1.dp, color.copy(alpha = 0.65f), RoundedCornerShape(6.dp))
            .padding(horizontal = 5.dp, vertical = 1.dp)
    ) {
        Text(text = text, color = color, fontSize = 9.sp, fontWeight = FontWeight.Bold)
    }
}

internal fun severityColor(severity: WorldSeverity): Color = when (severity) {
    WorldSeverity.CRITICAL -> AlertRed
    WorldSeverity.HIGH -> WarningAmber
    WorldSeverity.MEDIUM -> SkyBlueGlow
    WorldSeverity.LOW -> EmeraldPrimary
    WorldSeverity.INFO -> CyberCyan
}

internal fun freshnessColor(freshness: FreshnessClass): Color = when (freshness) {
    FreshnessClass.LIVE -> EmeraldPrimary
    FreshnessClass.NEAR_REAL_TIME -> CyberCyan
    FreshnessClass.DELAYED -> WarningAmber
    FreshnessClass.HISTORICAL -> SkyBlueGlow
    FreshnessClass.ESTIMATED -> Color(0xFFA78BFA)
    FreshnessClass.SIMULATED -> AlertRed
}
