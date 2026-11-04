package com.adshield.pro.ui.screens

import android.net.Uri
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Rule
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.FilterAlt
import androidx.compose.material.icons.filled.Public
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.adshield.pro.data.local.preferences.AppSettingsState
import com.adshield.pro.domain.model.CustomRule
import com.adshield.pro.domain.model.FilterEvaluationResult
import com.adshield.pro.domain.model.FilterListSource
import com.adshield.pro.domain.model.RuleCategory
import com.adshield.pro.domain.model.RuleConflictReport
import com.adshield.pro.domain.model.RuleMatchType
import com.adshield.pro.domain.model.RuleType
import com.adshield.pro.engine.browser.BrowserContentBlocker
import com.adshield.pro.engine.browser.SearchProvider
import com.adshield.pro.engine.downloader.MediaDownloaderEngine
import java.io.File

@Composable
fun AdBlockerHubScreen(
    sources: List<FilterListSource>,
    rules: List<CustomRule>,
    conflicts: List<RuleConflictReport>,
    sandboxResult: FilterEvaluationResult?,
    settings: AppSettingsState,
    isUpdatingFilters: Boolean,
    browserContentBlocker: BrowserContentBlocker,
    mediaProbeResult: MediaDownloaderEngine.MediaProbeResult?,
    mediaProbeError: String?,
    isProbingMedia: Boolean,
    mediaTasks: List<MediaDownloaderEngine.MediaDownloadTask>,
    onToggleSource: (FilterListSource, Boolean) -> Unit,
    onSyncAllNow: () -> Unit,
    onAddCustomSource: (String, String, RuleCategory) -> Unit,
    onDeleteCustomSource: (String) -> Unit,
    onUpdateAutoSyncSchedule: (Boolean, Int) -> Unit,
    onAddRule: (String, RuleType, RuleMatchType?, String) -> Unit,
    onUpdateRule: (CustomRule) -> Unit,
    onToggleRule: (CustomRule, Boolean) -> Unit,
    onDeleteRule: (Long) -> Unit,
    onDeduplicateRules: () -> Unit,
    onImportRulesText: (String) -> Unit,
    onExportRulesText: suspend () -> String,
    onTestDomainSandbox: (String) -> Unit,
    onToggleSiteException: (String, Boolean) -> Unit,
    onUpdateBrowserPrivacy: (Boolean, Boolean, Boolean, Boolean, Boolean) -> Unit,
    onSelectSearchProvider: (SearchProvider) -> Unit,
    onAddCustomCosmeticSelector: (String) -> Unit,
    onProbeMediaUrl: (String) -> Unit,
    onStartMediaDownload: (
        MediaDownloaderEngine.MediaProbeResult,
        MediaDownloaderEngine.MediaFormatOption,
        MediaDownloaderEngine.DownloadDestinationKind,
        Uri?
    ) -> Unit,
    onPauseMediaDownload: (String) -> Unit,
    onResumeMediaDownload: (String) -> Unit,
    onCancelMediaDownload: (String) -> Unit,
    onRemoveMediaDownload: (String, Boolean) -> Unit,
    onClearCompletedMediaDownloads: () -> Unit,
    onOpenCompletedFile: (File, String) -> Unit,
    onSaveCompletedToVault: (String) -> Unit,
    onShowFeedback: (String) -> Unit
) {
    var selectedSubTab by rememberSaveable { mutableIntStateOf(0) }
    var downloaderPrefillUrl by rememberSaveable { mutableStateOf("") }

    Column(modifier = Modifier.fillMaxSize()) {
        Surface(
            color = MaterialTheme.colorScheme.surface,
            tonalElevation = 2.dp,
            modifier = Modifier.fillMaxWidth()
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState())
                    .padding(horizontal = 16.dp, vertical = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                FilterChip(
                    selected = selectedSubTab == 0,
                    onClick = { selectedSubTab = 0 },
                    label = {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.FilterAlt, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("Blocklists", maxLines = 1)
                        }
                    }
                )
                FilterChip(
                    selected = selectedSubTab == 1,
                    onClick = { selectedSubTab = 1 },
                    label = {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.AutoMirrored.Filled.Rule, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("Rules (${rules.size})", maxLines = 1)
                        }
                    }
                )
                FilterChip(
                    selected = selectedSubTab == 2,
                    onClick = { selectedSubTab = 2 },
                    label = {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.Public, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("Browser", maxLines = 1)
                        }
                    }
                )
                FilterChip(
                    selected = selectedSubTab == 3,
                    onClick = { selectedSubTab = 3 },
                    label = {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.Download, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("Downloader", maxLines = 1)
                        }
                    }
                )
            }
        }

        Box(modifier = Modifier.fillMaxSize()) {
            when (selectedSubTab) {
                0 -> FiltersScreen(
                    sources = sources,
                    settings = settings,
                    isUpdating = isUpdatingFilters,
                    onToggleSource = onToggleSource,
                    onSyncAllNow = onSyncAllNow,
                    onAddCustomSource = onAddCustomSource,
                    onDeleteCustomSource = onDeleteCustomSource,
                    onUpdateAutoSyncSchedule = onUpdateAutoSyncSchedule
                )
                1 -> RulesScreen(
                    rules = rules,
                    conflicts = conflicts,
                    sandboxResult = sandboxResult,
                    onAddRule = onAddRule,
                    onUpdateRule = onUpdateRule,
                    onToggleRule = onToggleRule,
                    onDeleteRule = onDeleteRule,
                    onDeduplicateRules = onDeduplicateRules,
                    onImportRulesText = onImportRulesText,
                    onExportRulesText = onExportRulesText,
                    onTestDomainSandbox = onTestDomainSandbox
                )
                2 -> BrowserScreen(
                    settings = settings,
                    browserContentBlocker = browserContentBlocker,
                    onToggleSiteException = onToggleSiteException,
                    onUpdateBrowserPrivacy = onUpdateBrowserPrivacy,
                    onSelectSearchProvider = onSelectSearchProvider,
                    onAddCustomCosmeticSelector = onAddCustomCosmeticSelector,
                    onOpenInDownloader = { currentUrl ->
                        downloaderPrefillUrl = currentUrl
                        selectedSubTab = 3
                        onProbeMediaUrl(currentUrl)
                    },
                    onShowFeedback = onShowFeedback
                )
                else -> DownloaderScreen(
                    prefilledUrl = downloaderPrefillUrl,
                    probeResult = mediaProbeResult,
                    probeError = mediaProbeError,
                    isProbing = isProbingMedia,
                    tasks = mediaTasks,
                    onProbeUrl = onProbeMediaUrl,
                    onStartDownload = onStartMediaDownload,
                    onPause = onPauseMediaDownload,
                    onResume = onResumeMediaDownload,
                    onCancel = onCancelMediaDownload,
                    onRemove = onRemoveMediaDownload,
                    onClearFinished = onClearCompletedMediaDownloads,
                    onOpenCompletedFile = onOpenCompletedFile,
                    onSaveCompletedToVault = onSaveCompletedToVault
                )
            }
        }
    }
}
