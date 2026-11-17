package com.adshield.pro.ui.components

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.OpenInBrowser
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.adshield.pro.engine.security.UrlThreatScanner
import com.adshield.pro.ui.theme.AlertRed
import com.adshield.pro.ui.theme.CyberCyan
import com.adshield.pro.ui.theme.ElectricBlue
import com.adshield.pro.ui.theme.EmeraldPrimary
import com.adshield.pro.ui.theme.WarningAmber
import com.adshield.pro.ui.viewmodel.SharedLinkInspection

/**
 * Modal dialog shown whenever a URL/text is shared into AdShield Pro from Android's native Share
 * Sheet (or tested inside the Security Center Link Cleaner). Displays stripped tracking params,
 * unwrapped outbound redirects, and an instant on-device threat verdict, with one-tap Copy, Share,
 * and Open in Privacy Browser actions.
 */
@Composable
fun LinkCleanerDialog(
    inspection: SharedLinkInspection,
    onDismiss: () -> Unit,
    onOpenInPrivacyBrowser: (String) -> Unit,
    onFeedback: (String) -> Unit
) {
    val context = LocalContext.current
    val sanitized = inspection.sanitized
    val primary = sanitized.primaryLink
    val verdict = inspection.verdict
    var confirmDangerousOpen by remember(primary?.cleanedUrl) { mutableStateOf(false) }

    val copyPayload = primary?.cleanedUrl ?: sanitized.cleanedText
    val sharePayload = if (sanitized.links.size == 1 && sanitized.originalText.trim() == primary?.originalUrl) {
        primary.cleanedUrl
    } else {
        sanitized.cleanedText
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                text = "Link Cleaner & Threat Check",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
        },
        text = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(max = 430.dp)
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                if (primary == null) {
                    Text(
                        text = "No HTTP(S) link was detected in the shared text.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Surface(
                        color = MaterialTheme.colorScheme.surfaceVariant,
                        shape = RoundedCornerShape(10.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            text = sanitized.originalText.take(400),
                            style = MaterialTheme.typography.bodySmall,
                            modifier = Modifier.padding(10.dp)
                        )
                    }
                } else {
                    // 1. Tracker & Redirect Sanitization Summary
                    val removedCount = sanitized.totalRemovedParams
                    val unwrappedCount = sanitized.totalUnwrappedRedirects
                    Surface(
                        color = MaterialTheme.colorScheme.surfaceVariant,
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(
                            modifier = Modifier.padding(10.dp),
                            verticalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            val headline = when {
                                removedCount > 0 && unwrappedCount > 0 ->
                                    "Stripped $removedCount tracker(s) & unwrapped $unwrappedCount redirect"
                                removedCount > 0 ->
                                    "Stripped $removedCount tracking parameter(s) (−${primary.charsSaved} chars)"
                                unwrappedCount > 0 ->
                                    "Unwrapped redirect via ${primary.unwrappedFromHosts.joinToString(" → ")}"
                                else ->
                                    "Link is already free of known tracking parameters"
                            }
                            Text(
                                text = headline,
                                style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.SemiBold,
                                color = if (primary.wasModified) CyberCyan else EmeraldPrimary
                            )
                            if (primary.unwrappedFromHosts.isNotEmpty() && removedCount > 0) {
                                Text(
                                    text = "Redirect peeled: ${primary.unwrappedFromHosts.joinToString(" → ")}",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                            if (primary.removedParams.isNotEmpty()) {
                                Text(
                                    text = "Removed: ${primary.removedParams.joinToString(", ")}",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }

                    // 2. Cleaned URL box
                    Text(
                        text = if (sanitized.links.size > 1) {
                            "Cleaned primary link (${sanitized.links.size} links cleaned in text)"
                        } else {
                            "Clean link"
                        },
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.SemiBold
                    )
                    Surface(
                        color = MaterialTheme.colorScheme.surfaceVariant,
                        shape = RoundedCornerShape(10.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        SelectionContainer {
                            Text(
                                text = primary.cleanedUrl,
                                fontFamily = FontFamily.Monospace,
                                fontSize = 11.sp,
                                modifier = Modifier.padding(10.dp)
                            )
                        }
                    }

                    // 3. Instant On-Device Threat Verdict
                    when {
                        inspection.isScanning -> {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                                Spacer(Modifier.width(8.dp))
                                Text(
                                    "Checking against on-device threat rules & phishing heuristics…",
                                    style = MaterialTheme.typography.bodySmall
                                )
                            }
                        }
                        verdict != null -> {
                            val (tint, label) = when (verdict.threatLevel) {
                                UrlThreatScanner.ThreatLevel.DANGEROUS -> AlertRed to "HIGH RISK (${verdict.riskScore}/100)"
                                UrlThreatScanner.ThreatLevel.SUSPICIOUS -> WarningAmber to "SUSPICIOUS (${verdict.riskScore}/100)"
                                UrlThreatScanner.ThreatLevel.CLEAN -> EmeraldPrimary to "SAFE TO OPEN (${verdict.riskScore}/100)"
                            }
                            Surface(
                                color = tint.copy(alpha = 0.12f),
                                shape = RoundedCornerShape(12.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(
                                    modifier = Modifier.padding(10.dp),
                                    verticalArrangement = Arrangement.spacedBy(4.dp)
                                ) {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Icon(
                                            if (verdict.isSafe) Icons.Default.CheckCircle else Icons.Default.Warning,
                                            contentDescription = null,
                                            tint = tint,
                                            modifier = Modifier.size(16.dp)
                                        )
                                        Spacer(Modifier.width(6.dp))
                                        Text(label, color = tint, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                                    }
                                    verdict.findings.take(4).forEach { finding ->
                                        Text("• $finding", style = MaterialTheme.typography.labelSmall)
                                    }
                                    Text(
                                        text = verdict.recommendation,
                                        style = MaterialTheme.typography.labelSmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                            }
                        }
                    }

                    // 4. Quick Action Buttons
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Button(
                            onClick = {
                                copyTextToClipboard(context, copyPayload)
                                onFeedback("Clean link copied to clipboard.")
                            },
                            modifier = Modifier.weight(1f),
                            colors = ButtonDefaults.buttonColors(containerColor = ElectricBlue)
                        ) {
                            Icon(Icons.Default.ContentCopy, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(Modifier.width(6.dp))
                            Text("Copy", maxLines = 1)
                        }
                        OutlinedButton(
                            onClick = {
                                runCatching {
                                    val sendIntent = Intent(Intent.ACTION_SEND).apply {
                                        type = "text/plain"
                                        putExtra(Intent.EXTRA_TEXT, sharePayload)
                                    }
                                    context.startActivity(
                                        Intent.createChooser(sendIntent, "Share clean link")
                                            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                                    )
                                }
                            },
                            modifier = Modifier.weight(1f)
                        ) {
                            Icon(Icons.Default.Share, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(Modifier.width(6.dp))
                            Text("Share", maxLines = 1)
                        }
                    }

                    val isDangerous = verdict?.threatLevel == UrlThreatScanner.ThreatLevel.DANGEROUS
                    if (isDangerous && !confirmDangerousOpen) {
                        OutlinedButton(
                            onClick = { confirmDangerousOpen = true },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Icon(Icons.Default.Warning, contentDescription = null, tint = AlertRed, modifier = Modifier.size(16.dp))
                            Spacer(Modifier.width(6.dp))
                            Text("High risk — tap again to open anyway", color = AlertRed, fontSize = 12.sp)
                        }
                    } else {
                        OutlinedButton(
                            onClick = { onOpenInPrivacyBrowser(primary.cleanedUrl) },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Icon(Icons.Default.OpenInBrowser, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(Modifier.width(6.dp))
                            Text(
                                if (isDangerous) "Confirm open in Privacy Browser" else "Open in Privacy Browser",
                                maxLines = 1
                            )
                        }
                    }

                    if (primary.wasModified) {
                        Spacer(Modifier.height(2.dp))
                        Text(
                            text = "Original: ${primary.originalUrl.take(220)}${if (primary.originalUrl.length > 220) "…" else ""}",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text("Close")
            }
        }
    )
}

private fun copyTextToClipboard(context: Context, text: String) {
    val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return
    cm.setPrimaryClip(ClipData.newPlainText("Clean link", text))
}
