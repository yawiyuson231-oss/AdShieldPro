package com.adshield.pro.ui.evolution

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.adshield.pro.engine.evolution.EvolutionPublisherConfiguration
import com.adshield.pro.engine.evolution.EvolutionUpdateWorker
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Additive settings control; no network call or key material is accepted from the UI. */
@Composable
internal fun EvolutionSettingsCard() {
    val context = LocalContext.current.applicationContext
    val scope = rememberCoroutineScope()
    var enabled by remember { mutableStateOf(false) }
    var configured by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(true) }
    var canRollback by remember { mutableStateOf(false) }
    var status by remember { mutableStateOf("Loading publisher status…") }
    var message by remember { mutableStateOf("") }
    var refresh by remember { mutableStateOf(0) }
    LaunchedEffect(refresh) {
        do {
            val snapshot = withContext(Dispatchers.IO) {
                val consent = EvolutionPublisherConfiguration.enabled(context)
                val stager = EvolutionPublisherConfiguration.createStager(context)
                val active = runCatching { stager?.activeStatus() }
                val description = when {
                    stager == null -> "Publisher not configured. Downloads are unavailable."
                    !consent -> "Off. Publisher data is not used by scans."
                    active.isFailure -> "Active data is expired or invalid; local scanning remains available."
                    active.getOrNull() == null -> "No active data. Waiting for a verified update."
                    else -> "Active sequence ${active.getOrNull()!!.sequence}; expires ${java.util.Date(active.getOrNull()!!.expiresAt * 1000)}"
                }
                Triple(consent, stager != null, Pair(description + "\n" + EvolutionPublisherConfiguration.lastStatus(context), active.getOrNull()?.canRollback == true))
            }
            enabled = snapshot.first
            configured = snapshot.second
            status = snapshot.third.first
            canRollback = snapshot.third.second
            busy = false
            delay(30_000)
        } while (true)
    }
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Signed APK reputation updates", style = MaterialTheme.typography.titleMedium)
            Text("Optional downloads from this project's GitHub Releases. GitHub receives normal connection metadata, not scanned files or hashes. Exact-hash publisher labels are advisory only; local verdicts and DNS behavior do not change.", style = MaterialTheme.typography.bodySmall)
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text("Allow automatic data updates")
                Switch(checked = enabled, enabled = !busy && (configured || enabled), onCheckedChange = { value ->
                    busy = true
                    scope.launch {
                        try {
                            val saved = withContext(Dispatchers.IO) { EvolutionPublisherConfiguration.setEnabled(context, value) }
                            message = if (saved) "Preference saved" else "Preference could not be saved"
                        } catch (cancelled: CancellationException) { throw cancelled }
                        catch (_: Exception) { message = "Update scheduling unavailable" }
                        finally { busy = false; refresh++ }
                    }
                })
            }
            Text(status, style = MaterialTheme.typography.bodySmall)
            if (message.isNotBlank()) Text(message, style = MaterialTheme.typography.bodySmall)
            Row {
                TextButton(enabled = enabled && configured && !busy, onClick = {
                    scope.launch {
                        try {
                            withContext(Dispatchers.IO) { EvolutionUpdateWorker.checkNow(context) }
                            message = "Check queued; waits for unmetered network and suitable resources"
                        } catch (cancelled: CancellationException) { throw cancelled }
                        catch (_: Exception) { message = "Could not queue update check" }
                    }
                }) { Text("Check now") }
                TextButton(enabled = enabled && canRollback && !busy, onClick = {
                    busy = true
                    scope.launch {
                        try {
                            val restored = withContext(Dispatchers.IO) {
                                EvolutionPublisherConfiguration.createStager(context)?.rollback() == true
                            }
                            message = if (restored) "Previous verified data restored" else "No valid rollback available"
                        } catch (cancelled: CancellationException) { throw cancelled }
                        catch (_: Exception) { message = "Rollback rejected; existing data retained" }
                        finally { busy = false; refresh++ }
                    }
                }) { Text("Roll back") }
            }
        }
    }
}
