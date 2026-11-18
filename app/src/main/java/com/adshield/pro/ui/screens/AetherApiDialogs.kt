package com.adshield.pro.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.SecureFlagPolicy
import com.adshield.pro.engine.aether.AetherChatLimit
import com.adshield.pro.engine.aether.AetherOnlineApproval
import com.adshield.pro.engine.aether.AetherOnlineConfig
import com.adshield.pro.engine.aether.AetherOnlineEndpoint
import com.adshield.pro.engine.aether.AetherOnlineProvider

@Composable
internal fun AetherApiSetupDialog(
    endpoint: AetherOnlineEndpoint?,
    saving: Boolean,
    error: String?,
    onSave: (AetherOnlineConfig.Input) -> Unit,
    onDisconnect: () -> Unit,
    onDismiss: () -> Unit
) {
    var provider by remember(endpoint) { mutableStateOf(endpoint?.provider ?: AetherOnlineProvider.GEMINI) }
    var showProviders by remember { mutableStateOf(false) }
    var url by remember(endpoint) { mutableStateOf(endpoint?.takeIf { it.provider == AetherOnlineProvider.COMPATIBLE }?.url.orEmpty()) }
    var model by remember(endpoint) { mutableStateOf(endpoint?.model ?: provider.defaultModel) }
    var chatLimit by remember(endpoint) { mutableStateOf(endpoint?.chatLimit ?: AetherChatLimit.MAX_TOKENS) }
    // Never restore a key from the vault or put it in saved instance state.
    var apiKey by remember { mutableStateOf("") }
    val custom = provider == AetherOnlineProvider.COMPATIBLE
    AlertDialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn),
        title = { Text(if (endpoint == null) "Connect AI API" else "AI API settings") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("AI provider", style = MaterialTheme.typography.labelLarge)
                Box {
                    OutlinedButton(onClick = { showProviders = true }, enabled = !saving) { Text(provider.label) }
                    DropdownMenu(expanded = showProviders, onDismissRequest = { showProviders = false }) {
                        AetherOnlineProvider.entries.forEach { choice ->
                            DropdownMenuItem(text = { Text(choice.label) }, onClick = {
                                showProviders = false
                                if (provider != choice) {
                                    val saved = endpoint?.takeIf { it.provider == choice }
                                    provider = choice
                                    model = saved?.model ?: choice.defaultModel
                                    url = saved?.url.orEmpty()
                                    chatLimit = saved?.chatLimit ?: AetherChatLimit.MAX_TOKENS
                                    apiKey = "" // Don't carry a key over to another provider.
                                }
                            })
                        }
                    }
                }
                when (provider) {
                    AetherOnlineProvider.GEMINI -> Text("Paste a Gemini Developer API key from Google AI Studio. The Google endpoint is set for you.")
                    AetherOnlineProvider.OPENAI -> Text("Use an OpenAI API key and a text model that supports Chat Completions.")
                    AetherOnlineProvider.COMPATIBLE -> Text("Use a trusted HTTPS API with OpenAI-compatible Chat Completions and bearer authentication.")
                }
                if (custom) {
                    OutlinedTextField(
                        value = url,
                        onValueChange = { if (it.length <= AetherOnlineConfig.MAX_ENDPOINT_CHARS) url = it },
                        label = { Text("HTTPS API base URL or full endpoint") },
                        placeholder = { Text("https://api.example.com/v1") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        enabled = !saving,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri)
                    )
                }
                OutlinedTextField(
                    value = model,
                    onValueChange = { if (it.length <= AetherOnlineConfig.MAX_MODEL_CHARS + 7) model = it },
                    label = { Text("Model ID") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    enabled = !saving
                )
                OutlinedTextField(
                    value = apiKey,
                    onValueChange = { if (it.length <= AetherOnlineConfig.MAX_KEY_CHARS) apiKey = it },
                    label = { Text(if (endpoint?.provider == provider) "API key (re-enter to save)" else "API key") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    enabled = !saving,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password)
                )
                if (custom) {
                    TextButton(enabled = !saving, onClick = {
                        chatLimit = if (chatLimit == AetherChatLimit.MAX_TOKENS) AetherChatLimit.MAX_COMPLETION_TOKENS
                            else AetherChatLimit.MAX_TOKENS
                    }) { Text("Output limit: ${chatLimit.parameter}") }
                    Text("Tap to change the limit field only if your provider requires it.", style = MaterialTheme.typography.bodySmall)
                }
                Text("The key is encrypted on this phone. Saving won't contact the provider. You can review the test before sending it.",
                    style = MaterialTheme.typography.bodySmall)
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onSave(AetherOnlineConfig.Input(provider, if (custom) url else "", model, apiKey, chatLimit)) },
                enabled = !saving && (!custom || url.isNotBlank()) && model.isNotBlank() && apiKey.isNotBlank()
            ) { Text(if (saving) "Saving…" else "Save & review test") }
        },
        dismissButton = {
            Row {
                if (endpoint != null) TextButton(onClick = onDisconnect, enabled = !saving) { Text("Disconnect") }
                TextButton(onClick = onDismiss, enabled = !saving) { Text("Cancel") }
            }
        }
    )
}

@Composable
internal fun AetherApiReviewDialog(review: AetherOnlineApproval.Review, onSend: () -> Unit, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(if (review.test) "Test your AI API?" else "Send this request online?") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(review.endpoint.provider.label, style = MaterialTheme.typography.titleSmall)
                Text(review.endpoint.url, style = MaterialTheme.typography.bodySmall)
                Text("Model: ${review.endpoint.model}", style = MaterialTheme.typography.bodySmall)
                Text(review.prompt.text, style = MaterialTheme.typography.titleSmall)
                Text(if (review.test) {
                    "This sends one test request and does not run an audit. Your provider may charge for it."
                } else {
                    "The provider receives this text and task instructions, not your scans or settings. Don’t send passwords or personal details. Your provider may charge for requests."
                })
            }
        },
        confirmButton = { TextButton(onClick = onSend) { Text(if (review.test) "Send test" else "Send") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } }
    )
}
