package com.adshield.pro.ui.viewmodel

import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.adshield.pro.data.telegram.TelegramCloudSection
import com.adshield.pro.data.telegram.TelegramDuplicateFile
import com.adshield.pro.data.telegram.TelegramStorageRepository
import com.adshield.pro.data.telegram.TelegramStoredFile
import com.adshield.pro.data.telegram.TelegramTargetKind
import com.adshield.pro.data.telegram.TelegramTransfer
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

private data class PendingUpload(
    val uri: String,
    val name: String,
    val mime: String,
    val label: String
)

/**
 * UI state holder for the Telegram provider inside Cloud Storage. All work is delegated to the
 * repository, which sends real TDLib requests; this class never fakes a transfer or a connection.
 */
@HiltViewModel
class TelegramCloudViewModel @Inject constructor(
    private val repository: TelegramStorageRepository
) : ViewModel() {

    val status = repository.status
    val transfers: StateFlow<List<TelegramTransfer>> = repository.transfers
    val allFiles: StateFlow<List<TelegramStoredFile>> = repository.storedFiles
    val message = repository.message
    val error = repository.error
    val busy = repository.busy
    private val _authBusy = MutableStateFlow(true)
    val authBusy: StateFlow<Boolean> = _authBusy

    private val _section = MutableStateFlow(TelegramCloudSection.FILES)
    val section: StateFlow<TelegramCloudSection> = _section
    private val _query = MutableStateFlow("")
    val query: StateFlow<String> = _query
    private val _labelFilter = MutableStateFlow("")
    val labelFilter: StateFlow<String> = _labelFilter
    private val _duplicate = MutableStateFlow<TelegramStoredFile?>(null)
    val duplicate: StateFlow<TelegramStoredFile?> = _duplicate
    private var pendingUpload: PendingUpload? = null

    val files: StateFlow<List<TelegramStoredFile>> = combine(
        repository.storedFiles, _query, _labelFilter
    ) { list, query, label ->
        list.filter { file ->
            (query.isBlank() || file.name.contains(query.trim(), ignoreCase = true) ||
                file.label.contains(query.trim(), ignoreCase = true)) &&
                (label.isBlank() || file.label.equals(label, ignoreCase = true))
        }
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val labels: StateFlow<List<String>> = repository.storedFiles
        .map { list -> list.map { it.label }.filter { it.isNotBlank() }.distinct().sorted() }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    init {
        viewModelScope.launch {
            try {
                repository.initialize()
            } catch (failure: CancellationException) {
                throw failure
            } catch (failure: Exception) {
                repository.reportError(failure.message ?: "Could not restore Telegram session")
            } finally {
                _authBusy.value = false
            }
        }
    }

    fun setSection(section: TelegramCloudSection) { _section.value = section }
    fun setQuery(value: String) { _query.value = value }
    fun setLabelFilter(value: String) { _labelFilter.value = value }
    fun clearMessage() = repository.clearMessage()
    fun clearError() = repository.clearError()
    fun dismissDuplicate() { _duplicate.value = null; pendingUpload = null }

    fun connect(apiIdText: String, apiHash: String, target: TelegramTargetKind) = authAction {
        val apiId = apiIdText.trim().toIntOrNull()
            ?: return@authAction repository.reportError("api_id must be the numeric id from my.telegram.org")
        repository.connect(apiId, apiHash, target)
    }

    fun submitPhoneNumber(phone: String) = authAction { repository.submitPhoneNumber(phone) }
    fun submitCode(code: String) = authAction { repository.submitCode(code) }
    fun submitPassword(password: String) = authAction { repository.submitPassword(password) }
    fun checkAuthorization() = authAction { repository.checkAuthorization() }

    fun disconnect(logOutRemotely: Boolean = true) = authAction {
        repository.disconnect(logOutRemotely)
    }

    fun refresh() = launch { repository.refreshFiles(_query.value.takeIf { it.isNotBlank() }) }

    fun upload(uri: Uri, name: String, mimeType: String, label: String = "", forceDuplicate: Boolean = false) {
        pendingUpload = PendingUpload(uri.toString(), name, mimeType, label)
        launch {
            try {
                repository.upload(uri.toString(), name, mimeType, label, forceDuplicate)
            } catch (duplicate: TelegramDuplicateFile) {
                _duplicate.value = duplicate.existing
            }
        }
    }

    fun uploadAnyway() {
        val pending = pendingUpload ?: return dismissDuplicate()
        _duplicate.value = null
        upload(Uri.parse(pending.uri), pending.name, pending.mime, pending.label, forceDuplicate = true)
    }

    fun download(file: TelegramStoredFile, destination: Uri) = launch {
        repository.download(file, destination.toString())
    }

    fun retry(transferId: String) = launch { repository.retry(transferId) }
    fun cancel(transferId: String) = launch { repository.cancel(transferId) }
    fun setLabel(file: TelegramStoredFile, label: String) = launch { repository.setLabel(file, label) }
    fun delete(file: TelegramStoredFile) = launch { repository.delete(file) }
    fun clearLocalCache() = launch { repository.clearLocalCache() }

    private fun authAction(block: suspend () -> Unit) {
        if (_authBusy.value) return
        _authBusy.value = true
        viewModelScope.launch {
            try {
                block()
            } catch (failure: CancellationException) {
                throw failure
            } catch (failure: Exception) {
                repository.reportError(failure.message ?: "Telegram sign-in failed")
            } finally {
                _authBusy.value = false
            }
        }
    }

    private fun launch(block: suspend () -> Unit) {
        viewModelScope.launch {
            try {
                block()
            } catch (failure: CancellationException) {
                throw failure
            } catch (failure: Exception) {
                repository.reportError(failure.message ?: "Telegram operation failed")
            }
        }
    }
}
