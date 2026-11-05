package com.adshield.pro.ui.viewmodel

import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.adshield.pro.data.repository.DirectDownloadRepository
import com.adshield.pro.domain.model.DirectDownload
import com.adshield.pro.domain.model.InspectedMedia
import com.adshield.pro.engine.download.DirectMediaInspector
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class DownloaderViewModel @Inject constructor(
    private val inspector: DirectMediaInspector,
    private val repository: DirectDownloadRepository
) : ViewModel() {
    val downloads = repository.downloads
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())
    private val _inspection = MutableStateFlow<InspectedMedia?>(null)
    val inspection = _inspection.asStateFlow()
    private val _busy = MutableStateFlow(false)
    val busy = _busy.asStateFlow()
    private val _message = MutableStateFlow<String?>(null)
    val message = _message.asStateFlow()
    private val _error = MutableStateFlow<String?>(null)
    val error = _error.asStateFlow()
    private val _allowMetered = MutableStateFlow(false)
    val allowMetered = _allowMetered.asStateFlow()
    private var progressJob: Job? = null

    fun inspect(url: String) {
        if (_busy.value) return
        viewModelScope.launch {
            _busy.value = true
            _inspection.value = null
            _error.value = null
            runCatching { inspector.inspect(url) }
                .onSuccess { _inspection.value = it }
                .onFailure { _error.value = it.message ?: "Media inspection failed" }
            _busy.value = false
        }
    }

    fun enqueue(destination: Uri) {
        val media = _inspection.value ?: return
        viewModelScope.launch {
            _busy.value = true
            runCatching { repository.enqueue(media, destination, _allowMetered.value) }
                .onSuccess {
                    _message.value = "Download queued in Android DownloadManager. It continues according to system network and battery policy."
                    _inspection.value = null
                    refresh()
                }
                .onFailure { _error.value = it.message ?: "Could not queue download" }
            _busy.value = false
        }
    }

    fun setAllowMetered(value: Boolean) { _allowMetered.value = value }

    fun cancel(record: DirectDownload) {
        viewModelScope.launch {
            runCatching { repository.cancel(record) }
                .onSuccess { _message.value = "Download cancelled. The destination may contain a partial file." }
                .onFailure { _error.value = it.message }
            refresh()
        }
    }

    fun deleteHistory(record: DirectDownload) {
        viewModelScope.launch {
            runCatching { repository.deleteHistory(record) }
                .onSuccess { _message.value = "History entry removed; the downloaded document was not deleted." }
                .onFailure { _error.value = it.message }
        }
    }

    fun verify(record: DirectDownload, expectedSha256: String?) {
        viewModelScope.launch {
            _busy.value = true
            runCatching { repository.verifyIntegrity(record, expectedSha256) }
                .onSuccess { _message.value = it }
                .onFailure { _error.value = it.message ?: "Integrity check failed" }
            _busy.value = false
        }
    }

    fun refresh() {
        viewModelScope.launch { repository.refreshActive() }
    }

    fun startProgressUpdates() {
        if (progressJob?.isActive == true) return
        progressJob = viewModelScope.launch {
            while (isActive) {
                repository.refreshActive()
                delay(1200)
            }
        }
    }

    fun stopProgressUpdates() {
        progressJob?.cancel()
        progressJob = null
    }

    fun clearMessages() {
        _message.value = null
        _error.value = null
    }

    override fun onCleared() {
        stopProgressUpdates()
        super.onCleared()
    }
}
