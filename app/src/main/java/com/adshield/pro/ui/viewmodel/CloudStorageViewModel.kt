package com.adshield.pro.ui.viewmodel

import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.adshield.pro.data.repository.CloudStorageRepository
import com.adshield.pro.domain.model.CloudObject
import com.adshield.pro.domain.model.CloudOperationState
import com.adshield.pro.domain.model.CloudPreview
import com.adshield.pro.domain.model.InfinityCapacityCalculator
import com.adshield.pro.domain.model.StorageProvider
import com.adshield.pro.domain.model.StorageProviderHealth
import com.adshield.pro.domain.model.StorageProviderKind
import com.adshield.pro.domain.model.VerifiedStorageCapacity
import com.adshield.pro.engine.storage.WebDavPath
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class CloudStorageViewModel @Inject constructor(
    private val repository: CloudStorageRepository
) : ViewModel() {
    val providers: StateFlow<List<StorageProvider>> = repository.providers
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val capacity: StateFlow<VerifiedStorageCapacity> = repository.providers
        .map(InfinityCapacityCalculator::aggregate)
        .stateIn(
            viewModelScope,
            SharingStarted.WhileSubscribed(5000),
            InfinityCapacityCalculator.aggregate(emptyList())
        )

    private val _selectedProviderId = MutableStateFlow<String?>(null)
    val selectedProviderId = _selectedProviderId.asStateFlow()
    private val _currentPath = MutableStateFlow("")
    val currentPath = _currentPath.asStateFlow()
    private val _objects = MutableStateFlow<List<CloudObject>>(emptyList())
    val objects = _objects.asStateFlow()
    private val _searchQuery = MutableStateFlow("")
    val searchQuery = _searchQuery.asStateFlow()
    private val _operation = MutableStateFlow(CloudOperationState())
    val operation = _operation.asStateFlow()
    private val _shareLink = MutableStateFlow<String?>(null)
    val shareLink = _shareLink.asStateFlow()
    private val _preview = MutableStateFlow<CloudPreview?>(null)
    val preview = _preview.asStateFlow()

    fun selectProvider(id: String) {
        _selectedProviderId.value = id
        _currentPath.value = ""
        _searchQuery.value = ""
        _shareLink.value = null
        refresh()
    }

    fun closeProvider() {
        _selectedProviderId.value = null
        _objects.value = emptyList()
        _operation.value = CloudOperationState()
        _shareLink.value = null
    }

    fun setSearchQuery(value: String) { _searchQuery.value = value }

    fun registerProvider(
        name: String,
        kind: StorageProviderKind,
        baseUrl: String,
        username: String,
        password: String
    ) {
        viewModelScope.launch {
            _operation.value = CloudOperationState(running = true, indeterminate = true, label = "Verifying server and quota…")
            runCatching { repository.registerProvider(name, kind, baseUrl, username, password) }
                .onSuccess { provider ->
                    if (provider.health == StorageProviderHealth.ONLINE) {
                        _operation.value = CloudOperationState(label = "Connected and verified ${provider.name}")
                        selectProvider(provider.id)
                    } else {
                        _operation.value = CloudOperationState(error = provider.lastError ?: "Server could not be verified")
                    }
                }
                .onFailure { _operation.value = CloudOperationState(error = it.message ?: "Registration failed") }
        }
    }

    fun removeProvider(id: String) {
        viewModelScope.launch {
            runCatching { repository.removeProvider(id) }
                .onSuccess { if (_selectedProviderId.value == id) closeProvider() }
                .onFailure { _operation.value = CloudOperationState(error = it.message) }
        }
    }

    fun checkProvider(id: String) {
        viewModelScope.launch {
            _operation.value = CloudOperationState(running = true, indeterminate = true, label = "Checking server health and capacity…")
            runCatching { repository.checkProvider(id) }
                .onSuccess { provider ->
                    _operation.value = if (provider.health == StorageProviderHealth.ONLINE) {
                        if (provider.totalBytes == null) {
                            CloudOperationState(label = "Server online; DAV quota was not reported, so its capacity is not counted")
                        } else {
                            CloudOperationState(label = "Server online; quota response verified")
                        }
                    } else {
                        CloudOperationState(error = provider.lastError)
                    }
                }
                .onFailure { _operation.value = CloudOperationState(error = it.message) }
        }
    }

    fun refresh() {
        val providerId = _selectedProviderId.value ?: return
        viewModelScope.launch {
            _operation.value = CloudOperationState(running = true, indeterminate = true, label = "Reading remote folder…")
            runCatching { repository.list(providerId, _currentPath.value) }
                .onSuccess { listing ->
                    _objects.value = listing.objects
                    _operation.value = CloudOperationState(label = "Remote folder updated")
                }
                .onFailure { _operation.value = CloudOperationState(error = it.message ?: "Remote folder failed") }
        }
    }

    fun openFolder(folder: CloudObject) {
        if (!folder.isDirectory) return
        _currentPath.value = folder.path
        refresh()
    }

    fun goToParent() {
        if (_currentPath.value.isEmpty()) return
        _currentPath.value = WebDavPath.parent(_currentPath.value)
        refresh()
    }

    fun goToPath(path: String) {
        _currentPath.value = WebDavPath.normalize(path)
        refresh()
    }

    fun createFolder(name: String) = runMutation("Creating folder…") { providerId ->
        repository.createFolder(providerId, _currentPath.value, name)
    }

    fun rename(item: CloudObject, newName: String) = runMutation("Renaming remote item…") { providerId ->
        repository.rename(providerId, item.path, item.isDirectory, newName)
    }

    fun delete(item: CloudObject) = runMutation("Deleting remote item…") { providerId ->
        repository.delete(providerId, item.path, item.isDirectory)
    }

    fun upload(source: Uri, name: String, mimeType: String, sizeBytes: Long) {
        val providerId = _selectedProviderId.value ?: return
        viewModelScope.launch {
            _operation.value = CloudOperationState(
                running = true, totalBytes = sizeBytes.takeIf { it >= 0 }, label = "Uploading $name…"
            )
            runCatching {
                repository.upload(providerId, _currentPath.value, name, mimeType, source, sizeBytes) { done ->
                    _operation.value = _operation.value.copy(completedBytes = done)
                }
            }.onSuccess {
                _operation.value = CloudOperationState(label = "Upload completed; refreshing remote metadata…")
                refresh()
            }.onFailure {
                _operation.value = CloudOperationState(error = it.message ?: "Upload failed")
            }
        }
    }

    fun download(item: CloudObject, destination: Uri) {
        val providerId = _selectedProviderId.value ?: return
        viewModelScope.launch {
            _operation.value = CloudOperationState(
                running = true, totalBytes = item.sizeBytes, label = "Downloading ${item.name}…"
            )
            runCatching {
                repository.download(providerId, item.path, destination) { done ->
                    _operation.value = _operation.value.copy(completedBytes = done)
                }
            }.onSuccess { result ->
                _operation.value = CloudOperationState(
                    completedBytes = result.bytesWritten,
                    totalBytes = item.sizeBytes,
                    label = "Download completed: ${result.bytesWritten} bytes; SHA-256 ${result.sha256}"
                )
            }.onFailure {
                _operation.value = CloudOperationState(error = it.message ?: "Download failed")
            }
        }
    }

    fun preview(item: CloudObject) {
        val providerId = _selectedProviderId.value ?: return
        viewModelScope.launch {
            _operation.value = CloudOperationState(running = true, totalBytes = item.sizeBytes, label = "Preparing ${item.name} for preview…")
            runCatching {
                repository.preview(providerId, item) { done ->
                    _operation.value = _operation.value.copy(completedBytes = done)
                }
            }.onSuccess {
                _preview.value = it
                _operation.value = CloudOperationState(label = "Preview downloaded; SHA-256 ${it.sha256}")
            }.onFailure {
                _operation.value = CloudOperationState(error = it.message ?: "Preview failed")
            }
        }
    }

    fun clearPreview() { _preview.value = null }

    fun createPublicShare(item: CloudObject) {
        val providerId = _selectedProviderId.value ?: return
        viewModelScope.launch {
            _operation.value = CloudOperationState(running = true, indeterminate = true, label = "Creating Nextcloud public link…")
            runCatching { repository.createPublicShare(providerId, item.path) }
                .onSuccess {
                    _shareLink.value = it
                    _operation.value = CloudOperationState(label = "Public link created. Anyone with the link may access it.")
                }
                .onFailure { _operation.value = CloudOperationState(error = it.message ?: "Sharing failed") }
        }
    }

    fun clearShareLink() { _shareLink.value = null }
    fun clearOperationMessage() {
        if (!_operation.value.running) _operation.value = CloudOperationState()
    }

    private fun runMutation(label: String, block: suspend (String) -> Unit) {
        val providerId = _selectedProviderId.value ?: return
        viewModelScope.launch {
            _operation.value = CloudOperationState(running = true, indeterminate = true, label = label)
            runCatching { block(providerId) }
                .onSuccess { refresh() }
                .onFailure { _operation.value = CloudOperationState(error = it.message ?: "Remote operation failed") }
        }
    }
}
