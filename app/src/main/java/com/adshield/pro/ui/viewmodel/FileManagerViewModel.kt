package com.adshield.pro.ui.viewmodel

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.adshield.pro.data.repository.SafFileRepository
import com.adshield.pro.domain.model.DuplicateFileGroup
import com.adshield.pro.domain.model.FileScanProgress
import com.adshield.pro.domain.model.ManagedFile
import com.adshield.pro.domain.model.ManagedFileListing
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.inject.Inject

@HiltViewModel
class FileManagerViewModel @Inject constructor(
    @ApplicationContext private val context: Context,
    private val repository: SafFileRepository
) : ViewModel() {
    private val stateStore = context.getSharedPreferences("infinity_file_manager", Context.MODE_PRIVATE)
    private val _listing = MutableStateFlow<ManagedFileListing?>(null)
    val listing = _listing.asStateFlow()
    private val _canGoBack = MutableStateFlow(false)
    val canGoBack = _canGoBack.asStateFlow()
    private val _busy = MutableStateFlow(false)
    val busy = _busy.asStateFlow()
    private val _message = MutableStateFlow<String?>(null)
    val message = _message.asStateFlow()
    private val _error = MutableStateFlow<String?>(null)
    val error = _error.asStateFlow()
    private val _query = MutableStateFlow("")
    val query = _query.asStateFlow()
    private val _scanProgress = MutableStateFlow(FileScanProgress())
    val scanProgress = _scanProgress.asStateFlow()
    private val _duplicates = MutableStateFlow<List<DuplicateFileGroup>>(emptyList())
    val duplicates = _duplicates.asStateFlow()
    private val folderStack = ArrayList<String>()

    init {
        stateStore.getString("tree_uri", null)?.let { saved ->
            runCatching { Uri.parse(saved) }.getOrNull()?.let { tree ->
                viewModelScope.launch {
                    runCatching { repository.list(tree) }
                        .onSuccess {
                            _listing.value = it
                            folderStack.add(it.documentId)
                            _canGoBack.value = false
                        }
                }
            }
        }
    }

    fun openTree(tree: Uri) {
        runCatching {
            context.contentResolver.takePersistableUriPermission(
                tree,
                Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
            )
        }
        stateStore.edit().putString("tree_uri", tree.toString()).apply()
        folderStack.clear()
        _canGoBack.value = false
        viewModelScope.launch {
            _busy.value = true
            runCatching { repository.list(tree) }
                .onSuccess {
                    _listing.value = it
                    folderStack.add(it.documentId)
                    _error.value = null
                }
                .onFailure { _error.value = it.message ?: "Cannot open the selected storage tree" }
            _busy.value = false
        }
    }

    fun refresh() {
        val current = _listing.value ?: return
        viewModelScope.launch {
            _busy.value = true
            runCatching { repository.list(Uri.parse(current.treeUri), current.documentId) }
                .onSuccess { _listing.value = it; _error.value = null }
                .onFailure { _error.value = it.message }
            _busy.value = false
        }
    }

    fun openFolder(folder: ManagedFile) {
        if (!folder.isDirectory) return
        val current = _listing.value ?: return
        viewModelScope.launch {
            _busy.value = true
            runCatching { repository.list(Uri.parse(current.treeUri), folder.documentId) }
                .onSuccess {
                    folderStack.add(it.documentId)
                    _canGoBack.value = true
                    _listing.value = it
                    _query.value = ""
                }
                .onFailure { _error.value = it.message }
            _busy.value = false
        }
    }

    fun goBack(): Boolean {
        if (folderStack.size <= 1) return false
        folderStack.removeAt(folderStack.lastIndex)
        _canGoBack.value = folderStack.size > 1
        val current = _listing.value ?: return false
        val parentId = folderStack.last()
        viewModelScope.launch {
            runCatching { repository.list(Uri.parse(current.treeUri), parentId) }
                .onSuccess { _listing.value = it }
                .onFailure { _error.value = it.message }
        }
        return true
    }

    fun setQuery(value: String) { _query.value = value }

    fun createFolder(name: String) = mutate("Folder created") { tree, current ->
        repository.createFolder(tree, current.documentId, name)
    }

    fun rename(file: ManagedFile, name: String) = mutate("Item renamed") { tree, _ ->
        repository.rename(tree, file, name)
    }

    fun delete(file: ManagedFile) = mutate("Item deleted") { _, _ ->
        repository.delete(file)
    }

    fun importDocument(source: Uri, name: String, mimeType: String) = mutate("Import completed") { tree, current ->
        repository.importDocument(tree, current.documentId, source, name, mimeType)
    }

    fun scanTree() {
        val current = _listing.value ?: return
        if (_scanProgress.value.running) return
        viewModelScope.launch {
            _scanProgress.value = FileScanProgress(running = true)
            _error.value = null
            runCatching {
                repository.scanTree(Uri.parse(current.treeUri), current.documentId) { progress ->
                    _scanProgress.value = progress
                }
            }.onSuccess { result ->
                _scanProgress.value = _scanProgress.value.copy(running = false, scanned = result.records.size, skipped = result.skipped, errors = result.errors, limitReached = result.limitReached)
                _message.value = "Security scan finished: ${result.records.size} scanned, ${result.skipped} individually skipped, ${result.errors} errors." +
                    (if (result.limitReached) " The 250-file scan bound was reached; the tree was not fully scanned. " else " ") +
                    "Reports are saved in Security → History."
            }.onFailure {
                _scanProgress.value = _scanProgress.value.copy(running = false)
                _error.value = it.message ?: "Folder scan failed"
            }
        }
    }

    fun findDuplicates() {
        val current = _listing.value ?: return
        viewModelScope.launch {
            _busy.value = true
            _duplicates.value = emptyList()
            runCatching { repository.findDuplicates(Uri.parse(current.treeUri), current.documentId) }
                .onSuccess { groups ->
                    _duplicates.value = groups
                    _message.value = if (groups.isEmpty()) {
                        "No duplicate content found among same-size candidates within the 250-file bound."
                    } else {
                        "Found ${groups.size} duplicate-content group(s). Nothing was deleted."
                    }
                }
                .onFailure { _error.value = it.message ?: "Duplicate scan failed" }
            _busy.value = false
        }
    }

    fun clearMessages() {
        _message.value = null
        _error.value = null
    }

    private fun mutate(successMessage: String, block: suspend (Uri, ManagedFileListing) -> Unit) {
        val current = _listing.value ?: return
        val tree = Uri.parse(current.treeUri)
        viewModelScope.launch {
            _busy.value = true
            runCatching {
                block(tree, current)
                withContext(Dispatchers.IO) { repository.list(tree, current.documentId) }
            }
                .onSuccess { updated ->
                    _message.value = successMessage
                    _listing.value = updated
                }
                .onFailure { _error.value = it.message ?: "File operation failed" }
            _busy.value = false
        }
    }
}
