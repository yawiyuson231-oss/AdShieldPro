package com.adshield.pro.ui.viewmodel

import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.adshield.pro.cloud.AuthSession
import com.adshield.pro.cloud.CloudRepository
import com.adshield.pro.cloud.QuotaInfo
import com.adshield.pro.cloud.QuotaManager
import com.adshield.pro.cloud.ShareLink
import com.adshield.pro.data.local.db.CloudDnsBackupEntity
import com.adshield.pro.data.local.db.CloudFileEntity
import com.adshield.pro.data.local.db.CloudTransferEntity
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class CloudViewModel @Inject constructor(
    private val repository: CloudRepository
) : ViewModel() {

    val session: StateFlow<AuthSession?> = repository.sessionFlow
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), null)

    val apiBaseUrl: StateFlow<String> = repository.apiBaseUrlFlow
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), "")

    val files: StateFlow<List<CloudFileEntity>> = repository.filesFlow("/")
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val transfers: StateFlow<List<CloudTransferEntity>> = repository.transfers
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val dnsBackups: StateFlow<List<CloudDnsBackupEntity>> = repository.dnsBackups
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val quota = MutableStateFlow<QuotaInfo?>(null)
    val shares = MutableStateFlow<List<ShareLink>>(emptyList())
    val message = MutableStateFlow<String?>(null)

    /** Derived quota state — never invented: UNKNOWN until the server answered. */
    val quotaState: StateFlow<QuotaManager.QuotaState> = quota
        .map { info ->
            if (info == null) QuotaManager.QuotaState.UNKNOWN
            else QuotaManager.stateFor(info.usedBytes, info.quotaBytes)
        }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), QuotaManager.QuotaState.UNKNOWN)

    fun refreshAll() {
        viewModelScope.launch {
            refreshQuota()
            refreshFiles()
            refreshShares()
        }
    }

    fun refreshQuota() = viewModelScope.launch {
        repository.quota().onSuccess { quota.value = it }.onFailure { message.value = it.message }
    }

    fun refreshFiles() = viewModelScope.launch {
        repository.refreshFiles().onFailure { message.value = it.message }
    }

    fun refreshShares() = viewModelScope.launch {
        repository.listShares().onSuccess { shares.value = it }.onFailure { message.value = it.message }
    }

    fun signUp(email: String, password: String) = viewModelScope.launch {
        repository.signUp(email, password)
            .onSuccess { message.value = "Account created. Signed in as ${it.email}." }
            .onFailure { message.value = it.message }
    }

    fun signIn(email: String, password: String) = viewModelScope.launch {
        repository.signIn(email, password)
            .onSuccess { message.value = "Signed in as ${it.email}." }
            .onFailure { message.value = it.message }
    }

    fun signOut() = viewModelScope.launch { repository.signOut() }

    fun setApiBaseUrl(url: String) = viewModelScope.launch {
        repository.setApiBaseUrl(url)
            .onSuccess { message.value = "Cloud backend URL saved." }
            .onFailure { message.value = it.message }
    }

    fun upload(uri: Uri, displayName: String, folder: String) = viewModelScope.launch {
        repository.enqueueUpload(uri, displayName, folder)
            .onSuccess { result ->
                message.value = if (result.startsWith("duplicate:"))
                    "Duplicate detected — file already in your cloud (${result.substringAfterLast(':')})."
                else "Upload queued: $displayName"
            }
            .onFailure { message.value = it.message }
    }

    fun download(fileId: String, name: String, dest: Uri) = viewModelScope.launch {
        repository.enqueueDownload(fileId, name, dest)
            .onSuccess { message.value = "Download queued: $name" }
            .onFailure { message.value = it.message }
    }

    fun pause(id: String) = viewModelScope.launch { repository.pauseTransfer(id) }
    fun resume(id: String) = viewModelScope.launch { repository.resumeTransfer(id) }
    fun cancel(id: String) = viewModelScope.launch { repository.cancelTransfer(id) }

    fun createFolder(path: String) = viewModelScope.launch {
        repository.createFolder(path).onSuccess { refreshFiles() }.onFailure { message.value = it.message }
    }

    fun rename(id: String, name: String) = viewModelScope.launch {
        repository.renameFile(id, name).onSuccess { refreshFiles() }.onFailure { message.value = it.message }
    }

    fun move(id: String, folder: String) = viewModelScope.launch {
        repository.moveFile(id, folder).onSuccess { refreshFiles() }.onFailure { message.value = it.message }
    }

    fun copy(id: String, folder: String) = viewModelScope.launch {
        repository.copyFile(id, folder).onSuccess { refreshFiles() }.onFailure { message.value = it.message }
    }

    fun delete(id: String, permanent: Boolean) = viewModelScope.launch {
        repository.deleteFile(id, permanent).onSuccess { refreshFiles() }.onFailure { message.value = it.message }
    }

    fun restore(id: String) = viewModelScope.launch {
        repository.restoreFile(id).onSuccess { refreshFiles() }.onFailure { message.value = it.message }
    }

    fun share(id: String, ttlHours: Int, maxDownloads: Int) = viewModelScope.launch {
        repository.shareFile(id, ttlHours, maxDownloads)
            .onSuccess { message.value = "Expiring share link created (${it.expiresAtEpochMs / 3600000 / 1000}h TTL)." }
            .onFailure { message.value = it.message }
    }

    fun backupDnsConfig(label: String) = viewModelScope.launch {
        repository.backupDnsConfig(label)
            .onSuccess { message.value = "DNS configuration backed up to cloud (${it.sha256.take(12)}…)." }
            .onFailure { message.value = it.message }
    }

    fun restoreDnsBackup(id: String) = viewModelScope.launch {
        repository.restoreDnsBackup(id)
            .onSuccess { message.value = "DNS configuration restored from cloud ($it rules merged)." }
            .onFailure { message.value = it.message }
    }

    fun clearMessage() { message.value = null }

}
