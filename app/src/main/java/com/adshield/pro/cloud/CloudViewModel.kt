package com.adshield.pro.cloud

import android.content.Context
import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.adshield.pro.cloud.backup.DnsBackupManager
import com.adshield.pro.cloud.backup.RestoreReport
import com.adshield.pro.cloud.data.CloudAccountDto
import com.adshield.pro.cloud.data.CloudApiClient
import com.adshield.pro.cloud.data.CloudAuditEntity
import com.adshield.pro.cloud.data.CloudBackupDto
import com.adshield.pro.cloud.data.CloudBackupEntity
import com.adshield.pro.cloud.data.CloudConfig
import com.adshield.pro.cloud.data.CloudConfigRepository
import com.adshield.pro.cloud.data.CloudDao
import com.adshield.pro.cloud.data.CloudFileEntity
import com.adshield.pro.cloud.data.CloudHealthDto
import com.adshield.pro.cloud.data.CloudMetaDto
import com.adshield.pro.cloud.data.CloudNodeDto
import com.adshield.pro.cloud.data.CloudQuotaDto
import com.adshield.pro.cloud.data.CloudResult
import com.adshield.pro.cloud.data.CloudSecurityDto
import com.adshield.pro.cloud.data.CloudSession
import com.adshield.pro.cloud.data.CloudSessionStore
import com.adshield.pro.cloud.data.CloudShareDto
import com.adshield.pro.cloud.data.CloudShareEntity
import com.adshield.pro.cloud.data.CloudStatsDto
import com.adshield.pro.cloud.data.CloudTransferEntity
import com.adshield.pro.cloud.data.CloudVersionDto
import com.adshield.pro.cloud.engine.CloudDownloadEngine
import com.adshield.pro.cloud.engine.CloudUploadEngine
import com.adshield.pro.cloud.engine.PickResult
import com.adshield.pro.cloud.engine.TransferRegistry
import com.adshield.pro.cloud.work.CloudAutoBackupWorker
import com.adshield.pro.cloud.work.CloudDownloadWorker
import com.adshield.pro.cloud.work.CloudUploadWorker
import com.adshield.pro.cloud.work.enqueueManualBackup
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.inject.Inject

enum class CloudSection(val title: String) {
    OVERVIEW("Overview"),
    FILES("My Files"),
    PHOTOS("Photos"),
    VIDEOS("Videos"),
    DOCUMENTS("Documents"),
    BACKUPS("Backups"),
    SHARED("Shared"),
    UPLOADS("Uploads"),
    SECURITY("Security"),
    SETTINGS("Settings")
}

enum class CloudConnectionState { UNCONFIGURED, OFFLINE, AUTH_REQUIRED, DEGRADED, ONLINE }

data class CloudUiState(
    val config: CloudConfig = CloudConfig(),
    val session: CloudSession? = null,
    val connection: CloudConnectionState = CloudConnectionState.UNCONFIGURED,
    val health: CloudHealthDto? = null,
    val meta: CloudMetaDto? = null,
    val account: CloudAccountDto? = null,
    val stats: CloudStatsDto? = null,
    val security: CloudSecurityDto? = null,
    val files: List<CloudNodeDto> = emptyList(),
    val folderPath: List<Pair<String, String>> = emptyList(),
    val currentFolderId: String? = null,
    val searchQuery: String = "",
    val searchResults: List<CloudNodeDto> = emptyList(),
    val backups: List<CloudBackupDto> = emptyList(),
    val shares: List<CloudShareDto> = emptyList(),
    val audit: List<CloudAuditEntity> = emptyList(),
    val transfers: List<CloudTransferEntity> = emptyList(),
    val isLoading: Boolean = false,
    val isSigningIn: Boolean = false,
    val message: String? = null,
    val lastError: String? = null
) {
    val quota: CloudQuotaDto get() = account?.quota ?: CloudQuotaDto()
    val isSignedIn: Boolean get() = session != null
}

@HiltViewModel
class CloudViewModel @Inject constructor(
    @ApplicationContext private val context: Context,
    private val api: CloudApiClient,
    private val sessionStore: CloudSessionStore,
    private val configRepository: CloudConfigRepository,
    private val dao: CloudDao,
    private val uploadEngine: CloudUploadEngine,
    private val downloadEngine: CloudDownloadEngine,
    private val backupManager: DnsBackupManager
) : ViewModel() {

    private val _ui = MutableStateFlow(CloudUiState())
    val ui: StateFlow<CloudUiState> = _ui.asStateFlow()

    private var currentSection: CloudSection = CloudSection.OVERVIEW

    val sessionFlow: StateFlow<CloudSession?> = sessionStore.sessionFlow
        .stateIn(viewModelScope, SharingStarted.Eagerly, sessionStore.current())

    init {
        viewModelScope.launch {
            configRepository.configFlow.collect { config ->
                _ui.value = _ui.value.copy(
                    config = config,
                    connection = if (!config.isConfigured) CloudConnectionState.UNCONFIGURED else _ui.value.connection
                )
                if (config.isConfigured) refreshAll(showsSpinner = false)
            }
        }
        viewModelScope.launch {
            sessionStore.sessionFlow.collect { session ->
                _ui.value = _ui.value.copy(session = session)
            }
        }
        viewModelScope.launch {
            refreshTransfers()
        }
    }

    fun setSection(section: CloudSection) {
        currentSection = section
        viewModelScope.launch {
            when (section) {
                CloudSection.PHOTOS -> loadCategory("photos")
                CloudSection.VIDEOS -> loadCategory("videos")
                CloudSection.DOCUMENTS -> loadCategory("documents")
                CloudSection.FILES -> loadFolder(_ui.value.currentFolderId)
                else -> Unit
            }
        }
    }

    // ------------------------------------------------------------------ connection
    fun refreshAll(showsSpinner: Boolean = true) {
        viewModelScope.launch {
            val config = configRepository.snapshot()
            if (!config.isConfigured) {
                _ui.value = _ui.value.copy(connection = CloudConnectionState.UNCONFIGURED, isLoading = false)
                return@launch
            }
            if (showsSpinner) _ui.value = _ui.value.copy(isLoading = true)

            when (val health = api.health()) {
                is CloudResult.Success -> {
                    val meta = api.meta()
                    val online = health.value.status == "ok"
                    _ui.value = _ui.value.copy(
                        health = health.value,
                        meta = (meta as? CloudResult.Success)?.value ?: _ui.value.meta,
                        connection = when {
                            sessionStore.current() == null -> CloudConnectionState.AUTH_REQUIRED
                            online -> CloudConnectionState.ONLINE
                            else -> CloudConnectionState.DEGRADED
                        }
                    )
                }
                is CloudResult.Failure -> {
                    _ui.value = _ui.value.copy(
                        connection = if (sessionStore.current() == null) {
                            CloudConnectionState.AUTH_REQUIRED
                        } else {
                            CloudConnectionState.OFFLINE
                        },
                        lastError = health.message
                    )
                }
                else -> _ui.value = _ui.value.copy(connection = CloudConnectionState.UNCONFIGURED)
            }

            if (sessionStore.current() != null) {
                loadAccount()
                loadFolder(_ui.value.currentFolderId)
                loadBackups()
                loadShares()
                loadSecurity()
                loadAudit()
            }
            _ui.value = _ui.value.copy(isLoading = false)
        }
    }

    fun refresh() = refreshAll()

    private suspend fun loadAccount() {
        when (val result = api.account()) {
            is CloudResult.Success -> _ui.value = _ui.value.copy(account = result.value, lastError = null)
            is CloudResult.Failure -> _ui.value = _ui.value.copy(lastError = result.message)
            CloudResult.NotAuthenticated -> _ui.value =
                _ui.value.copy(connection = CloudConnectionState.AUTH_REQUIRED)
            CloudResult.NotConfigured -> _ui.value =
                _ui.value.copy(connection = CloudConnectionState.UNCONFIGURED)
        }
        when (val stats = api.stats()) {
            is CloudResult.Success -> _ui.value = _ui.value.copy(stats = stats.value)
            else -> Unit
        }
    }

    // ------------------------------------------------------------------ auth
    fun signIn(email: String, password: String) {
        viewModelScope.launch {
            _ui.value = _ui.value.copy(isSigningIn = true, lastError = null)
            when (val result = api.signIn(email.trim(), password)) {
                is CloudResult.Success -> {
                    _ui.value = _ui.value.copy(
                        isSigningIn = false,
                        message = "Signed in as ${result.value.email}",
                        connection = CloudConnectionState.ONLINE
                    )
                    refreshAll(showsSpinner = false)
                }
                is CloudResult.Failure -> _ui.value =
                    _ui.value.copy(isSigningIn = false, lastError = result.message)
                CloudResult.NotConfigured -> _ui.value = _ui.value.copy(
                    isSigningIn = false,
                    lastError = "Set your cloud deployment URL first (Settings)"
                )
                CloudResult.NotAuthenticated -> _ui.value =
                    _ui.value.copy(isSigningIn = false, lastError = "Sign-in failed")
            }
        }
    }

    fun register(email: String, password: String, displayName: String, turnstileToken: String?) {
        viewModelScope.launch {
            _ui.value = _ui.value.copy(isSigningIn = true, lastError = null)
            when (val result = api.register(email.trim(), password, displayName.ifBlank { null }, turnstileToken)) {
                is CloudResult.Success -> _ui.value = _ui.value.copy(
                    isSigningIn = false,
                    message = result.value
                )
                is CloudResult.Failure -> _ui.value = _ui.value.copy(isSigningIn = false, lastError = result.message)
                else -> _ui.value = _ui.value.copy(isSigningIn = false, lastError = "Registration unavailable")
            }
        }
    }

    fun requestRecovery(email: String, turnstileToken: String?) {
        viewModelScope.launch {
            when (val result = api.requestPasswordRecovery(email.trim(), turnstileToken)) {
                is CloudResult.Success -> _ui.value = _ui.value.copy(message = result.value)
                is CloudResult.Failure -> _ui.value = _ui.value.copy(lastError = result.message)
                else -> _ui.value = _ui.value.copy(lastError = "Recovery unavailable")
            }
        }
    }

    fun signOut() {
        api.signOut()
        viewModelScope.launch {
            dao.clearFiles()
            _ui.value = _ui.value.copy(
                session = null,
                account = null,
                files = emptyList(),
                stats = null,
                security = null,
                backups = emptyList(),
                shares = emptyList(),
                connection = CloudConnectionState.AUTH_REQUIRED,
                message = "Signed out. Local DNS protection is unaffected."
            )
        }
    }

    fun updateDeployment(apiUrl: String, supabaseUrl: String, anonKey: String) {
        viewModelScope.launch {
            val validationError = api.validateBaseUrl(apiUrl)
            if (validationError != null && apiUrl.isNotBlank()) {
                _ui.value = _ui.value.copy(lastError = validationError)
                return@launch
            }
            configRepository.updateDeployment(apiUrl, supabaseUrl, anonKey)
            _ui.value = _ui.value.copy(message = "Cloud deployment saved")
            refreshAll(showsSpinner = false)
        }
    }

    // ------------------------------------------------------------------ browsing
    fun openFolder(node: CloudNodeDto) {
        if (!node.isFolder) return
        val path = _ui.value.folderPath + (node.id to node.name)
        viewModelScope.launch {
            _ui.value = _ui.value.copy(folderPath = path, currentFolderId = node.id, searchResults = emptyList())
            loadFolder(node.id)
        }
    }

    fun navigateUp(): Boolean {
        val path = _ui.value.folderPath
        if (path.isEmpty()) return false
        val parent = path.dropLast(1)
        val parentId = parent.lastOrNull()?.first
        viewModelScope.launch {
            _ui.value = _ui.value.copy(folderPath = parent, currentFolderId = parentId)
            loadFolder(parentId)
        }
        return true
    }

    fun breadcrumbTo(index: Int) {
        val path = _ui.value.folderPath
        if (index >= path.size) return
        val trimmed = path.take(index + 1)
        viewModelScope.launch {
            _ui.value = _ui.value.copy(folderPath = trimmed, currentFolderId = trimmed.last().first)
            loadFolder(trimmed.last().first)
        }
    }

    fun loadFolder(parentId: String?) {
        viewModelScope.launch {
            _ui.value = _ui.value.copy(isLoading = true)
            when (val result = api.listFiles(parentId = parentId)) {
                is CloudResult.Success -> {
                    _ui.value = _ui.value.copy(files = result.value.items, isLoading = false)
                    cacheFiles(result.value.items)
                }
                is CloudResult.Failure -> _ui.value = _ui.value.copy(isLoading = false, lastError = result.message)
                else -> _ui.value = _ui.value.copy(isLoading = false)
            }
        }
    }

    private fun loadCategory(category: String) {
        viewModelScope.launch {
            _ui.value = _ui.value.copy(isLoading = true, folderPath = emptyList(), currentFolderId = null)
            when (val result = api.listFiles(parentId = null, category = category, limit = 100)) {
                is CloudResult.Success -> {
                    _ui.value = _ui.value.copy(files = result.value.items, isLoading = false)
                    cacheFiles(result.value.items)
                }
                is CloudResult.Failure -> _ui.value = _ui.value.copy(isLoading = false, lastError = result.message)
                else -> _ui.value = _ui.value.copy(isLoading = false)
            }
        }
    }

    fun search(query: String) {
        _ui.value = _ui.value.copy(searchQuery = query)
        if (query.isBlank()) {
            _ui.value = _ui.value.copy(searchResults = emptyList())
            return
        }
        viewModelScope.launch {
            when (val result = api.search(query)) {
                is CloudResult.Success -> _ui.value = _ui.value.copy(searchResults = result.value.items)
                is CloudResult.Failure -> _ui.value = _ui.value.copy(lastError = result.message)
                else -> Unit
            }
        }
    }

    private suspend fun cacheFiles(nodes: List<CloudNodeDto>) {
        val now = System.currentTimeMillis()
        dao.upsertFiles(
            nodes.map { node ->
                CloudFileEntity(
                    id = node.id,
                    parentId = node.parentId,
                    name = node.name,
                    kind = node.kind,
                    mime = node.mime,
                    size = node.size,
                    sha256 = node.sha256,
                    version = node.version,
                    status = node.status,
                    scanStatus = node.scanStatus,
                    scanDetail = node.scanDetail,
                    encrypted = node.encrypted,
                    updatedAt = node.updatedAt,
                    cachedAt = now
                )
            }
        )
    }

    // ------------------------------------------------------------------ file actions
    fun createFolder(name: String) {
        viewModelScope.launch {
            when (val result = api.createFolder(name, _ui.value.currentFolderId)) {
                is CloudResult.Success -> {
                    _ui.value = _ui.value.copy(message = "Folder created")
                    loadFolder(_ui.value.currentFolderId)
                }
                is CloudResult.Failure -> _ui.value = _ui.value.copy(lastError = result.message)
                else -> Unit
            }
        }
    }

    fun rename(node: CloudNodeDto, name: String) = mutate("Renamed") { api.rename(node.id, name) }

    fun move(node: CloudNodeDto, targetFolderId: String?) = mutate("Moved") { api.move(node.id, targetFolderId) }

    fun copy(node: CloudNodeDto) = mutate("Copied") { api.copy(node, _ui.value.currentFolderId) }

    fun trash(node: CloudNodeDto) {
        viewModelScope.launch {
            when (val result = api.trash(node.id)) {
                is CloudResult.Success -> {
                    _ui.value = _ui.value.copy(message = "Moved to trash (recoverable for ${"30"} days)")
                    loadFolder(_ui.value.currentFolderId)
                    loadAccount()
                }
                is CloudResult.Failure -> _ui.value = _ui.value.copy(lastError = result.message)
                else -> Unit
            }
        }
    }

    fun restore(node: CloudNodeDto) {
        viewModelScope.launch {
            when (val result = api.restore(node.id)) {
                is CloudResult.Success -> {
                    _ui.value = _ui.value.copy(message = "Restored")
                    loadFolder(_ui.value.currentFolderId)
                    loadAccount()
                }
                is CloudResult.Failure -> _ui.value = _ui.value.copy(lastError = result.message)
                else -> Unit
            }
        }
    }

    fun purge(node: CloudNodeDto) {
        viewModelScope.launch {
            when (val result = api.purge(node.id)) {
                is CloudResult.Success -> {
                    _ui.value = _ui.value.copy(message = "Deleted permanently")
                    loadAccount()
                }
                is CloudResult.Failure -> _ui.value = _ui.value.copy(lastError = result.message)
                else -> Unit
            }
        }
    }

    fun emptyTrash() {
        viewModelScope.launch {
            when (val result = api.emptyTrash()) {
                is CloudResult.Success -> {
                    _ui.value = _ui.value.copy(message = "Trash emptied")
                    loadAccount()
                }
                is CloudResult.Failure -> _ui.value = _ui.value.copy(lastError = result.message)
                else -> Unit
            }
        }
    }

    fun verifyFile(node: CloudNodeDto) {
        viewModelScope.launch {
            when (val result = api.verifyIntegrity(node.id)) {
                is CloudResult.Success -> _ui.value = _ui.value.copy(
                    message = if (result.value.matches) {
                        "Integrity verified — SHA-256 matches"
                    } else {
                        "INTEGRITY FAILURE: hash mismatch detected"
                    }
                )
                is CloudResult.Failure -> _ui.value = _ui.value.copy(lastError = result.message)
                else -> Unit
            }
        }
    }

    fun releaseQuarantine(node: CloudNodeDto) {
        viewModelScope.launch {
            when (val result = api.releaseQuarantine(node.id)) {
                is CloudResult.Success -> {
                    _ui.value = _ui.value.copy(message = "File released. Download it only if you trust the source.")
                    loadSecurity()
                    loadFolder(_ui.value.currentFolderId)
                }
                is CloudResult.Failure -> _ui.value = _ui.value.copy(lastError = result.message)
                else -> Unit
            }
        }
    }

    fun loadVersions(node: CloudNodeDto, onResult: (List<CloudVersionDto>, Int) -> Unit) {
        viewModelScope.launch {
            when (val result = api.versions(node.id)) {
                is CloudResult.Success -> onResult(result.value.versions, result.value.currentVersion)
                is CloudResult.Failure -> _ui.value = _ui.value.copy(lastError = result.message)
                else -> Unit
            }
        }
    }

    fun restoreVersion(node: CloudNodeDto, version: CloudVersionDto) {
        viewModelScope.launch {
            when (val result = api.restoreVersion(node.id, version.id)) {
                is CloudResult.Success -> {
                    _ui.value = _ui.value.copy(message = "Version ${version.version} restored")
                    loadFolder(_ui.value.currentFolderId)
                    loadAccount()
                }
                is CloudResult.Failure -> _ui.value = _ui.value.copy(lastError = result.message)
                else -> Unit
            }
        }
    }

    private fun mutate(successMessage: String, block: suspend () -> CloudResult<CloudNodeDto>) {
        viewModelScope.launch {
            when (val result = block()) {
                is CloudResult.Success -> {
                    _ui.value = _ui.value.copy(message = successMessage)
                    loadFolder(_ui.value.currentFolderId)
                }
                is CloudResult.Failure -> _ui.value = _ui.value.copy(lastError = result.message)
                else -> _ui.value = _ui.value.copy(lastError = "Cloud is not available")
            }
        }
    }

    // ------------------------------------------------------------------ transfers
    fun refreshTransfers() {
        viewModelScope.launch {
            val transfers = dao.allTransfers()
            _ui.value = _ui.value.copy(transfers = transfers)
        }
    }

    fun describePick(uri: Uri): PickResult? = uploadEngine.describe(uri)

    fun upload(uri: Uri, parentId: String? = _ui.value.currentFolderId) {
        viewModelScope.launch {
            val picked = uploadEngine.describe(uri)
            if (picked == null) {
                _ui.value = _ui.value.copy(lastError = "Could not read the selected file")
                return@launch
            }
            val config = configRepository.snapshot()
            val quota = _ui.value.quota
            if (quota.quotaBytes > 0 && picked.size > quota.remainingBytes) {
                _ui.value = _ui.value.copy(
                    lastError = "Not enough cloud space: ${api.formatBytes(quota.remainingBytes)} left, " +
                        "this file needs ${api.formatBytes(picked.size)}"
                )
                return@launch
            }
            val transferId = java.util.UUID.randomUUID().toString()
            val now = System.currentTimeMillis()
            val entity = CloudTransferEntity(
                id = transferId,
                direction = "upload",
                fileName = picked.name,
                mime = picked.mime,
                size = picked.size,
                bytesDone = 0,
                status = "queued",
                error = null,
                uploadId = null,
                nodeId = null,
                localUri = uri.toString(),
                localPath = null,
                sha256 = null,
                partSize = 0,
                partsTotal = 0,
                purpose = "file",
                backupKind = null,
                backupLabel = null,
                parentId = parentId,
                encrypted = config.clientSideEncryptionDefault,
                createdAt = now,
                updatedAt = now
            )
            dao.upsertTransfer(entity)
            CloudUploadWorker.enqueue(context, transferId, config.wifiOnlyUploads)
            _ui.value = _ui.value.copy(message = "Upload queued: ${picked.name}")
            refreshTransfers()
        }
    }

    fun download(node: CloudNodeDto) {
        viewModelScope.launch {
            val ticket = api.downloadTicket(node.id)
            if (ticket !is CloudResult.Success) {
                _ui.value = _ui.value.copy(
                    lastError = (ticket as? CloudResult.Failure)?.message ?: "Download is not available"
                )
                return@launch
            }
            val transferId = java.util.UUID.randomUUID().toString()
            val now = System.currentTimeMillis()
            dao.upsertTransfer(
                CloudTransferEntity(
                    id = transferId,
                    direction = "download",
                    fileName = ticket.value.fileName,
                    mime = ticket.value.mime ?: "application/octet-stream",
                    size = ticket.value.size,
                    bytesDone = 0,
                    status = "queued",
                    error = null,
                    uploadId = null,
                    nodeId = node.id,
                    localUri = null,
                    localPath = null,
                    sha256 = ticket.value.sha256,
                    partSize = 0,
                    partsTotal = 0,
                    purpose = "file",
                    backupKind = null,
                    backupLabel = null,
                    parentId = null,
                    encrypted = ticket.value.encrypted,
                    createdAt = now,
                    updatedAt = now
                )
            )
            CloudDownloadWorker.enqueue(context, transferId, ticket.value.url)
            _ui.value = _ui.value.copy(message = "Download started: ${node.name}")
            refreshTransfers()
        }
    }

    fun pauseTransfer(transfer: CloudTransferEntity) {
        TransferRegistry.peek(transfer.id)?.pause()
        CloudUploadWorker.cancel(context, transfer.id)
        viewModelScope.launch {
            dao.updateTransferStatus(transfer.id, "paused", null, System.currentTimeMillis())
            refreshTransfers()
        }
    }

    fun resumeTransfer(transfer: CloudTransferEntity) {
        val config = configRepository.snapshot()
        if (transfer.direction == "upload") {
            TransferRegistry.controlFor(transfer.id).resume()
            CloudUploadWorker.enqueue(context, transfer.id, config.wifiOnlyUploads, replace = true)
            viewModelScope.launch {
                dao.updateTransferStatus(transfer.id, "queued", null, System.currentTimeMillis())
                refreshTransfers()
            }
        }
    }

    fun cancelTransfer(transfer: CloudTransferEntity) {
        val control = TransferRegistry.peek(transfer.id)
        control?.cancel()
        CloudUploadWorker.cancel(context, transfer.id)
        viewModelScope.launch {
            dao.updateTransferStatus(transfer.id, "cancelled", null, System.currentTimeMillis())
            if (transfer.uploadId != null) api.abortUpload(transfer.uploadId)
            refreshTransfers()
        }
    }

    fun clearFinishedTransfers() {
        viewModelScope.launch {
            dao.pruneFinishedTransfers(System.currentTimeMillis() - 60_000)
            refreshTransfers()
        }
    }

    fun downloadEngine(): CloudDownloadEngine = downloadEngine

    // ------------------------------------------------------------------ sharing
    fun createShare(node: CloudNodeDto, expiryHours: Int, maxDownloads: Int, password: String?, allowPreview: Boolean) {
        viewModelScope.launch {
            when (
                val result = api.createShare(
                    nodeId = node.id,
                    expiresInSeconds = expiryHours.toLong() * 3600,
                    maxDownloads = maxDownloads,
                    password = password?.takeIf { it.isNotBlank() },
                    allowPreview = allowPreview
                )
            ) {
                is CloudResult.Success -> {
                    _ui.value = _ui.value.copy(
                        message = "Share link created: ${result.value.shareUrl}"
                    )
                    loadShares()
                }
                is CloudResult.Failure -> _ui.value = _ui.value.copy(lastError = result.message)
                else -> Unit
            }
        }
    }

    fun revokeShare(share: CloudShareDto) {
        viewModelScope.launch {
            when (val result = api.revokeShare(share.id)) {
                is CloudResult.Success -> {
                    dao.markShareRevoked(share.id)
                    _ui.value = _ui.value.copy(message = "Share link revoked")
                    loadShares()
                }
                is CloudResult.Failure -> _ui.value = _ui.value.copy(lastError = result.message)
                else -> Unit
            }
        }
    }

    private suspend fun loadShares() {
        when (val result = api.listShares()) {
            is CloudResult.Success -> {
                _ui.value = _ui.value.copy(shares = result.value)
                dao.upsertShares(
                    result.value.map { share ->
                        CloudShareEntity(
                            id = share.id,
                            nodeId = share.nodeId,
                            fileName = share.fileName,
                            expiresAt = share.expiresAt,
                            maxDownloads = share.maxDownloads,
                            downloadCount = share.downloadCount,
                            passwordProtected = share.passwordProtected,
                            allowPreview = share.allowPreview,
                            revoked = share.revoked,
                            createdAt = share.createdAt,
                            cachedAt = System.currentTimeMillis()
                        )
                    }
                )
            }
            else -> Unit
        }
    }

    // ------------------------------------------------------------------ backups
    fun createBackup(kind: String, label: String, passphrase: String?) {
        viewModelScope.launch {
            _ui.value = _ui.value.copy(isLoading = true)
            val control = com.adshield.pro.cloud.engine.TransferControl()
            when (val result = backupManager.uploadBackup(kind, label, passphrase?.toCharArray(), control) { progress ->
                _ui.value = _ui.value.copy(
                    message = "Backing up… ${(progress.fraction * 100).toInt()}%"
                )
            }) {
                is CloudResult.Success -> {
                    dao.upsertBackups(
                        listOf(
                            CloudBackupEntity(
                                id = result.value.id,
                                kind = result.value.kind,
                                label = result.value.label,
                                size = result.value.size,
                                sha256 = result.value.sha256,
                                encrypted = true,
                                integrityOk = true,
                                createdAt = result.value.createdAt,
                                verifiedAt = null,
                                restoredAt = null,
                                syncedAt = System.currentTimeMillis()
                            )
                        )
                    )
                    _ui.value = _ui.value.copy(
                        isLoading = false,
                        message = "Encrypted backup uploaded (${api.formatBytes(result.value.size)})"
                    )
                    loadBackups()
                    loadAccount()
                }
                is CloudResult.Failure -> _ui.value =
                    _ui.value.copy(isLoading = false, lastError = result.message)
                else -> _ui.value = _ui.value.copy(isLoading = false, lastError = "Backup upload unavailable")
            }
        }
    }

    fun scheduleAutoBackup(enabled: Boolean, intervalHours: Int, kinds: Set<String>) {
        viewModelScope.launch {
            configRepository.setAutoBackup(enabled, intervalHours)
            configRepository.setAutoBackupKinds(kinds)
            if (enabled) {
                CloudAutoBackupWorker.enqueuePeriodic(context, intervalHours, kinds)
                _ui.value = _ui.value.copy(message = "Automatic backups scheduled every $intervalHours h")
            } else {
                CloudAutoBackupWorker.cancel(context)
                _ui.value = _ui.value.copy(message = "Automatic backups disabled")
            }
        }
    }

    private suspend fun loadBackups() {
        when (val result = api.listBackups()) {
            is CloudResult.Success -> {
                _ui.value = _ui.value.copy(backups = result.value.backups)
                dao.upsertBackups(
                    result.value.backups.map { backup ->
                        CloudBackupEntity(
                            id = backup.id,
                            kind = backup.kind,
                            label = backup.label,
                            size = backup.size,
                            sha256 = backup.sha256,
                            encrypted = backup.encrypted,
                            integrityOk = backup.integrityOk,
                            createdAt = backup.createdAt,
                            verifiedAt = backup.verifiedAt,
                            restoredAt = backup.restoredAt,
                            syncedAt = System.currentTimeMillis()
                        )
                    }
                )
            }
            else -> Unit
        }
    }

    fun verifyBackup(backup: CloudBackupDto) {
        viewModelScope.launch {
            when (val result = api.verifyBackup(backup.id)) {
                is CloudResult.Success -> {
                    _ui.value = _ui.value.copy(
                        message = if (result.value.matches) {
                            "Backup integrity verified (SHA-256 matches)"
                        } else {
                            "BACKUP CORRUPTED: stored hash does not match"
                        }
                    )
                    loadBackups()
                }
                is CloudResult.Failure -> _ui.value = _ui.value.copy(lastError = result.message)
                else -> Unit
            }
        }
    }

    fun restoreBackup(backup: CloudBackupDto, passphrase: String?, onDone: (RestoreReport) -> Unit = {}) {
        viewModelScope.launch {
            _ui.value = _ui.value.copy(isLoading = true)
            val control = com.adshield.pro.cloud.engine.TransferControl()
            when (
                val result = backupManager.restoreBackup(
                    backup,
                    passphrase?.toCharArray(),
                    control
                ) { progress -> _ui.value = _ui.value.copy(message = "Restoring… ${(progress.fraction * 100).toInt()}%") }
            ) {
                is CloudResult.Success -> {
                    _ui.value = _ui.value.copy(
                        isLoading = false,
                        message = "Restored ${result.value.rulesAdded} rules (${result.value.rulesSkipped} already present)"
                    )
                    loadBackups()
                    onDone(result.value)
                }
                is CloudResult.Failure -> _ui.value =
                    _ui.value.copy(isLoading = false, lastError = result.message)
                else -> _ui.value = _ui.value.copy(isLoading = false, lastError = "Restore unavailable")
            }
        }
    }

    fun deleteBackup(backup: CloudBackupDto) {
        viewModelScope.launch {
            when (val result = api.deleteBackup(backup.id)) {
                is CloudResult.Success -> {
                    dao.deleteBackup(backup.id)
                    _ui.value = _ui.value.copy(message = "Backup deleted (${api.formatBytes(result.value)} freed)")
                    loadBackups()
                    loadAccount()
                }
                is CloudResult.Failure -> _ui.value = _ui.value.copy(lastError = result.message)
                else -> Unit
            }
        }
    }

    fun exportLocalBackup(kind: String) {
        viewModelScope.launch {
            runCatching { backupManager.exportLocalSnapshot(kind) }
                .onSuccess { file ->
                    _ui.value = _ui.value.copy(message = "Offline snapshot saved to ${file.name}")
                }
                .onFailure { _ui.value = _ui.value.copy(lastError = it.message) }
        }
    }

    // ------------------------------------------------------------------ security / audit
    private suspend fun loadSecurity() {
        when (val result = api.security()) {
            is CloudResult.Success -> _ui.value = _ui.value.copy(security = result.value)
            else -> Unit
        }
    }

    fun refreshSecurity() {
        viewModelScope.launch { loadSecurity() }
    }

    private suspend fun loadAudit() {
        when (val result = api.audit(80)) {
            is CloudResult.Success -> {
                val entries = result.value.entries.map {
                    CloudAuditEntity(
                        id = it.id,
                        action = it.action,
                        success = it.success,
                        detail = it.detail,
                        createdAt = it.createdAt,
                        cachedAt = System.currentTimeMillis()
                    )
                }
                _ui.value = _ui.value.copy(audit = entries)
                dao.upsertAudit(entries)
            }
            else -> Unit
        }
    }

    // ------------------------------------------------------------------ settings
    fun updatePreferences(
        autoBackup: Boolean,
        intervalHours: Int,
        backgroundUploads: Boolean,
        wifiOnly: Boolean,
        clientEncryption: Boolean,
        shareExpiryHours: Int,
        sharePassword: Boolean,
        warnPercent: Int
    ) {
        viewModelScope.launch {
            configRepository.setAutoBackup(autoBackup, intervalHours)
            configRepository.setBackgroundUploads(backgroundUploads, wifiOnly)
            configRepository.setClientEncryptionDefault(clientEncryption)
            configRepository.setShareDefaults(shareExpiryHours, sharePassword)
            configRepository.setWarnPercent(warnPercent)
            if (autoBackup) {
                CloudAutoBackupWorker.enqueuePeriodic(context, intervalHours, configRepository.snapshot().autoBackupKinds)
            } else {
                CloudAutoBackupWorker.cancel(context)
            }
            _ui.value = _ui.value.copy(message = "Cloud settings saved")
        }
    }

    fun enqueueManualBackup(kind: String, label: String) {
        enqueueManualBackup(context, kind, label)
        _ui.value = _ui.value.copy(message = "Backup queued in the background")
    }

    fun consumeMessage() {
        _ui.value = _ui.value.copy(message = null)
    }

    fun consumeError() {
        _ui.value = _ui.value.copy(lastError = null)
    }

    fun showMessage(message: String) {
        _ui.value = _ui.value.copy(message = message)
    }

    /** Decodes a preview image from a signed URL entirely on a background thread. */
    suspend fun loadPreviewBitmap(url: String): android.graphics.Bitmap? = withContext(Dispatchers.IO) {
        runCatching {
            api.execute(api.downloadRequest(url)).use { response ->
                if (!response.isSuccessful) return@use null
                response.body?.byteStream()?.use { stream ->
                    android.graphics.BitmapFactory.decodeStream(stream)
                }
            }
        }.getOrNull()
    }

    /** Previews are fetched as a short-lived signed URL; nothing is cached by the CDN. */
    suspend fun previewUrl(node: CloudNodeDto): String? = withContext(Dispatchers.IO) {
        when (val result = api.downloadTicket(node.id, preview = true)) {
            is CloudResult.Success -> result.value.url
            else -> null
        }
    }
}
