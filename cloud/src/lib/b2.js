/**
 * Backblaze B2 native API client.
 *
 * Why B2: 10 GB is free forever with no payment method on file, and downloads are free up to
 * 3x stored volume. The Worker talks to B2 with account-scoped credentials that live only in
 * Worker secrets; the Android client never sees them and instead receives short-lived,
 * single-purpose upload URLs or download authorizations.
 *
 * Streaming: large files are uploaded with B2's large-file API (b2_start_large_file +
 * per-part upload URLs + b2_finish_large_file), which is what makes pause/resume and
 * per-part retries possible. Files under the part threshold use the single-shot upload URL.
 */
const B2_API = '/b2api/v2/'

export class B2Error extends Error {
  constructor(status, code, message) {
    super(`B2 ${status} ${code}: ${message}`)
    this.status = status
    this.code = code
  }
}

export class B2Client {
  constructor({ keyId, applicationKey, bucketId, bucketName, apiBase, downloadBase }) {
    this.keyId = keyId
    this.applicationKey = applicationKey
    this.bucketId = bucketId
    this.bucketName = bucketName
    this.apiBase = (apiBase || 'https://api.backblazeb2.com').replace(/\/$/, '')
    this.downloadBase = (downloadBase || 'https://f000.backblazeb2.com').replace(/\/$/, '')
    this.token = null
    this.tokenExpiresAt = 0
    this.cachedUploadUrl = null
  }

  async authorize(force = false) {
    if (!force && this.token && Date.now() < this.tokenExpiresAt - 60_000) return this.token
    const basic = btoa(`${this.keyId}:${this.applicationKey}`)
    const response = await fetch(`${this.apiBase}${B2_API}b2_authorize_account`, {
      headers: { Authorization: `Basic ${basic}` }
    })
    const body = await response.json().catch(() => ({}))
    if (!response.ok) {
      throw new B2Error(response.status, body.code || 'auth_failed', body.message || 'authorization failed')
    }
    this.token = body.authorizationToken
    this.apiBase = body.apiUrl.replace(/\/$/, '')
    this.downloadBase = body.downloadUrl.replace(/\/$/, '')
    // B2 does not return an explicit TTL; re-authorize well inside the documented 24 h window.
    this.tokenExpiresAt = Date.now() + 23 * 3_600_000
    return this.token
  }

  async call(name, payload, { raw = false, retry = true } = {}) {
    const token = await this.authorize()
    const response = await fetch(`${this.apiBase}${B2_API}${name}`, {
      method: 'POST',
      headers: { Authorization: token, 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    })
    if (response.status === 401 && retry) {
      await this.authorize(true)
      return this.call(name, payload, { raw, retry: false })
    }
    if (raw) return response
    const body = await response.json().catch(() => ({}))
    if (!response.ok) {
      throw new B2Error(response.status, body.code || name, body.message || 'request failed')
    }
    return body
  }

  /** Small files (< part threshold): one upload URL, one POST. */
  async getUploadUrl() {
    const body = await this.call('b2_get_upload_url', { bucketId: this.bucketId })
    return { uploadUrl: body.uploadUrl, authorizationToken: body.authorizationToken }
  }

  async startLargeFile({ key, contentType, info = {} }) {
    const body = await this.call('b2_start_large_file', {
      bucketId: this.bucketId,
      fileName: key,
      contentType: contentType || 'application/octet-stream',
      fileInfo: { ...info, src: 'adshield-cloud' }
    })
    return { fileId: body.fileId }
  }

  async getPartUploadUrl(fileId) {
    const body = await this.call('b2_get_upload_part_url', { fileId })
    return { uploadUrl: body.uploadUrl, authorizationToken: body.authorizationToken }
  }

  async cancelLargeFile(fileId) {
    await this.call('b2_cancel_large_file', { fileId })
  }

  async finishLargeFile(fileId, partSha1Array) {
    return this.call('b2_finish_large_file', { fileId, partSha1Array })
  }

  /** Time-limited download authorization scoped to a single key prefix. */
  async getDownloadAuthorization({ keyPrefix, validDurationSeconds, contentType }) {
    const payload = {
      bucketId: this.bucketId,
      fileNamePrefix: keyPrefix,
      validDurationSeconds
    }
    if (contentType) payload.b2ContentDisposition = null
    const body = await this.call('b2_get_download_authorization', payload)
    return body.authorizationToken
  }

  downloadUrl(key, authorization) {
    const separator = authorization.includes('?') ? '&' : '?'
    return `${this.downloadBase}/file/${this.bucketName}/${encodePath(key)}${separator}Authorization=${encodeURIComponent(authorization)}`
  }

  async deleteFileVersion({ fileName, fileId }) {
    await this.call('b2_delete_file_version', { fileName, fileId })
  }

  /** Reconciliation: list live versions so used_bytes can be verified against reality. */
  async listFileVersions({ prefix, maxFileCount = 1000, startFileId = null }) {
    const payload = { bucketId: this.bucketId, prefix, maxFileCount, delimeter: '' }
    if (startFileId) payload.startFileId = startFileId
    return this.call('b2_list_file_versions', payload)
  }
}

function encodePath(key) {
  return key.split('/').map(encodeURIComponent).join('/')
}

export function btoa(input) {
  if (typeof globalThis.btoa === 'function') return globalThis.btoa(input)
  return Buffer.from(input, 'utf8').toString('base64')
}

/** 5 MiB is the B2 minimum part size and a sane default for mobile networks. */
export const PART_SIZE = 5 * 1024 * 1024
export const MIN_PART_SIZE = 5 * 1024 * 1024
export const MAX_PARTS = 10_000
export const SMALL_FILE_LIMIT = 5 * 1024 * 1024

export function planUpload(sizeBytes, requestedPartSize) {
  if (!Number.isFinite(sizeBytes) || sizeBytes <= 0) {
    throw new Error('declared size must be a positive number of bytes')
  }
  const partSize = Math.max(MIN_PART_SIZE, Math.floor(requestedPartSize || PART_SIZE))
  const totalParts = Math.ceil(sizeBytes / partSize)
  if (totalParts > MAX_PARTS) {
    throw new Error(`file needs ${totalParts} parts; the maximum is ${MAX_PARTS} (raise the part size)`)
  }
  return { partSize, totalParts, multipart: sizeBytes > SMALL_FILE_LIMIT }
}

export function partSizeFor(index, totalBytes, partSize) {
  return Math.min(partSize, totalBytes - index * partSize)
}
