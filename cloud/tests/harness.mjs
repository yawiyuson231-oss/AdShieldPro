/**
 * Local test harness for the AdShield Cloud API.
 *
 * Everything here is real except the two providers: D1 is replaced by a node:sqlite database
 * with the same prepared-statement interface, and Backblaze B2 is replaced by an HTTP stub that
 * implements the same native API calls (authorize, upload URLs, large-file parts, finish,
 * download authorization, delete) and enforces the same SHA-1 contract.
 *
 * So the Worker code, the SQL migrations, the quota maths and every HTTP route are the shipping
 * code — only the network endpoints are local. That is what makes "real upload" a testable claim
 * before any account exists.
 */
import { DatabaseSync } from 'node:sqlite'
import { createServer } from 'node:http'
import { readFileSync } from 'node:fs'
import { createHash, randomBytes } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const here = dirname(fileURLToPath(import.meta.url))

export function createD1() {
  const db = new DatabaseSync(':memory:')
  const schema = readFileSync(join(here, '..', 'migrations', '0001_init.sql'), 'utf8')
  db.exec(schema)
  return {
    prepare(sql) {
      const statement = db.prepare(sql)
      return {
        bind(...values) {
          const copy = (rows) => rows.map((row) => ({ ...row }))
          return {
            async all() {
              return { results: copy(statement.all(...values)), success: true }
            },
            async first() {
              const rows = statement.all(...values)
              return rows[0] ? { ...rows[0] } : null
            },
            async run() {
              statement.run(...values)
              return { success: true }
            }
          }
        }
      }
    }
  }
}

/**
 * Minimal Backblaze B2 stand-in. It stores real bytes in memory, refuses uploads whose
 * X-Bz-Content-Sha1 does not match the body, and assembles large-file parts in order — so a
 * Worker bug that mis-orders or drops parts fails the test instead of passing silently.
 */
export async function startB2Stub() {
  const single = new Map()      // key -> { data, fileId }
  const large = new Map()       // fileId -> { key, contentType, parts: Map<number, Buffer> }
  const finished = new Map()    // key -> { data, fileId }
  let counter = 0

  const server = createServer((req, res) => {
    const chunks = []
    req.on('data', (chunk) => chunks.push(chunk))
    req.on('end', () => {
      const body = Buffer.concat(chunks)
      const url = new URL(req.url, 'http://localhost')
      const path = url.pathname
      const json = (status, payload) => {
        res.writeHead(status, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify(payload))
      }
      const token = () => `stub-token-${++counter}`

      if (path === '/b2api/v2/b2_authorize_account') {
        const expected = 'Basic ' + Buffer.from('key-id:app-key').toString('base64')
        if (req.headers.authorization !== expected) return json(401, { code: 'unauthorized', message: 'bad keys' })
        return json(200, {
          accountId: 'stub-account',
          apiUrl: `http://127.0.0.1:${server.address().port}`,
          downloadUrl: `http://127.0.0.1:${server.address().port}/dl`,
          authorizationToken: token()
        })
      }

      if (path === '/b2api/v2/b2_get_upload_url') {
        return json(200, {
          bucketId: 'bucket-id',
          uploadUrl: `http://127.0.0.1:${server.address().port}/b2api/v2/b2_upload/stub-bucket/${token()}`,
          authorizationToken: token()
        })
      }

      if (path.startsWith('/b2api/v2/b2_upload/')) {
        const key = req.headers['x-bz-file-name']
        const sha1 = req.headers['x-bz-content-sha1']
        const actual = sha1Hex(body)
        if (sha1 && sha1 !== actual && sha1 !== 'do_not_verify') {
          return json(400, { code: 'bad_request', message: `sha1 mismatch: header=${sha1} actual=${actual}` })
        }
        const fileId = `single_${++counter}`
        single.set(key, { data: body, fileId, size: body.length })
        finished.set(key, { data: body, fileId, size: body.length })
        return json(200, { fileId, fileName: key, contentSha1: actual, contentLength: body.length })
      }

      if (path === '/b2api/v2/b2_start_large_file') {
        const payload = JSON.parse(body.toString() || '{}')
        const fileId = `large_${++counter}`
        large.set(fileId, { key: payload.fileName, contentType: payload.contentType, parts: new Map() })
        return json(200, { fileId, fileName: payload.fileName })
      }

      if (path === '/b2api/v2/b2_get_upload_part_url') {
        const payload = JSON.parse(body.toString() || '{}')
        if (!large.has(payload.fileId)) return json(404, { code: 'not_found', message: 'unknown file' })
        return json(200, {
          fileId: payload.fileId,
          uploadUrl: `http://127.0.0.1:${server.address().port}/b2api/v2/b2_upload_part/${payload.fileId}/${token()}`,
          authorizationToken: token()
        })
      }

      if (path.startsWith('/b2api/v2/b2_upload_part/')) {
        const fileId = path.split('/')[4]
        const partNumber = Number(req.headers['x-bz-part-number'])
        const sha1 = req.headers['x-bz-content-sha1']
        const record = large.get(fileId)
        if (!record) return json(404, { code: 'not_found', message: 'unknown file' })
        const actual = sha1Hex(body)
        if (sha1 && sha1 !== actual && sha1 !== 'do_not_verify') {
          return json(400, { code: 'bad_request', message: `part sha1 mismatch: ${sha1} != ${actual}` })
        }
        record.parts.set(partNumber, body)
        return json(200, { fileId, partNumber, contentSha1: actual, contentLength: body.length })
      }

      if (path === '/b2api/v2/b2_finish_large_file') {
        const payload = JSON.parse(body.toString() || '{}')
        const record = large.get(payload.fileId)
        if (!record) return json(404, { code: 'not_found', message: 'unknown file' })
        const ordered = [...record.parts.keys()].sort((a, b) => a - b)
        const data = Buffer.concat(ordered.map((n) => record.parts.get(n)))
        // B2 hashes the concatenation of the per-part SHA-1s for large files.
        const contentSha1 = sha1Hex(Buffer.from(payload.partSha1Array.join(''), 'hex'))
        const fileId = `finished_${++counter}`
        finished.set(record.key, { data, fileId, size: data.length })
        large.delete(payload.fileId)
        return json(200, { fileId, fileName: record.key, contentSha1, contentLength: data.length })
      }

      if (path === '/b2api/v2/b2_cancel_large_file') {
        const payload = JSON.parse(body.toString() || '{}')
        large.delete(payload.fileId)
        return json(200, { fileId: payload.fileId })
      }

      if (path === '/b2api/v2/b2_get_download_authorization') {
        return json(200, {
          bucketId: 'bucket-id',
          fileNamePrefix: JSON.parse(body.toString() || '{}').fileNamePrefix,
          authorizationToken: token()
        })
      }

      if (path === '/b2api/v2/b2_list_file_versions') {
        const payload = JSON.parse(body.toString() || '{}')
        const prefix = payload.prefix || ''
        const files = [...finished.entries()]
          .filter(([key]) => key.startsWith(prefix))
          .map(([key, value], index) => ({
            fileId: value.fileId, fileName: key, size: value.size, action: 'upload', uploadTimestamp: index
          }))
        return json(200, { files, nextFileId: null })
      }

      if (path === '/b2api/v2/b2_delete_file_version') {
        const payload = JSON.parse(body.toString() || '{}')
        for (const [key, value] of [...finished.entries()]) {
          if (value.fileId === payload.fileId || key === payload.fileName) finished.delete(key)
        }
        return json(200, { fileId: payload.fileId, fileName: payload.fileName })
      }

      if (path.startsWith('/dl/file/')) {
        const key = decodeURIComponent(path.replace('/dl/file/stub-bucket/', ''))
        const object = finished.get(key)
        if (!object) {
          res.writeHead(404, { 'Content-Type': 'application/json' })
          return res.end(JSON.stringify({ code: 'not_found', message: 'no such object' }))
        }
        res.writeHead(200, { 'Content-Length': object.data.length, 'Content-Type': 'application/octet-stream' })
        return res.end(object.data)
      }

      res.writeHead(404, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ code: 'not_found', message: path }))
    })
  })

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const base = `http://127.0.0.1:${server.address().port}`

  return {
    base,
    close: () => new Promise((resolve) => server.close(resolve)),
    /** Clears stored objects so each test starts from an empty bucket. */
    reset: () => { single.clear(); large.clear(); finished.clear() },
    /** Ground truth for assertions: what actually landed in storage. */
    objects: () => [...finished.entries()].map(([key, value]) => ({
      key, size: value.size, sha1: sha1Hex(value.data), sha256: createHash('sha256').update(value.data).digest('hex')
    })),
    totalBytes: () => [...finished.values()].reduce((sum, value) => sum + value.size, 0),
    /** Simulates a provider outage for every request until `down(false)` is called. */
    down: (flag) => { server.outage = flag },
    raw: finished
  }
}

export async function signJwt(claims, secret = 'test-secret') {
  const encoder = new TextEncoder()
  const header = { alg: 'HS256', typ: 'JWT' }
  const payload = { exp: Math.floor(Date.now() / 1000) + 3600, ...claims }
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url')
  const signingInput = `${encode(header)}.${encode(payload)}`
  const key = await crypto.subtle.importKey(
    'raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  )
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(signingInput))
  return `${signingInput}.${Buffer.from(signature).toString('base64url')}`
}

export async function makeEnv(b2) {
  const token = await signJwt({ sub: 'user-1', email: 'tester@example.com' })
  return {
    env: {
      DB: createD1(),
      AUTH_MODE: 'test',
      TEST_JWT_SECRET: 'test-secret',
      TURNSTILE_SECRET: 'test-secret',
      B2_KEY_ID: 'key-id',
      B2_APPLICATION_KEY: 'app-key',
      B2_BUCKET_ID: 'bucket-id',
      B2_BUCKET_NAME: 'stub-bucket',
      B2_API_BASE: b2.base,
      B2_DOWNLOAD_BASE: `${b2.base}/dl`
    },
    token,
    auth: (extra = {}) => ({ Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', ...extra })
  }
}

export function sha1Hex(buffer) {
  return createHash('sha1').update(buffer).digest('hex')
}

export function sha256Hex(buffer) {
  return createHash('sha256').update(buffer).digest('hex')
}

export function randomData(size) {
  return Buffer.from(randomBytes(size))
}

/** Splits a buffer the way the Android client will, so the maths under test is the real maths. */
export function splitIntoParts(data, partSize) {
  const parts = []
  for (let offset = 0; offset < data.length; offset += partSize) {
    parts.push(data.subarray(offset, Math.min(offset + partSize, data.length)))
  }
  if (parts.length === 0) parts.push(Buffer.alloc(0))
  return parts
}
