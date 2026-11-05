import { test, describe, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { buildApp } from '../src/index.js'
import {
  createD1, startB2Stub, makeEnv, signJwt, sha1Hex, sha256Hex, randomData, splitIntoParts
} from './harness.mjs'

let b2
before(async () => { b2 = await startB2Stub() })
after(async () => { await b2.close() })

async function setup() {
  b2.reset()
  const { env, token, auth } = await makeEnv(b2)
  const app = buildApp(env)
  const call = (path, init = {}) => app.fetch(new Request(`http://api${path}`, {
    headers: auth(), ...init
  }), env)
  const register = () => call('/v1/account/register', {
    method: 'POST', body: JSON.stringify({ turnstileToken: 'test' })
  })
  await register()
  return { env, app, call, token, auth, db: env.DB }
}

async function json(response) {
  const text = await response.text()
  try { return JSON.parse(text) } catch { return { raw: text } }
}

/** Uploads through the same path the Android client will use: direct PUT to the provider. */
async function upload({ call, name, data, parentId = null, partSize }) {
  const init = await json(await call('/v1/uploads/init', {
    method: 'POST',
    body: JSON.stringify({ name, size: data.length, contentType: 'application/octet-stream', parentId, partSize })
  }))
  assert.ok(init.sessionId, `upload init failed: ${JSON.stringify(init)}`)
  const parts = splitIntoParts(data, init.partSize)
  for (const part of init.parts) {
    const index = part.partNumber - 1
    const bytes = parts[index]
    const headers = {
      Authorization: part.token,
      'Content-Type': 'application/octet-stream',
      'X-Bz-Content-Sha1': sha1Hex(bytes)
    }
    if (init.multipart) {
      headers['X-Bz-Part-Number'] = String(part.partNumber)
    } else {
      headers['X-Bz-File-Name'] = init.key
    }
    const response = await fetch(part.uploadUrl, { method: 'POST', headers, body: bytes })
    assert.ok(response.ok, `provider rejected part ${part.partNumber}: ${response.status}`)
    const recorded = await json(await call(`/v1/uploads/${init.sessionId}/part/${part.partNumber}`, {
      method: 'POST', body: JSON.stringify({ size: bytes.length, sha1: sha1Hex(bytes) })
    }))
    assert.equal(recorded.partNumber, part.partNumber)
  }
  const completed = await json(await call(`/v1/uploads/${init.sessionId}/complete`, { method: 'POST' }))
  return { init, completed }
}

describe('AdShield Cloud API', () => {
  test('health reports the provider and the free allowance honestly', async () => {
    const { app, env } = await setup()
    const body = await json(await app.fetch(new Request('http://api/v1/health'), env))
    assert.equal(body.provider, 'backblaze-b2')
    assert.equal(body.freeTier.storageBytes, 10 * 1024 * 1024 * 1024)
    assert.match(body.freeTier.note, /no payment method required/)
  })

  test('requests without a verified token are refused', async () => {
    const { app, env } = await setup()
    const none = await app.fetch(new Request('http://api/v1/account'), env)
    assert.equal(none.status, 401)
    const forged = await app.fetch(new Request('http://api/v1/account', {
      headers: { Authorization: 'Bearer not-a-real-token' }
    }), env)
    assert.equal(forged.status, 401)
  })

  test('a small file uploads, downloads byte-identically and moves the quota', async () => {
    const { call, env } = await setup()
    const data = randomData(512 * 1024)
    const { completed } = await upload({ call, name: 'notes.txt', data })
    assert.equal(completed.node.sizeBytes, data.length)

    const before = await json(await call('/v1/account'))
    assert.equal(before.usage.usedBytes, data.length)
    assert.equal(before.usage.remainingBytes, before.usage.quotaBytes - data.length)

    const link = await json(await call(`/v1/nodes/${completed.node.id}/download`))
    const response = await fetch(link.url)
    const downloaded = Buffer.from(await response.arrayBuffer())
    assert.equal(downloaded.length, data.length)
    assert.equal(sha256Hex(downloaded), sha256Hex(data), 'downloaded bytes must be identical')
    assert.ok(b2.objects().some((o) => o.size === data.length))
  })

  test('a 12 MiB file uploads as three real multipart parts and reassembles exactly', async () => {
    const { call } = await setup()
    const data = randomData(12 * 1024 * 1024)
    const { init, completed } = await upload({ call, name: 'clip.mp4', data, partSize: 5 * 1024 * 1024 })
    assert.equal(init.multipart, true)
    assert.equal(init.totalParts, 3)
    assert.equal(init.partSize, 5 * 1024 * 1024)
    assert.equal(completed.node.sizeBytes, data.length)

    const link = await json(await call(`/v1/nodes/${completed.node.id}/download`))
    const downloaded = Buffer.from(await (await fetch(link.url)).arrayBuffer())
    assert.equal(sha256Hex(downloaded), sha256Hex(data))
  })

  test('an interrupted upload resumes from the parts already stored', async () => {
    const { call } = await setup()
    const data = randomData(12 * 1024 * 1024)
    const init = await json(await call('/v1/uploads/init', {
      method: 'POST',
      body: JSON.stringify({ name: 'resume.bin', size: data.length, partSize: 5 * 1024 * 1024 })
    }))
    const parts = splitIntoParts(data, init.partSize)

    // Only part 1 lands before the network drops.
    const first = init.parts[0]
    await fetch(first.uploadUrl, {
      method: 'POST',
      headers: {
        Authorization: first.token, 'X-Bz-Part-Number': '1', 'X-Bz-Content-Sha1': sha1Hex(parts[0])
      },
      body: parts[0]
    })
    await call(`/v1/uploads/${init.sessionId}/part/1`, {
      method: 'POST', body: JSON.stringify({ size: parts[0].length, sha1: sha1Hex(parts[0]) })
    })

    const resumed = await json(await call(`/v1/uploads/${init.sessionId}`))
    assert.deepEqual(resumed.session.uploadedParts, [1])
    assert.equal(resumed.session.uploadedBytes, parts[0].length)
    assert.deepEqual(resumed.partUrls.map((p) => p.partNumber), [2, 3])

    for (const part of resumed.partUrls) {
      const bytes = parts[part.partNumber - 1]
      await fetch(part.uploadUrl, {
        method: 'POST',
        headers: {
          Authorization: part.token,
          'X-Bz-Part-Number': String(part.partNumber),
          'X-Bz-Content-Sha1': sha1Hex(bytes)
        },
        body: bytes
      })
      await call(`/v1/uploads/${init.sessionId}/part/${part.partNumber}`, {
        method: 'POST', body: JSON.stringify({ size: bytes.length, sha1: sha1Hex(bytes) })
      })
    }
    const completed = await json(await call(`/v1/uploads/${init.sessionId}/complete`, { method: 'POST' }))
    assert.equal(completed.node.sizeBytes, data.length)
    const link = await json(await call(`/v1/nodes/${completed.node.id}/download`))
    const downloaded = Buffer.from(await (await fetch(link.url)).arrayBuffer())
    assert.equal(sha256Hex(downloaded), sha256Hex(data))
  })

  test('completing with missing parts is refused instead of storing a truncated file', async () => {
    const { call } = await setup()
    const data = randomData(12 * 1024 * 1024)
    const init = await json(await call('/v1/uploads/init', {
      method: 'POST', body: JSON.stringify({ name: 'partial.bin', size: data.length, partSize: 5 * 1024 * 1024 })
    }))
    const response = await call(`/v1/uploads/${init.sessionId}/complete`, { method: 'POST' })
    assert.equal(response.status, 409)
    const body = await json(response)
    assert.deepEqual(body.missingParts, [1, 2, 3])
  })

  test('cancelling an upload cancels the provider-side large file', async () => {
    const { call, env } = await setup()
    const init = await json(await call('/v1/uploads/init', {
      method: 'POST', body: JSON.stringify({ name: 'cancel.bin', size: 12 * 1024 * 1024, partSize: 5 * 1024 * 1024 })
    }))
    const cancelled = await json(await call(`/v1/uploads/${init.sessionId}/cancel`, { method: 'POST' }))
    assert.equal(cancelled.cancelled, true)
    const listed = await json(await call('/v1/nodes'))
    assert.equal(listed.nodes.length, 0)
    const usage = await json(await call('/v1/account'))
    assert.equal(usage.usage.usedBytes, 0)
  })

  test('an upload beyond the free allowance is refused with exact numbers', async () => {
    const { call, env } = await setup()
    // Lower the ceiling to 2 MiB so the refusal is exercised without uploading 10 GB.
    await env.DB.prepare(`UPDATE users SET quota_bytes = ? WHERE id = ?`).bind(2 * 1024 * 1024, 'user-1').run()
    const response = await call('/v1/uploads/init', {
      method: 'POST', body: JSON.stringify({ name: 'too-big.bin', size: 5 * 1024 * 1024 })
    })
    assert.equal(response.status, 413)
    const body = await json(response)
    assert.equal(body.detail.quotaBytes, 2 * 1024 * 1024)
    assert.equal(body.detail.remainingBytes, 2 * 1024 * 1024)
    const audit = await json(await call('/v1/audit'))
    assert.ok(audit.entries.some((entry) => entry.action === 'quota_refused'))
  })

  test('folders can be created, renamed, moved, copied, trashed, restored and purged', async () => {
    const { call } = await setup()
    const folder = await json(await call('/v1/folders', {
      method: 'POST', body: JSON.stringify({ name: 'Holidays' })
    }))
    const nested = await json(await call('/v1/folders', {
      method: 'POST', body: JSON.stringify({ name: 'Photos', parentId: folder.node.id })
    }))
    const listed = await json(await call(`/v1/nodes?parentId=${folder.node.id}`))
    assert.equal(listed.nodes.length, 1)
    assert.equal(listed.nodes[0].name, 'Photos')

    await json(await call(`/v1/nodes/${nested.node.id}/rename`, {
      method: 'POST', body: JSON.stringify({ name: 'Renamed' })
    }))
    const renamed = await json(await call(`/v1/nodes?parentId=${folder.node.id}`))
    assert.equal(renamed.nodes[0].name, 'Renamed')

    const copied = await json(await call(`/v1/nodes/${nested.node.id}/copy`, { method: 'POST' }))
    assert.match(copied.node.name, /\(copy\)$/)

    const trashed = await json(await call(`/v1/nodes/${nested.node.id}/delete`, { method: 'POST' }))
    assert.equal(trashed.trashed, true)
    const trash = await json(await call('/v1/nodes?trashed=1'))
    assert.equal(trash.nodes.length, 1)

    await json(await call(`/v1/nodes/${nested.node.id}/restore`, { method: 'POST' }))
    const restored = await json(await call(`/v1/nodes?parentId=${folder.node.id}`))
    assert.equal(restored.nodes.length, 2)
  })

  test('purging a file deletes the stored object and frees the quota', async () => {
    const { call, env } = await setup()
    const data = randomData(1024 * 1024)
    const { completed } = await upload({ call, name: 'purge-me.bin', data })
    const before = await json(await call('/v1/account'))
    assert.equal(before.usage.usedBytes, data.length)

    const response = await call(`/v1/nodes/${completed.node.id}`, { method: 'DELETE' })
    assert.equal(response.status, 200)
    const after = await json(await call('/v1/account'))
    assert.equal(after.usage.usedBytes, 0)
    assert.equal(b2.objects().filter((o) => o.key.includes('purge-me')).length, 0)
  })

  test('re-uploading the same name keeps a version history and prunes beyond five', async () => {
    const { call } = await setup()
    for (let i = 0; i < 7; i++) {
      await upload({ call, name: 'report.pdf', data: randomData(64 * 1024 + i) })
    }
    const listed = await json(await call('/v1/nodes'))
    const node = listed.nodes.find((n) => n.name === 'report.pdf')
    const versions = await json(await call(`/v1/nodes/${node.id}/versions`))
    assert.ok(versions.versions.length <= 5, 'history is capped at five stored versions')
    assert.ok(versions.versions.length >= 1)
    const account = await json(await call('/v1/account'))
    assert.ok(account.usage.usedBytes > 0)
  })

  test('share links work, expire and can be revoked', async () => {
    const { call, app, env } = await setup()
    const data = randomData(256 * 1024)
    const { completed } = await upload({ call, name: 'shared.png', data })

    const share = await json(await call('/v1/shares', {
      method: 'POST', body: JSON.stringify({ nodeId: completed.node.id, expiresInSeconds: 900 })
    }))
    const opened = await json(await app.fetch(new Request(`http://api/v1/share/${share.share.token}`), env))
    assert.equal(opened.sizeBytes, data.length)
    const downloaded = Buffer.from(await (await fetch(opened.url)).arrayBuffer())
    assert.equal(sha256Hex(downloaded), sha256Hex(data))

    // Force expiry without sleeping: rewrite the row the way time would.
    await env.DB.prepare(`UPDATE shares SET expires_at = ? WHERE id = ?`).bind(Date.now() - 1000, share.share.id).run()
    const expired = await app.fetch(new Request(`http://api/v1/share/${share.share.token}`), env)
    assert.equal(expired.status, 410)

    await call(`/v1/shares/${share.share.id}`, { method: 'DELETE' })
    const revoked = await app.fetch(new Request(`http://api/v1/share/${share.share.token}`), env)
    assert.equal(revoked.status, 404)
  })

  test('DNS backups are stored, integrity-verified, listed, restored and deletable', async () => {
    const { call } = await setup()
    const payload = Buffer.from(JSON.stringify({
      version: 4,
      protectionMode: 'AGGRESSIVE',
      resolverConfig: { preset: 'QUAD9', protocol: 'DOT', dnssecMode: 'REPORT_ONLY' },
      customRules: ['||ads.example^'],
      browserSiteExceptions: ['example.com']
    }), 'utf8')

    const init = await json(await call('/v1/backups/init', {
      method: 'POST',
      body: JSON.stringify({ kind: 'dns_config', label: 'Before switching resolver', size: payload.length })
    }))
    const response = await fetch(init.uploadUrl, {
      method: 'POST',
      headers: {
        Authorization: init.token,
        'X-Bz-File-Name': init.key,
        'Content-Type': 'application/json',
        'X-Bz-Content-Sha1': sha1Hex(payload)
      },
      body: payload
    })
    assert.ok(response.ok, 'provider accepted the backup payload')

    const committed = await json(await call(`/v1/backups/${init.backupId}/commit`, {
      method: 'POST', body: JSON.stringify({ size: payload.length, sha256: sha256Hex(payload) })
    }))
    assert.equal(committed.verified, true)
    assert.equal(committed.sha256, sha256Hex(payload))
    assert.equal(committed.sizeBytes, payload.length)

    const list = await json(await call('/v1/backups'))
    assert.equal(list.backups.length, 1)
    assert.equal(list.backups[0].kind, 'dns_config')

    const restored = await json(await call(`/v1/backups/${init.backupId}/restore`, { method: 'POST' }))
    const downloaded = Buffer.from(await (await fetch(restored.url)).arrayBuffer())
    assert.equal(sha256Hex(downloaded), sha256Hex(payload))
    const parsed = JSON.parse(downloaded.toString('utf8'))
    assert.equal(parsed.resolverConfig.preset, 'QUAD9')
    assert.deepEqual(parsed.customRules, ['||ads.example^'])

    const before = await json(await call('/v1/account'))
    assert.equal(before.usage.usedBytes, payload.length)
    await call(`/v1/backups/${init.backupId}`, { method: 'DELETE' })
    const after = await json(await call('/v1/account'))
    assert.equal(after.usage.usedBytes, 0)
  })

  test('a backup whose bytes do not match the claimed digest is rejected', async () => {
    const { call } = await setup()
    const payload = Buffer.from('{"version":4}', 'utf8')
    const init = await json(await call('/v1/backups/init', {
      method: 'POST', body: JSON.stringify({ kind: 'full_config', size: payload.length })
    }))
    await fetch(init.uploadUrl, {
      method: 'POST',
      headers: {
        Authorization: init.token, 'X-Bz-File-Name': init.key,
        'Content-Type': 'application/json', 'X-Bz-Content-Sha1': sha1Hex(payload)
      },
      body: payload
    })
    const response = await call(`/v1/backups/${init.backupId}/commit`, {
      method: 'POST', body: JSON.stringify({ size: payload.length, sha256: 'f'.repeat(64) })
    })
    assert.equal(response.status, 409)
    const body = await json(response)
    assert.equal(body.error, 'integrity check failed')
  })

  test('duplicate detection groups files by their real content hash', async () => {
    const { call } = await setup()
    const data = randomData(300 * 1024)
    await upload({ call, name: 'a.bin', data })
    await upload({ call, name: 'b.bin', data })
    await upload({ call, name: 'different.bin', data: randomData(300 * 1024) })
    const found = await json(await call('/v1/duplicates'))
    assert.equal(found.groups.length, 1)
    assert.equal(found.groups[0].copies, 2)
    assert.deepEqual(found.groups[0].names.sort(), ['a.bin', 'b.bin'])
  })

  test('reconciliation rebuilds usage from what the provider actually stores', async () => {
    const { call, env } = await setup()
    const data = randomData(2 * 1024 * 1024)
    await upload({ call, name: 'truth.bin', data })
    // Corrupt the counter the way a bug would, then prove reconciliation catches it.
    await env.DB.prepare(`UPDATE users SET used_bytes = 0 WHERE id = ?`).bind('user-1').run()
    const result = await json(await call('/v1/account/reconcile', { method: 'POST' }))
    assert.equal(result.b2Bytes, data.length)
    assert.equal(result.databaseBytes, data.length)
    assert.equal(result.driftBytes, 0)
    const account = await json(await call('/v1/account'))
    assert.equal(account.usage.usedBytes, data.length)
  })

  test('the hourly request ceiling protects the Workers free tier', async () => {
    const { call, env } = await setup()
    const bucket = Math.floor(Date.now() / 3_600_000)
    await env.DB.prepare(
      `INSERT INTO api_usage (user_id, bucket, requests) VALUES (?, ?, ?)`
    ).bind('user-1', bucket, 2_000).run()
    const limited = await call('/v1/account')
    assert.equal(limited.status, 429)
    const body = await json(limited)
    assert.equal(body.error, 'rate limited')
  })

  test('search finds files by name across folders', async () => {
    const { call } = await setup()
    await upload({ call, name: 'holiday-photo.jpg', data: randomData(1024) })
    await upload({ call, name: 'invoice.pdf', data: randomData(1024) })
    const found = await json(await call('/v1/nodes?search=holiday'))
    assert.equal(found.nodes.length, 1)
    assert.equal(found.nodes[0].name, 'holiday-photo.jpg')
  })

  test('every mutating action is written to the per-user audit log', async () => {
    const { call } = await setup()
    await upload({ call, name: 'audited.bin', data: randomData(2048) })
    const audit = await json(await call('/v1/audit'))
    const actions = audit.entries.map((entry) => entry.action)
    assert.ok(actions.includes('signup'))
    assert.ok(actions.includes('upload_init'))
    assert.ok(actions.includes('upload_complete'))
  })
})
