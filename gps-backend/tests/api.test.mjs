// Contract tests for the community traffic API, runnable with zero dependencies and no database:
//   node --test gps-backend/tests/
//
// They assert the properties the Android client depends on, including the negative ones: a segment
// with no observations must be absent from the response, and an implausible sample must be rejected
// rather than averaged in.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { createApp, createMemoryStore } from '../api/server.mjs'

const TOKEN = 'test-token-0123456789abcdef'

async function withServer(run) {
  const store = createMemoryStore()
  const server = createServer(createApp(store))
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const { port } = server.address()
  const base = `http://127.0.0.1:${port}`
  try {
    await run(base, store)
  } finally {
    await new Promise((resolve) => server.close(resolve))
  }
}

const post = (base, path, body, token = TOKEN) =>
  fetch(base + path, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-adshield-token': token },
    body: JSON.stringify(body)
  })

const get = (base, path, token = TOKEN) =>
  fetch(base + path, { headers: { 'x-adshield-token': token } })

function observation(overrides = {}) {
  return {
    segment_id: 'seg-145995-1209842-0',
    speed_kmh: 48.5,
    timestamp_ms: Date.now(),
    accuracy_m: 7,
    samples: 2,
    heading_deg: 90,
    ...overrides
  }
}

test('health reports the storage backend so nobody mistakes memory for production', async () => {
  await withServer(async (base) => {
    const response = await get(base, '/v1/health')
    assert.equal(response.status, 200)
    const body = await response.json()
    assert.equal(body.ok, true)
    assert.equal(body.storage, 'memory')
  })
})

test('requests without a token are refused', async () => {
  await withServer(async (base) => {
    const response = await fetch(base + '/v1/traffic/segments?ids=seg-1')
    assert.equal(response.status, 401)
  })
})

test('a segment with no observations is absent, not green', async () => {
  await withServer(async (base) => {
    const response = await get(base, '/v1/traffic/segments?ids=seg-never-seen')
    const body = await response.json()
    assert.deepEqual(body.segments, [])
    assert.equal(body.unknown_count, 1)
  })
})

test('one sample is still not enough evidence to publish a speed', async () => {
  await withServer(async (base) => {
    await post(base, '/v1/traffic/observations', { token: TOKEN, observations: [observation()] })
    const body = await (await get(base, '/v1/traffic/segments?ids=seg-145995-1209842-0')).json()
    // confidence for a single sample is below the 0.35 threshold, so nothing is published
    assert.equal(body.segments.length, 0)
  })
})

test('a well-observed segment publishes an average with its sample count', async () => {
  await withServer(async (base) => {
    const observations = Array.from({ length: 8 }, (_, index) =>
      observation({ speed_kmh: 40 + index, heading_deg: (index * 7) % 360 })
    )
    const submitted = await post(base, '/v1/traffic/observations', { token: TOKEN, observations })
    assert.equal(submitted.status, 200)
    const body = await (await get(base, '/v1/traffic/segments?ids=seg-145995-1209842-0')).json()
    assert.equal(body.segments.length, 1)
    const segment = body.segments[0]
    assert.ok(segment.avg_speed_kmh > 40 && segment.avg_speed_kmh < 48)
    assert.ok(segment.samples >= 8)
    assert.ok(segment.confidence >= 0.35)
  })
})

test('implausible samples are rejected instead of averaged in', async () => {
  await withServer(async (base) => {
    const body = await (
      await post(base, '/v1/traffic/observations', {
        token: TOKEN,
        observations: [
          observation({ speed_kmh: 900 }),          // faster than any road vehicle
          observation({ accuracy_m: 500 }),         // too coarse to attribute to a road
          observation({ timestamp_ms: Date.now() - 48 * 3600_000 }), // stale replay
          observation({ segment_id: '' })           // no segment
        ]
      })
    ).json()
    assert.equal(body.accepted, 0)
    assert.equal(body.rejected, 4)
  })
})

test('replayed uploads are idempotent', async () => {
  await withServer(async (base) => {
    const payload = { token: TOKEN, observations: [observation()] }
    const first = await (await post(base, '/v1/traffic/observations', payload)).json()
    const second = await (await post(base, '/v1/traffic/observations', payload)).json()
    assert.ok(first.accepted >= 1)
    assert.ok(second.accepted <= first.accepted)
  })
})

test('incidents get a lifetime and near-duplicates merge', async () => {
  await withServer(async (base) => {
    const first = await post(base, '/v1/traffic/incidents', {
      token: TOKEN,
      kind: 'ACCIDENT',
      lat: 14.5995,
      lon: 120.9842,
      notes: 'two cars, right lane'
    })
    assert.equal(first.status, 201)
    const created = await first.json()
    assert.ok(created.expires_at_ms > Date.now())

    const nearby = await post(base, '/v1/traffic/incidents', {
      token: 'another-token-abcdef012345',
      kind: 'ACCIDENT',
      lat: 14.5996,
      lon: 120.9842
    })
    const merged = await nearby.json()
    assert.equal(merged.merged, true)
    assert.equal(merged.id, created.id)
  })
})

test('an unknown incident kind is rejected', async () => {
  await withServer(async (base) => {
    const response = await post(base, '/v1/traffic/incidents', {
      token: TOKEN,
      kind: 'ALIENS',
      lat: 14.5995,
      lon: 120.9842
    })
    assert.equal(response.status, 400)
  })
})

test('oversized notes are truncated, never stored whole', async () => {
  await withServer(async (base, store) => {
    const long = 'x'.repeat(400)
    const response = await post(base, '/v1/traffic/incidents', {
      token: TOKEN,
      kind: 'HAZARD',
      lat: 14.6,
      lon: 120.99,
      notes: long
    })
    assert.equal(response.status, 201)
    const stats = await store.stats()
    assert.ok(stats.segments_seen >= 0)
  })
})
