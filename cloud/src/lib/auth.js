/**
 * Supabase Auth verification.
 *
 * Supabase issues ES256/RS256 JWTs signed by the project's JWKS. The Worker verifies the
 * signature, issuer and expiry on every request — possession of a user id is never trusted.
 *
 * In `AUTH_MODE=test` the Worker accepts HS256 tokens signed with TEST_JWT_SECRET so the local
 * suite can exercise real authorization paths without a Supabase project. That mode is refused
 * in production (checked in index.js) so a misconfigured secret cannot open the API.
 */
const encoder = new TextEncoder()

const jwksCache = new Map()

export async function getJwks(supabaseUrl, { force = false } = {}) {
  const url = `${supabaseUrl.replace(/\/$/, '')}/auth/v1/.well-known/jwks.json`
  const cached = jwksCache.get(url)
  if (!force && cached && Date.now() < cached.expiresAt) return cached.keys
  const response = await fetch(url)
  if (!response.ok) throw new Error(`could not fetch Supabase JWKS (${response.status})`)
  const body = await response.json()
  const keys = Array.isArray(body.keys) ? body.keys : []
  jwksCache.set(url, { keys, expiresAt: Date.now() + 3_600_000 })
  return keys
}

function selectJwk(keys, kid) {
  if (kid) return keys.find((k) => k && k.kid === kid) || null
  return keys.length === 1 ? keys[0] : null
}

function base64UrlToBytes(value) {
  const padded = String(value || '').replace(/-/g, '+').replace(/_/g, '/')
  if (!/^[A-Za-z0-9+/]*$/.test(padded) || padded.length % 4 === 1) {
    throw new Error('invalid base64url')
  }
  const padding = padded.length % 4 === 0 ? '' : '='.repeat(4 - (padded.length % 4))
  const binary = atob(padded + padding)
  const out = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i)
  return out
}

export function atob(input) {
  if (typeof globalThis.atob === 'function') return globalThis.atob(input)
  return Buffer.from(input, 'base64').toString('binary')
}

export async function verifyToken(token, env) {
  const parts = String(token || '').split('.')
  if (parts.length !== 3) return null
  const [headerPart, payloadPart, signaturePart] = parts
  let header
  let signedBytes
  try {
    header = JSON.parse(new TextDecoder().decode(base64UrlToBytes(headerPart)))
    signedBytes = base64UrlToBytes(signaturePart)
  } catch {
    return null
  }
  if (!header || typeof header !== 'object') return null
  const signingInput = encoder.encode(`${headerPart}.${payloadPart}`)

  if (env.AUTH_MODE === 'test') {
    if (header.alg !== 'HS256' || !env.TEST_JWT_SECRET) return null
    const key = await crypto.subtle.importKey(
      'raw', encoder.encode(env.TEST_JWT_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
    )
    const ok = await crypto.subtle.verify('HMAC', key, signedBytes, signingInput)
    if (!ok) return null
  } else {
    if ((header.alg !== 'RS256' && header.alg !== 'ES256') || !env.SUPABASE_URL) return null
    let keys = await getJwks(env.SUPABASE_URL)
    let jwk = selectJwk(keys, header.kid)
    if (!jwk && header.kid) {
      // Key rotation: refresh JWKS once before rejecting an unknown kid; never fall back to keys[0].
      keys = await getJwks(env.SUPABASE_URL, { force: true })
      jwk = selectJwk(keys, header.kid)
    }
    if (!jwk) return null
    const algorithm = header.alg === 'ES256'
      ? { name: 'ECDSA', namedCurve: 'P-256' }
      : { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }
    const key = await crypto.subtle.importKey('jwk', jwk, algorithm, false, ['verify'])
    const signature = header.alg === 'ES256' ? derToRaw(signedBytes) : signedBytes
    if (!signature) return null
    const ok = await crypto.subtle.verify(
      header.alg === 'ES256' ? { name: 'ECDSA', hash: 'SHA-256' } : 'RSASSA-PKCS1-v1_5',
      key, signature, signingInput
    )
    if (!ok) return null
  }

  let claims
  try {
    claims = JSON.parse(new TextDecoder().decode(base64UrlToBytes(payloadPart)))
  } catch {
    return null
  }
  if (!claims || typeof claims !== 'object') return null
  const nowSeconds = Math.floor(Date.now() / 1000)
  if (typeof claims.exp !== 'number' || !Number.isFinite(claims.exp) || claims.exp <= nowSeconds) return null
  if (claims.nbf !== undefined && (typeof claims.nbf !== 'number' || !Number.isFinite(claims.nbf) || claims.nbf > nowSeconds + 30)) {
    return null
  }
  if (env.SUPABASE_URL) {
    const base = env.SUPABASE_URL.replace(/\/+$/, '')
    const expectedIss = `${base}/auth/v1`
    if (env.AUTH_MODE !== 'test') {
      if (claims.iss !== expectedIss && claims.iss !== `${expectedIss}/`) return null
    } else if (claims.iss !== undefined) {
      if (claims.iss !== expectedIss && claims.iss !== `${expectedIss}/` && claims.iss !== base) return null
    }
  }
  if (!claims.sub || typeof claims.sub !== 'string') return null
  return { sub: claims.sub, email: typeof claims.email === 'string' ? claims.email : '' }
}

/** Converts an ECDSA P-256 signature (raw 64-byte IEEE P1363 or ASN.1 DER) into 64-byte r||s. */
export function derToRaw(der) {
  if (!(der instanceof Uint8Array)) return null
  if (der.length === 64) return der
  if (der.length < 8 || der[0] !== 0x30) return null
  let offset = 1
  const readLength = () => {
    if (offset >= der.length) return -1
    const first = der[offset++]
    if ((first & 0x80) === 0) return first
    const count = first & 0x7f
    if (count === 0 || count > 2 || offset + count > der.length) return -1
    let length = 0
    for (let i = 0; i < count; i++) length = (length << 8) | der[offset++]
    return length
  }
  const readInteger = () => {
    if (offset >= der.length || der[offset++] !== 0x02) return null
    const len = readLength()
    if (len <= 0 || offset + len > der.length) return null
    let slice = der.subarray(offset, offset + len)
    offset += len
    // Strip optional single leading 0x00 sign byte on positive ASN.1 INTEGER.
    if (slice.length > 1 && slice[0] === 0x00) slice = slice.subarray(1)
    if (slice.length > 32) return null
    return slice
  }
  const seqLen = readLength()
  if (seqLen < 0 || offset + seqLen !== der.length) return null
  const r = readInteger()
  const s = readInteger()
  if (!r || !s || offset !== der.length) return null
  const out = new Uint8Array(64)
  out.set(r, 32 - r.length)
  out.set(s, 64 - s.length)
  return out
}

export async function requireUser(request, env) {
  const header = request.headers.get('Authorization') || ''
  const match = /^Bearer (.+)$/.exec(header.trim())
  if (!match) return null
  const claims = await verifyToken(match[1], env).catch(() => null)
  if (!claims) return null
  return claims
}

export async function turnstileVerify(token, env, remoteIp) {
  if (env.AUTH_MODE === 'test' && env.TURNSTILE_SECRET === 'test-secret') return true
  if (!env.TURNSTILE_SECRET) return false
  const body = new URLSearchParams({ secret: env.TURNSTILE_SECRET, response: String(token || '') })
  if (remoteIp) body.set('remoteip', remoteIp)
  const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST',
    body
  })
  const result = await response.json().catch(() => ({}))
  return result.success === true
}
