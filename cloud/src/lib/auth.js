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

export async function getJwks(supabaseUrl) {
  const url = `${supabaseUrl.replace(/\/$/, '')}/auth/v1/.well-known/jwks.json`
  const cached = jwksCache.get(url)
  if (cached && Date.now() < cached.expiresAt) return cached.keys
  const response = await fetch(url)
  if (!response.ok) throw new Error(`could not fetch Supabase JWKS (${response.status})`)
  const body = await response.json()
  const keys = Array.isArray(body.keys) ? body.keys : []
  jwksCache.set(url, { keys, expiresAt: Date.now() + 3_600_000 })
  return keys
}

function base64UrlToBytes(value) {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/')
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
  try {
    header = JSON.parse(new TextDecoder().decode(base64UrlToBytes(headerPart)))
  } catch {
    return null
  }
  const signedBytes = base64UrlToBytes(signaturePart)
  const signingInput = encoder.encode(`${headerPart}.${payloadPart}`)

  if (env.AUTH_MODE === 'test') {
    if (header.alg !== 'HS256' || !env.TEST_JWT_SECRET) return null
    const key = await crypto.subtle.importKey(
      'raw', encoder.encode(env.TEST_JWT_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
    )
    const ok = await crypto.subtle.verify('HMAC', key, signedBytes, signingInput)
    if (!ok) return null
  } else {
    if (header.alg !== 'RS256' && header.alg !== 'ES256') return null
    const keys = await getJwks(env.SUPABASE_URL)
    const jwk = keys.find((k) => k.kid === header.kid) ?? keys[0]
    if (!jwk) return null
    const algorithm = header.alg === 'ES256'
      ? { name: 'ECDSA', namedCurve: 'P-256' }
      : { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }
    const key = await crypto.subtle.importKey('jwk', jwk, algorithm, false, ['verify'])
    const signature = header.alg === 'ES256' ? derToRaw(signedBytes) : signedBytes
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
  const nowSeconds = Math.floor(Date.now() / 1000)
  if (typeof claims.exp !== 'number' || claims.exp <= nowSeconds) return null
  if (env.SUPABASE_URL && claims.iss && !claims.iss.startsWith(env.SUPABASE_URL.replace(/\/$/, ''))) return null
  if (!claims.sub) return null
  return { sub: String(claims.sub), email: claims.email ?? '' }
}

/** JWKS signature is DER-encoded; WebCrypto wants the fixed-length r||s form. */
function derToRaw(der) {
  if (der.length === 64) return der
  let offset = 2
  const readLength = () => {
    const first = der[offset++]
    if (first < 0x80) return first
    const count = first & 0x7f
    let length = 0
    for (let i = 0; i < count; i++) length = (length << 8) | der[offset++]
    return length
  }
  readLength()
  const rStart = offset + 1
  const rLength = readLength() - 1
  const r = der.slice(rStart, rStart + rLength)
  const sStart = rStart + rLength + 1
  const sLength = readLength() - 1
  const s = der.slice(sStart, sStart + sLength)
  const out = new Uint8Array(64)
  out.set(r.subarray(-32), 32 - Math.min(32, r.length))
  out.set(s.subarray(-32), 64 - Math.min(32, s.length))
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
