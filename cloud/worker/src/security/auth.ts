import type { AppConfig, Env } from '../env';
import { ApiError, unauthorized } from '../http';
import { base64UrlToText, timingSafeEqual } from '../util/core';

/**
 * Supabase Auth JWT verification.
 *
 * Modern Supabase projects sign access tokens with an asymmetric key (ES256/RS256) and
 * expose the public keys at `${SUPABASE_URL}/auth/v1/.well-known/jwks.json`.
 * Legacy projects use a shared HS256 secret. Both paths are supported here; the worker
 * never trusts a token it has not cryptographically verified.
 */
export interface SupabaseClaims {
  sub: string;
  email?: string;
  role?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  iss?: string;
  user_metadata?: { display_name?: string; full_name?: string };
}

interface JwtHeader {
  alg: string;
  kid?: string;
  typ?: string;
}

interface Jwk {
  kty: string;
  kid?: string;
  n?: string;
  e?: string;
  crv?: string;
  x?: string;
  y?: string;
  alg?: string;
}

const jwksCache = new Map<string, { keys: Jwk[]; fetchedAt: number }>();
const JWKS_TTL_MS = 10 * 60 * 1000;

function decodeSegment(segment: string): unknown {
  return JSON.parse(base64UrlToText(segment));
}

function b64urlToBytes(input: string): Uint8Array {
  const padded = input.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(input.length / 4) * 4, '=');
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

const encoder = new TextEncoder();

type VerifyParams = { name: string; hash?: string };

interface ImportedKey {
  key: CryptoKey;
  params: VerifyParams;
}

async function importJwk(jwk: Jwk, alg: string): Promise<ImportedKey> {
  if (jwk.kty === 'RSA') {
    const key = await crypto.subtle.importKey(
      'jwk',
      { kty: 'RSA', n: jwk.n, e: jwk.e, alg: 'RS256', ext: true } as JsonWebKey,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify']
    );
    return { key, params: { name: 'RSASSA-PKCS1-v1_5' } };
  }
  if (jwk.kty === 'EC') {
    const curve = jwk.crv === 'P-384' ? 'P-384' : 'P-256';
    const hash = alg === 'ES384' || curve === 'P-384' ? 'SHA-384' : 'SHA-256';
    const key = await crypto.subtle.importKey(
      'jwk',
      { kty: 'EC', crv: curve, x: jwk.x, y: jwk.y, ext: true } as JsonWebKey,
      { name: 'ECDSA', namedCurve: curve },
      false,
      ['verify']
    );
    return { key, params: { name: 'ECDSA', hash } };
  }
  throw unauthorized('Unsupported signing key type', 'unsupported_jwk');
}

async function fetchJwks(env: Env): Promise<Jwk[]> {
  const url = `${(env.SUPABASE_URL ?? '').replace(/\/$/, '')}/auth/v1/.well-known/jwks.json`;
  const cached = jwksCache.get(url);
  if (cached && Date.now() - cached.fetchedAt < JWKS_TTL_MS) return cached.keys;

  const response = await fetch(url, { headers: { Accept: 'application/json' } });
  if (!response.ok) {
    throw new ApiError(503, 'jwks_unavailable', 'Could not fetch Supabase signing keys');
  }
  const body = (await response.json()) as { keys?: Jwk[] };
  const keys = body.keys ?? [];
  jwksCache.set(url, { keys, fetchedAt: Date.now() });
  return keys;
}

export async function verifySupabaseJwt(env: Env, token: string): Promise<SupabaseClaims> {
  const segments = token.split('.');
  if (segments.length !== 3) throw unauthorized('Malformed access token', 'invalid_token');

  let header: JwtHeader;
  let claims: SupabaseClaims;
  try {
    header = decodeSegment(segments[0]) as JwtHeader;
    claims = decodeSegment(segments[1]) as SupabaseClaims;
  } catch {
    throw unauthorized('Malformed access token', 'invalid_token');
  }

  const signingInput = encoder.encode(`${segments[0]}.${segments[1]}`) as unknown as ArrayBuffer;
  const signature = b64urlToBytes(segments[2]) as unknown as ArrayBuffer;

  if (header.alg === 'HS256') {
    if (!env.SUPABASE_JWT_SECRET) {
      throw unauthorized('This project signs tokens with HS256 but SUPABASE_JWT_SECRET is not configured', 'jwt_secret_missing');
    }
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(env.SUPABASE_JWT_SECRET) as unknown as ArrayBuffer,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );
    const ok = await crypto.subtle.verify('HMAC', key, signature, signingInput);
    if (!ok) throw unauthorized('Invalid access token signature', 'invalid_token_signature');
  } else if (header.alg === 'RS256' || header.alg === 'ES256' || header.alg === 'ES384') {
    const keys = await fetchJwks(env);
    const candidates = keys.filter((k) => (header.kid ? k.kid === header.kid : true));
    let verified = false;
    for (const jwk of candidates) {
      try {
        const { key, params } = await importJwk(jwk, header.alg);
        verified = await crypto.subtle.verify(
          params as unknown as Parameters<typeof crypto.subtle.verify>[0],
          key,
          signature,
          signingInput
        );
        if (verified) break;
      } catch {
        // try the next key
      }
    }
    if (!verified) throw unauthorized('Invalid access token signature', 'invalid_token_signature');
  } else {
    throw unauthorized(`Unsupported access token algorithm: ${header.alg}`, 'unsupported_jwt_alg');
  }

  const nowSeconds = Math.floor(Date.now() / 1000);
  if (claims.exp !== undefined && claims.exp + 30 < nowSeconds) {
    throw new ApiError(401, 'token_expired', 'Access token has expired');
  }
  if (claims.nbf !== undefined && claims.nbf - 30 > nowSeconds) {
    throw unauthorized('Access token is not valid yet', 'token_not_yet_valid');
  }
  if (!claims.sub) throw unauthorized('Access token has no subject', 'invalid_token');
  return claims;
}

export interface AuthedUser {
  id: string;
  email: string | null;
  displayName: string | null;
  quotaBytes: number;
  usedBytes: number;
  status: string;
  tier: string;
  clientEncryption: boolean;
  createdAt: number;
}

interface UserRow {
  id: string;
  email: string | null;
  display_name: string | null;
  tier: string;
  status: string;
  quota_bytes: number;
  used_bytes: number;
  client_encryption: number;
  created_at: number;
}

function toUser(row: UserRow): AuthedUser {
  return {
    id: row.id,
    email: row.email,
    displayName: row.display_name,
    quotaBytes: row.quota_bytes,
    usedBytes: row.used_bytes,
    status: row.status,
    tier: row.tier,
    clientEncryption: row.client_encryption === 1,
    createdAt: row.created_at,
  };
}

/**
 * Resolves (and lazily provisions) the local user row for a verified Supabase identity.
 */
export async function resolveUser(env: Env, config: AppConfig, claims: SupabaseClaims): Promise<AuthedUser> {
  const existing = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(claims.sub).first<UserRow>();
  const now = Date.now();
  const email = claims.email ?? null;
  const displayName =
    claims.user_metadata?.display_name ?? claims.user_metadata?.full_name ?? email?.split('@')[0] ?? null;

  if (!existing) {
    await env.DB.prepare(
      `INSERT INTO users (id, email, display_name, tier, status, quota_bytes, used_bytes, client_encryption, created_at, last_seen_at)
       VALUES (?, ?, ?, 'free', 'active', ?, 0, 0, ?, ?)
       ON CONFLICT(id) DO NOTHING`
    )
      .bind(claims.sub, email, displayName, config.defaultQuotaBytes, now, now)
      .run();
    const created = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(claims.sub).first<UserRow>();
    if (!created) throw new ApiError(500, 'user_provision_failed', 'Could not provision user profile');
    return toUser(created);
  }

  await env.DB.prepare('UPDATE users SET last_seen_at = ?, email = COALESCE(?, email) WHERE id = ?')
    .bind(now, email, claims.sub)
    .run();
  return toUser(existing);
}

export function requireActive(user: AuthedUser): void {
  if (user.status !== 'active') {
    throw new ApiError(403, 'account_suspended', 'This account is suspended. Contact support.');
  }
}

export { timingSafeEqual };
