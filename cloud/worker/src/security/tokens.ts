import { base64UrlDecode, base64UrlEncode, base64UrlToText, hmacSha256, randomToken, timingSafeEqual } from '../util/core';
import { ApiError, unauthorized } from '../http';

/**
 * Short-lived, HMAC-SHA256 signed capability tokens.
 *
 * These are what the Android client receives instead of cloud credentials: a token that
 * authorises one narrow action (download one object revision, upload one part) for a few
 * minutes. R2 / Supabase keys never leave the Worker.
 */
export type TokenPurpose = 'download' | 'upload-part' | 'share-download' | 'backup-download' | 'preview';

export interface TokenPayload {
  /** purpose */
  p: TokenPurpose;
  /** subject: owning user id (or 'share:<id>' for anonymous share downloads) */
  sub: string;
  /** issued at (seconds) */
  iat: number;
  /** expires at (seconds) */
  exp: number;
  /** unique token id, also used for single-use enforcement */
  jti: string;
  nodeId?: string;
  version?: number;
  storageKey?: string;
  uploadId?: string;
  partNumber?: number;
  shareId?: string;
  /** exact byte range this token may read, if pinned */
  maxBytes?: number;
}

function canonical(payload: TokenPayload): string {
  // Deterministic key order keeps signatures reproducible.
  const ordered: Record<string, unknown> = {
    p: payload.p,
    sub: payload.sub,
    iat: payload.iat,
    exp: payload.exp,
    jti: payload.jti,
  };
  for (const key of Object.keys(payload).sort()) {
    if (key in ordered) continue;
    const value = (payload as unknown as Record<string, unknown>)[key];
    if (value !== undefined) ordered[key] = value;
  }
  return JSON.stringify(ordered);
}

export async function signToken(secret: string, payload: Omit<TokenPayload, 'iat' | 'exp' | 'jti'> & Partial<TokenPayload>, ttlSeconds: number): Promise<{ token: string; payload: TokenPayload; expiresAt: number }> {
  const issuedAt = Math.floor(Date.now() / 1000);
  const full: TokenPayload = {
    ...payload,
    iat: issuedAt,
    exp: issuedAt + Math.max(5, Math.min(ttlSeconds, 3600)),
    jti: randomToken(12),
  } as TokenPayload;
  const body = base64UrlEncode(canonical(full));
  const signature = await hmacSha256(secret, body);
  return {
    token: `${body}.${base64UrlEncode(signature)}`,
    payload: full,
    expiresAt: full.exp * 1000,
  };
}

export async function verifyToken(secret: string, token: string, purpose: TokenPurpose): Promise<TokenPayload> {
  const parts = token.split('.');
  if (parts.length !== 2) throw unauthorized('Malformed signed URL', 'invalid_token');
  const [body, signature] = parts;
  const expected = base64UrlEncode(await hmacSha256(secret, body));
  if (!timingSafeEqual(signature, expected)) {
    throw unauthorized('Invalid signed URL signature', 'invalid_token_signature');
  }
  let payload: TokenPayload;
  try {
    payload = JSON.parse(base64UrlToText(body)) as TokenPayload;
  } catch {
    throw unauthorized('Invalid signed URL payload', 'invalid_token');
  }
  if (payload.p !== purpose) {
    throw unauthorized('Signed URL is not valid for this action', 'wrong_token_purpose');
  }
  if (payload.exp * 1000 <= Date.now()) {
    throw new ApiError(410, 'token_expired', 'This signed link has already expired');
  }
  // Round-trip the base64 decode once so malformed padding can never slip through.
  base64UrlDecode(signature);
  return payload;
}
