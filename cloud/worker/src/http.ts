import type { AppConfig, Env } from './env';
import { sha256Hex } from './util/core';

/** Structured API error with a stable machine-readable code. */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly details?: unknown
  ) {
    super(message);
  }
}

export const badRequest = (message: string, code = 'bad_request', details?: unknown) =>
  new ApiError(400, code, message, details);
export const unauthorized = (message = 'Authentication required', code = 'unauthorized') =>
  new ApiError(401, code, message);
export const forbidden = (message = 'You do not own this resource', code = 'forbidden') =>
  new ApiError(403, code, message);
export const notFound = (message = 'Not found', code = 'not_found') => new ApiError(404, code, message);
export const conflict = (message: string, code = 'conflict', details?: unknown) =>
  new ApiError(409, code, message, details);
export const tooLarge = (message: string, code = 'payload_too_large', details?: unknown) =>
  new ApiError(413, code, message, details);
export const quotaExceeded = (message: string, details?: unknown) =>
  new ApiError(507, 'quota_exceeded', message, details);
export const rateLimited = (message: string, retryAfter: number) => {
  const err = new ApiError(429, 'rate_limited', message, { retryAfter });
  return err;
};
export const notImplemented = (message: string) => new ApiError(501, 'not_implemented', message);

export interface RequestContext {
  req: Request;
  url: URL;
  env: Env;
  config: AppConfig;
  ipHash: string;
  userAgent: string;
  requestId: string;
  startedAt: number;
}

export function corsHeaders(config: AppConfig, request: Request): Record<string, string> {
  const origin = request.headers.get('Origin') ?? '';
  const allowed =
    config.allowedOrigins.includes('*') || config.allowedOrigins.includes(origin) ? origin || '*' : '';
  const headers: Record<string, string> = {
    'Access-Control-Allow-Methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS,HEAD',
    'Access-Control-Allow-Headers': 'Authorization,Content-Type,X-Requested-With,X-Client-Version,X-Turnstile-Token',
    'Access-Control-Max-Age': '86400',
    'Access-Control-Expose-Headers': 'Content-Length,Content-Range,ETag,X-Request-Id,Retry-After',
    Vary: 'Origin',
  };
  if (allowed) headers['Access-Control-Allow-Origin'] = allowed;
  return headers;
}

export function json(
  body: unknown,
  status = 200,
  extraHeaders: Record<string, string> = {}
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      ...extraHeaders,
    },
  });
}

export function errorResponse(err: ApiError, cors: Record<string, string>, requestId: string): Response {
  const headers: Record<string, string> = { ...cors, 'X-Request-Id': requestId };
  if (err.status === 429) {
    const retryAfter = Number((err.details as { retryAfter?: number } | undefined)?.retryAfter ?? 60);
    headers['Retry-After'] = String(Math.max(1, Math.ceil(retryAfter)));
  }
  return json(
    {
      error: {
        code: err.code,
        message: err.message,
        details: err.details ?? null,
        requestId,
      },
    },
    err.status,
    headers
  );
}

/** Hashes the client IP so audit logs never contain raw addresses (privacy). */
export async function hashIp(req: Request, secret: string): Promise<string> {
  const ip =
    req.headers.get('CF-Connecting-IP') ??
    req.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ??
    'unknown';
  const digest = await sha256Hex(`${secret}:${ip}`);
  return digest.slice(0, 32);
}

export async function readJson<T>(req: Request, config?: AppConfig): Promise<T> {
  const contentType = req.headers.get('Content-Type') ?? '';
  if (!contentType.toLowerCase().includes('application/json')) {
    throw badRequest('Content-Type must be application/json', 'unsupported_media_type');
  }
  const limit = config ? Math.min(config.maxSingleUploadBytes, 256 * 1024) : 256 * 1024;
  const text = await req.text();
  if (text.length > limit) throw tooLarge('JSON body too large', 'payload_too_large', { limit });
  try {
    return JSON.parse(text) as T;
  } catch {
    throw badRequest('Malformed JSON body', 'invalid_json');
  }
}

export function requireString(value: unknown, field: string, maxLength = 400): string {
  if (typeof value !== 'string' || !value.trim()) {
    throw badRequest(`Field "${field}" is required`, 'invalid_field', { field });
  }
  if (value.length > maxLength) {
    throw badRequest(`Field "${field}" exceeds ${maxLength} characters`, 'invalid_field', { field });
  }
  return value;
}

export function optionalString(value: unknown, maxLength = 400): string | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== 'string') throw badRequest('Expected a string value', 'invalid_field');
  if (value.length > maxLength) throw badRequest(`Value exceeds ${maxLength} characters`, 'invalid_field');
  return value;
}
