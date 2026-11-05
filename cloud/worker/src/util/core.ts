/** Small, dependency-free helpers shared across the worker. */

const encoder = new TextEncoder();

export function randomId(prefix: string): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return `${prefix}_${hex(bytes)}`;
}

export function randomToken(bytesLength = 32): string {
  const bytes = crypto.getRandomValues(new Uint8Array(bytesLength));
  return base64UrlEncode(bytes);
}

export function hex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function base64UrlEncode(input: Uint8Array | string): string {
  const bytes = typeof input === 'string' ? encoder.encode(input) : input;
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64UrlDecode(input: string): Uint8Array {
  const padded = input.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(input.length / 4) * 4, '=');
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function base64UrlToText(input: string): string {
  return new TextDecoder().decode(base64UrlDecode(input));
}

export async function sha256Hex(data: Uint8Array | string): Promise<string> {
  const bytes = typeof data === 'string' ? encoder.encode(data) : data;
  const digest = await crypto.subtle.digest('SHA-256', bytes as unknown as ArrayBuffer);
  return hex(new Uint8Array(digest));
}

export async function hmacSha256(key: string, message: string): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(key) as unknown as ArrayBuffer,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
  const signature = await crypto.subtle.sign('HMAC', cryptoKey, encoder.encode(message) as unknown as ArrayBuffer);
  return new Uint8Array(signature);
}

/** Constant-time comparison for secret-dependent values. */
export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** PBKDF2-SHA256 password hashing (used for share-link passwords). */
export async function pbkdf2Hash(password: string, saltB64: string, iterations = 120_000): Promise<string> {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password) as unknown as ArrayBuffer,
    'PBKDF2',
    false,
    ['deriveBits']
  );
  const salt = base64UrlDecode(saltB64);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: salt as unknown as ArrayBuffer, iterations, hash: 'SHA-256' },
    keyMaterial,
    256
  );
  return hex(new Uint8Array(bits));
}

export function nowMs(): number {
  return Date.now();
}

export function utcDay(ms: number = Date.now()): string {
  return new Date(ms).toISOString().slice(0, 10);
}

/** Human-readable byte size, used only for log/diagnostic text. */
export function formatBytes(bytes: number): string {
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}

/**
 * Normalises a user supplied name: strips path separators, control characters and
 * reserved device names, and bounds the length. Prevents path traversal in object keys.
 */
export function sanitizeName(raw: string): string {
  const withoutControl = Array.from(String(raw ?? ''))
    .filter((ch) => ch.charCodeAt(0) >= 32 && ch.charCodeAt(0) !== 127)
    .join('');
  const base = withoutControl
    .replace(/[\\/]/g, '_')
    .replace(/^\.+/, '')
    .replace(/[<>:"|?*]/g, '_')
    .trim();
  const safe = base.length ? base : 'untitled';
  return safe.slice(0, 180);
}

/** Safe extension (lowercase, alphanumeric, 1-8 chars) or empty string. */
export function fileExtension(name: string): string {
  const idx = name.lastIndexOf('.');
  if (idx <= 0 || idx === name.length - 1) return '';
  const ext = name.slice(idx + 1).toLowerCase();
  return /^[a-z0-9]{1,8}$/.test(ext) ? ext : '';
}

export function clampInt(value: unknown, min: number, max: number, fallback: number): number {
  const parsed = typeof value === 'number' ? value : Number.parseInt(String(value ?? ''), 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, Math.trunc(parsed)));
}
