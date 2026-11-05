import type { Env } from '../env';
import { ApiError } from '../http';

/**
 * Cloudflare Turnstile verification (free, no payment method required).
 *
 * Used for bot protection on account creation and account recovery. When TURNSTILE_SECRET
 * is not configured the check is skipped *and reported* so the client can surface
 * "bot protection disabled" instead of pretending it is active.
 */
export interface TurnstileResult {
  success: boolean;
  skipped: boolean;
  errorCodes: string[];
}

export async function verifyTurnstile(
  env: Env,
  token: string | undefined,
  remoteIp: string | null
): Promise<TurnstileResult> {
  if (!env.TURNSTILE_SECRET) {
    return { success: true, skipped: true, errorCodes: ['turnstile-not-configured'] };
  }
  if (!token) {
    return { success: false, skipped: false, errorCodes: ['missing-input-response'] };
  }
  const body = new FormData();
  body.append('secret', env.TURNSTILE_SECRET);
  body.append('response', token);
  if (remoteIp) body.append('remoteip', remoteIp);

  const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST',
    body,
  });
  if (!response.ok) {
    throw new ApiError(503, 'turnstile_unavailable', 'Bot protection service is unreachable');
  }
  const result = (await response.json()) as { success: boolean; 'error-codes'?: string[] };
  return {
    success: result.success === true,
    skipped: false,
    errorCodes: result['error-codes'] ?? [],
  };
}
