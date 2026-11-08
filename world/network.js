/** Bounded transport. Only callers' fixed catalogue URLs are fetched; no proxy or credentials. */
import { LIMITS } from './catalog.js';

export class SourceError extends Error {
  constructor(message, code = 'error', retryAt = null) {
    super(message); this.name = 'SourceError'; this.code = code; this.retryAt = retryAt;
  }
}

export function retryTime(response, now) {
  const header = response.headers?.get?.('retry-after');
  const seconds = header && /^\d+$/.test(header) ? Number(header) : NaN;
  const date = header ? Date.parse(header) : NaN;
  const reset = Number(response.headers?.get?.('x-ratelimit-reset')) * 1000;
  const target = Number.isFinite(seconds) ? now + seconds * 1000 : Number.isFinite(date) ? date : reset > now ? reset : now + 60_000;
  return Math.min(now + 86_400_000, Math.max(now + 60_000, target));
}

export async function fetchJson(url, { fetchImpl = globalThis.fetch?.bind(globalThis), signal, timeoutMs = LIMITS.timeoutMs, maxBytes = LIMITS.bytes, accept = 'application/json', now = Date.now() } = {}) {
  if (!fetchImpl) throw new SourceError('Network requests are unavailable in this environment.', 'offline');
  const controller = new AbortController();
  const cancel = () => controller.abort();
  if (signal?.aborted) throw new SourceError('Refresh cancelled.', 'cancelled');
  signal?.addEventListener('abort', cancel, { once: true });
  let timedOut = false;
  const timer = setTimeout(() => { timedOut = true; controller.abort(); }, timeoutMs);
  // The race also bounds implementations that fail to reject after an abort.
  let rejectAbort;
  const aborted = new Promise((_, reject) => { rejectAbort = () => reject(new SourceError(timedOut ? 'Source timed out.' : 'Refresh cancelled.', timedOut ? 'offline' : 'cancelled')); });
  controller.signal.addEventListener('abort', rejectAbort, { once: true });
  try {
    return await Promise.race([aborted, (async () => {
      const response = await fetchImpl(url, { signal: controller.signal, headers: { accept }, cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer' });
      if (controller.signal.aborted) throw new SourceError('Refresh cancelled.', 'cancelled');
      if (response.url && new URL(response.url).protocol !== 'https:') throw new SourceError('Source redirected away from HTTPS.');
      if (response.status === 429 || (response.status === 403 && response.headers?.get?.('x-ratelimit-remaining') === '0')) {
        throw new SourceError(`Provider rate limit (HTTP ${response.status}). The cached copy is retained.`, 'rate-limited', retryTime(response, now));
      }
      if (!response.ok) throw new SourceError(`Provider returned HTTP ${response.status}.`, response.status >= 500 ? 'offline' : 'error');
      const length = Number(response.headers?.get?.('content-length'));
      if (Number.isFinite(length) && length > maxBytes) throw new SourceError(`Source exceeds the ${maxBytes / 1_000_000} MB safety limit.`);
      let text;
      if (response.body?.getReader) {
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        const chunks = [];
        let size = 0;
        try {
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            size += value.byteLength;
            if (size > maxBytes) throw new SourceError(`Source exceeds the ${maxBytes / 1_000_000} MB safety limit.`);
            chunks.push(decoder.decode(value, { stream: true }));
          }
          chunks.push(decoder.decode()); text = chunks.join('');
        } catch (error) { await reader.cancel().catch(() => {}); throw error; }
        finally { reader.releaseLock(); }
      } else {
        text = await response.text();
        if (new TextEncoder().encode(text).length > maxBytes) throw new SourceError('Source exceeds the response safety limit.');
      }
      try { return JSON.parse(text); } catch { throw new SourceError('Source returned invalid JSON, not a usable feed.'); }
    })()]);
  } catch (error) {
    if (error instanceof SourceError) throw error;
    if (controller.signal.aborted) throw new SourceError(timedOut ? 'Source timed out.' : 'Refresh cancelled.', timedOut ? 'offline' : 'cancelled');
    throw new SourceError('Could not reach this source. Check your connection; the provider may be unavailable or disallow browser access (CORS).', 'offline');
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', cancel);
    controller.signal.removeEventListener('abort', rejectAbort);
  }
}
