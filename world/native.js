/** Narrow Android integration. This module is inert on the ordinary website. */
import { SOURCES } from './catalog.js';

export function configureDailyHost(store) {
  const bridge = globalThis.OmniWorldHost;
  if (typeof bridge?.postMessage !== 'function') return false;
  bridge.postMessage(JSON.stringify({ type: 'schedule', enabled: store.dailyRefresh,
    sources: SOURCES.filter((s) => store.sources[s.id]?.enabled).map((s) => s.id) }));
  return true;
}

export async function loadBackgroundSnapshot(store) {
  if (typeof globalThis.OmniWorldHost?.postMessage !== 'function') return { imported: 0 };
  try {
    const response = await store.fetchImpl('https://appassets.androidplatform.net/world-cache/latest.json', { cache: 'no-store', credentials: 'omit' });
    if (response.status === 404) return { imported: 0 };
    if (!response.ok) throw new Error('Background cache could not be read.');
    const text = await response.text();
    if (text.length > 30_000_000) throw new Error('Background cache exceeds the safety limit.');
    return await store.importBackground(JSON.parse(text));
  } catch (error) { return { imported: 0, error: error.message }; }
}
