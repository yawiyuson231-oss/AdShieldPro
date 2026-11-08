/** Narrow Android integration. This module is inert on the ordinary website. */
import { SOURCES } from './catalog.js';
import { fetchJson, SourceError } from './network.js';

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
    const snapshot = await fetchJson('https://appassets.androidplatform.net/world-cache/latest.json', {
      maxBytes: 30_000_000, timeoutMs: 15_000,
      fetchImpl: async (url, options) => {
        const response = await store.fetchImpl(url, options);
        if (response.status === 404) throw new SourceError('No daily snapshot yet.', 'not-found');
        return response;
      }
    });
    return await store.importBackground(snapshot);
  } catch (error) { return error.code === 'not-found' ? { imported: 0 } : { imported: 0, error: error.message }; }
}
