/** The Android host exposes only an origin-restricted, user-confirmed document export channel. */
import { download } from '../ui/dom.js';

export function saveWorldFile(filename, content, mime = 'application/json') {
  if (!/^omnishield-world-[a-z0-9.-]+$/.test(filename)) throw new Error('Invalid export filename.');
  if (!['application/json', 'text/csv', 'text/markdown', 'text/plain'].includes(mime)) throw new Error('Unsupported export type.');
  if (new TextEncoder().encode(content).length > 8_000_000) throw new Error('This export exceeds 8 MB. Narrow the filters and try again.');
  const bridge = globalThis.OmniWorldExport;
  if (typeof bridge?.postMessage === 'function') bridge.postMessage(JSON.stringify({ filename, content, mime }));
  else download(filename, content, mime);
}

export async function readWatchFile(file) {
  if (!file || file.size > 128_000) throw new Error('Choose a JSON watchlist smaller than 128 KB.');
  if (typeof file.text === 'function') return file.text();
  return new Promise((resolve, reject) => {
    const reader = new FileReader(); reader.onload = () => resolve(String(reader.result));
    reader.onerror = () => reject(new Error('The selected file could not be read.')); reader.readAsText(file);
  });
}
