/** Boots the exact offline entry point that Gradle packages in the Android APK. */
import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';
import { NOW, fixtures, response } from '../fixtures/world.mjs';
import { saveWorldFile } from '../../world/export.js';
import { configureDailyHost, loadBackgroundSnapshot } from '../../world/native.js';

let dom; let win; let app;
const hostMessages = []; const exports = []; const calls = [];
const set = (key, value) => Object.defineProperty(globalThis, key, { configurable: true, writable: true, value });
before(async () => {
  const html = readFileSync(new URL('../../world/embed.html', import.meta.url), 'utf8');
  dom = new JSDOM(html, { url: 'https://appassets.androidplatform.net/assets/world-monitor/world/embed.html', pretendToBeVisual: true, runScripts: 'outside-only' }); win = dom.window;
  for (const key of ['window', 'document', 'navigator', 'location', 'history', 'localStorage', 'FileReader', 'File', 'Blob', 'Event', 'Node']) set(key, key === 'window' ? win : win[key]);
  set('confirm', () => true);
  set('OmniWorldHost', { postMessage: (text) => hostMessages.push(JSON.parse(text)) });
  set('OmniWorldExport', { postMessage: (text) => exports.push(JSON.parse(text)) });
  set('fetch', async (url) => {
    calls.push(String(url));
    if (String(url).endsWith('/world-cache/latest.json')) return response({ version: 1, sources: [{ id: 'usgs', fetchedAt: NOW - 10000, data: fixtures.usgs }] });
    throw new Error(`No external requests allowed during packaged boot: ${url}`);
  });
  await import('../../world/embed.js'); app = globalThis.__worldMonitor; await app.ready;
  app.store.clock = () => NOW;
  // Real devices use the system clock. Import once explicitly with the fixed test clock as well.
  await app.store.importBackground({ version: 1, sources: [{ id: 'usgs', fetchedAt: NOW - 10000, data: fixtures.usgs }] });
});
after(() => { app?.stop(); dom?.window.close(); delete globalThis.OmniWorldHost; delete globalThis.OmniWorldExport; });

test('packaged entry point uses real monitor, no remote bootstrap, and a cached daily snapshot', () => {
  assert.ok(app.view); assert.match(win.document.body.textContent, /World Monitor/); assert.equal(app.store.events.length, 2);
  assert.equal(app.store.health().usgs.status, 'cached'); assert.ok(calls.every((url) => url.startsWith('https://appassets.androidplatform.net/')));
  const csp = win.document.querySelector('meta[http-equiv="Content-Security-Policy"]').content;
  assert.match(csp, /script-src 'self'/); assert.match(csp, /frame-src 'none'/);
});
test('native daily host receives only known built-in source IDs, never arbitrary URLs', async () => {
  await app.store.addSource({ name: 'Custom', url: 'https://example.org/data', parser: 'generic', intervalHours: 24 });
  await app.store.setDaily(true); assert.equal(configureDailyHost(app.store), true);
  const message = hostMessages.at(-1); assert.equal(message.type, 'schedule'); assert.equal(message.enabled, true); assert.ok(message.sources.includes('usgs')); assert.ok(message.sources.every((id) => !id.startsWith('custom-'))); assert.equal(message.url, undefined);
});
test('native export channel receives bounded text and rejects unsafe names and MIME types', () => {
  saveWorldFile('omnishield-world-test.csv', 'title\nexample', 'text/csv'); assert.equal(exports.at(-1).content, 'title\nexample'); assert.equal(exports.at(-1).mime, 'text/csv');
  assert.throws(() => saveWorldFile('../escape.txt', 'bad', 'text/plain'));
  assert.throws(() => saveWorldFile('omnishield-world-..json', 'bad'));
  assert.throws(() => saveWorldFile('omnishield-world-' + 'a'.repeat(100) + '.json', '{}'));
  assert.throws(() => saveWorldFile('omnishield-world-test.json', '界'.repeat(2_700_000)), /8 MB/);
  assert.throws(() => saveWorldFile('omnishield-world-test.html', '<script>', 'text/html'));
});
test('native source links route through the narrow HTTPS host message, not a remote WebView page', () => {
  app.view.openDetail(app.store.events[0]); const anchor = win.document.querySelector('#world-detail a');
  anchor.dispatchEvent(new win.MouseEvent('click', { bubbles: true, cancelable: true }));
  assert.equal(hostMessages.at(-1).type, 'open'); assert.match(hostMessages.at(-1).url, /^https:\/\/earthquake\.usgs\.gov/);
});


test('native cache reader rejects a declared oversized response before reading its body', async () => {
  let read = false;
  const result = await loadBackgroundSnapshot({ fetchImpl: async () => ({ ok: true, status: 200, headers: new Headers({ 'content-length': '30000001' }), text: async () => { read = true; return '{}'; } }) });
  assert.equal(result.imported, 0); assert.match(result.error, /safety limit/); assert.equal(read, false);
});
test('native cache absence is normal, while an invalid payload is surfaced as a cache error', async () => {
  assert.deepEqual(await loadBackgroundSnapshot({ fetchImpl: async () => response('', 404) }), { imported: 0 });
  const result = await loadBackgroundSnapshot({ fetchImpl: async () => response('<html>unexpected</html>') });
  assert.match(result.error, /invalid JSON/);
});
