/**
 * Integration tests for the v5.1 screens — driven through the real app.js in a
 * real DOM, with only the network boundary mocked. These are behaviour tests: a
 * button that does nothing, a scan that reports progress but inspects no bytes,
 * or a download that claims success without fetching will fail here.
 */
import test, { before, after } from 'node:test';
import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { JSDOM } from 'jsdom';

const ROOT = new URL('../../', import.meta.url);
const read = (p) => readFileSync(new URL(p, ROOT), 'utf8');

let dom;
let win;
let app;
let indexedDbFactory = null;

const EICAR = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';

/** In-memory IDBFactory so the vault exercises its real code path, not localStorage. */
function memoryIndexedDb() {
  const stores = new Map();
  return {
    open() {
      const request = {};
      setTimeout(() => {
        const db = {
          objectStoreNames: { contains: (name) => stores.has(name) },
          createObjectStore: (name) => stores.set(name, new Map()),
          transaction(name) {
            if (!stores.has(name)) stores.set(name, new Map());
            const map = stores.get(name);
            const tx = { error: null };
            const store = {
              get(key) { const r = {}; setTimeout(() => { r.result = map.get(key); r.onsuccess?.(); }, 0); return r; },
              put(value, key) { map.set(key, value); },
              delete(key) { map.delete(key); },
              getAllKeys() { const r = {}; setTimeout(() => { r.result = [...map.keys()]; r.onsuccess?.(); }, 0); return r; }
            };
            setTimeout(() => { if (!tx.error) tx.complete?.(); }, 5);
            return {
              objectStore: () => store,
              set oncomplete(fn) { tx.complete = fn; }, get oncomplete() { return tx.complete; },
              set onerror(fn) { tx.fail = fn; }, get onerror() { return tx.fail; },
              set onabort(fn) { tx.abort = fn; }
            };
          }
        };
        request.result = db;
        request.onupgradeneeded?.();
        request.onsuccess?.();
      }, 0);
      return request;
    }
  };
}

function installFetch() {
  return async (input, init = {}) => {
    const url = new URL(String(input), 'http://localhost:8080/');
    const href = url.href;
    if (href.includes('/assets/') || href.endsWith('manifest.webmanifest')) {
      const relative = href.slice(href.indexOf('/', href.indexOf('://') + 3) + 1);
      try {
        const body = read(relative);
        return { ok: true, status: 200, headers: { get: () => null }, async text() { return body; } };
      } catch {
        return { ok: false, status: 404, headers: { get: () => null }, async text() { return ''; } };
      }
    }
    if (url.hostname === 'api.duckduckgo.com') {
      const query = url.searchParams.get('q');
      return {
        ok: true, status: 200, headers: { get: () => null },
        async json() {
          return {
            Heading: query === 'dns' ? 'Domain Name System' : null,
            AbstractText: query === 'dns' ? 'The DNS maps names to addresses.' : '',
            AbstractSource: 'Wikipedia',
            AbstractURL: 'https://en.wikipedia.org/wiki/DNS',
            RelatedTopics: query === 'dns' ? [{ FirstURL: 'https://example.org/dns', Text: 'Related DNS topic' }] : []
          };
        }
      };
    }
    if (url.hostname === 'vimeo.com') {
      return {
        ok: true, status: 200, headers: { get: () => null },
        async json() { return { title: 'Vimeo Demo', author_name: 'Studio', thumbnail_url: 'https://i.vimeocdn.test/x.jpg', duration: 61 }; }
      };
    }
    if (url.hostname === 'cdn.example') {
      const bytes = new TextEncoder().encode('0123456789abcdef');
      let offset = 0;
      if (url.pathname.endsWith('.mp4')) {
        const request = init || {};
        if (request.method === 'HEAD') {
          return { ok: true, status: 200, url: href, headers: { get: (n) => ({ 'content-length': '16', 'content-type': 'video/mp4', 'accept-ranges': 'bytes' })[n] ?? null } };
        }
        const start = Number(/bytes=(\d+)-/.exec(request.headers?.Range || '')?.[1] || 0);
        offset = start;
        return {
          ok: true, status: start ? 206 : 200, url: href,
          headers: { get: (n) => ({ 'content-length': String(16 - start), 'content-type': 'video/mp4' })[n] ?? null },
          body: {
            getReader: () => ({
              async read() {
                if (offset >= bytes.length) return { done: true, value: undefined };
                const chunk = bytes.subarray(offset, Math.min(bytes.length, offset + 8));
                offset += chunk.length;
                return { done: false, value: chunk };
              }
            })
          }
        };
      }
    }
    if (url.hostname === 'www.youtube.com') {
      return { ok: true, status: 200, headers: { get: () => null }, async json() { return { title: 'A video', author_name: 'Someone' }; } };
    }
    if (href.includes('raw.githubusercontent.com')) return { ok: false, status: 503, headers: { get: () => null }, async text() { return ''; } };
    throw new Error(`unexpected fetch in test: ${href}`);
  };
}

const defineGlobal = (name, value) => Object.defineProperty(globalThis, name, { value, configurable: true, writable: true });

before(async () => {
  dom = await JSDOM.fromFile(fileURLToPath(new URL('index.html', ROOT)), {
    url: 'http://localhost:8080/',
    runScripts: 'outside-only',
    pretendToBeVisual: true
  });
  win = dom.window;
  indexedDbFactory = memoryIndexedDb();

  defineGlobal('window', win);
  defineGlobal('document', win.document);
  defineGlobal('navigator', win.navigator);
  defineGlobal('location', win.location);
  defineGlobal('history', win.history);
  defineGlobal('localStorage', win.localStorage);
  defineGlobal('FileReader', win.FileReader);
  defineGlobal('File', win.File);
  defineGlobal('Blob', win.Blob);
  defineGlobal('Event', win.Event);
  defineGlobal('MouseEvent', win.MouseEvent);
  defineGlobal('Node', win.Node);
  defineGlobal('HTMLElement', win.HTMLElement);
  defineGlobal('indexedDB', indexedDbFactory);
  defineGlobal('fetch', installFetch());
  defineGlobal('URL', win.URL.constructor === Function ? win.URL : globalThis.URL);
  defineGlobal('confirm', () => true);
  defineGlobal('alert', () => {});

  await import('../../app.js');
  app = globalThis.__omnishield;
  assert.ok(app, 'app.js must expose the automation hook');
  await app.ready;
});

after(() => {
  try { app?.stop(); } catch { /* ignore */ }
  try { win?.close(); } catch { /* ignore */ }
});

const $ = (sel) => win.document.querySelector(sel);
const text = (sel) => $(sel)?.textContent || '';
const fileOf = (name, content, type = 'application/octet-stream') => new win.File([content], name, { type });

test('every screen, including the four new ones, is reachable and rendered', () => {
  const pages = [...win.document.querySelectorAll('nav.tabs button')].map((b) => b.dataset.page);
  for (const expected of ['scan', 'search', 'vault', 'media']) assert.ok(pages.includes(expected), `missing tab ${expected}`);
  for (const page of pages) {
    app.navigate(page);
    const section = $(`#page-${page}`);
    assert.ok(section, `missing section for ${page}`);
    assert.equal(section.hidden, false);
    assert.ok(section.textContent.trim().length > 80, `${page} rendered too little content`);
  }
});

test('the scanner inspects real bytes and surfaces the EICAR signature through the UI', async () => {
  await app.navigate('scan');
  await app.uploadToVault([fileOf('clean.txt', 'just some notes', 'text/plain')]);

  const scanner = app.scanner();
  const clean = await scanner.run({ modules: ['vault', 'configuration'], configuration: { engineLoaded: true, vaultLocked: false } });
  assert.equal(clean.status, 'complete');
  assert.ok(clean.scanned.checks > 0, 'the vault and configuration checks must actually run');

  // Drive the real UI action with a file queue, exactly as the file picker does.
  const original = scanner.run.bind(scanner);
  scanner.run = async (request) => original({ ...request, files: [fileOf('eicar.com', EICAR, 'text/plain')] });
  const run = await app.runScan();
  scanner.run = original;
  assert.ok(run, 'runScan must hand back the completed run');
  assert.equal(run.status, 'complete');

  assert.match(text('#scan-status'), /complete/);
  assert.match(text('#scan-findings'), /EICAR/);
  assert.match(text('#scan-files-card'), /eicar\.com/);
  assert.match(text('#scan-summary'), /critical/);
  assert.equal($('#scan-report').disabled, false);
});

test('a scan with no selected module refuses instead of reporting a fake clean run', async () => {
  app.navigate('scan');
  const chips = [...win.document.querySelectorAll('#scan-modules button')];
  assert.ok(chips.length >= 5);
  const before = app.scanner().history.length;
  // Turn every available module off, then try to run.
  for (const chip of chips.filter((c) => !c.disabled)) chip.dispatchEvent(new win.MouseEvent('click', { bubbles: true }));
  await app.runScan();
  assert.equal(app.scanner().history.length, before, 'a scan with no modules must not be recorded as a run');
  // Restore the selection for the remaining tests.
  for (const chip of [...win.document.querySelectorAll('#scan-modules button')].filter((c) => !c.disabled)) chip.dispatchEvent(new win.MouseEvent('click', { bubbles: true }));
});

test('unavailable modules are rendered as disabled with the reason, not hidden', async () => {
  await app.navigate('scan');
  const chips = [...win.document.querySelectorAll('#scan-modules button')];
  const apps = chips.find((c) => /Installed applications/.test(c.textContent));
  assert.ok(apps, 'the installed-apps module must be listed');
  assert.equal(apps.disabled, true);
  assert.match(apps.textContent, /unavailable/);
  assert.match(text('#scan-modules-info'), /cannot enumerate installed apps/i);
});

test('search opens the chosen engine with noopener and records local history', async () => {
  app.navigate('search');
  const opened = [];
  win.open = (url, target, features) => { opened.push({ url, target, features }); return { opener: null }; };

  await app.selectSearchProvider('duckduckgo');
  $('#search-input').value = 'dns filtering';
  $('#search-go').dispatchEvent(new win.MouseEvent('click', { bubbles: true }));
  // runSearch is async — wait for the history write and the render it triggers.
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(opened.length, 1);
  assert.match(opened[0].url, /^https:\/\/duckduckgo\.com\/\?q=dns\+filtering$/);
  assert.equal(opened[0].features, 'noopener,noreferrer');
  assert.match(text('#search-out'), /Opened DuckDuckGo/);
  assert.match(text('#search-history'), /dns filtering/);

  await app.selectSearchProvider('google');
  $('#search-input').value = 'tracker list';
  $('#search-go').dispatchEvent(new win.MouseEvent('click', { bubbles: true }));
  await new Promise((r) => setTimeout(r, 50));
  assert.match(opened[1].url, /^https:\/\/www\.google\.com\/search\?q=tracker\+list$/);
  assert.match(text('#search-engine-pill'), /Google/);
});

test('a !bang overrides the selected engine and trackers are stripped from a pasted URL', async () => {
  app.navigate('search');
  const opened = [];
  win.open = (url) => { opened.push(url); return { opener: null }; };
  await app.selectSearchProvider('duckduckgo');
  $('#search-input').value = '!g quantum dns';
  $('#search-go').dispatchEvent(new win.MouseEvent('click', { bubbles: true }));
  await new Promise((r) => setTimeout(r, 50));
  assert.match(opened[0], /google\.com\/search\?q=quantum\+dns/);

  $('#search-input').value = 'https://shop.example/item?utm_source=news&fbclid=abc&id=7';
  $('#search-clean').dispatchEvent(new win.MouseEvent('click', { bubbles: true }));
  await new Promise((r) => setTimeout(r, 30));
  const out = text('#search-out');
  assert.match(out, /Removed 2 tracking parameter/);
  assert.match(out, /id=7/);
  assert.equal(out.includes('utm_source'), true, 'the removed parameter is named in the report');
});

test('in-app instant answers render real API content and an empty result is stated as empty', async () => {
  app.navigate('search');
  $('#search-input').value = 'dns';
  $('#search-instant').dispatchEvent(new win.MouseEvent('click', { bubbles: true }));
  await new Promise((r) => setTimeout(r, 80));
  assert.match(text('#search-answer'), /Domain Name System/);
  assert.match(text('#search-answer'), /maps names to addresses/);
  assert.match(text('#search-answer'), /Related DNS topic/);

  $('#search-input').value = 'zzzz-no-answer';
  $('#search-instant').dispatchEvent(new win.MouseEvent('click', { bubbles: true }));
  await new Promise((r) => setTimeout(r, 80));
  assert.match(text('#search-answer'), /no instant answer/i);
});

test('the cloud box stores, previews, downloads, renames and verifies real files', async () => {
  app.navigate('vault');
  const files = [fileOf('photo.png', new Uint8Array([0x89, 0x50, 0x4E, 0x47, 1, 2, 3]), 'image/png'),
    fileOf('notes.txt', 'hello vault', 'text/plain')];
  await app.uploadToVault(files);
  await app.navigate('vault');

  const vault = app.vault();
  assert.ok(vault.list().length >= 2, `expected stored files, found [${vault.list().map((e) => e.name).join(', ')}] — toasts: ${text('#toasts')}`);
  const photo = vault.list().find((entry) => entry.name === 'photo.png');
  assert.ok(photo, 'photo.png must be stored');
  assert.equal(photo.kind, 'image');
  assert.match(text('#vault-list'), /photo\.png/);
  assert.match(text('#vault-usage'), /stored/);

  await app.openVaultPreview(photo.id);
  assert.match(text('#vault-preview'), /photo\.png/);
  assert.ok($('#vault-preview img'), 'an image must produce an <img> preview');
  const previewSrc = $('#vault-preview img').getAttribute('src');
  assert.match(previewSrc, /^(blob:|data:image\/png;base64,)/, 'the preview must carry the stored bytes');

  // Rename through the real input, exactly as the button does.
  $('#vault-rename-input').value = 'holiday.png';
  $('#vault-preview button.primary').dispatchEvent(new win.MouseEvent('click', { bubbles: true }));
  await new Promise((r) => setTimeout(r, 40));
  assert.equal(vault.get(photo.id).name, 'holiday.png');

  const verified = await vault.verify(photo.id);
  assert.equal(verified.ok, true);
});

test('the cloud box passphrase lock encrypts on write and needs the key to read', async () => {
  app.navigate('vault');
  const vault = app.vault();
  await vault.setPassphrase('integration passphrase');
  await app.uploadToVault([fileOf('secret.txt', 'CLASSIFIED-PAYLOAD', 'text/plain')]);
  const entry = vault.list().find((e) => e.name === 'secret.txt');
  assert.ok(entry, 'the encrypted file must be indexed');
  assert.equal(entry.encrypted, true);
  vault.lock();
  await assert.rejects(() => vault.read(entry.id), /locked/);
  await vault.unlock('integration passphrase');
  const { blob } = await vault.read(entry.id);
  assert.equal(await blob.text(), 'CLASSIFIED-PAYLOAD');
  // Leave the vault open for the remaining tests.
  await vault.removePassphrase('integration passphrase');
});

test('the downloader refuses YouTube with a reason and downloads a permitted direct file for real', async () => {
  app.navigate('media');
  $('#media-url').value = 'https://www.youtube.com/watch?v=dQw4w9WgXcQ';
  await app.checkMediaUrl();
  const out = text('#media-out');
  assert.match(out, /YouTube/);
  assert.match(out, /not permitted/);
  assert.equal($('#media-add').disabled, true, 'a refused source must not be downloadable');

  $('#media-url').value = 'https://cdn.example/clip.mp4';
  await app.checkMediaUrl();
  assert.match(text('#media-out'), /download permitted/);
  assert.equal($('#media-add').disabled, false);
  assert.match(text('#media-out'), /resumable/);

  await app.addMediaDownload();
  const downloads = app.downloads();
  const task = downloads.list()[0];
  assert.ok(task);
  // start() is awaited inside addMediaDownload; give the stream one tick to finish.
  await new Promise((r) => setTimeout(r, 80));
  const finished = downloads.get(task.id);
  assert.equal(finished.status, 'done');
  assert.equal(finished.received, 16);
  assert.equal(app.vault().list().some((entry) => entry.name === 'clip.mp4'), true, 'the finished file lands in the cloud box');
  assert.match(text('#media-list'), /clip\.mp4/);
  assert.match(text('#media-history'), /saved to cloud box/);
});

test('Vimeo metadata is fetched for real and formats are offered', async () => {
  app.navigate('media');
  $('#media-url').value = 'https://vimeo.com/76979871';
  await app.checkMediaUrl();
  const out = text('#media-out');
  assert.match(out, /Vimeo/);
  assert.match(out, /Vimeo Demo|metadata/i);
  assert.match(out, /Choose a format/);
  const formats = [...win.document.querySelectorAll('#media-formats button')];
  assert.ok(formats.length >= 6, `expected a format ladder, found ${formats.length}`);
  assert.ok(formats.some((button) => /MP4 1080p/.test(button.textContent)));
  formats[2].dispatchEvent(new win.MouseEvent('click', { bubbles: true }));
  // Selecting a format re-renders the panel, so the pressed state must be read
  // from the freshly rendered buttons, not the detached ones.
  const rerendered = [...win.document.querySelectorAll('#media-formats button')];
  assert.equal(rerendered[2].getAttribute('aria-pressed'), 'true');
  assert.equal(rerendered.filter((b) => b.getAttribute('aria-pressed') === 'true').length, 1);
});

test('the new screens do not introduce HTML injection sinks', () => {
  const source = read('app.js');
  assert.equal(/\.innerHTML\s*=/.test(source), false);
  // The new UI is built only through the shared safe helpers.
  for (const helper of ['h(', 'mount(', 'table(', 'kv(', 'pill(']) assert.ok(source.includes(helper), `expected to use ${helper}`);
});
