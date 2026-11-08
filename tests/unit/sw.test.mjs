/** Execute the actual service-worker handlers with in-memory Cache API and network boundaries. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
const source = readFileSync(new URL('../../sw.js', import.meta.url), 'utf8');
const base = 'https://example.org/app/sw.js';
const href = (input) => new URL(typeof input === 'string' ? input : input.url, base).href;

function harness() {
  const handlers = {}; const stores = new Map(); const calls = [];
  let network = async (request) => new Response(`network: ${href(request)}`);
  let activated = 0; let claimed = 0;
  const fetch = (request) => { calls.push(href(request)); return network(request); };
  const open = async (name) => {
    if (!stores.has(name)) stores.set(name, new Map());
    const entries = stores.get(name);
    return {
      async put(key, response) { entries.set(href(key), response.clone()); },
      async match(key, { ignoreSearch = false } = {}) {
        const wanted = new URL(href(key));
        for (const [stored, response] of entries) {
          const u = new URL(stored);
          if (ignoreSearch ? u.origin === wanted.origin && u.pathname === wanted.pathname : u.href === wanted.href) return response.clone();
        }
        return undefined;
      },
      async add(key) { const response = await fetch(key); if (!response.ok) throw new Error('Asset unavailable'); entries.set(href(key), response.clone()); },
      async addAll(keys) {
        const values = await Promise.all(keys.map(async (key) => { const response = await fetch(key); if (!response.ok) throw new Error('Asset unavailable'); return [href(key), response]; }));
        for (const [key, response] of values) entries.set(key, response.clone());
      }
    };
  };
  const self = { location: new URL(base), addEventListener: (name, fn) => { handlers[name] = fn; }, skipWaiting: async () => { activated++; }, clients: { claim: async () => { claimed++; } } };
  class WorkerRequest extends Request { constructor(input, options) { super(href(input), options); } }
  vm.runInNewContext(source, { self, caches: { open, keys: async () => [...stores.keys()], delete: async (name) => stores.delete(name) }, Request: WorkerRequest, Response, URL, fetch });
  return {
    calls, stores, open, get activated() { return activated; }, get claimed() { return claimed; },
    setNetwork(fn) { network = fn; },
    async lifecycle(name) { let pending; handlers[name]({ waitUntil(value) { pending = value; } }); await pending; },
    request(path, mode = 'cors', method = 'GET') {
      let result;
      handlers.fetch({ request: { url: href(path), mode, method }, respondWith(value) { result = value; } });
      return result;
    },
    shell() { return [...stores.values()].find((_, index) => [...stores.keys()][index].endsWith('-shell')); }
  };
}

test('service worker precaches the actual world, country and packaged-entry assets', async () => {
  const h = harness(); await h.lifecycle('install');
  for (const path of ['./index.html', './world/map.js', './world/embed.html', './assets/country-boundaries.json', './assets/country-data-license.txt']) assert.ok(h.shell().has(href(path)), path);
  assert.equal(h.activated, 1);
});
test('an incomplete new shell cannot activate over a working offline version', async () => {
  const h = harness(); h.setNetwork(async (request) => new Response('result', { status: href(request).endsWith('/world/map.js') ? 503 : 200 }));
  await assert.rejects(h.lifecycle('install'), /Asset unavailable/); assert.equal(h.activated, 0); assert.equal(h.shell().size, 0);
});
test('service worker activation removes only its own old namespaces', async () => {
  const h = harness(); await h.open('unrelated-site-data'); await h.open('omnishield-x-v4-shell'); await h.lifecycle('install'); await h.lifecycle('activate');
  assert.ok(h.stores.has('unrelated-site-data')); assert.ok(!h.stores.has('omnishield-x-v4-shell')); assert.equal(h.claimed, 1);
});
test('cross-origin providers, same-origin custom feeds and non-GET requests bypass the worker', () => {
  const h = harness();
  assert.equal(h.request('https://earthquake.usgs.gov/feed'), undefined);
  assert.equal(h.request('./user-feed.json'), undefined);
  assert.equal(h.request('./index.html', 'cors', 'POST'), undefined);
  assert.equal(h.calls.length, 0);
});
test('a server error never overwrites the last-good offline app document', async () => {
  const h = harness(); await h.lifecycle('install'); const previous = await h.shell().get(href('./index.html')).clone().text();
  h.setNetwork(async () => new Response('server error', { status: 503 }));
  assert.equal(await (await h.request('./', 'navigate')).text(), previous);
  assert.equal(await h.shell().get(href('./index.html')).clone().text(), previous);
});
test('successful embedded-page navigation cannot poison the main offline app shell', async () => {
  const h = harness(); await h.lifecycle('install'); const previous = await h.shell().get(href('./index.html')).clone().text();
  h.setNetwork(async () => new Response('embedded app'));
  assert.equal(await (await h.request('./world/embed.html', 'navigate')).text(), 'embedded app');
  await Promise.resolve();
  assert.equal(await h.shell().get(href('./index.html')).clone().text(), previous);
  h.setNetwork(async () => { throw new Error('offline'); });
  assert.equal(await (await h.request('./', 'navigate')).text(), previous);
  assert.equal(await (await h.request('./world/embed.html', 'navigate')).text(), 'embedded app');
});
test('offline bundled map and country assets remain available without provider calls', async () => {
  const h = harness(); await h.lifecycle('install'); h.calls.length = 0;
  h.setNetwork(async () => { throw new Error('offline'); });
  const response = await h.request('./assets/country-boundaries.json');
  assert.equal(response.status, 200); assert.match(await response.text(), /country-boundaries/);
  assert.ok(h.calls.every((url) => url.startsWith('https://example.org/app/')));
});
