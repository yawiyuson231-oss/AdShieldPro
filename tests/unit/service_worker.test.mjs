import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { runInNewContext } from 'node:vm';

const SOURCE = readFileSync(new URL('../../sw.js', import.meta.url), 'utf8');
const SCOPE = 'https://site.example/AdShieldPro/app/';

function worker({ scope = SCOPE, unavailable = false } = {}) {
  const handlers = new Map();
  const buckets = new Map();
  const requests = [];
  let online = true;
  const keyFor = (request) => new URL(request.url ?? request, scope).href;
  const fetch = async (request) => {
    const url = keyFor(request);
    requests.push(url);
    if (!online) throw new TypeError('offline');
    const html = url === scope || url === `${scope}index.html`;
    return new Response(html ? 'app shell' : `asset: ${url}`, {
      headers: { 'content-type': html ? 'text/html' : 'text/plain' }
    });
  };
  runInNewContext(SOURCE, {
    URL, Response, fetch,
    Request: class { constructor(url) { this.url = keyFor(url); } },
    self: {
      location: new URL('sw.js', scope), registration: { scope },
      addEventListener: (name, fn) => handlers.set(name, fn),
      skipWaiting: async () => {}, clients: { claim: async () => {} }
    },
    caches: {
      keys: async () => [...buckets.keys()],
      delete: async (name) => buckets.delete(name),
      open: async (name) => {
        if (unavailable) throw new Error('cache storage is unavailable');
        if (!buckets.has(name)) buckets.set(name, new Map());
        const bucket = buckets.get(name);
        return {
          add: async (request) => bucket.set(keyFor(request), await fetch(request)),
          match: async (request) => bucket.get(keyFor(request))?.clone(),
          put: async (request, response) => bucket.set(keyFor(request), response)
        };
      }
    }
  });
  async function dispatch(name, details = {}) {
    const work = [];
    let response = null;
    handlers.get(name)({ ...details, waitUntil: (task) => work.push(task), respondWith: (task) => { response = task; } });
    const result = await response;
    await Promise.all(work);
    return result;
  }
  return {
    buckets, requests,
    dispatch,
    offline: () => { online = false; },
    request: (url, extra = {}) => dispatch('fetch', {
      request: { url: keyFor(url), method: 'GET', mode: 'same-origin', ...extra }
    })
  };
}

test('activating the worker never deletes caches outside its own registration scope', async () => {
  const local = worker();
  await local.dispatch('install');
  const old = `omnishield-x:${SCOPE}:old-shell`;
  const neighbor = 'omnishield-x:https://site.example/other/app/:old-shell';
  for (const name of [old, neighbor, 'another-app-cache']) local.buckets.set(name, new Map());
  await local.dispatch('activate');
  assert.equal(local.buckets.has(old), false, 'remove only obsolete caches of this scope');
  assert.equal(local.buckets.has(neighbor), true);
  assert.equal(local.buckets.has('another-app-cache'), true);
});

test('the worker does not serve or cache DNS/API requests, query variants, or other site paths', async () => {
  const local = worker();
  for (const [url, options] of [
    ['https://resolver.example/dns-query?dns=fixture'],
    ['./dns-query?dns=fixture'],
    ['./activity.json'],
    ['./app.js?version=different'],
    ['./app.js', { method: 'POST' }],
    ['../privacy.html', { mode: 'navigate' }],
    ['/other/index.html', { mode: 'navigate' }]
  ]) {
    assert.equal(await local.request(url, options), null, `unexpected interception of ${url}`);
  }
  assert.deepEqual(local.requests, []);
  assert.equal(local.buckets.size, 0);
});

test('the installed shell, shipped modules, and bundled rules still work offline', async () => {
  const local = worker();
  await local.dispatch('install');
  local.offline();
  assert.equal(await (await local.request('./', { mode: 'navigate' })).text(), 'app shell');
  assert.equal(await (await local.request('./app.js')).text(), `asset: ${SCOPE}app.js`);
  assert.equal(await (await local.request('./assets/core_lite_ads.txt')).text(), `asset: ${SCOPE}assets/core_lite_ads.txt`);
});

test('unavailable Cache Storage does not prevent online loads', async () => {
  const local = worker({ unavailable: true });
  await local.dispatch('install');
  assert.equal(await (await local.request('./', { mode: 'navigate' })).text(), 'app shell');
  assert.equal(await (await local.request('./app.js')).text(), `asset: ${SCOPE}app.js`);
  const rules = await local.request('./assets/core_lite_ads.txt');
  assert.equal(rules.status, 200);
});
