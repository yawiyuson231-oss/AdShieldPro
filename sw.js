/**
 * OmniShield X — service worker (offline protection).
 *
 * Strategy
 *  - App shell + JavaScript modules + the small curated feeds: precached.
 *  - The large bundled rule list (assets/core_lite_ads.txt): stale-while-revalidate,
 *    so the first visit caches it and later visits work fully offline.
 *  - Only the checked-in app shell and bundled assets are intercepted. DNS/API
 *    requests, query variants and paths outside the app use the browser's network.
 *  - App-shell navigations: network-first with an offline fallback.
 *
 * Bump VERSION to invalidate this registration's caches on release.
 */
const VERSION = 'omnishield-x-v5.0.3-dns.2';
const SCOPE = self.registration.scope;
// Cache Storage is origin-wide, even when this worker only controls one subdirectory.
const CACHE_PREFIX = `omnishield-x:${SCOPE}:`;
const SHELL_CACHE = `${CACHE_PREFIX}${VERSION}-shell`;
const RULES_CACHE = `${CACHE_PREFIX}${VERSION}-rules`;

const SHELL_ASSETS = [
  './',
  './index.html',
  './app.js',
  './engine.js',
  './manifest.webmanifest',
  './assets/icon.svg',
  './assets/extension-facts.json',
  './assets/core_supplement_ads.txt',
  './assets/core_supplement_aggressive.txt',
  './ui/dom.js',
  './dns/codec.js',
  './dns/cache.js',
  './dns/client.js',
  './dns/dnssec.js',
  './dns/chain.js',
  './dns/resolvers.js',
  './guard/video-safety.js',
  './aether/index.js',
  './aether/data.js',
  './aether/domain.js',
  './aether/lexical.js',
  './aether/typosquat.js',
  './aether/reputation.js',
  './aether/classifier.js',
  './security/monitor.js',
  './security/firewall-ai.js',
  './security/feedmanager.js',
  './security/backup.js',
  './security/privacy.js',
  './security/power.js',
  './security/sha256.js',
  './security/storage.js'
];

const RULES_ASSETS = ['./assets/core_lite_ads.txt'];
const INDEX = new URL('./index.html', SCOPE).href;
const SHELL_URLS = new Set(SHELL_ASSETS.map((path) => new URL(path, SCOPE).href));
const RULES_URLS = new Set(RULES_ASSETS.map((path) => new URL(path, SCOPE).href));

const openCache = (name) => caches.open(name).catch(() => null);
const readCache = (cache, key) => cache?.match(key).catch(() => undefined);

self.addEventListener('install', (event) => {
  event.waitUntil((async () => {
    async function precache(name, urls) {
      const cache = await openCache(name);
      if (!cache) return;
      // Do not abandon a usable offline shell because one optional asset failed to load.
      await Promise.all([...urls].map((url) =>
        cache.add(new Request(url, { cache: 'reload', redirect: 'error' })).catch(() => {})
      ));
    }
    await Promise.all([precache(SHELL_CACHE, SHELL_URLS), precache(RULES_CACHE, RULES_URLS)]);
    await self.skipWaiting();
  })());
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    const keys = await caches.keys().catch(() => []);
    const obsolete = keys.filter((key) => key.startsWith(CACHE_PREFIX) && key !== SHELL_CACHE && key !== RULES_CACHE);
    await Promise.all(obsolete.map((key) => caches.delete(key).catch(() => {})));
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', (event) => {
  const { request } = event;
  if (request.method !== 'GET') return;

  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;

  // Other pages on the same host must never be cached as the offline app shell.
  if (request.mode === 'navigate') {
    if (url.href !== SCOPE && url.href !== INDEX) return;
    event.respondWith((async () => {
      try {
        const fresh = await fetch(request);
        if (fresh.ok && !fresh.redirected && (fresh.headers.get('content-type') || '').includes('text/html')) {
          const copy = fresh.clone();
          event.waitUntil(openCache(SHELL_CACHE).then((cache) => cache?.put(INDEX, copy)).catch(() => {}));
        }
        return fresh;
      } catch {
        const cache = await openCache(SHELL_CACHE);
        // `catch` (no request argument) means all she can say is "this failed";
        // a plain network error is what a navigation expects when there is no
        // offline shell, and it is what the browser renders as its offline page.
        return (await readCache(cache, INDEX)) || (await readCache(cache, SCOPE)) || Response.error();
      }
    })());
    return;
  }

  // Same-origin DNS/API requests are live too. Use the exact static URL, including any query.
  const rules = RULES_URLS.has(url.href);
  if (!rules && !SHELL_URLS.has(url.href)) return;
  event.respondWith((async () => {
    const cache = await openCache(rules ? RULES_CACHE : SHELL_CACHE);
    const cached = await readCache(cache, request);
    const fresh = fetch(request).then((response) => {
      if (cache && response.ok && !response.redirected) {
        const copy = response.clone();
        event.waitUntil(cache.put(request, copy).catch(() => {}));
      }
      return response;
    }).catch(() => null);
    if (cached) {
      event.waitUntil(fresh);
      return cached;
    }
    return (await fresh) || new Response('', { status: 504, statusText: 'offline and not cached' });
  })());
});
