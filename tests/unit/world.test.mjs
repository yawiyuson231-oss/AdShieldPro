import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { SOURCES, SOURCE_BY_ID, CATEGORIES, LIMITS } from '../../world/catalog.js';
import { normalizeEvent, safeUrl, validCoordinates, timestamp, filterEvents, normalizeWatch, matchesWatch, histogram, clusterEvents, csvCell, exportCsv, buildBriefing, parseWatchImport } from '../../world/model.js';
import { parseSource } from '../../world/parsers.js';
import { WorldStore, sanitizeFilters } from '../../world/store.js';
import { fetchJson, retryTime } from '../../world/network.js';
import { WeatherService, parseForecast, parseAir, normalizePlace, weatherLabel, airLabel } from '../../world/weather.js';
import { COUNTRIES, COUNTRY_BY_CODE, CountryService, pointInRing, inCountry, countrySummary, searchCountries } from '../../world/countries.js';
import { normalizeCustomSource, MAX_CUSTOM_SOURCES } from '../../world/custom.js';
import { cameraBounds, project } from '../../world/map.js';
import { configureDailyHost, loadBackgroundSnapshot } from '../../world/native.js';
import { MemoryStorage } from '../../security/storage.js';
import { NOW, fixtures, emptyFixtures, quake, geo, forecast, air, response } from '../fixtures/world.mjs';

const copy = (x) => structuredClone(x);
const event = (overrides = {}) => normalizeEvent({ id: 'event', title: 'Example Philippines event', occurredAt: NOW - 1000, category: 'seismic', severity: 'high', lat: 15, lon: 121, ...overrides }, overrides.source || 'usgs', NOW);
function storeWith(fetchImpl, storage = new MemoryStorage()) { const s = new WorldStore({ storage, clock: () => NOW, fetchImpl, timeoutMs: 50 }); return s; }
function providerFetch(calls = []) { return async (url, init) => { const source = SOURCES.find((s) => s.url === url); calls.push({ url, init }); if (!source) throw new Error(`Unexpected URL ${url}`); return response(fixtures[source.id]); }; }

// Source catalogue and independent, explicit schema contracts.
test('World Monitor ships distinct, attributed, keyless public provider definitions', () => {
  assert.equal(SOURCES.length, 12); assert.equal(new Set(SOURCES.map((s) => s.id)).size, 12); assert.equal(new Set(SOURCES.map((s) => s.url)).size, 12);
  for (const s of SOURCES) { assert.equal(new URL(s.url).protocol, 'https:'); assert.ok(s.ttlMs >= 300000); assert.ok(s.terms && s.coverage && s.homepage); }
  assert.equal(SOURCES.length + MAX_CUSTOM_SOURCES, 100);
});
for (const spec of SOURCES) {
  test(`${spec.id}: valid provider response produces dated, source-qualified records`, () => {
    const result = parseSource(spec.id, copy(fixtures[spec.id]), NOW);
    assert.ok(result.events.length > 0); assert.equal(result.rejected, 0);
    for (const e of result.events) { assert.ok(e.id.startsWith(`${spec.id}:`)); assert.equal(e.source, spec.id); assert.ok(e.occurredAt <= NOW); assert.ok(e.severityBasis); assert.ok(CATEGORIES.some((c) => c.id === e.category)); }
  });
  test(`${spec.id}: valid empty data is distinguished from an invalid schema`, () => {
    assert.equal(parseSource(spec.id, emptyFixtures[spec.id], NOW).events.length, 0);
    assert.throws(() => parseSource(spec.id, { error: 'upstream error' }, NOW));
  });
}
test('USGS derives documented magnitude bands without confusing null magnitude with a value', () => {
  const levels = [7, 6, 4.5, 1, null].map((mag) => parseSource('usgs', geo([quake({ mag })]), NOW).events[0].severity);
  assert.deepEqual(levels, ['critical', 'high', 'moderate', 'info', 'info']);
});
test('EONET uses latest reported geometry, not a made-up location or impact score', () => {
  const e = parseSource('eonet', fixtures.eonet, NOW).events[0]; assert.equal(e.lon, 131); assert.equal(e.lat, -31); assert.equal(e.severity, 'info');
});
test('media publisher country and global cyber reports are never converted into map points', () => {
  for (const id of ['gdelt', 'kev', 'advisories', 'github-status', 'noaa']) for (const e of parseSource(id, fixtures[id], NOW).events) { assert.equal(e.lat, null); assert.equal(e.lon, null); }
});
test('resolved service incidents remain informational and retain provider status', () => {
  const e = parseSource('cloudflare-status', fixtures['cloudflare-status'], NOW).events[0]; assert.equal(e.severity, 'info'); assert.ok(e.tags.includes('resolved'));
});
test('invalid records are skipped with a count, but wholly invalid nonempty payloads fail', () => {
  const result = parseSource('usgs', geo([quake(), quake({ time: 'nonsense' })]), NOW); assert.equal(result.rejected, 1); assert.equal(result.events.length, 1);
  assert.throws(() => parseSource('usgs', geo([quake({ time: null })]), NOW), /none had a valid/);
});
test('duplicate provider IDs collapse and sorted bounded feeds retain the newest records', () => {
  const data = { vulnerabilities: Array.from({ length: 1000 }, (_, n) => ({ ...fixtures.kev.vulnerabilities[0], cveID: `CVE-2026-${10000 + n}`, dateAdded: new Date(NOW - n * 86400000).toISOString() })) };
  const result = parseSource('kev', data, NOW); assert.equal(result.events.length, LIMITS.eventsPerSource); assert.equal(result.truncated, true); assert.equal(result.events[0].id, 'kev:CVE-2026-10000');
  assert.equal(parseSource('usgs', geo([quake(), quake({ updated: NOW })]), NOW).events.length, 1);
});
test('polygon coordinates are labelled approximate and dateline centroids do not fall in Greenwich', () => {
  const p = copy(fixtures.nws); p.features[0].geometry = { type: 'Polygon', coordinates: [[[179, 10], [-179, 10], [-179, 12], [179, 12], [179, 10]]] };
  const e = parseSource('nws', p, NOW).events[0]; assert.ok(Math.abs(e.lon) > 170); assert.match(e.geoBasis, /Approximate/);
});

// Validation, querying, reports and geography.
test('public HTTPS links reject script schemes, credentials, private IPs and malformed URLs', () => {
  for (const value of ['javascript:alert(1)', 'http://example.com', 'https://a:b@example.org', 'https://127.0.0.1/x', 'https://0x7f000001/', 'https://localhost/', 'https://sub.localhost/', 'https://[::1]/', 'data:text/html,hi']) assert.equal(safeUrl(value), null, value);
  assert.equal(safeUrl('https://example.org/path?q=x'), 'https://example.org/path?q=x');
});
test('events require a known source, date, ID and title; coordinate zero is valid but null is not', () => {
  assert.equal(event({ occurredAt: null }), null); assert.equal(event({ title: '' }), null); assert.equal(event({ id: '' }), null); assert.equal(event({ occurredAt: NOW + 2 * 86400000 }), null);
  assert.equal(normalizeEvent({ id: 'x', title: 'x', category: 'news', occurredAt: NOW }, 'invented', NOW), null);
  assert.equal(validCoordinates(0, 0), true); assert.equal(validCoordinates(null, 0), false); assert.equal(validCoordinates(95, 0), false);
  assert.equal(event({ lat: null }).lat, null); assert.equal(event({ lat: 0, lon: 0 }).lat, 0);
});
test('provider timestamps support ISO, compact GDELT and numeric formats without a fabricated fallback', () => {
  assert.equal(timestamp('20261108T120000Z'), NOW); assert.equal(timestamp(`/Date(${NOW})/`), NOW); assert.equal(timestamp('not a date'), null); assert.equal(timestamp(0), null);
});
test('filters combine all words, category, region, priority, time and source deterministically', () => {
  const list = [event(), event({ id: 'other', lat: 38, lon: -120, title: 'California', severity: 'critical' }), event({ id: 'old', occurredAt: NOW - 10 * 86400000 })];
  assert.equal(filterEvents(list, { query: 'example philippines', region: 'philippines', range: '7d', source: 'usgs', categories: ['seismic'], severity: 'high' }, NOW).length, 1);
  assert.equal(filterEvents(list, { categories: [] }, NOW).length, 0);
  assert.equal(filterEvents(list, { sort: 'severity' }, NOW)[0].title, 'California');
  assert.equal(filterEvents([event({ lat: null, lon: null })], { region: 'philippines' }, NOW).length, 0);
});
test('corrupt or imported filter controls are reduced to bounded known values', () => {
  const f = sanitizeFilters({ query: 'x'.repeat(900), region: 'nonexistent', range: 'eternal', categories: ['cyber', 'cyber', '__proto__'], severity: 'fake', sort: 'evil' });
  assert.equal(f.query.length, 160); assert.equal(f.region, 'world'); assert.equal(f.range, '7d'); assert.deepEqual(f.categories, ['cyber']);
});
test('watch conditions are conjunctive; disabling a watch suppresses matches', () => {
  const w = normalizeWatch({ label: 'Local high', region: 'philippines', severity: 'high', category: 'seismic', query: 'example' }, 'w');
  assert.equal(matchesWatch(event(), w), true); assert.equal(matchesWatch(event({ severity: 'info' }), w), false); assert.equal(matchesWatch(event(), { ...w, enabled: false }), false);
  assert.throws(() => normalizeWatch({ label: '' }, 'w'), /name/);
});
test('histograms and clusters count only supplied records and geolocated points', () => {
  assert.equal(histogram([], NOW).reduce((n, b) => n + b.count, 0), 0);
  const e = event(); const list = [e, event({ id: 'b', lat: e.lat + .01 }), event({ id: 'ungrounded', lat: null })];
  assert.equal(histogram(list, NOW).reduce((n, b) => n + b.count, 0), 3);
  const groups = clusterEvents(list); assert.equal(groups.length, 1); assert.equal(groups[0].events.length, 2);
});
test('CSV exports escape quotes, multiline text and spreadsheet formula prefixes', () => {
  for (const value of ['=IMPORTXML("https://evil")', '+cmd', '-1+2', '@SUM(1)', ' \t=FORMULA()', '\n@SUM()']) assert.ok(csvCell(value).startsWith('"\''), value);
  assert.equal(csvCell('a"b'), '"a""b"');
  assert.match(exportCsv([event()]), /severityBasis,dataStatus/); assert.match(exportCsv([event()]), /cached/);
});
test('briefings attribute records and include outage, coverage and prediction limitations', () => {
  const text = buildBriefing([event()], { usgs: { status: 'offline', lastSuccess: NOW - 1000, error: 'Source down' } }, { region: 'world', range: '7d' }, NOW);
  assert.match(text, /USGS Earthquakes: offline/); assert.match(text, /Source down/); assert.match(text, /not a prediction/); assert.match(text, /1 matching records/);
});
test('watchlist import validates schema, size, count and every rule before replacement', () => {
  assert.throws(() => parseWatchImport('<html>'), /JSON/); assert.throws(() => parseWatchImport('{}'), /format/);
  assert.throws(() => parseWatchImport('x'.repeat(128001)), /128/);
  assert.throws(() => parseWatchImport(JSON.stringify({ schema: 'omnishield-world-watches', version: 1, watches: Array.from({ length: 31 }, () => ({ label: 'x' })) })), /30/);
  const watches = parseWatchImport(JSON.stringify({ schema: 'omnishield-world-watches', version: 1, watches: [{ label: 'Japan', query: 'Japan', severity: 'info' }] })); assert.equal(watches[0].label, 'Japan');
});
test('camera projection, zoom limits and pan boundaries stay deterministic', () => {
  assert.deepEqual(project(0, 0), { x: 500, y: 250 });
  assert.equal(cameraBounds({ zoom: 999, x: -10, y: 999 }).zoom, 8);
  assert.equal(cameraBounds({ zoom: 999, x: -10, y: 999 }).x, 0);
  assert.equal(cameraBounds({ zoom: 0 }).width, 1000);
});

// Bounded, honest network operations.
test('requests omit cookies and referrers and decode valid JSON', async () => {
  let options; const result = await fetchJson('https://example.org/data', { fetchImpl: async (_, init) => { options = init; return response({ valid: true }); } });
  assert.equal(result.valid, true); assert.equal(options.credentials, 'omit'); assert.equal(options.referrerPolicy, 'no-referrer'); assert.equal(options.cache, 'no-store');
});
test('HTTP errors, HTML, oversized bodies and non-HTTPS redirects are explicit failures', async () => {
  await assert.rejects(fetchJson('https://example.org', { fetchImpl: async () => response({}, 503) }), /503/);
  await assert.rejects(fetchJson('https://example.org', { fetchImpl: async () => response('<html>login</html>') }), /invalid JSON/);
  await assert.rejects(fetchJson('https://example.org', { maxBytes: 5, fetchImpl: async () => response('123456') }), /safety limit/);
  await assert.rejects(fetchJson('https://example.org', { fetchImpl: async () => ({ ok: true, status: 200, url: 'http://example.org' }) }), /HTTPS/);
});
test('response length caps are enforced before reading and during streaming', async () => {
  await assert.rejects(fetchJson('https://example.org', { maxBytes: 50, fetchImpl: async () => response('{}', 200, { 'content-length': '1000' }) }), /limit/);
  let cancelled = false;
  const stream = new ReadableStream({ pull(controller) { controller.enqueue(new Uint8Array(100)); }, cancel() { cancelled = true; } });
  await assert.rejects(fetchJson('https://example.org', { maxBytes: 50, fetchImpl: async () => new Response(stream) }), /limit/); assert.equal(cancelled, true);
});
test('timeouts also settle fetch implementations that ignore cancellation', async () => {
  const start = Date.now();
  await assert.rejects(fetchJson('https://example.org', { timeoutMs: 8, fetchImpl: () => new Promise(() => {}) }), /timed out/);
  assert.ok(Date.now() - start < 500);
});
test('429 and anonymous GitHub 403 cooldowns honour bounded retry metadata', async () => {
  assert.equal(retryTime(response({}, 429, { 'retry-after': '120' }), NOW), NOW + 120000);
  assert.equal(retryTime(response({}, 429, { 'retry-after': '999999999' }), NOW), NOW + 86400000);
  assert.equal(retryTime(response({}, 429, { 'retry-after': new Date(NOW + 180000).toUTCString() }), NOW), NOW + 180000);
  await assert.rejects(fetchJson('https://example.org', { now: NOW, fetchImpl: async () => response({}, 403, { 'x-ratelimit-remaining': '0' }) }), (e) => e.code === 'rate-limited' && e.retryAt > NOW);
});

// Persistence, single-flight concurrency, cancellation and native snapshot handoff.
test('construction, restore and filters do not make provider requests', async () => {
  let calls = 0; const s = storeWith(async () => { calls++; throw new Error('unexpected'); });
  await s.load(); await s.setFilters({ region: 'asia' }); await s.setEnabled('nws', true); assert.equal(calls, 0); assert.equal(s.events.length, 0);
});
test('same-source calls share one flight, fresh TTL avoids duplicate fetches, force remains explicit', async () => {
  const calls = []; const s = storeWith(providerFetch(calls));
  const a = s.sync('usgs'); const b = s.sync('usgs'); assert.equal(a, b); await Promise.all([a, b]);
  assert.equal(calls.length, 1); assert.equal(s.health().usgs.status, 'live'); assert.equal(s.sources.usgs.events.length, 2);
  await s.sync('usgs'); assert.equal(calls.length, 1); await s.sync('usgs', { force: true }); assert.equal(calls.length, 2);
});
test('full refresh caps concurrent source requests at three and excludes disabled providers', async () => {
  let active = 0; let max = 0; const seen = [];
  const s = storeWith(async (url) => { active++; max = Math.max(active, max); await new Promise((r) => setTimeout(r, 4)); const spec = SOURCES.find((p) => p.url === url); seen.push(spec.id); active--; return response(fixtures[spec.id]); });
  const a = s.refresh(); const b = s.refresh(); assert.equal(a, b); await a;
  assert.ok(max <= 3); assert.deepEqual(seen.sort(), SOURCES.filter((p) => p.enabled).map((p) => p.id).sort()); assert.equal(s.busy, false);
});
test('failed refresh retains validated events, reports failure and does not claim freshness', async () => {
  const s = storeWith(providerFetch()); await s.sync('usgs'); const previous = s.sources.usgs.events;
  s.fetchImpl = async () => response('<html>bad</html>'); await s.sync('usgs', { force: true });
  assert.equal(s.sources.usgs.events, previous); assert.equal(s.health().usgs.status, 'error'); assert.ok(s.sources.usgs.health.retryAt > NOW);
  assert.equal((await s.sync('usgs', { force: true })).reason, 'cooldown');
});
test('a genuinely empty successful refresh replaces old records instead of retaining invented activity', async () => {
  const s = storeWith(providerFetch()); await s.sync('usgs'); s.fetchImpl = async () => response(emptyFixtures.usgs); await s.sync('usgs', { force: true });
  assert.equal(s.sources.usgs.events.length, 0); assert.equal(s.health().usgs.status, 'live');
});
test('restored successful cache is labelled cached, expires by TTL and makes no network request', async () => {
  const storage = new MemoryStorage(); const s = storeWith(providerFetch(), storage); await s.sync('usgs');
  let calls = 0; const restored = storeWith(async () => { calls++; }, storage); await restored.load();
  assert.equal(restored.events.length, 2); assert.equal(restored.health().usgs.status, 'cached'); assert.equal(calls, 0);
  restored.clock = () => NOW + 600000; assert.equal(restored.health().usgs.status, 'stale');
});
test('provider rate limits survive workspace restore and cannot be bypassed by force refresh', async () => {
  const storage = new MemoryStorage(); const s = storeWith(async () => response({}, 429, { 'retry-after': '300' }), storage); await s.sync('usgs');
  const restored = storeWith(providerFetch(), storage); await restored.load(); assert.equal((await restored.sync('usgs', { force: true })).reason, 'cooldown');
});
test('cancelled and cleared refreshes cannot repopulate the cache via a late response', async () => {
  let release; const s = storeWith(() => new Promise((resolve) => { release = () => resolve(response(fixtures.usgs)); }));
  const pending = s.sync('usgs'); await Promise.resolve(); s.cancel(); release(); await pending; assert.equal(s.events.length, 0); assert.notEqual(s.health().usgs.status, 'live');
  s.fetchImpl = providerFetch(); await s.sync('usgs'); await s.addWatch({ label: 'High quakes', severity: 'high' }); await s.toggleBookmark(s.events[0]);
  await s.clearCache(); assert.equal(s.events.length, 0); assert.equal(s.bookmarks.length, 1); assert.equal(s.watches.length, 1); assert.equal(s.alerts.length, 0);
});
test('disabling a source cancels in-flight work and removes its alert matches', async () => {
  const s = storeWith(providerFetch()); await s.sync('usgs'); await s.addWatch({ label: 'High earthquakes', severity: 'high' }); assert.equal(s.alerts.length, 1);
  await s.setEnabled('usgs', false); assert.equal(s.alerts.length, 0); assert.equal(s.health().usgs.status, 'disabled'); assert.equal((await s.sync('usgs')).reason, 'disabled');
});
test('watch acknowledgements survive restore and repeat fetches do not create duplicates', async () => {
  const storage = new MemoryStorage(); const s = storeWith(providerFetch(), storage); await s.sync('usgs'); await s.addWatch({ label: 'Luzon', query: 'Luzon', severity: 'high' });
  assert.equal(s.alerts.length, 1); await s.acknowledge(); await s.sync('usgs', { force: true }); assert.equal(s.alerts.length, 1); assert.equal(s.alerts[0].read, true);
  const restored = storeWith(providerFetch(), storage); await restored.load(); assert.equal(restored.alerts.length, 1); assert.equal(restored.alerts[0].read, true);
});
test('watch replacement is atomic on validation failure and bookmarks are reversible', async () => {
  const s = storeWith(providerFetch()); await s.addWatch({ label: 'Existing' });
  await assert.rejects(s.replaceWatches([{ label: 'valid' }, { label: '' }]), /name/); assert.equal(s.watches[0].label, 'Existing');
  await s.toggleBookmark(event()); assert.equal(s.bookmarks.length, 1); await s.toggleBookmark(event()); assert.equal(s.bookmarks.length, 0);
});
test('storage corruption and quota errors are surfaced without false live data or lost in-memory results', async () => {
  const bad = new MemoryStorage({ 'world:workspace:v1': '{broken' }); const s = storeWith(providerFetch(), bad); await s.load(); assert.match(s.storageError, /could not be read/); assert.equal(s.events.length, 0);
  bad.failNext = 'write'; await s.sync('usgs'); assert.equal(s.events.length, 2); assert.match(s.storageError, /could not be saved/);
});
test('daily preference and saved country lenses persist without silently enabling five-minute polling', async () => {
  const storage = new MemoryStorage(); const s = storeWith(providerFetch(), storage); await s.setDaily(true); await s.setCountry('JP'); await s.toggleCountry('PH');
  const r = storeWith(providerFetch(), storage); await r.load(); assert.equal(r.dailyRefresh, true); assert.equal(r.autoRefresh, false); assert.equal(r.country, 'JP'); assert.deepEqual(r.savedCountries, ['PH']);
  await assert.rejects(r.setCountry('XX')); assert.equal(r.country, 'JP');
});
test('native daily snapshots are parsed again, labelled cached, and never override newer user refreshes', async () => {
  const s = storeWith(providerFetch());
  assert.equal((await s.importBackground({ version: 1, sources: [{ id: 'usgs', fetchedAt: NOW - 10000, data: fixtures.usgs }] })).imported, 1);
  assert.equal(s.health().usgs.status, 'cached'); await s.sync('usgs');
  await s.importBackground({ version: 1, sources: [{ id: 'usgs', fetchedAt: NOW - 5000, data: emptyFixtures.usgs }] }); assert.equal(s.events.length, 2);
  await assert.rejects(s.importBackground({ version: 999, sources: [] }));
});
test('native failed update keeps the previous background payload and exposes the actual error', async () => {
  const s = storeWith(providerFetch());
  const result = await s.importBackground({ version: 1, sources: [{ id: 'usgs', fetchedAt: NOW - 100000, attemptedAt: NOW - 1000, data: fixtures.usgs, error: 'HTTP 503' }] });
  assert.equal(result.imported, 1); assert.equal(s.events.length, 2); assert.equal(s.health().usgs.status, 'error'); assert.match(s.health().usgs.error, /503/);
});
test('native integration is completely inert on an ordinary website', async () => {
  let calls = 0; const s = storeWith(() => { calls++; }); assert.equal(configureDailyHost(s), false); assert.deepEqual(await loadBackgroundSnapshot(s), { imported: 0 }); assert.equal(calls, 0);
});

// Extensible feed catalogue.
test('custom feeds reject local URLs, credentials, unknown schema and invalid refresh intervals', () => {
  const base = { name: 'Public', url: 'https://example.org/feed', parser: 'generic', intervalHours: 24 };
  for (const url of ['https://localhost/', 'https://foo.local/', 'https://127.0.0.1/', 'http://example.org', 'https://example.org?api_key=secret']) assert.throws(() => normalizeCustomSource({ ...base, url }));
  assert.throws(() => normalizeCustomSource({ ...base, parser: 'unknown' })); assert.throws(() => normalizeCustomSource({ ...base, intervalHours: 0 }));
  assert.equal(normalizeCustomSource(base).id, normalizeCustomSource(base).id);
});
test('custom GeoJSON source can be added, fetched, restored, filtered and removed without orphan requests', async () => {
  const storage = new MemoryStorage(); let calls = 0;
  const raw = geo([{ type: 'Feature', id: 'custom-event', geometry: { type: 'Point', coordinates: [121, 15] }, properties: { title: 'User-added event', occurredAt: NOW - 1000, category: 'weather', severity: 'high', url: 'https://example.org/report' } }]);
  const s = storeWith(async () => { calls++; return response(raw); }, storage);
  const source = await s.addSource({ name: 'Example feed', url: 'https://example.org/world-feed', parser: 'generic', intervalHours: 24 }); assert.equal(calls, 0);
  await s.sync(source.id); assert.equal(calls, 1); assert.equal(s.sources[source.id].events[0].category, 'weather');
  await assert.rejects(s.addSource(source), /already/); await s.toggleBookmark(s.sources[source.id].events[0]);
  const r = storeWith(providerFetch(), storage); await r.load(); assert.ok(r.catalog.some((p) => p.id === source.id)); assert.equal(r.sources[source.id].events.length, 1);
  await r.setFilters({ source: source.id }); await r.removeSource(source.id); assert.equal(r.filters.source, 'all'); await assert.rejects(r.sync(source.id), /Unknown/);
  const again = storeWith(providerFetch(), storage); await again.load(); assert.equal(again.bookmarks.length, 1); assert.ok(SOURCE_BY_ID.get(again.bookmarks[0].source));
});

// Local weather and country dashboards.
test('weather accepts zero measurements, rejects missing required data and limits forecast length', () => {
  const data = copy(forecast); data.current.temperature_2m = 0; data.current.wind_speed_10m = 0; data.current.relative_humidity_2m = 0;
  const f = parseForecast(data); assert.equal(f.temperature, 0); assert.equal(f.wind, 0); assert.equal(f.days.length, 5); assert.equal(f.at, NOW);
  assert.equal(parseAir({ current: { time: '2026-11-08T12:00', us_aqi: 0 } }).aqi, 0);
  assert.throws(() => parseForecast({})); assert.throws(() => parseAir({})); assert.throws(() => normalizePlace({ lat: 100, lon: 0 }));
  assert.equal(normalizePlace({ lat: 14.60009, lon: 120.98009 }).lat, 14.6);
});
test('weather descriptions and air categories do not invent missing values', () => {
  assert.equal(weatherLabel(null), 'Conditions not supplied'); assert.equal(weatherLabel(95), 'Thunderstorm'); assert.equal(airLabel(null), 'Not available'); assert.equal(airLabel(40), 'Good'); assert.equal(airLabel(301), 'Hazardous');
});
test('weather uses explicit rounded coordinates, TTL cache, partial failure fallback and original timestamps', async () => {
  let calls = 0; let failAir = false; let clock = NOW;
  const service = new WeatherService({ storage: new MemoryStorage(), clock: () => clock, fetchImpl: async (url) => { calls++; assert.match(url, /latitude=14\.6&longitude=120\.98/); return url.includes('air-quality') ? failAir ? response({}, 503) : response(air) : response(forecast); } });
  const place = { name: 'Manila', lat: 14.60001, lon: 120.98001 };
  const first = await service.lookup(place); assert.equal(first.forecast.temperature, 29.5); assert.equal(first.air.aqi, 37); assert.equal(calls, 2);
  await service.lookup(place); assert.equal(calls, 2);
  failAir = true; clock += 3600000; const second = await service.lookup(place); assert.equal(second.airCached, true); assert.equal(second.airAt, NOW); assert.equal(second.forecastAt, clock); assert.equal(second.errors.length, 1);
});
test('weather cache restores without networking and distinguishes no data from an AQI of zero', async () => {
  const storage = new MemoryStorage(); const a = new WeatherService({ storage, clock: () => NOW, fetchImpl: async (url) => response(url.includes('air-quality') ? air : forecast) }); await a.lookup({ lat: 0, lon: 0 });
  let calls = 0; const b = new WeatherService({ storage, clock: () => NOW, fetchImpl: async () => { calls++; } }); await b.load(); assert.equal(calls, 0); assert.equal(b.get({ lat: 0, lon: 0 }).cached, true);
});
test('country directory has 250 searchable, unique entries and explicit geographic gaps', () => {
  assert.equal(COUNTRIES.length, 250); assert.equal(new Set(COUNTRIES.map((c) => c.code)).size, 250);
  assert.equal(searchCountries('Philippines')[0].code, 'PH'); assert.ok(searchCountries('Caribbean').length > 1); assert.equal(COUNTRY_BY_CODE.get('JP').capital, 'Tokyo');
});
test('country point-in-polygon handles holes and the antimeridian', () => {
  const outer = [[0, 0], [10, 0], [10, 10], [0, 10], [0, 0]]; const hole = [[4, 4], [6, 4], [6, 6], [4, 6], [4, 4]];
  assert.equal(pointInRing(2, 2, outer), true); assert.equal(inCountry({ lat: 5, lon: 5 }, [[outer, hole]]), false);
  const dateline = [[179, -2], [-179, -2], [-179, 2], [179, 2], [179, -2]];
  assert.equal(pointInRing(0, 179.5, dateline), true); assert.equal(pointInRing(0, -179.5, dateline), true); assert.equal(pointInRing(0, 0, dateline), false);
});
test('bundled boundaries locate real reference coordinates and never assign unlocated headlines to countries', () => {
  const boundaries = JSON.parse(readFileSync(new URL('../../assets/country-boundaries.json', import.meta.url))).countries;
  assert.equal(Object.keys(boundaries).length, 237);
  assert.equal(inCountry({ lat: 14.6, lon: 120.98 }, boundaries.PH), true); assert.equal(inCountry({ lat: 35.68, lon: 139.69 }, boundaries.PH), false);
  const summary = countrySummary(COUNTRY_BY_CODE.get('PH'), [event(), event({ id: 'headline', title: 'Philippines report', lat: null })], boundaries);
  assert.equal(summary.located.length, 1); assert.equal(summary.mentions.length, 1);
  assert.equal(countrySummary(COUNTRY_BY_CODE.get('TK'), [event()], boundaries).hasBoundary, false);
  const many = Array.from({ length: 4000 }, (_, n) => event({ id: String(n), lat: (n % 170) - 85, lon: (n % 350) - 175 }));
  const start = performance.now(); countrySummary(COUNTRY_BY_CODE.get('PH'), many, boundaries); assert.ok(performance.now() - start < 1500, 'country filtering must remain bounded');
});
test('country indicators use the actual publication year and preserve old values on provider failure', async () => {
  let fail = false; let clock = NOW; const service = new CountryService({ storage: new MemoryStorage(), clock: () => clock, fetchImpl: async () => fail ? response({}, 503) : response([{}, [{ date: '2026', value: null }, { date: '2024', value: 12345 }]]) });
  const first = await service.profile('PH'); assert.equal(first.population.year, '2024'); assert.equal(first.population.value, 12345);
  clock += 2 * 86400000; fail = true; const next = await service.profile('PH'); assert.equal(next.population.cached, true); assert.equal(next.population.value, 12345); assert.match(next.population.error, /503/);
  await assert.rejects(service.profile('XX'), /country/);
});


test('source failure reason, last attempt and backoff survive reload beside the last good records', async () => {
  const storage = new MemoryStorage(); const s = storeWith(providerFetch(), storage); await s.sync('usgs');
  s.fetchImpl = async () => response({}, 503); await s.sync('usgs', { force: true });
  const restored = storeWith(providerFetch(), storage); await restored.load();
  assert.equal(restored.events.length, 2); assert.equal(restored.health().usgs.status, 'offline');
  assert.match(restored.health().usgs.error, /503/); assert.equal(restored.health().usgs.lastAttempt, NOW);
  assert.equal(restored.health().usgs.failures, 1); assert.equal(restored.health().usgs.lastSuccess, NOW);
});

test('restored rate limits remain visibly rate-limited, not just silently delayed', async () => {
  const storage = new MemoryStorage(); const s = storeWith(async () => response({}, 429), storage); await s.sync('usgs');
  const restored = storeWith(providerFetch(), storage); await restored.load();
  assert.equal(restored.health().usgs.status, 'rate-limited'); assert.match(restored.health().usgs.error, /429/);
});
