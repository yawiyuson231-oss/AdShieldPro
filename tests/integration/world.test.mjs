/** Actual application DOM and controls; only provider transport and downloads are replaced. */
import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';
import { SOURCES } from '../../world/catalog.js';
import { WorldStore } from '../../world/store.js';
import { NOW, fixtures, emptyFixtures, forecast, air, response, quake, geo } from '../fixtures/world.mjs';

const ROOT = new URL('../../', import.meta.url);
const read = (name) => readFileSync(new URL(name, ROOT), 'utf8');
let dom; let win; let app; let view; let store;
const calls = []; const downloads = []; const modes = new Map();
const $ = (selector) => win.document.querySelector(selector);
const text = (selector) => $(selector)?.textContent || '';
const click = (selector) => { const node = $(selector); assert.ok(node, `Missing control ${selector}`); node.click(); };
const change = (selector, value) => { const node = $(selector); node.value = value; node.dispatchEvent(new win.Event('change', { bubbles: true })); };
const input = (selector, value) => { const node = $(selector); node.value = value; node.dispatchEvent(new win.Event('input', { bubbles: true })); };
const submit = (selector) => $(selector).dispatchEvent(new win.Event('submit', { bubbles: true, cancelable: true }));
const waitFor = async (predicate, message = 'UI operation') => {
  for (let n = 0; n < 150; n++) { if (predicate()) return; await new Promise((r) => setTimeout(r, 5)); }
  assert.fail(`${message} did not finish`);
};
const setGlobal = (name, value) => Object.defineProperty(globalThis, name, { configurable: true, writable: true, value });

before(async () => {
  dom = new JSDOM(read('index.html'), { url: 'https://preview.example/app/', pretendToBeVisual: true, runScripts: 'outside-only' }); win = dom.window;
  for (const key of ['window', 'document', 'navigator', 'location', 'history', 'localStorage', 'FileReader', 'File', 'Blob', 'Event', 'Node', 'HTMLElement']) setGlobal(key, key === 'window' ? win : win[key]);
  win.HTMLCanvasElement.prototype.getContext = () => null;
  win.HTMLElement.prototype.scrollIntoView = () => {};
  setGlobal('confirm', () => true);
  setGlobal('fetch', async (input, init) => {
    const url = new URL(String(input), win.location.href); const href = url.href; calls.push({ href, init });
    if (url.pathname.includes('/assets/')) {
      try { return response(read(url.pathname.slice(url.pathname.indexOf('assets/')))); } catch { return response('', 404); }
    }
    const source = SOURCES.find((s) => s.url === href);
    if (source) {
      if (modes.get(source.id) === 'error') return response({}, 503);
      if (modes.get(source.id) === 'empty') return response(emptyFixtures[source.id]);
      if (modes.get(source.id) === 'hostile') return response(geo([quake({ title: '<img src=x onerror=alert(1)>', place: '<script>window.pwned=1</script>', url: 'javascript:alert(1)' })]));
      return response(fixtures[source.id]);
    }
    if (url.hostname === 'api.open-meteo.com') return response(forecast);
    if (url.hostname === 'air-quality-api.open-meteo.com') return response(air);
    if (url.hostname === 'api.worldbank.org') return response([{}, [{ date: '2026', value: null }, { date: '2024', value: 12345 }]]);
    if (url.hostname === 'example.org' && url.pathname === '/public-world-feed') return response(geo([{ type: 'Feature', id: 'custom-record', geometry: null, properties: { title: 'Custom source test record', category: 'news', occurredAt: NOW - 1000, url: 'https://example.org/report' } }]));
    if (url.hostname === 'raw.githubusercontent.com') return response({}, 503);
    throw new Error(`Unexpected fetch: ${href}`);
  });
  await import('../../app.js'); app = globalThis.__omnishield; await app.ready;
  store = app.state.world; store.clock = () => NOW; view = app.state.worldView; view.download = (filename, data, mime) => downloads.push({ filename, data, mime });
  app.state.settings.autoUpdateFeeds = false;
});
after(() => { app?.stop(); win?.close(); });

test('World Monitor boots as a complete offline workspace without unrequested provider calls', () => {
  assert.equal(app.state.currentPage, 'world'); assert.equal($('#page-world').hidden, false);
  assert.equal(calls.filter((c) => SOURCES.some((s) => s.url === c.href)).length, 0);
  assert.match(text('#world-notice'), /You decide when to connect/); assert.ok($('#world-map svg')); assert.equal($('#world-map').querySelectorAll('.wm-map-node').length, 0);
  assert.match(text('#world-events'), /feeds are next/i); assert.equal($('#world-auto').getAttribute('aria-pressed'), 'false');
});
test('the real refresh button populates map, counts, sourced events and situation summary', async () => {
  click('#world-refresh'); await waitFor(() => !store.busy && store.events.length > 0);
  assert.equal(store.events.length, 6); assert.match(text('#world-stats'), /6/); assert.equal($('#world-refresh').disabled, false);
  assert.ok($('#world-map').querySelectorAll('.wm-map-node').length > 0); assert.match(text('#world-events'), /CVE-2026-54321/);
  assert.match(text('#world-notice'), /5 of 5/); assert.match(text('.wm-brief'), /6 records/);
});
test('search, country region, time, priority, layers and reset all affect real event records', () => {
  input('#world-search', 'Luzon'); assert.equal($('#world-events').querySelectorAll('article').length, 1);
  change('#world-region', 'philippines'); assert.match(text('#world-events'), /Luzon/);
  change('#world-severity', 'critical'); assert.match(text('#world-events'), /No records match/);
  click('#world-reset-filters'); assert.equal(store.filtered().length, 6);
  click('[data-layer="cyber"]'); assert.equal(store.filtered().length, 4); assert.equal($('[data-layer="cyber"]').getAttribute('aria-pressed'), 'false');
  click('#world-reset-filters'); change('#world-sort', 'severity'); assert.match($('#world-events article').textContent, /CRITICAL/);
});
test('map supports keyboard zoom and reset without relying on animation or remote tiles', () => {
  const svg = $('#world-map svg'); svg.focus(); const initial = svg.getAttribute('viewBox');
  svg.dispatchEvent(new win.KeyboardEvent('keydown', { key: '+', bubbles: true })); assert.notEqual(svg.getAttribute('viewBox'), initial);
  svg.dispatchEvent(new win.KeyboardEvent('keydown', { key: 'Home', bubbles: true })); assert.equal(svg.getAttribute('viewBox'), '0 0 1000 500');
  assert.match(svg.getAttribute('aria-label'), /Arrow keys/);
});
test('bookmarks and detail actions are functional and source links open safely', () => {
  click('[data-save-event="usgs:test-ph-quake"]'); assert.equal(store.bookmarks.length, 1);
  click('[data-world-tab="saved"]'); assert.match(text('#world-events'), /SAVED SNAPSHOT/);
  click('#world-events .wm-event-title'); assert.equal($('#world-detail').open, true); assert.match(text('#world-detail'), /Local magnitude bands/);
  const link = $('#world-detail a'); assert.equal(link.getAttribute('rel'), 'noopener noreferrer'); assert.equal(link.target, '_blank');
  click('#world-detail-locate'); assert.equal($('#world-detail').open, false); assert.ok(view.map.camera.zoom >= 3);
  click('[data-world-tab="events"]');
});
test('watch form creates persistent rules and its inbox supports acknowledgement and pause', async () => {
  click('[data-world-tab="watches"]'); input('#world-watch-name', 'Luzon watch'); input('#world-watch-query', 'Luzon'); submit('#world-watch-form');
  await waitFor(() => store.watches.length === 1); assert.equal(store.alerts.length, 1); assert.match(text('#world-alert-inbox'), /1 unread/);
  click('#world-alerts-read'); assert.equal(store.alerts[0].read, true); assert.match(text('#world-alert-inbox'), /0 unread/);
  click('[aria-label="Toggle Luzon watch"]'); assert.equal(store.watches[0].enabled, false); assert.equal(store.alerts.length, 0);
  click('[aria-label="Toggle Luzon watch"]'); assert.equal(store.alerts.length, 1);
  click('#world-watches-export'); const data = JSON.parse(downloads.at(-1).data); assert.equal(data.schema, 'omnishield-world-watches'); assert.equal(data.watches[0].label, 'Luzon watch');
});
test('watchlist import drives the actual file input, validates data and replaces only watch rules', async () => {
  const payload = JSON.stringify({ schema: 'omnishield-world-watches', version: 1, watches: [{ label: 'Imported cyber watch', category: 'cyber', severity: 'critical' }] });
  const file = new win.File([payload], 'watches.json', { type: 'application/json' });
  const control = $('#world-watch-import'); Object.defineProperty(control, 'files', { value: [file], configurable: true }); control.dispatchEvent(new win.Event('change', { bubbles: true }));
  await waitFor(() => store.watches[0]?.label === 'Imported cyber watch'); assert.equal(store.events.length, 6); assert.equal(store.bookmarks.length, 1); assert.equal(store.alerts.length, 1);
});
test('provider failures retain cached records, display reasons and disable premature retries', async () => {
  modes.set('usgs', 'error'); await store.sync('usgs', { force: true });
  click('[data-world-tab="sources"]'); const source = $('[data-source="usgs"]');
  assert.match(source.textContent, /OFFLINE/); assert.match(source.textContent, /503/); assert.match(source.textContent, /Retry after/); assert.equal(source.querySelector('.wm-source-actions button').disabled, true);
  assert.equal(store.sources.usgs.events.length, 2); modes.delete('usgs'); store.sources.usgs.health.retryAt = null; await store.sync('usgs', { force: true });
});
test('custom feed UI saves an endpoint without contacting it, then actual refresh parses it', async () => {
  click('[data-world-tab="sources"]');
  input('#world-custom-name', 'My worldwide feed'); input('#world-custom-url', 'https://example.org/public-world-feed');
  const before = calls.length; submit('#world-custom-form'); await waitFor(() => store.customSources.length === 1); assert.equal(calls.length, before);
  const id = store.customSources[0].id; click(`[data-source="${id}"] .wm-source-actions button`); await waitFor(() => store.sources[id].events.length === 1);
  assert.match($(`[data-source="${id}"]`).textContent, /LIVE/); assert.match($(`[data-source="${id}"]`).textContent, /User-added/);
});
test('all country dashboards are searchable and geographic evidence is separate from country mentions', async () => {
  click('#world-reset-filters'); click('[data-world-tab="countries"]');
  await waitFor(() => view.countryView.service.boundaries, 'bundled country boundaries');
  input('#world-country-search', 'Philippines'); assert.equal($('#world-country-directory').querySelectorAll('button').length, 1);
  click('[data-country="PH"]'); assert.match(text('#world-country-detail'), /Luzon/); assert.match(text('#world-country-detail'), /zero count means no matching received records/);
  click('#world-country-save'); assert.ok(store.savedCountries.includes('PH')); assert.equal($('#world-country-save').getAttribute('aria-pressed'), 'true');
  input('#world-country-search', 'Tokelau'); click('[data-country="TK"]'); assert.match(text('#world-country-detail'), /no separate polygon/);
  input('#world-country-search', 'Japan'); click('[data-country="JP"]'); assert.match(text('#world-country-detail'), /Tokyo/);
});
test('country indicators show the real publication year and never masquerade as live readings', async () => {
  click('#world-country-profile'); await waitFor(() => !view.countryView.profileBusy);
  assert.match(text('#world-country-detail'), /Published for 2024/); assert.match(text('#world-country-detail'), /12,345/);
});
test('country-to-weather action uses its stated reference point without requesting GPS', () => {
  click('#world-country-weather'); assert.equal(view.tab, 'weather'); assert.equal(Number($('#world-weather-lat').value), 36); assert.match(text('#world-weather-form'), /GPS is never requested/);
});
test('weather and air lookups are explicit and display modelled measurements and a five-day forecast', async () => {
  change('#world-weather-place', 'manila'); const before = calls.filter((c) => c.href.includes('open-meteo')).length;
  assert.equal(calls.filter((c) => c.href.includes('open-meteo')).length, before);
  submit('#world-weather-form'); await waitFor(() => !view.weatherBusy && text('#world-weather-result').includes('29.5'));
  assert.match(text('#world-weather-result'), /37/); assert.match(text('#world-weather-result'), /Good/); assert.equal($('#world-weather-result').querySelectorAll('.wm-forecast article').length, 5);
  assert.match(text('.wm-weather-attribution'), /Modelled weather/);
});
test('JSON, CSV and Markdown export buttons produce the actual filtered dataset with source status', () => {
  click('[data-world-tab="events"]'); input('#world-search', 'Luzon');
  for (const format of ['json', 'csv', 'md']) { change('#world-export-format', format); click('#world-export'); }
  const [json, csv, markdown] = downloads.slice(-3); assert.equal(JSON.parse(json.data).events.length, 1); assert.match(csv.data, /severityBasis,dataStatus/); assert.match(markdown.data, /1 matching records/); assert.match(markdown.data, /not a prediction/);
  click('#world-reset-filters');
});
test('daily and live refresh controls respect visibility, offline state and the session interval', async () => {
  click('[data-world-tab="sources"]');
  Object.defineProperty(win.document, 'visibilityState', { value: 'hidden', configurable: true }); const before = calls.length;
  click('#world-daily'); view.tick(); assert.equal(store.dailyRefresh, true); assert.equal(calls.length, before);
  Object.defineProperty(win.document, 'visibilityState', { value: 'visible', configurable: true });
  Object.defineProperty(win.navigator, 'onLine', { value: false, configurable: true }); view.tick(); assert.equal(calls.length, before);
  Object.defineProperty(win.navigator, 'onLine', { value: true, configurable: true }); view.tick(); await waitFor(() => !store.busy); assert.equal(store.lastDaily, NOW);
  await store.setDaily(false); click('#world-auto'); assert.equal(store.autoRefresh, true); await waitFor(() => !store.busy); click('#world-auto'); assert.equal(store.autoRefresh, false);
});
test('provider text is inert, hostile links are stripped, and no HTML injection reaches event details', async () => {
  modes.set('usgs', 'hostile'); store.sources.usgs.health.retryAt = null; await store.sync('usgs', { force: true }); click('[data-world-tab="events"]'); input('#world-search', '<img');
  assert.match(text('#world-events'), /<img src=x/); assert.equal($('#world-events img'), null); assert.equal($('#world-events script'), null);
  click('#world-events .wm-event-title'); assert.equal($('#world-detail script'), null); assert.equal($('#world-detail a'), null); assert.equal(win.pwned, undefined);
  click('#world-detail-close'); modes.delete('usgs'); await store.sync('usgs', { force: true }); click('#world-reset-filters');
});
test('command finder, keyboard shortcut, theme switch, URL routing and unknown-route guard all work', () => {
  click('#command-open'); assert.equal($('#command-menu').open, true); input('#command-search', 'DNS'); click('[data-command-page="dns"]'); assert.equal(app.state.currentPage, 'dns'); assert.equal($('#command-menu').open, false);
  win.document.dispatchEvent(new win.KeyboardEvent('keydown', { key: 'k', ctrlKey: true, bubbles: true })); assert.equal($('#command-menu').open, true);
  $('#command-search').dispatchEvent(new win.KeyboardEvent('keydown', { key: 'Escape', bubbles: true })); assert.equal($('#command-menu').open, false);
  click('#theme-toggle'); assert.equal(win.document.documentElement.dataset.theme, 'light'); assert.match($('#theme-toggle').getAttribute('aria-label'), /dark/); click('#theme-toggle');
  const old = app.state.currentPage; assert.equal(app.navigate('__proto__'), false); assert.equal(app.state.currentPage, old);
  win.location.hash = '#world'; win.dispatchEvent(new win.HashChangeEvent('hashchange')); assert.equal(app.state.currentPage, 'world'); assert.equal(text('#page-title'), 'World Monitor');
});
test('complete workspace restore preserves custom feeds, saved countries, watches, bookmarks and cached records', async () => {
  await store.persist(); const restored = new WorldStore({ storage: store.storage, clock: () => NOW, fetchImpl: async () => { throw new Error('Restore must not fetch'); } }); await restored.load();
  assert.equal(restored.customSources.length, 1); assert.equal(restored.bookmarks.length, 1); assert.equal(restored.watches.length, 1); assert.ok(restored.savedCountries.includes('PH'));
  assert.equal(restored.health().usgs.status, 'cached'); assert.ok(restored.events.length >= 6);
});
test('cache clear control is confirmation-gated and preserves saved records and watch rules', async () => {
  click('[data-world-tab="sources"]'); setGlobal('confirm', () => false); click('#world-clear-cache'); assert.ok(store.events.length > 0);
  setGlobal('confirm', () => true); click('#world-clear-cache'); await waitFor(() => store.events.length === 0); assert.equal(store.bookmarks.length, 1); assert.equal(store.watches.length, 1); assert.equal(store.alerts.length, 0);
});
