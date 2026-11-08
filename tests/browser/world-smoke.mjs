/** Real Chromium layout, document downloads, persistence and service-worker acceptance.
 * All remote data is explicitly synthetic at the network boundary; this is NOT a live-provider audit.
 * Run: npx playwright install chromium && npm run test:browser
 * Optional: WORLD_BROWSER_EXECUTABLE=/path/to/chromium WORLD_BROWSER_ARGS='["--no-sandbox"]'
 */
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile, mkdir } from 'node:fs/promises';
import { resolve, extname, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';
import { SOURCES } from '../../world/catalog.js';
import { fixtures, forecast, air } from '../fixtures/world.mjs';
const root = resolve(fileURLToPath(new URL('../../', import.meta.url)));
const screenshots = resolve(root, '.cache/screenshots'); await mkdir(screenshots, { recursive: true });
const mime = { '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.html': 'text/html', '.svg': 'image/svg+xml', '.webmanifest': 'application/manifest+json', '.txt': 'text/plain' };
const server = createServer(async (request, response) => {
  try {
    const path = decodeURIComponent(new URL(request.url, 'http://localhost').pathname);
    const file = resolve(root, `.${path.endsWith('/') ? `${path}index.html` : path}`);
    if (!file.startsWith(root + sep)) { response.writeHead(403).end(); return; }
    const content = await readFile(file); response.writeHead(200, { 'Content-Type': mime[extname(file)] || 'application/octet-stream' }).end(content);
  } catch { response.writeHead(404).end('Not found'); }
});
await new Promise((done) => server.listen(0, '0.0.0.0', done));
const base = `http://127.0.0.1:${server.address().port}`;
let browser; let checks = 0;
const pass = (name) => { checks++; console.log(`PASS ${name}`); };
try {
  const args = JSON.parse(process.env.WORLD_BROWSER_ARGS || '["--no-sandbox"]');
  assert.ok(!args.includes('--disable-web-security'), 'Browser acceptance must use normal web security');
  browser = await chromium.launch({ headless: true, executablePath: process.env.WORLD_BROWSER_EXECUTABLE || undefined, args });
  const context = await browser.newContext({ viewport: { width: 1440, height: 1050 }, acceptDownloads: true });
  const providerCalls = []; const errors = [];
  await context.route(/^https:\/\//, async (route) => {
    const url = route.request().url(); const provider = SOURCES.find((s) => s.url === url);
    const headers = { 'access-control-allow-origin': '*', 'content-type': 'application/json' };
    if (provider) { providerCalls.push(provider.id); await route.fulfill({ body: JSON.stringify(fixtures[provider.id]), headers }); }
    else if (new URL(url).hostname === 'api.open-meteo.com') await route.fulfill({ body: JSON.stringify(forecast), headers });
    else if (new URL(url).hostname === 'air-quality-api.open-meteo.com') await route.fulfill({ body: JSON.stringify(air), headers });
    else if (url.includes('api.worldbank.org')) await route.fulfill({ body: JSON.stringify([{}, [{ date: '2024', value: 12345 }]]), headers });
    else await route.abort();
  });
  const page = await context.newPage(); page.on('pageerror', (error) => errors.push(error.message));
  await page.goto(`${base}/#world`); await page.waitForFunction(() => globalThis.__omnishield?.state.booted);
  await page.evaluate(async () => { __omnishield.state.settings.autoUpdateFeeds = false; await navigator.serviceWorker.ready; });
  await page.waitForFunction(() => navigator.serviceWorker.controller);
  assert.equal(providerCalls.length, 0); assert.equal(await page.locator('.wm-map-node').count(), 0);
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth), 1440);
  await page.screenshot({ path: `${screenshots}/world-desktop-empty.png`, fullPage: true });
  pass('offline-ready initial workspace, desktop layout, no unsolicited world requests or fake markers');

  await page.locator('#world-refresh').click();
  await page.waitForFunction(() => !__omnishield.state.world.busy && __omnishield.state.world.events.length >= 6);
  assert.equal(providerCalls.length, SOURCES.filter((s) => s.enabled).length);
  assert.ok(await page.locator('.wm-map-node').count() > 0);
  pass('real Refresh control populates map and events from labelled test fixtures');

  await page.locator('#world-search').fill('Luzon');
  assert.equal(await page.locator('#world-events article').count(), 1);
  await page.locator('#world-events .wm-event-title').click();
  assert.equal(await page.locator('#world-detail').evaluate((node) => node.open), true);
  assert.equal(await page.locator('#world-detail a').getAttribute('rel'), 'noopener noreferrer');
  await page.locator('#world-detail-close').click();
  await page.locator('[data-save-event="usgs:test-ph-quake"]').click();
  await page.waitForFunction(() => __omnishield.state.world.bookmarks.length === 1);
  pass('search, detail dialog, protected source link and saved event');

  for (const format of ['json', 'csv', 'md']) {
    await page.locator('#world-export-format').selectOption(format);
    const downloadReady = page.waitForEvent('download'); await page.locator('#world-export').click();
    const download = await downloadReady; assert.equal(await download.failure(), null);
    const content = await readFile(await download.path(), 'utf8');
    assert.ok(download.suggestedFilename().endsWith(`.${format}`));
    if (format === 'json') assert.equal(JSON.parse(content).events.length, 1);
    else assert.match(content, /Luzon/);
  }
  pass('actual JSON, CSV and Markdown browser downloads contain the filtered dataset');
  await page.locator('#world-reset-filters').click();

  const map = page.locator('#world-map svg.wm-map-svg');
  await map.focus(); await page.keyboard.press('+');
  assert.ok(await page.evaluate(() => __omnishield.state.worldView.map.camera.zoom > 1));
  const box = await map.boundingBox(); const beforePan = await page.evaluate(() => __omnishield.state.worldView.map.camera.x);
  await page.mouse.move(box.x + box.width * .5, box.y + box.height * .5); await page.mouse.down();
  await page.mouse.move(box.x + box.width * .4, box.y + box.height * .5, { steps: 6 }); await page.mouse.up();
  assert.ok(await page.evaluate((before) => __omnishield.state.worldView.map.camera.x > before, beforePan));
  await map.focus(); await page.keyboard.press('Home');
  assert.equal(await map.getAttribute('viewBox'), '0 0 1000 500');
  pass('keyboard zoom, real pointer drag and map reset');

  await page.locator('[data-world-tab="watches"]').click();
  await page.locator('#world-watch-import').setInputFiles({ name: 'test-watches.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify({ schema: 'omnishield-world-watches', version: 1, watches: [{ label: 'Browser imported watch', query: 'Luzon', severity: 'high' }] })) });
  await page.waitForFunction(() => __omnishield.state.world.watches[0]?.label === 'Browser imported watch');
  assert.match(await page.locator('#world-alert-inbox').textContent(), /1 unread/);
  await page.locator('#world-alerts-read').click();
  assert.match(await page.locator('#world-alert-inbox').textContent(), /0 unread/);
  pass('real file-input import, local watch matching and acknowledgement');

  await page.locator('[data-world-tab="countries"]').click();
  await page.waitForFunction(() => __omnishield.state.worldView.countryView.service.boundaries);
  await page.locator('#world-country-search').fill('Philippines'); await page.locator('[data-country="PH"]').click();
  assert.match(await page.locator('#world-country-detail').textContent(), /Luzon/);
  await page.locator('#world-country-save').click();
  await page.locator('#world-country-profile').click();
  await page.waitForFunction(() => !__omnishield.state.worldView.countryView.profileBusy);
  assert.match(await page.locator('#world-country-detail').textContent(), /Published for 2024/);
  await page.locator('#world-country-search').fill('Tokelau'); await page.locator('[data-country="TK"]').click();
  assert.match(await page.locator('#world-country-detail').textContent(), /no separate polygon/);
  pass('country selection, spatial evidence, dated indicators and an explicit boundary gap');

  await page.locator('[data-world-tab="weather"]').click();
  await page.locator('#world-weather-place').selectOption('manila');
  await page.locator('#world-weather-form button[type="submit"]').click();
  await page.waitForFunction(() => !__omnishield.state.worldView.weatherBusy);
  assert.match(await page.locator('#world-weather-result').textContent(), /29.5/);
  assert.match(await page.locator('#world-weather-result').textContent(), /Good/);
  pass('explicit weather/air form displays independent provider values');

  await page.setViewportSize({ width: 390, height: 844 });
  for (const tab of ['events', 'countries', 'watches', 'weather', 'sources']) {
    await page.locator(`[data-world-tab="${tab}"]`).click();
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth), 390, `${tab} should fit a phone`);
  }
  await page.locator('#theme-toggle').click();
  assert.equal(await page.locator('html').getAttribute('data-theme'), 'light');
  pass('all monitor panes fit 390px, and theme switch works');

  await page.keyboard.press('Control+k'); await page.locator('#command-search').fill('DNS');
  await page.keyboard.press('ArrowUp');
  assert.equal(await page.locator('[data-command-page="dns"]').evaluate((node) => node === document.activeElement), true);
  await page.keyboard.press('Enter');
  await page.waitForFunction(() => __omnishield.state.currentPage === 'dns');
  await page.keyboard.press('Control+k'); await page.locator('#command-search').fill('World'); await page.keyboard.press('Enter');
  await page.waitForFunction(() => __omnishield.state.currentPage === 'world');
  pass('keyboard-only quick finder opens DNS and returns to World Monitor');

  await page.evaluate(() => __omnishield.state.world.persist());
  const beforeOffline = providerCalls.length;
  await context.setOffline(true); await page.reload();
  await page.waitForFunction(() => globalThis.__omnishield?.state.booted);
  assert.equal(providerCalls.length, beforeOffline);
  assert.equal(await page.locator('html').getAttribute('data-theme'), 'light');
  assert.equal(await page.evaluate(() => __omnishield.state.world.bookmarks.length), 1);
  assert.equal(await page.evaluate(() => __omnishield.state.world.watches[0].label), 'Browser imported watch');
  assert.ok(['cached', 'stale'].includes(await page.evaluate(() => __omnishield.state.world.health().usgs.status)));
  await page.locator('[data-world-tab="countries"]').click();
  await page.waitForFunction(() => __omnishield.state.worldView.countryView.service.boundaries);
  await page.locator('#world-country-search').fill('Philippines'); await page.locator('[data-country="PH"]').click();
  assert.match(await page.locator('#world-country-detail').textContent(), /Luzon/);
  pass('real offline reload keeps shell, map, country geometry, bookmarks, watches and cache labels');

  assert.deepEqual(errors, []); pass('no uncaught browser errors throughout');
  console.log(`\n${checks} real-browser acceptance checks passed; fixture-backed provider transport, not a live-source claim.`);
} finally {
  await browser?.close();
  await new Promise((done) => server.close(done));
}
