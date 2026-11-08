#!/usr/bin/env node
/** Point-in-time provider audit, separate from deterministic CI and from the user's local data. */
import { writeFileSync, appendFileSync } from 'node:fs';
import { SOURCES } from '../world/catalog.js';
import { fetchJson } from '../world/network.js';
import { parseSource } from '../world/parsers.js';
import { WeatherService } from '../world/weather.js';
import { CountryService } from '../world/countries.js';
const origin = 'https://yawiyuson231-oss.github.io';
const startedAt = new Date().toISOString();
const queue = [...SOURCES]; const results = [];
const worker = async () => {
  while (queue.length) {
    const source = queue.shift(); const started = performance.now();
    const row = { id: source.id, name: source.name, url: source.url, checkedAt: new Date().toISOString(), httpStatus: null, corsHeader: null, browserOriginAllowed: null, valid: false, records: null, error: null };
    try {
      const data = await fetchJson(source.url, {
        accept: source.accept, timeoutMs: 20_000,
        fetchImpl: async (url, options) => {
          const response = await fetch(url, { ...options, headers: { ...options.headers, origin } });
          row.httpStatus = response.status;
          row.corsHeader = response.headers.get('access-control-allow-origin');
          row.browserOriginAllowed = row.corsHeader === '*' || row.corsHeader === origin;
          return response;
        }
      });
      const parsed = parseSource(source.id, data);
      row.valid = true; row.records = parsed.events.length; row.rejected = parsed.rejected; row.truncated = parsed.truncated;
    } catch (error) { row.error = error.message; }
    row.durationMs = Math.round(performance.now() - started); results.push(row);
    console.log(`${row.valid ? 'VALID' : 'UNAVAILABLE'} ${row.id}: ${row.valid ? `${row.records} records; CORS ${row.browserOriginAllowed ? 'allowed' : 'not advertised'}` : row.error}`);
  }
};
await Promise.all([worker(), worker(), worker()]);
results.sort((a, b) => SOURCES.findIndex((s) => s.id === a.id) - SOURCES.findIndex((s) => s.id === b.id));
// Exercise the actual country/weather clients too, using a fixed public sample location,
// never a device's GPS or private preferences. These are context services, not extra event feeds.
const contextRows = {};
const contextFetch = async (url, options) => {
  const parsed = new URL(url);
  const id = parsed.hostname === 'api.open-meteo.com' ? 'forecast-manila' : parsed.hostname === 'air-quality-api.open-meteo.com' ? 'air-manila' : parsed.pathname.includes('SP.POP.TOTL') ? 'population-ph' : 'gdp-per-capita-ph';
  const row = contextRows[id] = { id, url, checkedAt: new Date().toISOString(), httpStatus: null, browserOriginAllowed: null };
  const response = await fetch(url, { ...options, headers: { ...options.headers, origin } });
  row.httpStatus = response.status; row.corsHeader = response.headers.get('access-control-allow-origin');
  row.browserOriginAllowed = row.corsHeader === '*' || row.corsHeader === origin;
  return response;
};
const [weather, country] = await Promise.all([
  new WeatherService({ fetchImpl: contextFetch }).lookup({ name: 'Manila (public audit sample)', lat: 14.60, lon: 120.98 }),
  new CountryService({ fetchImpl: contextFetch }).profile('PH')
]);
for (const [id, value, error] of [
  ['forecast-manila', weather.forecast, weather.errors.find((error) => error.startsWith('Forecast:'))],
  ['air-manila', weather.air, weather.errors.find((error) => error.startsWith('Air quality:'))],
  ['population-ph', country.population?.value, country.population?.error],
  ['gdp-per-capita-ph', country.gdpPerCapita?.value, country.gdpPerCapita?.error]
]) { contextRows[id].valid = value !== null && value !== undefined; contextRows[id].error = error || null; }
contextRows['population-ph'].publishedYear = country.population?.year;
contextRows['gdp-per-capita-ph'].publishedYear = country.gdpPerCapita?.year;
const contextServices = Object.values(contextRows);
console.log('Context services: ' + JSON.stringify(contextServices));
if (process.env.GITHUB_ACTIONS) console.log(`::notice title=World context audit::${contextServices.map((r) => `${r.id}: HTTP=${r.httpStatus}; valid=${r.valid}; CORS=${r.browserOriginAllowed}; year=${r.publishedYear || 'not applicable'}; ${r.error || 'schema valid'}`).join(' | ')}`);
const report = { version: 1, startedAt, finishedAt: new Date().toISOString(), origin, note: 'Point-in-time unauthenticated checks. Provider availability is not guaranteed; CORS headers are measured for this origin, not assumed. This report is not fed into the UI as live data.', results, contextServices };
if (process.env.GITHUB_ACTIONS) console.log(`::notice title=World source audit::${results.map((r) => `${r.id}: HTTP=${r.httpStatus}; valid=${r.valid}; records=${r.records}; CORS=${r.browserOriginAllowed}; ${r.error || 'schema valid'}`).join(' | ')}`);
const outIndex = process.argv.indexOf('--out');
if (outIndex >= 0) {
  if (!process.argv[outIndex + 1]) throw new Error('--out needs a path');
  writeFileSync(process.argv[outIndex + 1], JSON.stringify(report, null, 2) + '\n');
}
if (process.env.GITHUB_STEP_SUMMARY) {
  const lines = ['# World Monitor source audit', '', `Checked: ${report.startedAt}. This job reports failures; green means the audit ran, not that all sources are available.`, '', '| Source | HTTP | Valid records | Browser origin allowed | Error |', '|---|---:|---:|---|---|',
    ...results.map((r) => `| ${r.name} | ${r.httpStatus ?? '—'} | ${r.records ?? '—'} | ${r.browserOriginAllowed === true ? 'Yes' : r.browserOriginAllowed === false ? 'No CORS permission advertised' : 'Not measured'} | ${(r.error || 'None').replaceAll('|', '/')} |`)];
  lines.push('', '## Representative context services', '', ...contextServices.map((r) => `- ${r.id}: HTTP ${r.httpStatus ?? 'unavailable'}, validated=${r.valid}, CORS=${r.browserOriginAllowed}, published year=${r.publishedYear || 'not applicable'}${r.error ? ` — ${r.error}` : ''}`));
  appendFileSync(process.env.GITHUB_STEP_SUMMARY, lines.join('\n') + '\n');
}
