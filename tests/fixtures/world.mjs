/** Deliberately synthetic provider responses for deterministic tests; never shipped as live data. */
export const NOW = Date.UTC(2026, 10, 8, 12);
export const iso = (offset = 0) => new Date(NOW + offset).toISOString();
export const geo = (items) => ({ type: 'FeatureCollection', features: items });
export const point = (lon = 121, lat = 15, depth = 10) => ({ type: 'Point', coordinates: [lon, lat, depth] });
export const quake = (overrides = {}) => ({ type: 'Feature', id: 'test-ph-quake', geometry: point(), properties: {
  title: 'M 6.1 — Luzon, Philippines', place: 'Luzon, Philippines', time: NOW - 3_600_000, updated: NOW - 1000, mag: 6.1,
  url: 'https://earthquake.usgs.gov/earthquakes/eventpage/test', ...overrides
} });
export const fixtures = {
  usgs: geo([quake(), { ...quake({ title: 'M 3.1 — California', place: 'California, United States', mag: 3.1 }), id: 'test-ca-quake', geometry: point(-120, 38) }]),
  eonet: { events: [{ id: 'eonet-test', title: 'Test wildfire in Australia', description: 'Synthetic test fixture.', categories: [{ id: 'wildfires', title: 'Wildfires' }], sources: [{ url: 'https://example.org/fire' }], geometry: [{ date: iso(-86400000), type: 'Point', coordinates: [130, -30] }, { date: iso(-10000), type: 'Point', coordinates: [131, -31] }] }] },
  gdacs: geo([{ id: 'gdacs-test', geometry: point(178, -17), properties: { eventid: 1, episodeid: 2, eventtype: 'TC', alertlevel: 'Red', name: 'Test cyclone', description: 'Synthetic tropical cyclone record.', country: 'Fiji', fromdate: iso(-20000), url: { report: 'https://www.gdacs.org/report.aspx' } } }]),
  nws: geo([{ id: 'https://api.weather.gov/alerts/test', geometry: null, properties: { id: 'https://api.weather.gov/alerts/test', headline: 'Test severe weather warning', sent: iso(-30000), severity: 'Severe', description: 'Synthetic test fixture.', areaDesc: 'Florida', instruction: 'Read official guidance.' } }]),
  kev: { vulnerabilities: [{ cveID: 'CVE-2026-12345', vulnerabilityName: 'Test software issue', shortDescription: 'Test only.', vendorProject: 'Example', product: 'Example package', dateAdded: '2026-11-08', dueDate: '2026-11-20', requiredAction: 'Apply the vendor update.' }] },
  advisories: [{ ghsa_id: 'GHSA-test-1234', cve_id: 'CVE-2026-54321', summary: 'Test dependency issue', description: 'Test only.', severity: 'critical', published_at: iso(-40000), updated_at: iso(-1000), html_url: 'https://github.com/advisories/GHSA-test-1234', vulnerabilities: [{ package: { name: 'example-package' } }] }],
  gdelt: { articles: [{ title: 'Test headline mentions Philippines', url: 'https://example.org/news', domain: 'example.org', sourcecountry: 'United Kingdom', language: 'English', seendate: '20261108T110000Z' }] },
  noaa: [{ product_id: 'TEST', issue_datetime: '2026-11-08 11:00:00', message: 'Alert: synthetic space weather test\nDo not treat this as live data.' }],
  geonet: geo([{ geometry: point(174, -40), properties: { publicID: 'test-nz', magnitude: 5.5, locality: 'New Zealand', mmi: 3, depth: 10, time: iso(-50000) } }]),
  emsc: geo([{ id: 'test-emsc', geometry: point(22, 38), properties: { mag: 4.5, flynn_region: 'Greece', magtype: 'ml', time: iso(-60000), depth: 12 } }]),
  'github-status': { incidents: [{ id: 'gh-incident', name: 'Test service outage', impact: 'major', status: 'investigating', created_at: iso(-60000), shortlink: 'https://www.githubstatus.com/incidents/test', incident_updates: [{ body: 'Test fixture only.' }] }] },
  'cloudflare-status': { incidents: [{ id: 'cf-incident', name: 'Test resolved service issue', impact: 'critical', status: 'resolved', created_at: iso(-60000), shortlink: 'https://www.cloudflarestatus.com/incidents/test' }] }
};
export const emptyFixtures = {
  usgs: geo([]), eonet: { events: [] }, gdacs: geo([]), nws: geo([]), kev: { vulnerabilities: [] }, advisories: [], gdelt: { articles: [] },
  noaa: [], geonet: geo([]), emsc: geo([]), 'github-status': { incidents: [] }, 'cloudflare-status': { incidents: [] }
};
export const forecast = { current: { time: '2026-11-08T12:00', temperature_2m: 29.5, relative_humidity_2m: 72, weather_code: 2, wind_speed_10m: 11 }, daily: {
  time: ['2026-11-08', '2026-11-09', '2026-11-10', '2026-11-11', '2026-11-12'], temperature_2m_max: [31, 30, 32, 31, 30], temperature_2m_min: [25, 24, 25, 24, 25], precipitation_probability_max: [30, 40, 20, 10, 50], weather_code: [2, 61, 2, 0, 61]
} };
export const air = { current: { time: '2026-11-08T12:00', us_aqi: 37, pm2_5: 8.1 } };
export function response(data, status = 200, headers = {}) { return new Response(typeof data === 'string' ? data : JSON.stringify(data), { status, headers: { 'content-type': 'application/json', ...headers } }); }
