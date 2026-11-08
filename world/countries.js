/** Country views are lenses on received evidence, not assertions of complete coverage. */
import { COUNTRIES } from './countries-data.js';
import { validCoordinates, cleanText } from './model.js';
import { fetchJson } from './network.js';
export { COUNTRIES };
export const COUNTRY_BY_CODE = new Map(COUNTRIES.map((c) => [c.code, c]));

const RING_CACHE = new WeakMap();
function preparedRing(ring) {
  if (RING_CACHE.has(ring)) return RING_CACHE.get(ring);
  if (!ring.every((p) => Array.isArray(p) && validCoordinates(p[1], p[0]))) { RING_CACHE.set(ring, null); return null; }
  const points = [];
  let previous = ring[0][0];
  let minX = Infinity; let maxX = -Infinity; let minY = Infinity; let maxY = -Infinity;
  for (const pair of ring) {
    let x = pair[0]; const y = pair[1];
    while (x - previous > 180) x -= 360;
    while (x - previous < -180) x += 360;
    points.push([x, y]); previous = x;
    minX = Math.min(minX, x); maxX = Math.max(maxX, x); minY = Math.min(minY, y); maxY = Math.max(maxY, y);
  }
  const prepared = { points, minX, maxX, minY, maxY };
  RING_CACHE.set(ring, prepared); return prepared;
}
/** Unwrap each ring across the antimeridian; cache geometry so filtering is bounded and fast. */
export function pointInRing(lat, lon, ring) {
  if (!validCoordinates(lat, lon) || !Array.isArray(ring) || ring.length < 4) return false;
  const prepared = preparedRing(ring);
  if (!prepared) return false;
  const { points, minX, maxX, minY, maxY } = prepared;
  const mid = (minX + maxX) / 2;
  let x = lon;
  while (x - mid > 180) x -= 360;
  while (x - mid < -180) x += 360;
  if (x < minX || x > maxX || lat < minY || lat > maxY) return false;
  let inside = false;
  for (let i = 0, j = points.length - 1; i < points.length; j = i++) {
    const [xi, yi] = points[i]; const [xj, yj] = points[j];
    if ((yi > lat) !== (yj > lat) && x < (xj - xi) * (lat - yi) / (yj - yi) + xi) inside = !inside;
  }
  return inside;
}
export function inCountry(event, polygons) {
  if (!validCoordinates(event.lat, event.lon) || !Array.isArray(polygons)) return false;
  return polygons.some((poly) => pointInRing(event.lat, event.lon, poly[0]) && !poly.slice(1).some((ring) => pointInRing(event.lat, event.lon, ring)));
}

export function countrySummary(country, events, boundaries) {
  const polygons = boundaries?.[country.code];
  const located = polygons ? events.filter((e) => inCountry(e, polygons)) : [];
  const phrase = country.name.toLocaleLowerCase();
  const mentions = events.filter((e) => e.lat === null && `${e.title} ${e.summary}`.toLocaleLowerCase().includes(phrase));
  return { country, located, mentions, hasBoundary: !!polygons, priority: located.filter((e) => ['high', 'critical'].includes(e.severity)).length };
}
export function searchCountries(query) {
  const q = cleanText(query, 80).toLocaleLowerCase();
  return COUNTRIES.filter((c) => `${c.name} ${c.official} ${c.code} ${c.region} ${c.subregion}`.toLocaleLowerCase().includes(q));
}

export class CountryService {
  constructor({ fetchImpl = globalThis.fetch?.bind(globalThis), storage, clock = () => Date.now() } = {}) {
    this.fetchImpl = fetchImpl; this.storage = storage; this.clock = clock; this.boundaries = null; this.loading = null; this.error = null; this.profiles = new Map();
  }
  async loadBoundaries() {
    if (this.boundaries) return this.boundaries;
    if (this.loading) return this.loading;
    this.loading = (async () => {
      try {
        const response = await this.fetchImpl(new URL('../assets/country-boundaries.json', import.meta.url).href, { credentials: 'omit' });
        if (!response.ok) throw new Error('Map boundaries could not be loaded.');
        const text = await response.text();
        if (text.length > 3_000_000) throw new Error('Map boundaries exceed the size limit.');
        const data = JSON.parse(text);
        if (!data?.countries || typeof data.countries !== 'object') throw new Error('Invalid boundary data.');
        this.boundaries = data.countries; this.error = null; return this.boundaries;
      } catch (error) { this.error = error.message; return null; }
      finally { this.loading = null; }
    })();
    return this.loading;
  }
  async profile(code) {
    const country = COUNTRY_BY_CODE.get(code);
    if (!country) throw new Error('Choose a listed country.');
    let old = this.profiles.get(code);
    if (!old && this.storage) {
      try { const raw = await this.storage.getItem(`world:profile:${code}`); if (raw && raw.length < 20_000) { const saved = JSON.parse(raw); if (saved?.code === code && Number.isFinite(saved.receivedAt)) old = { ...saved, cached: true }; } } catch { /* an unreadable cache does not prevent a live lookup */ }
    }
    if (old && !old.cached && this.clock() - old.receivedAt < 86_400_000) { this.profiles.set(code, old); return old; }
    const fields = [['population', 'SP.POP.TOTL'], ['gdpPerCapita', 'NY.GDP.PCAP.CD']];
    const results = await Promise.all(fields.map(async ([id, indicator]) => {
      try {
        const payload = await fetchJson(`https://api.worldbank.org/v2/country/${country.iso3}/indicator/${indicator}?format=json&per_page=10`, { fetchImpl: this.fetchImpl, maxBytes: 300_000, now: this.clock() });
        if (!Array.isArray(payload) || !Array.isArray(payload[1])) throw new Error('No indicator data returned for this country.');
        const value = payload[1].filter((v) => Number.isFinite(v?.value) && /^\d{4}$/.test(v?.date)).sort((a, b) => Number(b.date) - Number(a.date))[0];
        if (!value) throw new Error('No published value in the latest 10 observations.');
        return [id, { value: value.value, year: value.date, receivedAt: this.clock(), cached: false, error: null }];
      } catch (e) { return [id, { value: old?.[id]?.value ?? null, year: old?.[id]?.year || null, receivedAt: old?.[id]?.receivedAt || null, cached: true, error: cleanText(e.message) }]; }
    }));
    const data = { code, receivedAt: this.clock(), ...Object.fromEntries(results) };
    data.cached = results.some(([, result]) => result.cached);
    this.profiles.set(code, data);
    try { await this.storage?.setItem(`world:profile:${code}`, JSON.stringify(data)); } catch { data.storageError = 'Country indicators could not be saved.'; }
    return data;
  }
}
