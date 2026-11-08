/** Explicit, city/coordinate-based weather lookup. No location permission or background tracking. */
import { fetchJson } from './network.js';
import { cleanText, timestamp, validCoordinates } from './model.js';

const finite = (n) => typeof n === 'number' && Number.isFinite(n) ? n : null;
const utcTime = (text) => timestamp(typeof text === 'string' && !/(Z|[+-]\d\d:\d\d)$/.test(text) ? `${text}Z` : text);
export const weatherLabel = (code) => {
  if (code === 0) return 'Clear sky';
  if ([1, 2, 3].includes(code)) return 'Partly cloudy / overcast';
  if ([45, 48].includes(code)) return 'Fog';
  if ([51, 53, 55, 56, 57].includes(code)) return 'Drizzle';
  if ([61, 63, 65, 66, 67, 80, 81, 82].includes(code)) return 'Rain';
  if ([71, 73, 75, 77, 85, 86].includes(code)) return 'Snow';
  if ([95, 96, 99].includes(code)) return 'Thunderstorm';
  return 'Conditions not supplied';
};
export function normalizePlace(raw) {
  if (!validCoordinates(raw?.lat, raw?.lon)) throw new Error('Latitude must be −90 to 90 and longitude −180 to 180.');
  return { name: cleanText(raw.name, 60) || `${raw.lat.toFixed(2)}, ${raw.lon.toFixed(2)}`, lat: Math.round(raw.lat * 100) / 100, lon: Math.round(raw.lon * 100) / 100 };
}
export function parseForecast(data) {
  const c = data?.current; const d = data?.daily;
  if (!c || finite(c.temperature_2m) === null || !utcTime(c.time) || !Array.isArray(d?.time)) throw new Error('Weather provider returned an incomplete forecast.');
  return { at: utcTime(c.time), temperature: finite(c.temperature_2m), humidity: finite(c.relative_humidity_2m), wind: finite(c.wind_speed_10m), code: finite(c.weather_code),
    days: d.time.slice(0, 5).map((date, i) => ({ date: cleanText(date, 10), high: finite(d.temperature_2m_max?.[i]), low: finite(d.temperature_2m_min?.[i]), rain: finite(d.precipitation_probability_max?.[i]), code: finite(d.weather_code?.[i]) })) };
}
export function parseAir(data) {
  const c = data?.current;
  if (!c || finite(c.us_aqi) === null || !utcTime(c.time)) throw new Error('Air-quality provider did not supply a current AQI.');
  return { at: utcTime(c.time), aqi: finite(c.us_aqi), pm25: finite(c.pm2_5) };
}
export function airLabel(aqi) {
  if (aqi === null || !Number.isFinite(aqi)) return 'Not available';
  return aqi <= 50 ? 'Good' : aqi <= 100 ? 'Moderate' : aqi <= 150 ? 'Unhealthy for sensitive groups' : aqi <= 200 ? 'Unhealthy' : aqi <= 300 ? 'Very unhealthy' : 'Hazardous';
}

export class WeatherService {
  constructor({ storage, fetchImpl = globalThis.fetch?.bind(globalThis), clock = () => Date.now(), timeoutMs } = {}) {
    this.storage = storage; this.fetchImpl = fetchImpl; this.clock = clock; this.timeoutMs = timeoutMs;
    this.cache = new Map(); this.pending = null; this.storageError = null;
  }
  key(place) { return `${place.lat.toFixed(2)},${place.lon.toFixed(2)}`; }
  async load() {
    try {
      const text = await this.storage?.getItem('world:weather:v1');
      if (!text || text.length > 100_000) return;
      const raw = JSON.parse(text);
      if (!Array.isArray(raw)) return;
      for (const row of raw.slice(-6)) {
        try {
          const place = normalizePlace(row.place);
          if (!Number.isFinite(row.fetchedAt) || row.fetchedAt > this.clock()) continue;
          // Re-validate cached normalized fields, never trust arbitrary HTML or values.
          const forecast = row.forecast && Number.isFinite(row.forecast.at) && finite(row.forecast.temperature) !== null && Array.isArray(row.forecast.days)
            ? { at: row.forecast.at, temperature: finite(row.forecast.temperature), humidity: finite(row.forecast.humidity), wind: finite(row.forecast.wind), code: finite(row.forecast.code),
              days: row.forecast.days.slice(0, 5).map((d) => ({ date: cleanText(d.date, 10), high: finite(d.high), low: finite(d.low), rain: finite(d.rain), code: finite(d.code) })) } : null;
          const air = row.air && finite(row.air.aqi) !== null && Number.isFinite(row.air.at) ? { at: row.air.at, aqi: finite(row.air.aqi), pm25: finite(row.air.pm25) } : null;
          this.cache.set(this.key(place), { place, forecast, air, fetchedAt: row.fetchedAt, forecastAt: row.forecastAt || row.fetchedAt, airAt: row.airAt || row.fetchedAt, cached: true, errors: [] });
        } catch { /* ignore an invalid place, not the other cached places */ }
      }
    } catch { this.storageError = 'Weather cache could not be read.'; }
  }
  get(place) { return this.cache.get(this.key(normalizePlace(place))) || null; }
  async lookup(raw) {
    const place = normalizePlace(raw);
    const key = this.key(place);
    if (this.pending) { if (this.pendingKey === key) return this.pending; throw new Error('Wait for the current place lookup to finish.'); }
    this.pendingKey = key; const old = this.cache.get(key);
    if (old && !old.cached && this.clock() - old.fetchedAt < 15 * 60_000 && !old.errors.length) return old;
    this.pending = (async () => {
      const params = `latitude=${place.lat}&longitude=${place.lon}&timezone=UTC`;
      const options = { fetchImpl: this.fetchImpl, maxBytes: 200_000, timeoutMs: this.timeoutMs, now: this.clock() };
      const [forecast, air] = await Promise.allSettled([
        fetchJson(`https://api.open-meteo.com/v1/forecast?${params}&current=temperature_2m,relative_humidity_2m,weather_code,wind_speed_10m&daily=weather_code,temperature_2m_max,temperature_2m_min,precipitation_probability_max&forecast_days=5`, options).then(parseForecast),
        fetchJson(`https://air-quality-api.open-meteo.com/v1/air-quality?${params}&current=us_aqi,pm2_5&forecast_days=1`, options).then(parseAir)
      ]);
      const result = { place, fetchedAt: this.clock(), cached: false,
        forecast: forecast.status === 'fulfilled' ? forecast.value : old?.forecast || null,
        air: air.status === 'fulfilled' ? air.value : old?.air || null,
        forecastCached: forecast.status !== 'fulfilled' && !!old?.forecast, airCached: air.status !== 'fulfilled' && !!old?.air,
        forecastAt: forecast.status === 'fulfilled' ? this.clock() : old?.forecastAt || null,
        airAt: air.status === 'fulfilled' ? this.clock() : old?.airAt || null,
        errors: [forecast.status === 'rejected' ? `Forecast: ${forecast.reason.message}` : null, air.status === 'rejected' ? `Air quality: ${air.reason.message}` : null].filter(Boolean) };
      this.cache.set(key, result);
      while (this.cache.size > 6) this.cache.delete(this.cache.keys().next().value);
      try { await this.storage?.setItem('world:weather:v1', JSON.stringify([...this.cache.values()])); }
      catch { this.storageError = 'Weather was received but could not be saved for offline use.'; }
      return result;
    })().finally(() => { this.pending = null; });
    return this.pending;
  }
}
