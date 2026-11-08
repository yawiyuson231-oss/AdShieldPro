/** Pure, bounded data operations shared by the web and packaged Android monitor. */
import { CATEGORIES, SEVERITIES, REGIONS, SOURCE_BY_ID, LIMITS } from './catalog.js';

export const cleanText = (value, max = 500) => typeof value === 'string'
  ? value.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\u202a-\u202e\u2066-\u2069]/g, '').trim().slice(0, max) : '';

export function safeUrl(value) {
  try {
    const url = new URL(value);
    if (url.protocol !== 'https:' || url.username || url.password) return null;
    if ((url.hostname === 'localhost' || url.hostname.endsWith('.localhost')) || !url.hostname.includes('.') || /[\[\]:]/.test(url.hostname)) return null;
    if (/^(127\.|10\.|192\.168\.|169\.254\.|0\.|172\.(1[6-9]|2\d|3[01])\.)/.test(url.hostname)) return null;
    return url.href.length <= 2048 ? url.href : null;
  } catch { return null; }
}

export function timestamp(value) {
  if (typeof value === 'number') return Number.isFinite(value) && value > 0 ? value : null;
  if (typeof value !== 'string' || !value.trim()) return null;
  let iso = value;
  if (/^\d{8}T\d{6}Z$/.test(value)) iso = value.replace(/^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$/, '$1-$2-$3T$4:$5:$6Z');
  const dotnet = value.match(/^\/Date\((\d+)\)\/$/);
  if (dotnet) return Number(dotnet[1]);
  const parsed = Date.parse(iso);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : null;
}

export function validCoordinates(lat, lon) {
  return typeof lat === 'number' && typeof lon === 'number' && Number.isFinite(lat) && Number.isFinite(lon)
    && lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180;
}

export function normalizeEvent(raw, sourceId, now = Date.now()) {
  if (!raw || !SOURCE_BY_ID.has(sourceId)) return null;
  const title = cleanText(raw.title, 200);
  const at = timestamp(raw.occurredAt);
  const id = cleanText(raw.id, 500);
  if (!title || !at || at > now + 86_400_000 || !id) return null;
  if (!CATEGORIES.some((c) => c.id === raw.category)) return null;
  const geo = validCoordinates(raw.lat, raw.lon);
  return {
    id: id.startsWith(`${sourceId}:`) ? id : `${sourceId}:${id}`,
    source: sourceId, title, summary: cleanText(raw.summary, 1600),
    category: raw.category, severity: SEVERITIES.includes(raw.severity) ? raw.severity : 'info',
    severityBasis: cleanText(raw.severityBasis, 240) || 'No severity published; informational only.',
    occurredAt: at, updatedAt: timestamp(raw.updatedAt) || at,
    url: safeUrl(raw.url), lat: geo ? raw.lat : null, lon: geo ? raw.lon : null,
    location: cleanText(raw.location, 160) || (geo ? 'Provider coordinates' : 'No event coordinates published'),
    geoBasis: geo ? (cleanText(raw.geoBasis, 180) || 'Provider-reported coordinates') : 'Not geolocated',
    tags: Array.isArray(raw.tags) ? [...new Set(raw.tags.map((t) => cleanText(t, 70)).filter(Boolean))].slice(0, 12) : []
  };
}

export function inRegion(event, regionId) {
  if (!regionId || regionId === 'world') return true;
  const region = REGIONS.find((r) => r.id === regionId);
  if (!region || !validCoordinates(event.lat, event.lon)) return false;
  const [west, south, east, north] = region.bounds;
  return event.lon >= west && event.lon <= east && event.lat >= south && event.lat <= north;
}

export function matchesQuery(event, query) {
  const words = cleanText(query, 160).toLocaleLowerCase().split(/\s+/).filter(Boolean);
  const haystack = `${event.title} ${event.summary} ${event.location} ${event.tags.join(' ')} ${event.source}`.toLocaleLowerCase();
  return words.every((word) => haystack.includes(word));
}

export function filterEvents(events, filters = {}, now = Date.now()) {
  const windowMs = { '24h': 86_400_000, '7d': 7 * 86_400_000, '30d': 30 * 86_400_000 }[filters.range];
  const levels = new Set(filters.categories || CATEGORIES.map((c) => c.id));
  const minimum = Math.max(0, SEVERITIES.indexOf(filters.severity || 'info'));
  return events.filter((e) => levels.has(e.category)
    && (!filters.source || filters.source === 'all' || e.source === filters.source)
    && SEVERITIES.indexOf(e.severity) >= minimum
    && (!windowMs || e.occurredAt >= now - windowMs)
    && inRegion(e, filters.region) && matchesQuery(e, filters.query))
    .sort((a, b) => filters.sort === 'severity'
      ? SEVERITIES.indexOf(b.severity) - SEVERITIES.indexOf(a.severity) || b.occurredAt - a.occurredAt || a.id.localeCompare(b.id)
      : b.occurredAt - a.occurredAt || a.id.localeCompare(b.id));
}

export function normalizeWatch(raw, id) {
  const label = cleanText(raw?.label, 60);
  const query = cleanText(raw?.query, 160);
  const region = REGIONS.some((r) => r.id === raw?.region) ? raw.region : 'world';
  const category = CATEGORIES.some((c) => c.id === raw?.category) ? raw.category : 'all';
  const severity = SEVERITIES.includes(raw?.severity) ? raw.severity : 'high';
  if (!label) throw new Error('Give your watch a name.');
  return { id: cleanText(id || raw.id, 80), label, query, region, category, severity, enabled: raw.enabled !== false };
}

export function matchesWatch(event, watch) {
  return watch.enabled && (watch.category === 'all' || event.category === watch.category)
    && SEVERITIES.indexOf(event.severity) >= SEVERITIES.indexOf(watch.severity)
    && inRegion(event, watch.region) && matchesQuery(event, watch.query);
}

export function histogram(events, now = Date.now(), hours = 24, buckets = 24) {
  const width = hours * 3_600_000 / buckets;
  const start = Math.floor(now / width) * width - (buckets - 1) * width;
  const result = Array.from({ length: buckets }, (_, i) => ({ at: start + i * width, count: 0, high: 0 }));
  for (const e of events) {
    const i = Math.floor((e.occurredAt - start) / width);
    if (i < 0 || i >= buckets) continue;
    result[i].count++;
    if (SEVERITIES.indexOf(e.severity) >= 2) result[i].high++;
  }
  return result;
}

export function clusterEvents(events, zoom = 1) {
  const cell = 30 / Math.max(1, zoom);
  const clusters = new Map();
  for (const e of events) {
    if (!validCoordinates(e.lat, e.lon)) continue;
    const key = `${Math.floor((e.lon + 180) / cell)}:${Math.floor((e.lat + 90) / cell)}`;
    const group = clusters.get(key) || { id: key, events: [], lat: 0, lon: 0, severity: 'info' };
    group.events.push(e); group.lat += e.lat; group.lon += e.lon;
    if (SEVERITIES.indexOf(e.severity) > SEVERITIES.indexOf(group.severity)) group.severity = e.severity;
    clusters.set(key, group);
  }
  return [...clusters.values()].map((g) => ({ ...g, lat: g.lat / g.events.length, lon: g.lon / g.events.length }));
}

/** Leading formula/control characters are escaped even when spreadsheet software trims whitespace. */
export function csvCell(value) {
  let text = String(value ?? '').replace(/\r/g, '');
  if (/^[\s\u0000-\u001f]*[=+@-]/.test(text) || /^[\t\n]/.test(text)) text = `'${text}`;
  return `"${text.replace(/"/g, '""')}"`;
}

export function exportCsv(events, health = {}) {
  const fields = ['id', 'source', 'category', 'severity', 'occurredAt', 'title', 'summary', 'location', 'lat', 'lon', 'url', 'severityBasis', 'dataStatus'];
  return [fields.join(','), ...events.map((e) => fields.map((key) => csvCell(key === 'occurredAt'
    ? new Date(e.occurredAt).toISOString() : key === 'dataStatus' ? health[e.source]?.status || 'cached' : e[key])).join(','))].join('\r\n');
}

export function buildBriefing(events, health, filters, now = Date.now()) {
  const high = events.filter((e) => SEVERITIES.indexOf(e.severity) >= 2);
  const counts = CATEGORIES.map((c) => `${c.label}: ${events.filter((e) => e.category === c.id).length}`).join(' · ');
  const lines = [
    '# OmniShield X · World Monitor briefing', `Generated: ${new Date(now).toISOString()}`, '',
    `Scope: ${filters.region || 'world'} · ${filters.range || 'all'} · query: ${cleanText(filters.query) || '(none)'}`,
    `${events.length} matching records; ${high.length} high/critical; ${events.filter((e) => e.lat !== null).length} geolocated.`, counts, '',
    '## Source health', ...Object.entries(health).map(([id, h]) => `- ${SOURCE_BY_ID.get(id)?.name || id}: ${h.status}; last success: ${h.lastSuccess ? new Date(h.lastSuccess).toISOString() : 'never'}${h.error ? `; ${cleanText(h.error)}` : ''}`), '',
    '## Priority records (maximum 30)',
    ...[...events].sort((a, b) => SEVERITIES.indexOf(b.severity) - SEVERITIES.indexOf(a.severity) || b.occurredAt - a.occurredAt)
      .slice(0, 30).map((e) => `- ${e.severity.toUpperCase()} | ${e.title.replace(/\s+/g, ' ')} | ${SOURCE_BY_ID.get(e.source)?.name}\n  ${new Date(e.occurredAt).toISOString()} · ${e.location}\n  ${e.url || 'No source link supplied'}`), '',
    '## Limits', 'This is a deterministic summary of the filtered, received records, not a prediction or a comprehensive world-risk score. Source coverage, publication delays and outages apply. Severity bands differ by source. No news publisher location is treated as an incident location. Consult official local authorities for emergencies.'
  ];
  return lines.join('\n');
}

export function parseWatchImport(text) {
  if (typeof text !== 'string' || text.length > 128_000) throw new Error('Watchlist file must be smaller than 128 KB.');
  let data;
  try { data = JSON.parse(text); } catch { throw new Error('This is not a valid JSON watchlist.'); }
  if (data?.schema !== 'omnishield-world-watches' || data.version !== 1 || !Array.isArray(data.watches)) throw new Error('Unsupported watchlist format. Export a World Monitor watchlist first.');
  if (data.watches.length > LIMITS.watches) throw new Error(`At most ${LIMITS.watches} watches are supported.`);
  return data.watches.map((raw, i) => normalizeWatch(raw, `import-${i}`));
}
