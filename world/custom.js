/** User-added keyless feeds. Only explicit HTTPS requests; custom feeds are never endorsed. */
import { safeUrl, cleanText } from './model.js';
import { sha256Hex } from '../security/sha256.js';

export const CUSTOM_FORMATS = Object.freeze([
  ['generic', 'GeoJSON events (documented format)'], ['usgs', 'USGS-compatible earthquakes'],
  ['eonet', 'NASA EONET-compatible events'], ['nws', 'NWS-compatible alerts'],
  ['gdacs', 'GDACS-compatible events'], ['kev', 'CISA KEV-compatible catalogue'],
  ['advisories', 'GitHub-compatible advisory array'], ['gdelt', 'GDELT-compatible headlines']
]);
export const MAX_CUSTOM_SOURCES = 88;
export function normalizeCustomSource(raw) {
  const name = cleanText(raw?.name, 70);
  const url = safeUrl(raw?.url);
  if (!name) throw new Error('Give this feed a name.');
  if (!url) throw new Error('Use a public HTTPS feed URL without a username or password.');
  const parsed = new URL(url);
  if (/(?:^|\.)local$|(?:^|\.)internal$|(?:^|\.)test$|(?:^|\.)invalid$/.test(parsed.hostname)) throw new Error('Local and internal hosts are not accepted.');
  if ([...parsed.searchParams.keys()].some((k) => /key|token|secret|password|auth/i.test(k))) throw new Error('Use a keyless public endpoint. Credentials must not be stored in a feed URL.');
  if (!CUSTOM_FORMATS.some(([id]) => id === raw.parser)) throw new Error('Choose a supported feed format.');
  const hours = Number(raw.intervalHours);
  if (!Number.isFinite(hours) || hours < 1 || hours > 168) throw new Error('Choose a refresh interval from 1 to 168 hours.');
  return {
    id: `custom-${sha256Hex(url).slice(0, 16)}`, name, short: name.slice(0, 16), url,
    parser: raw.parser, category: 'disaster', enabled: true, custom: true,
    homepage: parsed.origin, ttlMs: hours * 3_600_000,
    coverage: 'User-added feed · coverage depends on its publisher',
    terms: 'Not a bundled or verified provider. Use only feeds you have permission to access. Browser CORS and provider limits apply.',
    intervalHours: hours
  };
}
