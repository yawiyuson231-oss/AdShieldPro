/** Provider adapters: reject wrong schemas; accept an honestly empty feed; never invent coordinates. */
import { LIMITS, CATEGORIES, SOURCE_BY_ID } from './catalog.js';
import { normalizeEvent, timestamp, validCoordinates } from './model.js';
import { sha256Hex } from '../security/sha256.js';

function list(value, description) {
  if (!Array.isArray(value)) throw new Error(`Invalid ${description}: expected an array.`);
  return value;
}

function features(data) {
  if (data?.type !== 'FeatureCollection') throw new Error('Invalid GeoJSON: expected a FeatureCollection.');
  return list(data.features, 'GeoJSON features');
}

function location(geometry) {
  if (geometry?.type === 'Point') {
    const [lon, lat] = Array.isArray(geometry.coordinates) ? geometry.coordinates : [];
    return validCoordinates(lat, lon) ? { lat, lon, geoBasis: 'Provider-reported point' } : {};
  }
  // An area is plotted at an approximate ring centre, explicitly labelled as such.
  const ring = geometry?.type === 'Polygon' ? geometry.coordinates?.[0]
    : geometry?.type === 'MultiPolygon' ? geometry.coordinates?.[0]?.[0] : null;
  if (!Array.isArray(ring) || !ring.length) return {};
  const points = ring.filter((p) => Array.isArray(p) && validCoordinates(p[1], p[0]));
  if (!points.length) return {};
  const radians = points.map((p) => p[0] * Math.PI / 180);
  const lon = Math.atan2(radians.reduce((n, r) => n + Math.sin(r), 0), radians.reduce((n, r) => n + Math.cos(r), 0)) * 180 / Math.PI;
  return { lat: points.reduce((n, p) => n + p[1], 0) / points.length, lon, geoBasis: 'Approximate centre of a provider polygon; not an exact incident point' };
}

function statusRows(data) {
  return list(data?.incidents, 'status incidents').map((i) => ({
    id: i?.id, title: i?.name, summary: `${i?.status || 'unknown status'}. ${i?.incident_updates?.[0]?.body || ''}`,
    category: 'infrastructure', severity: i?.status === 'resolved' ? 'info' : i?.impact === 'critical' ? 'critical' : i?.impact === 'major' ? 'high' : i?.impact === 'minor' ? 'moderate' : 'info',
    severityBasis: `Provider impact: ${i?.impact || 'unknown'}; status: ${i?.status || 'unknown'}. Resolved incidents are informational.`,
    occurredAt: i?.created_at, updatedAt: i?.updated_at, url: i?.shortlink, tags: [i?.status, i?.impact].filter(Boolean), location: 'Provider service · not geolocated'
  }));
}
const rows = {
  generic(data) {
    return features(data).map((f) => {
      const p = f?.properties || {};
      return { id: String(f?.id || p.id || ''), title: p.title || p.name, summary: p.summary || p.description,
        category: CATEGORIES.some((c) => c.id === p.category) ? p.category : 'disaster', severity: p.severity,
        severityBasis: 'Custom feed publisher rating, not independently verified.', occurredAt: p.occurredAt || p.time || p.date,
        updatedAt: p.updatedAt, url: p.url, location: p.location, tags: Array.isArray(p.tags) ? p.tags : [], ...location(f?.geometry) };
    });
  },
  noaa(data) {
    return list(data, 'NOAA bulletins').map((r) => ({ id: `${r?.product_id || ''}:${r?.issue_datetime || ''}`, title: `${r?.product_id || 'Space weather'} · ${String(r?.message || '').split('\n').find((t) => /^(Alert|Watch|Warning|Summary)/i.test(t)) || 'NOAA space-weather bulletin'}`,
      summary: r?.message, category: 'space', severity: 'info', severityBasis: 'Informational bulletin; no cross-hazard severity is inferred. Read the original bulletin scale.',
      occurredAt: typeof r?.issue_datetime === 'string' ? r.issue_datetime.replace(' ', 'T') + (/Z$/.test(r.issue_datetime) ? '' : 'Z') : null,
      url: 'https://www.swpc.noaa.gov/products/alerts-watches-and-warnings', tags: [r?.product_id].filter(Boolean), location: 'Space weather · no ground point inferred' }));
  },
  geonet(data) {
    return features(data).map((f) => {
      const p = f?.properties || {}; const m = typeof p.magnitude === 'number' ? p.magnitude : null;
      return { id: p.publicID, title: `M ${m ?? '?'} · ${p.locality || 'New Zealand earthquake'}`, summary: `Depth: ${p.depth ?? 'unknown'} km. Provider intensity: ${p.mmi ?? 'unknown'}.`, category: 'seismic',
        severity: m >= 7 ? 'critical' : m >= 6 ? 'high' : m >= 4.5 ? 'moderate' : 'info', severityBasis: 'Local magnitude bands (7+, 6+, 4.5+); not a damage forecast.',
        occurredAt: p.time, updatedAt: p.modificationTime, url: p.publicID ? `https://www.geonet.org.nz/earthquake/${encodeURIComponent(p.publicID)}` : null, location: p.locality, tags: ['New Zealand'], ...location(f?.geometry) };
    });
  },
  emsc(data) {
    return features(data).map((f) => {
      const p = f?.properties || {}; const m = typeof p.mag === 'number' ? p.mag : null;
      return { id: String(f?.id || p.unid || ''), title: `M ${m ?? '?'} · ${p.flynn_region || 'Earthquake'}`, summary: `Depth: ${p.depth ?? 'unknown'} km. Magnitude type: ${p.magtype || 'unknown'}.`, category: 'seismic',
        severity: m >= 7 ? 'critical' : m >= 6 ? 'high' : m >= 4.5 ? 'moderate' : 'info', severityBasis: 'Local magnitude bands (7+, 6+, 4.5+); not a damage forecast.',
        occurredAt: p.time, updatedAt: p.lastupdate, url: 'https://www.seismicportal.eu/', location: p.flynn_region, tags: [p.auth].filter(Boolean), ...location(f?.geometry) };
    });
  },
  'github-status': statusRows,
  'cloudflare-status': statusRows,
  usgs(data) {
    return features(data).map((f) => {
      const p = f?.properties || {};
      const mag = typeof p.mag === 'number' ? p.mag : null;
      return {
        id: f?.id, title: p.title || p.place, category: 'seismic',
        summary: `Magnitude ${mag ?? 'not published'} · depth ${f?.geometry?.coordinates?.[2] ?? 'unknown'} km. ${p.tsunami === 1 ? 'Tsunami flag present; consult official warnings.' : 'Consult USGS for impact information.'}`,
        severity: mag >= 7 ? 'critical' : mag >= 6 ? 'high' : mag >= 4.5 ? 'moderate' : 'info',
        severityBasis: 'Local magnitude bands: 7+ critical, 6+ high, 4.5+ moderate; not an impact or tsunami forecast.',
        occurredAt: p.time, updatedAt: p.updated, url: p.url, location: p.place,
        tags: [mag === null ? 'magnitude unknown' : `M${mag}`, p.status].filter(Boolean), ...location(f?.geometry)
      };
    });
  },
  eonet(data) {
    return list(data?.events, 'EONET events').map((e) => {
      const geometries = Array.isArray(e?.geometry) ? [...e.geometry] : [];
      geometries.sort((a, b) => (timestamp(b?.date) || 0) - (timestamp(a?.date) || 0));
      const latest = geometries[0];
      const kinds = Array.isArray(e?.categories) ? e.categories.map((c) => c?.id) : [];
      const category = kinds.includes('wildfires') ? 'wildfire' : kinds.some((k) => ['severeStorms', 'snow', 'floods'].includes(k)) ? 'weather' : 'disaster';
      return {
        id: e?.id, title: e?.title, summary: e?.description || 'Open natural event reported through NASA EONET. Follow the original source for operational guidance.',
        category, severity: 'info', severityBasis: 'EONET does not supply a comparable impact rating. Informational is not a safety verdict.',
        occurredAt: latest?.date, url: e?.sources?.[0]?.url || e?.link,
        tags: Array.isArray(e?.categories) ? e.categories.map((c) => c?.title).filter(Boolean) : [], ...location(latest)
      };
    });
  },
  gdacs(data) {
    return features(data).map((f) => {
      const p = f?.properties || {};
      const level = String(p.alertlevel || '').toLowerCase();
      const kind = String(p.eventtype || '').toUpperCase();
      return {
        id: `${kind}:${p.eventid ?? f?.id ?? ''}:${p.episodeid ?? ''}`, title: p.name || p.eventname || p.description,
        summary: p.description, category: kind === 'EQ' ? 'seismic' : kind === 'WF' ? 'wildfire' : ['TC', 'FL'].includes(kind) ? 'weather' : 'disaster',
        severity: level === 'red' ? 'critical' : level === 'orange' ? 'high' : 'info',
        severityBasis: `GDACS provider alert: ${level || 'not published'}. Green maps to informational, orange to high, red to critical.`,
        occurredAt: p.fromdate || p.datemodified, updatedAt: p.datemodified,
        url: typeof p.url === 'string' ? p.url : p.url?.report,
        location: p.country, tags: [kind, p.country].filter(Boolean), ...location(f?.geometry)
      };
    });
  },
  nws(data) {
    return features(data).map((f) => {
      const p = f?.properties || {};
      const levels = { Extreme: 'critical', Severe: 'high', Moderate: 'moderate', Minor: 'info', Unknown: 'info' };
      return {
        id: p.id || f?.id, title: p.headline || p.event, summary: [p.description, p.instruction].filter(Boolean).join('\n'),
        category: 'weather', severity: levels[p.severity] || 'info', severityBasis: `NWS provider severity: ${p.severity || 'unknown'}.`,
        occurredAt: p.sent || p.effective, updatedAt: p.sent,
        url: p['@id'] || p.id || f?.id, location: p.areaDesc,
        tags: [p.event, p.certainty, p.urgency, 'United States'].filter(Boolean), ...location(f?.geometry)
      };
    });
  },
  kev(data) {
    return list(data?.vulnerabilities, 'CISA vulnerabilities').map((v) => ({
      id: v?.cveID, title: `${v?.cveID || ''} · ${v?.vulnerabilityName || v?.product || ''}`,
      summary: `${v?.shortDescription || ''}\nRequired action: ${v?.requiredAction || 'Consult the advisory.'}${v?.dueDate ? ` Due date (US federal directive): ${v.dueDate}.` : ''}`,
      category: 'cyber', severity: 'high', severityBasis: 'Local triage: high because CISA lists known exploitation. This is not a CVSS score or evidence of compromise on this device.',
      occurredAt: v?.dateAdded, url: v?.cveID ? `https://www.cve.org/CVERecord?id=${encodeURIComponent(v.cveID)}` : null,
      tags: [v?.vendorProject, v?.product, v?.cveID, v?.knownRansomwareCampaignUse === 'Known' ? 'ransomware use reported' : null].filter(Boolean),
      location: 'Global advisory · not geolocated'
    }));
  },
  advisories(data) {
    return list(data, 'GitHub advisories').map((v) => ({
      id: v?.ghsa_id, title: `${v?.cve_id || v?.ghsa_id || ''} · ${v?.summary || ''}`, summary: v?.description,
      category: 'cyber', severity: ['critical', 'high'].includes(v?.severity) ? v.severity : v?.severity === 'medium' ? 'moderate' : 'info',
      severityBasis: `GitHub advisory severity: ${v?.severity || 'not published'}. Applicability depends on the package and version installed.`,
      occurredAt: v?.published_at, updatedAt: v?.updated_at, url: v?.html_url,
      tags: [v?.cve_id, ...(Array.isArray(v?.vulnerabilities) ? v.vulnerabilities.map((p) => p?.package?.name) : [])].filter(Boolean),
      location: 'Global advisory · not geolocated'
    }));
  },
  gdelt(data) {
    return list(data?.articles, 'GDELT articles').map((a) => ({
      id: sha256Hex(String(a?.url || '')).slice(0, 32), title: a?.title,
      summary: `Media report indexed by GDELT. Publisher: ${a?.domain || 'not supplied'}. The publisher's country is not the event location.`,
      category: 'news', severity: 'info', severityBasis: 'Unverified media headline; no incident severity inferred.',
      occurredAt: a?.seendate, url: a?.url, tags: [a?.language, a?.domain].filter(Boolean),
      location: 'Media report · not geolocated'
    }));
  }
};

export function parseSource(sourceId, data, now = Date.now()) {
  const parserId = SOURCE_BY_ID.get(sourceId)?.parser || sourceId;
  if (!rows[parserId]) throw new Error(`No parser for ${sourceId}.`);
  const raw = rows[parserId](data);
  const valid = raw.map((r) => normalizeEvent(r, sourceId, now)).filter(Boolean);
  // A genuinely empty list is fine; an entirely unparseable nonempty list is not.
  if (raw.length && !valid.length) throw new Error('Response contained records, but none had a valid title, date and identifier.');
  const unique = new Map();
  for (const event of valid) {
    const previous = unique.get(event.id);
    if (!previous || event.updatedAt >= previous.updatedAt) unique.set(event.id, event);
  }
  const events = [...unique.values()].sort((a, b) => b.occurredAt - a.occurredAt).slice(0, LIMITS.eventsPerSource);
  return { events, received: raw.length, rejected: raw.length - valid.length, truncated: unique.size > LIMITS.eventsPerSource };
}
