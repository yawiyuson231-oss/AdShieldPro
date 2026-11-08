/** Public, keyless sources. Selecting a source is not evidence that it is reachable. */
export const WORLD_VERSION = '2.0';
export const CATEGORIES = Object.freeze([
  { id: 'seismic', label: 'Earthquakes', color: '#f5b85a', icon: 'activity' },
  { id: 'wildfire', label: 'Wildfires', color: '#f58066', icon: 'flame' },
  { id: 'weather', label: 'Weather', color: '#71b7f8', icon: 'cloud' },
  { id: 'disaster', label: 'Other hazards', color: '#c1a0ff', icon: 'globe' },
  { id: 'cyber', label: 'Cyber intelligence', color: '#72d5ba', icon: 'shield' },
  { id: 'space', label: 'Space weather', color: '#e7c77d', icon: 'sun' },
  { id: 'infrastructure', label: 'Service outages', color: '#8cb5bf', icon: 'network' },
  { id: 'news', label: 'World news', color: '#d4d8e1', icon: 'news' }
]);
export const SEVERITIES = Object.freeze(['info', 'moderate', 'high', 'critical']);
export const REGIONS = Object.freeze([
  { id: 'world', label: 'Worldwide', bounds: [-180, -90, 180, 90] },
  { id: 'philippines', label: 'Philippines', bounds: [116, 4, 127, 22] },
  { id: 'asia', label: 'Asia & Pacific', bounds: [60, -55, 180, 80] },
  { id: 'europe', label: 'Europe', bounds: [-25, 35, 60, 72] },
  { id: 'africa', label: 'Africa', bounds: [-25, -36, 60, 37] },
  { id: 'north-america', label: 'North America', bounds: [-170, 7, -50, 84] },
  { id: 'south-america', label: 'South America', bounds: [-85, -57, -32, 14] }
]);
const minute = 60_000;
export const SOURCES = Object.freeze([
  {
    id: 'usgs', name: 'USGS Earthquakes', short: 'USGS', category: 'seismic', enabled: true,
    url: 'https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/2.5_day.geojson',
    homepage: 'https://earthquake.usgs.gov/', ttlMs: 5 * minute,
    coverage: 'Worldwide · magnitude 2.5+ · past 24 hours',
    terms: 'USGS public data. Magnitude bands are local triage rules, not predicted impact.'
  },
  {
    id: 'eonet', name: 'NASA EONET', short: 'NASA', category: 'disaster', enabled: true,
    url: 'https://eonet.gsfc.nasa.gov/api/v3/events?status=open&limit=200',
    homepage: 'https://eonet.gsfc.nasa.gov/', ttlMs: 30 * minute,
    coverage: 'Worldwide · open natural events · up to 200 records',
    terms: 'NASA EONET open data. Locations can be approximate; not a warning service.'
  },
  {
    id: 'gdacs', name: 'GDACS Disaster Alerts', short: 'GDACS', category: 'disaster', enabled: true,
    url: 'https://www.gdacs.org/gdacsapi/api/events/geteventlist/MAP',
    homepage: 'https://www.gdacs.org/', ttlMs: 15 * minute,
    coverage: 'Worldwide · disaster alerts published by GDACS',
    terms: 'Attribute GDACS (UN / European Commission). Alert colour is the provider rating.'
  },
  {
    id: 'nws', name: 'US Weather Alerts', short: 'NWS', category: 'weather', enabled: false,
    url: 'https://api.weather.gov/alerts/active?status=actual',
    homepage: 'https://www.weather.gov/', ttlMs: 10 * minute,
    coverage: 'United States only · active official weather alerts',
    terms: 'US National Weather Service public data. Some alerts have no coordinates.'
  },
  {
    id: 'kev', name: 'CISA Known Exploited', short: 'CISA', category: 'cyber', enabled: true,
    url: 'https://api.github.com/repos/cisagov/kev-data/contents/known_exploited_vulnerabilities.json',
    accept: 'application/vnd.github.raw+json',
    homepage: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', ttlMs: 6 * 60 * minute,
    coverage: 'Global cyber · latest 800 catalogue entries · no geographic attribution',
    terms: 'Official cisagov mirror. Known exploitation does not mean your device is affected. GitHub anonymous quota applies.'
  },
  {
    id: 'advisories', name: 'GitHub Security Advisories', short: 'GitHub', category: 'cyber', enabled: true,
    url: 'https://api.github.com/advisories?per_page=50&type=reviewed',
    accept: 'application/vnd.github+json',
    homepage: 'https://github.com/advisories', ttlMs: 60 * minute,
    coverage: 'Global cyber · 50 latest reviewed advisories · not a device scan',
    terms: 'GitHub Advisory Database, CC-BY-4.0. Shared anonymous API limits apply.'
  },
  {
    id: 'noaa', name: 'NOAA Space Weather', short: 'NOAA', category: 'space', enabled: false,
    url: 'https://services.swpc.noaa.gov/products/alerts.json',
    homepage: 'https://www.swpc.noaa.gov/', ttlMs: 15 * minute,
    coverage: 'Global · solar and geomagnetic bulletins · no invented event coordinates',
    terms: 'NOAA public data. Bulletin text is not a local impact forecast.'
  },
  {
    id: 'geonet', name: 'GeoNet New Zealand', short: 'GeoNet', category: 'seismic', enabled: false,
    url: 'https://api.geonet.org.nz/quake?MMI=3', homepage: 'https://www.geonet.org.nz/', ttlMs: 10 * minute,
    coverage: 'New Zealand · reported earthquakes meeting the provider intensity filter',
    terms: 'GeoNet data, CC BY 4.0. Local magnitude bands are for triage, not predicted impact.'
  },
  {
    id: 'emsc', name: 'EMSC Seismic Portal', short: 'EMSC', category: 'seismic', enabled: false,
    url: 'https://www.seismicportal.eu/fdsnws/event/1/query?limit=100&format=json', homepage: 'https://www.seismicportal.eu/', ttlMs: 10 * minute,
    coverage: 'Worldwide · latest 100 seismic events · may overlap USGS',
    terms: 'Attribute EMSC. Separate provider reports are kept distinct; counts are not unique physical incidents.'
  },
  {
    id: 'github-status', name: 'GitHub Service Status', short: 'GitHub status', category: 'infrastructure', enabled: false,
    url: 'https://www.githubstatus.com/api/v2/incidents.json', homepage: 'https://www.githubstatus.com/', ttlMs: 10 * minute,
    coverage: 'GitHub official service incidents · provider-wide, not country-specific',
    terms: 'Public status API. Resolved records remain labelled; severity uses provider impact.'
  },
  {
    id: 'cloudflare-status', name: 'Cloudflare Service Status', short: 'Cloudflare', category: 'infrastructure', enabled: false,
    url: 'https://www.cloudflarestatus.com/api/v2/incidents.json', homepage: 'https://www.cloudflarestatus.com/', ttlMs: 10 * minute,
    coverage: 'Cloudflare official service incidents · no inferred point locations',
    terms: 'Public status API. An incident does not prove your connection was affected.'
  },
  {
    id: 'gdelt', name: 'GDELT World Headlines', short: 'GDELT', category: 'news', enabled: false,
    url: 'https://api.gdeltproject.org/api/v2/doc/doc?query=%28disaster%20OR%20cyberattack%20OR%20climate%20OR%20conflict%29&mode=artlist&format=json&maxrecords=75&sort=datedesc&timespan=1d',
    homepage: 'https://www.gdeltproject.org/', ttlMs: 15 * minute,
    coverage: 'Worldwide media · 75 headlines · past 24 hours · no inferred event coordinates',
    terms: 'GDELT indexes third-party reporting. Headlines are not verified incident reports; consult the publisher.'
  }
]);
export const SOURCE_BY_ID = new Map(SOURCES.map((s) => [s.id, s]));
export const WEATHER_PLACES = Object.freeze([
  { id: 'manila', name: 'Manila', lat: 14.60, lon: 120.98, zone: 'Asia/Manila' },
  { id: 'tokyo', name: 'Tokyo', lat: 35.68, lon: 139.69, zone: 'Asia/Tokyo' },
  { id: 'london', name: 'London', lat: 51.51, lon: -0.13, zone: 'Europe/London' },
  { id: 'new-york', name: 'New York', lat: 40.71, lon: -74.01, zone: 'America/New_York' },
  { id: 'sydney', name: 'Sydney', lat: -33.87, lon: 151.21, zone: 'Australia/Sydney' }
]);
export const LIMITS = Object.freeze({ eventsPerSource: 800, watches: 30, bookmarks: 200, alerts: 300, bytes: 6_000_000, timeoutMs: 15_000 });
