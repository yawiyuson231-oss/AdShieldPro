/** Searchable country/territory directory, saved lenses, grounded geography and dated indicators. */
import { h, mount, pill, note, number } from '../ui/dom.js';
import { icon } from '../ui/icons.js';
import { COUNTRIES, COUNTRY_BY_CODE, CountryService, countrySummary, searchCountries } from './countries.js';

const btn = (text, action, props = {}) => h('button', { type: 'button', onclick: action, ...props }, text);
export class CountryView {
  constructor(host, store, { onEvent, onWeather, onFocus, onError } = {}) {
    this.host = host; this.store = store; this.onEvent = onEvent; this.onWeather = onWeather; this.onFocus = onFocus; this.onError = onError;
    this.service = new CountryService({ fetchImpl: store.fetchImpl, storage: store.storage, clock: store.clock });
    this.query = ''; this.profileBusy = false;
    this.search = h('input', { type: 'search', id: 'world-country-search', 'aria-label': 'Search countries and territories', placeholder: `Search ${COUNTRIES.length} countries & territories…`, maxlength: 80,
      oninput: (e) => { this.query = e.target.value; this.renderDirectory(); } });
    this.directory = h('div', { class: 'wm-country-directory', id: 'world-country-directory' });
    this.detail = h('div', { class: 'wm-country-detail', id: 'world-country-detail' });
    mount(host, h('div', { class: 'wm-country-layout' }, h('aside', { class: 'wm-country-sidebar' },
      h('h3', {}, 'Around the world'), h('p', { class: 'small muted' }, `${COUNTRIES.length} country and territory profiles. Search by name, code or region.`),
      this.search, this.directory), this.detail));
    this.render(); this.service.loadBoundaries().then(() => this.render());
  }
  get country() { return COUNTRY_BY_CODE.get(this.store.country) || COUNTRIES[0]; }
  renderDirectory() {
    const rows = searchCountries(this.query);
    const saved = new Set(this.store.savedCountries);
    rows.sort((a, b) => Number(saved.has(b.code)) - Number(saved.has(a.code)) || a.name.localeCompare(b.name));
    mount(this.directory, h('span', { class: 'small muted' }, `${rows.length} matches · saved countries first`),
      rows.length ? rows.map((c) => btn([h('span', { class: 'wm-country-code' }, c.code), h('span', {}, c.name), saved.has(c.code) ? icon('bookmark', 12) : null],
        () => { this.store.setCountry(c.code); this.onFocus?.(c); }, { class: c.code === this.country.code ? 'selected' : '', 'aria-current': c.code === this.country.code ? 'true' : 'false', 'data-country': c.code }))
        : h('p', { class: 'empty' }, 'No matching country. Try another spelling or its two-letter code.'));
  }
  render() {
    if (!this.host.isConnected) return;
    this.renderDirectory();
    const country = this.country;
    const events = this.store.filtered();
    const summary = countrySummary(country, events, this.service.boundaries);
    const saved = this.store.savedCountries.includes(country.code);
    const profiles = this.service.profiles.get(country.code);
    const metric = (value, name) => h('div', {}, h('strong', {}, value), h('span', {}, name));
    const provider = (name, value, currency) => h('div', { class: 'wm-country-indicator' }, h('span', {}, name),
      h('strong', {}, Number.isFinite(value?.value) ? `${currency ? '$' : ''}${number(value.value, currency ? 0 : 0)}` : 'Not available'),
      h('small', {}, value?.year ? `Published for ${value.year} · ${value.cached ? 'cached' : 'received'}${currency ? ' · current US$' : ''}` : 'No current value received'),
      value?.error ? h('p', {}, value.error) : null);
    mount(this.detail,
      h('div', { class: 'wm-country-heading' }, h('div', {}, h('div', { class: 'eyebrow' }, `${country.region || 'World'} / ${country.subregion || country.code}`), h('h3', {}, country.name), h('p', {}, country.official)),
        btn([icon('bookmark', 16), saved ? 'Saved' : 'Save country'], () => this.store.toggleCountry(country.code), { id: 'world-country-save', 'aria-pressed': String(saved), class: saved ? 'selected' : '' })),
      h('div', { class: 'wm-country-metrics' }, metric(summary.hasBoundary ? number(summary.located.length) : '—', 'Received in approximate boundary'), metric(number(summary.priority), 'High / critical in boundary'), metric(number(summary.mentions.length), 'Mentions without event coordinates')),
      !this.service.boundaries ? note(this.service.loading ? 'Loading the bundled country boundaries…' : `Country boundaries are unavailable: ${this.service.error || 'no boundary data'}. No locations are inferred.`, 'warn') : !summary.hasBoundary ? note('This territory has no separate polygon in the bundled map. Geographic counts are unavailable; mentions below are not evidence of event location.', 'warn') : null,
      h('p', { class: 'wm-small-print' }, 'Current time, layer, source and region filters apply. Approximate Natural Earth boundaries are for context only. A zero count means no matching received records, not an absence of hazards. Country listings do not imply a position on sovereignty.'),
      h('dl', { class: 'wm-country-facts' }, h('dt', {}, 'Capital / administrative centre'), h('dd', {}, country.capital), h('dt', {}, 'Languages'), h('dd', {}, country.languages.join(', ') || 'Not listed'), h('dt', {}, 'Currency'), h('dd', {}, country.currencies.join(', ') || 'Not listed'), h('dt', {}, 'Area (bundled metadata)'), h('dd', {}, `${number(country.area)} km²`)),
      h('div', { class: 'row' }, btn([icon('pin', 16), 'Focus map'], () => this.onFocus?.(country), { id: 'world-country-locate', class: 'sm' }),
        btn([icon('cloud', 16), 'Weather at reference point'], () => this.onWeather?.(country), { id: 'world-country-weather', class: 'sm' }),
        btn(this.profileBusy ? 'Loading indicators…' : 'Load latest country indicators', async () => {
          if (this.profileBusy) return;
          this.profileBusy = true; this.render();
          try { await this.service.profile(country.code); } catch (e) { this.onError?.(e.message); }
          finally { this.profileBusy = false; this.render(); }
        }, { class: 'sm', disabled: this.profileBusy, id: 'world-country-profile' })),
      profiles ? h('div', { class: 'wm-country-indicators' }, provider('Population', profiles.population), provider('GDP per capita', profiles.gdpPerCapita, true)) : null,
      profiles?.storageError ? note(profiles.storageError, 'warn') : null,
      h('p', { class: 'wm-small-print' }, 'Indicators are requested only when you choose Load, directly from the World Bank (CC BY 4.0); publication year is shown, never presented as a real-time reading. Weather uses a country reference point, not your GPS position.'),
      h('h4', {}, 'Received geolocated events'),
      summary.located.length ? h('div', { class: 'wm-country-events' }, summary.located.slice(0, 100).map((e) => btn([pill(e.severity, ['high', 'critical'].includes(e.severity) ? 'bad' : ''), h('span', {}, e.title)], () => this.onEvent?.(e))))
        : h('p', { class: 'empty' }, summary.hasBoundary ? 'No matching received events in the approximate boundary.' : 'Geographic matches cannot be computed for this territory.'),
      summary.located.length > 100 ? h('p', { class: 'small muted' }, 'Showing the newest 100 matches. Narrow the time range for a smaller view.') : null,
      summary.mentions.length ? h('div', {}, h('h4', {}, 'Country mentions — not geolocated'), h('p', { class: 'wm-small-print' }, 'Text mentions are shown separately. They do not establish where an incident occurred.'),
        h('div', { class: 'wm-country-events' }, summary.mentions.slice(0, 50).map((e) => btn(e.title, () => this.onEvent?.(e))))) : null,
      h('p', { class: 'wm-country-credit' }, 'Country directory: ', h('a', { href: 'https://github.com/mledoze/countries', target: '_blank', rel: 'noopener noreferrer' }, 'mledoze/countries, ODbL-1.0'), ' · bundled 2026-11-08. Map: Natural Earth, public domain.'));
  }
}
