/** Shared interactive World Monitor UI. All provider content is rendered as text, never HTML. */
import { h, mount, pill, note, number, relativeTime, toast } from '../ui/dom.js';
import { icon } from '../ui/icons.js';
import { SOURCE_BY_ID, CATEGORIES, REGIONS, SEVERITIES, WEATHER_PLACES, WORLD_VERSION } from './catalog.js';
import { buildBriefing, exportCsv, histogram, parseWatchImport, validCoordinates } from './model.js';
import { WorldMap } from './map.js';
import { WeatherService, weatherLabel, airLabel } from './weather.js';
import { saveWorldFile, readWatchFile } from './export.js';
import { CountryView } from './country-view.js';
import { COUNTRIES } from './countries-data.js';
import { CUSTOM_FORMATS } from './custom.js';
import { configureDailyHost, loadBackgroundSnapshot } from './native.js';

const statusClass = (s) => s === 'live' ? 'ok' : ['error', 'rate-limited'].includes(s) ? 'bad' : ['stale', 'offline', 'cached'].includes(s) ? 'warn' : '';
const severityClass = (s) => ['critical', 'high'].includes(s) ? 'bad' : s === 'moderate' ? 'warn' : 'info';
const dateLabel = (at) => at ? new Date(at).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : 'Never';
const button = (text, onClick, props = {}) => h('button', { type: 'button', onclick: onClick, ...props }, text);
const link = (text, url) => h('a', { href: url, target: '_blank', rel: 'noopener noreferrer' }, text);
const category = (id) => CATEGORIES.find((c) => c.id === id) || CATEGORIES[0];
function select(id, label, choices, value, onChange) {
  const control = h('select', { id, 'aria-label': label, onchange: (e) => onChange(e.target.value) }, choices.map(([v, t]) => h('option', { value: v, text: t, selected: v === value })));
  return h('label', { class: 'wm-field' }, h('span', {}, label), control);
}
function emptyState(title, description, glyph = 'globe') {
  return h('div', { class: 'wm-empty' }, h('span', { class: 'wm-empty-icon' }, icon(glyph, 28)), h('h3', {}, title), h('p', {}, description));
}

export class WorldMonitorView {
  constructor(host, store, options = {}) {
    this.host = host; this.store = store; this.active = false; this.tab = 'events'; this.page = 0;
    this.selected = null; this.lastAuto = 0; this.renderedRegion = null; this.notice = null;
    this.weather = options.weather || new WeatherService({ storage: store.storage, fetchImpl: store.fetchImpl, clock: store.clock });
    this.weatherPlace = { ...WEATHER_PLACES[0] }; this.weatherBusy = false;
    this.download = options.download || saveWorldFile;
    this.build();
    this.unsubscribe = store.subscribe(() => this.render());
    this.timer = setInterval(() => this.tick(), 30_000);
    this.timer.unref?.();
    this.weather.load().then(() => this.renderWeather());
    this.render();
    loadBackgroundSnapshot(store).then((r) => { if (r.error) this.say(r.error, 'warn'); });
  }
  setActive(active) { this.active = active; if (active) this.tick(); }
  destroy() { clearInterval(this.timer); this.unsubscribe?.(); this.store.cancel(); this.detail.remove(); }
  tick() {
    if (!this.active || document.visibilityState === 'hidden') return;
    this.render();
    const dailyDue = this.store.dailyRefresh && this.store.clock() - this.store.lastDaily >= 86_400_000;
    const liveDue = this.store.autoRefresh && this.store.clock() - this.lastAuto >= 300_000;
    if ((dailyDue || liveDue) && navigator.onLine !== false && !this.store.busy) {
      if (dailyDue) { this.store.lastDaily = this.store.clock(); this.store.persist(); }
      this.lastAuto = this.store.clock(); this.store.refresh();
    }
  }
  say(message, kind = '') { this.notice = { message, kind }; this.renderNotice(); toast(message, kind); }
  async action(fn) { try { await fn(); } catch (e) { this.say(e.message || 'The action could not be completed.', 'bad'); } }

  build() {
    this.refreshButton = button([icon('refresh'), 'Refresh feeds'], () => this.refresh(), { id: 'world-refresh', class: 'primary' });
    this.autoButton = button('Auto-refresh off', () => {
      this.store.autoRefresh = !this.store.autoRefresh;
      if (this.store.autoRefresh) { this.lastAuto = this.store.clock(); this.refresh(); }
      this.render();
    }, { id: 'world-auto', 'aria-pressed': 'false', title: 'Refresh due sources every five minutes, only while this page is visible.' });
    this.clock = h('span', { class: 'wm-clock mono', 'aria-label': 'Current UTC time' });
    this.noticeHost = h('div', { id: 'world-notice', role: 'status', 'aria-live': 'polite' });
    this.summary = h('div', { class: 'wm-stats', id: 'world-stats' });
    this.search = h('input', { type: 'search', id: 'world-search', placeholder: 'Search events, places, CVEs…', maxlength: 160,
      'aria-label': 'Search received world events', value: this.store.filters.query,
      oninput: (e) => { this.page = 0; this.store.setFilters({ query: e.target.value }); } });
    const updateFilter = (key) => (value) => { this.page = 0; this.store.setFilters({ [key]: value }); };
    this.controls = h('div', { class: 'wm-filters' },
      h('label', { class: 'wm-search', for: 'world-search' }, icon('search'), this.search),
      select('world-region', 'Region', REGIONS.map((r) => [r.id, r.label]), this.store.filters.region, updateFilter('region')),
      select('world-range', 'Time window', [['24h', 'Past 24 hours'], ['7d', 'Past 7 days'], ['30d', 'Past 30 days'], ['all', 'All received']], this.store.filters.range, updateFilter('range')),
      select('world-severity', 'Priority', [['info', 'All priorities'], ['moderate', 'Moderate & above'], ['high', 'High & critical'], ['critical', 'Critical only']], this.store.filters.severity, updateFilter('severity')),
      button('Reset', () => { this.page = 0; this.store.resetFilters(); }, { class: 'ghost sm', id: 'world-reset-filters' }));
    this.layers = h('div', { class: 'wm-layers', 'aria-label': 'Event layers' });
    this.mapHost = h('div', { class: 'wm-map-viewport', id: 'world-map' });
    this.mapStatus = pill('No feeds refreshed', '');
    const mapPanel = h('section', { class: 'wm-map-panel', 'aria-label': 'Global situation map' },
      h('div', { class: 'wm-panel-heading' }, h('div', { class: 'row' }, icon('globe'), h('h3', {}, 'Global situation'), this.mapStatus), h('span', { class: 'small muted' }, 'Drag to explore · scroll to zoom')),
      this.mapHost);
    this.brief = h('aside', { class: 'wm-brief', 'aria-label': 'Situation summary' });
    this.tabs = h('nav', { class: 'wm-tabs', 'aria-label': 'World Monitor views' });
    this.panel = h('section', { class: 'wm-content', id: 'world-content', 'aria-label': 'World Monitor records' });
    this.countAnnouncement = h('span', { class: 'sr-only', role: 'status', 'aria-live': 'polite', 'aria-atomic': 'true', id: 'world-results-count' });
    this.exportFormat = h('select', { id: 'world-export-format', 'aria-label': 'Export format' },
      h('option', { value: 'json' }, 'JSON data'), h('option', { value: 'csv' }, 'CSV table'), h('option', { value: 'md' }, 'Briefing (.md)'));
    mount(this.host,
      h('div', { class: 'wm-heading' },
        h('div', {}, h('div', { class: 'eyebrow' }, h('span', { class: 'wm-brand-dot' }), 'GLOBAL AWARENESS / LOCAL CONTROL'),
          h('h2', {}, 'World Monitor', h('span', { class: 'wm-version' }, `v${WORLD_VERSION}`)),
          h('p', {}, 'A clearer view of a changing world.')),
        h('div', { class: 'wm-heading-actions' }, this.clock, h('div', { class: 'row' }, this.autoButton, this.refreshButton))),
      this.noticeHost, this.summary, this.controls, this.layers,
      h('div', { class: 'wm-command-grid' }, mapPanel, this.brief),
      h('div', { class: 'wm-viewbar' }, this.tabs,
        h('div', { class: 'wm-export row' }, this.exportFormat, button([icon('download'), 'Export'], () => this.action(() => this.export()), { id: 'world-export', class: 'sm' }))),
      this.countAnnouncement, this.panel,
      h('div', { class: 'wm-bottomline' }, h('span', {}, 'Source-backed. Locally stored. No tracking pixels.'), h('span', {}, 'Coverage is partial · not an emergency warning system')));
    this.map = new WorldMap(this.mapHost, { onSelect: (e) => this.openDetail(e) });
    this.detail = h('dialog', { class: 'wm-detail', 'aria-label': 'World event details', id: 'world-detail' });
    this.detail.addEventListener('click', (e) => { if (e.target === this.detail) this.closeDetail(); });
    this.detail.addEventListener('cancel', (e) => { e.preventDefault(); this.closeDetail(); });
    this.detail.addEventListener('keydown', (e) => this.trapDialog(e));
    document.body.append(this.detail);
  }

  renderNotice() {
    const any = Object.values(this.store.sources).some((s) => s.health.lastSuccess);
    mount(this.noticeHost,
      this.notice ? h('div', { class: 'wm-notice' }, note(this.notice.message, this.notice.kind), button('Dismiss', () => { this.notice = null; this.renderNotice(); }, { class: 'sm ghost' })) : null,
      this.store.storageError ? note(this.store.storageError, 'warn') : null,
      this.store.cacheNotice ? note(this.store.cacheNotice, 'warn') : null,
      !any && !this.store.busy ? h('div', { class: 'wm-onboarding' }, icon('lock'), h('p', {}, h('strong', {}, 'You decide when to connect. '),
        'Refresh feeds to request public data directly from the enabled providers. They receive your IP address, not your DNS history or precise location. Until then, this map has no live events.')) : null);
  }

  render() {
    const scheduleKey = JSON.stringify([this.store.dailyRefresh, this.store.catalog.filter((s) => this.store.sources[s.id].enabled).map((s) => s.id)]);
    if (scheduleKey !== this.scheduleKey) {
      try { this.nativeDaily = configureDailyHost(this.store); this.scheduleKey = scheduleKey; } catch { this.nativeDaily = false; }
    }
    const events = this.store.filtered(); const health = this.store.health(); const all = this.store.events;
    const active = Object.values(health).filter((s) => s.enabled); const live = active.filter((s) => s.status === 'live').length;
    const busy = this.store.busy; const unread = this.store.alerts.filter((a) => !a.read).length;
    this.refreshButton.disabled = busy;
    mount(this.refreshButton, icon('refresh'), busy ? 'Refreshing…' : 'Refresh feeds');
    this.autoButton.textContent = this.store.autoRefresh ? 'Auto · every 5 min' : 'Auto-refresh off';
    this.autoButton.setAttribute('aria-pressed', String(this.store.autoRefresh));
    this.clock.textContent = new Date(this.store.clock()).toLocaleTimeString('en-GB', { timeZone: 'UTC', hour: '2-digit', minute: '2-digit' }) + ' UTC';
    this.renderNotice();
    const stat = (label, value, sub, glyph, className = '') => h('div', { class: `wm-stat ${className}` },
      h('div', { class: 'wm-stat-top' }, h('span', {}, label), icon(glyph, 17)), h('strong', {}, value), h('small', {}, sub));
    mount(this.summary,
      stat('RECEIVED EVENTS', number(all.length), `${number(events.length)} match your filters`, 'globe'),
      stat('HIGH & CRITICAL', number(events.filter((e) => ['high', 'critical'].includes(e.severity)).length), 'Within the filtered records', 'activity', 'wm-priority'),
      stat('FRESH SOURCES', `${live} / ${active.length}`, busy ? 'Refresh in progress' : active.length ? 'Successful fetch within source TTL' : 'All sources disabled', 'layers'),
      stat('WATCH ALERTS', number(unread), this.store.watches.length ? `${this.store.watches.length} saved watches · unread matches` : 'Create a watch to focus your view', 'bell'));
    for (const [key, id] of [['region', 'world-region'], ['range', 'world-range'], ['severity', 'world-severity']]) this.host.querySelector(`#${id}`).value = this.store.filters[key];
    if (document.activeElement !== this.search) this.search.value = this.store.filters.query;
    mount(this.layers, h('span', { class: 'wm-layer-label' }, 'LAYERS'), CATEGORIES.map((c) => {
      const on = this.store.filters.categories.includes(c.id);
      return button([h('span', { class: 'wm-layer-dot', style: { backgroundColor: c.color } }), c.label,
        h('span', { class: 'wm-layer-count' }, all.filter((e) => e.category === c.id).length)], () => {
        this.page = 0; this.store.setFilters({ categories: on ? this.store.filters.categories.filter((id) => id !== c.id) : [...this.store.filters.categories, c.id] });
      }, { class: `wm-layer ${on ? 'selected' : ''}`, 'aria-pressed': String(on), 'data-layer': c.id });
    }));
    this.mapStatus.textContent = busy ? 'Syncing sources' : live ? `${live} fresh ${live === 1 ? 'source' : 'sources'}` : all.length ? 'Cached / stale data' : 'Awaiting data';
    this.mapStatus.className = `pill ${live ? 'ok' : all.length ? 'warn' : ''}`;
    this.map.update(events, this.selected?.id);
    if (this.renderedRegion !== this.store.filters.region) { this.renderedRegion = this.store.filters.region; this.map.setRegion(this.renderedRegion); }
    this.renderBrief(events, health);
    this.renderTabs(events.length);
    const countText = `${events.length} matching records, ${events.filter((e) => e.lat !== null).length} with coordinates.`;
    if (this.countAnnouncement.textContent !== countText) this.countAnnouncement.textContent = countText;
    this.renderPanel();
    if (this.detail.open && this.selected) this.renderDetail();
  }

  async refresh() {
    if (this.store.busy) return;
    await this.action(async () => {
      const results = await this.store.refresh();
      const rows = Object.values(results);
      const successes = rows.filter((r) => r.ok).length;
      this.say(rows.length ? `${successes} of ${rows.length} enabled sources available. ${successes < rows.length ? 'See Sources for errors and retry times; any previous data is retained.' : 'Feed timestamps and coverage are shown below.'}`
        : 'No sources are enabled. Open Sources to choose providers.', successes === rows.length && rows.length ? 'ok' : 'warn');
    });
  }

  renderBrief(events, health) {
    const priority = [...events].sort((a, b) => SEVERITIES.indexOf(b.severity) - SEVERITIES.indexOf(a.severity) || b.occurredAt - a.occurredAt).slice(0, 3);
    const bars = histogram(events, this.store.clock()); const peak = Math.max(1, ...bars.map((b) => b.count));
    const states = Object.values(health).filter((s) => s.enabled);
    const unavailable = states.filter((s) => ['error', 'offline', 'rate-limited'].includes(s.status)).length;
    mount(this.brief,
      h('div', { class: 'wm-panel-heading' }, h('h3', {}, icon('spark'), 'Situation brief'), pill('LOCAL SUMMARY', '')),
      h('p', { class: 'wm-brief-intro' }, events.length ? `${number(events.length)} records in view. ${unavailable ? `${unavailable} sources unavailable — coverage is incomplete.` : 'Based only on received data, not the whole world.'}` : 'Your view starts with evidence. Refresh sources to build a situation brief.'),
      h('div', { class: 'wm-brief-priorities' }, priority.length ? priority.map((e) => button([
        h('span', { class: `wm-severity-dot ${e.severity}` }), h('span', {}, h('strong', {}, e.title), h('small', {}, `${SOURCE_BY_ID.get(e.source)?.short} · ${relativeTime(e.occurredAt, this.store.clock())}`)), icon('arrow', 14)
      ], () => this.openDetail(e), { class: 'wm-brief-item' })) : h('div', { class: 'wm-brief-placeholder' }, icon('activity', 30), h('span', {}, 'No received activity yet'))),
      h('div', { class: 'wm-chart-label' }, h('span', {}, 'RECEIVED RECORDS / LAST 24H'), h('span', {}, `${bars.reduce((n, b) => n + b.count, 0)} total`)),
      h('div', { class: 'wm-histogram', role: 'img', 'aria-label': `Hourly distribution of ${bars.reduce((n, b) => n + b.count, 0)} filtered records over the past 24 hours.` }, bars.map((b) => h('span', { style: { height: `${Math.max(3, b.count / peak * 100)}%` }, title: `${new Date(b.at).toISOString()}: ${b.count} records`, class: b.high ? 'high' : b.count ? 'populated' : '' }))),
      button([icon('download', 15), 'Export situation briefing'], () => this.action(() => this.export('md')), { class: 'wm-brief-export', id: 'world-brief-export' }),
      h('p', { class: 'wm-small-print' }, 'Different sources use different severity scales. This is not a prediction, global risk score or emergency service.'));
  }

  renderTabs(count) {
    const entries = [['events', 'Event feed', count, 'activity'], ['countries', 'Countries', COUNTRIES.length, 'globe'], ['saved', 'Saved', this.store.bookmarks.length, 'bookmark'], ['watches', 'Watchlists', this.store.watches.length, 'bell'], ['sources', 'Sources', this.store.catalog.length, 'layers'], ['weather', 'Weather & air', null, 'cloud']];
    mount(this.tabs, entries.map(([id, title, n, glyph]) => button([icon(glyph, 16), title, n !== null ? h('span', { class: 'wm-tab-count' }, n) : null], () => this.setTab(id),
      { class: this.tab === id ? 'active' : '', 'aria-current': this.tab === id ? 'true' : 'false', 'data-world-tab': id })));
  }
  setTab(tab) { this.tab = tab; this.page = 0; this.renderTabs(this.store.filtered().length); this.renderPanel(); }
  renderPanel() {
    // Do not replace focused form fields when a source refresh publishes a status update.
    if (this.tab === 'watches' && this.panel.querySelector('#world-watch-form')) { this.renderWatchesList(); return; }
    if (this.tab === 'weather' && this.panel.querySelector('#world-weather-form')) { this.renderWeather(); return; }
    if (this.tab === 'countries') {
      if (this.countryView?.host.isConnected && this.panel.querySelector('#world-countries')) this.countryView.render();
      else {
        const host = h('div', { id: 'world-countries' }); mount(this.panel, host);
        this.countryView = new CountryView(host, this.store, {
          onEvent: (e) => this.openDetail(e), onError: (error) => this.say(error, 'warn'),
          onFocus: (c) => { this.map.focus({ id: null, lat: c.lat, lon: c.lon }); this.mapHost.scrollIntoView?.({ block: 'center', behavior: 'smooth' }); },
          onWeather: (c) => { this.weatherPlace = { name: `${c.name} reference point`, lat: c.lat, lon: c.lon }; this.setTab('weather'); this.panel.scrollIntoView?.({ block: 'start', behavior: 'smooth' }); }
        });
      }
    }
    else if (this.tab === 'sources') this.renderSources();
    else if (this.tab === 'watches') this.buildWatches();
    else if (this.tab === 'weather') this.buildWeather();
    else this.renderEvents();
  }

  renderEvents() {
    const saved = this.tab === 'saved'; const events = saved ? this.store.bookmarks : this.store.filtered();
    const pageCount = Math.max(1, Math.ceil(events.length / 25)); this.page = Math.min(this.page, pageCount - 1);
    const health = this.store.health();
    const rows = events.slice(this.page * 25, (this.page + 1) * 25);
    const toolbar = h('div', { class: 'wm-feed-heading' }, h('div', {}, h('h3', {}, saved ? 'Your saved events' : 'Intelligence feed'),
      h('p', { class: 'small muted' }, saved ? 'Saved snapshots remain available after a source refresh. They are not live updates.' : `${events.length} matching records · sorted by ${this.store.filters.sort === 'severity' ? 'priority' : 'publication / event time'}`)),
      !saved ? h('div', { class: 'row' },
        select('world-source-filter', 'Source', [['all', 'All sources'], ...this.store.catalog.map((s) => [s.id, s.short])], this.store.filters.source, (value) => { this.page = 0; this.store.setFilters({ source: value }); }),
        select('world-sort', 'Sort', [['newest', 'Newest first'], ['severity', 'Priority first']], this.store.filters.sort, (value) => { this.page = 0; this.store.setFilters({ sort: value }); })) : null);
    const list = h('div', { class: 'wm-event-list', id: 'world-events' }, rows.length ? rows.map((e) => {
      const cat = category(e.category); const isSaved = this.store.bookmarks.some((b) => b.id === e.id);
      return h('article', { class: 'wm-event', 'data-event': e.id },
        h('span', { class: 'wm-event-icon', style: { color: cat.color } }, icon(cat.icon, 20)),
        h('div', { class: 'wm-event-main' }, h('div', { class: 'wm-event-meta' }, pill(e.severity.toUpperCase(), severityClass(e.severity)), h('span', {}, SOURCE_BY_ID.get(e.source)?.short), h('time', { datetime: new Date(e.occurredAt).toISOString(), title: dateLabel(e.occurredAt) }, relativeTime(e.occurredAt, this.store.clock())),
          h('span', { class: 'wm-data-status' }, saved ? 'SAVED SNAPSHOT' : (health[e.source]?.status || 'cached').toUpperCase())),
          button(e.title, () => this.openDetail(e), { class: 'wm-event-title' }),
          h('p', { class: 'wm-event-location' }, icon('pin', 12), e.location)),
        button(icon('bookmark', 18), () => this.action(() => this.store.toggleBookmark(e)), { class: `wm-save ${isSaved ? 'selected' : ''}`, 'aria-label': `${isSaved ? 'Unsave' : 'Save'} ${e.title}`, 'aria-pressed': String(isSaved), 'data-save-event': e.id }));
    }) : emptyState(saved ? 'Keep the events that matter.' : this.store.events.length ? 'No records match this view.' : 'The world map is ready. Your feeds are next.',
      saved ? 'Use the bookmark button on any event. Saved records stay on this device.' : this.store.events.length ? 'Try a wider time window, another region, or reset the filters. Only events with provider coordinates appear in regional views.' : 'Choose Refresh feeds to connect. Unavailable providers will show their actual error in Sources — no sample activity is inserted.', saved ? 'bookmark' : 'globe'));
    mount(this.panel, toolbar, list, h('div', { class: 'wm-pagination' }, h('span', { class: 'small muted' }, events.length ? `Showing ${this.page * 25 + 1}–${Math.min(events.length, (this.page + 1) * 25)} of ${events.length}` : '0 records'),
      h('div', { class: 'row' }, button('Previous', () => { this.page--; this.renderEvents(); }, { disabled: this.page === 0, class: 'sm' }), h('span', { class: 'small' }, `${this.page + 1} / ${pageCount}`), button('Next', () => { this.page++; this.renderEvents(); }, { disabled: this.page + 1 >= pageCount, class: 'sm' }))));
  }

  renderSources() {
    const health = this.store.health();
    const active = document.activeElement;
    const focus = this.panel.contains(active) && active?.id ? { id: active.id, start: active.selectionStart, end: active.selectionEnd } : null;
    mount(this.panel,
      h('div', { class: 'wm-feed-heading' }, h('div', {}, h('h3', {}, 'Your sources. Their actual status.'), h('p', { class: 'small muted' }, 'Enabling a source does not contact it. Refresh explicitly, or turn on visible-page auto-refresh.')),
        button('Stop refresh', () => this.store.cancel(), { disabled: !this.store.busy, class: 'sm' })),
      h('div', { class: 'wm-source-grid' }, this.store.catalog.map((s) => {
        const state = health[s.id]; const cooling = state.retryAt > this.store.clock();
        return h('article', { class: 'wm-source', 'data-source': s.id },
          h('div', { class: 'wm-source-top' }, h('span', { class: 'wm-source-logo' }, s.short.slice(0, 2).toUpperCase()), h('div', {}, h('h4', {}, s.name), pill(state.status.toUpperCase(), statusClass(state.status))),
            h('label', { class: 'wm-switch', title: `Enable ${s.name}` }, h('input', { type: 'checkbox', checked: state.enabled, 'aria-label': `Enable ${s.name}`, onchange: (e) => this.store.setEnabled(s.id, e.target.checked) }), h('span', { 'aria-hidden': 'true' }))),
          h('p', { class: 'wm-source-coverage' }, s.coverage),
          h('dl', { class: 'wm-source-metrics' }, h('dt', {}, 'Last success'), h('dd', {}, state.lastSuccess ? `${relativeTime(state.lastSuccess, this.store.clock())} · ${dateLabel(state.lastSuccess)}` : 'Not yet received'), h('dt', {}, 'Records / TTL'), h('dd', {}, `${state.count} / ${s.ttlMs / 60_000} min`)),
          state.error ? note(state.error, 'warn') : null,
          state.rejected ? h('p', { class: 'small muted' }, `${state.rejected} malformed records skipped.`) : null,
          state.truncated ? h('p', { class: 'small muted' }, `Showing the newest ${state.count} records; the upstream response contained more.`) : null,
          h('div', { class: 'wm-source-actions' }, link('Provider & attribution ↗', s.homepage), button(cooling ? `Retry after ${new Date(state.retryAt).toLocaleTimeString()}` : 'Refresh source', () => this.action(() => this.store.sync(s.id, { force: true })),
            { class: 'sm', disabled: !state.enabled || state.status === 'loading' || cooling })),
          h('details', {}, h('summary', {}, 'Coverage & terms'), h('p', { class: 'small muted' }, s.terms)),
          s.custom ? button('Remove custom feed', () => this.action(async () => { if (confirm(`Remove ${s.name} and its received cache?`)) await this.store.removeSource(s.id); }), { class: 'sm danger' }) : null);
      })),
      this.dailyControls(), this.customSourceForm(),
      h('div', { class: 'wm-source-footer' }, note('A fresh source means a valid response within its cache TTL — not complete world coverage. Empty responses can be valid. Browser CORS rules, rate limits and provider outages are shown honestly. No API keys or proxy servers are bundled.'),
        button('Clear received cache', () => this.action(async () => { if (confirm('Clear received world events and alert matches? Your bookmarks and watch rules will be kept.')) { await this.store.clearCache(); this.say('Received cache cleared. Bookmarks and watch rules were kept.', 'ok'); } }), { class: 'danger sm', id: 'world-clear-cache' })));
    if (focus) {
      const next = this.panel.querySelector(`#${focus.id}`);
      next?.focus({ preventScroll: true });
      try { next?.setSelectionRange(focus.start, focus.end); } catch { /* selects have no selection range */ }
    }
  }

  dailyControls() {
    return h('div', { class: 'wm-daily-controls' },
      h('div', {}, h('h3', {}, icon('clock', 17), 'Daily updates'),
        h('p', { class: 'small muted' }, this.nativeDaily ? 'Android schedules enabled built-in sources approximately every 24 hours when connected and battery is not low. Custom sources refresh while this view is open. OS power controls may delay work.' : 'Refresh enabled feeds once per day while this page is open, visible and online. Browsers cannot promise background updates after the page is closed.'),
        h('p', { class: 'small muted' }, this.store.lastDaily ? `Last visible-page daily attempt: ${dateLabel(this.store.lastDaily)}. Source cards show actual successful updates.` : 'No visible-page daily refresh has run yet.')),
      button(this.store.dailyRefresh ? 'Daily updates on' : 'Enable daily updates', () => this.action(async () => {
        await this.store.setDaily(!this.store.dailyRefresh); this.tick();
      }), { class: this.store.dailyRefresh ? 'primary' : '', id: 'world-daily', 'aria-pressed': String(this.store.dailyRefresh) }));
  }

  customSourceForm() {
    this.sourceDraft ||= { name: '', url: '', parser: 'generic', intervalHours: 24 };
    const draft = this.sourceDraft;
    const field = (label, key, type = 'text') => h('label', { class: 'wm-field' }, h('span', {}, label), h('input', { type, id: `world-custom-${key}`, required: true, maxlength: key === 'url' ? 2048 : 70, value: draft[key],
      oninput: (e) => { draft[key] = e.target.value; }, ...(type === 'number' ? { min: 1, max: 168 } : {}) }));
    return h('details', { class: 'wm-custom-source', open: this.customFormOpen, ontoggle: (e) => { this.customFormOpen = e.target.open; } },
      h('summary', {}, '+ Add a worldwide data feed'),
      h('p', { class: 'small muted' }, 'Extend your own catalogue with a public, keyless HTTPS JSON endpoint. It must support browser access (CORS) and one of the supported schemas. Saving a source does not fetch it. Up to 100 configured sources are supported; this is not a claim that every public endpoint is available.'),
      h('form', { id: 'world-custom-form', class: 'wm-custom-form', onsubmit: (e) => { e.preventDefault(); this.action(async () => {
        await this.store.addSource(draft); this.sourceDraft = { name: '', url: '', parser: 'generic', intervalHours: 24 }; this.renderSources(); this.say('Custom feed added. Use Refresh source to test it; it is not treated as a verified provider.', 'ok');
      }); } }, field('Feed name', 'name'), field('Public HTTPS endpoint', 'url'),
        select('world-custom-parser', 'Response format', CUSTOM_FORMATS, draft.parser, (v) => { draft.parser = v; }), field('Refresh interval (hours)', 'intervalHours', 'number'),
        h('button', { type: 'submit', class: 'primary', id: 'world-custom-add' }, 'Add feed')),
      h('details', {}, h('summary', {}, 'Generic GeoJSON schema'), h('pre', { class: 'wm-schema' }, JSON.stringify({ type: 'FeatureCollection', features: [{ type: 'Feature', id: 'provider-id', properties: { title: 'Event title', occurredAt: '2026-11-08T00:00:00Z', category: 'disaster', severity: 'info', url: 'https://example.org/report' }, geometry: null }] }, null, 2))));
  }

  buildWatches() {
    const field = (label, input) => h('label', { class: 'wm-field' }, h('span', {}, label), input);
    const name = h('input', { type: 'text', id: 'world-watch-name', required: true, maxlength: 60, placeholder: 'e.g. Philippines hazards' });
    const query = h('input', { type: 'text', id: 'world-watch-query', maxlength: 160, placeholder: 'All words must match (optional)', value: this.store.filters.query });
    const form = h('form', { id: 'world-watch-form', class: 'wm-watch-form', onsubmit: (e) => { e.preventDefault(); this.action(async () => {
      await this.store.addWatch({ label: name.value, query: query.value, region: form.querySelector('#world-watch-region').value, severity: form.querySelector('#world-watch-severity').value, category: form.querySelector('#world-watch-category').value });
      name.value = ''; this.say('Watch saved on this device. Matching received records appear in the inbox below.', 'ok');
    }); } },
      h('h3', {}, 'Follow what matters to you.'), h('p', { class: 'small muted' }, 'Watches match received records from the past 7 days. No background or emergency push alerts are sent.'),
      field('Watch name', name), field('Keywords', query),
      select('world-watch-region', 'Region', REGIONS.map((r) => [r.id, r.label]), this.store.filters.region, () => {}),
      select('world-watch-category', 'Layer', [['all', 'All layers'], ...CATEGORIES.map((c) => [c.id, c.label])], 'all', () => {}),
      select('world-watch-severity', 'Minimum priority', SEVERITIES.map((s) => [s, s.charAt(0).toUpperCase() + s.slice(1)]), 'high', () => {}),
      h('button', { type: 'submit', class: 'primary', id: 'world-watch-add' }, icon('plus'), 'Save watch'));
    const file = h('input', { type: 'file', accept: '.json,application/json', id: 'world-watch-import', 'aria-label': 'Import a World Monitor watchlist', onchange: (e) => this.action(async () => {
      const selected = e.target.files?.[0]; if (!selected) return;
      try {
        const watches = parseWatchImport(await readWatchFile(selected));
        if (this.store.watches.length && !confirm(`Replace your ${this.store.watches.length} existing watches with ${watches.length} imported watches?`)) return;
        await this.store.replaceWatches(watches); this.say(`${watches.length} watches imported. No provider requests were made.`, 'ok');
      } finally { e.target.value = ''; }
    }) });
    this.watchesList = h('div', { id: 'world-watch-list' }); this.inbox = h('div', { id: 'world-alert-inbox' });
    mount(this.panel, h('div', { class: 'wm-watch-grid' }, form, h('div', { class: 'wm-watch-right' }, h('div', { class: 'wm-feed-heading' }, h('h3', {}, 'Saved watches'),
      button([icon('download', 15), 'Export watches'], () => this.action(() => { this.download('omnishield-world-watches.json', JSON.stringify({ schema: 'omnishield-world-watches', version: 1, watches: this.store.watches }, null, 2)); }), { class: 'sm', id: 'world-watches-export' })), this.watchesList,
      h('details', { class: 'wm-import' }, h('summary', {}, 'Import watches from another device'), h('p', { class: 'small muted' }, 'JSON only, up to 128 KB and 30 watches. Imports replace watch rules, never your received events.'), file))), this.inbox);
    this.renderWatchesList();
  }
  renderWatchesList() {
    if (!this.watchesList?.isConnected) return;
    mount(this.watchesList, this.store.watches.length ? this.store.watches.map((w) => h('article', { class: 'wm-watch', 'data-watch-id': w.id },
      h('div', {}, h('strong', {}, w.label), h('p', { class: 'small muted' }, `${w.query || 'All keywords'} · ${REGIONS.find((r) => r.id === w.region)?.label} · ${w.category} · ${w.severity}+`)),
      h('div', { class: 'row' }, button(w.enabled ? 'Enabled' : 'Paused', () => this.store.toggleWatch(w.id), { class: 'sm', 'aria-pressed': String(w.enabled), 'aria-label': `Toggle ${w.label}` }), button('Remove', () => this.store.removeWatch(w.id), { class: 'sm ghost', 'aria-label': `Remove watch ${w.label}` }))))
      : emptyState('No watches yet.', 'Create a rule on the left. Keywords, region, layer and minimum priority all have to match.', 'bell'));
    const alerts = this.store.alerts;
    mount(this.inbox, h('div', { class: 'wm-feed-heading' }, h('div', {}, h('h3', {}, 'Alert inbox'), h('p', { class: 'small muted' }, `${alerts.filter((a) => !a.read).length} unread matches · up to 300 retained · newest first`)),
      button('Mark all read', () => this.store.acknowledge(), { class: 'sm', disabled: !alerts.some((a) => !a.read), id: 'world-alerts-read' })),
      alerts.length ? h('div', { class: 'wm-inbox-list' }, alerts.map((a) => h('article', { class: `wm-alert ${a.read ? 'read' : ''}` },
        h('span', { class: `wm-severity-dot ${a.event.severity}` }), h('div', {}, h('span', { class: 'small muted' }, a.watchName), button(a.event.title, () => this.openDetail(a.event), { class: 'wm-event-title' })),
        button(a.read ? 'Read' : 'Mark read', () => this.store.acknowledge(a.key), { disabled: a.read, class: 'sm' }))))
        : emptyState('No matching alerts.', 'An empty inbox does not mean there are no hazards. Watches can only match the enabled sources and records you have received.', 'bell'));
  }

  buildWeather() {
    const preset = select('world-weather-place', 'City preset', [...WEATHER_PLACES.map((p) => [p.id, p.name]), ['custom', 'Custom coordinates']], this.weatherPlace.id || 'custom', (id) => {
      const p = WEATHER_PLACES.find((x) => x.id === id);
      if (p) { this.weatherPlace = { ...p }; lat.value = p.lat; lon.value = p.lon; this.renderWeather(); }
    });
    const lat = h('input', { type: 'number', id: 'world-weather-lat', min: -90, max: 90, step: '0.01', required: true, value: this.weatherPlace.lat, 'aria-label': 'Weather latitude' });
    const lon = h('input', { type: 'number', id: 'world-weather-lon', min: -180, max: 180, step: '0.01', required: true, value: this.weatherPlace.lon, 'aria-label': 'Weather longitude' });
    const custom = () => { preset.querySelector('select').value = 'custom'; };
    lat.addEventListener('input', custom); lon.addEventListener('input', custom);
    this.weatherButton = h('button', { type: 'submit', class: 'primary', id: 'world-weather-load' }, icon('cloud'), 'Load weather & air');
    const form = h('form', { id: 'world-weather-form', class: 'wm-weather-form', onsubmit: (e) => { e.preventDefault(); this.action(async () => {
      if (this.weatherBusy || lat.value.trim() === '' || lon.value.trim() === '') return;
      const selected = WEATHER_PLACES.find((p) => p.id === preset.querySelector('select').value);
      this.weatherPlace = { name: selected?.name || 'Custom location', lat: Number(lat.value), lon: Number(lon.value) };
      this.weatherBusy = true; this.weatherButton.disabled = true; this.weatherButton.textContent = 'Loading…';
      for (const input of form.querySelectorAll('input, select')) input.disabled = true;
      try { await this.weather.lookup(this.weatherPlace); this.renderWeather(); }
      finally { this.weatherBusy = false; this.weatherButton.disabled = false; mount(this.weatherButton, icon('cloud'), 'Load weather & air'); for (const input of form.querySelectorAll('input, select')) input.disabled = false; }
    }); } }, h('h3', {}, 'Local weather. A wider perspective.'), h('p', { class: 'small muted' }, 'Choose a city or enter coordinates. Only these rounded coordinates are sent to Open-Meteo; GPS is never requested.'),
      h('div', { class: 'wm-weather-inputs' }, preset, h('label', { class: 'wm-field' }, h('span', {}, 'Latitude'), lat), h('label', { class: 'wm-field' }, h('span', {}, 'Longitude'), lon), this.weatherButton));
    this.weatherResult = h('div', { id: 'world-weather-result' });
    mount(this.panel, form, this.weatherResult,
      h('div', { class: 'wm-weather-attribution small muted' }, 'Modelled weather and air quality, not on-site sensor readings. Times are UTC. ', link('Open-Meteo (CC BY 4.0)', 'https://open-meteo.com/'), ' · ', link('CAMS / air-quality attribution', 'https://open-meteo.com/en/docs/air-quality-api'), ' · Public API for non-commercial use; provider limits apply.'));
    this.renderWeather();
  }
  renderWeather() {
    if (!this.weatherResult?.isConnected) return;
    let result; try { result = this.weather.get(this.weatherPlace); } catch { return; }
    if (!result) { mount(this.weatherResult, emptyState('Choose a place to begin.', 'Weather and air quality are loaded only when you ask. No current conditions have been received for this place.', 'cloud')); return; }
    const f = result.forecast; const a = result.air;
    const stale = this.store.clock() - result.fetchedAt > 3_600_000;
    const label = (cached, at) => `${result.cached || cached || stale ? 'CACHED · ' : 'RECEIVED · '}${relativeTime(at, this.store.clock())}`;
    const metric = (title, value) => h('div', {}, h('span', { class: 'small muted' }, title), h('strong', {}, value));
    mount(this.weatherResult,
      result.errors?.length ? note(result.errors.join(' '), 'warn') : null,
      this.weather.storageError ? note(this.weather.storageError, 'warn') : null,
      h('div', { class: 'wm-weather-grid' },
        h('article', { class: 'wm-weather-current' }, h('div', { class: 'wm-feed-heading' }, h('h3', {}, result.place.name), pill(label(result.forecastCached, result.forecastAt), result.cached || result.forecastCached || stale ? 'warn' : '')),
          f ? h('div', {}, h('div', { class: 'wm-temperature' }, icon('sun', 44), h('strong', {}, `${number(f.temperature, 1)}°`)), h('p', {}, weatherLabel(f.code)),
            h('div', { class: 'wm-weather-measures' }, metric('Wind', f.wind === null ? '—' : `${f.wind} km/h`), metric('Humidity', f.humidity === null ? '—' : `${f.humidity}%`), metric('Model time', `${new Date(f.at).toISOString().slice(11, 16)} UTC`)))
            : emptyState('Forecast unavailable', 'The forecast provider did not return usable conditions.', 'cloud')),
        h('article', { class: 'wm-air' }, h('div', { class: 'wm-feed-heading' }, h('h3', {}, 'Air quality'), pill(label(result.airCached, result.airAt), result.cached || result.airCached || stale ? 'warn' : '')),
          a ? h('div', {}, h('div', { class: 'wm-aqi' }, h('strong', {}, number(a.aqi)), h('span', {}, 'US AQI')), h('p', {}, airLabel(a.aqi)), h('p', { class: 'small muted' }, `PM2.5: ${a.pm25 ?? '—'} µg/m³ · ${new Date(a.at).toISOString().slice(11, 16)} UTC`), h('p', { class: 'wm-small-print' }, 'Model estimate. Follow local health guidance, especially for sensitive groups.'))
            : emptyState('Air quality unavailable', 'No AQI was returned for this location.', 'activity'))),
      f ? h('div', { class: 'wm-forecast' }, f.days.map((d) => h('article', {}, h('span', {}, d.date), icon(d.code === 0 ? 'sun' : 'cloud', 26), h('strong', {}, `${d.high ?? '—'}° / ${d.low ?? '—'}°`), h('small', {}, `${d.rain ?? '—'}% precipitation`)))) : null);
  }

  openDetail(event) {
    this.previousFocus = document.activeElement; this.selected = event;
    this.map.update(this.store.filtered(), event.id); this.renderDetail();
    if (!this.detail.open) { if (typeof this.detail.showModal === 'function') this.detail.showModal(); else this.detail.setAttribute('open', ''); }
    this.detail.querySelector('button')?.focus();
  }
  closeDetail() { if (typeof this.detail.close === 'function') this.detail.close(); else this.detail.removeAttribute('open'); this.previousFocus?.focus?.(); }
  trapDialog(e) {
    if (e.key === 'Escape') { e.preventDefault(); this.closeDetail(); return; }
    if (e.key !== 'Tab') return;
    const nodes = [...this.detail.querySelectorAll('button:not(:disabled), a[href], [tabindex="0"]')];
    const first = nodes[0]; const last = nodes[nodes.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last?.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first?.focus(); }
  }
  renderDetail() {
    if (!this.selected) return;
    const latest = this.store.events.find((e) => e.id === this.selected.id);
    const event = latest || this.selected; this.selected = event;
    const source = SOURCE_BY_ID.get(event.source); const state = this.store.health()[event.source];
    const saved = this.store.bookmarks.some((b) => b.id === event.id);
    const hadFocus = this.detail.contains(document.activeElement); const focusId = document.activeElement?.id;
    mount(this.detail,
      h('div', { class: 'wm-detail-top' }, h('span', { class: 'eyebrow' }, 'SOURCE RECORD / EVENT DETAILS'), button(icon('close'), () => this.closeDetail(), { 'aria-label': 'Close event details', class: 'ghost', id: 'world-detail-close' })),
      h('div', { class: 'row' }, pill(event.severity.toUpperCase(), severityClass(event.severity)), pill(latest ? state?.status.toUpperCase() : 'SAVED / EARLIER SNAPSHOT', latest ? statusClass(state?.status) : 'warn'), pill(category(event.category).label)),
      h('h2', {}, event.title), h('p', { class: 'wm-detail-summary' }, event.summary || 'The provider supplied no additional description.'),
      h('dl', { class: 'kv' }, h('dt', {}, 'Provider'), h('dd', {}, source?.name), h('dt', {}, 'Event / publication time'), h('dd', {}, `${dateLabel(event.occurredAt)} (your timezone)`),
        h('dt', {}, 'Source last received'), h('dd', {}, dateLabel(state?.lastSuccess)), h('dt', {}, 'Location'), h('dd', {}, event.location),
        h('dt', {}, 'Coordinates'), h('dd', {}, validCoordinates(event.lat, event.lon) ? `${event.lat.toFixed(3)}, ${event.lon.toFixed(3)} · ${event.geoBasis}` : 'Not supplied — no location is inferred'),
        h('dt', {}, 'Why this priority?'), h('dd', {}, event.severityBasis)),
      h('div', { class: 'wm-detail-tags row' }, event.tags.map((t) => pill(t))),
      h('div', { class: 'wm-detail-actions row' }, event.url ? link('Open original source ↗', event.url) : h('span', { class: 'small muted' }, 'No valid HTTPS source link supplied.'),
        button([icon('bookmark'), saved ? 'Remove bookmark' : 'Save event'], () => this.action(() => this.store.toggleBookmark(event)), { id: 'world-detail-save', 'aria-pressed': String(saved) }),
        button([icon('pin'), 'Locate on map'], () => { this.closeDetail(); this.map.focus(event); this.mapHost.scrollIntoView?.({ behavior: 'smooth', block: 'center' }); this.map.svg.focus(); }, { disabled: !validCoordinates(event.lat, event.lon), id: 'world-detail-locate' })),
      note('An advisory or report does not prove that your device or location is affected. Verify details with the original provider and follow local authorities for emergency instructions.'));
    if (hadFocus) (focusId && this.detail.querySelector(`#${focusId}`) || this.detail.querySelector('button'))?.focus();
  }

  export(format = this.exportFormat.value) {
    const events = this.tab === 'saved' ? this.store.bookmarks : this.store.filtered();
    const health = this.store.health(); const stamp = new Date(this.store.clock()).toISOString().slice(0, 10);
    const filters = this.tab === 'saved' ? { region: 'saved snapshots', range: 'all' } : this.store.filters;
    if (format === 'csv') this.download(`omnishield-world-${stamp}.csv`, exportCsv(events, this.tab === 'saved' ? {} : health), 'text/csv');
    else if (format === 'md') this.download(`omnishield-world-${stamp}.md`, buildBriefing(events, health, filters, this.store.clock()), 'text/markdown');
    else this.download(`omnishield-world-${stamp}.json`, JSON.stringify({ schema: 'omnishield-world-events', version: 1, generatedAt: new Date(this.store.clock()).toISOString(), scope: this.tab === 'saved' ? 'saved snapshots' : 'filtered received records', filters, sources: health, events, note: 'Source coverage is partial. This export is a snapshot, not an emergency warning or prediction.' }, null, 2), 'application/json');
    this.say(`Export prepared: ${events.length} ${this.tab === 'saved' ? 'saved' : 'filtered'} records.`, 'ok');
  }
}
