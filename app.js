/**
 * OmniShield X — application controller (AETHER AI Evolution, v5).
 *
 * Everything here runs in the browser with no backend. Modules:
 *   engine.js                  deterministic filter ladder (the only thing that blocks)
 *   dns/                       DoH/DoT transports, DNSSEC assessment, cache, pipeline
 *   aether/                    reputation scoring, lexical model, typosquat detection
 *   security/                  firewall AI, monitor, feeds, backup, privacy analytics
 *   ui/dom.js                  safe DOM helpers (textContent only — no innerHTML)
 */
import { OmniShieldFilterEngine } from './engine.js';
import { DnsClient } from './dns/client.js';
import { RESOLVERS, DotTransport } from './dns/resolvers.js';
import { auditChain } from './dns/chain.js';
import { Aether } from './aether/index.js';
import { DomainClassifier } from './aether/classifier.js';
import { SIGNAL_WEIGHTS, EVIDENCE_FLOORS } from './aether/reputation.js';
import { SecurityMonitor } from './security/monitor.js';
import { FirewallAI, DEFAULT_CONFIG as FW_CONFIG } from './security/firewall-ai.js';
import { FeedManager, FEED_REGISTRY } from './security/feedmanager.js';
import { BackupManager, SCHEMA_VERSION } from './security/backup.js';
import { PrivateAnalytics } from './security/privacy.js';
import { PowerGovernor } from './security/power.js';
import { createStorage, IndexedDbAdapter, MAX_FILE_BYTES, MAX_FILE_LABEL } from './security/storage.js';
import { FileVault, setDefaultSinkVault } from './security/vault.js';
import { SystemScanner, scanUrl } from './security/scan.js';
import { DownloadQueue, parseMediaUrl, probeMedia, inspectRemote } from './security/media.js';
import { PROVIDERS as SEARCH_PROVIDERS, buildSearchUrl, stripTracking, openExternal as openSearch, instantAnswer, sanitizeQuery, resolveBang, providerById as searchProvider, SearchHistory } from './security/search.js';
import * as ui from './ui/dom.js';
import { h, mount, pill, note, empty, kpi, table, kv, number, plural, bytes, relativeTime, drawSeries, toast, download, setBusy } from './ui/dom.js';

const BUNDLED = {
  lite: { file: 'assets/core_lite_ads.txt', category: 'ADS', source: 'core_lite_ads', label: 'HaGeZi Multi LIGHT (bundled)' },
  supplement: { file: 'assets/core_supplement_ads.txt', category: 'ADS', source: 'core_supplement_ads', label: 'Curated apex supplement (bundled)' },
  aggressive: { file: 'assets/core_supplement_aggressive.txt', category: 'ADS', source: 'core_supplement_aggressive', label: 'Aggressive tier (optional, disabled)' }
};

const state = {
  storage: null,
  engine: null,
  aether: null,
  client: null,
  monitor: null,
  firewall: null,
  feeds: null,
  backups: null,
  analytics: null,
  settings: { aggressiveTier: false, autoUpdateFeeds: true, monitorRefreshMs: 1000 },
  lastBenchmark: null,
  benchmarkRunning: false,
  power: null,
  powerInfo: null,
  customRules: [],
  importedBackup: null,
  booted: false,
  training: false,
  trainingError: null,
  bundled: {},
  snapshotTimer: null,
  lastSnapshotId: null,
  currentPage: 'dashboard',
  // v5.1 additions: on-device vault, system scanner, private search, downloader.
  vault: null,
  scanner: null,
  downloads: null,
  searchHistory: null,
  scanFiles: [],
  scanRun: null,
  scanTrace: [],
  vaultView: { folder: '/', kind: null, query: '' },
  search: { provider: 'duckduckgo', kind: 'web', lastQuery: '', lastUrl: null },
  mediaDraft: null,
  mediaTimer: null,
  vaultUrl: null
};

/* ------------------------------------------------------------------ */
/* Boot                                                                */
/* ------------------------------------------------------------------ */

function setBootStatus(text, cls = 'info') {
  const el = document.getElementById('boot-status');
  if (!el) return;
  ui.clear(el);
  el.className = `pill ${cls}`;
  el.appendChild(h('span', { class: 'dot' }));
  el.appendChild(document.createTextNode(` ${text}`));
}

async function fetchText(url) {
  const response = await fetch(url, { cache: 'no-cache' });
  if (!response.ok) throw new Error(`HTTP ${response.status} for ${url}`);
  return response.text();
}

async function boot() {
  try {
    state.storage = createStorage('omnishield-x');
    state.monitor = new SecurityMonitor();
    state.analytics = new PrivateAnalytics({ storage: state.storage });
    await state.analytics.load();
    state.feeds = new FeedManager({ storage: state.storage, onEvent: (e) => { if (e.ok === false) console.debug('[feeds]', e.reason, e.detail); } });
    state.backups = new BackupManager({ storage: state.storage, maxSnapshots: 4 });

    state.vault = new FileVault({ storage: state.storage });
    await state.vault.load();
    setDefaultSinkVault(state.vault);
    state.scanner = new SystemScanner({ vault: state.vault });
    state.downloads = new DownloadQueue({
      onUpdate: () => { if (state.currentPage === 'media') renderMediaTransfers(); }
    });
    state.searchHistory = await new SearchHistory({ storage: state.storage }).load();
    await restoreDownloadHistory();
    try {
      const savedProvider = await state.storage.getItem('search:provider');
      if (savedProvider && SEARCH_PROVIDERS.some((provider) => provider.id === savedProvider)) state.search.provider = savedProvider;
    } catch { /* the default provider is fine if the preference cannot be read */ }

    setBootStatus('loading rule sets…', 'info');
    state.engine = new OmniShieldFilterEngine();
    await loadBundledRules();

    state.aether = new Aether({ engine: state.engine });
    state.client = new DnsClient({ engine: state.engine, onObservation: handleObservation });
    state.firewall = new FirewallAI({ onEvent: (event) => {
      if (event.decision === 'block') toast(`Firewall AI blocked ${event.domain}: ${event.reasons[0] || ''}`, 'warn');
    } });

    await restoreConfiguration();
    applyUserRules();
    await loadCachedModel();

    state.booted = true;
    setBootStatus(`ready · ${number(state.engine.totalRules())} rules`, 'ok');
    updateNetworkStatus();
    renderAll();

    // Train the lexical model after first paint so the UI never blocks.
    setTimeout(() => { ensureModel().catch((err) => { state.trainingError = err.message; }); }, 300);
    registerServiceWorker();
    // The governor starts the monitor loop itself, with the interval it derives
    // from device power state — calling startMonitorLoop() separately here would
    // briefly install an untrottled timer and then replace it.
    startPowerGovernor();
    updateOnlineStatus();
    window.addEventListener('online', updateOnlineStatus);
    window.addEventListener('offline', updateOnlineStatus);
    window.addEventListener('pagehide', () => { saveSnapshot('pagehide').catch(() => {}); });
  } catch (err) {
    console.error(err);
    setBootStatus('boot failed', 'bad');
    mount('#dash-kpis', note(`Startup failed: ${err.message}. If you opened this file directly (file://), run it over HTTP (e.g. "npm run serve") — browsers block module and asset loading from file://.`, 'bad'));
  }
}

async function loadBundledRules() {
  for (const key of ['lite', 'supplement']) {
    const descriptor = BUNDLED[key];
    try {
      const text = await fetchText(descriptor.file);
      const result = state.engine.loadFilterList(text, descriptor.category, descriptor.source);
      state.bundled[descriptor.source] = { ...result, label: descriptor.label, bytes: text.length };
    } catch (err) {
      state.bundled[descriptor.source] = { error: err.message, label: descriptor.label };
    }
  }
  if (state.settings.aggressiveTier) await enableAggressiveTier(true);
}

async function enableAggressiveTier(enable) {
  const descriptor = BUNDLED.aggressive;
  if (enable) {
    try {
      const text = await fetchText(descriptor.file);
      state.engine.loadFilterList(text, descriptor.category, descriptor.source);
      state.settings.aggressiveTier = true;
    } catch (err) {
      toast(`Could not load the aggressive tier: ${err.message}`, 'bad');
      return false;
    }
  } else {
    // Rebuild the engine without the aggressive source.
    state.settings.aggressiveTier = false;
    await rebuildEngine();
  }
  scheduleSnapshot('aggressive-tier');
  renderAll();
  return true;
}

async function rebuildEngine() {
  const engine = new OmniShieldFilterEngine();
  for (const key of ['lite', 'supplement']) {
    try {
      const text = await fetchText(BUNDLED[key].file);
      engine.loadFilterList(text, BUNDLED[key].category, BUNDLED[key].source);
    } catch { /* keep going with whatever loads */ }
  }
  if (state.settings.aggressiveTier) {
    try { engine.loadFilterList(await fetchText(BUNDLED.aggressive.file), 'ADS', BUNDLED.aggressive.source); } catch { /* ignore */ }
  }
  state.customRules.forEach((rule) => engine.addUserRule(rule.pattern, rule.isAllow));
  state.engine = engine;
  state.aether.attachEngine(engine);
  state.client.setEngine(engine);
}

function handleObservation(event) {
  const domain = event.name;
  if (!domain) return;
  if (event.kind === 'blocked') {
    const category = event.blockedBy?.category || 'UNCATEGORISED';
    state.monitor.record({ kind: 'blocked', domain, category, latencyMs: event.latencyMs, at: event.at });
    state.analytics.record({ kind: 'blocked', category, domain, at: event.at });
    state.aether.observe(domain, { blocked: true, at: event.at });
    state.firewall.observe({ domain, app: 'browser', at: event.at });
    return;
  }
  state.monitor.record({ kind: 'lookup', domain, status: event.status, latencyMs: event.latencyMs, at: event.at });
  state.analytics.record({ kind: event.ok ? 'allowed' : 'error', category: 'DNS', domain, at: event.at });
  if (event.ok) {
    state.aether.observe(domain, { blocked: false, at: event.at });
    state.firewall.observe({ domain, app: 'browser', at: event.at });
  }
}

/* ------------------------------------------------------------------ */
/* Configuration persistence                                           */
/* ------------------------------------------------------------------ */

function buildState({ includeModel = false } = {}) {
  const aetherState = state.aether ? state.aether.exportState() : null;
  if (aetherState) {
    if (!includeModel) delete aetherState.classifier;
    aetherState.observations = (aetherState.observations || []).slice(-500);
  }
  return {
    schemaVersion: SCHEMA_VERSION,
    appVersion: '5.1.0',
    savedAt: new Date().toISOString(),
    settings: { ...state.settings },
    customRules: state.customRules.map((r) => ({ pattern: r.pattern, isAllow: r.isAllow, rawPattern: r.pattern, ruleType: r.isAllow ? 'ALLOW' : 'BLOCK', matchType: 'SUFFIX', isEnabled: true })),
    aether: aetherState,
    firewall: state.firewall ? { policies: state.firewall.snapshot().policies, config: state.firewall.config } : null,
    // Android backup fields are preserved verbatim when a backup was imported.
    protectionMode: state.importedBackup?.protectionMode ?? 'BALANCED',
    browserSiteExceptions: state.importedBackup?.browserSiteExceptions ?? [],
    excludedAppPackages: state.importedBackup?.excludedAppPackages ?? []
  };
}

function applyUserRules() {
  for (const rule of state.customRules) state.engine.addUserRule(rule.pattern, rule.isAllow);
}

async function restoreConfiguration() {
  const recovery = await state.backups.recover();
  if (recovery.ok) {
    const saved = recovery.state || {};
    if (saved.settings) state.settings = { ...state.settings, ...saved.settings };
    if (Array.isArray(saved.customRules)) {
      state.customRules = saved.customRules
        .map((r) => ({
          pattern: String(r.pattern ?? r.rawPattern ?? ''),
          isAllow: r.isAllow ?? r.ruleType === 'ALLOW'
        }))
        .filter((r) => r.pattern);
    }
    if (saved.aether && state.aether) state.aether.importState(saved.aether);
    if (saved.firewall?.policies && state.firewall) {
      for (const policy of saved.firewall.policies) {
        for (const d of policy.deny || []) state.firewall.setPolicy(policy.app, d, 'block');
        for (const d of policy.allow || []) state.firewall.setPolicy(policy.app, d, 'allow');
      }
    }
    state.lastSnapshotId = recovery.id;
    if (recovery.skipped.length) {
      toast(`Recovered configuration ${recovery.id}, skipped ${recovery.skipped.length} corrupt snapshot(s).`, 'warn');
    }
  } else if (recovery.reason !== 'no-snapshots') {
    toast(`Configuration recovery: ${recovery.reason}. Starting from safe defaults.`, 'warn');
  }
}

function scheduleSnapshot(reason = 'change') {
  clearTimeout(state.snapshotTimer);
  state.snapshotTimer = setTimeout(() => saveSnapshot(reason).catch(() => {}), 1200);
}

async function saveSnapshot(reason = 'manual', { silent = true } = {}) {
  if (!state.booted && reason !== 'manual') return null;
  try {
    const saved = await state.backups.save(buildState(), { reason });
    state.lastSnapshotId = saved.id;
    if (!silent) toast('Configuration snapshot saved.', 'ok');
    renderSnapshots();
    return saved;
  } catch (err) {
    // Quota problems are common: prune the oldest snapshot and try once more.
    try {
      const list = await state.backups.list();
      if (list.length > 1) {
        await state.backups.remove(list[list.length - 1].id);
        const retry = await state.backups.save(buildState(), { reason });
        state.lastSnapshotId = retry.id;
        if (!silent) toast('Saved after pruning the oldest snapshot (storage was full).', 'warn');
        renderSnapshots();
        return retry;
      }
    } catch { /* fall through */ }
    if (!silent) toast(`Snapshot failed: ${err.message}`, 'bad');
    return null;
  }
}

async function loadCachedModel() {
  try {
    const raw = await state.storage.getItem('aether:model');
    if (!raw) return false;
    const classifier = DomainClassifier.fromJSON(JSON.parse(raw));
    if (!classifier) return false;
    setClassifier(classifier);
    return true;
  } catch { return false; }
}

function setClassifier(classifier) {
  state.aether.classifier = classifier;
  state.aether.reputation.setClassifier(classifier);
}

async function ensureModel(force = false) {
  if (state.training) return;
  if (!force && state.aether.classifier.isTrained) return;
  state.training = true;
  renderAetherModel();
  try {
    await new Promise((resolve) => setTimeout(resolve, 20));
    const metrics = state.aether.train();
    try {
      await state.storage.setItem('aether:model', JSON.stringify(state.aether.classifier.toJSON()));
    } catch { toast('Model trained but could not be cached (storage full). It will retrain next visit.', 'warn'); }
    state.trainingError = null;
    toast(`AETHER model trained: AUC ${metrics.auc}, precision ${metrics.atThreshold.precision} at the operating point.`, 'ok');
  } catch (err) {
    state.trainingError = err.message;
    toast(`Model training failed: ${err.message}`, 'bad');
  } finally {
    state.training = false;
    renderAetherModel();
    renderDashboard();
  }
}

/* ------------------------------------------------------------------ */
/* Router                                                              */
/* ------------------------------------------------------------------ */

const PAGE_RENDERERS = {
  dashboard: renderDashboard,
  aether: renderAether,
  dns: renderDns,
  firewall: renderFirewall,
  monitor: renderMonitor,
  feeds: renderFeeds,
  privacy: renderPrivacy,
  sync: renderSync,
  scan: renderScan,
  search: renderSearch,
  vault: renderVault,
  media: renderMedia,
  extension: renderExtension,
  status: renderStatus
};

function navigate(page) {
  const focusOnNavigate = state.booted && state.currentPage !== page;
  state.currentPage = page;
  for (const section of document.querySelectorAll('.page')) section.hidden = section.id !== `page-${page}`;
  for (const button of document.querySelectorAll('nav.tabs button')) {
    const active = button.dataset.page === page;
    button.classList.toggle('active', active);
    // Screen readers need to know which section is showing; the CSS class alone
    // conveys nothing to assistive technology.
    if (active) button.setAttribute('aria-current', 'page');
    else button.removeAttribute('aria-current');
  }
  const section = document.getElementById(`page-${page}`);
  if (section) {
    section.setAttribute('aria-current', 'true');
    // Move focus to the new page so keyboard and screen-reader users are not
    // left behind on the tab they just pressed.
    if (focusOnNavigate) {
      try { section.focus({ preventScroll: true }); } catch { section.focus(); }
    }
  }
  for (const other of document.querySelectorAll('.page')) {
    if (other !== section) other.removeAttribute('aria-current');
  }
  let rendered = Promise.resolve();
  try {
    // Renderers may be async (they read shipped artifacts); a rejection must be
    // reported, never left as an unhandled promise. The promise is returned so a
    // caller can await a fully painted page instead of racing it.
    rendered = Promise.resolve(PAGE_RENDERERS[page]?.()).catch((err) => {
      console.error(err);
      toast(`Render error on ${page}: ${err.message}`, 'bad');
    });
  } catch (err) { console.error(err); toast(`Render error on ${page}: ${err.message}`, 'bad'); }
  if (location.hash !== `#${page}`) history.replaceState(null, '', `#${page}`);
  return rendered;
}

function renderAll() {
  for (const render of Object.values(PAGE_RENDERERS)) {
    try { Promise.resolve(render()).catch((err) => console.error('render failed', err)); } catch (err) { console.error('render failed', err); }
  }
}

document.querySelectorAll('nav.tabs button').forEach((button) => {
  button.addEventListener('click', () => navigate(button.dataset.page));
});

/* ------------------------------------------------------------------ */
/* Dashboard                                                           */
/* ------------------------------------------------------------------ */

function renderDashboard() {
  if (!state.engine) return;
  const breakdown = state.engine.breakdown();
  const metrics = state.monitor.metrics();
  const clf = state.aether.classifier;
  const observations = state.aether.observations.size;

  mount('#dash-kpis',
    kpi(number(breakdown.total), 'block rules active in this browser'),
    kpi(number(breakdown.blockDomains), 'filtered domains'),
    kpi(number(breakdown.safetyEntries), 'safety allowlist entries (never blocked)'),
    kpi(clf.isTrained ? clf.metrics.auc.toFixed(3) : '—', 'AETHER model AUC (held-out)', clf.isTrained ? 'ok' : 'warn')
  );

  mount('#dash-aether',
    h('h2', {}, 'AETHER status', pill(clf.isTrained ? 'model active' : 'warming up', clf.isTrained ? 'ok' : 'warn')),
    h('p', { text: clf.isTrained
      ? 'Threat intelligence is live: feed matching, typosquat detection and a calibrated lexical model. Every verdict is explainable and reversible.'
      : 'Feed matching and heuristics are live. The lexical model is training in the background; it is only ever one small signal and never decides alone.' }),
    kv([
      ['Rules loaded', `${number(breakdown.total)} (${Object.entries(breakdown.sources).map(([s, n]) => `${s}: ${number(n)}`).join(' · ')})`],
      ['Signals weighted', Object.entries(SIGNAL_WEIGHTS).map(([id, w]) => `${id} ${w}`).join(' · ')],
      ['Evidence floors', Object.values(EVIDENCE_FLOORS).map((f) => `≥${f.score}`).join(' · ')],
      ['Domains observed', number(observations)],
      ['False positives reported', number(state.aether.stats.falsePositivesReported)],
      ['Model training', clf.isTrained ? `${clf.metrics.trainMs} ms on ${number(clf.metrics.trainSize)} samples · holdout ${number(clf.metrics.holdoutSize)}` : (state.training ? 'running…' : 'not yet trained')]
    ])
  );

  const power = state.powerInfo || state.power?.describe() || null;
  mount('#dash-resources',
    h('h2', { text: 'CPU, memory & battery' }),
    kv([
      ['Repaint cadence', `${state.monitorIntervalMs || state.settings.monitorRefreshMs} ms while a live view is open · 0 ms when the tab is hidden`],
      ['Power state', power ? power.summary : 'starting…'],
      ['Throttle', power && power.factor > 1 ? `${power.factor}x (band: ${power.band})` : 'none — default cadence'],
      ['Rule set memory', `${bytes(estimateRuleMemory(breakdown.total))} (estimate: ${Math.round((estimateRuleMemory(breakdown.total) / breakdown.total))} bytes per rule)`],
      ['Analysis cost', clf.isTrained ? 'model trained once per visit; no retraining loop' : 'training once, in the background']
    ]),
    h('div', { class: 'row', style: { marginTop: '10px' } },
      h('button', {
        class: 'sm',
        text: state.benchmarkRunning ? 'Measuring…' : 'Measure filtering cost',
        disabled: state.benchmarkRunning,
        onclick: () => {
          if (state.benchmarkRunning) return;
          state.benchmarkRunning = true;
          renderDashboard();
          // Yield once so the busy state paints before the loop blocks the thread.
          setTimeout(() => {
            let result = null;
            try { result = runEngineBenchmark(); } catch (err) { result = { ok: false, reason: err.message }; }
            state.lastBenchmark = result;
            state.benchmarkRunning = false;
            // The dashboard repaints every second; render from state so a measured
            // result survives the next tick instead of vanishing.
            renderBenchmark(result);
            renderDashboard();
          }, 20);
        }
      }),
      h('span', { class: 'tiny muted', text: 'Runs 5,000 real evaluations on this device' })
    ),
    h('div', { id: 'dash-bench', style: { marginTop: '8px' } }),
    h('p', { class: 'small muted', style: { marginTop: '8px' }, text: 'The monitor loop is the only recurring timer in this app. It is skipped entirely in a hidden tab and slowed on low battery when the browser exposes battery state. Nothing here affects what is filtered.' })
  );

  renderBenchmark(state.lastBenchmark);

  const categories = breakdown.categories || {};
  const maxCategory = Math.max(1, ...Object.values(categories));
  mount('#dash-protection',
    h('h2', { text: 'Protection by category' }),
    Object.keys(categories).length
      ? h('div', { class: 'bars' }, Object.entries(categories).sort((a, b) => b[1] - a[1]).map(([cat, count]) => h('div', { class: 'bar-row' },
        h('span', { text: cat }),
        h('div', { class: 'bar-track' }, h('div', { class: 'bar-fill', style: { width: `${(count / maxCategory) * 100}%` } })),
        h('span', { class: 'mono', text: number(count) })
      )))
      : empty('No rules loaded.'),
    h('p', { class: 'small muted', style: { marginTop: '10px' }, text: 'Category counts come from the loaded feeds, not from a marketing claim. Blocking only happens when a real rule matches.' })
  );

  mount('#dash-activity',
    h('h2', { text: 'This session' }),
    kv([
      ['Requests processed', number(metrics.lookups)],
      ['Blocked before leaving device', number(metrics.blocked)],
      ['Resolved', number(state.client.stats.network)],
      ['Cache hits', number(state.client.stats.cached)],
      ['DNS errors', number(state.client.stats.errors)],
      ['Median latency', metrics.latency.p50 === null ? '—' : `${metrics.latency.p50} ms`]
    ]),
    h('p', { class: 'small muted', style: { marginTop: '8px' }, text: metrics.lookups === 0
      ? 'No activity yet. Try the DNS Lab or AETHER to generate real measurements.'
      : 'Measured on this device. Nothing is estimated.' })
  );

  const feedRows = Object.entries(state.bundled).map(([source, info]) => [
    source,
    info.error ? pill('failed', 'bad') : pill('loaded', 'ok'),
    info.error ? info.error : number(info.added),
    info.error ? '—' : number(info.duplicates)
  ]);
  mount('#dash-integrity',
    h('h2', { text: 'Data integrity & recovery' }),
    table(['Source', 'State', 'Rules added', 'Duplicates skipped'], feedRows),
    h('div', { class: 'row', style: { marginTop: '12px' } },
      pill(state.lastSnapshotId ? `snapshot ${state.lastSnapshotId}` : 'no snapshot yet', state.lastSnapshotId ? 'ok' : 'warn'),
      pill(state.storage?.constructor?.name || 'storage', 'info'),
      pill('analytics: local only', 'info')
    )
  );
}

/* ------------------------------------------------------------------ */
/* AETHER page                                                         */
/* ------------------------------------------------------------------ */

function renderAether() {
  renderAetherModel();
  renderAetherFeedback();
}

function scoreColor(score) {
  if (score >= 70) return 'var(--red)';
  if (score >= 45) return 'var(--amber)';
  if (score >= 20) return 'var(--purple)';
  return 'var(--ok)';
}

function verdictPillClass(verdict) {
  if (verdict === 'high-confidence' || verdict === 'likely-malicious') return 'bad';
  if (verdict === 'suspicious') return 'warn';
  if (verdict === 'watch') return 'purple';
  return 'ok';
}

function analyseDomain(input) {
  const out = document.getElementById('aether-result');
  const domain = String(input || '').trim();
  if (!domain) { mount(out, note('Enter a hostname first.', 'warn')); return; }
  let report;
  try {
    report = state.aether.analyze(domain);
  } catch (err) {
    mount(out, note(`Analysis failed: ${err.message}`, 'bad'));
    return;
  }
  if (report.error === 'invalid-domain') {
    mount(out, note(report.summary, 'warn'));
    return;
  }

  const signalNodes = report.signals.length
    ? report.signals.sort((a, b) => b.contribution - a.contribution).map((signal) => h('div', { class: 'signal' },
      h('header', {},
        h('h4', { text: signal.label }),
        h('span', { class: `pill ${signal.contribution >= 15 ? 'bad' : signal.contribution > 0 ? 'warn' : ''}` },
          `${plural(signal.contribution, 'point')} · weight ${signal.weight}/${signal.baseWeight}${signal.weightMultiplier < 1 ? ` ×${signal.weightMultiplier}` : ''}`)
      ),
      h('p', { class: 'evidence', text: signal.evidence }),
      signal.contributions?.length
        ? h('p', { class: 'tiny mono', text: `deciding tokens (log-odds): ${signal.contributions.map((c) => `${c.token} (${c.weight > 0 ? '+' : ''}${c.weight})`).join(', ')}` })
        : null
    ))
    : [empty('No signal produced evidence for this hostname. That is not proof of safety — it only means nothing we can see matched.')];

  const guardrailNodes = report.guardrails.map((g) => note(`${g.label}: ${g.detail}`, 'ok'));
  const floorNodes = (report.floors || []).map((f) => note(`Evidence floor ${f.score}/100 — ${f.reason}`, 'warn'));

  const filterVerdict = report.filterVerdict;
  const blocked = filterVerdict.blocked;

  mount(out,
    h('div', { class: 'verdict ' + (blocked ? 'blocked' : 'allowed') },
      h('div', { class: 'gauge' },
        h('div', { class: 'gauge-ring', style: { '--v': String(report.score), '--c': scoreColor(report.score) } },
          h('span', {}, String(report.score), h('small', { text: 'of 100' }))),
        h('div', { style: { flex: '1 1 240px' } },
          h('h3', { text: report.domain }),
          h('div', { class: 'row', style: { marginTop: '4px' } },
            pill(report.verdictLabel, verdictPillClass(report.verdict)),
            pill(blocked ? `filtered by ${filterVerdict.source}` : 'allowed by filter', blocked ? 'bad' : 'ok'),
            report.capped ? pill('guardrail capped', 'info') : null
          ),
          h('p', { style: { marginTop: '8px' }, text: report.summary })
        )
      ),
      h('ul', {}, (report.filterVerdict.reasons || []).map((reason) => h('li', { text: reason })))
    ),
    guardrailNodes.length ? h('div', { style: { marginTop: '12px' }, class: 'grid' }, guardrailNodes) : null,
    floorNodes.length ? h('div', { style: { marginTop: '12px' }, class: 'grid' }, floorNodes) : null,
    h('h3', { text: `Evidence (${report.signals.length} signal${report.signals.length === 1 ? '' : 's'})` }),
    ...signalNodes,
    h('h3', { text: 'Actions' }),
    h('div', { class: 'row' },
      h('button', {
        class: 'primary sm',
        text: blocked ? 'Allow this domain' : 'Block this domain',
        onclick: () => toggleDomainRule(report.domain, blocked)
      }),
      h('button', {
        class: 'sm',
        text: 'Report false positive',
        disabled: !blocked,
        onclick: () => reportFalsePositive(report.domain)
      }),
      h('button', { class: 'sm ghost', text: 'Re-analyse', onclick: () => analyseDomain(report.domain) })
    ),
    note('AETHER scores are advisory evidence, not enforcement. Blocking happens only through filter rules — yours or the feed\'s — and can be undone at any time.', 'ok')
  );
}

function toggleDomainRule(domain, currentlyBlocked) {
  if (currentlyBlocked) {
    state.customRules = state.customRules.filter((r) => !(r.pattern === domain && r.isAllow));
    state.customRules.push({ pattern: domain, isAllow: true });
    state.engine.addUserRule(`||${domain}^`, true);
    toast(`${domain} added to your allowlist.`, 'ok');
  } else {
    state.customRules = state.customRules.filter((r) => !(r.pattern === domain && !r.isAllow));
    state.customRules.push({ pattern: domain, isAllow: false });
    state.engine.addUserRule(`||${domain}^`, false);
    toast(`${domain} blocked by your rule.`, 'ok');
  }
  state.aether.reputation.cache.clear();
  scheduleSnapshot('custom-rule');
  analyseDomain(domain);
  renderSync();
  renderDashboard();
}

function reportFalsePositive(domain) {
  const result = state.aether.reportFalsePositive(domain);
  if (!result.ok) { toast(result.error || 'Could not record the report.', 'bad'); return; }
  state.customRules = state.customRules.filter((r) => r.pattern !== domain);
  state.customRules.push({ pattern: domain, isAllow: true });
  toast(result.note, 'ok');
  scheduleSnapshot('false-positive');
  analyseDomain(domain);
  renderAetherFeedback();
  renderSync();
}

function renderAetherModel() {
  const node = document.getElementById('aether-model');
  if (!node) return;
  const clf = state.aether?.classifier;
  if (!clf) { mount(node, h('h2', { text: 'Lexical model' }), empty('Engine not ready.')); return; }
  if (!clf.isTrained) {
    mount(node,
      h('h2', {}, 'Lexical model', pill(state.training ? 'training…' : 'not trained', 'warn')),
      h('p', { text: 'A multinomial Naive Bayes classifier over character n-grams, trained on this device from the bundled feeds. '
        + 'It is deliberately a small signal (weight 7/100) because lexical style alone cannot prove malice.' }),
      h('div', { class: 'row' },
        h('button', { class: 'primary sm', text: state.training ? 'Training…' : 'Train model now', disabled: state.training, onclick: () => ensureModel(true) })
      ),
      state.trainingError ? note(`Training error: ${state.trainingError}`, 'bad') : null
    );
    return;
  }
  const m = clf.metrics;
  const at = m.atThreshold || {};
  mount(node,
    h('h2', {}, 'Lexical model', pill(`AUC ${m.auc}`, m.auc >= 0.85 ? 'ok' : 'warn'), pill(`threshold ${m.operatingThreshold}`, 'info')),
    table(['Metric', 'Held-out value', 'Meaning'], [
      ["AUC (ROC)", String(m.auc), 'Ranking quality across all thresholds; 0.5 is random'],
      ['Operating threshold', String(m.operatingThreshold), m.atThreshold?.unreachable
        ? `Target specificity ${m.targetSpecificity} was not reached out-of-sample (holdout ${m.atThreshold.specificity}); the tuning split chose the conservative maximum`
        : `Chosen on the tuning split for specificity ≥ ${m.targetSpecificity}`],
      ['Precision at operating point', String(at.precision ?? '—'), 'Of domains it flags, how many were truly in the ad/threat corpus'],
      ['Recall at operating point', String(at.recall ?? '—'), 'Of ad/threat domains, how many it flags'],
      ['Specificity at operating point', String(at.specificity ?? '—'), 'Of legitimate domains, how many stay below the threshold'],
      ['Balanced accuracy', String(at.balancedAccuracy ?? '—'), 'Mean of recall and specificity — immune to the corpus ratio'],
      ['Precision at 1% base rate', String(at.precisionAtPrevalence?.[0.01] ?? '—'), 'If 1 in 100 domains were malicious, this is the chance a flagged domain really is'],
      ['Precision at 10% base rate', String(at.precisionAtPrevalence?.[0.1] ?? '—'), 'Same conversion at a threat-heavy base rate'],
      ['Best F1 (sweep)', String(m.bestF1), `At threshold ${m.bestThreshold} — reference only; F1 flatters a positive-heavy corpus, so it is not used`],
      ['Fit / tuning / holdout', `${number(m.fitSize ?? m.trainSize)} / ${number(m.tuneSize ?? m.tuningSize)} / ${number(m.holdoutSize)}`, 'Three-way split: threshold is tuned on the middle split, reported on the holdout'],
      ['Vocabulary', number(m.vocabSize), 'Character n-gram and word tokens'],
      ['Training time', `${m.trainMs} ms`, `On this device at ${new Date().toLocaleTimeString()}`]
    ]),
    h('div', { class: 'row', style: { marginTop: '10px' } },
      h('button', { class: 'sm', text: state.training ? 'Training…' : 'Retrain on current feeds', disabled: state.training, onclick: () => ensureModel(true) }),
      pill(m.binary ? 'presence features' : 'count features', 'info'),
      pill(m.featureMode, 'info')
    ),
    (m.atThreshold?.unreachable ? note(`Calibration note: ${m.atThreshold.reason || `the ${m.targetSpecificity} specificity target was not reached out-of-sample`}. Measured holdout specificity is ${m.atThreshold.specificity} and recall ${m.atThreshold.recall} at threshold ${m.operatingThreshold}. The model's weight stays at 7/100 regardless.`, 'warn') : null),
    note(`Honest limitation: the model only sees the characters of a hostname. It cannot see page content, certificates, WHOIS, or traffic. `
      + `Measured on this device, ${m.atThreshold?.fp ?? '—'} of ${m.atThreshold?.negatives ?? '—'} held-out legitimate domains were flagged — which is why its weight is 7/100 and why known-popular domains are hard-capped by a guardrail.`, 'warn')
  );
}

function renderAetherFeedback() {
  const node = document.getElementById('aether-feedback');
  if (!node) return;
  const snapshot = state.aether.reputation.statsSnapshot();
  const adapted = Object.entries(snapshot.feedback).filter(([, v]) => v.falsePositives + v.confirmations > 0);
  mount(node,
    h('h2', { text: 'Adaptive weighting (your feedback)' }),
    h('p', { class: 'small muted', text: 'Reporting a false positive shrinks the weight of the signals that fired, bounded to 40% of the published weight so evidence can never be silenced completely.' }),
    adapted.length
      ? table(['Signal', 'False positives', 'Confirmations', 'Weight multiplier', 'Effective weight'], adapted.map(([id, v]) => {
        const w = snapshot.weights[id] || {};
        return [id, String(v.falsePositives), String(v.confirmations), String(w.multiplier ?? 1), String(w.effective ?? w.base ?? '—')];
      }))
      : empty('No feedback recorded yet. The published weights are in full effect.')
  );
}

/* ------------------------------------------------------------------ */
/* DNS lab                                                             */
/* ------------------------------------------------------------------ */

async function resolveDomain() {
  const input = document.getElementById('dns-input');
  const type = document.getElementById('dns-type').value;
  const button = document.getElementById('dns-go');
  const out = document.getElementById('dns-result');
  const domain = String(input.value || '').trim();
  if (!domain) { mount(out, note('Enter a hostname first.', 'warn')); return; }
  setBusy(button, true, 'Resolving…');
  mount(out, h('p', { class: 'muted small', text: 'Contacting an encrypted resolver…' }));
  try {
    const result = type === 'dual'
      ? await state.client.lookupDualStack(domain)
      : await state.client.lookup(domain, { type });
    renderDnsResult(out, result, type);
    renderDnsCache();
    renderMonitor();
  } catch (err) {
    mount(out, note(`Resolution failed: ${err.message}`, 'bad'));
  } finally {
    setBusy(button, false);
  }
}

/**
 * Audits the CNAME chain of a resolution result: which links leave the queried
 * site, and whether any of them is already blocked or flagged. Purely advisory.
 */
function chainAuditFor(result) {
  if (!result || !Array.isArray(result.cname) || !result.cname.length) {
    return auditChain({ name: result?.name || '', cname: [], engine: state.engine });
  }
  return auditChain({
    name: result.name,
    cname: result.cname,
    engine: state.engine,
    reputation: (domain) => state.aether.reputation.analyze(domain)
  });
}

function chainAuditNodes(audit) {
  return [
    h('h3', { text: 'Redirect chain audit (DNS CNAME)' }),
    h('div', { class: 'row' },
      pill(audit.cloaking ? 'cloaking detected' : `${audit.depth} link(s)`, audit.cloaking ? 'warn' : 'info'),
      h('span', { class: 'small muted', text: audit.summary })
    ),
    audit.links.length
      ? table(['Chain link', 'Registrable domain', 'Filter', 'AETHER score'], audit.links.map((link) => [
        link.target,
        link.registrable || '—',
        link.blocked ? pill(`blocked · ${link.blockedBy.source}`, 'bad') : pill('no rule', 'ok'),
        link.score === null ? '—' : `${link.score} (${link.verdict})`
      ]))
      : empty('No CNAME links in this answer.'),
    h('ul', { style: { paddingLeft: '20px', marginTop: '8px' } }, (audit.evidence || []).map((line) => h('li', { class: 'small', text: line }))),
    note(audit.scope, 'info')
  ];
}

function renderDnsResult(out, result, type) {
  if (type === 'dual') {
    const a = result.results.a;
    const aaaa = result.results.aaaa;
    const cls = result.blocked ? 'blocked' : (a.ok || aaaa.ok) ? 'allowed' : 'error';
    mount(out,
      h('div', { class: `verdict ${cls}` },
        h('h3', { text: `${result.name} — ${result.blocked ? 'blocked' : a.ok || aaaa.ok ? 'resolved' : 'not resolved'}` }),
        h('ul', {},
          h('li', { text: `IPv4: ${a.addresses.join(', ') || '—'} ${a.status !== 'ok' ? `(${a.status})` : ''}` }),
          h('li', { text: `IPv6: ${aaaa.addresses.join(', ') || '—'} ${aaaa.status !== 'ok' ? `(${aaaa.status})` : ''}` }),
          h('li', { text: `Cache: ${a.cached ? 'hit' : 'miss'} · latency ${result.latencyMs} ms` }),
          ...(a.reasons || []).map((r) => h('li', { text: r }))
        )
      ),
      h('h3', { text: 'Per-family detail' }),
      table(['Query', 'Status', 'Resolver', 'Transport', 'DNSSEC', 'Latency'], [
        ['A', a.status, a.resolver?.name ?? '—', a.transport ?? '—', a.dnssec?.status ?? '—', `${a.latencyMs} ms`],
        ['AAAA', aaaa.status, aaaa.resolver?.name ?? '—', aaaa.transport ?? '—', aaaa.dnssec?.status ?? '—', `${aaaa.latencyMs} ms`]
      ]),
      ...(a.cname?.length ? chainAuditNodes(chainAuditFor(a)) : [])
    );
    return;
  }

  const cls = result.blocked ? 'blocked' : result.ok ? 'allowed' : 'error';
  mount(out,
    h('div', { class: `verdict ${cls}` },
      h('h3', { text: `${result.name} (${result.type})` }),
      h('ul', {}, (result.reasons || []).map((r) => h('li', { text: r })))
    ),
    kv([
      ['Status', result.status],
      ['Addresses', result.addresses.join(', ') || '—'],
      ['CNAME chain', result.cname?.length ? result.cname.map((c) => c.to).join(' → ') : '—'],
      ['TTL', result.ttl ?? '—'],
      ['Resolver', result.resolver ? `${result.resolver.name} (${result.resolver.operator})` : '—'],
      ['Transport', result.transport ?? '—'],
      ['DNSSEC', result.dnssec ? `${result.dnssec.status} — ${result.dnssec.detail}` : '—'],
      ['Cached', result.cached ? (result.stale ? 'stale (refreshing)' : 'yes') : 'no'],
      ['Latency', `${result.latencyMs} ms`],
      ['Pipeline', (result.pipeline || []).join(' → ')],
      ['Fallback attempts', (result.attempts || []).length ? (result.attempts || []).map((a) => `${a.resolverId}:${a.ok ? 'ok' : a.reason || a.code}`).join(', ') : 'single attempt']
    ]),
    ...(result.cname?.length ? chainAuditNodes(chainAuditFor(result)) : [])
  );
}

function renderDns() {
  const health = state.client?.pool.health.snapshot() || [];
  const order = state.client?.pool.order().map((r) => r.id) || [];
  mount('#dns-resolvers',
    h('h2', { text: 'Encrypted resolvers' }),
    table(['Resolver', 'Policy (operator claim)', 'Health', 'EWMA'], RESOLVERS.map((resolver) => {
      const hstate = health.find((s) => s.id === resolver.id) || {};
      const cls = hstate.available === false ? 'bad' : hstate.ewmaMs ? 'ok' : '';
      return [
        h('div', {}, h('div', { text: resolver.name }), h('span', { class: 'tiny muted mono', text: `${resolver.dohJson || resolver.dohWire}` })),
        h('div', { class: 'tiny' }, h('div', { text: resolver.filtering }), h('span', { class: 'muted', text: resolver.privacy })),
        pill(hstate.available === false ? 'circuit open' : (hstate.successes ? 'healthy' : 'untested'), cls),
        hstate.ewmaMs ? `${Math.round(hstate.ewmaMs)} ms` : '—'
      ];
    })),
    h('p', { class: 'small muted', style: { marginTop: '8px' }, text: `Fallback order: ${order.join(' → ') || 'default'}. A failing resolver trips a circuit breaker after repeated failures and stops receiving traffic until its cooldown expires.` }),
    note(`DoT: ${DotTransport.capability().reason}`, 'warn')
  );

  renderDnsCache();
}

function renderDnsCache() {
  if (!state.client) return;
  const snapshot = state.client.snapshot();
  mount('#dns-cache',
    h('h2', { text: 'Cache & latency' }),
    kv([
      ['Entries', `${snapshot.cache.entries} / ${snapshot.cache.maxEntries}`],
      ['Live entries', String(snapshot.cache.live)],
      ['Hits / misses', `${snapshot.cache.stats.hits} / ${snapshot.cache.stats.misses}`],
      ['Negative hits', String(snapshot.cache.stats.negativeHits)],
      ['Single-flight joins', String(snapshot.cache.stats.singleFlightJoins)],
      ['p50 / p95 latency', snapshot.latency.p50 === null ? '—' : `${snapshot.latency.p50} / ${snapshot.latency.p95} ms`],
      ['Blocked lookups', String(snapshot.stats.blocked)],
      ['Network lookups', String(snapshot.stats.network)]
    ]),
    h('div', { class: 'row', style: { marginTop: '10px' } },
      h('button', { class: 'sm', text: 'Flush cache', onclick: () => { state.client.cache.clear(); renderDnsCache(); toast('DNS cache flushed.', 'ok'); } })
    )
  );
}

/* ------------------------------------------------------------------ */
/* Firewall AI                                                         */
/* ------------------------------------------------------------------ */

function renderFirewall() {
  const snapshot = state.firewall?.snapshot();
  if (!snapshot) return;
  mount('#fw-state',
    h('h2', {}, 'Observed behaviour', pill(`${number(snapshot.destinations)} destinations`, 'info')),
    kv([
      ['Observations recorded', number(snapshot.stats.observations)],
      ['Evaluations', number(snapshot.stats.evaluations)],
      ['Monitor decisions', number(snapshot.stats.monitors)],
      ['Block recommendations', number(snapshot.stats.blocks)],
      ['Beaconing detections', number(snapshot.stats.beaconing)],
      ['Tunnelling detections', number(snapshot.stats.tunneling)],
      ['Rate anomalies', number(snapshot.stats.rateAnomalies)],
      ['Fan-out events', number(snapshot.stats.fanout)]
    ]),
    h('p', { class: 'small muted', style: { marginTop: '8px' } },
      'Sources: DNS Lab resolutions, AETHER analyses and any observation log you import. '
      + 'The browser cannot passively capture other applications\' traffic — that requires the Android VPN core — so this list only reflects what OmniShield X itself performed or was given.'),
    snapshot.policies.length
      ? table(['App', 'Denied', 'Allowed'], snapshot.policies.map((p) => [p.app, p.deny.join(', ') || '—', p.allow.join(', ') || '—']))
      : empty('No per-app policies set. Safe default: monitor only, never auto-block.'),
    h('h2', { style: { marginTop: '14px' }, text: 'Detector thresholds (as configured, not as marketed)' }),
    table(['Detector', 'Threshold'], firewallThresholdRows()),
    h('p', { class: 'small muted', style: { marginTop: '8px' },
      text: 'These are the live values used by the detectors above. Blocks require at least two independent indicators, and the safe default remains monitor-only.' })
  );
}

/**
 * Renders DEFAULT_CONFIG as a readable list. The numbers come from the module,
 * not from a copy of the docs, so the UI cannot drift from the behaviour.
 */
function firewallThresholdRows() {
  const rows = [];
  for (const [key, value] of Object.entries(FW_CONFIG)) {
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      for (const [sub, subValue] of Object.entries(value)) {
        rows.push([`${key}.${sub}`, String(subValue)]);
      }
    } else if (!Array.isArray(value)) {
      rows.push([key, String(value)]);
    } else {
      rows.push([key, value.length ? value.join(', ') : '—']);
    }
  }
  return rows;
}

function runFirewallSelfTest() {
  const out = document.getElementById('fw-selftest-out');
  const fw = new FirewallAI({ clock: () => 1_700_000_000_000 });
  const base = 1_700_000_000_000;
  const results = [];

  // Beacon: exact 60s cadence.
  for (let i = 0; i < 12; i++) fw.observe({ domain: 'beacon.fixture', at: base + i * 60_000 });
  results.push(['Beaconing (60s cadence)', fw.detectBeaconing('beacon.fixture')]);

  // Jittered traffic must not fire.
  let t = base;
  for (const gap of [5_000, 120_000, 9_000, 300_000, 15_000, 45_000, 7_000, 200_000]) {
    t += gap; fw.observe({ domain: 'human.fixture', at: t });
  }
  results.push(['Beaconing (human jitter)', fw.detectBeaconing('human.fixture')]);

  // Tunnel: long, unique, high-entropy labels.
  const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';
  for (let i = 0; i < 24; i++) {
    let token = '';
    for (let j = 0; j < 48; j++) token += alphabet[(i * 7 + j * 11) % alphabet.length];
    fw.observe({ domain: `${token}.${i}.chunk.data.tunnel.fixture`, at: base + i * 1000 });
  }
  results.push(['DNS tunnelling', fw.detectTunneling('tunnel.fixture')]);

  results.push(['Fan-out (70 distinct)', (() => {
    for (let i = 0; i < 70; i++) fw.observe({ domain: `spray${i}.fixture`, at: base + i * 300 });
    return fw.detectFanout(base + 21_000);
  })()]);

  mount(out,
    note('These fixtures are synthetic test vectors used to verify the detectors. They are NOT your traffic and are never counted as protection.', 'warn'),
    table(['Detector', 'Fired', 'Confidence', 'Measured detail'], results.map(([name, result]) => [
      name,
      result.fired ? pill('yes', 'bad') : pill('no', 'ok'),
      result.confidence || result.reason || '—',
      result.fired
        ? (result.cv !== undefined ? `CV ${result.cv}, mean ${result.meanIntervalMs} ms` :
          result.avgEntropy !== undefined ? `entropy ${result.avgEntropy}, ${result.uniqueSubdomains} unique` :
            `${result.distinct} distinct`)
        : (result.reason || 'within normal range')
    ])),
    h('div', { class: 'row', style: { marginTop: '10px' } }, ...results.map(([name, result]) =>
      pill(`${name}: ${result.fired ? 'fires' : 'ignores'}`, result.fired ? 'warn' : 'ok'))),
    note('Interpretation matters: a periodic check-in can be command-and-control OR a legitimate app polling an API. '
      + 'That is exactly why two independent signals are required before a block recommendation.', 'ok')
  );
}

function inspectFirewall() {
  const domain = String(document.getElementById('fw-input').value || '').trim();
  const out = document.getElementById('fw-inspect-out');
  if (!domain) { mount(out, note('Enter a destination that appears in the observation list.', 'warn')); return; }
  const report = state.firewall.inspect(domain);
  const reputation = state.aether.analyze(domain);
  const decision = state.firewall.evaluate(domain, { reputation });
  mount(out,
    h('div', { class: `verdict ${decision.decision === 'block' ? 'blocked' : decision.decision === 'monitor' ? 'error' : 'allowed'}` },
      h('h3', { text: `${decision.domain} → ${decision.decision.toUpperCase()} (confidence: ${decision.confidence})` }),
      h('ul', {}, decision.reasons.map((r) => h('li', { text: r })))
    ),
    h('h3', { text: 'Raw detector output' }),
    table(['Detector', 'Fired', 'Detail'], [
      ['Beaconing', report.beaconing.fired ? 'yes' : 'no', report.beaconing.evidence || report.beaconing.reason || '—'],
      ['Rate', report.rate.fired ? 'yes' : 'no', report.rate.evidence || report.rate.reason || '—'],
      ['Tunnelling', report.tunneling.fired ? 'yes' : 'no', report.tunneling.evidence || report.tunneling.reason || '—']
    ]),
    kv([
      ['Observations', String(report.observations)],
      ['Registrable domain', report.parent],
      ['Entropy (main label)', String(report.features.entropy)],
      ['Labels', String(report.features.labelCount)],
      ['AETHER reputation', `${reputation.score}/100 (${reputation.verdictLabel})`]
    ])
  );
}

function importFirewallLog(file) {
  const reader = new FileReader();
  reader.onload = () => {
    try {
      const parsed = JSON.parse(String(reader.result));
      const entries = Array.isArray(parsed) ? parsed : parsed.observations || parsed.entries || parsed.logs;
      if (!Array.isArray(entries)) throw new Error('expected an array, or an object with observations/entries/logs');
      const accepted = state.firewall.importLog(entries);
      toast(`Imported ${accepted} observation(s).`, 'ok');
      renderFirewall();
      renderMonitor();
    } catch (err) {
      toast(`Import failed: ${err.message}`, 'bad');
    }
  };
  reader.readAsText(file);
}

/* ------------------------------------------------------------------ */
/* Monitor                                                             */
/* ------------------------------------------------------------------ */

function renderMonitor() {
  if (!state.monitor) return;
  const metrics = state.monitor.metrics();
  mount('#mon-kpis',
    kpi(number(metrics.lookups), 'requests processed'),
    kpi(number(metrics.blocked), 'blocked before resolution'),
    kpi(metrics.blockedRatio === null ? '—' : `${metrics.blockedRatio}%`, 'blocked share'),
    kpi(metrics.latency.p95 === null ? '—' : `${metrics.latency.p95} ms`, 'p95 resolution latency')
  );

  const canvas = document.getElementById('mon-chart');
  drawSeries(canvas, [
    { points: metrics.series.lookups, color: '#2e7dff', fill: 'rgba(46,125,255,.25)' },
    { points: metrics.series.blocked, color: '#ff5470' }
  ], { height: 90 });
  mount('#mon-legend',
    h('span', {}, pill('requests', 'info')),
    h('span', {}, pill('blocked', 'bad')),
    h('span', { class: 'muted', text: `bucket = ${metrics.bucketMs / 1000}s` })
  );

  const categories = Object.entries(metrics.categories).sort((a, b) => b[1] - a[1]);
  const max = Math.max(1, ...categories.map(([, v]) => v));
  mount('#mon-categories',
    h('h2', { text: 'Blocked by category' }),
    categories.length
      ? h('div', { class: 'bars' }, categories.map(([cat, count]) => h('div', { class: 'bar-row' },
        h('span', { text: cat }),
        h('div', { class: 'bar-track' }, h('div', { class: 'bar-fill hot', style: { width: `${(count / max) * 100}%` } })),
        h('span', { class: 'mono', text: number(count) })
      )))
      : empty('Nothing blocked in this session yet.')
  );

  mount('#mon-top',
    h('h2', { text: 'Most active domains' }),
    metrics.topDomains.length
      ? table(['Domain', 'Requests', 'Blocked', 'Category'], metrics.topDomains.map((d) => [d.domain, number(d.count), number(d.blocked), d.category || '—']))
      : empty('No domain activity recorded.')
  );

  mount('#mon-events',
    h('h2', { text: 'Recent events' }),
    metrics.recent.length
      ? table(['Time', 'Kind', 'Domain', 'Detail'], [...metrics.recent].reverse().map((e) => [
        new Date(e.at).toLocaleTimeString(),
        e.kind,
        e.domain || '—',
        e.kind === 'blocked' ? (e.category || 'blocked') : e.kind === 'lookup' ? `${e.status || ''} ${e.latencyMs ? `${e.latencyMs} ms` : ''}`.trim() : (e.decision || '')
      ]))
      : empty('No events yet. Use the DNS Lab or AETHER to produce real measurements.')
  );
}

/**
 * Rough in-memory cost of the loaded rules. Measured from the engine's own
 * counts, with a conservative per-rule allowance for the stored pattern string
 * plus the Set/Map slot — labelled as an estimate everywhere it is shown.
 */
function estimateRuleMemory(totalRules) {
  return Math.round((Number(totalRules) || 0) * 120);
}

/**
 * Measures this device's actual filtering cost: evaluates a deterministic sample
 * of the loaded rule set and reports per-op latency plus throughput. Nothing is
 * cached or estimated — the number shown is the number measured just now.
 */
function runEngineBenchmark(iterations = 5000) {
  const domains = [...state.engine.filterSubdomains.keys()];
  if (!domains.length) return { ok: false, reason: 'no rules loaded, so there is nothing to measure' };
  const sample = domains.slice(0, Math.min(iterations, domains.length));
  const samples = new Float64Array(sample.length);
  const startedAt = performance.now();
  for (let i = 0; i < sample.length; i++) {
    const t0 = performance.now();
    state.engine.evaluate(sample[i]);
    samples[i] = performance.now() - t0;
  }
  const totalMs = performance.now() - startedAt;
  const sorted = Array.from(samples).sort((a, b) => a - b);
  const pct = (p) => sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * p))];
  return {
    ok: true,
    evaluated: sample.length,
    totalMs: Math.round(totalMs * 100) / 100,
    perSecond: Math.round(sample.length / (totalMs / 1000)),
    p50us: Math.round(pct(0.5) * 1000),
    p95us: Math.round(pct(0.95) * 1000),
    meanUs: Math.round((totalMs * 1000 / sample.length) * 10) / 10,
    measuredAt: new Date().toISOString()
  };
}

function renderBenchmark(result) {
  const node = document.getElementById('dash-bench');
  if (!node) return;
  if (!result) { mount(node, empty('No benchmark run yet. It measures your device, not a marketing claim.')); return; }
  if (!result.ok) { mount(node, note(result.reason, 'warn')); return; }
  mount(node,
    kv([
      ['Evaluations measured', `${number(result.evaluated)} (sampled from the loaded rule set)`],
      ['Total time', `${result.totalMs} ms`],
      ['Mean per evaluation', `${result.meanUs} µs`],
      ['p50 / p95', `${result.p50us} µs / ${result.p95us} µs`],
      ['Throughput', `${number(result.perSecond)} evaluations/second`],
      ['Measured', relativeTime(result.measuredAt)]
    ]),
    note('Measured on this device just now, using performance.now() around real engine.evaluate() calls. Rule matching is a Set/Map walk; no network or model inference is involved.', 'info')
  );
}

function startMonitorLoop() {
  clearInterval(state.monitorTimer);
  const interval = state.power
    ? state.power.intervalFor(state.settings.monitorRefreshMs)
    : state.settings.monitorRefreshMs;
  state.monitorIntervalMs = interval;
  state.monitorTimer = setInterval(() => {
    // Background tabs do no work at all: a hidden tab cannot show a live view.
    if (document.hidden) return;
    if (state.currentPage === 'monitor') renderMonitor();
    if (state.currentPage === 'dashboard') renderDashboard();
  }, interval);
  return interval;
}

/**
 * Battery-aware scheduling. The Battery Status API is not available in every
 * browser (and is deliberately absent in Safari); when it is missing the app
 * keeps the default cadence and says so instead of pretending to optimise.
 */
async function startPowerGovernor() {
  state.power = new PowerGovernor({
    onChange: (info) => {
      state.powerInfo = info;
      startMonitorLoop();
      if (state.currentPage === 'dashboard') renderDashboard();
      if (state.currentPage === 'status') renderStatus();
      toast(`Repaint cadence changed: ${info.summary}`, 'info');
    }
  });
  state.powerInfo = await state.power.start();
  startMonitorLoop();
  if (state.currentPage === 'dashboard') renderDashboard();
}

/* ------------------------------------------------------------------ */
/* Feeds                                                               */
/* ------------------------------------------------------------------ */

async function renderFeeds() {
  if (!state.feeds) return;
  const statuses = await state.feeds.list();
  mount('#feeds-list',
    h('h2', { text: 'Feed registry' }),
    table(['Feed', 'Category', 'Source', 'Installed', 'Rules', 'Integrity'], FEED_REGISTRY.map((feed) => {
      const status = statuses.find((s) => s.id === feed.id) || {};
      return [
        h('div', {}, h('div', { text: feed.name }), h('span', { class: 'tiny muted', text: `${feed.license} · ${feed.homepage}` })),
        feed.category,
        h('span', { class: 'tiny mono', text: feed.url.replace('https://raw.githubusercontent.com/', '').slice(0, 48) + '…' }),
        status.installed ? pill(`v ${relativeTime(status.fetchedAt)}`, status.stale ? 'warn' : 'ok') : pill('bundled only', 'info'),
        status.installed ? number(status.rules) : (feed.id === 'core_lite_ads' && state.bundled.core_lite_ads?.added ? number(state.bundled.core_lite_ads.added) : '—'),
        status.installed ? h('span', { class: 'tiny mono', text: status.hash?.slice(0, 16) }) : '—'
      ];
    })),
    h('p', { class: 'small muted', style: { marginTop: '8px' }, text: 'Online updates are optional. The bundled copy in assets/ is always available offline and is never modified.' }),
    h('h3', { text: 'Optional aggressive tier' }),
    h('div', { class: 'row' },
      h('button', {
        class: state.settings.aggressiveTier ? 'danger sm' : 'sm',
        text: state.settings.aggressiveTier ? 'Disable aggressive tier' : 'Enable aggressive tier',
        onclick: async () => {
          const target = !state.settings.aggressiveTier;
          if (target && !confirm('The aggressive tier blocks tag managers and social SDKs. Some sites may break. You can undo this instantly, and every block stays labelled. Continue?')) return;
          await enableAggressiveTier(target);
          toast(target ? 'Aggressive tier enabled — reversible at any time.' : 'Aggressive tier disabled.', target ? 'warn' : 'ok');
        }
      }),
      pill(state.settings.aggressiveTier ? 'enabled' : 'disabled (safe default)', state.settings.aggressiveTier ? 'warn' : 'ok')
    )
  );
}

async function checkFeedUpdates() {
  const button = document.getElementById('feeds-check');
  const status = document.getElementById('feeds-status');
  setBusy(button, true, 'Checking…');
  const lines = [];
  try {
    for (const feed of FEED_REGISTRY) {
      let result;
      try {
        result = await state.feeds.update(feed.id);
      } catch (err) {
        result = { ok: false, reason: 'exception', detail: err.message };
      }
      if (result.ok && result.changed) {
        const text = await state.feeds.content(feed.id);
        state.engine.loadFilterList(text, feed.category, feed.id);
        state.aether.reputation.cache.clear();
        lines.push(note(`${feed.name}: updated — ${number(result.meta.rules)} rules, sha256 ${result.meta.hash.slice(0, 12)}…`, 'ok'));
      } else if (result.ok) {
        lines.push(note(`${feed.name}: already up to date (${result.reason}).`, 'ok'));
      } else {
        lines.push(note(`${feed.name}: not applied — ${result.reason}${result.detail ? ` (${result.detail})` : ''}.`
          + (result.retained ? ` Previous copy retained (${number(result.retained.rules)} rules).` : ' No copy installed; bundled rules stay active.'), 'warn'));
      }
    }
    lines.push(note('Feed updates are validated before use: structure, SHA-256 integrity, and rollback protection against truncated lists.', 'ok'));
    mount(status, ...lines);
    await saveSnapshot('feed-update');
    renderAll();
  } finally {
    setBusy(button, false);
  }
}

async function verifyFeeds() {
  const status = document.getElementById('feeds-status');
  const results = [];
  for (const feed of FEED_REGISTRY) {
    const result = await state.feeds.verify(feed.id);
    results.push(note(`${feed.name}: ${result.ok ? 'integrity OK' : `not verified (${result.reason})`}`, result.ok ? 'ok' : 'warn'));
  }
  mount(status, ...results);
}

/* ------------------------------------------------------------------ */
/* Privacy                                                             */
/* ------------------------------------------------------------------ */

function renderPrivacy() {
  const report = state.analytics.report();
  const days = report.days.length
    ? table(['Day', 'Reported events', 'Suppressed', 'Distinct domains', 'Categories'], report.days.map((d) => [
      d.day, number(d.reportedEvents), `${number(d.suppressedEvents)} (${d.suppressedBuckets} buckets)`, number(d.distinctDomains),
      Object.entries(d.categories).map(([c, n]) => `${c}: ${n}`).join(', ') || '—'
    ]))
    : empty('No analytics recorded yet.');

  mount('#privacy-out',
    h('h2', { text: 'Aggregate report' }),
    days,
    kv([
      ['Reported events', number(report.totals.reported)],
      ['Suppressed events (k-anonymity)', number(report.totals.suppressed)],
      ['k threshold', String(report.k)],
      ['Retention', `${report.retentionDays} days`],
      ['Leaves device', 'no']
    ])
  );

  mount('#privacy-note',
    h('h2', { text: 'What is stored' }),
    kv([
      ['Hostnames', 'Never stored in the clear — salted SHA-256 prefix only'],
      ['Storage key', 'omnishield-x:analytics:state'],
      ['Network transmission', 'None; no analytics endpoint exists in this app'],
      ['Suppression', `Any category with fewer than ${report.k} events is withheld from the report`]
    ]),
    note('This is local aggregation, not a cryptographic anonymity system: someone with access to this browser profile could correlate hashes. '
      + 'Nothing is uploaded, so the exposure is limited to this device.', 'warn')
  );
}

/* ------------------------------------------------------------------ */
/* Backup & sync                                                       */
/* ------------------------------------------------------------------ */

async function renderSnapshots() {
  if (!state.backups) return;
  const list = await state.backups.list();
  mount('#snapshot-list',
    h('h2', { text: 'Snapshots' }),
    list.length
      ? table(['Snapshot', 'Created', 'Reason', 'Schema', 'Size', 'Integrity', ''], list.map((s) => [
        h('span', { class: 'mono tiny', text: s.id }),
        s.createdAt ? relativeTime(s.createdAt) : '—',
        s.reason || '—',
        s.schemaVersion ?? '—',
        bytes(s.bytes),
        s.corrupt ? pill('corrupt', 'bad') : (s.valid ? pill('verified', 'ok') : pill('invalid', 'bad')),
        s.corrupt ? '—' : h('button', {
          class: 'sm ghost', text: 'Restore',
          onclick: async () => {
            const result = await state.backups.restore(s.id);
            if (!result.ok) { toast(`Restore failed: ${result.reason}`, 'bad'); return; }
            toast('Snapshot restored. Reloading configuration…', 'ok');
            location.reload();
          }
        })
      ]))
      : empty('No snapshots yet — one is created automatically after changes.'),
    h('p', { class: 'small muted', style: { marginTop: '8px' }, text: 'Hashes are verified before any restore; a corrupt snapshot is reported and skipped, never silently applied.' })
  );
}

function renderSync() {
  const status = document.getElementById('sync-status');
  if (status) {
    mount(status,
      h('div', { class: 'row' },
        pill(state.lastSnapshotId ? `last snapshot ${state.lastSnapshotId}` : 'no snapshot', state.lastSnapshotId ? 'ok' : 'warn'),
        pill(`${state.customRules.length} custom rule${state.customRules.length === 1 ? '' : 's'}`, 'info'),
        pill(`${state.aether?.observations.size ?? 0} observed domains`, 'info')
      )
    );
  }
  const wrap = document.getElementById('rules-body');
  if (wrap) {
    ui.clear(wrap);
    if (!state.customRules.length) {
      wrap.appendChild(h('tr', {}, h('td', { colspan: 5, class: 'empty' }, 'No custom rules yet. Allow or block a domain from AETHER, or import an Android backup.')));
    }
    for (const rule of state.customRules) {
      wrap.appendChild(h('tr', {},
        h('td', { class: 'mono', text: rule.pattern }),
        h('td', {}, pill(rule.isAllow ? 'ALLOW' : 'BLOCK', rule.isAllow ? 'ok' : 'bad')),
        h('td', { text: 'suffix' }),
        h('td', { text: 'on' }),
        h('td', {},
          h('button', {
            class: 'sm ghost', text: 'Remove',
            onclick: () => {
              state.customRules = state.customRules.filter((r) => r !== rule);
              state.engine.removeUserRule(`||${rule.pattern}^`, rule.isAllow);
              scheduleSnapshot('rule-removed');
              renderSync();
              renderDashboard();
              toast(`Removed ${rule.isAllow ? 'allow' : 'block'} rule for ${rule.pattern}.`, 'ok');
            }
          })
        )
      ));
    }
    document.getElementById('sync-table-wrap').hidden = false;
  }
  renderSnapshots();
}

function importAndroidBackup(file) {
  const status = document.getElementById('import-status');
  const reader = new FileReader();
  reader.onload = () => {
    try {
      const data = JSON.parse(String(reader.result));
      if (!Array.isArray(data.customRules)) throw new Error('not an OmniShield backup (customRules array missing)');
      state.importedBackup = data;
      let applied = 0;
      for (const rule of data.customRules) {
        const pattern = String(rule.rawPattern ?? rule.pattern ?? '').trim();
        if (!pattern) continue;
        const isAllow = rule.ruleType === 'ALLOW' || rule.isAllow === true;
        if (state.customRules.some((r) => r.pattern === pattern && r.isAllow === isAllow)) continue;
        state.customRules.push({ pattern, isAllow });
        if (state.engine.addUserRule(pattern, isAllow)) applied++;
      }
      state.aether.reputation.cache.clear();
      const notes = [
        note(`Imported: ${data.customRules.length} custom rule(s) (${applied} applied to the engine), `
          + `${data.browserSiteExceptions?.length || 0} site exception(s), ${data.excludedAppPackages?.length || 0} app exclusion(s).`, 'ok'),
        note('Imported values are rendered as text only — file contents are never interpreted as markup.', 'ok')
      ];
      if (data.protectionMode) {
        notes.push(note(`Protection mode in the backup: ${typeof data.protectionMode === 'object' ? data.protectionMode.title : data.protectionMode}`, 'ok'));
      }
      mount(status, ...notes);
      document.getElementById('export-btn').disabled = false;
      scheduleSnapshot('android-import');
      renderSync();
      renderDashboard();
    } catch (err) {
      mount(status, note(`Import failed: ${err.message}`, 'bad'));
    }
  };
  reader.readAsText(file);
}

function exportMergedConfig() {
  const payload = {
    ...(state.importedBackup || {}),
    ...buildState({ includeModel: true }),
    exportedAt: new Date().toISOString(),
    exportedBy: 'OmniShield X web platform v5.1.0'
  };
  download('omnishield-x-config.json', JSON.stringify(payload, null, 2));
  toast('Merged configuration exported.', 'ok');
}

/* ------------------------------------------------------------------ */
/* Extension & capabilities                                            */
/* ------------------------------------------------------------------ */

async function renderExtension() {
  const breakdown = state.engine?.breakdown();
  const facts = await fetchJSONSafe('./assets/extension-facts.json');
  const artifactRows = facts
    ? [
        ['Rules shipped in the ZIP', `${number(facts.rules)} static rules in ${facts.rulesets} ruleset files`],
        ['Unique domains', number(facts.uniqueDomains)],
        ['Feed lines considered', `${number(facts.feedLinesConsidered)} → capped at ${number(facts.maxStaticRules)} by feed order`],
        ['Archive size', bytes(facts.bytes)],
        ['Archive version', String(facts.version)]
      ]
    : [['Rules shipped in the ZIP', 'facts file unavailable — rebuild with npm run build:extension']];

  mount('#extension-facts',
    h('h2', { text: 'Extension facts (measured from the shipped ZIP, not marketed)' }),
    kv([
      ...artifactRows,
      ['Rules in this web core', `${number(breakdown?.total ?? 0)} (same feeds, different engine)`],
      ['Why not all of them', `Chrome guarantees ${number(facts?.maxStaticRules ?? 30000)} static rules per extension; anything above that is shared with every other installed blocker and can fail to enable`],
      ['Permissions requested', 'declarativeNetRequest, declarativeNetRequestFeedback, storage'],
      ['Host access', 'a content script matches http/https pages to inject cosmetic CSS — it reads no page content and sends nothing'],
      ['Network calls', 'none at runtime; rules are static files'],
      ['Counts in the popup', 'from the browser\'s own matched-rule events, and only where the browser exposes them — otherwise the popup shows "—" and the reason'],
      ['Cannot do', 'filter other apps, filter traffic in other browsers, or block first-party ads served from the site\'s own domain (rules are third-party only)']
    ]),
    note('This is a content blocker, not a privacy VPN. Chrome limits how many static rules an extension may ship, which is why the extension carries a capped subset of the 79k-rule web core. The builder script (npm run build:extension) regenerates the ZIP deterministically from the bundled feeds.', 'warn')
  );
}

/** Fetch + parse JSON, returning null instead of throwing on any failure. */
async function fetchJSONSafe(url) {
  try {
    const response = await fetch(url, { cache: 'no-cache' });
    if (!response.ok) return null;
    return await response.json();
  } catch {
    return null;
  }
}

const CAPABILITIES = [
  ['Deterministic DNS filter ladder', 'works', 'engine.test.mjs — ladder order, user allow overrides, undo symmetry'],
  ['Hosts-file + Adblock + plain-domain parsing', 'works', 'engine.test.mjs — formats'],
  ['Wildcard rules (with catch-all rejection)', 'works', 'engine.test.mjs — wildcards'],
  ['DoH (JSON API)', 'works', 'dns-transport.test.mjs — DoH JSON'],
  ['DoH (RFC 8484 wire)', 'works', 'dns-transport.test.mjs — wire'],
  ['DoT (DNS over TLS)', 'partial', 'Codec + framing implemented and tested; browsers cannot open TCP:853'],
  ['DNSSEC: AD-bit trust from validating resolver', 'works', 'dns-transport.test.mjs — DNSSEC status'],
  ['DNSSEC: local chain-of-trust validation', 'not-implemented', 'Requires walking root KSK → ZSK; documented limitation'],
  ['IPv4 + IPv6 dual-stack resolution', 'works', 'dns-client.test.mjs — dual-stack'],
  ['TTL + negative caching, single-flight', 'works', 'cache.test.mjs'],
  ['Resolver health & circuit-breaker fallback', 'works', 'dns-transport.test.mjs — fallback/breaker'],
  ['AETHER reputation with attributable evidence', 'works', 'reputation.test.mjs — every point attributable'],
  ['Lexical ML model with held-out metrics', 'works', 'classifier.test.mjs — AUC/precision floors'],
  ['Typosquat / homograph / IDN detection', 'works', 'lexical.test.mjs'],
  ['False-positive guardrails (popularity, allowlist)', 'works', 'reputation.test.mjs'],
  ['Firewall AI behavioural detection', 'works', 'firewall.test.mjs — 16 tests, positive + negative'],
  ['Real-time monitoring', 'works', 'monitor.test.mjs — measured events only'],
  ['Feed updates with integrity + rollback protection', 'works', 'infrastructure.test.mjs — feed manager'],
  ['Config backup, migration, auto-recovery', 'works', 'infrastructure.test.mjs — backup manager'],
  ['Offline operation (bundled rules + service worker)', 'works', 'sw.js caches the shell and bundled lists'],
  ['CNAME cloaking / DNS redirect-chain audit', 'works', 'chain.test.mjs — named targets, blocked-by attribution, advisory only'],
  ['HTTP redirect analysis (301/302/JS)', 'not-implemented', 'Invisible to a DNS filter; only the CNAME chain can be audited'],
  ['Privacy analytics with k-anonymity', 'works', 'infrastructure.test.mjs — privacy'],
  ['Battery/CPU-aware repaint scheduling', 'works', 'power.test.mjs — bands, clamping, honest unsupported path'],
  ['Battery Status API in every browser', 'partial', 'Chrome/Edge expose it; Safari does not. Falls back to the default cadence and says so'],
  ['System scan: file byte inspection', 'works', 'scan.test.mjs — magic bytes vs extension, embedded PE, dropper scripts, macro docs, zip-slip, EICAR, entropy'],
  ['System scan: URL / phishing analysis', 'works', 'scan.test.mjs — typosquat, IP lure, punycode, abuse TLDs, credential paths'],
  ['System scan: integrity + configuration audit', 'works', 'scan.test.mjs — vault re-hash, resolver encryption, DNSSEC state, feed hashes'],
  ['System scan: installed apps / whole device', 'not-implemented', 'A web page cannot enumerate installed apps or read the file system. Android scoped storage forbids it too; files must be granted explicitly'],
  ['Private search with DuckDuckGo / Google / Startpage / Brave / Mojeek', 'works', 'search.test.mjs — per-engine URL construction, noopener,noreferrer, blocked-pop-up reporting'],
  ['Private search: in-app results for any engine', 'not-implemented', 'Every engine refuses cross-origin result reads. Queries open in a new tab; only DuckDuckGo Instant Answers can be shown in-app'],
  ['Search: tracking-parameter stripping', 'works', 'search.test.mjs — utm_*, fbclid, gclid, msclkid and the published list'],
  ['Private cloud box on this device', 'works', 'vault.test.mjs — IndexedDB storage, folders, previews, SHA-256 verify, quotas'],
  ['Cloud box: server-side sync between devices', 'not-implemented', 'No backend by design. Transfers are files you move yourself (Backup & Sync tab)'],
  ['Cloud box: AES-GCM passphrase lock', 'works', 'vault.test.mjs — ciphertext excludes plaintext, wrong passphrase rejected, tag check on read'],
  ['Cloud box: recover a lost passphrase', 'rejected', 'Never implemented — a recovery path would defeat the encryption'],
  ['Universal downloader: direct media and permitted sources', 'works', 'media.test.mjs — streaming, real progress, pause/resume with Range, cancel, history'],
  ['Universal downloader: YouTube / Spotify / Instagram extraction', 'not-implemented', 'Their terms forbid it and the streams are DRM-protected or signed manifests. The UI refuses with a reason instead of guessing'],
  ['Universal downloader: server-side transcoding or format conversion', 'not-implemented', 'The browser stores the bytes the server sends; no transcoder runs here'],
  ['Passive capture of other apps\' traffic', 'not-implemented', 'Requires OS-level VPN (Android core); browsers cannot do this'],
  ['Antivirus / file scanning', 'not-implemented', 'This is DNS filtering, not an antivirus. Never claimed.'],
  ['Universal ad blocking (all apps, all browsers)', 'not-implemented', 'No technology can guarantee that; see capabilities notes'],
  ['Certificate interception / TLS decryption', 'rejected', 'Deliberately never implemented — it would break your security']
];

function renderStatus() {
  mount('#capabilities',
    table(['Capability', 'Status', 'Evidence / reason'], CAPABILITIES.map(([name, status, evidence]) => [
      name,
      status === 'works' ? pill('verified', 'ok')
        : status === 'partial' ? pill('partial', 'warn')
          : status === 'rejected' ? pill('never', 'info') : pill('not implemented', 'bad'),
      evidence
    ]))
  );
  mount('#limits',
    h('h2', { text: 'Explicit limitations of this deployment' }),
    h('ul', { style: { paddingLeft: '20px', display: 'grid', gap: '6px' } },
      h('li', { text: 'This is a browser application: it cannot install a VPN, capture other apps\' DNS, or block traffic outside this page. The Android core does that.' }),
      h('li', { text: 'AETHER\'s lexical score is a weak signal by measurement (AUC ≈ 0.86), weighted 7/100, and its precision at a 1% base rate is ≈ 0.06. It can raise a flag; it cannot block.' }),
      h('li', { text: 'The classifier is trained on the bundled feeds plus a curated legitimate-domain list. Unfamiliar legitimate domains can be flagged as "ad-like" — the popularity guardrail and low weight limit the impact.' }),
      h('li', { text: 'DNSSEC trust is delegated to the upstream resolver\'s AD bit. OmniShield X does not verify signatures locally.' }),
      h('li', { text: 'Public suffix handling covers common multi-label ccTLD suffixes, not the full Public Suffix List.' }),
      h('li', { text: 'First-party advertising served from the site\'s own domain cannot be filtered by DNS.' }),
      h('li', { text: 'Feed content is trusted as published by its maintainers (HaGeZi, GPLv3); a compromised upstream is mitigated by hash and shrink checks, not eliminated.' }),
      h('li', { text: 'The private cloud box is this browser profile on this device. Clearing site data deletes it, and it is not synced anywhere — export the manifest or download files to keep copies.' }),
      h('li', { text: 'A web page cannot enumerate other applications, read the whole device file system, or download media a platform forbids. Those rows are marked not implemented and the UI refuses rather than simulating them.' })
    )
  );
}

/* ------------------------------------------------------------------ */
/* System scan                                                         */
/* ------------------------------------------------------------------ */

const SCAN_MODULE_LABELS = {
  files: 'Files & downloads',
  urls: 'Links & QR targets',
  vault: 'Cloud box integrity',
  configuration: 'Security configuration',
  storage: 'Browser storage',
  applications: 'Installed apps',
  systemFiles: 'Whole-device files',
  network: 'Other apps\' traffic'
};

function scanEnabledModules() {
  if (!state.scanEnabled) {
    state.scanEnabled = { files: true, urls: true, vault: true, configuration: true, storage: true };
  }
  return state.scanEnabled;
}

function scanSeverityPill(severity) {
  const cls = severity === 'critical' || severity === 'high' ? 'bad'
    : severity === 'medium' ? 'warn'
      : severity === 'low' ? 'info'
        : severity === 'clean' ? 'ok' : '';
  return pill(severity, cls);
}

/** Reads the live configuration so the audit inspects what is actually running. */
async function collectScanConfiguration() {
  const config = { engineLoaded: !!state.engine };
  try {
    const active = state.client.pool.order()[0];
    if (active) config.resolver = { name: active.name, dohJson: active.dohJson, dot: active.dot };
  } catch { /* leave undefined: the audit reports the gap */ }
  try {
    const statuses = await state.feeds.list();
    const checked = [];
    for (const status of statuses) {
      if (!status.installed) continue;
      const verification = await state.feeds.verify(status.id);
      checked.push({ id: status.id, verified: verification.ok, error: verification.reason === 'ok' ? null : verification.reason });
    }
    if (checked.length) config.feeds = checked;
  } catch { /* reported as unknown */ }
  if (state.engine) config.rules = state.engine.breakdown();
  config.vaultLocked = !!state.vault?.locked;
  config.serviceWorker = !!(globalThis.navigator?.serviceWorker?.controller);
  if (state.lastDnsAssessment) config.dnssec = state.lastDnsAssessment;
  return config;
}

function renderScan() {
  if (!state.scanner) return;
  const enabled = scanEnabledModules();
  const modules = state.scanner.capabilities();

  mount('#scan-modules', modules.map((capability) => h('button', {
    type: 'button',
    class: 'chip',
    'aria-pressed': String(!!enabled[capability.id] && capability.available),
    disabled: !capability.available,
    title: capability.available ? capability.detail : `${capability.detail} Not selectable.`,
    text: `${capability.label}${capability.available ? '' : ' · unavailable'}`,
    onclick: () => {
      if (!capability.available) return;
      enabled[capability.id] = !enabled[capability.id];
      renderScan();
    }
  })));

  const selected = state.scanFiles.length;
  mount('#scan-status', h('span', { text: state.scanner.running ? 'running' : (state.scanRun ? state.scanRun.status : 'idle') }));

  const run = state.scanRun;
  mount('#scan-phase', run
    ? h('span', { text: `${run.phase} · ${run.progress === 1 ? 'finished in' : 'running for'} ${(run.durationMs ?? (Date.now() - run.startedAt))} ms · ${plural(selected, 'file')} queued` })
    : h('span', { text: selected ? `${plural(selected, 'file')} ready — press Run scan.` : 'No scan has run yet. Choose files or run the configuration, link and storage checks.' }));
  const bar = document.getElementById('scan-bar');
  if (bar) bar.style.width = `${Math.round((run?.progress ?? 0) * 100)}%`;

  mount('#scan-trace', state.scanTrace.slice(-12).map((line) => h('div', { text: line })));

  const stopButton = document.getElementById('scan-stop');
  if (stopButton) stopButton.disabled = !state.scanner.running;
  const runButton = document.getElementById('scan-run');
  if (runButton) runButton.disabled = state.scanner.running;
  const reportButton = document.getElementById('scan-report');
  if (reportButton) reportButton.disabled = !run || run.status === 'running';

  const findings = run?.findings || [];
  mount('#scan-findings',
    h('h2', { text: 'Findings' }),
    run ? table(['Severity', 'Target', 'Finding', 'Evidence'], findings.map((finding) => [
      scanSeverityPill(finding.severity), finding.target || '—', finding.label || '—', finding.evidence || '—'
    ]), { emptyText: 'No findings in this run — every check that ran came back clean.' }) : empty('Run a scan to see findings.'),
    run?.errors.length ? note(`${plural(run.errors.length, 'item')} could not be checked: ${run.errors.map((e) => `${e.target || e.scope}: ${e.message}`).join('; ')}`, 'warn') : null,
    run?.skipped.length ? h('p', { class: 'small muted', style: { marginTop: '8px' }, text: `Skipped: ${run.skipped.map((s) => s.scope).join(', ')} (see the module list for why).` }) : null
  );

  mount('#scan-modules-info',
    h('h2', { text: 'What each module can reach' }),
    table(['Module', 'Available', 'Scope'], modules.map((capability) => [
      capability.label,
      capability.available ? pill('yes', 'ok') : pill('no', 'bad'),
      capability.detail
    ])),
    h('h3', { text: 'Where the data lives' }),
    kv([
      ['Storage backend in use', state.vault?.storage?.name || 'unknown'],
      ['IndexedDB available', IndexedDbAdapter.detect() ? 'yes — large files and binary payloads are supported' : 'no — the cloud box falls back to localStorage (small files only)'],
      ['Files queued for this run', String(state.scanFiles.length)],
      ['Bytes read per file', 'head window 4 KB, deep window 6 MB — files larger than that are scanned from their first 6 MB and their size is reported'],
      ['Largest file accepted', `${MAX_FILE_LABEL} (${number(MAX_FILE_BYTES / 1048576)} MB) for the scan queue, the cloud box and transfers`]
    ])
  );

  mount('#scan-files-card',
    h('h2', { text: 'Files inspected' }),
    table(['File', 'Size', 'Detected', 'Severity', 'SHA-256'], (run?.files || []).map((file) => [
      h('div', { class: 'file-row' }, h('span', { class: 'file-ico', text: '📄' }), h('span', { text: file.name })),
      bytes(file.size),
      file.container || file.type,
      scanSeverityPill(file.severity),
      h('span', { class: 'tiny mono', text: file.sha256 ? `${file.sha256.slice(0, 24)}…` : '—' })
    ]), { emptyText: 'No files inspected yet.' })
  );

  const summary = run?.summary;
  mount('#scan-summary', summary
    ? h('span', { text: `${summary.status} · ${plural(summary.findings, 'finding')} · ${plural(summary.files, 'file')} · ${bytes(summary.bytes)} read · ${plural(summary.checks, 'check')}` })
    : h('span', { text: '' }));

  mount('#scan-history',
    h('h2', { text: 'Scan history' }),
    table(['Started', 'Modules', 'Files', 'Findings', 'Result', ''], state.scanner.history.slice().reverse().map((entry) => [
      relativeTime(entry.startedAt),
      entry.modules.length,
      entry.scanned.files,
      entry.summary.findings,
      scanSeverityPill(entry.summary.status),
      h('button', {
        class: 'sm', type: 'button', text: 'Report',
        onclick: () => downloadScanReport(entry.id)
      })
    ]), { emptyText: 'No runs recorded in this session.' })
  );
}

function downloadScanReport(runId = null) {
  const report = state.scanner.report(runId);
  if (!report) { toast('No scan report to export yet.', 'warn'); return; }
  download(`omnishield-scan-${report.run.id}.json`, JSON.stringify(report, null, 2));
  toast('Scan report downloaded (findings only — no file contents).', 'ok');
}

async function runScan() {
  if (!state.scanner || state.scanner.running) return;
  const enabled = scanEnabledModules();
  const modules = Object.entries(enabled).filter(([, on]) => on).map(([id]) => id);
  if (!modules.length) { toast('Select at least one module to scan.', 'warn'); return; }
  state.scanTrace = [];
  state.scanner.onProgress((event) => {
    if (event.type === 'progress') {
      state.scanTrace.push(`${new Date().toLocaleTimeString()} · ${event.run.phase} · ${Math.round(event.run.progress * 100)}%`);
      state.scanRun = event.run;
      if (state.currentPage === 'scan') renderScan();
    } else if (event.type === 'done') {
      state.scanTrace.push(`${new Date().toLocaleTimeString()} · ${event.run.status} · ${event.run.summary.findings} finding(s)`);
      state.scanRun = event.run;
      if (state.currentPage === 'scan') renderScan();
    }
  });

  const urls = new Set();
  for (const task of state.downloads?.list() || []) if (task.url) urls.add(task.url);
  const mediaInput = document.getElementById('media-url')?.value?.trim();
  if (mediaInput) urls.add(mediaInput);
  const searchInput = document.getElementById('search-input')?.value?.trim();
  if (searchInput && /^https?:\/\//i.test(searchInput)) urls.add(searchInput);

  try {
    const configuration = await collectScanConfiguration();
    const run = await state.scanner.run({
      modules,
      files: state.scanFiles,
      urls: [...urls],
      configuration: modules.includes('configuration') ? configuration : null
    });
    state.scanRun = run;
    const worst = run.summary.counts.critical + run.summary.counts.high;
    toast(`Scan ${run.status}: ${plural(run.summary.findings, 'finding')}${worst ? `, ${worst} high or critical` : ''}.`, worst ? 'warn' : 'ok');
    renderScan();
    return run;
  } catch (error) {
    toast(`Scan failed: ${error.message}`, 'bad');
    renderScan();
    return null;
  }
}

/** Walks a dropped item list, including folders, without leaving the page. */
async function collectDroppedFiles(transfer) {
  const items = transfer?.items ? [...transfer.items] : [];
  const entries = items
    .map((item) => (typeof item.webkitGetAsEntry === 'function' ? item.webkitGetAsEntry() : null))
    .filter(Boolean);
  if (!entries.length) return [...(transfer?.files || [])];

  const files = [];
  const walk = async (entry, prefix = '') => {
    if (!entry) return;
    if (entry.isFile) {
      const file = await new Promise((resolve) => entry.file(resolve, () => resolve(null)));
      if (file) {
        try { Object.defineProperty(file, '__path', { value: `${prefix}${file.name}`, configurable: true }); } catch { /* read-only in some engines */ }
        files.push(file);
      }
      return;
    }
    if (entry.isDirectory) {
      const reader = entry.createReader();
      for (;;) {
        const batch = await new Promise((resolve) => reader.readEntries(resolve, () => resolve([])));
        if (!batch.length) break;
        for (const child of batch) await walk(child, `${prefix}${entry.name}/`);
      }
    }
  };
  for (const entry of entries) await walk(entry);
  return files.length ? files : [...(transfer?.files || [])];
}

function addScanFiles(files) {
  const list = [...files].filter(Boolean);
  if (!list.length) return;
  const tooBig = list.filter((file) => file.size > MAX_FILE_BYTES);
  const accepted = list.filter((file) => file.size <= MAX_FILE_BYTES);
  if (tooBig.length) {
    toast(`${plural(tooBig.length, 'file')} skipped — the queue accepts files up to ${MAX_FILE_LABEL} (largest was ${bytes(Math.max(...tooBig.map((f) => f.size)))}).`, 'warn');
  }
  if (!accepted.length) { renderScan(); return; }
  state.scanFiles = [...state.scanFiles, ...accepted].slice(0, 2000);
  toast(`${plural(accepted.length, 'file')} added to the scan queue (${plural(state.scanFiles.length, 'file')} queued).`, 'ok');
  renderScan();
}

/* ------------------------------------------------------------------ */
/* Private search                                                      */
/* ------------------------------------------------------------------ */

function renderSearch() {
  const provider = searchProvider(state.search.provider);

  mount('#search-engine-pill', h('span', { text: provider.name }));
  mount('#search-engines', SEARCH_PROVIDERS.map((entry) => h('div', {
    class: 'engine-card',
    role: 'button',
    tabindex: '0',
    'aria-pressed': String(entry.id === provider.id),
    onclick: () => selectSearchProvider(entry.id),
    onkeydown: (event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); selectSearchProvider(entry.id); } }
  },
    h('h4', { text: entry.name }),
    h('p', { text: entry.privacy })
  )));

  const kinds = ['web', 'images', 'videos', 'news', 'maps'];
  mount('#search-kinds', kinds.map((kind) => h('button', {
    type: 'button',
    class: 'chip',
    'aria-pressed': String(state.search.kind === kind),
    disabled: kind !== 'web' && provider.kinds?.[kind] === null,
    text: provider.kinds?.[kind] === null ? `${kind} · not offered by ${provider.name}` : kind,
    onclick: () => { state.search.kind = kind; renderSearch(); }
  })));

  mount('#search-privacy',
    h('h2', { text: `${provider.name} — privacy position` }),
    kv([
      ['Query endpoint', h('span', { class: 'tiny mono', text: provider.search })],
      ['What the engine receives', provider.name === 'Google' ? 'your query, IP address and Google account cookies in the browser profile' : 'your query and the IP address of this connection'],
      ['Privacy stance', provider.privacy],
      ['Bangs', h('code', { text: `${provider.bang} query` }) ],
      ['Referrer', 'The query opens with noopener,noreferrer, so no referrer header is sent from this page.'],
      ['What is stored here', state.searchHistory?.enabled ? `${plural(state.searchHistory.entries.length, 'query', 'queries')} in this browser` : 'nothing — history is switched off']
    ]),
    note('Opening a third-party search page hands that engine your query and connection. This app cannot proxy it without a backend, and it does not pretend to: the link opens the engine you chose, stripped of tracking parameters.', 'warn')
  );

  const history = state.searchHistory || new SearchHistory({});
  mount('#search-history',
    h('h2', { text: 'Search history (this device only)' }),
    h('div', { class: 'row' },
      h('button', {
        type: 'button', class: 'sm', text: history.enabled ? 'Turn history off' : 'Turn history on',
        onclick: async () => {
          await history.setEnabled(!history.enabled);
          toast(history.enabled ? 'Search history enabled (stored locally).' : 'Search history disabled and cleared.', 'ok');
          renderSearch();
        }
      }),
      h('button', {
        type: 'button', class: 'danger sm', text: 'Clear history',
        onclick: async () => { await history.clear(); renderSearch(); toast('Search history cleared.', 'ok'); }
      }),
      pill(history.enabled ? 'enabled' : 'disabled', history.enabled ? 'ok' : 'info')
    ),
    table(['Query', 'Engine', 'When'], history.entries.slice(0, 20).map((entry) => [
      h('a', { href: buildSearchUrl(entry.provider, entry.query), target: '_blank', rel: 'noopener noreferrer', text: entry.query }),
      searchProvider(entry.provider).name,
      relativeTime(entry.at)
    ]), { emptyText: history.enabled ? 'No searches yet.' : 'History is switched off — nothing is recorded.' })
  );
}

async function selectSearchProvider(id) {
  state.search.provider = id;
  try { await state.storage.setItem('search:provider', id); } catch { /* preference is best-effort */ }
  renderSearch();
}

async function runSearch({ instant = false, clean = false } = {}) {
  const input = document.getElementById('search-input');
  const raw = input?.value || '';
  const parsedBang = resolveBang(raw);
  if (parsedBang.provider && parsedBang.provider !== state.search.provider) await selectSearchProvider(parsedBang.provider);
  const query = sanitizeQuery(parsedBang.query);
  const out = document.getElementById('search-out');

  if (clean) {
    const result = stripTracking(query);
    if (!result.ok) {
      mount(out, note(`“${query}” is not a valid URL, so there was nothing to clean. Paste a full link with http(s)://.`, 'warn'));
      return;
    }
    mount(out, note(result.removed.length
      ? `Removed ${result.removed.length} tracking parameter(s): ${result.removed.join(', ')}.`
      : 'No tracking parameters found in that URL.', result.removed.length ? 'ok' : 'info'),
    h('p', { class: 'small' }, h('a', { href: result.url, target: '_blank', rel: 'noopener noreferrer', text: result.url })));
    return;
  }

  if (!query) { mount(out, note('Type something to search for.', 'warn')); return; }

  if (instant) {
    await runInstantAnswer(query);
    return;
  }

  let url;
  try {
    url = buildSearchUrl(state.search.provider, query, { kind: state.search.kind });
  } catch (error) {
    mount(out, note(error.message, 'warn'));
    return;
  }
  state.search.lastQuery = query;
  state.search.lastUrl = url;
  await state.searchHistory?.record(query, state.search.provider);
  const opened = openSearch(url, window);
  mount(out,
    opened.opened
      ? note(`Opened ${searchProvider(state.search.provider).name} in a new tab.`, 'ok')
      : note(`${opened.reason}. Open it manually:`, 'warn'),
    h('p', { class: 'small' }, h('a', { href: url, target: '_blank', rel: 'noopener noreferrer', text: url })),
    h('div', { class: 'row', style: { marginTop: '8px' } },
      h('button', { type: 'button', class: 'sm', text: 'Inspect this query in AETHER', onclick: () => {
        const aetherInput = document.getElementById('aether-input');
        if (aetherInput) { aetherInput.value = query; }
        navigate('aether');
        analyseDomain(query);
      } }),
      h('button', { type: 'button', class: 'sm', text: 'Scan the URL', onclick: () => {
        const result = scanUrl(url);
        mount(out, note(`URL check: ${result.level} (${result.score}/100) — ${result.findings.map((f) => f.label).join('; ')}`, result.level === 'clean' ? 'ok' : 'warn'));
      } })
    )
  );
  renderSearch();
}

async function runInstantAnswer(query) {
  const out = document.getElementById('search-out');
  const box = document.getElementById('search-answer');
  mount(box, h('h2', { text: 'Instant answer' }), h('p', { class: 'small muted', text: 'Asking DuckDuckGo…' }));
  const result = await instantAnswer(query);
  if (!result.ok) {
    mount(box, h('h2', { text: 'Instant answer' }),
      note(`No in-app answer: ${result.error}`, 'warn'),
      h('p', { class: 'small muted', text: 'The full search still works in a new tab — use Search above.' }));
    mount(out, note('In-app answers come from the DuckDuckGo Instant Answer API, which allows cross-origin reads. When it cannot be reached, nothing is shown rather than a guess.', 'warn'));
    return;
  }
  if (!result.hasContent) {
    mount(box, h('h2', { text: 'Instant answer' }),
      note('DuckDuckGo has no instant answer for that query. That is an empty result, not an error.', 'info'));
    return;
  }
  mount(box,
    h('h2', { text: result.heading || 'Instant answer' }),
    result.answer ? h('p', { text: result.answer }) : null,
    result.definition ? h('p', { text: result.definition }) : null,
    result.sourceUrl ? h('p', { class: 'small' }, h('a', { href: result.sourceUrl, target: '_blank', rel: 'noopener noreferrer', text: result.source || result.sourceUrl })) : null,
    result.topics.length ? h('ul', { style: { paddingLeft: '18px', marginTop: '8px' } }, result.topics.map((topic) =>
      h('li', { class: 'small' }, h('a', { href: topic.url, target: '_blank', rel: 'noopener noreferrer', text: topic.title })))) : null,
    h('p', { class: 'tiny muted', style: { marginTop: '8px' }, text: `${result.endpoint} · fetched ${relativeTime(result.fetchedAt)} · passed through no proxy` })
  );
  mount(out, note('Answer rendered from the DuckDuckGo Instant Answer API response above.', 'ok'));
}

/* ------------------------------------------------------------------ */
/* Private cloud box                                                   */
/* ------------------------------------------------------------------ */

const KIND_ICON = { image: '🖼', video: '🎬', audio: '🎵', document: '📄', archive: '🗜', other: '📦' };

async function renderVault() {
  if (!state.vault) return;
  await state.vault.load();
  const view = state.vaultView;

  const lockPill = document.getElementById('vault-lock-pill');
  if (lockPill) {
    lockPill.className = `pill ${state.vault.locked ? (state.vault.unlocked ? 'ok' : 'warn') : 'info'}`;
    lockPill.textContent = state.vault.locked ? (state.vault.unlocked ? 'locked · unlocked this session' : 'locked') : 'unlocked';
  }
  const lockButton = document.getElementById('vault-lock');
  if (lockButton) lockButton.textContent = state.vault.locked ? 'Manage passphrase' : 'Set passphrase';

  const usage = await state.vault.usage();
  const quota = usage.estimate?.supported ? usage.estimate.quota : null;
  const bar = document.getElementById('vault-bar');
  if (bar) bar.style.width = `${quota ? Math.min(100, Math.round((usage.estimate.usage / quota) * 100)) : Math.min(100, Math.round((usage.bytes / (25 * 1024 * 1024)) * 100))}%`;
  mount('#vault-usage',
    h('span', { text: `${plural(usage.files, 'file')} · ${bytes(usage.bytes)} stored · ${quota ? `${bytes(usage.estimate.usage)} of ${bytes(quota)} browser quota in use` : 'browser did not report a quota (StorageManager.estimate unavailable)'} · backend: ${state.vault.storage.name}` }),
    state.vault.indexError ? note(state.vault.indexError, 'bad') : null
  );

  mount('#vault-folders',
    h('h2', { text: 'Folders' }),
    h('div', { style: { display: 'grid', gap: '4px' } }, state.vault.foldersList().map((folder) => h('button', {
      type: 'button',
      class: 'sm',
      style: { textAlign: 'left', borderColor: folder.path === view.folder ? 'var(--blue)' : '' },
      text: `${folder.path === '/' ? 'All files' : folder.path} (${folder.count})`,
      onclick: () => { view.folder = folder.path; renderVault(); }
    }))),
    state.vaultNewFolder
      ? h('div', { class: 'row', style: { marginTop: '10px' } },
        h('input', { type: 'text', id: 'vault-folder-name', placeholder: '/Photos/2026' }),
        h('button', { type: 'button', class: 'primary sm', text: 'Create', onclick: createVaultFolder }),
        h('button', { type: 'button', class: 'sm', text: 'Cancel', onclick: () => { state.vaultNewFolder = false; renderVault(); } }))
      : null
  );

  const kinds = ['image', 'video', 'audio', 'document', 'archive', 'other'];
  mount('#vault-kinds', [
    h('button', { type: 'button', class: 'chip', 'aria-pressed': String(!view.kind), text: 'all types', onclick: () => { view.kind = null; renderVault(); } }),
    ...kinds.map((kind) => h('button', {
      type: 'button', class: 'chip', 'aria-pressed': String(view.kind === kind),
      text: `${KIND_ICON[kind]} ${kind}`,
      onclick: () => { view.kind = view.kind === kind ? null : kind; renderVault(); }
    }))
  ]);

  const entries = state.vault.list({ folder: view.folder === '/' ? null : view.folder, kind: view.kind, query: view.query });
  mount('#vault-list',
    table(['Name', 'Type', 'Size', 'Folder', 'Added', 'Actions'], entries.map((entry) => [
      h('div', { class: 'file-row' },
        h('span', { class: 'file-ico', text: KIND_ICON[entry.kind] || '📦' }),
        h('button', { type: 'button', class: 'ghost', style: { padding: '0', border: 'none', color: 'var(--text)' }, text: entry.name, onclick: () => openVaultPreview(entry.id) })
      ),
      entry.kind + (entry.encrypted ? ' · encrypted' : ''),
      bytes(entry.size),
      entry.folder,
      relativeTime(entry.createdAt),
      h('div', { class: 'row', style: { gap: '6px' } },
        h('button', { type: 'button', class: 'sm', text: 'Preview', onclick: () => openVaultPreview(entry.id) }),
        h('button', { type: 'button', class: 'sm', text: 'Download', onclick: () => downloadVaultFile(entry.id) }),
        h('button', { type: 'button', class: 'sm', text: 'Verify', onclick: () => verifyVaultFile(entry.id) }),
        h('button', { type: 'button', class: 'sm danger', text: 'Delete', onclick: () => deleteVaultFile(entry.id) })
      )
    ]), { emptyText: view.query || view.kind || view.folder !== '/' ? 'Nothing matches this filter.' : 'The cloud box is empty. Add files to get started.' })
  );

  if (!state.vaultDetails) {
    mount('#vault-preview',
      h('h2', { text: 'Preview & file details' }),
      empty('Select a file to preview it, rename it, move it between folders or add tags.')
    );
  }
}

async function createVaultFolder() {
  const input = document.getElementById('vault-folder-name');
  try {
    const created = await state.vault.createFolder(input?.value || '');
    state.vaultNewFolder = false;
    state.vaultView.folder = created;
    toast(`Folder ${created} created.`, 'ok');
  } catch (error) {
    toast(`Could not create the folder: ${error.message}`, 'bad');
  }
  renderVault();
}

async function uploadToVault(files) {
  const list = [...files];
  if (!list.length) return;
  let stored = 0;
  const errors = [];
  for (const file of list) {
    try {
      await state.vault.put(file, { folder: state.vaultView.folder, source: 'upload' });
      stored += 1;
    } catch (error) {
      errors.push(`${file.name}: ${error.message}`);
    }
  }
  if (stored) toast(`${plural(stored, 'file')} added to the cloud box.`, 'ok');
  if (errors.length) toast(`${plural(errors.length, 'file')} not stored — ${errors[0]}`, 'bad');
  // Awaited: callers (and tests) may rely on the list already showing the new files.
  await renderVault();
}

async function openVaultPreview(id) {
  const entry = state.vault.get(id);
  if (!entry) return;
  if (state.vaultUrl) { state.vault.releaseUrl(state.vaultUrl); state.vaultUrl = null; }
  state.vaultDetails = entry;
  const box = document.getElementById('vault-preview');
  mount(box,
    h('h2', { text: `${KIND_ICON[entry.kind] || '📦'} ${entry.name}` }),
    kv([
      ['Type', `${entry.kind} · ${entry.mime}`],
      ['Size', bytes(entry.size)],
      ['Folder', entry.folder],
      ['Added', new Date(entry.createdAt).toLocaleString()],
      ['SHA-256', h('span', { class: 'tiny mono', text: entry.sha256 })],
      ['Encryption', entry.encrypted ? 'AES-GCM 256' : 'none (passphrase lock off when added)'],
      ['Tags', entry.tags.length ? entry.tags.join(', ') : '—'],
      ['Source', entry.source]
    ]),
    h('div', { id: 'vault-media', style: { marginTop: '10px' } }),
    h('h3', { text: 'Organise' }),
    h('div', { class: 'row' },
      h('input', { type: 'text', id: 'vault-rename-input', value: entry.name, 'aria-label': 'New name', style: { maxWidth: '260px' } }),
      h('button', { type: 'button', class: 'primary sm', text: 'Rename', onclick: () => renameVaultFile(entry.id) }),
      h('input', { type: 'text', id: 'vault-move-input', value: entry.folder, 'aria-label': 'Folder', style: { maxWidth: '200px' } }),
      h('button', { type: 'button', class: 'sm', text: 'Move', onclick: () => moveVaultFile(entry.id) }),
      h('input', { type: 'text', id: 'vault-tag-input', value: entry.tags.join(', '), 'aria-label': 'Tags', style: { maxWidth: '200px' } }),
      h('button', { type: 'button', class: 'sm', text: 'Save tags', onclick: () => tagVaultFile(entry.id) })
    )
  );

  const media = document.getElementById('vault-media');
  if (entry.size > 60 * 1024 * 1024 && ['video', 'audio'].includes(entry.kind)) {
    mount(media, note('This file is large; preview is skipped to keep the tab responsive. Use Download to save a copy.', 'info'));
    return;
  }
  try {
    const url = await state.vault.urlFor(entry.id);
    state.vaultUrl = url;
    if (entry.kind === 'image') mount(media, h('img', { src: url, alt: entry.name, class: 'media-thumb' }));
    else if (entry.kind === 'video') mount(media, h('video', { src: url, controls: 'controls', class: 'media-thumb' }));
    else if (entry.kind === 'audio') mount(media, h('audio', { src: url, controls: 'controls', style: { width: '100%' } }));
    else if (entry.kind === 'document' && /^text\/|json|xml/.test(entry.mime)) {
      const textBody = await (await state.vault.read(entry.id)).blob.text();
      mount(media, h('pre', { class: 'trace', text: textBody.slice(0, 4000) + (textBody.length > 4000 ? '\n… (truncated preview)' : '') }));
    } else if (entry.mime === 'application/pdf') {
      mount(media, h('iframe', { src: url, title: entry.name, style: { width: '100%', height: '420px', border: '1px solid var(--line-soft)', borderRadius: '12px' } }));
    } else {
      mount(media, note('No inline preview for this type. Download it to open it in your usual app.', 'info'));
    }
  } catch (error) {
    mount(media, note(`Preview failed: ${error.message}`, 'bad'));
  }
}

async function downloadVaultFile(id) {
  const entry = state.vault.get(id);
  if (!entry) return;
  try {
    const { blob } = await state.vault.read(id);
    const url = URL.createObjectURL(blob.type ? blob : new Blob([blob], { type: entry.mime }));
    const anchor = h('a', { href: url, download: entry.name });
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
    toast(`Saving ${entry.name}.`, 'ok');
  } catch (error) {
    toast(`Could not read ${entry.name}: ${error.message}`, 'bad');
  }
}

async function verifyVaultFile(id) {
  const result = await state.vault.verify(id);
  toast(result.ok ? `Verified ${state.vault.get(id)?.name}: ${result.note}.` : `Integrity failure on ${state.vault.get(id)?.name}: ${result.error}`, result.ok ? 'ok' : 'bad');
}

async function deleteVaultFile(id) {
  const entry = state.vault.get(id);
  if (!entry) return;
  if (!confirm(`Delete “${entry.name}” from the cloud box? This cannot be undone.`)) return;
  await state.vault.remove(id);
  if (state.vaultDetails?.id === id) { state.vaultDetails = null; if (state.vaultUrl) { state.vault.releaseUrl(state.vaultUrl); state.vaultUrl = null; } }
  toast(`${entry.name} deleted.`, 'ok');
  renderVault();
}

async function renameVaultFile(id) {
  const value = document.getElementById('vault-rename-input')?.value;
  try { await state.vault.rename(id, value); toast('Renamed.', 'ok'); state.vaultDetails = state.vault.get(id); renderVault(); await openVaultPreview(id); } catch (error) { toast(error.message, 'bad'); }
}

async function moveVaultFile(id) {
  const value = document.getElementById('vault-move-input')?.value;
  try { await state.vault.move(id, value); toast('Moved.', 'ok'); state.vaultDetails = state.vault.get(id); renderVault(); await openVaultPreview(id); } catch (error) { toast(error.message, 'bad'); }
}

async function tagVaultFile(id) {
  const value = (document.getElementById('vault-tag-input')?.value || '').split(',');
  try { await state.vault.tag(id, value); toast('Tags saved.', 'ok'); renderVault(); await openVaultPreview(id); } catch (error) { toast(error.message, 'bad'); }
}

function renderVaultLockForm() {
  const box = document.getElementById('vault-preview');
  const vault = state.vault;
  if (vault.locked && !vault.unlocked) {
    mount(box, h('h2', { text: 'Unlock the cloud box' }),
      h('div', { class: 'row' }, h('input', { type: 'password', id: 'vault-pass', placeholder: 'Passphrase', 'aria-label': 'Passphrase' }),
        h('button', { type: 'button', class: 'primary', text: 'Unlock', onclick: async () => {
          try { await vault.unlock(document.getElementById('vault-pass')?.value || ''); toast('Cloud box unlocked for this session.', 'ok'); renderVault(); }
          catch (error) { toast(error.message, 'bad'); }
        } })));
    return;
  }
  mount(box, h('h2', { text: 'Passphrase lock (AES-GCM 256)' }),
    h('p', { class: 'small muted', text: 'Files added while the lock is on are encrypted with a key derived from your passphrase (PBKDF2-SHA256, 210 000 iterations). There is no recovery: if the passphrase is lost the encrypted files cannot be read.' }),
    h('div', { class: 'row' },
      h('input', { type: 'password', id: 'vault-pass', placeholder: vault.locked ? 'Current passphrase' : 'New passphrase (8+ characters)', 'aria-label': 'Passphrase' }),
      h('input', { type: 'password', id: 'vault-pass2', placeholder: 'Repeat', 'aria-label': 'Repeat passphrase' }),
      h('button', { type: 'button', class: 'primary', text: vault.locked ? 'Unlock / change' : 'Enable lock', onclick: async () => {
        const first = document.getElementById('vault-pass')?.value || '';
        const second = document.getElementById('vault-pass2')?.value || '';
        try {
          if (vault.locked) await vault.unlock(first);
          if (first !== second) throw new Error('The two passphrases do not match.');
          await vault.setPassphrase(first);
          toast('Passphrase lock enabled — new files are encrypted.', 'ok');
          renderVault();
        } catch (error) { toast(error.message, 'bad'); }
      } }),
      vault.locked ? h('button', { type: 'button', class: 'danger', text: 'Remove lock (decrypts files)', onclick: async () => {
        const pass = document.getElementById('vault-pass')?.value || '';
        try { await vault.removePassphrase(pass); toast('Lock removed; stored files were decrypted.', 'warn'); renderVault(); }
        catch (error) { toast(error.message, 'bad'); }
      } }) : null,
      vault.locked ? h('button', { type: 'button', text: 'Lock now', onclick: () => { vault.lock(); toast('Cloud box locked.', 'ok'); renderVault(); } }) : null
    ));
}

/* ------------------------------------------------------------------ */
/* Media downloader                                                    */
/* ------------------------------------------------------------------ */

function persistDownloadHistory() {
  if (!state.downloads) return;
  const tasks = state.downloads.list().slice(0, 60).map((task) => ({
    id: task.id, url: task.url, name: task.name, status: task.status, size: task.size,
    received: task.received, format: task.format, platform: task.platform, sha256: task.sha256,
    error: task.error, finishedAt: task.finishedAt, updatedAt: task.updatedAt
  }));
  Promise.resolve(state.storage?.setItem('media:history', JSON.stringify(tasks))).catch(() => {});
}

async function restoreDownloadHistory() {
  try {
    const raw = await state.storage.getItem('media:history');
    if (!raw) return;
    const tasks = JSON.parse(raw);
    if (!Array.isArray(tasks)) return;
    for (const task of tasks) {
      if (!task?.id || !task.url) continue;
      state.downloads.tasks.set(task.id, { ...task, status: task.status === 'downloading' ? 'interrupted' : task.status });
    }
  } catch { /* history is a convenience, not a contract */ }
}

function renderMedia() {
  if (!state.downloads) return;
  const draft = state.mediaDraft;
  const out = document.getElementById('media-out');
  if (out && draft) {
    const platform = draft.parsed.platform;
    const fetchable = !!draft.parsed.direct;
    // Three honest states: permitted and fetchable · permitted but needs an
    // authorised link we cannot obtain in a browser · not permitted at all.
    const status = fetchable
      ? pill('download permitted', 'ok')
      : platform.directDownload
        ? pill('needs the uploader\'s authorised link', 'warn')
        : pill('download not permitted', 'bad');
    const explanation = fetchable ? null : platform.directDownload
      ? note(`${platform.reason || 'This platform only serves media through an authorised link.'} ${platform.alternative ? `Alternative: ${platform.alternative}` : ''}`, 'warn')
      : note(`${platform.reason || 'This platform does not permit third-party downloads.'} ${platform.alternative ? `Alternative: ${platform.alternative}` : ''}`, 'warn');

    mount(out,
      h('div', { class: 'row', style: { justifyContent: 'space-between' } },
        h('h3', { style: { margin: '0' }, text: `${platform.name}${draft.parsed.id ? ` · ${draft.parsed.id}` : ''}` }),
        status),
      explanation,
      draft.probe && draft.probe.ok ? kv([
        ['Title', draft.probe.title || '—'],
        ['Author', draft.probe.author || '—'],
        ['Duration', draft.probe.durationSeconds ? `${Math.floor(draft.probe.durationSeconds / 60)}m ${draft.probe.durationSeconds % 60}s` : '—'],
        ['Metadata source', draft.probe.source]
      ]) : draft.probe && !draft.probe.ok ? h('p', { class: 'small muted', text: `Metadata: ${draft.probe.error}` }) : null,
      draft.remote ? h('p', { class: 'small', style: { marginTop: '8px' }, text: draft.remote.ok
        ? `Pre-flight: ${bytes(draft.remote.size ?? 0)} · ${draft.remote.type || 'type unknown'} · ${draft.remote.resumable ? 'resumable (Range supported)' : 'no range support — a pause restarts the transfer'}`
        : `Pre-flight: ${draft.remote.error}` }) : null,
      draft.probe?.ok && draft.probe.thumbnail ? h('img', { src: draft.probe.thumbnail, alt: 'thumbnail', class: 'media-thumb', style: { marginTop: '10px' } }) : null,
      h('div', { style: { marginTop: '12px' } },
        h('h4', { class: 'small', text: 'Choose a format' }),
        h('div', { class: 'chips', id: 'media-formats' }, (draft.probe?.formats || []).map((format) => h('button', {
          type: 'button', class: 'chip', 'aria-pressed': String(draft.format?.id === format.id),
          text: format.resolution ? `${format.container.toUpperCase()} ${format.resolution}` : `${format.container.toUpperCase()} ${format.bitrateKbps} kbps`,
          onclick: () => { draft.format = format; renderMedia(); }
        }))),
        h('p', { class: 'tiny muted', style: { marginTop: '6px' }, text: 'Formats are the container/resolution ladder the platform publishes and the choice is recorded against the transfer. The browser stores the bytes the server actually sends; it does not transcode.' }),
        fetchable
          ? h('p', { class: 'tiny muted', text: `Destination: your cloud box, folder /Downloads · file ${draft.parsed.canonical.split('/').pop()?.split('?')[0] || 'download'}` })
          : h('p', { class: 'tiny muted', text: 'No transfer can be started for this URL — the Download button stays disabled on purpose.' })
      )
    );
  }
  const addButton = document.getElementById('media-add');
  if (addButton) addButton.disabled = !draft || !draft.parsed.direct || state.downloads.get(draft.taskId || '')?.status === 'downloading';
  renderMediaTransfers();
}

function renderMediaTransfers() {
  if (!state.downloads) return;
  const tasks = state.downloads.list();
  const stats = state.downloads.stats();
  mount('#media-progress-pill', h('span', { text: stats.active ? `${stats.active} active` : `${stats.done} complete` }));
  const active = tasks.find((task) => task.status === 'downloading');
  const bar = document.getElementById('media-bar');
  if (bar) bar.style.width = `${active && active.size ? Math.min(100, Math.round((active.received / active.size) * 100)) : 0}%`;

  mount('#media-list',
    table(['File', 'Platform', 'Size', 'Progress', 'Status', 'Actions'], tasks.map((task) => [
      h('span', { class: 'small mono-ellipsis', title: task.name, text: task.name }),
      task.platform || 'direct',
      task.size ? bytes(task.size) : bytes(task.received),
      h('div', { style: { minWidth: '110px' } },
        h('div', { class: 'track', style: { margin: '0' } }, h('i', { style: { width: `${task.size ? Math.min(100, Math.round((task.received / task.size) * 100)) : (task.status === 'done' ? 100 : 0)}%` } })),
        h('span', { class: 'tiny muted', text: `${bytes(task.received)}${task.size ? ` / ${bytes(task.size)}` : ''}` })),
      pill(task.status, task.status === 'done' ? 'ok' : task.status === 'failed' || task.status === 'cancelled' ? 'bad' : task.status === 'paused' || task.status === 'interrupted' ? 'warn' : 'info'),
      h('div', { class: 'row', style: { gap: '6px' } },
        ['paused', 'queued', 'interrupted', 'failed'].includes(task.status) ? h('button', { type: 'button', class: 'sm', text: 'Resume', onclick: () => resumeDownload(task.id) }) : null,
        task.status === 'downloading' ? h('button', { type: 'button', class: 'sm', text: 'Pause', onclick: () => { state.downloads.pause(task.id); renderMediaTransfers(); } }) : null,
        ['downloading', 'paused', 'queued'].includes(task.status) ? h('button', { type: 'button', class: 'sm danger', text: 'Cancel', onclick: () => { state.downloads.cancel(task.id); persistDownloadHistory(); renderMediaTransfers(); } }) : null,
        h('button', { type: 'button', class: 'sm', text: 'Remove', onclick: () => { state.downloads.remove(task.id); persistDownloadHistory(); renderMediaTransfers(); } })
      )
    ]), { emptyText: 'No transfers yet. Check a URL above, then press Download.' })
  );

  mount('#media-history',
    h('h2', { text: 'Download history (this device)' }),
    table(['When', 'File', 'Result', 'SHA-256'], tasks.filter((task) => ['done', 'failed', 'cancelled'].includes(task.status)).map((task) => [
      relativeTime(task.finishedAt || task.updatedAt),
      h('span', { class: 'small mono-ellipsis', text: task.name }),
      task.status === 'done' ? pill('saved to cloud box', 'ok') : pill(task.error ? `${task.status}: ${task.error}` : task.status, 'bad'),
      h('span', { class: 'tiny mono', text: task.sha256 ? `${task.sha256.slice(0, 16)}…` : '—' })
    ]), { emptyText: 'No finished transfers yet.' }),
    h('p', { class: 'small muted', style: { marginTop: '8px' }, text: 'Only sources that permit downloading are fetched. Every entry above is a real transfer attempt and its real outcome.' })
  );
}

async function checkMediaUrl() {
  const input = document.getElementById('media-url');
  const button = document.getElementById('media-check');
  const out = document.getElementById('media-out');
  const parsed = parseMediaUrl(input?.value || '');
  if (!parsed.ok) {
    state.mediaDraft = null;
    mount(out, note(parsed.error, 'warn'));
    renderMedia();
    return;
  }
  state.mediaDraft = { parsed, probe: null, remote: null, format: null, taskId: null };
  setBusy(button, true, 'Checking…');
  renderMedia();
  try {
    const probe = await probeMedia(parsed);
    state.mediaDraft.probe = probe;
    const formats = probe.formats || [];
    state.mediaDraft.format = formats[0] || null;
    if (parsed.direct) {
      state.mediaDraft.remote = await inspectRemote(parsed.canonical);
    }
  } catch (error) {
    state.mediaDraft.probe = { ok: false, error: error.message };
  } finally {
    setBusy(button, false);
  }
  renderMedia();
}

async function startDownload(taskId) {
  const task = state.downloads.get(taskId);
  if (!task) return;
  const result = await state.downloads.start(taskId);
  persistDownloadHistory();
  renderMediaTransfers();
  if (result.status === 'done') toast(`${result.name} saved to the cloud box (${bytes(result.received)}).`, 'ok');
  else if (result.status === 'failed') toast(`Download failed: ${result.error}`, 'bad');
  else if (result.status === 'paused') toast('Download paused — Resume continues from the saved byte offset when the server supports ranges.', 'warn');
}

async function resumeDownload(taskId) {
  const task = state.downloads.get(taskId);
  if (!task) return;
  task.status = 'queued';
  renderMediaTransfers();
  await startDownload(taskId);
}

async function addMediaDownload() {
  const draft = state.mediaDraft;
  if (!draft || !draft.parsed.direct) { toast('That source does not permit downloading.', 'warn'); return; }
  const name = decodeURIComponent(draft.parsed.canonical.split('/').pop().split('?')[0] || 'download.bin');
  const task = state.downloads.add({
    url: draft.parsed.canonical,
    name,
    format: draft.format?.id || null,
    kind: draft.parsed.kind,
    size: draft.remote?.size ?? null,
    resumable: draft.remote?.resumable ?? null,
    platform: draft.parsed.platform.id,
    destination: '/Downloads'
  });
  draft.taskId = task.id;
  renderMedia();
  await startDownload(task.id);
}

/* ------------------------------------------------------------------ */
/* Wiring for the v5.1 screens                                         */
/* ------------------------------------------------------------------ */

function wireNewFeatures() {
  // --- scanner
  const scanFiles = document.getElementById('scan-files');
  const scanFolder = document.getElementById('scan-folder');
  const scanDrop = document.getElementById('scan-drop');
  document.getElementById('scan-pick')?.addEventListener('click', () => scanFiles?.click());
  document.getElementById('scan-pick-folder')?.addEventListener('click', () => scanFolder?.click());
  scanFiles?.addEventListener('change', (event) => { addScanFiles(event.target.files || []); event.target.value = ''; });
  scanFolder?.addEventListener('change', (event) => { addScanFiles(event.target.files || []); event.target.value = ''; });
  document.getElementById('scan-run')?.addEventListener('click', runScan);
  document.getElementById('scan-stop')?.addEventListener('click', () => { state.scanner?.stop(); toast('Stopping after the current file.', 'warn'); });
  document.getElementById('scan-report')?.addEventListener('click', () => downloadScanReport());

  if (scanDrop) {
    const over = (event) => { event.preventDefault(); scanDrop.classList.add('over'); };
    const leave = () => scanDrop.classList.remove('over');
    scanDrop.addEventListener('dragover', over);
    scanDrop.addEventListener('dragenter', over);
    scanDrop.addEventListener('dragleave', leave);
    scanDrop.addEventListener('drop', async (event) => {
      event.preventDefault();
      leave();
      const dropped = await collectDroppedFiles(event.dataTransfer);
      addScanFiles(dropped);
    });
  }

  // --- search
  document.getElementById('search-go')?.addEventListener('click', () => runSearch());
  document.getElementById('search-instant')?.addEventListener('click', () => runSearch({ instant: true }));
  document.getElementById('search-clean')?.addEventListener('click', () => runSearch({ clean: true }));
  const searchInput = document.getElementById('search-input');
  searchInput?.addEventListener('keydown', (event) => { if (event.key === 'Enter') { event.preventDefault(); runSearch(); } });

  // --- vault
  const vaultFiles = document.getElementById('vault-files');
  document.getElementById('vault-upload')?.addEventListener('click', () => vaultFiles?.click());
  vaultFiles?.addEventListener('change', async (event) => { await uploadToVault(event.target.files || []); event.target.value = ''; });
  document.getElementById('vault-new-folder')?.addEventListener('click', () => { state.vaultNewFolder = true; renderVault(); });
  document.getElementById('vault-lock')?.addEventListener('click', () => { renderVaultLockForm(); });
  document.getElementById('vault-manifest')?.addEventListener('click', () => {
    const manifest = state.vault.manifest();
    download('omnishield-vault-manifest.json', JSON.stringify(manifest, null, 2));
    toast('Manifest exported (file names and hashes — no contents).', 'ok');
  });
  document.getElementById('vault-wipe')?.addEventListener('click', async () => {
    if (!confirm('Delete every file in the cloud box? This cannot be undone.')) return;
    const result = await state.vault.destroy();
    toast(`${plural(result.removed, 'file')} deleted.`, 'ok');
    state.vaultDetails = null;
    renderVault();
  });
  document.getElementById('vault-filter')?.addEventListener('input', (event) => {
    state.vaultView.query = event.target.value;
    renderVault();
  });

  // --- media
  document.getElementById('media-check')?.addEventListener('click', checkMediaUrl);
  document.getElementById('media-add')?.addEventListener('click', addMediaDownload);
  document.getElementById('media-url')?.addEventListener('keydown', (event) => { if (event.key === 'Enter') { event.preventDefault(); checkMediaUrl(); } });
}

/* ------------------------------------------------------------------ */
/* Status helpers                                                      */
/* ------------------------------------------------------------------ */

function updateNetworkStatus() {
  const el = document.getElementById('net-status');
  if (!el) return;
  ui.clear(el);
  const online = navigator.onLine;
  el.className = `pill ${online ? 'ok' : 'warn'}`;
  el.appendChild(h('span', { class: 'dot' }));
  el.appendChild(document.createTextNode(online ? ' network available' : ' offline — bundled rules active'));
}

function updateOnlineStatus() {
  updateNetworkStatus();
  if (!navigator.onLine || !state.settings.autoUpdateFeeds || !state.feeds) return;
  if (state.feedCheckScheduled) return;
  // Delayed so the first paint and the initial rule load are never competing with
  // multi-megabyte feed downloads on a slow connection.
  state.feedCheckScheduled = true;
  setTimeout(() => { checkFeedUpdatesQuietly().finally(() => { state.feedCheckScheduled = false; }); }, 15000);
}

async function checkFeedUpdatesQuietly() {
  if (state.feedCheckRunning) return;
  state.feedCheckRunning = true;
  try {
    for (const feed of FEED_REGISTRY) {
      try {
        const result = await state.feeds.update(feed.id);
        if (result.ok && result.changed) {
          const text = await state.feeds.content(feed.id);
          state.engine.loadFilterList(text, feed.category, feed.id);
          toast(`${feed.name} updated (${number(result.meta.rules)} rules).`, 'ok');
          renderDashboard();
        }
      } catch { /* stay on bundled rules */ }
    }
  } finally {
    state.feedCheckRunning = false;
  }
}

function registerServiceWorker() {
  if (!('serviceWorker' in navigator)) return;
  if (!/^https?:$/.test(location.protocol)) return;
  navigator.serviceWorker.register('sw.js').catch((err) => console.warn('service worker registration failed', err));
}

/* ------------------------------------------------------------------ */
/* Event wiring                                                        */
/* ------------------------------------------------------------------ */

function wireEvents() {
  const aetherInput = document.getElementById('aether-input');
  document.getElementById('aether-go').addEventListener('click', () => analyseDomain(aetherInput.value));
  aetherInput.addEventListener('keydown', (event) => { if (event.key === 'Enter') analyseDomain(aetherInput.value); });
  document.getElementById('aether-demo').addEventListener('click', () => {
    const shapes = ['ads.doubleclick.net', 'paypa1.com', 'secure-paypal-login.tk', 'accounts.google.com', 'my-random-blog.example'];
    const next = shapes[(Math.floor(Math.random() * shapes.length))];
    aetherInput.value = next;
    analyseDomain(next);
  });

  const dnsInput = document.getElementById('dns-input');
  document.getElementById('dns-go').addEventListener('click', resolveDomain);
  dnsInput.addEventListener('keydown', (event) => { if (event.key === 'Enter') resolveDomain(); });
  document.getElementById('dns-flush').addEventListener('click', () => {
    state.client.cache.clear();
    renderDnsCache();
    toast('DNS cache flushed.', 'ok');
  });

  document.getElementById('fw-selftest').addEventListener('click', runFirewallSelfTest);
  document.getElementById('fw-go').addEventListener('click', inspectFirewall);
  document.getElementById('fw-export').addEventListener('click', () => {
    const snapshot = state.firewall.snapshot();
    download('omnishield-firewall-observations.json', JSON.stringify({
      exportedAt: new Date().toISOString(),
      stats: snapshot.stats,
      note: 'Destination scale only; no payloads are ever captured.',
      observations: [...state.firewall.destinations.values()]
        .filter((d) => !d.domain.startsWith('parent:'))
        .map((d) => ({ domain: d.domain, app: d.app, count: d.count, firstSeen: d.firstSeen, lastSeen: d.lastSeen }))
    }, null, 2));
  });
  document.getElementById('fw-import').addEventListener('change', (event) => {
    const file = event.target.files?.[0];
    if (file) importFirewallLog(file);
  });

  document.getElementById('feeds-check').addEventListener('click', checkFeedUpdates);
  document.getElementById('feeds-verify').addEventListener('click', verifyFeeds);

  document.getElementById('privacy-export').addEventListener('click', () => {
    download('omnishield-analytics.json', state.analytics.exportJSON());
    toast('Aggregate report exported.', 'ok');
  });
  document.getElementById('privacy-clear').addEventListener('click', async () => {
    if (!confirm('Delete all locally stored analytics? This cannot be undone.')) return;
    await state.analytics.clear();
    renderPrivacy();
    toast('Analytics deleted.', 'ok');
  });

  document.getElementById('snapshot-save').addEventListener('click', () => saveSnapshot('manual', { silent: false }));
  document.getElementById('snapshot-recover').addEventListener('click', async () => {
    const result = await state.backups.recover();
    const status = document.getElementById('sync-status');
    if (result.ok) {
      mount(status, note(`Newest valid snapshot ${result.id} verified (${relativeTime(result.createdAt)}${result.skipped.length ? `, ${result.skipped.length} corrupt skipped` : ''}).`, 'ok'));
    } else {
      mount(status, note(`Recovery: ${result.reason}. ${result.detail || ''}`, 'warn'));
    }
  });

  document.getElementById('import-file').addEventListener('change', (event) => {
    const file = event.target.files?.[0];
    if (file) importAndroidBackup(file);
  });
  document.getElementById('import-btn').addEventListener('click', () => {
    const file = document.getElementById('import-file').files?.[0];
    if (!file) { mount('#import-status', note('Choose a JSON backup exported from the Android app first.', 'warn')); return; }
    importAndroidBackup(file);
  });
  document.getElementById('export-btn').addEventListener('click', exportMergedConfig);

  wireNewFeatures();
}

/* ------------------------------------------------------------------ */
/* Start                                                               */
/* ------------------------------------------------------------------ */

wireEvents();
const initial = location.hash.replace('#', '');
const ready = boot().then(() => {
  if (initial && PAGE_RENDERERS[initial]) navigate(initial);
  else navigate('dashboard');
  return state;
});

/**
 * Test/automation hook. Exposes the live application state and the boot promise
 * so the integration suite can drive the real UI instead of a mock of it.
 */
globalThis.__omnishield = {
  state,
  ready,
  navigate,
  renderAll,
  analyseDomain,
  resolveDomain,
  runFirewallSelfTest,
  checkFeedUpdates,
  saveSnapshot,
  buildState,
  startMonitorLoop,
  // v5.1 feature handles: the integration suite drives these exactly as the UI does.
  scanner: () => state.scanner,
  vault: () => state.vault,
  downloads: () => state.downloads,
  runScan,
  runSearch,
  checkMediaUrl,
  addMediaDownload,
  uploadToVault,
  openVaultPreview,
  selectSearchProvider,
  stop() {
    clearInterval(state.monitorTimer);
    try { state.power?.stop(); } catch { /* ignore */ }
  }
};
