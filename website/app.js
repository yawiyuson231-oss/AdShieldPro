/* OmniShield X Web Platform — dashboard logic (no servers; all processing local) */
import { OmniShieldFilterEngine } from './engine.js';

const state = { engine: null, loading: false, backup: null };

const ASSET_STATS = {
  core_max_ads: { rules: 176131, label: 'HaGeZi Multi Pro — Ads & Trackers', license: 'GPLv3' },
  core_max_threats: { rules: 191527, label: 'HaGeZi TIF mini — Malware/Phishing', license: 'GPLv3' },
  core_lite_ads: { rules: 79668, label: 'HaGeZi Light — entry-level fallback', license: 'GPLv3' }
};

function nav(id) {
  for (const section of document.querySelectorAll('.page')) section.hidden = section.id !== 'page-' + id;
  for (const b of document.querySelectorAll('nav button')) b.classList.toggle('active', b.dataset.page === id);
  if (id === 'checker') ensureEngineLoaded();
}

document.querySelectorAll('nav button').forEach(b => b.addEventListener('click', () => nav(b.dataset.page)));

function setStatus(el, text, cls) { el.textContent = text; el.className = 'status ' + (cls || ''); }

/* ---------------- Domain checker: the REAL engine, REAL rule files ---------------- */
async function ensureEngineLoaded() {
  if (state.engine || state.loading) return;
  state.loading = true;
  const status = document.getElementById('checker-status');
  setStatus(status, 'Loading the real production rule set (core_lite_ads, 79,668 rules)…');
  try {
    const engine = new OmniShieldFilterEngine();
    const res = await fetch('assets/core_lite_ads.txt');
    const text = await res.text();
    engine.loadFilterList(text, 'ADS', 'core_lite_ads');
    state.engine = engine;
    document.getElementById('stat-rules').textContent = engine.totalRules().toLocaleString();
    setStatus(status, `Loaded ${engine.totalRules().toLocaleString()} live rules — the same file the Android APK ships.`, 'ok');
  } catch (e) {
    setStatus(status, 'Rule file unavailable (open this site from the repo root or GitHub Pages).', 'warn');
  }
  state.loading = false;
}

document.getElementById('check-btn').addEventListener('click', () => {
  const input = document.getElementById('check-input');
  const out = document.getElementById('check-result');
  if (!state.engine) { ensureEngineLoaded(); return; }
  const verdict = state.engine.evaluate(input.value);
  out.className = 'verdict ' + (verdict.blocked ? 'blocked' : 'allowed');
  out.innerHTML = verdict.blocked
    ? `<strong>BLOCKED</strong> by ${verdict.source}${verdict.matched ? ` (rule: <code>${verdict.matched}</code>)` : ''} — domain: <code>${verdict.domain}</code>`
    : `<strong>ALLOWED</strong> — ${verdict.source} — domain: <code>${verdict.domain}</code>`;
});
document.getElementById('check-input').addEventListener('keydown', e => { if (e.key === 'Enter') document.getElementById('check-btn').click(); });

/* ---------------- Policy Sync: round-trips the Android backup JSON ---------------- */
document.getElementById('import-btn').addEventListener('click', () => {
  const file = document.getElementById('import-file').files[0];
  const status = document.getElementById('sync-status');
  if (!file) { setStatus(status, 'Choose a JSON backup exported from the Android app first.', 'warn'); return; }
  const reader = new FileReader();
  reader.onload = () => {
    try {
      const data = JSON.parse(reader.result);
      if (!Array.isArray(data.customRules)) throw new Error('not an OmniShield backup');
      state.backup = data;
      renderBackup(data);
      setStatus(status, `Loaded: ${data.customRules.length} custom rules, mode ${data.protectionMode?.title || data.protectionMode}, ${data.browserSiteExceptions?.length || 0} site exceptions, ${data.excludedAppPackages?.length || 0} app exclusions.`, 'ok');
    } catch (err) {
      setStatus(status, 'Import failed: ' + err.message, 'warn');
    }
  };
  reader.readAsText(file);
});

function renderBackup(data) {
  const tbody = document.getElementById('rules-body');
  tbody.innerHTML = '';
  for (const rule of data.customRules) {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${rule.rawPattern}</td><td>${rule.ruleType}</td><td>${rule.matchType}</td><td>${rule.isEnabled ? 'on' : 'off'}</td><td>${(rule.comment || '').slice(0, 40)}</td>`;
    tbody.appendChild(tr);
  }
  document.getElementById('sync-table-wrap').hidden = false;
  document.getElementById('export-btn').disabled = false;
}

document.getElementById('export-btn').addEventListener('click', () => {
  if (!state.backup) return;
  const blob = new Blob([JSON.stringify(state.backup, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'omnishield-x-config.json';
  a.click();
  URL.revokeObjectURL(a.href);
});

/* ---------------- Dashboard real numbers ---------------- */
const rows = document.getElementById('assets-body');
if (rows) {
  for (const [file, info] of Object.entries(ASSET_STATS)) {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td><code>${file}.txt</code></td><td>${info.label}</td><td>${info.rules.toLocaleString()}</td><td>${info.license}</td>`;
    rows.appendChild(tr);
  }
}
