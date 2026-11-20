// OmniShield X — extension service worker.
//
// Counts come from chrome.declarativeNetRequest.onRuleMatchedDebug, which is the
// only API that reports individual matched rules. It requires the
// "declarativeNetRequestFeedback" permission and is only available for unpacked /
// development installs — so this file never pretends a count exists when the API
// is missing: the popup asks what is actually supported and says so.

const STORAGE_KEY = 'sessionCounts';
const sessionCounts = { total: 0 };
const countsSupported = typeof chrome !== 'undefined'
  && !!chrome.declarativeNetRequest
  && !!chrome.declarativeNetRequest.onRuleMatchedDebug;

let hydratePromise = Promise.resolve();
if (countsSupported && chrome.storage?.session?.get) {
  hydratePromise = new Promise((resolve) => {
    try {
      chrome.storage.session.get([STORAGE_KEY, 'total'], (stored) => {
        const saved = stored?.[STORAGE_KEY];
        if (saved && typeof saved === 'object') {
          for (const [k, v] of Object.entries(saved)) {
            if (typeof v === 'number' && Number.isFinite(v) && v >= 0) {
              sessionCounts[k] = (sessionCounts[k] || 0) + v;
            }
          }
        } else if (typeof stored?.total === 'number' && Number.isFinite(stored.total)) {
          sessionCounts.total += stored.total;
        }
        resolve();
      });
    } catch { resolve(); }
  });
}

/**
 * Debounced writer.
 *
 * A single heavy page can match hundreds of rules a second, and the previous code
 * wrote the whole map to storage.session on *every* match — a write storm that
 * storage.session rate-limits, silently losing counts. Coalescing to one write per
 * 250 ms keeps the numbers accurate without the churn; the last write always lands
 * because the timer is trailing-edge.
 */
let persistTimer = null;
function persistCounts() {
  if (persistTimer !== null) return;
  persistTimer = setTimeout(() => {
    persistTimer = null;
    try {
      chrome.storage?.session?.set({ [STORAGE_KEY]: { ...sessionCounts }, total: sessionCounts.total });
    } catch { /* ignore */ }
  }, 250);
}

if (countsSupported) {
  chrome.declarativeNetRequest.onRuleMatchedDebug.addListener((info) => {
    const tabId = info.request?.tabId ?? -1;
    sessionCounts[tabId] = (sessionCounts[tabId] || 0) + 1;
    sessionCounts.total += 1;
    // storage.session is best-effort: counts are diagnostics, not billing data.
    persistCounts();
  });
  // MV3 service workers are terminated after ~30 s idle, so tab ids are recycled:
  // without this, a closed tab's count could reappear under a brand-new tab. Polling
  // (never tabs events) keeps the extension free of the "tabs" permission.
  const dropClosedTabs = () => {
    chrome.tabs?.query?.({}, (tabs) => {
      if (chrome.runtime?.lastError || !Array.isArray(tabs)) return;
      const live = new Set(tabs.map((tab) => tab.id));
      let changed = false;
      for (const key of Object.keys(sessionCounts)) {
        if (key === 'total') continue;
        if (!live.has(Number(key))) { delete sessionCounts[key]; changed = true; }
      }
      if (changed) persistCounts();
    });
  };
  setInterval(dropClosedTabs, 60_000);
  if (chrome.runtime?.onStartup) chrome.runtime.onStartup.addListener(dropClosedTabs);
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type !== 'getCounts') return undefined;
  hydratePromise.finally(() => {
    sendResponse({
      supported: countsSupported,
      tab: countsSupported ? (sessionCounts[msg.tabId] || 0) : null,
      total: countsSupported ? sessionCounts.total : null,
      reason: countsSupported
        ? null
        : 'The browser did not expose onRuleMatchedDebug (the count API needs an unpacked install with the declarativeNetRequestFeedback permission).'
    });
  });
  return true;
});

// Report the rule count the browser actually indexed, so the popup can show a
// measured number instead of a claimed one.
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type !== 'getRulesets') return undefined;
  const ids = chrome.declarativeNetRequest?.getEnabledRulesets
    ? chrome.declarativeNetRequest.getEnabledRulesets()
    : Promise.resolve([]);
  Promise.resolve(ids)
    .then((enabled) => sendResponse({ enabled: enabled || [] }))
    .catch((err) => sendResponse({ enabled: [], error: err?.message || 'ruleset query failed' }));
  return true;
});
