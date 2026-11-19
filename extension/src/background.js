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

function persistCounts() {
  try {
    chrome.storage?.session?.set({ [STORAGE_KEY]: { ...sessionCounts }, total: sessionCounts.total });
  } catch { /* ignore */ }
}

if (countsSupported) {
  chrome.declarativeNetRequest.onRuleMatchedDebug.addListener((info) => {
    const tabId = info.request?.tabId ?? -1;
    sessionCounts[tabId] = (sessionCounts[tabId] || 0) + 1;
    sessionCounts.total += 1;
    // storage.session is best-effort: counts are diagnostics, not billing data.
    persistCounts();
  });
  chrome.tabs?.onRemoved?.addListener((tabId) => {
    delete sessionCounts[tabId];
    persistCounts();
  });
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

const DYNAMIC_RULE_ID_BASE = 900000;
const MAX_DYNAMIC_CUSTOM_RULES = 500;

async function syncDynamicCustomRules(customRules = { allow: [], block: [] }) {
  if (!chrome.declarativeNetRequest?.updateDynamicRules) return { ok: false, count: 0 };
  const allow = Array.isArray(customRules.allow) ? customRules.allow : [];
  const block = Array.isArray(customRules.block) ? customRules.block : [];

  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  const removeRuleIds = existing
    .map((r) => r.id)
    .filter((id) => id >= DYNAMIC_RULE_ID_BASE && id < DYNAMIC_RULE_ID_BASE + MAX_DYNAMIC_CUSTOM_RULES);

  const addRules = [];
  let nextId = DYNAMIC_RULE_ID_BASE;
  for (const domain of allow) {
    if (addRules.length >= MAX_DYNAMIC_CUSTOM_RULES) break;
    const clean = String(domain || '').trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
    if (!clean) continue;
    addRules.push({
      id: nextId++,
      priority: 100,
      action: { type: 'allow' },
      condition: { urlFilter: `||${clean}^`, resourceTypes: ['main_frame', 'sub_frame', 'script', 'image', 'xmlhttprequest', 'other'] }
    });
  }
  for (const domain of block) {
    if (addRules.length >= MAX_DYNAMIC_CUSTOM_RULES) break;
    const clean = String(domain || '').trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
    if (!clean) continue;
    addRules.push({
      id: nextId++,
      priority: 90,
      action: { type: 'block' },
      condition: { urlFilter: `||${clean}^`, resourceTypes: ['sub_frame', 'script', 'image', 'xmlhttprequest', 'ping', 'other'] }
    });
  }

  await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds, addRules });
  return { ok: true, count: addRules.length };
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type !== 'syncDynamicRules') return undefined;
  syncDynamicCustomRules(msg.rules)
    .then((res) => sendResponse(res))
    .catch((err) => sendResponse({ ok: false, count: 0, error: err?.message || 'dynamic rule sync failed' }));
  return true;
});
