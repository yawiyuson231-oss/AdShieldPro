// OmniShield X — extension service worker.
//
// Counts come from chrome.declarativeNetRequest.onRuleMatchedDebug, which is the
// only API that reports individual matched rules. It requires the
// "declarativeNetRequestFeedback" permission and is only available for unpacked /
// development installs — so this file never pretends a count exists when the API
// is missing: the popup asks what is actually supported and says so.

const sessionCounts = { total: 0 };
const countsSupported = typeof chrome !== 'undefined'
  && !!chrome.declarativeNetRequest
  && !!chrome.declarativeNetRequest.onRuleMatchedDebug;

if (countsSupported) {
  chrome.declarativeNetRequest.onRuleMatchedDebug.addListener((info) => {
    const tabId = info.request?.tabId ?? -1;
    sessionCounts[tabId] = (sessionCounts[tabId] || 0) + 1;
    sessionCounts.total += 1;
    // storage.session is best-effort: counts are diagnostics, not billing data.
    try { chrome.storage?.session?.set({ total: sessionCounts.total }); } catch { /* ignore */ }
  });
  chrome.tabs?.onRemoved?.addListener((tabId) => { delete sessionCounts[tabId]; });
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type === 'getCounts') {
    sendResponse({
      supported: countsSupported,
      tab: countsSupported ? (sessionCounts[msg.tabId] || 0) : null,
      total: countsSupported ? sessionCounts.total : null,
      reason: countsSupported
        ? null
        : 'The browser did not expose onRuleMatchedDebug (the count API needs an unpacked install with the declarativeNetRequestFeedback permission).'
    });
  }
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
