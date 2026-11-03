// OmniShield X — service worker: real per-tab block counts from DNR events
const sessionCounts = {};
chrome.declarativeNetRequest.onRuleMatchedDebug.addListener((info) => {
  const tabId = info.request.tabId;
  sessionCounts[tabId] = (sessionCounts[tabId] || 0) + 1;
  const total = (sessionCounts.total || 0) + 1;
  sessionCounts.total = total;
  chrome.storage.session?.set({ total });
});
chrome.tabs.onRemoved.addListener((tabId) => delete sessionCounts[tabId]);
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg?.type === 'getCounts') {
    sendResponse({ tab: sessionCounts[msg.tabId] || 0, total: sessionCounts.total || 0 });
  }
  return true;
});
