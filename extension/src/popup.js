// OmniShield X — popup: shows measured counts, or an explicit reason they are absent.
const el = (id) => document.getElementById(id);

function render({ supported, tab, total, reason }) {
  if (supported) {
    el('tab').textContent = String(tab ?? 0);
    el('total').textContent = String(total ?? 0);
    el('note').textContent = 'Counted from this extension\'s own matched-rule events.';
    return;
  }
  el('tab').textContent = '—';
  el('total').textContent = '—';
  el('tab').classList.add('na');
  el('total').classList.add('na');
  el('note').textContent = reason || 'Per-tab counts are unavailable in this browser.';
}

try {
  chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
    chrome.runtime.sendMessage({ type: 'getCounts', tabId: tab?.id }, (res) => {
      if (chrome.runtime.lastError || !res) {
        render({ supported: false, reason: chrome.runtime.lastError?.message || 'No response from the service worker.' });
        return;
      }
      render(res);
    });
  });
} catch (err) {
  render({ supported: false, reason: err?.message || 'Extension APIs unavailable on this page.' });
}
