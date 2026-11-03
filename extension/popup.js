chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
  chrome.runtime.sendMessage({ type: 'getCounts', tabId: tab?.id }, (res) => {
    document.getElementById('tab').textContent = res?.tab ?? 0;
    document.getElementById('total').textContent = res?.total ?? 0;
  });
});
