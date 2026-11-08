/** Packaged entry point: exactly the same monitor and tests, with no remote scripts or unrestricted native interface. */
import { WorldStore } from './store.js';
import { WorldMonitorView } from './view.js';
import { createStorage } from '../security/storage.js';
import { h, mount, note } from '../ui/dom.js';
import { safeUrl } from './model.js';
import { loadBackgroundSnapshot } from './native.js';

const store = new WorldStore({ storage: createStorage('omnishield-world-native') });
let view;
const ready = (async () => {
  try {
    await store.load();
    view = new WorldMonitorView(document.getElementById('world-embedded'), store);
    view.setActive(true);
  } catch (error) {
    mount('#world-embedded', h('h1', {}, 'World Monitor could not start'), note(error.message, 'bad'));
  }
  return store;
})();

// Native opening is explicit and restricted to public HTTPS URLs by both sides.
document.addEventListener('click', (event) => {
  const anchor = event.target.closest?.('a[href]');
  const bridge = globalThis.OmniWorldHost;
  if (!anchor || typeof bridge?.postMessage !== 'function' || !safeUrl(anchor.href)) return;
  event.preventDefault(); bridge.postMessage(JSON.stringify({ type: 'open', url: anchor.href }));
});
document.addEventListener('visibilitychange', () => {
  view?.setActive(document.visibilityState !== 'hidden');
  if (document.visibilityState !== 'hidden') loadBackgroundSnapshot(store);
});
window.addEventListener('pagehide', () => view?.setActive(false));
window.addEventListener('pageshow', () => view?.setActive(true));
// The test harness can inspect the real packaged application without a second UI implementation.
globalThis.__worldMonitor = { store, ready, get view() { return view; }, stop: () => view?.destroy() };
