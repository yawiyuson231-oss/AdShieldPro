/** Workspace navigation, keyboard command finder and persistent colour theme. */
import { h, mount } from './dom.js';
import { icon } from './icons.js';

const GLYPHS = { dashboard: 'grid', world: 'globe', aether: 'spark', dns: 'network', firewall: 'shield', monitor: 'activity', feeds: 'layers', privacy: 'lock', sync: 'cloud', extension: 'extension', status: 'check' };
export function setupShell(navigate) {
  const pages = [...document.querySelectorAll('nav.tabs button[data-page]')].map((b) => ({ id: b.dataset.page, name: b.textContent.trim() }));
  for (const b of document.querySelectorAll('nav.tabs button[data-page]')) b.prepend(icon(GLYPHS[b.dataset.page]));
  const theme = document.getElementById('theme-toggle');
  const applyTheme = (value) => {
    document.documentElement.dataset.theme = value;
    mount(theme, icon('sun', 17));
    theme.setAttribute('aria-label', value === 'light' ? 'Switch to dark theme' : 'Switch to light theme');
    try { localStorage.setItem('omnishield-x:theme', value); } catch { /* theme still works for this session */ }
  };
  let initial = 'dark';
  try { if (localStorage.getItem('omnishield-x:theme') === 'light') initial = 'light'; } catch { /* safe dark default */ }
  applyTheme(initial);
  theme.addEventListener('click', () => applyTheme(document.documentElement.dataset.theme === 'light' ? 'dark' : 'light'));

  let previousFocus;
  const dialog = h('dialog', { class: 'command-dialog', id: 'command-menu', 'aria-label': 'Find a page' });
  const results = h('div', { class: 'command-list', id: 'command-results' });
  const search = h('input', { type: 'search', id: 'command-search', placeholder: 'Find a page or tool…', autocomplete: 'off', 'aria-label': 'Search pages', 'aria-controls': 'command-results' });
  const close = () => { if (typeof dialog.close === 'function') dialog.close(); else dialog.removeAttribute('open'); previousFocus?.focus?.(); };
  const render = () => {
    const matches = pages.filter((p) => `${p.name} ${p.id}`.toLowerCase().includes(search.value.toLowerCase().trim()));
    mount(results, matches.length ? matches.map((p) => h('button', { type: 'button', onclick: () => { close(); navigate(p.id); }, 'data-command-page': p.id }, icon(GLYPHS[p.id]), h('span', {}, p.name), icon('arrow', 15))) : h('p', { class: 'empty' }, 'No matching page. Try “world”, “DNS”, or “backup”.'));
  };
  search.addEventListener('input', render);
  mount(dialog, h('div', { class: 'command-top' }, icon('search'), search,
    h('button', { type: 'button', onclick: close, class: 'ghost', 'aria-label': 'Close quick find' }, icon('close', 16))), results,
    h('p', { class: 'command-footer' }, '↑ ↓ to move · Enter to open · Escape to close · searches only this app'));
  const open = () => {
    previousFocus = document.activeElement; search.value = ''; render();
    if (!dialog.open) { if (typeof dialog.showModal === 'function') dialog.showModal(); else dialog.setAttribute('open', ''); }
    search.focus();
  };
  dialog.addEventListener('cancel', (e) => { e.preventDefault(); close(); });
  dialog.addEventListener('click', (e) => { if (e.target === dialog) close(); });
  dialog.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') { e.preventDefault(); close(); return; }
    const buttons = [...results.querySelectorAll('button')]; const index = buttons.indexOf(document.activeElement);
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault(); buttons[(index + (e.key === 'ArrowDown' ? 1 : -1) + buttons.length) % buttons.length]?.focus();
    } else if (e.key === 'Enter' && document.activeElement === search) { e.preventDefault(); buttons[0]?.click(); }
    else if (e.key === 'Tab') {
      const focusables = [...dialog.querySelectorAll('input, button')]; const first = focusables[0]; const last = focusables[focusables.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    }
  });
  document.body.append(dialog);
  document.getElementById('command-open').prepend(icon('search', 14));
  document.getElementById('command-open').addEventListener('click', open);
  const keydown = (e) => { if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); dialog.open ? close() : open(); } };
  document.addEventListener('keydown', keydown);
  const onHash = () => { const id = location.hash.slice(1); if (pages.some((p) => p.id === id)) navigate(id, { historyMode: 'none' }); };
  window.addEventListener('hashchange', onHash); window.addEventListener('popstate', onHash);
  // Name legacy controls without relying on placeholder-only labels.
  const labels = { 'aether-input': 'Hostname to analyse', 'dns-input': 'Hostname to resolve', 'dns-type': 'DNS record type', 'fw-input': 'Observed firewall destination', 'import-file': 'Configuration backup JSON file', 'fw-import': 'Firewall observation JSON file' };
  for (const [id, label] of Object.entries(labels)) document.getElementById(id)?.setAttribute('aria-label', label);
  return {
    update(page) { const title = document.getElementById('page-title'); if (title) title.textContent = pages.find((p) => p.id === page)?.name || 'Workspace'; },
    destroy() { dialog.remove(); document.removeEventListener('keydown', keydown); window.removeEventListener('hashchange', onHash); window.removeEventListener('popstate', onHash); }
  };
}
