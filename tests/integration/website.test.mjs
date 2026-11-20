/**
 * Integration tests — marketing site (docs/index.html), privacy page (docs/privacy.html),
 * and custom 404 page (docs/404.html) in a live jsdom environment.
 */
import test from 'node:test';
import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { JSDOM } from 'jsdom';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const read = (p) => readFileSync(resolve(ROOT, p), 'utf8');

function mountPage(relPath, { url = 'https://yawiyuson231-oss.github.io/AdShieldPro/', reducedMotion = false } = {}) {
  const errors = [];
  const clipboardWrites = [];
  const dom = new JSDOM(read(relPath), {
    url,
    runScripts: 'dangerously',
    pretendToBeVisual: true,
    beforeParse(win) {
      win.addEventListener('error', (e) => errors.push(e.error || e.message));
      win.addEventListener('unhandledrejection', (e) => errors.push(e.reason));
      win.matchMedia = (query) => ({
        matches: query.includes('prefers-reduced-motion') ? reducedMotion : false,
        media: query,
        addEventListener() {},
        removeEventListener() {},
        addListener() {},
        removeListener() {}
      });
      win.IntersectionObserver = class {
        constructor(cb) { this.cb = cb; }
        observe(target) { this.cb([{ target, isIntersecting: true }]); }
        unobserve() {}
        disconnect() {}
      };
      win.ResizeObserver = class {
        observe() {}
        unobserve() {}
        disconnect() {}
      };
      win.fetch = async () => ({ ok: false, status: 503, json: async () => null });
      Object.defineProperty(win.navigator, 'clipboard', {
        configurable: true,
        value: {
          writeText: async (text) => { clipboardWrites.push(text); }
        }
      });
    }
  });
  return { dom, win: dom.window, doc: dom.window.document, errors, clipboardWrites };
}

test('marketing page boots cleanly, exposes accessible hero title, and wires interactive controls', async () => {
  const { dom, win, doc, errors, clipboardWrites } = mountPage('docs/index.html', { reducedMotion: true });
  try {
    await new Promise((r) => setTimeout(r, 40));
    assert.deepEqual(errors, [], 'marketing page must execute with zero uncaught errors');
    assert.ok(doc.body.classList.contains('is-loaded'), 'loader must dismiss immediately in reduced motion');

    // Screen-reader-safe character splitting on the hero logo.
    const logo = doc.querySelector('.hero-logo');
    assert.equal(logo.getAttribute('aria-label'), 'ADSHIELD PRO');
    const chars = [...logo.querySelectorAll('.char')];
    assert.ok(chars.length >= 10);
    assert.ok(chars.every((c) => c.getAttribute('aria-hidden') === 'true'));

    // Mobile drawer open / Escape close.
    const toggle = doc.querySelector('.nav-toggle');
    const nav = doc.getElementById('site-nav');
    toggle.click();
    assert.equal(toggle.getAttribute('aria-expanded'), 'true');
    assert.ok(nav.classList.contains('is-open'));
    doc.dispatchEvent(new win.KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    assert.equal(toggle.getAttribute('aria-expanded'), 'false');
    assert.equal(nav.classList.contains('is-open'), false);

    // Simulated phone showcase tabs, keyboard navigation, and protection switch.
    const rulesTab = doc.getElementById('tab-rules');
    rulesTab.click();
    assert.equal(rulesTab.getAttribute('aria-selected'), 'true');
    assert.equal(doc.getElementById('screen-rules').hidden, false);
    rulesTab.dispatchEvent(new win.KeyboardEvent('keydown', { key: 'ArrowRight', bubbles: true }));
    assert.equal(doc.getElementById('tab-boost').getAttribute('aria-selected'), 'true');

    const shieldSwitch = doc.querySelector('.p-toggle');
    shieldSwitch.click();
    assert.equal(shieldSwitch.getAttribute('aria-checked'), 'false');
    assert.equal(doc.querySelector('[data-status-text]').textContent, 'Protection paused');

    // Interactive DNS demo respects reduced motion until user explicitly resumes.
    const pauseBtn = doc.querySelector('[data-demo-pause]');
    assert.equal(pauseBtn.getAttribute('aria-pressed'), 'true', 'reduced motion must pause continuous canvas animation');
    const strictBtn = doc.querySelector('[data-scenario="strict"]');
    strictBtn.click();
    assert.equal(strictBtn.getAttribute('aria-pressed'), 'true');
    assert.match(doc.querySelector('[data-scenario-text]').textContent, /Strict:/);

    // Signed APK checksum copy button.
    const shaEl = doc.getElementById('apk-sha256');
    const copyBtn = doc.querySelector('[data-copy-sha]');
    assert.match(shaEl.textContent, /^[0-9a-f]{64}$/);
    copyBtn.click();
    await new Promise((r) => setTimeout(r, 30));
    assert.deepEqual(clipboardWrites, [shaEl.textContent]);
    assert.equal(copyBtn.textContent, 'Copied');

    // Download footer links have separators between every adjacent pair of anchors.
    const linkChildren = [...doc.querySelector('.download-links').children];
    for (let i = 0; i < linkChildren.length - 1; i++) {
      assert.notEqual(
        `${linkChildren[i].tagName}-${linkChildren[i + 1].tagName}`,
        'A-A',
        'adjacent download links must have a visible separator'
      );
    }

    // Structured data is valid JSON matching v2.11.0.
    const ld = JSON.parse(doc.querySelector('script[type="application/ld+json"]').textContent);
    assert.equal(ld.softwareVersion, '2.11.0');
    assert.match(ld.downloadUrl, /AdShieldPro-2\.11\.0-release\.apk$/);
  } finally {
    dom.window.close();
  }
});

test('website v2.0: quick-jump palette filters, navigates, and closes on Escape', async () => {
  const { dom, doc, errors } = mountPage('docs/index.html', { reducedMotion: true });
  const win = dom.window;
  try {
    await new Promise((r) => setTimeout(r, 40));
    assert.deepEqual(errors, []);

    const modal = doc.getElementById('cmd-modal');
    assert.ok(modal, 'command palette markup must exist');
    assert.equal(modal.hidden, true);

    doc.querySelector('[data-cmd-open]').click();
    assert.equal(modal.hidden, false);
    assert.equal(doc.activeElement.id, 'cmd-input');
    const rows = [...doc.querySelectorAll('#cmd-list .cmd-item')];
    assert.ok(rows.length >= 10, 'palette lists every section, page and external action');
    assert.ok(rows.some((r) => r.textContent.includes('Discord server')));
    assert.ok(rows[0].classList.contains('is-selected'));

    // Filtering narrows the list by title, detail, tag or keyword.
    const input = doc.getElementById('cmd-input');
    input.value = 'discord';
    input.dispatchEvent(new win.Event('input', { bubbles: true }));
    const filtered = [...doc.querySelectorAll('#cmd-list .cmd-item')];
    assert.ok(filtered.length >= 1 && filtered.length < 10, 'the query must narrow the list');
    assert.ok(filtered.some((r) => /Discord server/.test(r.textContent)));
    assert.ok(filtered.every((r) => /Discord|Community/.test(r.textContent)));

    // Arrow keys move the selection, Enter runs it and closes the dialog.
    input.value = '';
    input.dispatchEvent(new win.Event('input', { bubbles: true }));
    modal.dispatchEvent(new win.KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true }));
    assert.ok(doc.querySelectorAll('#cmd-list .cmd-item')[1].classList.contains('is-selected'));
    modal.dispatchEvent(new win.KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    assert.equal(modal.hidden, true, 'Enter must close the palette after navigating');
    assert.equal(win.location.hash, '#showcase');

    // Ctrl/Cmd + K toggles, Escape closes.
    doc.dispatchEvent(new win.KeyboardEvent('keydown', { key: 'k', ctrlKey: true, bubbles: true }));
    assert.equal(modal.hidden, false);
    modal.dispatchEvent(new win.KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    assert.equal(modal.hidden, true);

    // No match renders a helpful empty state instead of throwing.
    modal.hidden = false;
    input.value = 'zzzz-nothing';
    input.dispatchEvent(new win.Event('input', { bubbles: true }));
    assert.match(doc.getElementById('cmd-list').textContent, /No matches/);
  } finally {
    dom.window.close();
  }
});

test('website v2.0: architecture matrix tablist roves focus and swaps panes', async () => {
  const { dom, doc, errors } = mountPage('docs/index.html', { reducedMotion: true });
  const win = dom.window;
  try {
    await new Promise((r) => setTimeout(r, 40));
    assert.deepEqual(errors, []);

    const tabs = [...doc.querySelectorAll('.arch-tab[data-arch-tab]')];
    assert.equal(tabs.length, 4);
    assert.deepEqual(tabs.map((t) => t.dataset.archTab), ['doq', 'doh', 'alias', 'audit']);
    assert.equal(tabs[0].getAttribute('aria-selected'), 'true');
    assert.equal(doc.getElementById('arch-pane-doq').hidden, false);
    assert.equal(doc.getElementById('arch-pane-audit').hidden, true);

    tabs[3].click();
    assert.equal(tabs[3].getAttribute('aria-selected'), 'true');
    assert.equal(tabs[0].getAttribute('aria-selected'), 'false');
    assert.equal(doc.getElementById('arch-pane-audit').hidden, false);
    assert.equal(doc.getElementById('arch-pane-doq').hidden, true);

    // ArrowRight wraps from the last tab back to the first and moves focus.
    tabs[3].dispatchEvent(new win.KeyboardEvent('keydown', { key: 'ArrowRight', bubbles: true }));
    assert.equal(tabs[0].getAttribute('aria-selected'), 'true');
    assert.equal(doc.activeElement.id, 'arch-tab-doq');
    assert.equal(tabs[0].tabIndex, 0);
    assert.equal(tabs[1].tabIndex, -1);
  } finally {
    dom.window.close();
  }
});

test('website v2.0: link sanitizer unwraps redirects and strips tracking parameters', async () => {
  const { dom, doc, errors, clipboardWrites } = mountPage('docs/index.html', { reducedMotion: true });
  const win = dom.window;
  try {
    await new Promise((r) => setTimeout(r, 40));
    assert.deepEqual(errors, []);

    const input = doc.getElementById('lab-url-input');
    const out = doc.getElementById('lab-url-clean');
    const tags = () => [...doc.querySelectorAll('#lab-url-tags li')].map((li) => li.textContent);
    const stats = () => doc.getElementById('lab-url-stats').textContent;

    doc.querySelector('[data-url-preset="social"]').click();
    assert.match(out.textContent, /^https:\/\/shop\.example\.org\/deals\?item=headphones$/);
    assert.doesNotMatch(out.textContent, /fbclid|utm_/);
    assert.doesNotMatch(out.textContent, /l\.facebook\.com/);
    assert.ok(tags().some((t) => t.includes('fbclid')));
    assert.match(stats(), /Unwrapped 1 redirect/);
    assert.match(stats(), /Removed \d+ tracking param/);

    // A search-ad redirect wrapper is peeled to the destination.
    doc.querySelector('[data-url-preset="search"]').click();
    assert.match(out.textContent, /^https:\/\/news\.example\.net\/article\/42\?page=2$/);
    assert.match(stats(), /Kept 1 functional param/);

    // Functional parameters survive; share/tracking parameters do not.
    doc.querySelector('[data-url-preset="video"]').click();
    assert.match(out.textContent, /^https:\/\/video\.example\.com\/watch\?v=demo42&feature=share$/);
    assert.doesNotMatch(out.textContent, /si=|utm_campaign/);
    assert.match(stats(), /Kept 2 functional params/);

    // Invalid and non-http input is rejected without throwing.
    input.value = 'not a url';
    doc.getElementById('lab-url-run').click();
    assert.match(out.textContent, /Not a valid http\(s\) URL/);
    assert.ok(out.classList.contains('is-warn'));
    input.value = 'javascript:alert(1)';
    doc.getElementById('lab-url-run').click();
    assert.match(out.textContent, /Not a valid http\(s\) URL/);

    // Copy button writes the sanitized string, never the raw input.
    doc.querySelector('[data-url-preset="social"]').click();
    doc.getElementById('lab-url-copy').click();
    await new Promise((r) => setTimeout(r, 20));
    assert.deepEqual(clipboardWrites, ['https://shop.example.org/deals?item=headphones']);
  } finally {
    dom.window.close();
  }
});

test('website v2.0: domain inspector scores homoglyph impersonation and clean hosts', async () => {
  const { dom, doc, errors } = mountPage('docs/index.html', { reducedMotion: true });
  try {
    await new Promise((r) => setTimeout(r, 40));
    assert.deepEqual(errors, []);

    const input = doc.getElementById('lab-domain-input');
    const score = () => doc.getElementById('lab-domain-score').textContent;
    const verdict = () => doc.getElementById('lab-domain-verdict').textContent;
    const signals = () => [...doc.querySelectorAll('#lab-domain-signals li')].map((li) => li.textContent);

    doc.querySelector('[data-domain-preset="discord-scam"]').click();
    assert.match(verdict(), /High lookalike \/ phishing risk/);
    const badScore = Number(score().match(/^(\d+)/)[1]);
    assert.ok(badScore >= 70, `expected a high score, got ${badScore}`);
    assert.equal(doc.getElementById('lab-domain-host').textContent, 'disc0rd-nitro-gift.claim-drop.top');
    assert.ok(signals().some((s) => s.includes('Brand impersonation') && s.includes('discord')));
    assert.ok(signals().some((s) => s.includes('High-abuse TLD') && s.includes('.top')));
    assert.ok(doc.getElementById('lab-domain-score').classList.contains('bad'));

    // Tracker-style hostnames surface the tracker naming pattern.
    doc.querySelector('[data-domain-preset="tracker"]').click();
    assert.ok(signals().some((s) => s.includes('Tracker naming pattern')));

    // A plain media CDN carries no structural signals and a low score.
    doc.querySelector('[data-domain-preset="clean"]').click();
    assert.match(verdict(), /No structural signals/);
    assert.equal(Number(score().match(/^(\d+)/)[1]), 0);
    assert.equal(doc.getElementById('lab-domain-score').className, 'domain-score-num');

    // Malformed input is handled gracefully.
    input.value = '';
    doc.getElementById('lab-domain-run').click();
    assert.match(verdict(), /Enter a valid hostname/);
    assert.equal(score(), '—');
  } finally {
    dom.window.close();
  }
});

test('website v2.0: fifth phone screen cycles per-app DNS policies', async () => {
  const { dom, doc, errors } = mountPage('docs/index.html', { reducedMotion: true });
  const win = dom.window;
  try {
    await new Promise((r) => setTimeout(r, 40));
    assert.deepEqual(errors, []);

    const tabs = [...doc.querySelectorAll('.phone-tab[data-phone-tab]')];
    assert.equal(tabs.length, 5);
    assert.equal(tabs[4].id, 'tab-firewall');
    assert.equal(doc.getElementById('screen-firewall').hidden, true);

    // ArrowRight from the fourth tab lands on the new fifth screen.
    tabs[3].dispatchEvent(new win.KeyboardEvent('keydown', { key: 'ArrowRight', bubbles: true }));
    assert.equal(doc.getElementById('tab-firewall').getAttribute('aria-selected'), 'true');
    assert.equal(doc.getElementById('screen-firewall').hidden, false);
    assert.equal(doc.querySelectorAll('.phone-nav [data-phone-tab]').length, 5);

    const first = doc.querySelector('#screen-firewall [data-app-policy]');
    const summary = doc.querySelector('[data-fw-summary]');
    assert.equal(first.textContent, 'FILTERED');
    assert.match(summary.textContent, /^2 filtered · 1 allow · 0 block DNS · 1 split-tunnel$/);

    first.click();
    assert.equal(first.textContent, 'ALLOW DNS');
    assert.equal(first.dataset.mode, 'allow');
    assert.match(summary.textContent, /^1 filtered · 2 allow · 0 block DNS · 1 split-tunnel$/);
    assert.match(first.getAttribute('aria-label'), /Web Browser DNS mode: ALLOW DNS/);

    first.click();
    assert.equal(first.textContent, 'BLOCK DNS');
    assert.equal(first.dataset.mode, 'block');
    first.click();
    assert.equal(first.textContent, 'SPLIT-TUNNEL');
    first.click();
    assert.equal(first.textContent, 'FILTERED', 'policy cycling wraps back to filtered');
  } finally {
    dom.window.close();
  }
});

test('website v2.0: Discord invite is integrated as a plain external link everywhere', async () => {
  const INVITE = 'https://discord.gg/TZh3kwDU9M';
  const { dom, doc, errors, clipboardWrites } = mountPage('docs/index.html', { reducedMotion: true });
  try {
    await new Promise((r) => setTimeout(r, 40));
    assert.deepEqual(errors, []);

    const anchors = [...doc.querySelectorAll('a[href="https://discord.gg/TZh3kwDU9M"]')];
    assert.ok(anchors.length >= 4, 'header, hero, community hub, FAQ, download and footer link out');
    for (const a of anchors) {
      assert.match(a.getAttribute('rel') || '', /noopener/, 'external invite links must set rel=noopener');
    }
    assert.ok(anchors.every((a) => !a.hasAttribute('data-site-rel')));

    // Header and hero CTAs, community hub and footer entry.
    assert.ok(doc.querySelector('.nav a.nav-discord[href="https://discord.gg/TZh3kwDU9M"]'));
    assert.ok(doc.querySelector('#community .discord-hub a.btn-discord-solid[href="https://discord.gg/TZh3kwDU9M"]'));
    assert.equal(doc.getElementById('discord-invite').textContent, 'discord.gg/TZh3kwDU9M');
    const footerHrefs = [...doc.querySelectorAll('.site-footer nav a')].map((a) => a.getAttribute('href'));
    assert.ok(footerHrefs.includes(INVITE));

    // The zero-widget guarantee: no Discord iframe, script, or pixel anywhere.
    assert.equal(doc.querySelectorAll('iframe').length, 0, 'no third-party iframes may be embedded');
    assert.equal(doc.querySelectorAll('script[src]').length, 0, 'the site must not load remote scripts');
    assert.doesNotMatch(doc.documentElement.outerHTML, /discord(app)?\.(com|net)\/widget|discord\.gg\/api/);

    // Copy-invite button writes the exact invite and confirms.
    const copyBtn = doc.querySelector('[data-copy-discord]');
    copyBtn.click();
    await new Promise((r) => setTimeout(r, 20));
    assert.deepEqual(clipboardWrites, [INVITE]);
    assert.equal(copyBtn.textContent, 'Copied');
  } finally {
    dom.window.close();
  }
});

test('privacy page renders full policy sections, DoQ disclosure, and Play Data Safety table', () => {
  const { dom, doc, errors } = mountPage('docs/privacy.html', {
    url: 'https://yawiyuson231-oss.github.io/AdShieldPro/privacy.html'
  });
  try {
    assert.deepEqual(errors, []);
    assert.equal(doc.querySelectorAll('section.card').length, 5);
    assert.match(doc.body.textContent, /DNS-over-QUIC \(DoQ, RFC 9250\)/);
    assert.ok(doc.querySelectorAll('table tbody tr').length >= 7);
    assert.ok(doc.querySelector('a[href="./"]'), 'must link back to site home');
    assert.ok(doc.querySelector('a[href="app/"]'), 'must link to web platform');
  } finally {
    dom.window.close();
  }
});

test('custom 404 page resolves project-root links from arbitrary nested paths', () => {
  const { dom, doc, errors } = mountPage('docs/404.html', {
    url: 'https://yawiyuson231-oss.github.io/AdShieldPro/deep/missing/route'
  });
  try {
    assert.deepEqual(errors, []);
    const hrefs = [...doc.querySelectorAll('[data-site-rel]')].map((a) => a.getAttribute('href'));
    assert.deepEqual(hrefs, [
      '/AdShieldPro/',
      '/AdShieldPro/app/',
      '/AdShieldPro/privacy.html'
    ]);
  } finally {
    dom.window.close();
  }
});

test('Discord invite is present on every published page, always as a plain external anchor', () => {
  const INVITE = 'https://discord.gg/TZh3kwDU9M';
  const pages = [
    ['docs/privacy.html', 'https://yawiyuson231-oss.github.io/AdShieldPro/privacy.html', 2],
    ['docs/404.html', 'https://yawiyuson231-oss.github.io/AdShieldPro/missing/page', 1]
  ];
  for (const [page, url, minLinks] of pages) {
    const { dom, doc, errors } = mountPage(page, { url });
    try {
      assert.deepEqual(errors, [], `${page} must boot without errors`);
      const links = [...doc.querySelectorAll(`a[href="${INVITE}"]`)];
      assert.ok(links.length >= minLinks, `${page} must link the invite from its navigation`);
      links.forEach((a) => assert.match(a.getAttribute('rel') || '', /noopener/));
      assert.equal(doc.querySelectorAll('iframe').length, 0, `${page} must not embed a Discord widget`);
      assert.equal(links.filter((a) => a.hasAttribute('data-site-rel')).length, 0,
        'the external invite must never be rewritten as a site-relative link');
    } finally {
      dom.window.close();
    }
  }

  // The /app/ platform page is static markup plus app.js — assert on the source,
  // which is exactly what the browser receives before hydration.
  const appHtml = read('index.html');
  assert.ok(appHtml.includes(`href="${INVITE}"`), '/app/ must link the community server');
  assert.match(appHtml, /rel="noopener noreferrer"/);
  assert.doesNotMatch(appHtml, /discord(app)?\.com\/widget|discord\.gg\/api/, 'no Discord widget may be embedded');
});
