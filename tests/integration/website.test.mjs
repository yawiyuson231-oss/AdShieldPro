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
