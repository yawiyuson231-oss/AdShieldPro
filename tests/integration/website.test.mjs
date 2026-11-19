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

function mountPage(relPath, {
  url = 'https://yawiyuson231-oss.github.io/AdShieldPro/', reducedMotion = false,
  fetch = async () => ({ ok: false, status: 503, json: async () => null })
} = {}) {
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
      win.fetch = fetch;
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

const STATIC_APK = 'https://github.com/yawiyuson231-oss/AdShieldPro/releases/download/v2.11.0/AdShieldPro-2.11.0-release.apk';
const STATIC_SHA = 'c54609cc63056d8b7705f252666ade80940fce8e7a59b254f8c31a4826a8288c';

function releaseFixture({ tag = 'v2.12.0', digest = `sha256:${'ab'.repeat(32)}`, shaAsset = true } = {}) {
  const version = tag.slice(1);
  const name = `AdShieldPro-${version}-release.apk`;
  const base = `https://github.com/yawiyuson231-oss/AdShieldPro/releases/download/${tag}/`;
  const url = `${base}${name}`;
  const assets = [{ name, browser_download_url: url, digest, size: 58_000_000 }];
  if (shaAsset) assets.push({ name: `${name}.sha256`, browser_download_url: `${url}.sha256`, size: 97 });
  return { tag_name: tag, draft: false, prerelease: false, assets };
}

function releaseFetch(release) {
  return async () => ({ ok: true, status: 200, json: async () => release });
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

test('incomplete future releases never replace the verified APK checksum or URL', async () => {
  const incomplete = [
    releaseFixture({ digest: null }),
    releaseFixture({ shaAsset: false }),
    { ...releaseFixture(), draft: true },
    { ...releaseFixture(), prerelease: true },
    { ...releaseFixture(), tag_name: 'preview-v2.12.0-run.1' },
    { ...releaseFixture(), assets: [{ name: 'app-debug.apk', browser_download_url: `${STATIC_APK}debug`, digest: `sha256:${'ab'.repeat(32)}` }] }
  ];
  for (const release of incomplete) {
    const { dom, doc, errors } = mountPage('docs/index.html', { reducedMotion: true, fetch: releaseFetch(release) });
    try {
      await new Promise((r) => setTimeout(r, 30));
      assert.deepEqual(errors, []);
      assert.ok([...doc.querySelectorAll('[data-apk-link]')].every((a) => a.href === STATIC_APK));
      assert.equal(doc.getElementById('apk-sha256').textContent, STATIC_SHA);
      assert.match(doc.querySelector('[data-release-badge]').textContent, /v2\.11\.0/);
      const ld = JSON.parse(doc.querySelector('script[type="application/ld+json"]').textContent);
      assert.equal(ld.softwareVersion, '2.11.0');
    } finally { dom.window.close(); }
  }
});

test('a fully verified release updates the APK, SHA-256 and structured data together', async () => {
  const release = releaseFixture();
  const { dom, doc, errors } = mountPage('docs/index.html', { reducedMotion: true, fetch: releaseFetch(release) });
  try {
    await new Promise((r) => setTimeout(r, 30));
    assert.deepEqual(errors, []);
    const apkUrl = release.assets[0].browser_download_url;
    assert.ok([...doc.querySelectorAll('[data-apk-link]')].every((a) => a.href === apkUrl));
    assert.match(doc.querySelector('[data-apk-cta]').textContent, /v2\.12\.0/);
    assert.match(doc.querySelector('[data-release-badge]').textContent, /v2\.12\.0/);
    assert.match(doc.querySelector('[data-release-lead]').textContent, /2\.12\.0/);
    assert.match(doc.querySelector('[data-apk-meta]').textContent, /AdShieldPro-2\.12\.0-release\.apk/);
    assert.equal(doc.getElementById('apk-sha256').textContent, 'ab'.repeat(32));
    assert.equal(doc.querySelector('[data-sha-link]').href, `${apkUrl}.sha256`);
    const ld = JSON.parse(doc.querySelector('script[type="application/ld+json"]').textContent);
    assert.equal(ld.softwareVersion, '2.12.0');
    assert.equal(ld.downloadUrl, apkUrl);
  } finally { dom.window.close(); }
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
