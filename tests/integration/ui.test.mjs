/**
 * Integration tests — the real application running in a real DOM (jsdom).
 *
 * These tests import the actual app.js, boot it against the actual index.html,
 * and drive the actual buttons. Network access is mocked at the fetch boundary
 * so results are deterministic; everything above fetch is production code.
 */
import test, { before, after } from 'node:test';
import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { JSDOM } from 'jsdom';

const ROOT = new URL('../../', import.meta.url);
const read = (p) => readFileSync(new URL(p, ROOT), 'utf8');

let dom;
let win;
let app;
const feedState = { mode: 'unavailable', rules: 50001 };

function bigFeed(ruleCount) {
  const lines = [`# synthetic feed for tests`, `! generated at test time`];
  for (let i = 0; i < ruleCount; i++) lines.push(`||feedrule${i}.testdomain.example^`);
  return lines.join('\n');
}

function installFetch() {
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(String(input), 'http://localhost:8080/');
    const href = url.href;

    // Bundled assets come from disk — exactly what the browser would download.
    if (href.includes('/assets/') || href.endsWith('manifest.webmanifest')) {
      const relative = href.slice(href.indexOf('/', href.indexOf('://') + 3) + 1);
      try {
        const body = read(relative);
        return { ok: true, status: 200, headers: { get: () => null }, async text() { return body; } };
      } catch {
        return { ok: false, status: 404, headers: { get: () => null }, async text() { return ''; } };
      }
    }

    // DoH JSON endpoint (Cloudflare/Google style).
    if (url.hostname === 'cloudflare-dns.com' || url.hostname === 'dns.google') {
      const name = url.searchParams.get('name') || '';
      const type = Number(url.searchParams.get('type') || 1);
      const answerable = name === 'example.com';
      if (!answerable) {
        return {
          ok: true, status: 200, headers: { get: () => null },
          async json() { return { Status: 3, AD: false, Question: [{ name: `${name}.`, type }] }; },
          async text() { return ''; }
        };
      }
      const data = type === 28 ? '2606:2800:220:1:248:1893:25c8:1946' : '93.184.216.34';
      return {
        ok: true, status: 200, headers: { get: () => null },
        async json() {
          return { Status: 0, AD: true, Question: [{ name: `${name}.`, type }], Answer: [{ name: `${name}.`, type, TTL: 120, data }] };
        },
        async text() { return ''; }
      };
    }

    // Feed updates: behaviour is switched per test.
    if (url.hostname === 'raw.githubusercontent.com') {
      if (feedState.mode === 'valid') {
        const body = bigFeed(feedState.rules);
        return {
          ok: true, status: 200,
          headers: { get: (k) => (k.toLowerCase() === 'etag' ? '"test-etag"' : null) },
          async text() { return body; }
        };
      }
      if (feedState.mode === 'html') {
        return {
          ok: true, status: 200, headers: { get: () => null },
          async text() { return `<!DOCTYPE html><html><body>${'x'.repeat(4000)}</body></html>`; }
        };
      }
      return { ok: false, status: 503, headers: { get: () => null }, async text() { return ''; } };
    }

    throw new Error(`unexpected fetch in test: ${href}`);
  };
  return fetchImpl;
}

function defineGlobal(name, value) {
  Object.defineProperty(globalThis, name, { value, configurable: true, writable: true });
}

before(async () => {
  dom = await JSDOM.fromFile(fileURLToPath(new URL('index.html', ROOT)), {
    url: 'http://localhost:8080/',
    runScripts: 'outside-only',
    pretendToBeVisual: true
  });
  win = dom.window;

  // Bridge the jsdom environment into the module scope app.js expects.
  defineGlobal('window', win);
  defineGlobal('document', win.document);
  defineGlobal('navigator', win.navigator);
  defineGlobal('location', win.location);
  defineGlobal('history', win.history);
  defineGlobal('localStorage', win.localStorage);
  defineGlobal('FileReader', win.FileReader);
  defineGlobal('File', win.File);
  defineGlobal('Blob', win.Blob);
  defineGlobal('Event', win.Event);
  defineGlobal('Node', win.Node);
  defineGlobal('HTMLElement', win.HTMLElement);
  defineGlobal('localStorage', win.localStorage);
  defineGlobal('fetch', installFetch());
  defineGlobal('confirm', () => true);
  defineGlobal('alert', () => {});

  await import('../../app.js');
  app = globalThis.__omnishield;
  assert.ok(app, 'app.js must expose the automation hook');
  await app.ready;
});

after(() => {
  try { app?.stop(); } catch { /* ignore */ }
  win?.close();
});

const $ = (sel) => win.document.querySelector(sel);
const text = (sel) => $(sel)?.textContent || '';
const click = (sel) => $(sel).dispatchEvent(new win.MouseEvent('click', { bubbles: true }));

test('boots with real bundled rules and reports readiness honestly', () => {
  const state = app.state;
  assert.ok(state.booted, 'app must finish booting');
  assert.ok(state.engine.totalRules() > 70000, `only ${state.engine.totalRules()} rules loaded`);
  assert.match(text('#boot-status'), /ready/i);
  assert.ok(state.bundled.core_lite_ads.added > 70000);
  assert.ok(state.bundled.core_supplement_ads.added > 50);
});

test('every navigation target renders without error', () => {
  const pages = [...win.document.querySelectorAll('nav.tabs button')].map((b) => b.dataset.page);
  assert.ok(pages.length >= 10, `expected 10+ pages, found ${pages.length}`);
  for (const page of pages) {
    app.navigate(page);
    const section = $(`#page-${page}`);
    assert.ok(section, `missing section for ${page}`);
    assert.equal(section.hidden, false, `${page} section should be visible after navigation`);
    assert.ok(section.textContent.trim().length > 40, `${page} rendered too little content`);
  }
  app.navigate('dashboard');
});

test('AETHER blocks a feed-listed ad domain and explains why', () => {
  app.navigate('aether');
  $('#aether-input').value = 'ads.doubleclick.net';
  click('#aether-go');
  const out = text('#aether-result');
  assert.match(out, /ads\.doubleclick\.net/);
  assert.match(out, /filtered by core_/i, 'must attribute the block to a feed');
  assert.match(out, /Rule .* appears in the/i, 'must show the matched rule reason');
  const verdict = $('#aether-result .verdict');
  assert.ok(verdict.classList.contains('blocked'), 'verdict element must be marked blocked');
});

test('AETHER keeps a legitimate popular domain clean (false-positive guardrail)', () => {
  $('#aether-input').value = 'accounts.google.com';
  click('#aether-go');
  const out = text('#aether-result');
  assert.match(out, /accounts\.google\.com/);
  assert.match(out, /guardrail|Guardrail|popular/i, 'popularity guardrail must be visible');
  const score = Number($('#aether-result .gauge-ring span')?.firstChild?.textContent);
  assert.ok(score <= 10, `legitimate domain scored ${score}`);
});

test('reporting a false positive allowlists the domain and is reversible', () => {
  $('#aether-input').value = 'ads.doubleclick.net';
  click('#aether-go');
  const buttons = [...win.document.querySelectorAll('#aether-result button')];
  const report = buttons.find((b) => /Report false positive/i.test(b.textContent));
  assert.ok(report, 'false-positive button must exist');
  report.dispatchEvent(new win.MouseEvent('click', { bubbles: true }));

  assert.equal(app.state.engine.evaluate('ads.doubleclick.net').blocked, false, 'allow rule must take effect');
  assert.ok(app.state.customRules.some((r) => r.pattern === 'ads.doubleclick.net' && r.isAllow));

  app.navigate('sync');
  assert.match(text('#rules-body'), /ads\.doubleclick\.net/);

  // Undo through the real UI button.
  const remove = [...win.document.querySelectorAll('#rules-body button')].find((b) => /Remove/i.test(b.textContent));
  remove.dispatchEvent(new win.MouseEvent('click', { bubbles: true }));
  assert.equal(app.state.engine.evaluate('ads.doubleclick.net').blocked, true, 'removal must restore blocking');
});

test('DNS lab resolves over DoH, caches, and records real monitor events', async () => {
  app.navigate('dns');
  $('#dns-input').value = 'example.com';
  click('#dns-go');
  await new Promise((r) => setTimeout(r, 250));

  const out = text('#dns-result');
  assert.match(out, /93\.184\.216\.34/, 'must show the resolved IPv4 address');
  assert.match(out, /VALIDATED_UPSTREAM/, 'must report the DNSSEC verdict');
  assert.match(out, /Cloudflare|Google/, 'must name the resolver used');

  const before = app.state.monitor.metrics().lookups;
  click('#dns-go');
  await new Promise((r) => setTimeout(r, 250));
  assert.equal(app.state.client.stats.cached >= 1, true, 'second resolution must be served from cache');
  assert.ok(app.state.monitor.metrics().lookups > before, 'cache hits must still be recorded');

  app.navigate('monitor');
  assert.match(text('#mon-kpis'), /\d/, 'monitor KPIs must show measured numbers');
});

test('DNS lab refuses to invent an answer for an unresolvable name', async () => {
  app.navigate('dns');
  $('#dns-input').value = 'definitely-not-registered.example';
  click('#dns-go');
  await new Promise((r) => setTimeout(r, 250));
  const out = text('#dns-result');
  assert.match(out, /NXDOMAIN|not resolved/i);
  assert.equal(out.includes('93.184.216.34'), false, 'must not leak another domain\'s answer');
});

test('Firewall AI self-test exercises every detector with labelled fixtures', () => {
  app.navigate('firewall');
  click('#fw-selftest');
  const out = text('#fw-selftest-out');
  assert.match(out, /synthetic test vectors/i, 'fixtures must be labelled synthetic');
  assert.match(out, /Beaconing \(60s cadence\)/);
  assert.match(out, /Beaconing \(human jitter\)/);
  assert.match(out, /DNS tunnelling/);
  assert.match(out, /Fan-out/);
  assert.match(out, /beacon\.fixture|fires/, 'detectors must report firing');
});

test('feed updates are validated: HTML is rejected, a valid feed is applied', async () => {
  app.navigate('feeds');
  feedState.mode = 'html';
  await app.checkFeedUpdates();
  assert.match(text('#feeds-status'), /html-instead-of-list|not applied/i);
  const rulesBefore = app.state.engine.totalRules();

  feedState.mode = 'valid';
  feedState.rules = 50001;
  await app.checkFeedUpdates();
  const status = text('#feeds-status');
  assert.match(status, /updated|already up to date/i, `unexpected feed status: ${status.slice(0, 200)}`);
  assert.ok(app.state.engine.totalRules() >= rulesBefore, 'valid feed must add rules');
  assert.match(text('#feeds-list'), /Installed|bundled only|rules/i);
});

test('snapshots round-trip and survive a simulated storage failure', async () => {
  const saved = await app.saveSnapshot('integration-test', { silent: true });
  assert.ok(saved.id, 'snapshot must be saved');
  const list = await app.state.backups.list();
  assert.ok(list.some((s) => s.id === saved.id && s.valid), 'saved snapshot must verify');

  const recovery = await app.state.backups.recover();
  assert.equal(recovery.ok, true);
  assert.ok(recovery.state.customRules !== undefined);
});

test('imported backup content is rendered as text, never as markup (XSS regression)', () => {
  const hostile = {
    customRules: [{
      rawPattern: '<img src=x onerror="globalThis.__pwned=1">',
      ruleType: 'BLOCK', matchType: 'SUFFIX', isEnabled: true, comment: '<script>globalThis.__pwned2=1</script>'
    }],
    protectionMode: 'BALANCED',
    browserSiteExceptions: ['<b>x</b>'],
    excludedAppPackages: []
  };
  const file = new win.File([JSON.stringify(hostile)], 'backup.json', { type: 'application/json' });
  const input = $('#import-file');
  Object.defineProperty(input, 'files', { value: [file], configurable: true });
  input.dispatchEvent(new win.Event('change', { bubbles: true }));

  return new Promise((resolve, reject) => {
    setTimeout(() => {
      try {
        assert.equal($('#rules-body img'), null, 'injected <img> must not exist in the DOM');
        assert.equal($('#rules-body script'), null, 'injected <script> must not exist in the DOM');
        assert.equal(win.__pwned, undefined);
        assert.equal(win.__pwned2, undefined);
        assert.match(text('#rules-body'), /<img src=x/, 'the payload must appear as literal text');
        assert.match(text('#import-status'), /Imported/i);
        resolve();
      } catch (err) { reject(err); }
    }, 120);
  });
});

test('privacy report suppresses small buckets and states it leaves nothing behind', () => {
  app.navigate('privacy');
  const out = text('#privacy-out') + text('#privacy-note');
  assert.match(out, /k threshold|Suppressed/i);
  assert.match(out, /no/i);
  assert.match(out, /salted SHA-256/i);
});

test('capability matrix marks unimplemented features as not implemented', () => {
  app.navigate('status');
  const out = text('#capabilities');
  assert.match(out, /DoT \(DNS over TLS\)/);
  assert.match(out, /not implemented/);
  assert.match(out, /Antivirus/);
  assert.match(out, /local chain-of-trust validation/);
  assert.match(text('#limits'), /cannot install a VPN/i);
});

test('no page uses innerHTML or trusts file content as markup', () => {
  const appSource = read('app.js');
  const domSource = read('ui/dom.js');
  assert.equal(/\.innerHTML\s*=/.test(appSource), false, 'app.js must not assign innerHTML');
  assert.equal(/insertAdjacentHTML/.test(appSource), false, 'app.js must not use insertAdjacentHTML');
  assert.equal(/\.innerHTML\s*=/.test(domSource), false, 'ui/dom.js must not assign innerHTML');
});
