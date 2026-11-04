/**
 * Unit tests — deploy assembler (scripts/stage-site.mjs).
 *
 * The deployment serves the marketing site at / and the web platform at /app/.
 * The failure this suite exists to prevent: the site deploys and the app cannot
 * start, because a module or feed behind the service-worker precache list was
 * never staged.
 */
import test from 'node:test';
import { strict as assert } from 'node:assert';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync, cpSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { stageSite, checkPrecache, APP_ROOT_FILES, APP_DIRS } from '../../scripts/stage-site.mjs';

const ROOT = new URL('../../', import.meta.url).pathname;

/** A miniature repository with the same shape as the real one. */
function fixture() {
  const dir = mkdtempSync(join(tmpdir(), 'omnishield-stage-'));
  mkdirSync(join(dir, 'docs'), { recursive: true });
  writeFileSync(join(dir, 'docs/index.html'), '<h1>AdShield Pro</h1>');
  writeFileSync(join(dir, 'docs/PRIVACY_POLICY.md'), '# privacy');
  for (const file of APP_ROOT_FILES) {
    if (file === 'omnishield-x-extension.zip') continue; // large, and optional in the fixture
    writeFileSync(join(dir, file), `/* ${file} */`);
  }
  writeFileSync(join(dir, 'index.html'), '<!DOCTYPE html><html><body>app</body></html>');
  writeFileSync(join(dir, 'sw.js'), [
    "const SHELL = ['./', './index.html', './app.js', './assets/icon.svg'];",
    "const RULES = ['./assets/feeds.txt'];"
  ].join('\n'));
  mkdirSync(join(dir, 'assets'), { recursive: true });
  writeFileSync(join(dir, 'assets/icon.svg'), '<svg/>');
  writeFileSync(join(dir, 'assets/feeds.txt'), '||ads.example^');
  for (const d of APP_DIRS) {
    if (d === 'assets') continue;
    mkdirSync(join(dir, d), { recursive: true });
    writeFileSync(join(dir, d, 'mod.js'), 'export const x = 1;');
  }
  return dir;
}

test('the real repository stages into a deployable tree', () => {
  const out = mkdtempSync(join(tmpdir(), 'omnishield-site-'));
  try {
    const result = stageSite({ out: join(out, 'site') });
    assert.ok(result.precache >= 20, `expected the full precache list, got ${result.precache}`);
    assert.ok(existsSync(join(result.out, 'index.html')), 'marketing site keeps the root');
    for (const file of ['index.html', 'app.js', 'engine.js', 'sw.js', 'manifest.webmanifest']) {
      assert.ok(existsSync(join(result.appDir, file)), `${file} must be staged under /app/`);
    }
    assert.ok(existsSync(join(result.appDir, 'assets/core_lite_ads.txt')), 'the rule feed must ship');
    assert.ok(!existsSync(join(result.appDir, 'tests')), 'tests must never be published');
    assert.ok(!existsSync(join(result.appDir, 'node_modules')), 'node_modules must never be published');
    assert.ok(!existsSync(join(result.appDir, 'package.json')), 'dev metadata must never be published');
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
});

test('a missing precache target fails the assembly instead of shipping a broken app', () => {
  const dir = fixture();
  try {
    // Remove a file the service worker precaches.
    rmSync(join(dir, 'assets/feeds.txt'));
    assert.throws(() => stageSite({ out: '_site', root: dir }), /not self-sufficient|missing/i);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('checkPrecache reports the exact missing entries', () => {
  const dir = fixture();
  try {
    const appDir = join(dir, 'appdir');
    mkdirSync(appDir, { recursive: true });
    cpSync(join(dir, 'sw.js'), join(appDir, 'sw.js'));
    cpSync(join(dir, 'index.html'), join(appDir, 'index.html'));
    cpSync(join(dir, 'app.js'), join(appDir, 'app.js'));
    const report = checkPrecache(appDir);
    assert.equal(report.ok, false);
    assert.ok(report.missing.includes('assets/icon.svg'), JSON.stringify(report.missing));
    assert.ok(report.missing.includes('assets/feeds.txt'));
    assert.match(report.error, /assets\/icon\.svg/);

    // Staging the assets makes it pass.
    cpSync(join(dir, 'assets'), join(appDir, 'assets'), { recursive: true });
    assert.equal(checkPrecache(appDir).ok, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the assembler refuses a repository without a marketing site', () => {
  const dir = fixture();
  try {
    rmSync(join(dir, 'docs'), { recursive: true, force: true });
    assert.throws(() => stageSite({ out: '_site', root: dir }), /docs\/index\.html/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the published extension archive carries the same version as the app', () => {
  const facts = JSON.parse(readFileSync(join(ROOT, 'assets/extension-facts.json'), 'utf8'));
  const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
  assert.equal(facts.version, pkg.version, 'the ZIP must be rebuilt after a version bump');
  assert.ok(facts.rules <= facts.maxStaticRules);
});
