/**
 * Unit tests — extension builder.
 *
 * The shipped ZIP is a real artifact users load into Chrome, so the rules that
 * go into it matter: they must be deduplicated, must never include the system
 * safety allowlist (captive portals, connectivity checks), and must stay inside
 * Chrome's guaranteed static-rule allowance. These tests use synthetic feeds so
 * they stay fast and independent of the 79k-rule bundled list.
 */
import test from 'node:test';
import { strict as assert } from 'node:assert';
import { mkdtempSync, writeFileSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  crc32, createZip, readZip, selectRules, splitRules, toDnrRules,
  buildManifest, build, inspect, MAX_STATIC_RULES, RULES_PER_FILE
} from '../../scripts/build-extension.mjs';

function tempWorkspace(feeds) {
  const dir = mkdtempSync(join(tmpdir(), 'omnishield-ext-'));
  mkdirSync(join(dir, 'assets'), { recursive: true });
  for (const [name, text] of Object.entries(feeds)) writeFileSync(join(dir, 'assets', name), text);
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'test', version: '9.9.9' }));
  mkdirSync(join(dir, 'extension/src'), { recursive: true });
  for (const file of ['background.js', 'popup.js', 'popup.html', 'content.js', 'icon.png']) {
    writeFileSync(join(dir, 'extension/src', file), `/* ${file} */\n`);
  }
  return dir;
}

test('crc32 matches the standard check vector', () => {
  assert.equal(crc32(Buffer.from('123456789', 'utf8')), 0xcbf43926);
  assert.equal(crc32(Buffer.from('')), 0);
});

test('zip writer and reader round-trip text, binary and large bodies', () => {
  const entries = [
    { name: 'manifest.json', data: JSON.stringify({ hello: 'world' }) },
    { name: 'icon.png', data: Buffer.from([0x89, 0x50, 0x4e, 0x47, 0, 1, 2, 3]) },
    { name: 'big.txt', data: 'a'.repeat(50000) }
  ];
  const zip = createZip(entries);
  assert.equal(zip.readUInt32LE(0), 0x04034b50, 'must start with a local file header');
  const back = readZip(zip);
  assert.deepEqual(back.map((e) => e.name).sort(), ['big.txt', 'icon.png', 'manifest.json']);
  for (const original of entries) {
    const found = back.find((e) => e.name === original.name);
    const expected = Buffer.isBuffer(original.data) ? original.data : Buffer.from(original.data, 'utf8');
    assert.ok(found.data.equals(expected), `${original.name} must round-trip byte-for-byte`);
  }
});

test('zip output is deterministic (same input, same bytes)', () => {
  const entries = [{ name: 'a.txt', data: 'x'.repeat(100) }, { name: 'b.txt', data: 'y'.repeat(100) }];
  assert.ok(createZip(entries).equals(createZip([...entries].reverse())),
    'entry order must not change the archive');
});

test('rule selection dedupes, drops the safety allowlist and skips junk', () => {
  const dir = tempWorkspace({
    'supplement.txt': [
      '! comment header',
      '||ads.example.com^',
      '||ads.example.com^',
      '||captive.apple.com^',
      '||connectivitycheck.gstatic.com^',
      'not-a-domain-rule',
      '||com^'
    ].join('\n'),
    'lite.txt': ['||tracker.example.net^', '||ads.example.com^'].join('\n'),
    'unused.txt': '||never-read.example^'
  });
  try {
    const { rules, skipped } = selectRules({
      root: dir,
      files: ['assets/supplement.txt', 'assets/lite.txt']
    });
    assert.deepEqual(rules, ['ads.example.com', 'tracker.example.net'],
      'feeds are read in order, duplicates and safety entries removed');
    assert.equal(skipped.duplicate, 2);
    assert.equal(skipped.safety, 2);
    assert.equal(skipped.malformed, 1);
    assert.equal(skipped.tooShort, 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the static-rule cap is enforced, not exceeded', () => {
  const lines = Array.from({ length: 40 }, (_, i) => `||ad${i}.example^`).join('\n');
  const dir = tempWorkspace({ 'supplement.txt': lines });
  try {
    const result = selectRules({ root: dir, files: ['assets/supplement.txt'], maxRules: 25 });
    assert.equal(result.rules.length, 25);
    assert.equal(result.capped, true);
    assert.equal(result.skipped.overCap, 15);
    assert.ok(result.rules.length <= MAX_STATIC_RULES);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('rulesets split at the configured size and keep unique domains', () => {
  const domains = Array.from({ length: 10 }, (_, i) => `d${i}.example`);
  const chunks = splitRules(domains, 4);
  assert.deepEqual(chunks.map((c) => c.length), [4, 4, 2]);
  assert.deepEqual(chunks.flat(), domains);
  const rules = toDnrRules(chunks[0]);
  assert.equal(rules[0].id, 1);
  assert.equal(rules[0].action.type, 'block');
  assert.deepEqual(rules[0].condition, { requestDomains: ['d0.example'], domainType: 'thirdParty' });
  assert.ok(RULES_PER_FILE * 2 >= MAX_STATIC_RULES, 'two rulesets must be able to hold the cap');
});

test('manifest is MV3 with one ruleset entry per generated file', () => {
  const manifest = buildManifest({ version: '1.2.3', rulesetCount: 2 });
  assert.equal(manifest.manifest_version, 3);
  assert.equal(manifest.version, '1.2.3');
  assert.deepEqual(manifest.declarative_net_request.rule_resources.map((r) => r.path),
    ['rules-1.json', 'rules-2.json']);
  assert.ok(manifest.permissions.includes('declarativeNetRequestFeedback'),
    'per-tab counts need the feedback permission; without it the popup shows "—"');
  // Content-script match patterns are URLs by definition; anything else pointing
  // at the network would be a remote dependency and is forbidden.
  const { content_scripts: _matches, ...rest } = manifest;
  assert.ok(!/https?:\/\//.test(JSON.stringify(rest)),
    'no manifest field other than content-script match patterns may reference a remote URL');
});

test('build then inspect reproduces a valid, in-limit archive', () => {
  const dir = tempWorkspace({
    'supplement.txt': ['||ads.example.com^', '||tracker.example.net^'].join('\n'),
    'lite.txt': '||beacon.example.org^'
  });
  try {
    const result = build({
      root: dir, outFile: 'out/ext.zip', files: ['assets/supplement.txt', 'assets/lite.txt']
    });
    assert.equal(result.rules, 3);
    assert.equal(result.rulesets, 1);
    assert.ok(existsIn(dir, 'out/ext.zip'));

    const report = inspect({ root: dir, outFile: 'out/ext.zip' });
    assert.equal(report.ok, true, report.error);
    assert.equal(report.ruleCount, 3);
    assert.equal(report.uniqueDomains, 3);
    assert.equal(report.version, '9.9.9');
    assert.equal(report.overLimit, false);
    assert.ok(report.files.includes('manifest.json'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('inspect rejects an archive with a missing ruleset file', () => {
  const dir = tempWorkspace({ 'supplement.txt': '||ads.example.com^' });
  try {
    // Same manifest, but the rules file is deliberately absent.
    const manifest = buildManifest({ version: '1.0.0', rulesetCount: 1 });
    const zip = createZip([{ name: 'manifest.json', data: JSON.stringify(manifest) }]);
    mkdirSync(join(dir, 'out'), { recursive: true });
    writeFileSync(join(dir, 'out/ext.zip'), zip);
    const report = inspect({ root: dir, outFile: 'out/ext.zip' });
    assert.equal(report.ok, false);
    assert.match(report.error, /rules-1\.json/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the repository archive is in-limit and matches the packaged sources', () => {
  const report = inspect();
  assert.equal(report.ok, true, report.error);
  assert.ok(report.ruleCount <= MAX_STATIC_RULES, `${report.ruleCount} rules exceeds the guaranteed allowance`);
  assert.equal(report.ruleCount, report.uniqueDomains, 'no duplicate domains may ship');
  assert.ok(report.rulesets >= 1 && report.rulesets <= 50);
  const version = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8')).version;
  assert.equal(report.version, version, 'the ZIP must be rebuilt after a version bump');
});

function existsIn(dir, file) {
  try { readFileSync(join(dir, file)); return true; } catch { return false; }
}
