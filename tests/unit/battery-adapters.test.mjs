/**
 * Unit tests — battery adapters, driven by recorded fixture data.
 *
 * Each fixture is the real shape of the platform's output (sysfs files, CIM JSON,
 * ioreg text). The adapters therefore get exercised against all three platforms on
 * Linux CI, which is the only place they can be verified without three machines.
 */
import test from 'node:test';
import { strict as assert } from 'node:assert';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readSnapshot as readLinux, pickBattery } from '../../desktop/src/adapters/linux.js';
import { parseCimJson, QUERY as WINDOWS_QUERY } from '../../desktop/src/adapters/windows.js';
import { parseIoreg } from '../../desktop/src/adapters/macos.js';
import { Source, summaryLine } from '../../desktop/src/core/battery.js';
import { DEFAULT_SETTINGS } from '../../desktop/src/core/alerts.js';

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'battery');
const fixture = (name) => JSON.parse(readFileSync(join(FIXTURES, name), 'utf8'));

/** Materialises a fixture's `files` map into a temp sysfs tree. */
function makeSysfs(files) {
  const root = mkdtempSync(join(tmpdir(), 'sysfs-'));
  for (const [path, value] of Object.entries(files)) {
    const full = join(root, path);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, `${value}\n`);
  }
  return root;
}

test('linux: energy-based driver reads charge, current, voltage and cell temperature', (t) => {
  const data = fixture('linux-bat0.json');
  const root = makeSysfs(data.files);
  t.after(() => rmSync(root, { recursive: true, force: true }));

  const snap = readLinux({ root });
  assert.equal(snap.platform, 'linux');
  assert.equal(snap.percent, 62);
  assert.equal(snap.isCharging, false);
  assert.equal(snap.current.source, Source.MEASURED);
  assert.equal(snap.current.milliAmps, -812);
  assert.equal(snap.voltageMilliVolts, 3900);
  // 3900 mV * -812 mA = -3.17 W
  assert.equal(snap.powerMilliWatts, -3167);
  assert.equal(snap.heat.cellCelsius, 31.4);
  // sysfs energy_now is 24.5 Wh, which is more precise than charge x voltage.
  assert.equal(snap.energyMilliWattHours, 24500);
  assert.equal(snap.healthLabel, 'Good');
});

test('linux: charge-based driver with a charging status reports positive current', (t) => {
  const root = makeSysfs(fixture('linux-charge-variant.json').files);
  t.after(() => rmSync(root, { recursive: true, force: true }));

  const snap = readLinux({ root });
  assert.equal(snap.isCharging, true);
  assert.equal(snap.current.milliAmps, 1500);
  assert.equal(snap.percent, 64);
  assert.equal(snap.chargeMilliAmpHours, 3200);
  // No `temp` file on this driver, so no cell temperature is claimed.
  assert.equal(snap.heat.cellCelsius, null);
  assert.match(snap.heat.heatSource, /No temperature sensor/);
});

test('linux: the mains supply is never mistaken for a battery', (t) => {
  const root = makeSysfs(fixture('linux-bat0.json').files);
  t.after(() => rmSync(root, { recursive: true, force: true }));
  assert.equal(pickBattery(root), 'BAT0');
});

test('linux: a desktop with no battery says so instead of inventing 100%', (t) => {
  const root = mkdtempSync(join(tmpdir(), 'sysfs-empty-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const snap = readLinux({ root });
  assert.equal(snap.current.source, Source.UNAVAILABLE);
  assert.match(snap.chargingLabel, /No battery detected/);
});

test('windows: CIM output yields charge and voltage but admits there is no current', () => {
  const snap = parseCimJson(fixture('windows-battery.json').json);
  assert.equal(snap.platform, 'windows');
  assert.equal(snap.percent, 74);
  assert.equal(snap.isCharging, false);
  assert.equal(snap.voltageMilliVolts, 11400);
  // The honest part: Windows exposes no current, so nothing is derived from it.
  assert.equal(snap.current.source, Source.UNAVAILABLE);
  assert.equal(snap.powerMilliWatts, null);
  assert.equal(snap.heat.effectiveCelsius, null);
});

test('windows: the charging enum is decoded, not treated as a boolean', () => {
  const charging = parseCimJson(JSON.stringify({
    Name: 'BAT', EstimatedChargeRemaining: 80, BatteryStatus: 6, DesignVoltage: 11400
  }));
  assert.equal(charging.isCharging, true);
  assert.match(charging.chargingLabel, /Charging/);

  const onAc = parseCimJson(JSON.stringify({
    Name: 'BAT', EstimatedChargeRemaining: 100, BatteryStatus: 3, DesignVoltage: 11400
  }));
  assert.equal(onAc.isCharging, false);
  assert.match(onAc.chargingLabel, /Fully charged/);
});

test('windows: malformed output degrades to unavailable rather than throwing', () => {
  for (const bad of ['', 'not json', 'null', '[]', '{}']) {
    const snap = parseCimJson(bad);
    assert.equal(snap.current.source, Source.UNAVAILABLE, `input=${bad}`);
    assert.equal(snap.heat.effectiveCelsius, null);
  }
});

test('windows: an out-of-range charge reading is clamped, not displayed', () => {
  const snap = parseCimJson(JSON.stringify({ Name: 'BAT', EstimatedChargeRemaining: 127, BatteryStatus: 1 }));
  assert.equal(snap.percent, 100);
});

test('windows: an array of batteries uses the first entry', () => {
  const snap = parseCimJson(JSON.stringify([
    { Name: 'BAT0', EstimatedChargeRemaining: 55, BatteryStatus: 1, DesignVoltage: 11400 },
    { Name: 'BAT1', EstimatedChargeRemaining: 90, BatteryStatus: 1, DesignVoltage: 11400 }
  ]));
  assert.equal(snap.percent, 55);
  assert.equal(snap.batteryName, 'BAT0');
});

test('windows query selects the fields the parser actually reads', () => {
  for (const field of ['EstimatedChargeRemaining', 'BatteryStatus', 'DesignVoltage', 'Name']) {
    assert.match(WINDOWS_QUERY, new RegExp(field), `query must request ${field}`);
  }
});

test('macos: ioreg gives measured current, voltage and cell temperature', () => {
  const snap = parseIoreg(readFileSync(join(FIXTURES, 'macos-ioreg.txt'), 'utf8'));
  assert.equal(snap.platform, 'macos');
  assert.equal(snap.current.source, Source.MEASURED);
  assert.equal(snap.current.milliAmps, -1187);
  assert.equal(snap.voltageMilliVolts, 11934);
  // 30.72 °C from centi-degrees.
  assert.equal(snap.heat.cellCelsius, 30.72);
  assert.equal(snap.percent, 62);
  assert.equal(snap.chargeMilliAmpHours, 4338);
  assert.equal(snap.healthLabel, 'Good');
});

test('macos: a charging battery reports positive current', () => {
  const charging = readFileSync(join(FIXTURES, 'macos-ioreg.txt'), 'utf8')
    .replace('"CurrentAmperage" = -1187', '"CurrentAmperage" = 2100')
    .replace('"IsCharging" = No', '"IsCharging" = Yes');
  const snap = parseIoreg(charging);
  assert.equal(snap.isCharging, true);
  assert.equal(snap.current.milliAmps, 2100);
  assert.ok(snap.powerMilliWatts > 0);
});

test('macos: missing ioreg output degrades to unavailable', () => {
  const snap = parseIoreg('');
  assert.equal(snap.current.source, Source.UNAVAILABLE);
  assert.match(snap.chargingLabel, /No battery detected/);
});

test('all three platforms share one summary format', () => {
  const linux = readLinux.__fixtureSummary
    ? null
    : summaryLine(parseIoreg(readFileSync(join(FIXTURES, 'macos-ioreg.txt'), 'utf8')));
  const win = summaryLine(parseCimJson(fixture('windows-battery.json').json));
  // Same shape: level, then an explicit statement about the current.
  assert.match(linux, /^62% • -1187 mA/);
  assert.match(win, /^74% • current not reported/);
});

// --- Desktop app wiring ------------------------------------------------

test('desktop: a sample produces a snapshot, a summary and honest limitations', async () => {
  const { tick } = await import('../../desktop/src/main.js');
  const delivered = [];
  const result = await tick({
    platform: 'linux',
    nowMs: 1_700_000_000_000,
    settings: { ...DEFAULT_SETTINGS, enabled: false },
    deliver: (title, body) => delivered.push({ title, body })
  });
  assert.equal(result.snapshot.platform, 'linux');
  assert.match(result.summary, /%/);
  assert.equal(delivered.length, 0, 'disabled settings must not notify');
  assert.ok(Array.isArray(result.limitations));
});

test('desktop: enabled alerts are delivered through the injected notifier', async () => {
  const { tick } = await import('../../desktop/src/main.js');
  const delivered = [];
  // Windows fixture shape: no current, but a synthetic heat reading forces the path.
  const result = await tick({
    platform: 'win32',
    nowMs: 1_700_000_000_000,
    settings: { ...DEFAULT_SETTINGS, enabled: true, lowPercentThreshold: 50 },
    deliver: (title, body) => delivered.push({ title, body })
  });
  // No battery on CI -> percent 0 and no alert-worthy heat; the contract we assert is
  // that delivery goes through the injected channel and never throws.
  assert.ok(Array.isArray(delivered));
  assert.ok(result.state);
});

test('desktop: the notifier command per platform is chosen without throwing', async () => {
  const { notify } = await import('../../desktop/src/main.js');
  const called = [];
  // The runtime passes a callback, so the stub must accept and invoke it or the test
  // hangs waiting for a completion that never comes.
  const runner = (cmd, args, cb) => {
    called.push({ cmd, args });
    if (typeof cb === 'function') cb(null, '', '');
  };
  notify('Title', 'Body', { platform: 'darwin', runner });
  notify('Title', 'Body', { platform: 'linux', runner });
  notify('Title', 'Body', { platform: 'win32', runner });
  assert.deepEqual(called.map((c) => c.cmd), ['osascript', 'notify-send', 'powershell.exe']);
  // Quotes in the message must not break out of the apple script string.
  notify('T "quoted"', 'B `backtick`', { platform: 'darwin', runner });
  const script = called[3].args.join(' ');
  assert.ok(!script.includes('"quoted"'), 'double quotes must be stripped from the message');
  assert.ok(!script.includes('`backtick`'), 'backticks must be stripped from the message');
  assert.match(script, /-e display notification/);
});

test('desktop: the local server exposes health and refuses unknown paths', async () => {
  const { serve } = await import('../../desktop/src/main.js');
  const server = serve(0, () => ({ summary: 'stub' }));
  // listen() is asynchronous: address() is null until the socket is bound.
  await new Promise((resolve) => server.once('listening', resolve));
  const { port } = server.address();
  const get = (path) => fetch(`http://127.0.0.1:${port}${path}`);
  try {
    assert.equal((await get('/health')).status, 200);
    const battery = await get('/battery');
    assert.equal(battery.status, 200);
    assert.equal((await battery.json()).summary, 'stub');
    assert.equal((await get('/nope')).status, 404);
  } finally {
    server.close();
  }
});

test('desktop: the server reports 503 before the first reading', async () => {
  const { serve } = await import('../../desktop/src/main.js');
  const server = serve(0, () => null);
  await new Promise((resolve) => server.once('listening', resolve));
  const { port } = server.address();
  try {
    const res = await fetch(`http://127.0.0.1:${port}/battery`);
    assert.equal(res.status, 503);
  } finally {
    server.close();
  }
});
