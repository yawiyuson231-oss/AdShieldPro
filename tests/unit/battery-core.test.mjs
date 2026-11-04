/**
 * Unit tests — shared battery core.
 *
 * These encode the rules the Android app and the desktop app must agree on: sign
 * conventions, when a value is withheld, and how unavailable data is described.
 */
import test from 'node:test';
import { strict as assert } from 'node:assert';
import {
  LIMITS, Source, normaliseCurrent, powerMilliWatts, energyMilliWattHours,
  resolveHeat, summaryLine, buildSnapshot, isPlausibleVoltage
} from '../../desktop/src/core/battery.js';
import {
  DEFAULT_SETTINGS, AlertKind, COOLDOWN, clampSettings, emptyState, evaluate, unavailableReasons
} from '../../desktop/src/core/alerts.js';

test('current is normalised so negative always means discharging', () => {
  assert.equal(normaliseCurrent(-812, false).milliAmps, -812);
  // A driver reporting positive while discharging is corrected.
  assert.equal(normaliseCurrent(812, false).milliAmps, -812);
  // A driver reporting negative while charging is corrected.
  assert.equal(normaliseCurrent(-1500, true).milliAmps, 1500);
  assert.equal(normaliseCurrent(1500, true).milliAmps, 1500);
});

test('implausible or absent current is reported as unavailable, never as zero', () => {
  for (const raw of [null, undefined, 0, NaN, 5, 40_000]) {
    const result = normaliseCurrent(raw, false);
    assert.equal(result.source, Source.UNAVAILABLE, `raw=${raw}`);
    assert.match(result.note, /does not report/);
  }
});

test('current exactly at the plausibility bounds is accepted', () => {
  assert.equal(normaliseCurrent(-LIMITS.minMilliAmps, false).source, Source.MEASURED);
  assert.equal(normaliseCurrent(-LIMITS.maxMilliAmps, false).source, Source.MEASURED);
});

test('power is derived from measured volts and amps with the discharge sign kept', () => {
  // 3900 * -812 / 1000 = -3166.8, rounded to -3167
  assert.equal(powerMilliWatts(3900, -812, true), -3167);
  assert.equal(powerMilliWatts(4100, 2000, true), 8200);
});

test('power is withheld when either input is missing or implausible', () => {
  assert.equal(powerMilliWatts(3900, -812, false), null, 'unmeasured current');
  assert.equal(powerMilliWatts(null, -812, true), null, 'no voltage');
  assert.equal(powerMilliWatts(0, -812, true), null, 'zero voltage');
  assert.equal(powerMilliWatts(40_000, -812, true), null, 'implausible voltage');
});

test('energy is charge times voltage and is withheld without a charge counter', () => {
  assert.equal(energyMilliWattHours(2450, 3900), 9555);
  assert.equal(energyMilliWattHours(2450, null), null);
  assert.equal(energyMilliWattHours(null, 3900), null);
});

test('voltage plausibility covers the real range of phone and laptop cells', () => {
  assert.equal(isPlausibleVoltage(3900), true);
  assert.equal(isPlausibleVoltage(11_400), true);
  assert.equal(isPlausibleVoltage(120), false);
  assert.equal(isPlausibleVoltage(20_000), true, 'a 4S laptop pack is real');
  assert.equal(isPlausibleVoltage(45_000), false);
});

test('the cell wins for decisions and a hot SoC is described as workload', () => {
  const heat = resolveHeat({ cellCelsius: 33, socCelsius: 61 });
  assert.equal(heat.effectiveCelsius, 33);
  assert.match(heat.heatSource, /28\.0 °C hotter/);
  assert.match(heat.heatSource, /workload, not the cell/);

  const close = resolveHeat({ cellCelsius: 34, socCelsius: 36 });
  assert.match(close.heatSource, /close together/);
});

test('the SoC is used only when the cell is not reported', () => {
  const heat = resolveHeat({ cellCelsius: null, socCelsius: 58, socLabel: 'Package sensor' });
  assert.equal(heat.effectiveCelsius, 58);
  assert.equal(heat.effectiveSource, Source.DERIVED);
  assert.match(heat.heatSource, /Package sensor/);
  assert.match(heat.heatSource, /battery cell not reported/);
});

test('no sensor at all is stated, not rounded to a comfortable number', () => {
  const heat = resolveHeat({});
  assert.equal(heat.effectiveCelsius, null);
  assert.equal(heat.effectiveSource, Source.UNAVAILABLE);
  assert.match(heat.heatSource, /No temperature sensor/);
});

test('implausible temperatures are rejected rather than shown', () => {
  assert.equal(resolveHeat({ cellCelsius: 0 }).effectiveCelsius, 0);
  assert.equal(resolveHeat({ cellCelsius: -500 }).effectiveCelsius, null);
  assert.equal(resolveHeat({ cellCelsius: 400 }).effectiveCelsius, null);
});

test('the summary line shows measured values and admits missing ones', () => {
  const full = buildSnapshot({
    percent: 62, isCharging: false, currentMilliAmps: -812,
    voltageMilliVolts: 3900, cellCelsius: 31.4, chargeMilliAmpHours: 2450
  });
  const line = summaryLine(full);
  assert.match(line, /^62% • -812 mA \(3\.2 W\) • 31\.4°C cell • 9\.6 Wh stored$/);

  const bare = buildSnapshot({ percent: 55, isCharging: false });
  const bareLine = summaryLine(bare);
  assert.match(bareLine, /current not reported/);
  assert.match(bareLine, /no temperature sensor readable/);
  assert.doesNotMatch(bareLine, /0 mA/);
});

test('percent is clamped to 0..100 and rounding is explicit', () => {
  assert.equal(buildSnapshot({ percent: 127, isCharging: false }).percent, 100);
  assert.equal(buildSnapshot({ percent: -4, isCharging: false }).percent, 0);
  assert.equal(buildSnapshot({ percent: 61.6, isCharging: false }).percent, 62);
});

// --- Alert rules ---------------------------------------------------------

const settings = (over = {}) => ({ ...DEFAULT_SETTINGS, enabled: true, ...over });

const snapshot = (over = {}) => buildSnapshot({
  percent: 62,
  isCharging: false,
  currentMilliAmps: -800,
  voltageMilliVolts: 3900,
  cellCelsius: 32,
  ...over
});

test('nothing fires while the feature is disabled', () => {
  const { alerts } = evaluate(snapshot({ percent: 5, cellCelsius: 50 }), { ...DEFAULT_SETTINGS, enabled: false });
  assert.equal(alerts.length, 0);
});

test('low battery fires once per drop, then again only after 5% more drain', () => {
  const s = settings();
  const first = evaluate(snapshot({ percent: 20 }), s, emptyState(), 1000);
  assert.equal(first.alerts.length, 1);
  assert.equal(first.alerts[0].kind, AlertKind.LOW_BATTERY);

  const again = evaluate(snapshot({ percent: 18 }), s, first.state, 2000);
  assert.equal(again.alerts.length, 0, 'no repeat within 5%');

  const further = evaluate(snapshot({ percent: 14 }), s, again.state, 3000);
  assert.equal(further.alerts.length, 1);
});

test('charging resets the low-battery cycle so the next drop warns again', () => {
  const s = settings();
  const low = evaluate(snapshot({ percent: 20 }), s, emptyState(), 1000);
  assert.equal(low.alerts.length, 1);
  const charging = evaluate(snapshot({ percent: 30, isCharging: true, currentMilliAmps: 1500 }), s, low.state, 2000);
  assert.equal(charging.state.lastLowPercent, null);
  const drained = evaluate(snapshot({ percent: 19 }), s, charging.state, 3000);
  assert.equal(drained.alerts.some((a) => a.kind === AlertKind.LOW_BATTERY), true);
});

test('charge complete fires once per session, not every sample at 100%', () => {
  const s = settings({ fullPercentThreshold: 100 });
  const at100 = snapshot({ percent: 100, isCharging: true, currentMilliAmps: 200 });
  const first = evaluate(at100, s, emptyState(), 1000);
  assert.equal(first.alerts.filter((a) => a.kind === AlertKind.CHARGE_COMPLETE).length, 1);
  const second = evaluate(at100, s, first.state, 2000);
  assert.equal(second.alerts.filter((a) => a.kind === AlertKind.CHARGE_COMPLETE).length, 0);

  // A later session (different 12h bucket) alerts again.
  const nextSession = evaluate(at100, s, second.state, 1000 + 13 * 60 * 60 * 1000);
  assert.equal(nextSession.alerts.filter((a) => a.kind === AlertKind.CHARGE_COMPLETE).length, 1);
});

test('heat re-alerts after the cooldown or a 2 °C rise, not on every sample', () => {
  const s = settings({ tempWarningCelsius: 41 });
  const hot = snapshot({ cellCelsius: 42 });
  const first = evaluate(hot, s, emptyState(), 0);
  assert.equal(first.alerts.filter((a) => a.kind === AlertKind.HEAT).length, 1);

  const immediately = evaluate(hot, s, first.state, 60_000);
  assert.equal(immediately.alerts.filter((a) => a.kind === AlertKind.HEAT).length, 0, 'suppressed');

  const rising = evaluate(snapshot({ cellCelsius: 44.5 }), s, first.state, 60_000);
  assert.equal(rising.alerts.filter((a) => a.kind === AlertKind.HEAT).length, 1, 're-alerts on +2°C');

  const afterCooldown = evaluate(hot, s, first.state, COOLDOWN.tempMs + 1);
  assert.equal(afterCooldown.alerts.filter((a) => a.kind === AlertKind.HEAT).length, 1);
});

test('unchanged hot temperature stays quiet until the cooldown elapses', () => {
  const s = settings({ tempWarningCelsius: 41 });
  const hot = snapshot({ cellCelsius: 42 });
  const first = evaluate(hot, s, emptyState(), 0);
  const midway = evaluate(hot, s, first.state, COOLDOWN.tempMs - 1000);
  assert.equal(midway.alerts.filter((a) => a.kind === AlertKind.HEAT).length, 0);
});

test('heavy draw needs a measured current and respects its cooldown', () => {
  const s = settings({ currentAlertMilliAmps: 1800 });
  const heavy = snapshot({ currentMilliAmps: -2400 });
  const first = evaluate(heavy, s, emptyState(), 0);
  assert.equal(first.alerts.filter((a) => a.kind === AlertKind.HEAVY_DRAW).length, 1);

  const again = evaluate(heavy, s, first.state, 60_000);
  assert.equal(again.alerts.filter((a) => a.kind === AlertKind.HEAVY_DRAW).length, 0, 'cooldown');

  const later = evaluate(heavy, s, again.state, COOLDOWN.currentMs + 1);
  assert.equal(later.alerts.filter((a) => a.kind === AlertKind.HEAVY_DRAW).length, 1);
});

test('no heavy-draw alert is invented when the platform cannot measure current', () => {
  const s = settings();
  const windows = buildSnapshot({ percent: 40, isCharging: false }); // no current anywhere
  const { alerts } = evaluate(windows, s, emptyState(), 0);
  assert.equal(alerts.filter((a) => a.kind === AlertKind.HEAVY_DRAW).length, 0);
  assert.match(unavailableReasons(windows).join(' '), /does not expose one/);
});

test('thresholds are clamped into useful ranges and cannot contradict', () => {
  const clamped = clampSettings({
    enabled: true, lowPercentThreshold: 80, fullPercentThreshold: 20,
    tempWarningCelsius: 10, currentAlertMilliAmps: 99_000
  });
  assert.equal(clamped.lowPercentThreshold, 50);
  assert.equal(clamped.fullPercentThreshold, 60, 'low + 10 floor');
  assert.equal(clamped.tempWarningCelsius, 35);
  assert.equal(clamped.currentAlertMilliAmps, 5000);
});

test('alert bodies never contain a fabricated zero current', () => {
  const s = settings({ tempWarningCelsius: 30 });
  const unmeasured = buildSnapshot({ percent: 15, isCharging: false, cellCelsius: 45 });
  const { alerts } = evaluate(unmeasured, s, emptyState(), 0);
  for (const alert of alerts) {
    assert.doesNotMatch(alert.body, /0 mA/, alert.body);
  }
});
